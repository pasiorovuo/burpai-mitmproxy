import asyncio
import datetime
import http
import json
import logging
import typing
import uuid
from dataclasses import dataclass, field

import httpx
import mitmproxy.http

_logger = logging.getLogger(__name__)

_POLL_INTERVAL = 5

# ── Wire types ─────────────────────────────────────────────────────────────────


class ToolCall(typing.TypedDict):
    id: str
    tool_name: str
    arguments: dict[str, typing.Any]


# ── Session state ──────────────────────────────────────────────────────────────

_PENDING = "PENDING"
_PROCESSING = "PROCESSING"
_COMPLETE = "COMPLETE"
_ERROR = "ERROR"


@dataclass
class ExploreSession:
    exploration_id: str
    step_id: str
    state: str = _PENDING
    # True for the step created by /start; False for all steps after /continue or /finish.
    # Controls whether exploration_id is included in PENDING status responses.
    is_initial_step: bool = True
    pending_tool_calls: list[ToolCall] = field(default_factory=list)
    conversation: list[dict[str, typing.Any]] = field(default_factory=list)
    error: str | None = None


class ExploreStore:
    def __init__(self) -> None:
        self._by_eid: dict[str, ExploreSession] = {}
        self._by_sid: dict[str, ExploreSession] = {}

    def create(self, initial_messages: list[dict[str, typing.Any]]) -> ExploreSession:
        session = ExploreSession(
            exploration_id=str(uuid.uuid4()),
            step_id=str(uuid.uuid4()),
            conversation=initial_messages,
        )
        self._by_eid[session.exploration_id] = session
        self._by_sid[session.step_id] = session
        return session

    def by_step_id(self, step_id: str) -> ExploreSession | None:
        return self._by_sid.get(step_id)

    def by_exploration_id(self, eid: str) -> ExploreSession | None:
        return self._by_eid.get(eid)

    def advance(self, session: ExploreSession) -> None:
        self._by_sid.pop(session.step_id, None)
        session.step_id = str(uuid.uuid4())
        session.state = _PENDING
        session.is_initial_step = False
        session.pending_tool_calls = []
        session.error = None
        self._by_sid[session.step_id] = session


# ── Prompt construction ────────────────────────────────────────────────────────

_SYSTEM_PROMPT = (
    "You are an expert web security analyst and penetration tester working within Burp Suite, "
    "a professional web security testing tool. Your task is to autonomously explore and exploit "
    "web vulnerabilities based on the HTTP evidence provided by the user.\n\n"
    "Your workflow:\n"
    "1. Analyse the provided HTTP request/response evidence and the user's instructions.\n"
    "2. Form a hypothesis about the vulnerability or issue.\n"
    "3. Use the `repeater` tool to send targeted HTTP requests to the target and analyse the responses.\n"
    "4. Iterate — adapt your payloads and approach based on what you observe.\n"
    "5. When the investigation is complete or the user's question is fully answered, call the "
    "`reporter` tool to deliver your findings.\n\n"
    "Rules you must follow:\n"
    "- You MUST always respond using a tool call — either `repeater` to continue investigating, "
    "or `reporter` to conclude. Never respond with plain text.\n"
    "- Do not repeat an identical HTTP request. If you want to send a request you have already "
    "sent, try a different approach instead.\n"
    "- Populate every field in every tool call. All arguments are required.\n"
    "- Call `reporter` when: the investigation is complete, the user's question is answered, "
    "no further progress is possible, or after receiving an empty response indicating a "
    "connection failure."
)

_TOOL_DEFINITIONS: list[dict[str, typing.Any]] = [
    {
        "type": "function",
        "function": {
            "name": "repeater",
            "description": (
                "Issues an HTTP request to the target using Burp Suite's Repeater tool "
                "and returns the raw HTTP response for analysis. Use this to probe the "
                "target, test payloads, and gather evidence."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "request": {
                        "type": "string",
                        "description": (
                            "The full raw HTTP request to send to the target, with LF (\\n) "
                            "line endings. Include all necessary headers."
                        ),
                    },
                    "step_title": {
                        "type": "string",
                        "description": "A short label for this step, shown in the Burp Suite UI.",
                    },
                    "step_action": {
                        "type": "string",
                        "description": (
                            "A concise description of what this request is intended to "
                            "accomplish and why."
                        ),
                    },
                    "learnings": {
                        "type": "string",
                        "description": (
                            "What you learned from the previous response that motivates "
                            "this request."
                        ),
                    },
                    "progress": {
                        "type": "string",
                        "description": "A summary of exploitation progress so far.",
                    },
                    "knowledge": {
                        "type": "string",
                        "description": (
                            "Accumulated facts about the target: technology stack, confirmed "
                            "vulnerabilities, extracted values."
                        ),
                    },
                },
                "required": [
                    "request",
                    "step_title",
                    "step_action",
                    "learnings",
                    "progress",
                    "knowledge",
                ],
                "additionalProperties": False,
            },
            "strict": True,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "reporter",
            "description": (
                "Concludes the exploration and delivers a final report to the user. "
                "Call this when the investigation is complete, the user's question has "
                "been answered, or no further progress is possible (including after "
                "receiving an empty response indicating a connection failure)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "report": {
                        "type": "string",
                        "description": (
                            "A markdown-formatted report of the full investigation: "
                            "vulnerability found, exploitation steps, extracted data, "
                            "and any recommendations."
                        ),
                    },
                    "step_title": {
                        "type": "string",
                        "description": "A short label for the final step, shown in the Burp Suite UI.",
                    },
                    "step_action": {
                        "type": "string",
                        "description": "A concise description of what the report covers.",
                    },
                    "learnings": {
                        "type": "string",
                        "description": "Final summary of what was learned during the exploration.",
                    },
                    "progress": {
                        "type": "string",
                        "description": "Final exploitation progress summary.",
                    },
                    "knowledge": {
                        "type": "string",
                        "description": "Final accumulated knowledge about the target.",
                    },
                },
                "required": [
                    "report",
                    "step_title",
                    "step_action",
                    "learnings",
                    "progress",
                    "knowledge",
                ],
                "additionalProperties": False,
            },
            "strict": True,
        },
    },
]


def _format_evidence(evidence: list[dict[str, typing.Any]]) -> str:
    parts: list[str] = []
    for i, ev in enumerate(evidence, 1):
        prefix = f"Evidence {i}" if len(evidence) > 1 else "Evidence"
        blocks: list[str] = []

        request: str | None = ev.get("request")
        response: str | None = ev.get("response")
        notes: str | None = ev.get("notes")
        request_highlights: list[str] = ev.get("request_highlights") or []
        response_highlights: list[str] = ev.get("response_highlights") or []

        if request is None and response is not None:
            blocks.append("(No HTTP request was captured.)")

        if request is not None:
            blocks.append(f"HTTP Request:\n```\n{request}\n```")
            if request_highlights:
                hl = "\n".join(f"  - {h}" for h in request_highlights)
                blocks.append(f"User-highlighted text in the request:\n{hl}")

        if response is not None:
            blocks.append(f"HTTP Response:\n```\n{response}\n```")
            if response_highlights:
                hl = "\n".join(f"  - {h}" for h in response_highlights)
                blocks.append(f"User-highlighted text in the response:\n{hl}")
        elif request is not None:
            blocks.append("(No HTTP response was captured.)")

        if notes:
            blocks.append(f"User annotation: {notes}")

        if not blocks:
            blocks.append("(No evidence data was attached.)")

        parts.append(f"{prefix}:\n" + "\n\n".join(blocks))

    return "\n\n---\n\n".join(parts)


def build_initial_messages(
    issue_definition: dict[str, typing.Any],
) -> list[dict[str, typing.Any]]:
    detail: str = issue_definition.get("detail", "")
    target: str = issue_definition.get("target", "")
    background: str = issue_definition.get("background", "")
    evidence: list[dict[str, typing.Any]] = issue_definition.get("evidence", [])

    user_parts: list[str] = []
    if detail:
        user_parts.append(f"Task: {detail}")
    if target:
        user_parts.append(f"Target: {target}")
    if background:
        user_parts.append(f"Background: {background}")
    if evidence:
        user_parts.append(_format_evidence(evidence))

    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": "\n\n".join(user_parts)},
    ]


# ── Response helpers ───────────────────────────────────────────────────────────


def _hakawai_header() -> str:
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    ts = f"{now.strftime('%Y-%m-%dT%H:%M:%S')}.{now.microsecond:06d}000Z"
    return f"creditCost=1,balanceTimestamp={ts},planType=credit,balance=9999.11"


def _json_response(
    status: http.HTTPStatus,
    body: dict[str, typing.Any],
) -> mitmproxy.http.Response:
    return mitmproxy.http.Response.make(
        status_code=int(status),
        content=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Portswigger-Hakawai-Ai": _hakawai_header(),
        },
    )


def _error_response(message: str) -> mitmproxy.http.Response:
    return mitmproxy.http.Response.make(
        status_code=500,
        content=message.encode(),
        headers={
            "Content-Type": "text/plain",
            "Portswigger-Hakawai-Ai": _hakawai_header(),
        },
    )


# ── Handler ────────────────────────────────────────────────────────────────────


class ExploreHandler:
    def __init__(self) -> None:
        self._store = ExploreStore()

    def handle_start(
        self,
        body: dict[str, typing.Any],
        backend_url: str,
        api_key: str,
        model: str,
    ) -> mitmproxy.http.Response:
        issue_definition: dict[str, typing.Any] = body.get("issue_definition", {})
        messages = build_initial_messages(issue_definition)
        session = self._store.create(messages)
        asyncio.ensure_future(self._run_llm(session, backend_url, api_key, model))
        return _json_response(
            http.HTTPStatus.ACCEPTED,
            {"step_id": session.step_id, "poll_interval_seconds": _POLL_INTERVAL},
        )

    def handle_status(self, step_id: str) -> mitmproxy.http.Response:
        session = self._store.by_step_id(step_id)
        if session is None:
            return _error_response(f"Unknown step_id: {step_id}")

        if session.state == _ERROR:
            return _error_response(session.error or "LLM call failed")

        if session.state == _PENDING:
            body: dict[str, typing.Any] = {
                "step_id": step_id,
                "state": _PENDING,
                "retry_count": 0,
                "poll_interval_seconds": _POLL_INTERVAL,
            }
            if not session.is_initial_step:
                body["exploration_id"] = session.exploration_id
            return _json_response(http.HTTPStatus.OK, body)

        if session.state == _PROCESSING:
            return _json_response(
                http.HTTPStatus.OK,
                {
                    "step_id": step_id,
                    "state": _PROCESSING,
                    "exploration_id": session.exploration_id,
                    "retry_count": 0,
                    "poll_interval_seconds": _POLL_INTERVAL,
                },
            )

        # COMPLETE
        first = session.pending_tool_calls[0]
        return _json_response(
            http.HTTPStatus.OK,
            {
                "step_id": step_id,
                "state": _COMPLETE,
                "exploration_id": session.exploration_id,
                "response": {
                    "exploration_id": session.exploration_id,
                    "step_title": first["arguments"].get("step_title", ""),
                    "step_action": first["arguments"].get("step_action", ""),
                    "tool_calls": [
                        {
                            "id": tc["id"],
                            "tool_name": tc["tool_name"],
                            "arguments": tc["arguments"],
                        }
                        for tc in session.pending_tool_calls
                    ],
                },
                "retry_count": 0,
            },
        )

    def handle_continue(
        self,
        body: dict[str, typing.Any],
        backend_url: str,
        api_key: str,
        model: str,
    ) -> mitmproxy.http.Response:
        return self._submit_results(body, backend_url, api_key, model)

    def handle_finish(
        self,
        body: dict[str, typing.Any],
        backend_url: str,
        api_key: str,
        model: str,
    ) -> mitmproxy.http.Response:
        return self._submit_results(body, backend_url, api_key, model)

    def _submit_results(
        self,
        body: dict[str, typing.Any],
        backend_url: str,
        api_key: str,
        model: str,
    ) -> mitmproxy.http.Response:
        exploration_id: str | None = body.get("exploration_id")
        if not exploration_id:
            return _error_response("Missing exploration_id")

        session = self._store.by_exploration_id(exploration_id)
        if session is None:
            return _error_response(f"Unknown exploration_id: {exploration_id}")

        for tr in body.get("tool_results", []):
            session.conversation.append(
                {
                    "role": "tool",
                    "tool_call_id": tr["tool_id"],
                    "content": tr["result"],
                }
            )

        self._store.advance(session)
        asyncio.ensure_future(self._run_llm(session, backend_url, api_key, model))

        return _json_response(
            http.HTTPStatus.ACCEPTED,
            {
                "step_id": session.step_id,
                "exploration_id": exploration_id,
                "poll_interval_seconds": _POLL_INTERVAL,
            },
        )

    async def _run_llm(
        self,
        session: ExploreSession,
        backend_url: str,
        api_key: str,
        model: str,
    ) -> None:
        session.state = _PROCESSING
        try:
            payload = {
                "model": model,
                "messages": session.conversation,
                "tools": _TOOL_DEFINITIONS,
                "tool_choice": "required",
                "max_completion_tokens": 16384,
            }
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(
                    backend_url,
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    content=json.dumps(payload),
                )
                resp.raise_for_status()
                data: dict[str, typing.Any] = resp.json()

            message: dict[str, typing.Any] = data["choices"][0]["message"]
            raw_tool_calls: list[dict[str, typing.Any]] | None = message.get("tool_calls")

            if not raw_tool_calls:
                raise ValueError(
                    f"LLM returned no tool calls despite tool_choice=required; "
                    f"finish_reason={data['choices'][0].get('finish_reason')!r}"
                )

            session.conversation.append(message)

            session.pending_tool_calls = [
                {
                    "id": tc["id"],
                    "tool_name": tc["function"]["name"],
                    "arguments": json.loads(tc["function"]["arguments"]),
                }
                for tc in raw_tool_calls
            ]
            session.state = _COMPLETE

        except Exception as exc:
            _logger.error(
                "LLM call failed for exploration %s: %s",
                session.exploration_id,
                exc,
                exc_info=True,
            )
            session.error = str(exc)
            session.state = _ERROR
