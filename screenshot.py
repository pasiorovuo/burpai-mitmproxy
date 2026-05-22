import datetime
import http
import json
import logging
import typing

import httpx
import mitmproxy.http

_logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are a web security analyst working within Burp Suite's broken access control testing "
    "tool. Your task is to examine a screenshot of a web page and determine whether the content "
    "shown is sensitive.\n\n"
    "Sensitive content includes: pages that require authentication to access, pages containing "
    "personal or financial data, internal admin interfaces, user-specific records or progress, "
    "credentials or tokens visible on screen, or any content that should not be publicly "
    "accessible.\n\n"
    "Classify the screenshot as SENSITIVE or NOT_SENSITIVE and explain your reasoning concisely."
)

_RESPONSE_SCHEMA: dict[str, typing.Any] = {
    "type": "json_schema",
    "json_schema": {
        "name": "screenshot_sensitivity",
        "strict": True,
        "schema": {
            "type": "object",
            "properties": {
                "classification": {
                    "type": "string",
                    "enum": ["SENSITIVE", "NOT_SENSITIVE"],
                },
                "reasoning": {"type": "string"},
            },
            "required": ["classification", "reasoning"],
            "additionalProperties": False,
        },
    },
}


def _hakawai_header() -> str:
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    ts = f"{now.strftime('%Y-%m-%dT%H:%M:%S')}.{now.microsecond:06d}000Z"
    return f"creditCost=1,balanceTimestamp={ts},planType=credit,balance=9999.11"


def _json_response(body: dict[str, typing.Any]) -> mitmproxy.http.Response:
    return mitmproxy.http.Response.make(
        status_code=200,
        content=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Portswigger-Hakawai-Ai": _hakawai_header(),
        },
    )


class ScreenshotHandler:
    async def handle(
        self,
        body: dict[str, typing.Any],
        backend_url: str,
        api_key: str,
        model: str,
    ) -> mitmproxy.http.Response:
        screenshot_b64: str | None = body.get("screenshotAsBase64")
        if not screenshot_b64:
            return mitmproxy.http.Response.make(
                status_code=int(http.HTTPStatus.INTERNAL_SERVER_ERROR),
                content=b"Missing screenshotAsBase64",
                headers={"Content-Type": "text/plain"},
            )

        payload: dict[str, typing.Any] = {
            "model": model,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": _SYSTEM_PROMPT},
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/png;base64,{screenshot_b64}",
                            },
                        },
                    ],
                }
            ],
            "response_format": _RESPONSE_SCHEMA,
            "max_completion_tokens": 1024,
        }

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
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

            result: dict[str, typing.Any] = json.loads(
                data["choices"][0]["message"]["content"]
            )
            return _json_response(
                {
                    "success": True,
                    "classification": result["classification"],
                    "reasoning": result["reasoning"],
                }
            )

        except Exception as exc:
            _logger.error("Screenshot sensitivity call failed: %s", exc, exc_info=True)
            return _json_response(
                {"success": False, "classification": None, "reasoning": None}
            )
