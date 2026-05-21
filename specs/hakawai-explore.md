# Hakawai Explore Service — Protocol Specification

## Overview

The `hakawai-explore-service` implements Burp AI's **autonomous vulnerability exploration** feature. When a user asks the AI to explain or exploit an issue from Burp Repeater (or similar tools), Burp initiates a multi-step agentic flow. The AI analyses the provided HTTP evidence, issues HTTP requests back to the target via a tool called `repeater`, iterates based on results, and finally produces a report via a `reporter` tool.

All traffic flows through:
```
POST /ai/hakawai-explore-service/api/v1/async/start
GET  /ai/hakawai-explore-service/api/v1/async/status/{step_id}
POST /ai/hakawai-explore-service/api/v1/async/continue
POST /ai/hakawai-explore-service/api/v1/async/finish
```

There is also a separate balance-check endpoint:
```
HEAD /burp/balance
```

---

## Session Identifiers

Two distinct UUIDs are used throughout a session:

| Identifier | Scope | First seen |
|---|---|---|
| `step_id` | One async task (polling target) | `/start` response and each `/continue` response |
| `exploration_id` | Entire session | First non-PENDING status response, or any PENDING response after the first step |

The `exploration_id` is **absent** from the `/start` response and from PENDING responses for the very first step. Once assigned, it is included in all subsequent status responses regardless of state.

The `/continue` request references `exploration_id`, not `step_id`.

---

## Response Header

All responses from this service include:

```
Portswigger-Hakawai-Ai: creditCost=0,balanceTimestamp=2026-05-18T17:47:28.282270370Z,planType=credit,balance=10000
```

Fields: `creditCost`, `balanceTimestamp` (ISO 8601 with nanoseconds), `planType`, `balance` (decimal).

The `/burp/balance` endpoint uses a slightly different order (`creditCost`, `balance`, `balanceTimestamp`) and omits `planType`.

**Proxy mock values:** The proxy does not have access to real billing data. Use static mock values:

```
Portswigger-Hakawai-Ai: creditCost=1,balanceTimestamp=<current UTC timestamp>,planType=credit,balance=9999.11
```

`balanceTimestamp` should be the current UTC time formatted as ISO 8601 with nanosecond precision (e.g. `2026-05-21T10:00:00.000000000Z`). For `/burp/balance` the header omits `planType` and uses the field order `creditCost`, `balance`, `balanceTimestamp`.

---

## Endpoint 1: POST /ai/hakawai-explore-service/api/v1/async/start

Initiates a new exploration session.

### Request

```
POST /ai/hakawai-explore-service/api/v1/async/start HTTP/1.1
Host: ai.portswigger.net
Content-Type: application/json; charset=utf-8
Portswigger-Burp-Ai-Token: <token>
```

```json
{
  "issue_definition": {
    "name": "REQUEST_RESPONSE_EXPLORE",
    "type": "INFORMATION",
    "detail": "Explain this issue and give me instructions on how to exploit it",
    "background": "",
    "target": "https://example.web-security-academy.net",
    "evidence": [
      {
        "type": "REQUEST_RESPONSE",
        "request": "<raw HTTP request string with \\r\\n line endings>",
        "response": "<raw HTTP response string with \\r\\n line endings>",
        "request_highlights": [],
        "response_highlights": [],
        "notes": null
      }
    ]
  },
  "profile": "repeater"
}
```

**Fields:**
- `issue_definition.name`: Always `"REQUEST_RESPONSE_EXPLORE"` for Repeater-initiated explorations.
- `issue_definition.type`: Always `"INFORMATION"` in observed captures.
- `issue_definition.detail`: The user's natural-language instruction.
- `issue_definition.background`: Empty string in observed captures.
- `issue_definition.target`: Target base URL.
- `evidence[].type`: Always `"REQUEST_RESPONSE"` in observed captures.
- `evidence[].request`: Full raw HTTP request string (`\r\n` line endings), or `null` if the user did not include a request.
- `evidence[].response`: Full raw HTTP response string (`\r\n` line endings), or `null` if the user did not include a response.
- `evidence[].notes`: User-provided annotation string, or `null` if absent.
- `profile`: Identifies the source Burp tool. Observed value: `"repeater"`.

**Evidence field combinations:** All three of `request`, `response`, and `notes` are independently nullable. The user controls which panes are attached when invoking the feature, so any combination is valid. Observed and expected combinations:

| `request` | `response` | `notes` | `*_highlights` non-empty | Observed | Context |
|---|---|---|---|---|---|
| string | string | null | no | yes | Standard capture — both HTTP sides, no annotation |
| string | string | string | no | yes | Both HTTP sides plus a user annotation |
| string | null | null | no | yes | Request only — user highlighted the request pane |
| null | string | null | no | yes | Response only — user highlighted the response pane |
| null | null | string | no | yes | Annotation only — no HTTP traffic attached |
| string | null | null | yes | yes | Request with highlighted substring(s) — user selected text before invoking AI |
| string | null | string | no | no | Request plus annotation, no response |
| null | string | string | no | no | Response plus annotation, no request |
| null | null | null | no | no | No evidence — all fields absent |

The proxy must handle all combinations. Fields that are `null` should simply be omitted from the prompt context rather than treated as errors.

**`request_highlights` / `response_highlights`:** Each is an array of verbatim substrings the user has selected/highlighted in the corresponding Burp pane. The observed format is an array of header-line strings (e.g. `["Accept-Language: en-GB,en;q=0.9"]`). When non-empty, the selected text should be surfaced in the prompt so the LLM understands what the user is specifically drawing attention to. These are always `[]` in most captures; the non-empty case was observed in flow `9a1a4844`.

### Response — 202 Accepted

```json
{
  "step_id": "d994787e-4c05-49a8-80a2-61c53f82cc02",
  "poll_interval_seconds": 5
}
```

**No `exploration_id`** is present in the start response. The client must poll `/status/{step_id}` to obtain it.

---

## Endpoint 2: GET /ai/hakawai-explore-service/api/v1/async/status/{step_id}

Polls the state of a running async step.

### Request

```
GET /ai/hakawai-explore-service/api/v1/async/status/{step_id} HTTP/1.1
Host: ai.portswigger.net
Portswigger-Burp-Ai-Token: <token>
```

No request body.

### Response — 200 OK

Three possible states:

#### PENDING (first step)

```json
{
  "step_id": "d994787e-4c05-49a8-80a2-61c53f82cc02",
  "state": "PENDING",
  "retry_count": 0,
  "poll_interval_seconds": 5
}
```

`exploration_id` is **absent** in PENDING responses for the first step (before the exploration_id has been assigned).

#### PENDING (subsequent steps)

```json
{
  "step_id": "b701ce59-57bd-4837-ba58-a8c16890d906",
  "state": "PENDING",
  "exploration_id": "8ea7078d-face-488b-8467-4ec81a52cef0",
  "retry_count": 0,
  "poll_interval_seconds": 5
}
```

Once an `exploration_id` has been assigned, PENDING responses for subsequent steps include it.

#### PROCESSING

```json
{
  "step_id": "d994787e-4c05-49a8-80a2-61c53f82cc02",
  "state": "PROCESSING",
  "exploration_id": "d35de644-0e52-489b-bf02-9a716078e17f",
  "retry_count": 0,
  "poll_interval_seconds": 5
}
```

#### COMPLETE (single tool call)

```json
{
  "step_id": "d994787e-4c05-49a8-80a2-61c53f82cc02",
  "state": "COMPLETE",
  "exploration_id": "d35de644-0e52-489b-bf02-9a716078e17f",
  "response": {
    "exploration_id": "d35de644-0e52-489b-bf02-9a716078e17f",
    "step_title": "Extract username via CAST error injection",
    "step_action": "<AI reasoning text explaining what to do next and why>",
    "tool_calls": [
      {
        "id": "toolu_012KQVpUA24997ucX8SxTbVh",
        "tool_name": "repeater",
        "arguments": {
          "request": "<raw HTTP request to send to target>",
          "learnings": "<what the AI learned from the previous step>",
          "progress": "<AI summary of exploitation progress>",
          "knowledge": "<accumulated facts about the target>",
          "step_title": "<LLM-generated; copied to response.step_title>",
          "step_action": "<LLM-generated; copied to response.step_action>"
        }
      }
    ]
  },
  "retry_count": 0
}
```

#### COMPLETE (multiple tool calls)

The server may return more than one tool call in a single COMPLETE response. The client executes all of them and submits all results together in one `/continue` request:

```json
{
  "step_id": "6fc383b7-ae69-4f53-a145-ab879affbedc",
  "state": "COMPLETE",
  "exploration_id": "05fa8599-d327-4c5b-ab0f-a74b6272bed4",
  "response": {
    "exploration_id": "05fa8599-d327-4c5b-ab0f-a74b6272bed4",
    "step_title": "Fetch homepage to discover more endpoints",
    "step_action": "<AI reasoning>",
    "tool_calls": [
      {
        "id": "toolu_01BK4HCTLSgFqG5cEM4nBVd8",
        "tool_name": "repeater",
        "arguments": {
          "request": "GET / HTTP/1.1\nHost: ...",
          "learnings": "...",
          "progress": "...",
          "knowledge": "...",
          "step_title": "Fetch homepage to discover more endpoints",
          "step_action": "..."
        }
      },
      {
        "id": "toolu_01Ao6qJibQiyNSKBpMZrydHg",
        "tool_name": "repeater",
        "arguments": {
          "request": "GET /product?productId=20 HTTP/1.1\nHost: ...",
          "learnings": "...",
          "progress": "...",
          "knowledge": "...",
          "step_title": "Test TrackingId cookie for SQL injection",
          "step_action": "..."
        }
      }
    ]
  },
  "retry_count": 0
}
```

**Key structural observations:**
- `response.step_title` and `response.step_action` are duplicated inside `arguments`. The top-level `response.step_title` / `response.step_action` are display labels; the copies inside `arguments` are passed as tool context.
- `tool_calls` contains **one or more** entries. Multiple tool calls in a step are all executed and all results are submitted in the next `/continue`.
- Tool call IDs use the `toolu_` prefix (Anthropic Claude tool use format).
- Field name is `tool_name` (not `name`) and `arguments` (not `function.arguments`).

---

## Endpoint 3: POST /ai/hakawai-explore-service/api/v1/async/continue

Submits tool execution results and advances the session to the next step.

### Request

```
POST /ai/hakawai-explore-service/api/v1/async/continue HTTP/1.1
Host: ai.portswigger.net
Content-Type: application/json; charset=utf-8
Portswigger-Burp-Ai-Token: <token>
```

```json
{
  "exploration_id": "d35de644-0e52-489b-bf02-9a716078e17f",
  "tool_results": [
    {
      "tool_id": "toolu_012KQVpUA24997ucX8SxTbVh",
      "result": "<raw HTTP response string, or an error message string>"
    }
  ]
}
```

When the preceding COMPLETE response contained multiple tool calls, the client submits all results in the same `/continue` body:

```json
{
  "exploration_id": "05fa8599-d327-4c5b-ab0f-a74b6272bed4",
  "tool_results": [
    {
      "tool_id": "toolu_01BK4HCTLSgFqG5cEM4nBVd8",
      "result": "HTTP/2 200 OK\r\n..."
    },
    {
      "tool_id": "toolu_01Ao6qJibQiyNSKBpMZrydHg",
      "result": "HTTP/2 500 Internal Server Error\r\n..."
    }
  ]
}
```

**Fields:**
- `exploration_id`: The session identifier obtained from the status response.
- `tool_results[].tool_id`: Matches the `id` field of the corresponding tool_call from the COMPLETE status response. One entry per tool call returned in the COMPLETE step.
- `tool_results[].result`: For `repeater` tool: the full raw HTTP response from the target (with `\r\n` line endings). For error conditions: a plain-text error string (see Loop Detection below).

### Response — 202 Accepted

```json
{
  "step_id": "d93c7bd8-6840-4933-a8bd-73f8e1478438",
  "exploration_id": "d35de644-0e52-489b-bf02-9a716078e17f",
  "poll_interval_seconds": 5
}
```

The new `step_id` is used for subsequent polling. The `exploration_id` is unchanged throughout the session.

---

## Endpoint 4: POST /ai/hakawai-explore-service/api/v1/async/finish

Used instead of `/continue` when Burp could not execute a `repeater` tool call — e.g. the target was unreachable, the request timed out, or the lab expired. The request structure is identical to `/continue` but the `result` field is always an empty string.

### Request

```
POST /ai/hakawai-explore-service/api/v1/async/finish HTTP/1.1
Host: ai.portswigger.net
Content-Type: application/json; charset=utf-8
Portswigger-Burp-Ai-Token: <token>
```

```json
{
  "exploration_id": "bbac780a-f9b8-406e-b147-45efe9593799",
  "tool_results": [
    {
      "tool_id": "toolu_015s5ohtbCvoY7BbXSsSQ3cU",
      "result": ""
    }
  ]
}
```

The `tool_id` matches the `id` of the `repeater` tool call from the preceding COMPLETE response. The empty `result` signals that no HTTP response was obtained.

### Response — 202 Accepted

Identical structure to `/continue`:

```json
{
  "step_id": "b14fd2bd-8e67-4e29-a0cf-f6bb06e237ca",
  "exploration_id": "bbac780a-f9b8-406e-b147-45efe9593799",
  "poll_interval_seconds": 5
}
```

Burp continues polling the returned `step_id` normally. In the observed sequence the LLM responded to the empty result by producing a `reporter` tool call to conclude the session gracefully.

### Proxy handling

Route `/finish` through the same logic as `/continue`. The empty result string is passed to the LLM as the tool result content; the LLM is expected to recognise that execution failed and call `reporter` to end the session.

---

## Endpoint 5: HEAD /burp/balance

Returns the current AI credit balance. No request body.

### Request

```
HEAD /burp/balance HTTP/1.1
Host: ai.portswigger.net
Portswigger-Burp-Ai-Token: <token>
```

### Response — 200 OK

Headers include:
```
Portswigger-Hakawai-Ai: creditCost=0.00000000000000000,balance=9999.111,balanceTimestamp=2026-05-18T17:56:26.651104Z
```

No response body. (Captured flows show a body present from the real backend, but that is non-standard for HEAD and the proxy must not return one.)

---

## Tool Types

### `repeater`

Instructs Burp to send an HTTP request to the target and return the response.

Arguments:
| Field | Type | Description |
|---|---|---|
| `request` | string | Full raw HTTP request (LF-terminated lines in observed captures) |
| `learnings` | string | AI reasoning about what was learned from the previous result |
| `progress` | string | Summary of exploitation progress so far |
| `knowledge` | string | Accumulated facts about the target environment |
| `step_title` | string | Short label for this step |
| `step_action` | string | Description of what this request is intended to accomplish |

The client executes the request and returns the raw HTTP response as the `result` string in `/continue`.

### `reporter`

The terminal tool. Signals the end of the exploration. Burp displays the report to the user and does **not** send another `/continue` after a `reporter` tool call.

Arguments:
| Field | Type | Description |
|---|---|---|
| `report` | string | Markdown-formatted final report with vulnerability details and extracted data |
| `learnings` | string | Final learnings summary |
| `progress` | string | Final progress summary |
| `knowledge` | string | Final accumulated knowledge |
| `step_title` | string | Short label for the final step |
| `step_action` | string | Description of what the report represents |

---

## State Machine

```
Client                              Server
  |                                   |
  |--- POST /async/start ------------>|
  |<-- 202 { step_id }               |
  |                                   |
  |--- GET /status/{step_id} -------->|
  |<-- 200 { PENDING }               |  (repeat until not PENDING)
  |--- GET /status/{step_id} -------->|
  |<-- 200 { PROCESSING }            |  (repeat until COMPLETE)
  |--- GET /status/{step_id} -------->|
  |<-- 200 { COMPLETE, tool_calls }  |
  |                                   |
  | [attempt to execute tool]         |
  |                                   |
  |--- POST /async/continue ---------->|  (tool executed successfully)
  |    { exploration_id, tool_results }|
  |<-- 202 { new_step_id, exploration_id } |
  |                                   |
  |  OR                               |
  |                                   |
  |--- POST /async/finish ----------->|  (tool execution failed/empty)
  |    { exploration_id,              |
  |      tool_results[result=""] }    |
  |<-- 202 { new_step_id, exploration_id } |
  |                                   |
  | [repeat status polling +          |
  |  continue/finish until            |
  |  tool_name == "reporter"]         |
  |                                   |
  | [display report to user]          |
  | [no further request sent]         |
```

Poll interval is dictated by `poll_interval_seconds` (observed value: always 5 seconds).

---

## Loop Detection

The proxy (client-side) tracks previously sent `repeater` requests within a session. If the AI requests the same HTTP request that was already sent, the client returns the following `result` string instead of executing the request:

```
You have sent this request before. You are stuck in a loop. Try something else!
```

This is handled by the client (Burp), not the server. The server continues processing the loop-detection result as a normal tool result.

---

## Observed Request Sequence (Example)

The following sequence was captured for a visible error-based SQL injection lab:

| Step | step_id prefix | Tool | Action |
|---|---|---|---|
| 1 | `d994787e` | `repeater` | Extract username via CAST: `xyz' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--` |
| 2 | `d93c7bd8` | `repeater` | Try URL-encoded semicolon approach |
| 3 | `e20e1205` | `repeater` | Retry AND CAST injection (loop detection triggered) |
| 4 | `8cd425a7` | `repeater` | Simpler CAST without prefix: `' AND CAST(...) AS int)=1--` → reveals `administrator` |
| 5 | `41732de0` | `repeater` | Extract password (wrong host — typo in hostname) |
| 6 | `86227dcd` | `repeater` | Extract password (loop detection triggered, same request as step 3) |
| 7 | `62429970` | `repeater` | Simpler password extraction → reveals `ozttz0wrctelv9w3stu1` |
| 8 | `a4c06fd5` | `reporter` | Final report with credentials `administrator / ozttz0wrctelv9w3stu1` |

All steps share `exploration_id = d35de644-0e52-489b-bf02-9a716078e17f`.

---

## Implementation Notes

### Session State to Persist

For each active exploration, the proxy must track:

```
exploration_id       UUID, obtained from first non-PENDING status response
current_step_id      UUID, updated after each /start and /continue
step_state           PENDING | PROCESSING | COMPLETE
pending_tool_calls   List of { tool_id, tool_name, arguments }, saved from each COMPLETE response (one or more)
conversation_history Full message list for LLM continuity
sent_requests        Set of raw request strings for loop detection
```

### Proxy Responsibilities

1. **On `/start`**: Create a new exploration session. Call the LLM with the issue_definition and tool definitions. Return a `step_id` immediately (202). Begin async LLM generation.
2. **On `/status/{step_id}`**: Return current state. PENDING while LLM has not started; PROCESSING while generating; COMPLETE once tool_calls are ready. Include `exploration_id` in PENDING responses once the exploration has been assigned one (i.e., all steps after the first). `retry_count` is always `0`.
3. **On `/continue`**: Look up the exploration by `exploration_id`. Feed all tool results back to the LLM as tool messages (one message per result). Generate the next step. Return a new `step_id` (202).
4. **On `/finish`**: Identical handling to `/continue`. The empty `result` string is passed to the LLM as the tool result content. The LLM is expected to call `reporter` in response.
5. **On reporter tool**: Return COMPLETE with `tool_name: "reporter"`. Burp displays the report and sends no further request.
6. **Multi-tool-call steps**: When the LLM returns multiple tool calls in one step, include all of them in the COMPLETE response, preserving their order. The client will execute all and return all results in one `/continue`. Feed each result as a separate tool message to the LLM, in the same order.
7. **Loop detection**: The proxy checks previously sent `repeater` requests. If the AI issues an identical request string, the proxy returns the loop-detection string as the tool result without executing the request.
8. **`response.step_title` / `response.step_action`**: Populate these by copying directly from the tool call's `arguments.step_title` and `arguments.step_action`. These are produced by the LLM as part of the tool arguments and surfaced to Burp's UI via the top-level response fields.
9. **Unknown `step_id` or `exploration_id`**: Return HTTP 500 with a plain error body. Behaviour on the Burp side is unknown; fail loudly rather than silently.

### Prompt Construction

The LLM call must include:

**System prompt** — establish the agent's role and capabilities. Cover:
- Burp Suite's purpose (web security testing tool) and what this feature does (agentic vulnerability exploration from Repeater)
- The agent's task: analyse the provided HTTP evidence, use the `repeater` tool to send requests and observe responses, iterate, and produce a final report via the `reporter` tool
- Behavioural constraints: be methodical, avoid repeating identical requests, prefer targeted payloads, summarise learning at each step
- **Required output format**: the LLM must always respond via a tool call — either `repeater` (to continue) or `reporter` (to conclude). It must never produce a plain-text response. All fields in the tool arguments (`step_title`, `step_action`, `learnings`, `progress`, `knowledge`, and either `request` or `report`) are required.

**User turn** — assemble from `issue_definition`:
- The user's instruction from `detail` (e.g. "Explain this issue and give me instructions on how to exploit it")
- The target URL from `target`
- Each evidence item, formatted according to what fields are present:
  - Both request and response: include both with clear labels
  - Request only: include the request; note that no response was captured
  - Response only: include the response; note that no request was captured
  - Notes only: include the annotation text; note that no HTTP traffic was attached
  - Combinations with both HTTP and notes: include all present fields
  - If `request_highlights` or `response_highlights` is non-empty, call out the highlighted substring(s) explicitly so the LLM understands the user is drawing attention to specific text
- `background` if non-empty (always empty in observed captures, but include if present)

**Tool definitions** — both `repeater` and `reporter` must be provided as OpenAI-format tool definitions. Every argument field must be present in the schema's `properties` and listed in `required`. This is what causes the LLM to populate them — if a field is absent from `required`, the LLM will omit it silently.

**`tool_choice`** — set to `required` in the OpenAI API call so the LLM is forced to respond via a tool call at every step. If the LLM returns a plain-text response despite this (e.g. due to a model or configuration issue), the proxy must treat it as an error rather than attempting to parse it as a tool call.

The `description` of each field is load-bearing: it tells the LLM what content to generate. Suggested descriptions:

`repeater`:
- `request`: The full raw HTTP request to send to the target, with LF line endings. Include all necessary headers.
- `step_title`: A short label for this step (used in the Burp UI).
- `step_action`: A concise description of what this request is intended to accomplish and why.
- `learnings`: What you learned from the previous response that motivates this request.
- `progress`: A summary of exploitation progress so far.
- `knowledge`: Accumulated facts about the target: technology stack, confirmed vulnerabilities, extracted values.

`reporter`:
- `report`: A markdown-formatted report of the full investigation: vulnerability found, exploitation steps, extracted data, and any recommendations.
- `step_title`: A short label for the final step (used in the Burp UI).
- `step_action`: A concise description of what the report covers.
- `learnings`: Final summary of what was learned during the exploration.
- `progress`: Final exploitation progress summary.
- `knowledge`: Final accumulated knowledge about the target.

The LLM decides when to call `reporter`. It should do so when the investigation is complete, when no further progress is possible, or when the user's original question has been answered.

**Line endings**: evidence `request`/`response` fields use `\r\n`. The `request` field inside `repeater` tool arguments uses `\n` in observed captures. Follow the same convention: pass the LLM-generated request string as-is (with `\n`) to the target; do not normalise.

**Conversation history**: maintain the full message list across steps. On `/continue`, append:
1. An assistant message containing the tool call(s) from the COMPLETE step
2. One tool result message per tool call, in the same order as the tool calls, each with `tool_call_id` matching the call's `id` and `content` set to the raw HTTP response string (or the loop-detection string)

### OpenAI Backend Translation

The Burp wire format uses an Anthropic-native tool call structure. Mapping to/from OpenAI format:

| Burp wire format | OpenAI format |
|---|---|
| `tool_calls[].id` | `tool_calls[].id` |
| `tool_calls[].tool_name` | `tool_calls[].function.name` |
| `tool_calls[].arguments` (object) | `tool_calls[].function.arguments` (JSON string) |
| `tool_results[].tool_id` | `tool_call_id` in tool message |
| `tool_results[].result` | `content` in tool message |

### SQLite Recommendation

This flow spans multiple HTTP round-trips over seconds to minutes. In-memory state is sufficient for single-instance operation, but SQLite is appropriate if:
- Sessions must survive proxy restarts
- Multiple concurrent explorations need tracking
- Debugging requires queryable session history

Minimum schema:
```sql
CREATE TABLE explorations (
    exploration_id TEXT PRIMARY KEY,
    step_id TEXT NOT NULL,
    state TEXT NOT NULL,  -- PENDING | PROCESSING | COMPLETE | DONE
    tool_calls_json TEXT,  -- JSON array of {id, tool_name, arguments}; one or more entries per COMPLETE step
    conversation_json TEXT NOT NULL,
    sent_requests_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
```
