# Screenshot Sensitivity Service — Protocol Specification

## Overview

The `hakawai-broken-access-control` service exposes a screenshot classification endpoint used by Burp's broken access control tooling. It accepts a PNG screenshot as base64, sends it to a vision-capable AI model, and returns a sensitivity classification with reasoning.

The endpoint is **synchronous** — there is no async/polling step. A single POST returns the result directly.

```
POST /ai/hakawai-broken-access-control/api/v1/screenshot-sensitivity
```

---

## Endpoint: POST /ai/hakawai-broken-access-control/api/v1/screenshot-sensitivity

### Request

```
POST /ai/hakawai-broken-access-control/api/v1/screenshot-sensitivity HTTP/1.1
Host: ai.portswigger.net
Content-Type: application/json; charset=utf-8
Portswigger-Burp-Ai-Token: <token>
```

```json
{
  "screenshotAsBase64": "<base64-encoded PNG>"
}
```

**Fields:**
- `screenshotAsBase64`: A base64-encoded PNG image of the screen content to be classified. No data-URI prefix — raw base64 only.

### Response — 200 OK

```json
{
  "success": true,
  "classification": "SENSITIVE",
  "reasoning": "The screenshot shows a page from a security training platform indicating that a lab has been solved, which suggests user-specific progress. The presence of a 'My account' link and a 'Solved' status further indicates that this is a personalized area requiring authentication."
}
```

**Fields:**
- `success`: Boolean. `true` when the model returned a usable result.
- `classification`: String enum. Observed value: `"SENSITIVE"`. Expected values: `"SENSITIVE"` | `"NOT_SENSITIVE"`.
- `reasoning`: Plain-text explanation of why the classification was assigned.

**Response header** (same format as all other services):
```
Portswigger-Hakawai-Ai: creditCost=20.547,balanceTimestamp=2026-05-22T04:32:21.478347286Z,planType=credit,balance=6383.75338
```

---

## Implementation Notes

### Prompt Construction

The LLM must receive the image via the OpenAI vision message format:

```json
{
  "role": "user",
  "content": [
    {
      "type": "text",
      "text": "<system + task instructions>"
    },
    {
      "type": "image_url",
      "image_url": {
        "url": "data:image/png;base64,<screenshotAsBase64>"
      }
    }
  ]
}
```

**System/task instructions** should direct the model to:
- Act as a web security analyst assessing whether a screenshot contains sensitive information
- Consider: authentication state (logged-in pages, account details), personal or financial data, internal admin interfaces, user-specific progress or records, credentials or tokens visible on screen
- Respond with exactly one of `SENSITIVE` or `NOT_SENSITIVE` and a plain-text explanation
- Context: this is used within Burp Suite's broken access control testing feature to determine whether a page that is accessible without authentication actually contains sensitive content

### LLM Output Format

Use OpenAI structured output to guarantee a parseable response. Include in the API call:

```json
{
  "response_format": {
    "type": "json_schema",
    "json_schema": {
      "name": "screenshot_sensitivity",
      "strict": true,
      "schema": {
        "type": "object",
        "properties": {
          "classification": {
            "type": "string",
            "enum": ["SENSITIVE", "NOT_SENSITIVE"]
          },
          "reasoning": {
            "type": "string"
          }
        },
        "required": ["classification", "reasoning"],
        "additionalProperties": false
      }
    }
  }
}
```

The proxy parses `choices[0].message.content` as JSON and reads `classification` and `reasoning` directly.

### Response Construction

The proxy maps the LLM output to the Burp wire format:

| LLM output | Burp response field |
|---|---|
| `classification` | `classification` |
| `reasoning` | `reasoning` |
| LLM call succeeded | `success: true` |
| LLM call failed | `success: false` |

### Model Requirement

The backend model must support vision (image input). Standard text-only models will not work for this endpoint. The proxy must use a vision-capable model (e.g. `gpt-4o`) regardless of the configured default model, or fail loudly if the configured model does not support images.

### Error Handling

If the LLM call fails or returns an unparseable response, return:
```json
{
  "success": false,
  "classification": null,
  "reasoning": null
}
```

Use HTTP 200 in both success and failure cases, matching observed backend behaviour.
