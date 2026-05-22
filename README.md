# Burp AI Proxy

A proxy implementation for intercepting and proxying Burp AI requests to a
custom OpenAI-compatible backend. Portswigger does not enable use of company-
managed AI implementations, so this project attempts to resolve the issue by
modifying and proxying the requests to a OpenAI-compatible API backend that can
be managed by organizations themselves, and thus avoid sending sensitive data to
Portswigger and the US.

The proxy denies all requests to `ai.portswigger.net` unless `debug` is enabled
(the default). In `debug` mode the proxy forwards unhandled requests to
Portswigger and logs them to disk.

## Implemented features

- **Explain this** — single-shot explanation of a selected HTTP request or response
- **AI exploration** (`hakawai-explore-service`) — autonomous multi-step vulnerability
  exploration from Burp Repeater; the AI iterates over the target using HTTP requests
  and produces a final report
- **Screenshot sensitivity** (`hakawai-broken-access-control`) — classifies a screenshot
  as `SENSITIVE` or `NOT_SENSITIVE` using a vision-capable model, used by Burp's broken
  access control tooling
- **API extensions** — Montoya API prompt endpoint used by extensions such as Shadow Repeater

## Installation

### 1. Clone the repo and install dependencies

```bash
git clone <repo-url>
cd <repo-dir>
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Generate mitmproxy certificates

Run mitmproxy once to generate its CA certificate:

```bash
mitmdump --listen-port 9001
```

Certificates are written to `~/.mitmproxy/`. Stop mitmproxy after the
certificates appear.

### 3. Trust the mitmproxy CA certificate

Burp needs to trust mitmproxy's CA so it accepts the intercepted TLS connections.
How this is done depends on your OS and Burp version.

#### macOS

Newer Burp releases on macOS use the system Keychain rather than a bundled Java
keystore. Add the certificate to the **System** keychain so Burp picks it up:

```bash
sudo security add-trusted-cert \
  -d \
  -r trustRoot \
  -k /Library/Keychains/System.keychain \
  ~/.mitmproxy/mitmproxy-ca-cert.pem
```

You will be prompted for your administrator password. After adding the
certificate, verify it appears in **Keychain Access** under the **System**
keychain with trust set to **Always Trust**.

> **Note:** If Burp still does not trust the certificate, open Keychain Access,
> find the `mitmproxy` certificate in the System keychain, double-click it,
> expand the **Trust** section, and set **When using this certificate** to
> **Always Trust**.

#### macOS (older Burp releases)

If your Burp version ships its own JRE at
`/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/`,
import the certificate into the bundled Java keystore instead:

```bash
keytool -importcert \
  -alias mitmproxy \
  -keystore "/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/lib/security/cacerts" \
  -file ~/.mitmproxy/mitmproxy-ca-cert.cer
```

## Running

Activate the virtual environment first if it is not already active:

```bash
source .venv/bin/activate
```

```bash
mitmdump \
  --listen-port 9001 \
  --script proxy.py \
  --set url=<openai-compatible chat completions URL> \
  --set api_key=<your API key> \
  --set model=gpt-4o # Use a more capable model for better results
```

Then configure a HTTP proxy in Burp Suite and point `ai.portswigger.net` to
`127.0.0.1:9001`. It is not recommended to proxy all Burp traffic through
mitmproxy, as it may interfere with some vulnerability categories such as
request smuggling.

## Configuration

All options are passed as `--set option=value` arguments to `mitmdump`.

| Option | Default | Description |
|---|---|---|
| `url` | _(required)_ | Full URL to an OpenAI-compatible `/v1/chat/completions` endpoint |
| `api_key` | _(required)_ | API key for the AI backend |
| `model` | `gpt-4o` | Model to use. Must be vision-capable for screenshot classification |
| `save_dir` | _(none)_ | Directory where intercepted flows are saved as text files (created if absent) |
| `debug` | `false` | Forward unhandled requests to Portswigger and log all flows to console |
| `passthrough` | `false` | Forward **all** requests to Portswigger unmodified (requires `debug=true`). Use this to capture raw traffic for analysis |
| `request_headers_denylist` | `Portswigger-Burp-Ai-Token` | Comma-separated list of header name regexes stripped before forwarding to the AI backend |
| `response_headers_denylist` | _(none)_ | Comma-separated list of header name regexes stripped from responses |

