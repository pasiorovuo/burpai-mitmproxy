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

### 1. Get the latest version

`burpai-mitmproxy` is published as Docker containers in the Github Container Registry.
The versioning scheme is based on build dates. Navigate to
https://github.com/pasiorovuo/burpai-mitmproxy/pkgs/container/burpai-mitmproxy and
find the latest version available. Pull the image with

```bash
docker pull ghcr.io/pasiorovuo/burpai-mitmproxy:<version acquired above>
```

### 2. Create an env file (optional)

The container requires below environment variables. Either create an .env file or
pass them otherwise (e.g. with -e). It's important to point the url to the exact
chat completions endpoint instead of the base URL.

```ini
CHAT_COMPLETION_API_KEY=...
CHAT_COMPLETION_MODEL=...
CHAT_COMPLETION_URL=.../v1/chat/completions
```

### 3. Start the container

Start mitmproxy and it will generate the certificates.

```bash
docker run --detach --name burpai-mitmproxy -p 9001:9001 --env-file .env burpai-mitmproxy:<version>
```

### 4. Copy the certificate off the container

Certificates are written to `/home/mitmproxy/.mitmproxy/`. Copy them with

```bash
docker cp burpai-mitmproxy:/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.cer .
```

### 5. Trust the mitmproxy CA certificate

Burp needs to trust mitmproxy's CA so it accepts the intercepted TLS connections.
How this is done depends on your OS and Burp version.

N.B. This step needs to be repeated every time the container is recreated.

#### macOS

Newer Burp releases on macOS use the system Keychain rather than a bundled Java
keystore. Add the certificate to the **System** keychain so Burp picks it up:

```bash
sudo security add-trusted-cert \
  -d \
  -r trustRoot \
  -k /Library/Keychains/System.keychain \
  mitmproxy-ca-cert.pem
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
  -file mitmproxy-ca-cert.cer
```

## Running

The container can be started with

```bash
docker run --detach --name burpai-mitmproxy -p 9001:9001 --env-file .env burpai-mitmproxy:<version>
```

If you've followed above installation steps, the container is already running.

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
| `model` | `gpt-4o` | Model to use. Use a more capabel model such as Anthropic's Claude 4.6 for better results. Must be vision-capable for screenshot classification |
| `save_dir` | _(none)_ | Directory where intercepted flows are saved as text files (created if absent) |
| `debug` | `false` | Forward unhandled requests to Portswigger and log all flows to console |
| `passthrough` | `false` | Forward **all** requests to Portswigger unmodified (requires `debug=true`). Use this to capture raw traffic for analysis |
| `request_headers_denylist` | `Portswigger-Burp-Ai-Token` | Comma-separated list of header name regexes stripped before forwarding to the AI backend |
| `response_headers_denylist` | _(none)_ | Comma-separated list of header name regexes stripped from responses |

