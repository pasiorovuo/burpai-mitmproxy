# Burp AI Proxy

A proxy implementation for intercepting and proxying Burp AI requests to a
custom OpenAI-compatible backend. Portswigger does not enable use of company-
managed AI implementations, so this project attempts to resolve the issue by
modifying and proxying the requests to a backend that can be managed by
organizations themselves, and thus avoid sending sensitive data to Portswigger
and the US.

The proxy denies all requests `ai.portswigger.net` if `debug` is not enabled
(the default). In `debug` mode the proxy forwards the requests to Portswigger,
and logs the requests and responses in the console.

## Installation

- Clone the repo
- Install `mitmproxy`
- Start `mitmproxy` with for example `mitmdump --listen-port 9001` to have
  `mitmproxy` create TLS certificates. Certificates are placed in
  `~/.mitmproxy` on Unix-based systems.
- Import the `mitmproxy` CA certificate to the Burp Suite CA certificate
  container. This step varies by OS.
  - MacOS: `keytool -importcert -alias mitmproxy -keystore /Applications/Burp\ Suite\ Professional.app/Contents/Resources/jre.bundle/Contents/Home/lib/security/cacerts -file ~/.mitmproxy/mitmproxy-ca-cert.cer`

## Running

- Start the proxy: `mitmdump --listen-port 9001 --script proxy.py --set url=<open ai chat completions URL> --set api_key=<your API key>`
- Configure a HTTP Proxy in Burp and point it to the running `mitmproxy`.

## Configuration

Configuration options are described below. They are set with
`--set option=value` command line parameters for `mitmdump`.

- `url`: The URL for the AI backend. This expects to be the full URL to an
  OpenAI `/v1/chat/completions` API.
- `api_key`: The Open AI compatible API key
- `debug`: Whether to enable debug. In debug mode the proxy will output all
  original and modified requests and their responses. Additionally, the proxy
  will forward the requests that it is unable to handle to the Burp AI backend
  so the requests and responses can be monitored. This is mainly for
  development. Defaults to `false`.
- `model`: Defines the AI model to use. Defaults to `gpt-4o`.
- `request_headers_denylist`: A comma-separated list of regex header names that
  are removed from the requests to the Open AI backend. Defaults to
  `Portswigger-Burp-Ai-Token`.
- `response_headers_denylist`: A comma-separated list of header regex names that
  are removed from the responses. Defaults to empty.
