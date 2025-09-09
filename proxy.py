import http
import json
import logging
import re
import urllib.parse

import mitmproxy.addonmanager
import mitmproxy.ctx
import mitmproxy.exceptions
import mitmproxy.http

import prompts
import responses


BURP_AI_DOMAIN = "ai.portswigger.net"
# We store the original URL here so that we can handle the request/response
# appropriately after the request has been modified to point to the new URL.
ORIGINAL_URL_HEADER = "X-BurpAiProxy-Url"


class BurpAiProxy:
    def __init__(self) -> None:
        self._url = ""
        self._api_key = ""
        self._request_headers_blocklist: set[str] = set()
        self._response_headers_blocklist: set[str] = set()
        self._debug = False
        self._logger = logging.getLogger(__name__)

    def load(self, loader: mitmproxy.addonmanager.Loader) -> None:
        loader.add_option(
            default="",
            help=(
                "The Open AI compatible API base URL to which Burp AI requests should be redirected. "
                "e.g., https://api.openai.com/v1/chat/completions."
            ),
            name="url",
            typespec=str,
        )
        loader.add_option(
            default="",
            help="The API key to use when forwarding requests to the AI service.",
            name="api_key",
            typespec=str,
        )
        loader.add_option(
            default="Portswigger-Burp-Ai-Token",
            help="A comma-separated list of request headers (regex) to remove before forwarding to the AI service.",
            name="request_headers_denylist",
            typespec=str,
        )
        loader.add_option(
            default="",
            help="A comma-separated list of response headers (regex) to remove before sending back to the client.",
            name="response_headers_denylist",
            typespec=str,
        )
        loader.add_option(
            default=False,
            help=(
                "Enable debugging on the proxy."
                "In debug mode the proxy will forward unhandled requests to the Burp AI backend "
                "and log requests and responses in the console."
            ),
            name="debug",
            typespec=bool,
        )
        loader.add_option(
            default="gpt-4o",
            help="The AI model to use when forwarding requests to the AI service.",
            name="model",
            typespec=str,
        )

    def configure(self, updated: set[str]) -> None:
        # Handle changes in configuration
        if "url" in updated:
            self._url = mitmproxy.ctx.options.url

        if "api_key" in updated:
            self._api_key = mitmproxy.ctx.options.api_key

        if "request_headers_denylist" in updated:
            self._request_headers_blocklist = set(
                h.strip()
                for h in mitmproxy.ctx.options.request_headers_denylist.split(",")
                if h.strip()
            )

        if "response_headers_denylist" in updated:
            self._response_headers_blocklist = set(
                h.strip()
                for h in mitmproxy.ctx.options.response_headers_denylist.split(",")
                if h.strip()
            )

        if "debug" in updated:
            self._debug = mitmproxy.ctx.options.debug
            logging.basicConfig(level=logging.DEBUG if self._debug else logging.INFO)
            self._logger = logging.getLogger(__name__)

        if "model" in updated:
            prompts.Prompt.set_model(mitmproxy.ctx.options.model)

        # Validate required variables
        if not self._url:
            raise mitmproxy.exceptions.OptionsError("The `url` option is required.")
        if not self._api_key:
            raise mitmproxy.exceptions.OptionsError("The `api_key` option is required.")

    def request(self, flow: mitmproxy.http.HTTPFlow) -> None:
        # Handle only requests to the Burp AI domain
        if flow.request.pretty_host != BURP_AI_DOMAIN:
            return

        # Log original request
        self._log_rr(flow.request)

        # Handle specific paths as needed
        if flow.request.path == "/burp/balance":
            # Mock response for /burp/balance endpoint
            flow.response = responses.CreditBalanceResponse()
        elif flow.request.path == "/ai/hakawai-explain-this/api/v1/explainthis":
            self.proxy_request(
                flow=flow,
                prompt=prompts.ExplainThisPrompt(flow.request.text),
            )
        elif flow.request.path == "/ai/hakawai-montoya-service/api/v1/prompt":
            self.proxy_request(
                flow=flow,
                prompt=prompts.MontoyaPrompt(flow.request.text),
            )
        else:
            self._logger.warning(
                "\033[1;41mThis request was unhandled in burpai-proxy\033[0m"
            )

            # Deny the request if not in debug mode
            if not self._debug:
                flow.response = mitmproxy.http.Response.make(
                    http.HTTPStatus.INTERNAL_SERVER_ERROR,
                    b"This request was unhandled in burpai-proxy",
                    {"Content-Type": "text/plain"},
                )
                return

        # Log modified request
        self._log_rr(flow.request)

    def response(self, flow: mitmproxy.http.HTTPFlow) -> None:
        backend_url = urllib.parse.urlparse(self._url)

        if (
            flow.request.host != BURP_AI_DOMAIN
            and flow.request.host != backend_url.hostname
        ):
            # We haven't processed this request, ignore it
            return

        if flow.response is None:
            self._logger.warning("No response received")
            return

        # Log original response
        self._log_rr(flow.response)

        if ORIGINAL_URL_HEADER not in flow.request.headers:
            # This is not a request we have modified, ignore it
            return

        path = urllib.parse.urlparse(flow.request.headers[ORIGINAL_URL_HEADER]).path  # type: ignore

        # Remove unnecessary headers
        self._cleanup_headers(flow.response, self._response_headers_blocklist)

        # Add or update "standard" headers
        flow.response.headers.update(responses.headers())  # type: ignore

        # Handle specific paths as needed
        if path == "/ai/hakawai-explain-this/api/v1/explainthis":  # type: ignore
            self.handle_response(flow)
        elif path == "/ai/hakawai-montoya-service/api/v1/prompt":  # type: ignore
            self.handle_response(flow)
        else:
            self._logger.warning(
                "\033[1;41mThis response was unhandled in burpai-proxy\033[0m"
            )

        self._log_rr(flow.response)

    def proxy_request(
        self, flow: mitmproxy.http.HTTPFlow, prompt: prompts.Prompt
    ) -> None:
        self._cleanup_headers(flow.request, self._request_headers_blocklist)

        # Store original host and path in the request
        flow.request.headers[ORIGINAL_URL_HEADER] = flow.request.url

        # Add the API key to the request headers
        flow.request.headers["Authorization"] = f"Bearer {self._api_key}"

        # Redirect the request to the new URL
        flow.request.url = self._url

        # Set the request body to match Open AI format
        flow.request.text = prompt.text()

    def handle_response(self, flow: mitmproxy.http.HTTPFlow) -> None:
        if flow.response is None:
            self._logger.info("No response received")
            return

        try:
            data = json.loads(flow.response.text or "{}")
            message = data["choices"][0]["message"]
            del message["role"]
            flow.response.text = json.dumps(message)
        except Exception as e:
            print(f"Error processing response: {e}")

    def _cleanup_headers(
        self, rr: mitmproxy.http.Request | mitmproxy.http.Response, blocklist: set[str]
    ) -> None:
        """
        Remove any headers that should not be forwarded. Removes headers in place.
        """
        for regex in blocklist:
            for header in rr.headers:
                if re.match(regex, header, re.IGNORECASE):
                    del rr.headers[header]

    def _log_rr(
        self, r: mitmproxy.http.Request | mitmproxy.http.Response | None
    ) -> None:
        """
        Log the request/response if debugging is enabled.
        """
        if r is None:
            return

        if self._debug:
            # print() the request/response to avoid timestamps etc.
            print("-->")
            if isinstance(r, mitmproxy.http.Request):
                print(f"{r.method} {r.url} {r.http_version}")
            else:
                print(f"{r.status_code} {r.reason} {r.http_version}")
            print("\n".join([f"{k}: {v}" for k, v in r.headers.items()]))  # type: ignore
            print("")
            if r.content:
                print(r.content.decode("utf-8", errors="replace"))
            print("<--")


addons = [BurpAiProxy()]
