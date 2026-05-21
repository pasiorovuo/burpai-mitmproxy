import http
import json
import logging
import pathlib
import re
import urllib.parse
import uuid
import io
from typing import cast

import mitmproxy.addonmanager
import mitmproxy.ctx
import mitmproxy.exceptions
import mitmproxy.http
import mitmproxy.proxy.server_hooks

import explore
import prompts
import responses

# Bump this constant after every change to ensure mitmdump reloads the addon.
_VERSION = 1

_EXPLORE_BASE = "/ai/hakawai-explore-service/api/v1/async"
_EXPLORE_STATUS_RE = re.compile(r"^/ai/hakawai-explore-service/api/v1/async/status/([^/]+)$")

BURP_AI_DOMAIN = "ai.portswigger.net"
# We store the original URL here so that we can handle the request/response
# appropriately after the request has been modified to point to the new URL.
ORIGINAL_URL_HEADER = "X-BurpAiProxy-Url"
FLOW_UUID_METADATA_KEY = "burpai_proxy_flow_uuid"


class BurpAiProxy:
    def __init__(self) -> None:
        self._url = ""
        self._api_key = ""
        self._save_dir: pathlib.Path | None = None
        self._request_headers_blocklist: set[str] = set()
        self._response_headers_blocklist: set[str] = set()
        self._debug = False
        self._logger = logging.getLogger(__name__)
        self._explore = explore.ExploreHandler()

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
            default="",
            help=(
                "An optional directory in which completed Burp-side flows are saved as "
                "text files."
            ),
            name="save_dir",
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

        if "save_dir" in updated:
            save_dir = mitmproxy.ctx.options.save_dir.strip()
            self._save_dir = None
            if save_dir:
                path = pathlib.Path(save_dir).expanduser()
                path.mkdir(parents=True, exist_ok=True)
                if not path.is_dir():
                    raise mitmproxy.exceptions.OptionsError(
                        "The `save_dir` option must point to a directory."
                    )
                self._save_dir = path

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
        self._save_request(flow, flow.request, original=True)

        # Handle specific paths as needed
        if flow.request.path == "/burp/balance":
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
        elif flow.request.path == f"{_EXPLORE_BASE}/start":
            body = json.loads(flow.request.text or "{}")
            flow.response = self._explore.handle_start(
                body, self._url, self._api_key, prompts.Prompt.model()
            )
        elif m := _EXPLORE_STATUS_RE.match(flow.request.path):
            flow.response = self._explore.handle_status(m.group(1))
        elif flow.request.path == f"{_EXPLORE_BASE}/continue":
            body = json.loads(flow.request.text or "{}")
            flow.response = self._explore.handle_continue(
                body, self._url, self._api_key, prompts.Prompt.model()
            )
        elif flow.request.path == f"{_EXPLORE_BASE}/finish":
            body = json.loads(flow.request.text or "{}")
            flow.response = self._explore.handle_finish(
                body, self._url, self._api_key, prompts.Prompt.model()
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
        self._save_request(flow, flow.request, original=False)

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
        self._save_response(flow, original=True)

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

        self._save_response(flow, original=False)

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
            self._logger.warning(f"Error processing response: {e}")

    def _save_request(
        self,
        flow: mitmproxy.http.HTTPFlow,
        request: mitmproxy.http.Request,
        original: bool,
    ) -> None:
        message = self._serialize_message(request)
        if message is None:
            return

        message = (
            f"--- {'Original' if original else 'Modified'} Request ---\n"
            f"{message}\n"
            f"--- End {'Original' if original else 'Modified'} Request ---\n"
        )

        self._save_message(flow, message)

    def _save_response(self, flow: mitmproxy.http.HTTPFlow, original: bool) -> None:
        if flow.response is None:
            return

        message = self._serialize_message(flow.response)
        if message is None:
            return

        message = (
            f"--- {'Original' if original else 'Modified'} Response ---\n"
            f"{message}\n"
            f"--- End {'Original' if original else 'Modified'} Response ---\n"
        )
        self._save_message(flow, message)

    def _save_message(self, flow: mitmproxy.http.HTTPFlow, message: str) -> None:
        file_path = self._get_save_filename(flow)
        if file_path is None:
            return

        with file_path.open("a") as handle:
            handle.write(message)
            handle.write("\n\n")
            handle.flush()

    def _get_save_filename(self, flow: mitmproxy.http.HTTPFlow) -> pathlib.Path | None:
        if self._save_dir is None:
            return None

        flow_uuid = flow.metadata.get(FLOW_UUID_METADATA_KEY)
        if not isinstance(flow_uuid, str) or not flow_uuid:
            flow_uuid = str(uuid.uuid4())
            flow.metadata[FLOW_UUID_METADATA_KEY] = flow_uuid

        return self._save_dir / f"{flow_uuid}.txt"

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

    def _serialize_message(
        self, r: mitmproxy.http.Request | mitmproxy.http.Response | None
    ) -> str | None:
        if r is None:
            return None

        s = io.StringIO()
        # Write the start line
        if isinstance(r, mitmproxy.http.Request):
            s.write(f"{r.method} {r.url} {r.http_version}\n")
        else:
            s.write(f"{r.http_version} {r.status_code} {r.reason}\n")

        # Write the headers
        s.writelines(
            [f"{k}: {v}\n" for k, v in cast(tuple[str, str], r.headers.items())],
        )

        # Write a blank line to separate headers from the body
        s.write("\n")

        if r.content:
            s.write(
                self._format_message_body(
                    r.content,
                    r.headers.get("content-type", ""),  # type: ignore
                )
            )

        return s.getvalue()

    def _format_message_body(self, content: bytes, content_type: str) -> str:
        decoded = content.decode("utf-8", errors="replace")

        media_type = content_type.split(";", 1)[0].strip().lower()
        if media_type != "application/json":
            return decoded

        try:
            parsed = json.loads(decoded)
        except json.JSONDecodeError:
            return decoded

        return json.dumps(parsed, indent=2, ensure_ascii=False)

    def server_connect(
        self, data: mitmproxy.proxy.server_hooks.ServerConnectionHookData
    ) -> None:
        """
        Hook to modify the server connection before it is established. Prevents
        connections to the original Burp AI domain and redirects them to the
        configured backend URL.
        """
        if not self._debug:
            host, _ = data.server.address if data.server.address else ("", 0)
            if host == BURP_AI_DOMAIN:
                backend_url = urllib.parse.urlparse(self._url)
                data.server.address = (
                    str(backend_url.hostname),
                    backend_url.port or 443,
                )
                data.server.sni = backend_url.hostname


addons = [BurpAiProxy()]
