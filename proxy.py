import datetime
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
_VERSION = 2

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

        if not self._url:
            raise mitmproxy.exceptions.OptionsError("The `url` option is required.")
        if not self._api_key:
            raise mitmproxy.exceptions.OptionsError("The `api_key` option is required.")

    def request(self, flow: mitmproxy.http.HTTPFlow) -> None:
        if flow.request.pretty_host != BURP_AI_DOMAIN:
            return

        # Save what Burp sent, before any modification.
        self._save_request(flow)

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
            if not self._debug:
                flow.response = mitmproxy.http.Response.make(
                    http.HTTPStatus.INTERNAL_SERVER_ERROR,
                    b"This request was unhandled in burpai-proxy",
                    {"Content-Type": "text/plain"},
                )

    def response(self, flow: mitmproxy.http.HTTPFlow) -> None:
        backend_url = urllib.parse.urlparse(self._url)

        if (
            flow.request.host != BURP_AI_DOMAIN
            and flow.request.host != backend_url.hostname
        ):
            return

        if flow.response is None:
            self._logger.warning("No response received")
            return

        if ORIGINAL_URL_HEADER not in flow.request.headers:
            # Locally handled request — response is already final.
            self._save_response(flow)
            return

        path = urllib.parse.urlparse(flow.request.headers[ORIGINAL_URL_HEADER]).path  # type: ignore

        self._cleanup_headers(flow.response, self._response_headers_blocklist)
        flow.response.headers.update(responses.headers())  # type: ignore

        if path == "/ai/hakawai-explain-this/api/v1/explainthis":  # type: ignore
            self.handle_response(flow)
        elif path == "/ai/hakawai-montoya-service/api/v1/prompt":  # type: ignore
            self.handle_response(flow)
        else:
            self._logger.warning(
                "\033[1;41mThis response was unhandled in burpai-proxy\033[0m"
            )

        # Save what Burp receives, after all transformations.
        self._save_response(flow)

    def proxy_request(
        self, flow: mitmproxy.http.HTTPFlow, prompt: prompts.Prompt
    ) -> None:
        self._cleanup_headers(flow.request, self._request_headers_blocklist)
        flow.request.headers[ORIGINAL_URL_HEADER] = flow.request.url
        flow.request.headers["Authorization"] = f"Bearer {self._api_key}"
        flow.request.url = self._url
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

    def _save_request(self, flow: mitmproxy.http.HTTPFlow) -> None:
        file_path = self._get_save_filename(flow)
        if file_path is None:
            return

        r = flow.request
        now = datetime.datetime.now(tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        s = io.StringIO()
        s.write(f"# {now} {r.method} {r.path}\n\n")
        s.write("--- Request ---\n")
        s.write(f"{r.method} {r.url} {r.http_version}\n")
        s.writelines(f"{k}: {v}\n" for k, v in cast(tuple[str, str], r.headers.items()))
        s.write("\n")
        if r.content:
            s.write(self._format_body(r.get_text(strict=False), r.headers.get("content-type", "")))  # type: ignore

        with file_path.open("w") as f:
            f.write(s.getvalue())
            f.write("\n\n")

    def _save_response(self, flow: mitmproxy.http.HTTPFlow) -> None:
        if flow.response is None:
            return
        file_path = self._get_save_filename(flow)
        if file_path is None:
            return

        r = flow.response

        s = io.StringIO()
        s.write("--- Response ---\n")
        s.write(f"{r.http_version} {r.status_code} {r.reason}\n")
        s.writelines(f"{k}: {v}\n" for k, v in cast(tuple[str, str], r.headers.items()))
        s.write("\n")
        if r.content:
            s.write(self._format_body(r.get_text(strict=False), r.headers.get("content-type", "")))  # type: ignore

        with file_path.open("a") as f:
            f.write(s.getvalue())
            f.write("\n\n")

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
        for regex in blocklist:
            for header in rr.headers:
                if re.match(regex, header, re.IGNORECASE):
                    del rr.headers[header]

    def _format_body(self, text: str, content_type: str) -> str:
        media_type = content_type.split(";", 1)[0].strip().lower()
        if media_type != "application/json":
            return text
        try:
            return json.dumps(json.loads(text), indent=2, ensure_ascii=False)
        except json.JSONDecodeError:
            return text

    def server_connect(
        self, data: mitmproxy.proxy.server_hooks.ServerConnectionHookData
    ) -> None:
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
