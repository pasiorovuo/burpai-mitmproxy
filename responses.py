import datetime
import http
import json
import time
import typing

import mitmproxy.http

CREDIT_BALANCE = "9999.111"


def headers():
    return {
        "Content-Type": "application/json",
        "Server": "'; DELETE carlos FROM users --",
        "Portswigger-Hakawai-Ai": ",".join(
            [
                "creditCost=0.00000000000000000",
                f"balance={CREDIT_BALANCE}",
                f"balanceTimestamp={datetime.datetime.now(tz=datetime.timezone.utc).isoformat().replace('+00:00', 'Z')}",
            ]
        ),
        "X-Robots-Tag": "noindex",
    }


class Response(mitmproxy.http.Response):
    def __init__(
        self,
        status_code: http.HTTPStatus,
        content: str,
        headers: typing.Dict[str, str],
    ) -> None:
        encodeargs = {
            "encoding": "utf-8",
            "errors": "surrogateescape",
        }
        super().__init__(
            http_version=b"HTTP/1.1",
            status_code=status_code,
            reason=status_code.phrase.encode(),
            headers=mitmproxy.http.Headers(
                (k.encode(**encodeargs), v.encode(**encodeargs))
                for k, v in headers.items()
            ),
            content=content.encode("utf-8"),
            trailers=None,
            timestamp_start=time.time(),
            timestamp_end=time.time(),
        )

    @property
    def _headers(self) -> dict[str, str]:
        return headers()


class CreditBalanceResponse(Response):
    def __init__(self) -> None:
        super().__init__(
            status_code=http.HTTPStatus.OK,
            headers=self._headers,
            content=json.dumps(
                {
                    "balance": CREDIT_BALANCE,
                    "timestamp": datetime.datetime.now(tz=datetime.timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z"),
                }
            ),
        )
