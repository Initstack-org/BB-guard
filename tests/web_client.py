"""A tiny ASGI test client (no httpx needed): one request per call, a cookie jar, form encoding."""

from __future__ import annotations

import asyncio
from http.cookies import SimpleCookie
from urllib.parse import urlencode, urlsplit


class Response:
    def __init__(self, status: int, headers: list, body: bytes):
        self.status = status
        self.raw_headers = headers
        self.body = body

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def header(self, name: str) -> str | None:
        for key, value in self.raw_headers:
            if key.decode().lower() == name.lower():
                return value.decode()
        return None

    def set_cookies(self) -> list[str]:
        return [v.decode() for k, v in self.raw_headers if k.decode().lower() == "set-cookie"]


class Client:
    def __init__(self, app, host: str = "guard.example.org", peer=("127.0.0.1", 50000),
                 origin: str | None = "https://guard.example.org"):
        self.app, self.host, self.peer, self.origin = app, host, peer, origin
        self.cookies: dict[str, str] = {}

    def request(self, method: str, path: str, *, form: dict | None = None, body: bytes | None = None,
                headers: dict | None = None, content_type: str | None = None, peer=None,
                host: str | None = None, send_origin: bool = True) -> Response:
        hdrs = {"host": self.host if host is None else host, "user-agent": "pytest-client"}
        if self.cookies:
            hdrs["cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if method != "GET" and send_origin and self.origin:
            hdrs["origin"] = self.origin
        if form is not None:
            body = urlencode(form).encode()
            hdrs["content-type"] = "application/x-www-form-urlencoded"
        if content_type:
            hdrs["content-type"] = content_type
        hdrs.update({k.lower(): v for k, v in (headers or {}).items()})
        parts = urlsplit(path)
        scope = {
            "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method,
            "scheme": "https", "path": parts.path, "raw_path": parts.path.encode(), "root_path": "",
            "query_string": parts.query.encode(), "client": peer or self.peer, "server": (self.host, 443),
            "headers": [(k.encode(), v.encode()) for k, v in hdrs.items()],
        }
        response = asyncio.run(self._call(scope, body or b""))
        self._store_cookies(response)
        return response

    async def _call(self, scope, body: bytes) -> Response:
        sent: list = []
        pending = [{"type": "http.request", "body": body, "more_body": False}]

        async def receive():
            return pending.pop(0) if pending else {"type": "http.disconnect"}

        async def send(message):
            sent.append(message)

        await self.app(scope, receive, send)
        start = next(m for m in sent if m["type"] == "http.response.start")
        data = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
        return Response(start["status"], list(start["headers"]), data)

    def _store_cookies(self, response: Response) -> None:
        for raw in response.set_cookies():
            jar = SimpleCookie()
            jar.load(raw)
            for name, morsel in jar.items():
                if morsel["max-age"] == "0" or morsel.value == "":
                    self.cookies.pop(name, None)
                else:
                    self.cookies[name] = morsel.value

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, **kw):
        return self.request("POST", path, **kw)
