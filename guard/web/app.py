"""Dashboard web application: sign-in, sign-out, health check, static files and the dashboard shell.

Built on Starlette (the framework FastAPI is built on); see CHANGES.md for why. Every route is
registered through `RouteTable.add` with one class from docs/API.md section 2, and the request
wrapper enforces that class: A needs a session, W adds CSRF and an Origin check, R adds recent
re-authentication. Handlers are plain functions run in the threadpool with their own SQLite
connection, so the event loop never blocks on the database or on password hashing.
"""

from __future__ import annotations

import ipaddress
import json
import secrets
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlsplit

from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers, MutableHeaders
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from .. import audit, db
from ..auth import csrf, service, sessions
from ..config import Config

SESSION_COOKIE = "__Host-guard_session"
PRE_COOKIE = "__Host-guard_pre"
PRE_COOKIE_MAX_AGE_S = 900
# Proposed defaults from docs/SUBSYSTEMS.md section 7.2. The settings keys that would override
# them are not wired up yet (Stage 8, General Settings).
SESSION_IDLE_S = 1800
SESSION_MAX_S = 43200
REAUTH_WINDOW_S = 300
MAX_BODY_BYTES = 64 * 1024
MAX_PASSWORD_CHARS = 1024

PAGE_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "frame-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

# Class P routes that may exist (docs/API.md section 4). The sweep test fails on anything else.
PUBLIC_ALLOW_LIST = frozenset({"/login", "/login/password", "/healthz", "/static"})

# Sidebar from GOAL.md section 1.A. Pages marked built=False are listed but not links yet.
NAV = [
    ("Overview", [("Dashboard", "/", True)]),
    ("Traffic", [("Visitors", "/visitors", False), ("IP Intelligence", "/ip-intel", False),
                 ("URL History", "/url-history", False)]),
    ("Security", [("IP Rules", "/ip-rules", False), ("URL Access Rules", "/url-rules", False),
                  ("Block Page", "/block-page", False)]),
    ("MyBB", [("HTML Injections", "/injections", False),
              ("Injection History / Versions", "/injections/history", False)]),
    ("Administration", [("Administrators", "/admins", False),
                        ("Authentication / Passkeys", "/account", False),
                        ("Audit Log", "/audit", False), ("API Settings", "/settings/api", False),
                        ("General Settings", "/settings", False),
                        ("Backups and Retention", "/backups", False)]),
]

_templates = Environment(
    loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
    autoescape=select_autoescape(["html"]), trim_blocks=True, lstrip_blocks=True)


# ---------------------------------------------------------------------------------------------
# Request helpers


def client_ip(request: Request) -> str:
    """The real client address (docs/ARCHITECTURE.md section 8): X-Guard-Client-Ip is honoured only
    when the TCP peer is loopback (the Nginx vhost). X-Forwarded-For and CF-Connecting-IP are never read."""
    peer = request.client.host if request.client else ""
    try:
        peer_is_loopback = ipaddress.ip_address(peer).is_loopback
    except ValueError:
        peer_is_loopback = False
    if peer_is_loopback:
        header = request.headers.get("x-guard-client-ip", "").strip()
        if header and service.canonical_ip(header) != "invalid":
            return service.canonical_ip(header)
    return service.canonical_ip(peer)


def get_setting(conn: sqlite3.Connection, key: str, default):
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    if row is None:
        return default
    try:
        return json.loads(row["value"])
    except ValueError:
        return default


def password_login_enabled(conn: sqlite3.Connection) -> bool:
    value = get_setting(conn, "auth.password_login_enabled", True)
    return value if isinstance(value, bool) else True


def _error(request: Request, status: int, code: str, message: str, headers: dict | None = None) -> Response:
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": {"code": code, "message": message}}, status_code=status,
                            headers=headers)
    return PlainTextResponse(message, status_code=status, headers=headers)


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_MAX_S, path="/", secure=True,
                        httponly=True, samesite="lax")


def _clear_cookie(response: Response, name: str) -> None:
    response.delete_cookie(name, path="/", secure=True, httponly=True, samesite="lax")


def _valid_pre_cookie(value: str | None) -> bool:
    return bool(value) and len(value) <= 64 and all(c.isalnum() or c in "-_" for c in value)


# ---------------------------------------------------------------------------------------------
# Context and the guarded endpoint wrapper


@dataclass
class Ctx:
    request: Request
    state: object
    conn: sqlite3.Connection
    now_ms: int
    ip: str
    form: dict
    session: sessions.SessionInfo | None = None
    admin: sqlite3.Row | None = None

    @property
    def cfg(self) -> Config:
        return self.state.cfg

    def csrf_token(self) -> str:
        return csrf.session_token(self.cfg.secret_key, self.session.token_hash)

    def audit(self, action: str, outcome: str, **kw) -> None:
        audit.record(self.conn, action, outcome, ip=self.ip, ts_ms=self.now_ms,
                     actor_admin_id=self.admin["id"] if self.admin is not None else None,
                     actor_name=self.admin["username"] if self.admin is not None else "", **kw)


class BodyTooLarge(Exception):
    pass


async def _read_form(request: Request) -> dict:
    total = 0
    chunks = []
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_BODY_BYTES:
            raise BodyTooLarge
        chunks.append(chunk)
    ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if ctype != "application/x-www-form-urlencoded":
        return {}
    try:
        parsed = parse_qs(b"".join(chunks).decode("utf-8", "replace"), keep_blank_values=True,
                          max_num_fields=50)
    except ValueError:
        return {}
    return {k: v[0] for k, v in parsed.items()}


def _csrf_checks(ctx: Ctx) -> Response | None:
    """W and R routes: Origin/Referer must match, and the session CSRF token must be supplied."""
    req = ctx.request
    if not csrf.origin_ok(ctx.cfg.external_origin, req.headers.get("origin"), req.headers.get("referer")):
        reason = "origin"
    else:
        supplied = req.headers.get("x-csrf-token") or ctx.form.get("csrf_token")
        if csrf.verify(ctx.csrf_token(), supplied):
            return None
        reason = "token"
    ctx.audit("auth.csrf_failure", "denied", detail={"reason": reason, "path": req.url.path[:200]})
    return _error(req, 403, "csrf_failed", "Forbidden")


def _dispatch(cls: str, fn: Callable[[Ctx], Response], request: Request, form: dict) -> Response:
    st = request.app.state
    conn = db.connect(st.cfg.db_path)
    try:
        ctx = Ctx(request, st, conn, st.clock(), client_ip(request), form)
        if cls == "P":
            return fn(ctx)
        info = sessions.validate_session(conn, request.cookies.get(SESSION_COOKIE), ctx.now_ms,
                                         idle_s=SESSION_IDLE_S)
        if info is None:
            if request.url.path.startswith("/api/"):
                return _error(request, 401, "unauthenticated", "Sign in required")
            return RedirectResponse("/login", status_code=303)
        ctx.session = info
        ctx.admin = conn.execute(
            "SELECT id, username, display_name, theme, timezone FROM admins WHERE id = ?",
            (info.admin_id,)).fetchone()
        if cls in ("W", "R"):
            failure = _csrf_checks(ctx)
            if failure is not None:
                return failure
        if cls == "R" and not st.reauth.is_recent(info, ctx.now_ms, REAUTH_WINDOW_S):
            ctx.audit("auth.reauth_required", "denied", detail={"path": request.url.path[:200]})
            return _error(request, 403, "reauth_required", "Please confirm your password again")
        return fn(ctx)
    finally:
        conn.close()


@dataclass
class RouteTable:
    routes: list = field(default_factory=list)
    classes: dict = field(default_factory=dict)

    def add(self, path: str, fn: Callable[[Ctx], Response], cls: str, methods=("GET",)) -> None:
        if cls not in ("P", "A", "W", "R"):
            raise ValueError(f"unknown route class {cls!r} for {path}")

        async def endpoint(request: Request) -> Response:
            form: dict = {}
            if request.method not in ("GET", "HEAD", "OPTIONS"):
                try:
                    form = await _read_form(request)
                except BodyTooLarge:
                    return _error(request, 413, "too_large", "Request body too large")
            return await run_in_threadpool(_dispatch, cls, fn, request, form)

        self.routes.append(Route(path, endpoint, methods=list(methods)))
        for method in methods:
            self.classes[(path, method)] = cls

    def mount_static(self, path: str, directory: Path) -> None:
        self.routes.append(Mount(path, app=StaticFiles(directory=str(directory)), name="static"))
        self.classes[(path, "GET")] = "P"


# ---------------------------------------------------------------------------------------------
# Handlers


def _render(name: str, status: int = 200, headers: dict | None = None, **context) -> HTMLResponse:
    return HTMLResponse(_templates.get_template(name).render(**context), status_code=status,
                        headers=headers)


def _login_page(ctx: Ctx, pre: str, *, status: int = 200, error: str = "", new_cookie: bool = False,
                headers: dict | None = None) -> Response:
    response = _render("login.html", status, headers,
                       csrf_token=csrf.pre_session_token(ctx.cfg.secret_key, pre),
                       password_enabled=password_login_enabled(ctx.conn), error=error)
    if new_cookie:
        response.set_cookie(PRE_COOKIE, pre, max_age=PRE_COOKIE_MAX_AGE_S, path="/", secure=True,
                            httponly=True, samesite="lax")
    return response


def login_get(ctx: Ctx) -> Response:
    if sessions.validate_session(ctx.conn, ctx.request.cookies.get(SESSION_COOKIE), ctx.now_ms,
                                 idle_s=SESSION_IDLE_S):
        return RedirectResponse("/", status_code=303)
    pre = ctx.request.cookies.get(PRE_COOKIE)
    fresh = not _valid_pre_cookie(pre)
    if fresh:
        pre = secrets.token_urlsafe(32)
    return _login_page(ctx, pre, new_cookie=fresh)


def login_password(ctx: Ctx) -> Response:
    req = ctx.request
    pre = req.cookies.get(PRE_COOKIE)
    origin_good = csrf.origin_ok(ctx.cfg.external_origin, req.headers.get("origin"),
                                 req.headers.get("referer"))
    token_good = (_valid_pre_cookie(pre) and csrf.verify(
        csrf.pre_session_token(ctx.cfg.secret_key, pre), ctx.form.get("csrf_token")))
    if not (origin_good and token_good):
        audit.record(ctx.conn, "auth.csrf_failure", "denied", ip=ctx.ip, ts_ms=ctx.now_ms,
                     detail={"reason": "origin" if not origin_good else "token", "path": "/login/password"})
        return PlainTextResponse("Forbidden", status_code=403)

    result = service.authenticate_password(
        ctx.conn, ctx.state.hasher, ctx.form.get("username", "")[:64],
        ctx.form.get("password", "")[:MAX_PASSWORD_CHARS + 1], ip=ctx.ip,
        user_agent=req.headers.get("user-agent", ""), now_ms=ctx.now_ms, session_max_s=SESSION_MAX_S,
        password_login_enabled=password_login_enabled(ctx.conn))
    if result.locked:
        return _login_page(ctx, pre, status=429, error="Too many attempts. Try again later.",
                           headers={"Retry-After": str(result.retry_after_s)})
    if not result.ok:
        return _login_page(ctx, pre, status=401, error="Invalid username or password.")
    ctx.state.reauth.mark(result.session.id, ctx.now_ms)
    response = RedirectResponse("/", status_code=303)
    _set_session_cookie(response, result.token)
    _clear_cookie(response, PRE_COOKIE)
    return response


def logout(ctx: Ctx) -> Response:
    sessions.revoke_session(ctx.conn, ctx.session.id, ctx.now_ms)
    ctx.state.reauth.forget(ctx.session.id)
    ctx.audit("auth.logout", "success")
    response = RedirectResponse("/login", status_code=303)
    _clear_cookie(response, SESSION_COOKIE)
    return response


def dashboard(ctx: Ctx) -> Response:
    return _render("dashboard.html", admin=ctx.admin, nav=NAV, current="/", csrf_token=ctx.csrf_token())


def healthz(ctx: Ctx) -> Response:
    return JSONResponse({"status": "ok"})


# ---------------------------------------------------------------------------------------------
# Application


class SecurityMiddleware:
    """Host check (421 for any other Host) and the headers every response carries (docs/API.md section 1)."""

    def __init__(self, app, hostname: str):
        self.app = app
        self.hostname = hostname.lower()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["X-Content-Type-Options"] = "nosniff"
                headers["Referrer-Policy"] = "same-origin"
                if not path.startswith("/static/"):
                    headers.setdefault("Cache-Control", "no-store")
                if headers.get("content-type", "").startswith("text/html"):
                    headers.setdefault("Content-Security-Policy", PAGE_CSP)
            await send(message)

        try:
            host = urlsplit("//" + Headers(scope=scope).get("host", "")).hostname or ""
        except ValueError:
            host = ""
        if host.lower() != self.hostname:
            await PlainTextResponse("Misdirected Request", status_code=421)(scope, receive, send_with_headers)
            return
        await self.app(scope, receive, send_with_headers)


def create_app(cfg: Config, *, hasher=None, clock: Callable[[], int] = db.now_ms,
               extra_routes: Callable[[RouteTable], None] | None = None) -> Starlette:
    if hasher is None:
        from ..auth.passwords import Argon2Hasher  # noqa: PLC0415
        hasher = Argon2Hasher()
    table = RouteTable()
    table.add("/login", login_get, "P")
    table.add("/login/password", login_password, "P", methods=("POST",))
    table.add("/healthz", healthz, "P")
    table.add("/logout", logout, "W", methods=("POST",))
    table.add("/", dashboard, "A")
    table.mount_static("/static", Path(__file__).parent / "static")
    if extra_routes is not None:
        extra_routes(table)
    # docs_url / redoc / openapi do not exist in Starlette; there is nothing to disable.
    app = Starlette(routes=table.routes)
    app.state.cfg = cfg
    app.state.hasher = hasher
    app.state.clock = clock
    app.state.reauth = sessions.ReauthTracker()
    app.state.route_classes = table.classes
    return _wrap(app, cfg)


def _wrap(app: Starlette, cfg: Config):
    """Wrap with the middleware but keep `.state` and `.routes` reachable for tests and the sweep."""
    wrapped = SecurityMiddleware(app, cfg.rp_id)
    wrapped.state = app.state
    wrapped.routes = app.routes
    return wrapped
