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
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlencode, urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers, MutableHeaders
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from .. import audit, db
from ..auth import csrf, passkeys, service, sessions, throttle
from ..config import Config
from . import audit_log
from . import admins as admins_mod
from . import charts as charts_mod
from . import limits as limits_mod
from . import settings_registry
from . import traffic

SESSION_COOKIE = "__Host-guard_session"
PRE_COOKIE = "__Host-guard_pre"
PRE_COOKIE_MAX_AGE_S = 900
# Defaults from docs/SUBSYSTEMS.md section 7.2. The auth.* settings override them on every request
# (guard/web/limits.py); a missing or out-of-range setting falls back to these.
SESSION_IDLE_S = limits_mod.DEFAULT_IDLE_S
SESSION_MAX_S = limits_mod.DEFAULT_MAX_S
REAUTH_WINDOW_S = limits_mod.DEFAULT_REAUTH_S
MAX_BODY_BYTES = 64 * 1024
MAX_PASSWORD_CHARS = 1024

PAGE_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "frame-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

# Class P routes that may exist (docs/API.md section 4). The sweep test fails on anything else.
PUBLIC_ALLOW_LIST = frozenset({"/login", "/login/password", "/login/passkey/options",
                               "/login/passkey/verify", "/healthz", "/static"})

PASSKEYS_UNAVAILABLE = "Passkeys are not available on this server."

# Sidebar from GOAL.md section 1.A. Pages marked built=False are listed but not links yet.
NAV = [
    ("Overview", [("Dashboard", "/", True)]),
    ("Traffic", [("Visitors", "/visitors", True), ("IP Intelligence", "/ip-intel", False),
                 ("URL History", "/url-history", True)]),
    ("Security", [("IP Rules", "/ip-rules", False), ("URL Access Rules", "/url-rules", False),
                  ("Block Page", "/block-page", False)]),
    ("MyBB", [("HTML Injections", "/injections", False),
              ("Injection History / Versions", "/injections/history", False)]),
    ("Administration", [("Administrators", "/admins", True),
                        ("Authentication / Passkeys", "/account", True),
                        ("Audit Log", "/audit", True), ("API Settings", "/settings/api", False),
                        ("General Settings", "/settings", True),
                        ("Backups and Retention", "/backups", False)]),
]

_templates = Environment(
    loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
    autoescape=select_autoescape(["html"]), trim_blocks=True, lstrip_blocks=True)
_templates.filters["bytes"] = traffic.human_bytes


# ---------------------------------------------------------------------------------------------
# Request helpers


def _peer_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def trusted_ip_set(connectors) -> frozenset:
    """Canonical text of the configured tunnel-connector addresses (unparseable entries are dropped, so
    an unparseable peer address can never match one)."""
    return frozenset(c for c in (service.canonical_ip(x) for x in connectors) if c != "invalid")


def client_ip(request: Request) -> str:
    """The real client address (docs/ARCHITECTURE.md section 8).

    Only two sources of a forwarded address are ever honoured, each only from its own kind of peer:
    - X-Guard-Client-Ip, when the TCP peer is loopback (an Nginx vhost on the same machine);
    - CF-Connecting-IP, when the TCP peer is one of the configured trusted connectors (cloudflared
      connecting straight to Guard).
    A missing or malformed header falls back to the peer's own address. X-Forwarded-For and every other
    header are never read, and neither header is read from any other peer.
    """
    peer = _peer_ip(request)
    try:
        peer_is_loopback = ipaddress.ip_address(peer).is_loopback
    except ValueError:
        peer_is_loopback = False
    if peer_is_loopback:
        header = request.headers.get("x-guard-client-ip", "").strip()
        if header and service.canonical_ip(header) != "invalid":
            return service.canonical_ip(header)
    elif service.canonical_ip(peer) in getattr(request.app.state, "trusted_ips", frozenset()):
        header = request.headers.get("cf-connecting-ip", "").strip()
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


def _set_session_cookie(response: Response, token: str, max_age_s: int) -> None:
    response.set_cookie(SESSION_COOKIE, token, max_age=max_age_s, path="/", secure=True,
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
    limits: limits_mod.Limits = limits_mod.Limits()

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


async def _read_form(request: Request, json_body: bool = False) -> dict:
    """The request body as a dict: an urlencoded form, or (only for routes registered with json_body) a JSON
    object sent as application/json. Anything else, or anything malformed, is an empty dict, which the
    handlers and the CSRF check then reject."""
    total = 0
    chunks = []
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_BODY_BYTES:
            raise BodyTooLarge
        chunks.append(chunk)
    ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if json_body:
        if ctype != "application/json":
            return {}
        try:
            data = json.loads(b"".join(chunks).decode("utf-8"))
        except (ValueError, RecursionError):
            return {}
        return data if isinstance(data, dict) else {}
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
        if csrf.verify(ctx.csrf_token(), supplied if isinstance(supplied, str) else None):
            return None
        reason = "token"
    ctx.audit("auth.csrf_failure", "denied", detail={"reason": reason, "path": req.url.path[:200]})
    return _error(req, 403, "csrf_failed", "Forbidden")


def _dispatch(cls: str, fn: Callable[[Ctx], Response], request: Request, form: dict) -> Response:
    st = request.app.state
    conn = db.connect(st.cfg.db_path)
    try:
        ctx = Ctx(request, st, conn, st.clock(), client_ip(request), form)
        ctx.limits = limits_mod.load(conn)
        if cls == "P":
            return fn(ctx)
        info = sessions.validate_session(conn, request.cookies.get(SESSION_COOKIE), ctx.now_ms,
                                         idle_s=ctx.limits.idle_s)
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
        if cls == "R" and not st.reauth.is_recent(info, ctx.now_ms, ctx.limits.reauth_s):
            ctx.audit("auth.reauth_required", "denied", detail={"path": request.url.path[:200]})
            return _error(request, 403, "reauth_required", "Please confirm your password again")
        return fn(ctx)
    finally:
        conn.close()


@dataclass
class RouteTable:
    routes: list = field(default_factory=list)
    classes: dict = field(default_factory=dict)

    def add(self, path: str, fn: Callable[[Ctx], Response], cls: str, methods=("GET",), *,
            json_body: bool = False) -> None:
        if cls not in ("P", "A", "W", "R"):
            raise ValueError(f"unknown route class {cls!r} for {path}")

        async def endpoint(request: Request) -> Response:
            form: dict = {}
            if request.method not in ("GET", "HEAD", "OPTIONS"):
                try:
                    form = await _read_form(request, json_body)
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
                       password_enabled=password_login_enabled(ctx.conn), error=error,
                       passkeys_available=ctx.state.webauthn.available())
    if new_cookie:
        response.set_cookie(PRE_COOKIE, pre, max_age=PRE_COOKIE_MAX_AGE_S, path="/", secure=True,
                            httponly=True, samesite="lax")
    return response


def login_get(ctx: Ctx) -> Response:
    if sessions.validate_session(ctx.conn, ctx.request.cookies.get(SESSION_COOKIE), ctx.now_ms,
                                 idle_s=ctx.limits.idle_s):
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
        user_agent=req.headers.get("user-agent", ""), now_ms=ctx.now_ms,
        session_max_s=ctx.limits.max_s, policy=ctx.limits.throttle,
        password_login_enabled=password_login_enabled(ctx.conn))
    if result.locked:
        return _login_page(ctx, pre, status=429, error="Too many attempts. Try again later.",
                           headers={"Retry-After": str(result.retry_after_s)})
    if not result.ok:
        return _login_page(ctx, pre, status=401, error="Invalid username or password.")
    ctx.state.reauth.mark(result.session.id, ctx.now_ms)
    response = RedirectResponse("/", status_code=303)
    _set_session_cookie(response, result.token, ctx.limits.max_s)
    _clear_cookie(response, PRE_COOKIE)
    return response


def _json_error(status: int, code: str, message: str, headers: dict | None = None) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "message": message}}, status_code=status, headers=headers)


def _pre_session_ok(ctx: Ctx, path: str) -> str | None:
    """The sign-in routes' CSRF rule (docs/API.md section 4): the pre-session cookie must be present and the
    token derived from it must be supplied (header `X-CSRF-Token` or a `csrf_token` field), and the Origin
    must match. Returns the pre-session value, or None after auditing the failure."""
    req = ctx.request
    pre = req.cookies.get(PRE_COOKIE)
    origin_good = csrf.origin_ok(ctx.cfg.external_origin, req.headers.get("origin"),
                                 req.headers.get("referer"))
    supplied = req.headers.get("x-csrf-token") or ctx.form.get("csrf_token")
    token_good = (_valid_pre_cookie(pre) and isinstance(supplied, str) and csrf.verify(
        csrf.pre_session_token(ctx.cfg.secret_key, pre), supplied))
    if origin_good and token_good:
        return pre
    audit.record(ctx.conn, "auth.csrf_failure", "denied", ip=ctx.ip, ts_ms=ctx.now_ms,
                 detail={"reason": "origin" if not origin_good else "token", "path": path})
    return None


def login_passkey_options(ctx: Ctx) -> Response:
    pre = _pre_session_ok(ctx, "/login/passkey/options")
    if pre is None:
        return _json_error(403, "csrf_failed", "Forbidden")
    if not ctx.state.webauthn.available():
        return _json_error(503, "unavailable", PASSKEYS_UNAVAILABLE)
    wait = throttle.check(ctx.conn, throttle.ip_key(ctx.ip), ctx.now_ms)
    if wait:
        return _json_error(429, "rate_limited", "Too many attempts. Try again later.",
                           {"Retry-After": str(wait)})
    try:
        options = passkeys.begin_signin(ctx.state.webauthn, ctx.state.challenges, rp_id=ctx.cfg.rp_id,
                                        binding=pre, now_ms=ctx.now_ms)
    except passkeys.PasskeyUnavailable:
        return _json_error(503, "unavailable", PASSKEYS_UNAVAILABLE)
    return JSONResponse({"data": options})


def login_passkey_verify(ctx: Ctx) -> Response:
    pre = _pre_session_ok(ctx, "/login/passkey/verify")
    if pre is None:
        return _json_error(403, "csrf_failed", "Forbidden")
    if not ctx.state.webauthn.available():
        return _json_error(503, "unavailable", PASSKEYS_UNAVAILABLE)
    credential = ctx.form.get("credential")
    if not isinstance(credential, dict):
        return _json_error(400, "bad_request", "The passkey response is missing.")
    try:
        result = passkeys.finish_signin(
            ctx.state.webauthn, ctx.state.challenges, ctx.conn, binding=pre, credential=credential,
            rp_id=ctx.cfg.rp_id, origin=ctx.cfg.external_origin, ip=ctx.ip,
            user_agent=ctx.request.headers.get("user-agent", ""), now_ms=ctx.now_ms,
            policy=ctx.limits.throttle, session_max_s=ctx.limits.max_s)
    except passkeys.PasskeyUnavailable:
        return _json_error(503, "unavailable", PASSKEYS_UNAVAILABLE)
    if result.locked:
        return _json_error(429, "rate_limited", "Too many attempts. Try again later.",
                           {"Retry-After": str(result.retry_after_s)})
    if not result.ok:
        return _json_error(401, "invalid", "Passkey sign-in failed.")
    ctx.state.reauth.mark(result.session.id, ctx.now_ms)
    response = JSONResponse({"data": {"redirect": "/"}})
    _set_session_cookie(response, result.token, ctx.limits.max_s)
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
    """Overview: last-24-hours totals and graphs, top URLs, newest visitors and the log reader's state.

    Every number comes from a rollup, an indexed aggregate or a top-5 query, so the page stays cheap on a
    large database. The Dashboard is read-only and writes nothing (not even an audit row).
    """
    tz = ctx.admin["timezone"]
    overview = traffic.site_overview(ctx.conn, ctx.now_ms, tz)
    note = f"per hour, {tz}"
    svgs = [
        charts_mod.bar_chart("Requests", [(b.label, b.full_label, b.requests) for b in overview["buckets"]],
                             value_text=lambda n: f"{n:,}", note=note),
        charts_mod.bar_chart("Sent by the site (bytes out)",
                             [(b.label, b.full_label, b.bytes_out) for b in overview["buckets"]],
                             value_text=traffic.human_bytes, note=note)]
    top_rows, _ = traffic.url_ranking(ctx.conn, traffic.UrlListFilters(period="24h", size=5), ctx.now_ms)
    recent_rows, _ = traffic.visitor_page(ctx.conn, traffic.VisitorFilters(size=5))
    state = traffic.ingest_status(ctx.conn)
    ingest = {"last_request": _format_ms(state["last_request_ms"], tz) if state["last_request_ms"] else "",
              "updated": _format_ms(state["updated_ms"], tz) if state["updated_ms"] else "",
              "lines_total": state["lines_total"], "bad_lines_total": state["bad_lines_total"],
              "peer_mismatch_total": state["peer_mismatch_total"]}
    return _render(
        "dashboard.html", admin=ctx.admin, nav=NAV, current="/", csrf_token=ctx.csrf_token(),
        timezone_name=tz, overview=overview, chart_svgs=svgs, ingest=ingest,
        window_label=f"{_format_ms(overview['from_ms'], tz)} to {_format_ms(overview['to_ms'] - 1, tz)}",
        top_urls=[{"id": r["id"], "host": r["host"], "path": r["path"], "hits": r["hits"]} for r in top_rows],
        recent=[{"ip": r["ip"], "last": _format_ms(r["last_seen_ms"], tz), "requests": r["request_count"]}
                for r in recent_rows])


def healthz(ctx: Ctx) -> Response:
    return JSONResponse({"status": "ok"})


# ---------------------------------------------------------------------------------------------
# Account page, re-authentication and own sessions (docs/API.md section 5)
#
# Deviations from API.md, both for the owner to confirm (see CHANGES.md): these routes take HTML
# form posts and answer with a redirect or a re-rendered page, not JSON; and the password change
# is class W rather than R, because it already requires the current password, which is stronger
# than the re-authentication window and avoids a raw JSON error on a form post.

FLASH = {
    "password_changed": "Password changed. Your other sessions were signed out.",
    "reauth_ok": "Password confirmed.",
    "reauth_passkey_ok": "Passkey confirmed.",
    "session_revoked": "Session signed out.",
    "sessions_revoked": "Your other sessions were signed out.",
    "passkey_added": "Passkey added.",
    "passkey_renamed": "Passkey renamed.",
    "passkey_revoked": "Passkey removed.",
}


def _format_ms(ms: int, tz_name: str) -> str:
    """An epoch-millisecond UTC timestamp in the admin's timezone; UTC if the name is unusable."""
    try:
        tz = ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        tz = timezone.utc
    return datetime.fromtimestamp(ms / 1000, tz).strftime("%Y-%m-%d %H:%M:%S %Z")


def _window_label(seconds: int) -> str:
    if seconds % 60 == 0:
        minutes = seconds // 60
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    return f"{seconds} seconds"


def _account_page(ctx: Ctx, *, status: int = 200, error: str = "", message: str = "",
                  headers: dict | None = None) -> Response:
    tz = ctx.admin["timezone"]
    rows = [{"id": s["id"], "method": s["auth_method"], "ip": s["ip"], "agent": s["user_agent"][:120],
             "created": _format_ms(s["created_ms"], tz), "last_seen": _format_ms(s["last_seen_ms"], tz),
             "current": s["id"] == ctx.session.id}
            for s in sessions.list_for_admin(ctx.conn, ctx.admin["id"], ctx.now_ms,
                                             idle_s=ctx.limits.idle_s)]
    return _render("account.html", status, headers, admin=ctx.admin, nav=NAV, current="/account",
                   csrf_token=ctx.csrf_token(), sessions=rows, error=error, message=message,
                   reauth_recent=ctx.state.reauth.is_recent(ctx.session, ctx.now_ms,
                                                            ctx.limits.reauth_s),
                   window_label=_window_label(ctx.limits.reauth_s), timezone_name=tz,
                   password_enabled=password_login_enabled(ctx.conn),
                   min_length=ctx.limits.min_password_length,
                   passkeys=_passkey_rows(ctx, tz), passkeys_available=ctx.state.webauthn.available())


def _passkey_rows(ctx: Ctx, tz: str) -> list:
    return [{"id": p["id"], "name": p["name"], "added": _format_ms(p["created_ms"], tz),
             "last_used": _format_ms(p["last_used_ms"], tz) if p["last_used_ms"] else "Never",
             "kind": {None: "", True: "Synced passkey", False: "Device-bound"}[p["synced"]],
             "transports": ", ".join(p["transports"]), "cred_hash": p["cred_hash"]}
            for p in passkeys.list_for_admin(ctx.conn, ctx.admin["id"])]


def _password_field(ctx: Ctx, name: str) -> str:
    return ctx.form.get(name, "")[:MAX_PASSWORD_CHARS + 1]


def _failed_check_page(ctx: Ctx, check: service.PasswordCheck, wrong_message: str) -> Response:
    if check.locked:
        return _account_page(ctx, status=429, error="Too many attempts. Try again later.",
                             headers={"Retry-After": str(check.retry_after_s)})
    return _account_page(ctx, status=403, error=wrong_message)


def account_get(ctx: Ctx) -> Response:
    return _account_page(ctx, message=FLASH.get(ctx.request.query_params.get("msg", ""), ""))


def account_password(ctx: Ctx) -> Response:
    new_password = _password_field(ctx, "new_password")
    if new_password != _password_field(ctx, "confirm_password"):
        return _account_page(ctx, status=400, error="The new passwords do not match.")
    try:
        check = service.change_password(
            ctx.conn, ctx.state.hasher, ctx.admin["id"], _password_field(ctx, "current_password"),
            new_password, ip=ctx.ip, now_ms=ctx.now_ms, keep_session_id=ctx.session.id,
            min_length=ctx.limits.min_password_length, policy=ctx.limits.throttle,
            password_login_enabled=password_login_enabled(ctx.conn))
    except service.AccountError as exc:
        text = str(exc)
        return _account_page(ctx, status=400, error=("New " + text) if text.startswith("password") else text)
    if not check.ok:
        return _failed_check_page(ctx, check, "The current password is not correct.")
    ctx.state.reauth.mark(ctx.session.id, ctx.now_ms)
    return RedirectResponse("/account?msg=password_changed", status_code=303)


def reauth_password(ctx: Ctx) -> Response:
    check = service.check_admin_password(
        ctx.conn, ctx.state.hasher, ctx.admin["id"], _password_field(ctx, "password"), ip=ctx.ip,
        now_ms=ctx.now_ms, action="auth.reauth", policy=ctx.limits.throttle,
        password_login_enabled=password_login_enabled(ctx.conn))
    if not check.ok:
        return _failed_check_page(ctx, check, "That password is not correct.")
    ctx.state.reauth.mark(ctx.session.id, ctx.now_ms)
    ctx.audit("auth.reauth", "success", detail={"method": "password"})
    return RedirectResponse("/account?msg=reauth_ok", status_code=303)


def session_revoke(ctx: Ctx) -> Response:
    try:
        session_id = int(ctx.form.get("session_id", "")[:20])
    except ValueError:
        return _account_page(ctx, status=400, error="Choose a session to sign out.")
    if session_id == ctx.session.id:
        return _account_page(ctx, status=400, error="Use Sign out to end this session.")
    with db.transaction(ctx.conn):
        revoked = sessions.revoke_own(ctx.conn, ctx.admin["id"], session_id, ctx.now_ms)
        if revoked:
            ctx.audit("session.revoke", "success", target_type="session", target_id=str(session_id))
    if not revoked:
        return PlainTextResponse("Not found", status_code=404)
    ctx.state.reauth.forget(session_id)
    return RedirectResponse("/account?msg=session_revoked", status_code=303)


def sessions_revoke_others(ctx: Ctx) -> Response:
    with db.transaction(ctx.conn):
        count = sessions.revoke_all_for_admin(ctx.conn, ctx.admin["id"], ctx.now_ms,
                                              except_id=ctx.session.id)
        ctx.audit("session.revoke_others", "success", detail={"count": count})
    return RedirectResponse("/account?msg=sessions_revoked", status_code=303)


# ---------------------------------------------------------------------------------------------
# Passkeys on the account page (docs/API.md section 5). The browser steps (navigator.credentials) run in
# /static/passkeys.js and talk to the JSON routes below; the rename and remove buttons are plain form
# posts like the rest of the page. Deviations from API.md, for the owner to confirm: rename and remove take
# `passkey_id` in the form, not the path, and answer with a redirect or the re-rendered page.


def _passkey_json_failure(exc: Exception) -> JSONResponse:
    if isinstance(exc, passkeys.PasskeyNotFound):
        return _json_error(404, "not_found", _sentence(str(exc)))
    if isinstance(exc, passkeys.PasskeyConflict):
        return _json_error(409, "conflict", _sentence(str(exc)))
    return _json_error(400, "invalid", _sentence(str(exc)))


def _need_passkeys(ctx: Ctx) -> Response | None:
    return None if ctx.state.webauthn.available() else _json_error(503, "unavailable", PASSKEYS_UNAVAILABLE)


def passkey_register_options(ctx: Ctx) -> Response:
    if (unavailable := _need_passkeys(ctx)) is not None:
        return unavailable
    name = ctx.form.get("name")
    try:
        options = passkeys.begin_registration(
            ctx.state.webauthn, ctx.state.challenges, ctx.conn, ctx.admin["id"], rp_id=ctx.cfg.rp_id,
            binding=str(ctx.session.id), now_ms=ctx.now_ms, name=name if isinstance(name, str) else None)
    except passkeys.PasskeyUnavailable:
        return _json_error(503, "unavailable", PASSKEYS_UNAVAILABLE)
    except service.AccountError as exc:
        return _passkey_json_failure(exc)
    return JSONResponse({"data": options})


def passkey_register_verify(ctx: Ctx) -> Response:
    if (unavailable := _need_passkeys(ctx)) is not None:
        return unavailable
    credential = ctx.form.get("credential")
    if not isinstance(credential, dict):
        return _json_error(400, "bad_request", "The passkey response is missing.")
    try:
        created = passkeys.finish_registration(
            ctx.state.webauthn, ctx.state.challenges, ctx.conn, admin_id=ctx.admin["id"],
            actor_name=ctx.admin["username"], binding=str(ctx.session.id), credential=credential,
            name=ctx.form.get("name"), rp_id=ctx.cfg.rp_id, origin=ctx.cfg.external_origin, ip=ctx.ip,
            now_ms=ctx.now_ms)
    except passkeys.PasskeyUnavailable:
        return _json_error(503, "unavailable", PASSKEYS_UNAVAILABLE)
    except passkeys.PasskeyError:
        return _json_error(400, "verification_failed", "That passkey could not be verified. Try again.")
    except service.AccountError as exc:
        return _passkey_json_failure(exc)
    return JSONResponse({"data": created})


def reauth_passkey_options(ctx: Ctx) -> Response:
    if (unavailable := _need_passkeys(ctx)) is not None:
        return unavailable
    try:
        options = passkeys.begin_reauth(ctx.state.webauthn, ctx.state.challenges, ctx.conn, ctx.admin["id"],
                                        rp_id=ctx.cfg.rp_id, binding=str(ctx.session.id), now_ms=ctx.now_ms)
    except passkeys.PasskeyUnavailable:
        return _json_error(503, "unavailable", PASSKEYS_UNAVAILABLE)
    except service.AccountError as exc:
        return _passkey_json_failure(exc)
    return JSONResponse({"data": options})


def reauth_passkey_verify(ctx: Ctx) -> Response:
    if (unavailable := _need_passkeys(ctx)) is not None:
        return unavailable
    credential = ctx.form.get("credential")
    if not isinstance(credential, dict):
        return _json_error(400, "bad_request", "The passkey response is missing.")
    try:
        check = passkeys.finish_reauth(
            ctx.state.webauthn, ctx.state.challenges, ctx.conn, ctx.admin["id"], binding=str(ctx.session.id),
            credential=credential, rp_id=ctx.cfg.rp_id, origin=ctx.cfg.external_origin, ip=ctx.ip,
            now_ms=ctx.now_ms, policy=ctx.limits.throttle)
    except passkeys.PasskeyUnavailable:
        return _json_error(503, "unavailable", PASSKEYS_UNAVAILABLE)
    if check.locked:
        return _json_error(429, "rate_limited", "Too many attempts. Try again later.",
                           {"Retry-After": str(check.retry_after_s)})
    if not check.ok:
        return _json_error(403, "invalid", "The passkey could not be confirmed.")
    ctx.state.reauth.mark(ctx.session.id, ctx.now_ms)
    return JSONResponse({"data": {"ok": True}})


def _form_passkey_id(ctx: Ctx) -> int | None:
    try:
        return int(ctx.form.get("passkey_id", "")[:20])
    except ValueError:
        return None


def _passkey_form_failure(ctx: Ctx, exc: service.AccountError) -> Response:
    status = 404 if isinstance(exc, passkeys.PasskeyNotFound) else 409 if isinstance(
        exc, passkeys.PasskeyConflict) else 400
    return _account_page(ctx, status=status, error=_sentence(str(exc)))


def passkey_rename(ctx: Ctx) -> Response:
    passkey_id = _form_passkey_id(ctx)
    if passkey_id is None:
        return _account_page(ctx, status=400, error="Choose a passkey.")
    try:
        passkeys.rename(ctx.conn, ctx.admin["id"], passkey_id, ctx.form.get("name", "")[:200],
                        actor_name=ctx.admin["username"], ip=ctx.ip, now_ms=ctx.now_ms)
    except service.AccountError as exc:
        return _passkey_form_failure(ctx, exc)
    return RedirectResponse("/account?msg=passkey_renamed", status_code=303)


def passkey_revoke(ctx: Ctx) -> Response:
    passkey_id = _form_passkey_id(ctx)
    if passkey_id is None:
        return _account_page(ctx, status=400, error="Choose a passkey.")
    try:
        passkeys.revoke(ctx.conn, ctx.admin["id"], passkey_id, actor_name=ctx.admin["username"], ip=ctx.ip,
                        now_ms=ctx.now_ms,
                        password_usable=passkeys.password_usable(ctx.conn, ctx.admin["id"],
                                                                 password_login_enabled(ctx.conn)))
    except service.AccountError as exc:
        return _passkey_form_failure(ctx, exc)
    return RedirectResponse("/account?msg=passkey_revoked", status_code=303)


# ---------------------------------------------------------------------------------------------
# Audit Log page (docs/API.md section 10.2). Read-only, server-rendered, GET filters, keyset paging.
# Deviation for the owner to confirm: the JSON endpoints (/api/v1/audit, /api/v1/audit/{id}) and the
# CSV export are not built; the page does its own querying, as the account page does.


def audit_page(ctx: Ctx) -> Response:
    tz = ctx.admin["timezone"]
    error, status = "", 200
    try:
        f = audit_log.parse_filters(dict(ctx.request.query_params.items()), tz)
    except audit_log.FilterError as exc:
        f, error, status = audit_log.Filters(), str(exc), 400
    rows, next_cursor = audit_log.query(ctx.conn, f)
    events = [{"time": _format_ms(r["ts_ms"], tz), "actor": r["actor_name"], "ip": r["ip"],
               "action": r["action"], "outcome": r["outcome"], "target_type": r["target_type"],
               "target_id": r["target_id"], "detail": audit_log.detail_preview(r["detail"])}
              for r in rows]
    older_url = ""
    if next_cursor:
        keep = {"actor": f.actor, "action": f.action, "outcome": f.outcome,
                "target_type": f.target_type, "target_id": f.target_id, "from": f.from_date,
                "to": f.to_date}
        query = {k: v for k, v in keep.items() if v}
        if f.size != audit_log.DEFAULT_SIZE:
            query["size"] = str(f.size)
        query["before"] = next_cursor
        older_url = "/audit?" + urlencode(query)
    values = {"actor": f.actor, "action": f.action, "outcome": f.outcome,
              "target_type": f.target_type, "target_id": f.target_id, "from_date": f.from_date,
              "to_date": f.to_date}
    return _render("audit.html", status, admin=ctx.admin, nav=NAV, current="/audit",
                   csrf_token=ctx.csrf_token(), events=events, values=values, error=error,
                   outcomes=audit_log.OUTCOMES, older_url=older_url, timezone_name=tz)


# ---------------------------------------------------------------------------------------------
# Administrators page (docs/API.md section 10.1). Create, disable, enable and set-password are class R
# (recent re-authentication). Deviations for the owner to confirm: HTML form posts with redirects, the
# target admin id is a form field (`admin_id`) rather than a path segment, and there is no
# display-name edit for other admins yet.

ADMIN_FLASH = {
    "created": "Administrator created.",
    "disabled": "Account disabled and its sessions signed out.",
    "enabled": "Account enabled.",
    "password_set": "Password set. That administrator's sessions were signed out.",
}


def _admins_page(ctx: Ctx, *, status: int = 200, error: str = "", message: str = "",
                 form_values: dict | None = None) -> Response:
    tz = ctx.admin["timezone"]
    rows = [{"id": r["id"], "username": r["username"], "display_name": r["display_name"],
             "disabled": bool(r["is_disabled"]), "passkey_count": r["passkey_count"],
             "last_login": _format_ms(r["last_login_ms"], tz) if r["last_login_ms"] else "",
             "created_by": r["created_by_name"] or ""} for r in admins_mod.list_admins(ctx.conn)]
    return _render("admins.html", status, admin=ctx.admin, nav=NAV, current="/admins",
                   csrf_token=ctx.csrf_token(), admins=rows, error=error, message=message,
                   form_values=form_values or {"username": "", "display_name": ""},
                   reauth_recent=ctx.state.reauth.is_recent(ctx.session, ctx.now_ms, ctx.limits.reauth_s),
                   window_label=_window_label(ctx.limits.reauth_s), timezone_name=tz,
                   min_length=ctx.limits.min_password_length)


def _sentence(text: str) -> str:
    return text[:1].upper() + text[1:] + "."


def _form_admin_id(ctx: Ctx) -> int | None:
    try:
        return int(ctx.form.get("admin_id", "")[:20])
    except ValueError:
        return None


def admins_get(ctx: Ctx) -> Response:
    return _admins_page(ctx, message=ADMIN_FLASH.get(ctx.request.query_params.get("msg", ""), ""))


def admins_create(ctx: Ctx) -> Response:
    values = {"username": ctx.form.get("username", "").strip()[:64],
              "display_name": ctx.form.get("display_name", "").strip()[:100]}
    password = _password_field(ctx, "password")
    if password != _password_field(ctx, "confirm_password"):
        return _admins_page(ctx, status=400, error="The passwords do not match.", form_values=values)
    try:
        service.create_admin(ctx.conn, ctx.state.hasher, values["username"], password,
                             now_ms=ctx.now_ms, display_name=values["display_name"],
                             created_by=ctx.admin["id"], actor_name=ctx.admin["username"],
                             min_length=ctx.limits.min_password_length)
    except service.AccountError as exc:
        return _admins_page(ctx, status=400, error=_sentence(str(exc)), form_values=values)
    return RedirectResponse("/admins?msg=created", status_code=303)


def _admin_toggle(ctx: Ctx, action, flash: str) -> Response:
    target = _form_admin_id(ctx)
    if target is None:
        return _admins_page(ctx, status=400, error="Choose an administrator.")
    try:
        action(ctx.conn, target, actor_id=ctx.admin["id"], actor_name=ctx.admin["username"],
               ip=ctx.ip, now_ms=ctx.now_ms)
    except admins_mod.AdminActionError as exc:
        return _admins_page(ctx, status=exc.status, error=str(exc))
    return RedirectResponse(f"/admins?msg={flash}", status_code=303)


def admins_disable(ctx: Ctx) -> Response:
    return _admin_toggle(ctx, admins_mod.disable, "disabled")


def admins_enable(ctx: Ctx) -> Response:
    return _admin_toggle(ctx, admins_mod.enable, "enabled")


def admins_password(ctx: Ctx) -> Response:
    target = _form_admin_id(ctx)
    if target is None:
        return _admins_page(ctx, status=400, error="Choose an administrator.")
    if target == ctx.admin["id"]:
        return _admins_page(ctx, status=400,
                            error="Change your own password on the Authentication page.")
    new_password = _password_field(ctx, "new_password")
    if new_password != _password_field(ctx, "confirm_password"):
        return _admins_page(ctx, status=400, error="The passwords do not match.")
    try:
        service.set_password(ctx.conn, ctx.state.hasher, target, new_password, now_ms=ctx.now_ms,
                             actor_admin_id=ctx.admin["id"], actor_name=ctx.admin["username"],
                             action="admin.password_reset", min_length=ctx.limits.min_password_length,
                             ip=ctx.ip)
    except service.AccountError as exc:
        text = str(exc)
        return _admins_page(ctx, status=404 if text == "no such administrator" else 400,
                            error=_sentence(text))
    return RedirectResponse("/admins?msg=password_set", status_code=303)


# ---------------------------------------------------------------------------------------------
# General Settings page (docs/API.md section 10.4). All changes are class R (the API plan makes only
# some keys R; making all of them R is stricter and simpler, owner to confirm). Typed validation lives
# in guard/web/settings_registry.py. Deviations: HTML form posts with redirects, the key travels in a
# form field, and there is no JSON registry endpoint.

SETTINGS_FLASH = {"saved": "Setting saved.", "reset": "Setting reset to its default.",
                  "unchanged": "That setting was already at its default."}


def _settings_page(ctx: Ctx, *, status: int = 200, error: str = "", message: str = "",
                   typed: dict | None = None) -> Response:
    tz = ctx.admin["timezone"]
    rows = settings_registry.stored(ctx.conn)
    grouped: dict = {}
    for s in settings_registry.REGISTRY:
        row = rows.get(s.key)
        value = settings_registry.effective_value(s, row)
        text = (typed or {}).get(s.key)
        if text is None:
            text = settings_registry.display(s, value)
        grouped.setdefault(s.group, []).append({
            "key": s.key, "desc": s.desc, "kind": s.kind, "editable": s.editable,
            "confirm": s.confirm, "choices": s.choices, "custom": row is not None,
            "value_text": text, "default_text": settings_registry.display(s, s.default),
            "rows": min(12, max(3, text.count("\n") + 2)),
            "updated": _format_ms(row["updated_ms"], tz) if row is not None else ""})
    return _render("settings.html", status, admin=ctx.admin, nav=NAV, current="/settings",
                   csrf_token=ctx.csrf_token(), groups=list(grouped.items()), error=error,
                   message=message,
                   reauth_recent=ctx.state.reauth.is_recent(ctx.session, ctx.now_ms, ctx.limits.reauth_s),
                   window_label=_window_label(ctx.limits.reauth_s))


def settings_get(ctx: Ctx) -> Response:
    return _settings_page(ctx, message=SETTINGS_FLASH.get(ctx.request.query_params.get("msg", ""), ""))


def settings_set(ctx: Ctx) -> Response:
    key = ctx.form.get("key", "")[:100]
    raw = ctx.form.get("value", "")[:settings_registry.MAX_JSON_CHARS + 1]
    try:
        settings_registry.set_value(ctx.conn, key, raw, confirm=ctx.form.get("confirm", "")[:20],
                                    admin_id=ctx.admin["id"], admin_name=ctx.admin["username"],
                                    ip=ctx.ip, now_ms=ctx.now_ms)
    except settings_registry.SettingError as exc:
        status = 404 if str(exc) == "Unknown setting." else 400
        return _settings_page(ctx, status=status, error=f"{key[:60]}: {exc}",
                              typed={key: raw} if key in settings_registry.BY_KEY else None)
    return RedirectResponse("/settings?msg=saved", status_code=303)


def settings_reset(ctx: Ctx) -> Response:
    key = ctx.form.get("key", "")[:100]
    try:
        changed = settings_registry.reset_value(ctx.conn, key, confirm=ctx.form.get("confirm", "")[:20],
                                                admin_id=ctx.admin["id"], admin_name=ctx.admin["username"],
                                                ip=ctx.ip, now_ms=ctx.now_ms)
    except settings_registry.SettingError as exc:
        status = 404 if str(exc) == "Unknown setting." else 400
        return _settings_page(ctx, status=status, error=f"{key[:60]}: {exc}")
    return RedirectResponse("/settings?msg=" + ("reset" if changed else "unchanged"), status_code=303)


# ---------------------------------------------------------------------------------------------
# Visitors, request detail and URL History (docs/API.md 7.1 and 7.3). Read-only pages (class A) with GET
# filters and keyset paging; queries live in guard/web/traffic.py and graphs in guard/web/charts.py.
# Deviations for the owner to confirm: server-rendered pages instead of the JSON endpoints, and the
# identifiers travel in query strings (`/visitors/ip?ip=...`, `/url-history/detail?id=...`). CSV exports
# are written to the audit log (`export.visitors`, `export.url_history`).

URL_PERIODS = [("all", "All time"), ("24h", "Last 24 hours"), ("7d", "Last 7 days"),
               ("30d", "Last 30 days")]
URL_RANGES = [("24h", "24 hours"), ("7d", "7 days"), ("30d", "30 days")]


def _qp(ctx: Ctx) -> dict:
    return dict(ctx.request.query_params.items())


def _page_url(path: str, keep: dict, size: int | None = None, before: str = "") -> str:
    query = {k: v for k, v in keep.items() if v}
    if size is not None and size != traffic.DEFAULT_SIZE:
        query["size"] = str(size)
    if before:
        query["before"] = before
    return path + ("?" + urlencode(query) if query else "")


def _next_url(path: str, keep: dict, cursor: str | None, size: int) -> str:
    return _page_url(path, keep, size, cursor) if cursor else ""


def _request_rows(rows, tz: str) -> list:
    return [{"id": r["id"], "time": _format_ms(r["ts_ms"], tz), "ip": r["ip"], "method": r["method"],
             "host": r["host"], "path": r["path"], "query": r["query"] or "", "status": r["status"],
             "status_class": f"{r['status'] // 100}xx", "bytes_in": r["bytes_in"],
             "bytes_out": r["bytes_out"], "duration_ms": r["duration_ms"], "outcome": r["outcome"],
             "reason": r["reason"] or ""} for r in rows]


def _csv_response(text: str, filename: str, truncated: bool) -> Response:
    return Response(text, media_type="text/csv", headers={
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Guard-Truncated": "1" if truncated else "0"})


def _visitor_keep(f: traffic.VisitorFilters) -> dict:
    return {"ip": f.ip_text, "from": f.from_date, "to": f.to_date,
            "sort": f.sort if f.sort != "last_seen" else ""}


def visitors_page(ctx: Ctx) -> Response:
    tz = ctx.admin["timezone"]
    error, status = "", 200
    try:
        f = traffic.parse_visitor_filters(_qp(ctx), tz)
    except traffic.FilterError as exc:
        f, error, status = traffic.VisitorFilters(), str(exc), 400
    rows, cursor = traffic.visitor_page(ctx.conn, f)
    visitors = [{"ip": r["ip"], "first": _format_ms(r["first_seen_ms"], tz),
                 "last": _format_ms(r["last_seen_ms"], tz), "requests": r["request_count"],
                 "bytes_in": r["bytes_in"], "bytes_out": r["bytes_out"], "denied": r["denied_count"]}
                for r in rows]
    keep = _visitor_keep(f)
    values = {"ip": f.ip_text, "from_date": f.from_date, "to_date": f.to_date, "sort": f.sort}
    return _render("visitors.html", status, admin=ctx.admin, nav=NAV, current="/visitors",
                   csrf_token=ctx.csrf_token(), visitors=visitors, values=values, error=error,
                   older_url=_next_url("/visitors", keep, cursor, f.size),
                   export_url=_page_url("/visitors/export.csv", keep), timezone_name=tz)


def visitors_export(ctx: Ctx) -> Response:
    try:
        f = traffic.parse_visitor_filters(_qp(ctx), ctx.admin["timezone"])
    except traffic.FilterError as exc:
        return PlainTextResponse(str(exc), status_code=400)
    rows = traffic.visitor_rows_for_csv(ctx.conn, f)
    truncated = len(rows) > traffic.CSV_MAX_ROWS
    rows = rows[:traffic.CSV_MAX_ROWS]
    ctx.audit("export.visitors", "success", detail={"rows": len(rows), "truncated": truncated})
    return _csv_response(traffic.visitors_to_csv(rows), "visitors.csv", truncated)


def visitor_detail(ctx: Ctx) -> Response:
    tz = ctx.admin["timezone"]
    raw_ip = (ctx.request.query_params.get("ip") or "").strip()[:64]
    row = traffic.visitor_by_ip(ctx.conn, raw_ip)
    if row is None:
        return _render("visitor_detail.html", 404, admin=ctx.admin, nav=NAV, current="/visitors",
                       csrf_token=ctx.csrf_token(), ip=raw_ip, visitor=None, timezone_name=tz)
    error, status = "", 200
    try:
        rf, values = traffic.parse_request_filters(_qp(ctx), tz, visitor_id=row["id"])
    except traffic.FilterError as exc:
        rf = traffic.RequestFilters(visitor_id=row["id"])
        values = {"from_date": "", "to_date": "", "status": ""}
        error, status = str(exc), 400
    reqs, cursor = traffic.request_page(ctx.conn, rf)
    urls, url_total = traffic.visitor_urls(ctx.conn, row["id"])
    visitor = {"requests": row["request_count"], "bytes_in": row["bytes_in"],
               "bytes_out": row["bytes_out"], "denied": row["denied_count"], "url_total": url_total,
               "first": _format_ms(row["first_seen_ms"], tz), "last": _format_ms(row["last_seen_ms"], tz)}
    keep = {"ip": row["ip"], "from": values["from_date"], "to": values["to_date"],
            "status": values["status"]}
    return _render(
        "visitor_detail.html", status, admin=ctx.admin, nav=NAV, current="/visitors",
        csrf_token=ctx.csrf_token(), ip=row["ip"], visitor=visitor, error=error, values=values,
        timezone_name=tz, breakdown_cap=traffic.PER_VISITOR_BREAKDOWN_ROWS,
        methods=traffic.visitor_breakdown(ctx.conn, row["id"], "method", rf.from_ms, rf.to_ms),
        statuses=traffic.visitor_breakdown(ctx.conn, row["id"], "status", rf.from_ms, rf.to_ms),
        urls=[{"url_id": u["url_id"], "host": u["host"], "path": u["path"], "hits": u["hits"],
               "first": _format_ms(u["first_seen_ms"], tz), "last": _format_ms(u["last_seen_ms"], tz)}
              for u in urls],
        agents=[{"value": a["value"], "hits": a["hits"], "first": _format_ms(a["first_seen_ms"], tz),
                 "last": _format_ms(a["last_seen_ms"], tz)}
                for a in traffic.visitor_agents(ctx.conn, row["id"])],
        accounts=[{"uid": a["uid"], "username": a["username"], "hits": a["hits"],
                   "last": _format_ms(a["last_seen_ms"], tz)}
                  for a in traffic.visitor_accounts(ctx.conn, row["id"])],
        requests=_request_rows(reqs, tz), show_ip=False, show_url=True,
        older_url=_next_url("/visitors/ip", keep, cursor, rf.size))


def request_detail_page(ctx: Ctx) -> Response:
    tz = ctx.admin["timezone"]
    raw = (ctx.request.query_params.get("id") or "").strip()
    row = traffic.request_detail(ctx.conn, int(raw)) if raw.isdigit() and len(raw) <= 16 else None
    if row is None:
        return _render("request_detail.html", 404, admin=ctx.admin, nav=NAV, current="/visitors",
                       csrf_token=ctx.csrf_token(), req=None, timezone_name=tz)
    req = dict(row)
    req["time"] = _format_ms(row["ts_ms"], tz)
    req["time_utc"] = traffic.iso_utc(row["ts_ms"])
    return _render("request_detail.html", admin=ctx.admin, nav=NAV, current="/visitors",
                   csrf_token=ctx.csrf_token(), req=req, timezone_name=tz)


def url_history_page(ctx: Ctx) -> Response:
    tz = ctx.admin["timezone"]
    error, status = "", 200
    try:
        f = traffic.parse_url_list_filters(_qp(ctx))
    except traffic.FilterError as exc:
        f, error, status = traffic.UrlListFilters(), str(exc), 400
    rows, cursor = traffic.url_ranking(ctx.conn, f, ctx.now_ms)
    urls = [{"id": r["id"], "host": r["host"], "path": r["path"], "truncated": bool(r["path_truncated"]),
             "hits": r["hits"], "first": _format_ms(r["first_seen_ms"], tz),
             "last": _format_ms(r["last_seen_ms"], tz)} for r in rows]
    keep = {"q": f.q, "period": f.period if f.period != "all" else ""}
    return _render("url_history.html", status, admin=ctx.admin, nav=NAV, current="/url-history",
                   csrf_token=ctx.csrf_token(), urls=urls, error=error, periods=URL_PERIODS,
                   values={"q": f.q, "period": f.period}, size=f.size, timezone_name=tz,
                   older_url=_next_url("/url-history", keep, cursor, f.size))


def _url_detail_filters(ctx: Ctx, params: dict):
    """(filters, error text). A bad filter falls back to the defaults for the same URL id."""
    tz = ctx.admin["timezone"]
    try:
        return traffic.parse_url_detail_filters(params, tz, ctx.now_ms), ""
    except traffic.FilterError as exc:
        message = str(exc)
    return traffic.parse_url_detail_filters({"id": params.get("id", "")}, tz, ctx.now_ms), message


def _url_detail_keep(f: traffic.UrlDetailFilters) -> dict:
    return {"id": str(f.url_id), "range": f.range.key if f.range.key != "custom" else "",
            "from": f.range.from_date, "to": f.range.to_date, "ip": f.ip_text, "status": f.status_text}


def url_detail_page(ctx: Ctx) -> Response:
    tz = ctx.admin["timezone"]
    try:
        f, error = _url_detail_filters(ctx, _qp(ctx))
    except traffic.FilterError as exc:
        return _render("url_detail.html", 400, admin=ctx.admin, nav=NAV, current="/url-history",
                       csrf_token=ctx.csrf_token(), url=None, error=str(exc), timezone_name=tz)
    status = 400 if error else 200
    row = traffic.url_by_id(ctx.conn, f.url_id)
    if row is None:
        return _render("url_detail.html", 404, admin=ctx.admin, nav=NAV, current="/url-history",
                       csrf_token=ctx.csrf_token(), url=None, error="", timezone_name=tz)
    ids = traffic.resolve_visitor_ids(ctx.conn, f.ip_exact, f.ip_prefix)
    summary = traffic.url_summary(ctx.conn, f.url_id, f.range.from_ms, f.range.to_ms, ids, f.status_lo,
                                  f.status_hi)
    reqs, cursor = traffic.url_requests_page(ctx.conn, f, ids)
    unit, buckets = traffic.url_series(ctx.conn, row["id"], row["hit_count"], f.range.from_ms,
                                       f.range.to_ms, tz)
    note = f"per {unit}, {tz}"
    svgs = [
        charts_mod.bar_chart("Requests", [(b.label, b.full_label, b.requests) for b in buckets],
                             value_text=lambda n: f"{n:,}", note=note),
        charts_mod.bar_chart("Received by the site (bytes in)",
                             [(b.label, b.full_label, b.bytes_in) for b in buckets],
                             value_text=traffic.human_bytes, note=note),
        charts_mod.bar_chart("Sent by the site (bytes out)",
                             [(b.label, b.full_label, b.bytes_out) for b in buckets],
                             value_text=traffic.human_bytes, note=note)]
    keep = _url_detail_keep(f)
    base_keep = {"id": str(f.url_id), "ip": f.ip_text, "status": f.status_text}
    return _render(
        "url_detail.html", status, admin=ctx.admin, nav=NAV, current="/url-history",
        csrf_token=ctx.csrf_token(), error=error, timezone_name=tz,
        url={"id": row["id"], "host": row["host"], "path": row["path"],
             "truncated": bool(row["path_truncated"]), "hit_count": row["hit_count"],
             "first": _format_ms(row["first_seen_ms"], tz), "last": _format_ms(row["last_seen_ms"], tz)},
        values={"range": f.range.key, "from_date": f.range.from_date, "to_date": f.range.to_date,
                "ip": f.ip_text, "status": f.status_text},
        ranges=URL_RANGES,
        range_urls={key: _page_url("/url-history/detail", dict(base_keep, range=key)) for key, _ in URL_RANGES},
        range_label=f"{_format_ms(f.range.from_ms, tz)} to {_format_ms(f.range.to_ms - 1, tz)}",
        summary=summary, chart_svgs=svgs, requests=_request_rows(reqs, tz), show_ip=True, show_url=False,
        export_url=_page_url("/url-history/export.csv", keep),
        older_url=_next_url("/url-history/detail", keep, cursor, f.size))


def url_history_export(ctx: Ctx) -> Response:
    try:
        f, error = _url_detail_filters(ctx, _qp(ctx))
    except traffic.FilterError as exc:
        return PlainTextResponse(str(exc), status_code=400)
    if error:
        return PlainTextResponse(error, status_code=400)
    row = traffic.url_by_id(ctx.conn, f.url_id)
    if row is None:
        return PlainTextResponse("Not found", status_code=404)
    ids = traffic.resolve_visitor_ids(ctx.conn, f.ip_exact, f.ip_prefix)
    rows = traffic.url_requests_for_csv(ctx.conn, f, ids)
    truncated = len(rows) > traffic.CSV_MAX_ROWS
    rows = rows[:traffic.CSV_MAX_ROWS]
    ctx.audit("export.url_history", "success", target_type="url", target_id=str(row["id"]),
              detail={"rows": len(rows), "truncated": truncated})
    return _csv_response(traffic.requests_to_csv(rows), f"url-history-{row['id']}.csv", truncated)


# ---------------------------------------------------------------------------------------------
# Application


class SecurityMiddleware:
    """Connection gate, host check (421 for any other Host) and the headers every response carries.

    When the dashboard listens on the LAN (`allowed_peers` is given), only loopback and the trusted
    connectors may connect at all; everyone else gets a bare 403 before any page logic runs, so a
    neighbour on the LAN cannot even reach the login form.
    """

    def __init__(self, app, hostname: str, allowed_peers: frozenset | None = None):
        self.app = app
        self.hostname = hostname.lower()
        self.allowed_peers = allowed_peers

    def _peer_allowed(self, scope) -> bool:
        if self.allowed_peers is None:
            return True
        client = scope.get("client")
        peer = service.canonical_ip(client[0]) if client else "invalid"
        try:
            if ipaddress.ip_address(client[0]).is_loopback:
                return True
        except (ValueError, TypeError, IndexError):
            return False
        return peer in self.allowed_peers

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if not self._peer_allowed(scope):
            await PlainTextResponse("Forbidden", status_code=403)(scope, receive, send)
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
               extra_routes: Callable[[RouteTable], None] | None = None,
               webauthn: passkeys.WebAuthnBackend | None = None) -> Starlette:
    if hasher is None:
        from ..auth.passwords import Argon2Hasher  # noqa: PLC0415
        hasher = Argon2Hasher()
    table = RouteTable()
    table.add("/login", login_get, "P")
    table.add("/login/password", login_password, "P", methods=("POST",))
    table.add("/login/passkey/options", login_passkey_options, "P", methods=("POST",), json_body=True)
    table.add("/login/passkey/verify", login_passkey_verify, "P", methods=("POST",), json_body=True)
    table.add("/healthz", healthz, "P")
    table.add("/logout", logout, "W", methods=("POST",))
    table.add("/", dashboard, "A")
    table.add("/account", account_get, "A")
    table.add("/audit", audit_page, "A")
    table.add("/admins", admins_get, "A")
    table.add("/api/v1/admins", admins_create, "R", methods=("POST",))
    table.add("/api/v1/admins/disable", admins_disable, "R", methods=("POST",))
    table.add("/api/v1/admins/enable", admins_enable, "R", methods=("POST",))
    table.add("/api/v1/admins/password", admins_password, "R", methods=("POST",))
    table.add("/settings", settings_get, "A")
    table.add("/api/v1/settings/set", settings_set, "R", methods=("POST",))
    table.add("/api/v1/settings/reset", settings_reset, "R", methods=("POST",))
    table.add("/visitors", visitors_page, "A")
    table.add("/visitors/ip", visitor_detail, "A")
    table.add("/visitors/request", request_detail_page, "A")
    table.add("/visitors/export.csv", visitors_export, "A")
    table.add("/url-history", url_history_page, "A")
    table.add("/url-history/detail", url_detail_page, "A")
    table.add("/url-history/export.csv", url_history_export, "A")
    table.add("/api/v1/account/password", account_password, "W", methods=("POST",))
    table.add("/api/v1/reauth/password", reauth_password, "W", methods=("POST",))
    table.add("/api/v1/account/sessions/revoke", session_revoke, "W", methods=("POST",))
    table.add("/api/v1/account/sessions/revoke-others", sessions_revoke_others, "W", methods=("POST",))
    table.add("/api/v1/reauth/passkey/options", reauth_passkey_options, "W", methods=("POST",), json_body=True)
    table.add("/api/v1/reauth/passkey/verify", reauth_passkey_verify, "W", methods=("POST",), json_body=True)
    table.add("/api/v1/passkeys/register/options", passkey_register_options, "R", methods=("POST",),
              json_body=True)
    table.add("/api/v1/passkeys/register/verify", passkey_register_verify, "R", methods=("POST",),
              json_body=True)
    table.add("/api/v1/passkeys/rename", passkey_rename, "W", methods=("POST",))
    table.add("/api/v1/passkeys/revoke", passkey_revoke, "R", methods=("POST",))
    table.mount_static("/static", Path(__file__).parent / "static")
    if extra_routes is not None:
        extra_routes(table)
    # docs_url / redoc / openapi do not exist in Starlette; there is nothing to disable.
    app = Starlette(routes=table.routes)
    app.state.cfg = cfg
    app.state.hasher = hasher
    app.state.clock = clock
    app.state.reauth = sessions.ReauthTracker()
    app.state.webauthn = webauthn if webauthn is not None else passkeys.LibraryBackend()
    app.state.challenges = passkeys.ChallengeStore()
    app.state.route_classes = table.classes
    app.state.trusted_ips = trusted_ip_set(cfg.trusted_connectors)
    return _wrap(app, cfg)


def _wrap(app: Starlette, cfg: Config):
    """Wrap with the middleware but keep `.state` and `.routes` reachable for tests and the sweep."""
    gate = app.state.trusted_ips if cfg.dashboard_on_lan else None
    wrapped = SecurityMiddleware(app, cfg.rp_id, gate)
    wrapped.state = app.state
    wrapped.routes = app.routes
    return wrapped
