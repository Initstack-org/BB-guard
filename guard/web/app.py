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
from ..auth import csrf, service, sessions
from ..config import Config
from . import audit_log
from . import admins as admins_mod
from . import limits as limits_mod

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
    ("Administration", [("Administrators", "/admins", True),
                        ("Authentication / Passkeys", "/account", True),
                        ("Audit Log", "/audit", True), ("API Settings", "/settings/api", False),
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
# Account page, re-authentication and own sessions (docs/API.md section 5)
#
# Deviations from API.md, both for the owner to confirm (see CHANGES.md): these routes take HTML
# form posts and answer with a redirect or a re-rendered page, not JSON; and the password change
# is class W rather than R, because it already requires the current password, which is stronger
# than the re-authentication window and avoids a raw JSON error on a form post.

FLASH = {
    "password_changed": "Password changed. Your other sessions were signed out.",
    "reauth_ok": "Password confirmed.",
    "session_revoked": "Session signed out.",
    "sessions_revoked": "Your other sessions were signed out.",
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
                   min_length=ctx.limits.min_password_length)


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
    table.add("/account", account_get, "A")
    table.add("/audit", audit_page, "A")
    table.add("/admins", admins_get, "A")
    table.add("/api/v1/admins", admins_create, "R", methods=("POST",))
    table.add("/api/v1/admins/disable", admins_disable, "R", methods=("POST",))
    table.add("/api/v1/admins/enable", admins_enable, "R", methods=("POST",))
    table.add("/api/v1/admins/password", admins_password, "R", methods=("POST",))
    table.add("/api/v1/account/password", account_password, "W", methods=("POST",))
    table.add("/api/v1/reauth/password", reauth_password, "W", methods=("POST",))
    table.add("/api/v1/account/sessions/revoke", session_revoke, "W", methods=("POST",))
    table.add("/api/v1/account/sessions/revoke-others", sessions_revoke_others, "W", methods=("POST",))
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
