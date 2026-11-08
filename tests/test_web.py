"""Web layer tests: sign-in, sign-out, CSRF, client IP, headers, route classes (docs/API.md 2, 4, 12).

They drive the ASGI app directly (tests/web_client.py), so they need Starlette and Jinja2 but not
httpx. A fake password hasher keeps them fast; Argon2Hasher is not exercised here.
"""

import hashlib
import re

import pytest

from guard import db
from guard.auth import service, sessions
from guard.config import Config
from guard.web.app import (PUBLIC_ALLOW_LIST, SESSION_COOKIE, PRE_COOKIE, SESSION_IDLE_S, create_app)
from tests.web_client import Client

pytest.importorskip("starlette")
pytest.importorskip("jinja2")

ORIGIN = "https://guard.example.org"
PASSWORD = "correct horse battery staple"


class FakeHasher:
    def hash(self, password):
        return "$argon2id$fake$" + hashlib.sha256(password.encode()).hexdigest()

    def verify(self, stored, password):
        return stored == self.hash(password)

    def needs_rehash(self, stored):
        return False


class Clock:
    def __init__(self, start=1_800_000_000_000):
        self.now = start

    def __call__(self):
        return self.now


@pytest.fixture
def env(tmp_path):
    cfg = Config(db_path=str(tmp_path / "guard.sqlite3"), external_origin=ORIGIN,
                 trusted_connectors=(), secret_key=bytes(range(32)))
    conn = db.connect(cfg.db_path)
    db.migrate(conn)
    clock = Clock()
    service.create_admin(conn, FakeHasher(), "alice", PASSWORD, now_ms=clock())
    app = create_app(cfg, hasher=FakeHasher(), clock=clock)
    yield type("Env", (), {"cfg": cfg, "conn": conn, "clock": clock, "app": app})
    conn.close()


def token_from(response) -> str:
    return re.search(r'name="csrf_token" value="([^"]+)"', response.text).group(1)


def sign_in(env, client=None, username="alice", password=PASSWORD):
    client = client or Client(env.app)
    token = token_from(client.get("/login"))
    return client, client.post("/login/password", form={"username": username, "password": password,
                                                        "csrf_token": token})


def audit_actions(env):
    return [r["action"] for r in env.conn.execute("SELECT action FROM audit_events ORDER BY id")]


# ---- public routes, headers, host ------------------------------------------------------------

def test_healthz_and_headers(env):
    r = Client(env.app).get("/healthz")
    assert r.status == 200 and r.text == '{"status":"ok"}'
    assert r.header("x-content-type-options") == "nosniff"
    assert r.header("referrer-policy") == "same-origin"
    assert r.header("cache-control") == "no-store"


def test_wrong_host_is_421(env):
    for host in ("evil.example.com", "", "guard.example.org.evil.com"):
        assert Client(env.app).get("/healthz", host=host).status == 421


def test_host_with_port_is_accepted(env):
    assert Client(env.app).get("/healthz", host="guard.example.org:443").status == 200


def test_login_page_sets_pre_cookie_and_csp(env):
    r = Client(env.app).get("/login")
    assert r.status == 200
    csp = r.header("content-security-policy")
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    cookie = r.set_cookies()[0]
    assert cookie.startswith(PRE_COOKIE + "=")
    for flag in ("HttpOnly", "Secure", "SameSite=lax", "Path=/"):
        assert flag.lower() in cookie.lower()
    assert "domain" not in cookie.lower()
    assert 'name="password"' in r.text


def test_login_page_has_no_inline_script_or_style(env):
    text = Client(env.app).get("/login").text.lower()
    assert "<script" not in text and "<style" not in text and " style=" not in text


def test_docs_routes_do_not_exist(env):
    c = Client(env.app)
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert c.get(path).status == 404


def test_internal_routes_are_not_on_dashboard(env):
    c = Client(env.app)
    for path in ("/check", "/block", "/readyz"):
        assert c.get(path).status == 404


# ---- password sign-in ------------------------------------------------------------------------

def test_sign_in_success(env):
    client, r = sign_in(env)
    assert r.status == 303 and r.header("location") == "/"
    session_cookie = next(c for c in r.set_cookies() if c.startswith(SESSION_COOKIE + "="))
    for flag in ("HttpOnly", "Secure", "SameSite=lax", "Path=/"):
        assert flag.lower() in session_cookie.lower()
    assert PRE_COOKIE not in client.cookies and SESSION_COOKIE in client.cookies
    page = client.get("/")
    assert page.status == 200 and "alice" in page.text and "Sign out" in page.text
    assert "auth.login" in audit_actions(env)
    row = env.conn.execute("SELECT last_login_ms FROM admins WHERE username='alice'").fetchone()
    assert row["last_login_ms"] == env.clock()


def test_session_token_is_not_stored_in_database(env):
    client, _ = sign_in(env)
    token = client.cookies[SESSION_COOKIE]
    stored = [bytes(r[0]) for r in env.conn.execute("SELECT token_hash FROM sessions")]
    assert all(token.encode() not in blob for blob in stored)
    assert sessions.hash_token(token) in stored


def test_wrong_password_and_unknown_user_look_identical(env):
    _, bad_pw = sign_in(env, password="wrong password here")
    _, no_user = sign_in(env, username="nobody")
    assert bad_pw.status == no_user.status == 401
    assert "Invalid username or password." in bad_pw.text and "Invalid username or password." in no_user.text
    assert SESSION_COOKIE not in bad_pw.text
    assert audit_actions(env).count("auth.login_failed") == 2


def test_failed_login_page_can_be_resubmitted(env):
    client, bad = sign_in(env, password="wrong password here")
    assert bad.status == 401
    r = client.post("/login/password", form={"username": "alice", "password": PASSWORD,
                                             "csrf_token": token_from(bad)})
    assert r.status == 303


def test_login_requires_csrf_token(env):
    client = Client(env.app)
    client.get("/login")
    for form in ({"username": "alice", "password": PASSWORD},
                 {"username": "alice", "password": PASSWORD, "csrf_token": "nope"}):
        r = client.post("/login/password", form=form)
        assert r.status == 403
    assert SESSION_COOKIE not in client.cookies
    assert audit_actions(env).count("auth.csrf_failure") == 2


def test_login_without_pre_cookie_is_rejected(env):
    donor = Client(env.app)
    token = token_from(donor.get("/login"))
    r = Client(env.app).post("/login/password", form={"username": "alice", "password": PASSWORD,
                                                      "csrf_token": token})
    assert r.status == 403


def test_login_with_other_browsers_token_is_rejected(env):
    a, b = Client(env.app), Client(env.app)
    token_a = token_from(a.get("/login"))
    b.get("/login")
    assert b.post("/login/password", form={"username": "alice", "password": PASSWORD,
                                           "csrf_token": token_a}).status == 403


def test_login_checks_origin(env):
    client = Client(env.app)
    token = token_from(client.get("/login"))
    form = {"username": "alice", "password": PASSWORD, "csrf_token": token}
    assert client.post("/login/password", form=form, headers={"origin": "https://evil.example.com"}).status == 403
    assert client.post("/login/password", form=form, send_origin=False).status == 403
    ok = client.post("/login/password", form=form, send_origin=False,
                     headers={"referer": ORIGIN + "/login"})
    assert ok.status == 303


def test_lockout_after_repeated_failures(env):
    client = Client(env.app)
    last = None
    for _ in range(5):
        token = token_from(client.get("/login"))
        last = client.post("/login/password", form={"username": "alice", "password": "bad password!!",
                                                    "csrf_token": token})
    assert last.status in (401, 429)
    token = token_from(client.get("/login"))
    locked = client.post("/login/password", form={"username": "alice", "password": PASSWORD,
                                                  "csrf_token": token})
    assert locked.status == 429 and int(locked.header("retry-after")) > 0
    assert SESSION_COOKIE not in client.cookies
    assert "auth.lockout" in audit_actions(env)


def test_password_login_can_be_disabled_by_setting(env):
    client = Client(env.app)
    token = token_from(client.get("/login"))  # fetched while the form still exists
    env.conn.execute("INSERT INTO settings(key, value, updated_ms) VALUES ('auth.password_login_enabled','false',1)")
    r = client.post("/login/password", form={"username": "alice", "password": PASSWORD, "csrf_token": token})
    assert r.status == 401 and SESSION_COOKIE not in client.cookies
    assert 'name="password"' not in Client(env.app).get("/login").text


def test_overlong_password_does_not_crash(env):
    _, r = sign_in(env, password="x" * 5000)
    assert r.status == 401


def test_body_too_large(env):
    r = Client(env.app).post("/login/password", body=b"a=" + b"b" * 70_000,
                             content_type="application/x-www-form-urlencoded")
    assert r.status == 413


def test_non_form_post_is_rejected_by_csrf(env):
    client = Client(env.app)
    client.get("/login")
    r = client.post("/login/password", body=b'{"username":"alice"}', content_type="application/json")
    assert r.status == 403


def test_signed_in_user_visiting_login_is_redirected(env):
    client, _ = sign_in(env)
    r = client.get("/login")
    assert r.status == 303 and r.header("location") == "/"


# ---- sessions, logout ------------------------------------------------------------------------

def test_dashboard_requires_session(env):
    r = Client(env.app).get("/")
    assert r.status == 303 and r.header("location") == "/login"


def test_garbage_session_cookie_is_ignored(env):
    c = Client(env.app)
    c.cookies[SESSION_COOKIE] = "x" * 500
    assert c.get("/").status == 303
    c.cookies[SESSION_COOKIE] = "!!!not-base64!!!"
    assert c.get("/").status == 303


def test_idle_session_expires(env):
    client, _ = sign_in(env)
    env.clock.now += (SESSION_IDLE_S + 1) * 1000
    assert client.get("/").status == 303


def test_activity_keeps_session_alive_within_idle_window(env):
    client, _ = sign_in(env)
    for _ in range(4):
        env.clock.now += (SESSION_IDLE_S - 60) * 1000
        assert client.get("/").status == 200


def test_disabled_admin_session_stops_working(env):
    client, _ = sign_in(env)
    env.conn.execute("UPDATE admins SET is_disabled = 1 WHERE username='alice'")
    assert client.get("/").status == 303


def test_logout_needs_csrf_token_and_origin(env):
    client, _ = sign_in(env)
    assert client.post("/logout", form={}).status == 403
    assert client.post("/logout", form={"csrf_token": "wrong"}).status == 403
    token = token_from(client.get("/"))
    assert client.post("/logout", form={"csrf_token": token}, headers={"origin": "https://evil.example.com"}).status == 403
    assert client.get("/").status == 200  # still signed in after the rejected attempts
    assert audit_actions(env).count("auth.csrf_failure") == 3


def test_logout_revokes_session_server_side(env):
    client, _ = sign_in(env)
    stolen = client.cookies[SESSION_COOKIE]
    r = client.post("/logout", form={"csrf_token": token_from(client.get("/"))})
    assert r.status == 303 and r.header("location") == "/login"
    assert SESSION_COOKIE not in client.cookies
    replay = Client(env.app)
    replay.cookies[SESSION_COOKIE] = stolen
    assert replay.get("/").status == 303
    assert "auth.logout" in audit_actions(env)


def test_csrf_token_of_another_session_is_rejected(env):
    a, _ = sign_in(env)
    b, _ = sign_in(env)
    token_b = token_from(b.get("/"))
    assert a.post("/logout", form={"csrf_token": token_b}).status == 403


def test_csrf_header_is_accepted_as_well_as_form_field(env):
    client, _ = sign_in(env)
    token = token_from(client.get("/"))
    assert client.post("/logout", form={}, headers={"x-csrf-token": token}).status == 303


# ---- trusted client IP -----------------------------------------------------------------------

def session_ip(env):
    return env.conn.execute("SELECT ip FROM sessions ORDER BY id DESC LIMIT 1").fetchone()["ip"]


def test_loopback_peer_may_set_client_ip_header(env):
    client = Client(env.app)
    token = token_from(client.get("/login", headers={"x-guard-client-ip": "203.0.113.9"}))
    client.post("/login/password", form={"username": "alice", "password": PASSWORD, "csrf_token": token},
                headers={"x-guard-client-ip": "203.0.113.9"})
    assert session_ip(env) == "203.0.113.9"


def test_non_loopback_peer_cannot_set_client_ip_header(env):
    client = Client(env.app, peer=("198.51.100.7", 40000))
    token = token_from(client.get("/login"))
    client.post("/login/password", form={"username": "alice", "password": PASSWORD, "csrf_token": token},
                headers={"x-guard-client-ip": "203.0.113.9"})
    assert session_ip(env) == "198.51.100.7"


def test_forwarded_headers_are_never_used(env):
    client = Client(env.app, peer=("198.51.100.7", 40000))
    spoof = {"x-forwarded-for": "203.0.113.9", "cf-connecting-ip": "203.0.113.10", "x-real-ip": "203.0.113.11"}
    token = token_from(client.get("/login"))
    client.post("/login/password", form={"username": "alice", "password": PASSWORD, "csrf_token": token},
                headers=spoof)
    assert session_ip(env) == "198.51.100.7"
    loop = Client(env.app)
    token = token_from(loop.get("/login"))
    loop.post("/login/password", form={"username": "alice", "password": PASSWORD, "csrf_token": token},
              headers=spoof)
    assert session_ip(env) == "127.0.0.1"


def test_malformed_client_ip_header_falls_back_to_peer(env):
    client = Client(env.app)
    token = token_from(client.get("/login"))
    client.post("/login/password", form={"username": "alice", "password": PASSWORD, "csrf_token": token},
                headers={"x-guard-client-ip": "not an ip"})
    assert session_ip(env) == "127.0.0.1"


# ---- static files ----------------------------------------------------------------------------

def test_static_file_served_with_cacheable_headers(env):
    r = Client(env.app).get("/static/style.css")
    assert r.status == 200 and "text/css" in r.header("content-type")
    assert r.header("x-content-type-options") == "nosniff"
    assert r.header("cache-control") != "no-store"


@pytest.mark.parametrize("path", ["/static/../config.py", "/static/%2e%2e/config.py",
                                  "/static/..%2fconfig.py", "/static/missing.css", "/static/"])
def test_static_path_traversal_is_rejected(env, path):
    assert Client(env.app).get(path).status in (400, 404)


# ---- route sweep (docs/API.md section 12) ----------------------------------------------------

def walk(app):
    for route in app.routes:
        path = route.path
        methods = sorted(m for m in (getattr(route, "methods", None) or {"GET"}) if m not in ("HEAD", "OPTIONS"))
        yield path, methods


def test_every_route_has_a_class(env):
    classes = env.app.state.route_classes
    for path, methods in walk(env.app):
        for method in methods:
            assert (path, method) in classes, f"{method} {path} has no route class"


def test_public_routes_are_on_the_allow_list(env):
    for (path, _), cls in env.app.state.route_classes.items():
        if cls == "P":
            assert path in PUBLIC_ALLOW_LIST, f"{path} is public but not on the allow-list"


def test_unauthenticated_requests_to_admin_routes_are_refused(env):
    c = Client(env.app)
    for (path, method), cls in env.app.state.route_classes.items():
        if cls in ("A", "W", "R"):
            r = c.request(method, path, form={} if method != "GET" else None)
            assert r.status in (303, 401), f"{method} {path} -> {r.status}"
            if r.status == 303:
                assert r.header("location") == "/login"


def test_write_routes_reject_missing_token_and_wrong_origin(env):
    client, _ = sign_in(env)
    token = token_from(client.get("/"))
    for (path, method), cls in env.app.state.route_classes.items():
        if cls in ("W", "R"):
            assert client.request(method, path, form={}).status == 403
            assert client.request(method, path, form={"csrf_token": token},
                                  headers={"origin": "https://evil.example.com"}).status == 403


def test_expired_session_is_refused_on_every_admin_route(env):
    client, _ = sign_in(env)
    env.clock.now += (SESSION_IDLE_S + 1) * 1000
    for (path, method), cls in env.app.state.route_classes.items():
        if cls in ("A", "W", "R"):
            assert client.request(method, path, form={} if method != "GET" else None).status in (303, 401)


def test_unknown_route_class_is_rejected_at_registration(env):
    from guard.web.app import RouteTable
    with pytest.raises(ValueError):
        RouteTable().add("/x", lambda ctx: None, "Z")


# ---- class R and API-style errors (via a test-only route table entry) ------------------------

def make_extra(table):
    from starlette.responses import JSONResponse
    table.add("/api/v1/_probe_read", lambda ctx: JSONResponse({"ok": True}), "A")
    table.add("/api/v1/_probe_reauth", lambda ctx: JSONResponse({"ok": True}), "R", methods=("POST",))


@pytest.fixture
def probe_env(env, tmp_path):
    env.app = create_app(env.cfg, hasher=FakeHasher(), clock=env.clock, extra_routes=make_extra)
    return env


def test_api_unauthenticated_is_401_json(probe_env):
    r = Client(probe_env.app).get("/api/v1/_probe_read")
    assert r.status == 401 and '"unauthenticated"' in r.text


def test_reauth_route_allows_fresh_session(probe_env):
    client, _ = sign_in(probe_env)
    token = token_from(client.get("/"))
    r = client.post("/api/v1/_probe_reauth", form={"csrf_token": token})
    assert r.status == 200


def test_reauth_route_refuses_old_session(probe_env):
    client, _ = sign_in(probe_env)
    token = token_from(client.get("/"))
    probe_env.clock.now += 400 * 1000  # past the 300 s window but inside the idle limit
    client.get("/")                    # activity does not count as re-authentication
    r = client.post("/api/v1/_probe_reauth", form={"csrf_token": token})
    assert r.status == 403 and '"reauth_required"' in r.text
    assert "auth.reauth_required" in audit_actions(probe_env)


def test_api_csrf_failure_is_json(probe_env):
    client, _ = sign_in(probe_env)
    r = client.post("/api/v1/_probe_reauth", form={})
    assert r.status == 403 and '"csrf_failed"' in r.text
