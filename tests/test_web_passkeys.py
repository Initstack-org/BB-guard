"""Passkey routes end to end (docs/API.md sections 4 and 5), with a fake WebAuthn backend.

Sign-in, registration, re-authentication, rename and revoke are driven over the ASGI app like a browser
would: cookies, CSRF header, JSON bodies. The backend is the fake from tests/passkey_helpers.py, so these
tests need Starlette and Jinja2 but not the `webauthn` package.
"""

import json
import re

import pytest

from guard import db
from guard.auth import service
from guard.auth.passkeys import ChallengeStore
from guard.config import Config
from guard.web.app import PRE_COOKIE, SESSION_COOKIE, create_app
from tests.passkey_helpers import FakeAuthenticator, FakeBackend, admin_handle, b64u, enroll
from tests.test_web import ORIGIN, PASSWORD, Clock, FakeHasher, sign_in, token_from
from tests.web_client import Client

pytest.importorskip("starlette")
pytest.importorskip("jinja2")


@pytest.fixture
def env(tmp_path):
    cfg = Config(db_path=str(tmp_path / "guard.sqlite3"), external_origin=ORIGIN,
                 trusted_connectors=(), secret_key=bytes(range(32)))
    conn = db.connect(cfg.db_path)
    db.migrate(conn)
    clock = Clock()
    alice = service.create_admin(conn, FakeHasher(), "alice", PASSWORD, now_ms=clock())
    backend = FakeBackend()
    app = create_app(cfg, hasher=FakeHasher(), clock=clock, webauthn=backend)
    yield type("Env", (), {"cfg": cfg, "conn": conn, "clock": clock, "app": app, "backend": backend,
                           "alice": alice, "store": ChallengeStore()})
    conn.close()


def post_json(client, path, payload, token):
    return client.post(path, body=json.dumps(payload).encode(), content_type="application/json",
                       headers={"X-CSRF-Token": token})


def body(response):
    return json.loads(response.text)


def signed_in(env):
    client, response = sign_in(env)
    assert response.status == 303
    return client, token_from(client.get("/account"))


def enrolled(env, name="Phone", admin=None, **kw):
    return enroll(env.conn, env.backend, env.store, admin or env.alice, name=name, binding=f"x-{name}", **kw)


def login_options(client):
    token = token_from(client.get("/login"))
    return token, body(post_json(client, "/login/passkey/options", {}, token))["data"]


def second_admin(env, name="bob"):
    return service.create_admin(env.conn, FakeHasher(), name, PASSWORD, now_ms=env.clock())


def audit_details(env, action, outcome=None):
    sql = "SELECT detail FROM audit_events WHERE action = ?" + (" AND outcome = ?" if outcome else "")
    rows = env.conn.execute(sql, (action, outcome) if outcome else (action,)).fetchall()
    return [json.loads(r["detail"]) for r in rows]


def app_without_library(env):
    return create_app(env.cfg, hasher=FakeHasher(), clock=env.clock, webauthn=FakeBackend(available=False))


# ---- pages and static file -------------------------------------------------------------------

def test_login_page_offers_passkeys_with_one_external_script(env):
    text = Client(env.app).get("/login").text
    assert 'id="passkey-signin"' in text and 'name="password"' in text
    assert re.findall(r"<script[^>]*>", text) == ['<script src="/static/passkeys.js" defer>']


def test_login_page_hides_passkeys_without_the_library(env):
    text = Client(app_without_library(env)).get("/login").text
    assert "passkey-signin" not in text and "/static/passkeys.js" not in text
    assert 'name="password"' in text


def test_the_script_is_served_and_free_of_dangerous_sinks(env):
    r = Client(env.app).get("/static/passkeys.js")
    assert r.status == 200 and "navigator.credentials" in r.text
    for sink in ("innerHTML", "eval(", "document.write", "localStorage", "sessionStorage"):
        assert sink not in r.text


def test_account_page_lists_passkeys_without_secrets(env):
    authn, _ = enrolled(env, "Work laptop")
    client, _ = signed_in(env)
    text = client.get("/account").text
    assert "Work laptop" in text and 'id="passkey-add"' in text and "/static/passkeys.js" in text
    assert "Device-bound" in text
    for secret in (b64u(authn.credential_id), authn.credential_id.hex(), b64u(authn.public_key),
                   authn.public_key.hex()):
        assert secret not in text


def test_account_page_explains_a_missing_library(env):
    client, response = sign_in(type("E", (), {"app": app_without_library(env)}))
    assert response.status == 303
    text = client.get("/account").text
    assert "webauthn" in text and 'id="passkey-add"' not in text and "/static/passkeys.js" not in text


def test_passkey_routes_have_the_expected_classes(env):
    classes = env.app.state.route_classes
    expected = {"/login/passkey/options": "P", "/login/passkey/verify": "P",
                "/api/v1/reauth/passkey/options": "W", "/api/v1/reauth/passkey/verify": "W",
                "/api/v1/passkeys/register/options": "R", "/api/v1/passkeys/register/verify": "R",
                "/api/v1/passkeys/rename": "W", "/api/v1/passkeys/revoke": "R"}
    for path, cls in expected.items():
        assert classes[(path, "POST")] == cls


@pytest.mark.parametrize("path", ["/api/v1/reauth/passkey/options", "/api/v1/reauth/passkey/verify",
                                  "/api/v1/passkeys/register/options", "/api/v1/passkeys/register/verify",
                                  "/api/v1/passkeys/rename", "/api/v1/passkeys/revoke"])
def test_management_routes_need_a_session(env, path):
    r = Client(env.app).post(path, body=b"{}", content_type="application/json")
    assert r.status == 401 and body(r)["error"]["code"] == "unauthenticated"


# ---- sign-in ---------------------------------------------------------------------------------

def test_sign_in_options_need_the_pre_session_token(env):
    client = Client(env.app)
    token = token_from(client.get("/login"))
    path = "/login/passkey/options"
    attempts = [
        client.post(path, body=b"{}", content_type="application/json"),
        post_json(client, path, {}, "not-the-token"),
        client.post(path, body=b"{}", content_type="application/json",
                    headers={"X-CSRF-Token": token, "Origin": "https://evil.example.org"}),
        post_json(Client(env.app), path, {}, token)]   # a browser with no pre-session cookie
    for r in attempts:
        assert r.status == 403 and body(r)["error"]["code"] == "csrf_failed"
    assert len(audit_details(env, "auth.csrf_failure", "denied")) == 4
    assert len(env.app.state.challenges) == 0


def test_sign_in_options_hold_a_challenge_and_name_no_account(env):
    client = Client(env.app)
    token = token_from(client.get("/login"))
    r = post_json(client, "/login/passkey/options", {}, token)
    assert r.status == 200 and r.header("content-type").startswith("application/json")
    assert r.header("cache-control") == "no-store"
    data = body(r)["data"]
    assert data["rpId"] == "guard.example.org" and data["userVerification"] == "required"
    assert not data.get("allowCredentials") and len(env.app.state.challenges) == 1


def test_sign_in_is_unavailable_without_the_library(env):
    client = Client(app_without_library(env))
    token = token_from(client.get("/login"))
    for path in ("/login/passkey/options", "/login/passkey/verify"):
        r = post_json(client, path, {"credential": {}}, token)
        assert r.status == 503 and body(r)["error"]["code"] == "unavailable"


def test_passkey_sign_in_end_to_end(env):
    authn, _ = enrolled(env)
    client = Client(env.app)
    token, options = login_options(client)
    credential = authn.get(options["challenge"], user_handle=admin_handle(env.conn, env.alice))
    r = post_json(client, "/login/passkey/verify", {"credential": credential}, token)
    assert r.status == 200 and body(r) == {"data": {"redirect": "/"}}
    cookie = next(c for c in r.set_cookies() if c.startswith(SESSION_COOKIE + "="))
    for flag in ("HttpOnly", "Secure", "SameSite=lax", "Path=/"):
        assert flag.lower() in cookie.lower()
    assert PRE_COOKIE not in client.cookies and SESSION_COOKIE in client.cookies
    page = client.get("/")
    assert page.status == 200 and "alice" in page.text
    assert env.conn.execute("SELECT auth_method FROM sessions").fetchone()[0] == "passkey"
    assert audit_details(env, "auth.login", "success") == [{"method": "passkey", "passkey": "Phone"}]
    # Signing in with a passkey counts as recent confirmation, so sensitive routes open at once.
    account_token = token_from(client.get("/account"))
    assert post_json(client, "/api/v1/passkeys/register/options", {"name": "Second"},
                     account_token).status == 200


def test_failed_sign_ins_look_the_same(env):
    alice_key, _ = enrolled(env)
    bob = second_admin(env)
    bob_key, _ = enrolled(env, "Bob phone", admin=bob)
    env.conn.execute("UPDATE admins SET is_disabled = 1, disabled_ms = ? WHERE id = ?", (env.clock(), bob))
    client = Client(env.app)
    token = token_from(client.get("/login"))
    outcomes = []
    for authn, extra in ((FakeAuthenticator(), {}), (alice_key, {"bad_signature": True}), (bob_key, {})):
        options = body(post_json(client, "/login/passkey/options", {}, token))["data"]
        r = post_json(client, "/login/passkey/verify",
                      {"credential": authn.get(options["challenge"], **extra)}, token)
        outcomes.append((r.status, r.text))
    outcomes.append(tuple(
        (r.status, r.text) for r in [post_json(client, "/login/passkey/verify",
                                               {"credential": alice_key.get(b64u(b"x" * 32))}, token)])[0])
    assert len(set(outcomes)) == 1 and outcomes[0][0] == 401
    assert SESSION_COOKIE not in client.cookies


def test_verify_needs_a_credential_object(env):
    client = Client(env.app)
    token = token_from(client.get("/login"))
    assert post_json(client, "/login/passkey/verify", {}, token).status == 400
    assert post_json(client, "/login/passkey/verify", {"credential": "text"}, token).status == 400
    r = client.post("/login/passkey/verify", form={"credential": "x"}, headers={"X-CSRF-Token": token})
    assert r.status == 400 and body(r)["error"]["code"] == "bad_request"


def test_a_challenge_belongs_to_one_browser(env):
    authn, _ = enrolled(env)
    first = Client(env.app)
    _, options = login_options(first)
    credential = authn.get(options["challenge"])
    second = Client(env.app)
    token = token_from(second.get("/login"))
    r = post_json(second, "/login/passkey/verify", {"credential": credential}, token)
    assert r.status == 401 and SESSION_COOKIE not in second.cookies


def test_repeated_failures_lock_the_address_for_passkeys_too(env):
    client = Client(env.app)
    token = token_from(client.get("/login"))
    stranger, last = FakeAuthenticator(), None
    for _ in range(5):
        options = body(post_json(client, "/login/passkey/options", {}, token))["data"]
        last = post_json(client, "/login/passkey/verify",
                         {"credential": stranger.get(options["challenge"])}, token)
    assert last.status == 429 and int(last.header("retry-after")) > 0
    assert post_json(client, "/login/passkey/options", {}, token).status == 429


# ---- registration ----------------------------------------------------------------------------

def test_registration_over_http(env):
    client, token = signed_in(env)
    options = body(post_json(client, "/api/v1/passkeys/register/options", {"name": "Phone"}, token))["data"]
    assert options["user"]["name"] == "alice" and options["rp"]["id"] == "guard.example.org"
    authn = FakeAuthenticator()
    r = post_json(client, "/api/v1/passkeys/register/verify",
                  {"credential": authn.create(options["challenge"]), "name": "Phone"}, token)
    assert r.status == 200 and body(r)["data"]["name"] == "Phone"
    row = env.conn.execute("SELECT name, admin_id FROM passkeys").fetchone()
    assert (row["name"], row["admin_id"]) == ("Phone", env.alice)
    assert audit_details(env, "passkey.add", "success")[0]["name"] == "Phone"
    assert "Passkey added." in client.get("/account?msg=passkey_added").text


def test_registration_refuses_a_taken_name_before_the_device_is_asked(env):
    enrolled(env, "Phone")
    client, token = signed_in(env)
    r = post_json(client, "/api/v1/passkeys/register/options", {"name": "phone"}, token)
    assert r.status == 409 and body(r)["error"]["code"] == "conflict"
    r = post_json(client, "/api/v1/passkeys/register/options", {"name": "   "}, token)
    assert r.status == 400 and body(r)["error"]["code"] == "invalid"


def test_registration_that_does_not_verify_stores_nothing(env):
    client, token = signed_in(env)
    options = body(post_json(client, "/api/v1/passkeys/register/options", {"name": "Phone"}, token))["data"]
    bad = FakeAuthenticator().create(options["challenge"], origin="https://evil.example.org")
    r = post_json(client, "/api/v1/passkeys/register/verify", {"credential": bad, "name": "Phone"}, token)
    assert r.status == 400 and body(r)["error"]["code"] == "verification_failed"
    assert "Origin" not in r.text   # the person is never told which check failed
    assert env.conn.execute("SELECT COUNT(*) FROM passkeys").fetchone()[0] == 0
    assert audit_details(env, "passkey.add", "failure") == [{"reason": "registration_invalid:Origin"}]


def test_registration_verify_needs_a_credential(env):
    client, token = signed_in(env)
    r = post_json(client, "/api/v1/passkeys/register/verify", {"name": "Phone"}, token)
    assert r.status == 400 and body(r)["error"]["code"] == "bad_request"


def test_registration_needs_csrf_and_recent_confirmation(env):
    client, token = signed_in(env)
    r = client.post("/api/v1/passkeys/register/options", body=b'{"name":"Phone"}',
                    content_type="application/json")
    assert r.status == 403 and body(r)["error"]["code"] == "csrf_failed"
    env.clock.now += 400_000   # past the five-minute confirmation window
    for path in ("/api/v1/passkeys/register/options", "/api/v1/passkeys/register/verify"):
        r = post_json(client, path, {"name": "Phone"}, token)
        assert r.status == 403 and body(r)["error"]["code"] == "reauth_required"


# ---- re-authentication with a passkey --------------------------------------------------------

def test_passkey_confirmation_reopens_sensitive_routes(env):
    authn, _ = enrolled(env)
    client, token = signed_in(env)
    env.clock.now += 400_000
    assert post_json(client, "/api/v1/passkeys/register/options", {"name": "X"}, token).status == 403
    options = body(post_json(client, "/api/v1/reauth/passkey/options", {}, token))["data"]
    assert [c["id"] for c in options["allowCredentials"]] == [b64u(authn.credential_id)]
    r = post_json(client, "/api/v1/reauth/passkey/verify",
                  {"credential": authn.get(options["challenge"])}, token)
    assert r.status == 200 and body(r) == {"data": {"ok": True}}
    assert post_json(client, "/api/v1/passkeys/register/options", {"name": "X"}, token).status == 200
    assert audit_details(env, "auth.reauth", "success") == [{"method": "passkey", "passkey": "Phone"}]


def test_passkey_confirmation_needs_a_passkey(env):
    client, token = signed_in(env)
    r = post_json(client, "/api/v1/reauth/passkey/options", {}, token)
    assert r.status == 404 and body(r)["error"]["code"] == "not_found"


def test_a_wrong_passkey_confirmation_is_refused_and_does_not_reopen_anything(env):
    authn, _ = enrolled(env)
    client, token = signed_in(env)
    env.clock.now += 400_000
    options = body(post_json(client, "/api/v1/reauth/passkey/options", {}, token))["data"]
    r = post_json(client, "/api/v1/reauth/passkey/verify",
                  {"credential": authn.get(options["challenge"], bad_signature=True)}, token)
    assert r.status == 403 and body(r)["error"]["code"] == "invalid"
    assert post_json(client, "/api/v1/passkeys/register/options", {"name": "X"}, token).status == 403
    assert audit_details(env, "auth.reauth", "failure")[0]["reason"] == "assertion_invalid:Signature"


def test_passkey_confirmation_refuses_another_admins_passkey(env):
    enrolled(env)
    bob_key, _ = enrolled(env, "Bob phone", admin=second_admin(env))
    client, token = signed_in(env)
    options = body(post_json(client, "/api/v1/reauth/passkey/options", {}, token))["data"]
    r = post_json(client, "/api/v1/reauth/passkey/verify",
                  {"credential": bob_key.get(options["challenge"])}, token)
    assert r.status == 403


# ---- rename and revoke -----------------------------------------------------------------------

def test_rename_form(env):
    _, phone = enrolled(env, "Phone")
    enrolled(env, "Tablet")
    client, token = signed_in(env)
    url = "/api/v1/passkeys/rename"
    r = client.post(url, form={"csrf_token": token, "passkey_id": phone["id"], "name": "Work phone"})
    assert r.status == 303 and r.header("location") == "/account?msg=passkey_renamed"
    assert env.conn.execute("SELECT name FROM passkeys WHERE id = ?", (phone["id"],)).fetchone()[0] == "Work phone"
    r = client.post(url, form={"csrf_token": token, "passkey_id": phone["id"], "name": "tablet"})
    assert r.status == 409 and "already have a passkey" in r.text
    r = client.post(url, form={"csrf_token": token, "passkey_id": "abc", "name": "x"})
    assert r.status == 400
    r = client.post(url, form={"passkey_id": phone["id"], "name": "x"})
    assert r.status == 403   # no CSRF token


def test_passkeys_of_other_admins_cannot_be_touched(env):
    _, bobs = enrolled(env, "Bob phone", admin=second_admin(env))
    client, token = signed_in(env)
    r = client.post("/api/v1/passkeys/rename", form={"csrf_token": token, "passkey_id": bobs["id"],
                                                     "name": "mine now"})
    assert r.status == 404
    r = client.post("/api/v1/passkeys/revoke", form={"csrf_token": token, "passkey_id": bobs["id"]})
    assert r.status == 404
    assert env.conn.execute("SELECT name FROM passkeys").fetchone()[0] == "Bob phone"


def test_revoke_form(env):
    _, phone = enrolled(env, "Phone")
    client, token = signed_in(env)
    r = client.post("/api/v1/passkeys/revoke", form={"csrf_token": token, "passkey_id": phone["id"]})
    assert r.status == 303 and r.header("location") == "/account?msg=passkey_revoked"
    assert env.conn.execute("SELECT COUNT(*) FROM passkeys").fetchone()[0] == 0
    assert audit_details(env, "passkey.revoke", "success")[0]["name"] == "Phone"


def test_revoke_needs_recent_confirmation(env):
    _, phone = enrolled(env, "Phone")
    client, token = signed_in(env)
    env.clock.now += 400_000
    r = client.post("/api/v1/passkeys/revoke", form={"csrf_token": token, "passkey_id": phone["id"]})
    assert r.status == 403 and body(r)["error"]["code"] == "reauth_required"
    assert env.conn.execute("SELECT COUNT(*) FROM passkeys").fetchone()[0] == 1


def test_the_last_passkey_stays_when_password_sign_in_is_off(env):
    _, phone = enrolled(env, "Phone")
    client, token = signed_in(env)
    env.conn.execute("INSERT INTO settings(key, value, updated_ms) VALUES ('auth.password_login_enabled',"
                     " 'false', ?)", (env.clock(),))
    r = client.post("/api/v1/passkeys/revoke", form={"csrf_token": token, "passkey_id": phone["id"]})
    assert r.status == 409 and "lock you out" in r.text
    assert env.conn.execute("SELECT COUNT(*) FROM passkeys").fetchone()[0] == 1
