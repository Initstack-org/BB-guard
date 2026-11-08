"""Account page, re-authentication, password change, own sessions, settings-driven limits.

Same approach as tests/test_web.py: the ASGI app is driven directly, with a fake password hasher.
"""

import json

import pytest

from guard.auth import service, sessions
from guard.web.app import SESSION_COOKIE

from tests.test_web import (ORIGIN, PASSWORD, FakeHasher, audit_actions, env, sign_in,  # noqa: F401
                            token_from)
from tests.web_client import Client

NEW_PW = "another long passphrase"


def signed_in(env, **kw):
    client, response = sign_in(env, **kw)
    assert response.status == 303
    return client


def post_form(client, path, **fields):
    token = token_from(client.get("/account"))
    return client.post(path, form={"csrf_token": token, **fields})


def session_id_of(env, client):
    token_hash = sessions.hash_token(client.cookies[SESSION_COOKIE])
    return env.conn.execute("SELECT id FROM sessions WHERE token_hash = ?", (token_hash,)).fetchone()["id"]


def put_setting(env, key, value):
    env.conn.execute("INSERT OR REPLACE INTO settings(key, value, updated_ms) VALUES (?,?,1)",
                     (key, json.dumps(value)))


# ---- the page --------------------------------------------------------------------------------

def test_account_page_renders(env):
    page = signed_in(env).get("/account")
    assert page.status == 200
    for text in ("Change password", "Confirm your password", "Your sessions", "This session",
                 "Passkey registration is not available yet", "alice"):
        assert text in page.text
    assert 'href="/account"' in page.text and 'aria-current="page"' in page.text


def test_account_page_has_no_inline_script_or_style(env):
    text = signed_in(env).get("/account").text.lower()
    assert "<script" not in text and "<style" not in text and " style=" not in text


def test_account_page_requires_a_session(env):
    r = Client(env.app).get("/account")
    assert r.status == 303 and r.header("location") == "/login"


def test_unknown_flash_code_is_ignored_and_not_reflected(env):
    page = signed_in(env).get("/account?msg=%3Cscript%3Ealert(1)%3C/script%3E")
    assert page.status == 200 and "alert(1)" not in page.text
    assert 'role="status"' not in page.text


def test_known_flash_code_shows_its_text(env):
    assert "Password confirmed." in signed_in(env).get("/account?msg=reauth_ok").text


def test_new_routes_have_the_expected_classes(env):
    classes = env.app.state.route_classes
    assert classes[("/account", "GET")] == "A"
    for path in ("/api/v1/account/password", "/api/v1/reauth/password",
                 "/api/v1/account/sessions/revoke", "/api/v1/account/sessions/revoke-others"):
        assert classes[(path, "POST")] == "W"


def test_session_listing_escapes_user_agent_and_shows_no_secrets(env):
    client = Client(env.app)
    token = token_from(client.get("/login"))
    client.post("/login/password", form={"username": "alice", "password": PASSWORD, "csrf_token": token},
                headers={"user-agent": "<script>alert(1)</script>"})
    page = client.get("/account")
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text and "<script>alert" not in page.text
    stored_hash = env.conn.execute("SELECT token_hash FROM sessions").fetchone()[0]
    assert bytes(stored_hash).hex() not in page.text and client.cookies[SESSION_COOKIE] not in page.text


def test_times_are_shown_in_the_admins_timezone(env):
    try:
        from zoneinfo import ZoneInfo
        ZoneInfo("America/New_York")
    except Exception:  # noqa: BLE001 - no tz database on this machine
        pytest.skip("no tz database")
    client = signed_in(env)
    assert "UTC" in client.get("/account").text
    env.conn.execute("UPDATE admins SET timezone = 'America/New_York' WHERE username = 'alice'")
    page = client.get("/account")
    assert "EST" in page.text and "America/New_York" in page.text


def test_unusable_timezone_falls_back_to_utc(env):
    client = signed_in(env)
    env.conn.execute("UPDATE admins SET timezone = 'Not/AZone' WHERE username = 'alice'")
    assert client.get("/account").status == 200


# ---- change password -------------------------------------------------------------------------

def test_change_password_success(env):
    client, other = signed_in(env), signed_in(env)
    r = post_form(client, "/api/v1/account/password", current_password=PASSWORD,
                  new_password=NEW_PW, confirm_password=NEW_PW)
    assert r.status == 303 and r.header("location") == "/account?msg=password_changed"
    assert "Password changed" in client.get(r.header("location")).text
    assert client.get("/").status == 200          # this session survives
    assert other.get("/").status == 303           # the other one was signed out
    assert sign_in(env, password=NEW_PW)[1].status == 303
    assert sign_in(env, password=PASSWORD)[1].status == 401
    assert ("account.password_change") in audit_actions(env)


def test_change_password_wrong_current_password(env):
    client = signed_in(env)
    r = post_form(client, "/api/v1/account/password", current_password="not my password",
                  new_password=NEW_PW, confirm_password=NEW_PW)
    assert r.status == 403 and "current password is not correct" in r.text
    assert NEW_PW not in r.text and "not my password" not in r.text
    assert sign_in(env, password=PASSWORD)[1].status == 303
    assert env.conn.execute("SELECT outcome FROM audit_events WHERE action='account.password_change'"
                            ).fetchone()["outcome"] == "failure"


def test_change_password_mismatch(env):
    r = post_form(signed_in(env), "/api/v1/account/password", current_password=PASSWORD,
                  new_password=NEW_PW, confirm_password=NEW_PW + "x")
    assert r.status == 400 and "do not match" in r.text
    assert sign_in(env, password=PASSWORD)[1].status == 303


@pytest.mark.parametrize("new, text", [("short", "at least 12"), (PASSWORD, "differ from the current")])
def test_change_password_rejects_bad_new_password(env, new, text):
    r = post_form(signed_in(env), "/api/v1/account/password", current_password=PASSWORD,
                  new_password=new, confirm_password=new)
    assert r.status == 400 and text in r.text
    assert sign_in(env, password=PASSWORD)[1].status == 303


def test_change_password_is_throttled(env):
    client = signed_in(env)
    last = None
    for _ in range(5):
        last = post_form(client, "/api/v1/account/password", current_password="wrong wrong wrong",
                         new_password=NEW_PW, confirm_password=NEW_PW)
    assert last.status == 429 and int(last.header("retry-after")) > 0
    locked = post_form(client, "/api/v1/account/password", current_password=PASSWORD,
                       new_password=NEW_PW, confirm_password=NEW_PW)
    assert locked.status == 429
    assert "auth.lockout" in audit_actions(env)


def test_change_password_needs_csrf_and_origin(env):
    client = signed_in(env)
    form = {"current_password": PASSWORD, "new_password": NEW_PW, "confirm_password": NEW_PW}
    assert client.post("/api/v1/account/password", form=form).status == 403
    token = token_from(client.get("/account"))
    assert client.post("/api/v1/account/password", form={**form, "csrf_token": token},
                       headers={"origin": "https://evil.example.com"}).status == 403
    assert sign_in(env, password=PASSWORD)[1].status == 303


def test_password_change_honours_min_length_setting(env):
    put_setting(env, "auth.password_min_length", 30)
    r = post_form(signed_in(env), "/api/v1/account/password", current_password=PASSWORD,
                  new_password=NEW_PW, confirm_password=NEW_PW)
    assert r.status == 400 and "at least 30" in r.text


def test_change_password_with_password_login_disabled(env):
    client = signed_in(env)
    put_setting(env, "auth.password_login_enabled", False)
    page = client.get("/account")
    assert "Password sign-in is turned off" in page.text and 'name="current_password"' not in page.text
    r = post_form(client, "/api/v1/account/password", current_password=PASSWORD,
                  new_password=NEW_PW, confirm_password=NEW_PW)
    assert r.status == 403


# ---- re-authentication -----------------------------------------------------------------------

def test_reauth_refreshes_the_window(env):
    client = signed_in(env)
    assert "It is confirmed right now." in client.get("/account").text
    env.clock.now += 400 * 1000
    assert "It is not confirmed right now." in client.get("/account").text
    r = post_form(client, "/api/v1/reauth/password", password=PASSWORD)
    assert r.status == 303 and r.header("location") == "/account?msg=reauth_ok"
    page = client.get(r.header("location"))
    assert "Password confirmed." in page.text and "It is confirmed right now." in page.text
    event = env.conn.execute("SELECT outcome, actor_name FROM audit_events WHERE action='auth.reauth'").fetchone()
    assert event["outcome"] == "success" and event["actor_name"] == "alice"


def test_reauth_wrong_password_does_not_refresh(env):
    client = signed_in(env)
    env.clock.now += 400 * 1000
    r = post_form(client, "/api/v1/reauth/password", password="not my password")
    assert r.status == 403 and "not correct" in r.text
    assert "It is not confirmed right now." in client.get("/account").text
    assert env.conn.execute("SELECT outcome FROM audit_events WHERE action='auth.reauth'"
                            ).fetchone()["outcome"] == "failure"


def test_reauth_is_throttled_together_with_sign_in(env):
    client = signed_in(env)
    last = None
    for _ in range(5):
        last = post_form(client, "/api/v1/reauth/password", password="not my password")
    assert last.status == 429
    assert sign_in(env)[1].status == 429  # same lock keys as sign-in


def test_reauth_window_setting_is_used(env):
    put_setting(env, "auth.reauth_window_s", 60)
    client = signed_in(env)
    env.clock.now += 90 * 1000
    page = client.get("/account")
    assert "within the last 1 minute" in page.text and "It is not confirmed right now." in page.text


def test_changing_password_counts_as_confirming_it(env):
    client = signed_in(env)
    env.clock.now += 400 * 1000
    post_form(client, "/api/v1/account/password", current_password=PASSWORD,
              new_password=NEW_PW, confirm_password=NEW_PW)
    assert "It is confirmed right now." in client.get("/account").text


# ---- own sessions ----------------------------------------------------------------------------

def test_sessions_are_listed_and_marked(env):
    a, b = signed_in(env), signed_in(env)
    page = a.get("/account")
    assert page.text.count("This session") == 1
    assert page.text.count('name="session_id"') == 1
    assert f'value="{session_id_of(env, b)}"' in page.text
    assert "Sign out all other sessions" in page.text


def test_revoke_another_own_session(env):
    a, b = signed_in(env), signed_in(env)
    r = post_form(a, "/api/v1/account/sessions/revoke", session_id=str(session_id_of(env, b)))
    assert r.status == 303 and r.header("location") == "/account?msg=session_revoked"
    assert b.get("/").status == 303 and a.get("/").status == 200
    event = env.conn.execute("SELECT * FROM audit_events WHERE action='session.revoke'").fetchone()
    assert event["outcome"] == "success" and event["target_id"] == str(session_id_of(env, b))


def test_cannot_revoke_current_session_here(env):
    a = signed_in(env)
    r = post_form(a, "/api/v1/account/sessions/revoke", session_id=str(session_id_of(env, a)))
    assert r.status == 400 and a.get("/").status == 200


@pytest.mark.parametrize("value", ["", "abc", "1.5", "-1", "99999999", "1; DROP TABLE sessions"])
def test_revoke_with_bad_session_id(env, value):
    a = signed_in(env)
    r = post_form(a, "/api/v1/account/sessions/revoke", session_id=value)
    assert r.status in (400, 404) and a.get("/").status == 200
    assert env.conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1


def test_cannot_revoke_another_admins_session(env):
    bob_id = service.create_admin(env.conn, FakeHasher(), "bobby", PASSWORD, now_ms=env.clock())
    bob, _ = sign_in(env, username="bobby")
    alice = signed_in(env)
    r = post_form(alice, "/api/v1/account/sessions/revoke", session_id=str(session_id_of(env, bob)))
    assert r.status == 404 and bob.get("/").status == 200
    assert bob_id and env.conn.execute("SELECT revoked_ms FROM sessions WHERE admin_id = ?",
                                       (bob_id,)).fetchone()[0] is None


def test_revoke_others(env):
    a, b, c = signed_in(env), signed_in(env), signed_in(env)
    r = post_form(a, "/api/v1/account/sessions/revoke-others")
    assert r.status == 303 and r.header("location") == "/account?msg=sessions_revoked"
    assert b.get("/").status == 303 and c.get("/").status == 303 and a.get("/").status == 200
    event = env.conn.execute("SELECT detail FROM audit_events WHERE action='session.revoke_others'").fetchone()
    assert json.loads(event["detail"]) == {"count": 2}


def test_revoke_others_does_not_touch_other_admins(env):
    service.create_admin(env.conn, FakeHasher(), "bobby", PASSWORD, now_ms=env.clock())
    bob, _ = sign_in(env, username="bobby")
    post_form(signed_in(env), "/api/v1/account/sessions/revoke-others")
    assert bob.get("/").status == 200


# ---- limits from settings --------------------------------------------------------------------

def test_idle_timeout_setting_is_used(env):
    client = signed_in(env)
    put_setting(env, "auth.session_idle_s", 120)
    env.clock.now += 121 * 1000
    assert client.get("/").status == 303


def test_idle_timeout_setting_out_of_range_is_ignored(env):
    client = signed_in(env)
    put_setting(env, "auth.session_idle_s", 5)  # below the 60 s floor: default (30 min) applies
    env.clock.now += 121 * 1000
    assert client.get("/").status == 200


def test_session_max_setting_sets_cookie_and_expiry(env):
    put_setting(env, "auth.session_max_s", 3600)
    client, r = sign_in(env)
    cookie = next(c for c in r.set_cookies() if c.startswith(SESSION_COOKIE + "="))
    assert "Max-Age=3600" in cookie
    assert env.conn.execute("SELECT expires_ms - created_ms FROM sessions").fetchone()[0] == 3_600_000
    # Stay active (inside the idle limit) so only the absolute limit can end the session.
    for _ in range(2):
        env.clock.now += 1500 * 1000
        assert client.get("/").status == 200
    env.clock.now += 1500 * 1000  # 4500 s after sign-in, past the 3600 s limit
    assert client.get("/").status == 303


def test_throttle_setting_is_used_for_sign_in(env):
    put_setting(env, "auth.throttle", {"max_failures": 3, "window_s": 900, "lockout_s": 900, "lockout_max_s": 86400})
    client = Client(env.app)
    last = None
    for _ in range(3):
        _, last = sign_in(env, client, password="wrong wrong wrong")
    assert last.status == 429
    assert sign_in(env, client)[1].status == 429


def test_unsafe_throttle_setting_is_ignored(env):
    put_setting(env, "auth.throttle", {"max_failures": 1, "window_s": 900, "lockout_s": 900, "lockout_max_s": 86400})
    client = Client(env.app)
    _, first = sign_in(env, client, password="wrong wrong wrong")
    assert first.status == 401  # not locked after one failure: the default policy applies
    assert sign_in(env, client)[1].status == 303
