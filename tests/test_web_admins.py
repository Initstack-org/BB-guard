"""Administrators page: list, create, disable, enable, set another admin's password (docs/API.md 10.1).

Same approach as tests/test_web.py (ASGI app driven directly, fake hasher). Not yet run anywhere.
"""

import pytest

from guard import db
from guard.auth import service
from guard.web import admins as admins_mod

from tests.test_web import PASSWORD, FakeHasher, audit_actions, env, sign_in, token_from  # noqa: F401
from tests.web_client import Client

BOB_PW = "bobs long starting passphrase"
NEW_PW = "a brand new long passphrase"


def signed_in(env, username="alice", password=PASSWORD):
    client, response = sign_in(env, username=username, password=password)
    assert response.status == 303
    return client


def add_bob(env):
    return service.create_admin(env.conn, FakeHasher(), "bob", BOB_PW, now_ms=env.clock())


def post(client, path, **fields):
    token = token_from(client.get("/admins"))
    return client.post(path, form={"csrf_token": token, **fields})


def admin_row(env, username):
    return env.conn.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()


# ---- the page --------------------------------------------------------------------------------

def test_route_classes(env):
    classes = env.app.state.route_classes
    assert classes[("/admins", "GET")] == "A"
    for path in ("/api/v1/admins", "/api/v1/admins/disable", "/api/v1/admins/enable",
                 "/api/v1/admins/password"):
        assert classes[(path, "POST")] == "R"


def test_page_requires_a_session(env):
    r = Client(env.app).get("/admins")
    assert r.status == 303 and r.header("location") == "/login"


def test_page_lists_admins(env):
    add_bob(env)
    page = signed_in(env).get("/admins")
    assert page.status == 200
    for text in ("alice", "(you)", "bob", "Add an administrator", "never"):
        assert text in page.text
    assert 'href="/admins"' in page.text and 'aria-current="page"' in page.text
    lowered = page.text.lower()
    assert "<script" not in lowered and "<style" not in lowered and " style=" not in lowered


def test_page_shows_no_password_hash_or_secrets(env):
    page = signed_in(env).get("/admins").text
    assert "$argon2id$" not in page and "password_hash" not in page


def test_unknown_flash_code_is_not_reflected(env):
    page = signed_in(env).get("/admins?msg=%3Cscript%3Ealert(1)%3C/script%3E")
    assert "alert(1)" not in page.text and 'role="status"' not in page.text


# ---- create ----------------------------------------------------------------------------------

def test_create_admin_and_new_admin_can_sign_in(env):
    client = signed_in(env)
    r = post(client, "/api/v1/admins", username="carol", display_name="Carol C", password=BOB_PW,
             confirm_password=BOB_PW)
    assert r.status == 303 and r.header("location") == "/admins?msg=created"
    row = admin_row(env, "carol")
    assert row["display_name"] == "Carol C" and row["created_by"] == admin_row(env, "alice")["id"]
    assert sign_in(env, username="carol", password=BOB_PW)[1].status == 303
    event = env.conn.execute("SELECT * FROM audit_events WHERE action='admin.create' "
                             "ORDER BY id DESC").fetchone()
    assert event["actor_name"] == "alice" and event["target_id"] == str(row["id"])
    assert BOB_PW not in repr([dict(e) for e in env.conn.execute("SELECT * FROM audit_events")])
    assert "Administrator created." in client.get("/admins?msg=created").text


@pytest.mark.parametrize("fields, message", [
    ({"username": "carol", "password": "short", "confirm_password": "short"}, "at least 12"),
    ({"username": "ab", "password": BOB_PW, "confirm_password": BOB_PW}, "Username must be"),
    ({"username": "bad name!", "password": BOB_PW, "confirm_password": BOB_PW}, "Username must be"),
    ({"username": "carol", "password": BOB_PW, "confirm_password": BOB_PW + "x"}, "do not match"),
    ({"username": "ALICE", "password": BOB_PW, "confirm_password": BOB_PW}, "already taken"),
])
def test_create_rejects_bad_input(env, fields, message):
    before = env.conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0]
    r = post(signed_in(env), "/api/v1/admins", **fields)
    assert r.status == 400 and message in r.text
    assert env.conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0] == before


def test_create_error_keeps_and_escapes_the_typed_values(env):
    r = post(signed_in(env), "/api/v1/admins", username="x<b>", display_name='"><script>alert(1)</script>',
             password="short", confirm_password="short")
    assert r.status == 400 and "<script>alert" not in r.text and "&lt;script&gt;" in r.text


def test_display_name_is_escaped_in_the_list(env):
    client = signed_in(env)
    post(client, "/api/v1/admins", username="carol", display_name="<b>Carol</b>", password=BOB_PW,
         confirm_password=BOB_PW)
    page = client.get("/admins").text
    assert "<b>Carol</b>" not in page and "&lt;b&gt;Carol&lt;/b&gt;" in page


def test_create_needs_recent_reauthentication(env):
    client = signed_in(env)
    env.clock.now += 400_000  # past the 300 s window, still inside the 30 minute idle limit
    r = post(client, "/api/v1/admins", username="carol", password=BOB_PW, confirm_password=BOB_PW)
    assert r.status == 403 and admin_row(env, "carol") is None
    assert "auth.reauth_required" in audit_actions(env)


def test_create_without_csrf_token_is_refused(env):
    client = signed_in(env)
    r = client.post("/api/v1/admins", form={"username": "carol", "password": BOB_PW,
                                            "confirm_password": BOB_PW})
    assert r.status == 403 and admin_row(env, "carol") is None


# ---- disable and enable ----------------------------------------------------------------------

def test_disable_revokes_sessions_and_blocks_sign_in(env):
    bob_id = add_bob(env)
    bob = signed_in(env, "bob", BOB_PW)
    assert bob.get("/account").status == 200
    r = post(signed_in(env), "/api/v1/admins/disable", admin_id=str(bob_id))
    assert r.status == 303 and r.header("location") == "/admins?msg=disabled"
    assert admin_row(env, "bob")["is_disabled"] == 1
    assert bob.get("/account").status == 303                       # session no longer valid
    assert sign_in(env, username="bob", password=BOB_PW)[1].status == 401
    event = env.conn.execute("SELECT * FROM audit_events WHERE action='admin.disable'").fetchone()
    assert event["actor_name"] == "alice" and event["target_id"] == str(bob_id)


def test_enable_restores_sign_in(env):
    bob_id = add_bob(env)
    alice = signed_in(env)
    post(alice, "/api/v1/admins/disable", admin_id=str(bob_id))
    r = post(alice, "/api/v1/admins/enable", admin_id=str(bob_id))
    assert r.status == 303 and admin_row(env, "bob")["is_disabled"] == 0
    assert admin_row(env, "bob")["disabled_ms"] is None
    assert sign_in(env, username="bob", password=BOB_PW)[1].status == 303
    assert "admin.enable" in audit_actions(env)


def test_cannot_disable_yourself(env):
    alice_id = admin_row(env, "alice")["id"]
    r = post(signed_in(env), "/api/v1/admins/disable", admin_id=str(alice_id))
    assert r.status == 409 and "own account" in r.text
    assert admin_row(env, "alice")["is_disabled"] == 0


def test_disable_and_enable_state_conflicts(env):
    bob_id = add_bob(env)
    alice = signed_in(env)
    assert post(alice, "/api/v1/admins/enable", admin_id=str(bob_id)).status == 409   # already enabled
    post(alice, "/api/v1/admins/disable", admin_id=str(bob_id))
    assert post(alice, "/api/v1/admins/disable", admin_id=str(bob_id)).status == 409  # already disabled


@pytest.mark.parametrize("value, status", [("99999", 404), ("abc", 400), ("", 400), ("1; DROP TABLE admins", 400)])
def test_bad_admin_id(env, value, status):
    add_bob(env)
    client = signed_in(env)
    assert post(client, "/api/v1/admins/disable", admin_id=value).status == status
    assert post(client, "/api/v1/admins/enable", admin_id=value).status == status
    assert env.conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0] == 2


def test_last_enabled_admin_cannot_be_disabled(conn, hasher, admin_id):
    # Unreachable from the page (the actor is always enabled and cannot target themselves), so the
    # guard is tested on the function directly with an actor id that is not an enabled admin.
    with pytest.raises(admins_mod.AdminActionError, match="last enabled"):
        admins_mod.disable(conn, admin_id, actor_id=999, actor_name="x", ip="203.0.113.1", now_ms=1)
    assert conn.execute("SELECT is_disabled FROM admins").fetchone()[0] == 0


def test_disable_unknown_admin_is_404_on_the_function(conn, admin_id):
    with pytest.raises(admins_mod.AdminActionError) as err:
        admins_mod.disable(conn, 4242, actor_id=admin_id, actor_name="alice", ip="", now_ms=1)
    assert err.value.status == 404


def test_disable_needs_recent_reauthentication(env):
    bob_id = add_bob(env)
    client = signed_in(env)
    env.clock.now += 400_000
    assert post(client, "/api/v1/admins/disable", admin_id=str(bob_id)).status == 403
    assert admin_row(env, "bob")["is_disabled"] == 0


# ---- set another admin's password ------------------------------------------------------------

def test_set_password_signs_them_out_and_new_password_works(env):
    bob_id = add_bob(env)
    bob = signed_in(env, "bob", BOB_PW)
    r = post(signed_in(env), "/api/v1/admins/password", admin_id=str(bob_id), new_password=NEW_PW,
             confirm_password=NEW_PW)
    assert r.status == 303 and r.header("location") == "/admins?msg=password_set"
    assert bob.get("/account").status == 303
    assert sign_in(env, username="bob", password=BOB_PW)[1].status == 401
    assert sign_in(env, username="bob", password=NEW_PW)[1].status == 303
    event = env.conn.execute("SELECT * FROM audit_events WHERE action='admin.password_reset'").fetchone()
    assert event["actor_name"] == "alice" and event["target_id"] == str(bob_id) and event["outcome"] == "success"
    assert NEW_PW not in repr([dict(e) for e in env.conn.execute("SELECT * FROM audit_events")])


@pytest.mark.parametrize("new, confirm, message", [
    ("short", "short", "at least 12"), (NEW_PW, NEW_PW + "x", "do not match")])
def test_set_password_rejects_bad_input(env, new, confirm, message):
    bob_id = add_bob(env)
    r = post(signed_in(env), "/api/v1/admins/password", admin_id=str(bob_id), new_password=new,
             confirm_password=confirm)
    assert r.status == 400 and message in r.text
    assert sign_in(env, username="bob", password=BOB_PW)[1].status == 303


def test_set_password_rejects_own_account_and_unknown_admin(env):
    alice_id = admin_row(env, "alice")["id"]
    client = signed_in(env)
    own = post(client, "/api/v1/admins/password", admin_id=str(alice_id), new_password=NEW_PW,
               confirm_password=NEW_PW)
    assert own.status == 400 and "Authentication page" in own.text
    assert post(client, "/api/v1/admins/password", admin_id="9999", new_password=NEW_PW,
                confirm_password=NEW_PW).status == 404
    assert post(client, "/api/v1/admins/password", admin_id="x", new_password=NEW_PW,
                confirm_password=NEW_PW).status == 400


def test_set_password_needs_recent_reauthentication(env):
    bob_id = add_bob(env)
    client = signed_in(env)
    env.clock.now += 400_000
    r = post(client, "/api/v1/admins/password", admin_id=str(bob_id), new_password=NEW_PW,
             confirm_password=NEW_PW)
    assert r.status == 403
    assert sign_in(env, username="bob", password=BOB_PW)[1].status == 303


def test_admin_actions_require_a_session(env):
    for path in ("/api/v1/admins", "/api/v1/admins/disable", "/api/v1/admins/enable",
                 "/api/v1/admins/password"):
        r = Client(env.app).post(path, form={"admin_id": "1"})
        assert r.status in (303, 401, 403)
    assert env.conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0] == 1
