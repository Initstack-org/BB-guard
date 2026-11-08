"""Password re-check, password change, own-session listing and settings-driven limits."""

import json

import pytest

from guard.auth import service, sessions
from guard.auth.service import AccountError, change_password, check_admin_password
from guard.auth.throttle import ThrottlePolicy
from guard.web import limits

from conftest import GOOD_PW, NOW, FakeHasher

IP = "203.0.113.7"
NEW_PW = "another long passphrase"


def audit_rows(conn):
    return [(r["action"], r["outcome"]) for r in conn.execute("SELECT action, outcome FROM audit_events ORDER BY id")]


def recheck(conn, hasher, admin_id, pw=GOOD_PW, at=NOW, **kw):
    return check_admin_password(conn, hasher, admin_id, pw, ip=IP, now_ms=at, action="auth.reauth", **kw)


def new_session(conn, admin_id, at=NOW, ip=IP):
    return sessions.create_session(conn, admin_id, "password", ip, "UA", at)


# ---- check_admin_password --------------------------------------------------------------------

def test_recheck_accepts_correct_password(conn, hasher, admin_id):
    assert recheck(conn, hasher, admin_id).ok
    assert audit_rows(conn) == [("admin.create", "success")]  # success is audited by the caller


def test_recheck_rejects_wrong_password_and_audits(conn, hasher, admin_id):
    result = recheck(conn, hasher, admin_id, pw="not the password")
    assert not result.ok and not result.locked
    assert audit_rows(conn)[-1] == ("auth.reauth", "failure")
    assert "not the password" not in json.dumps([dict(r) for r in conn.execute("SELECT * FROM audit_events")])


def test_recheck_locks_after_repeated_failures_and_stops_counting(conn, hasher, admin_id):
    policy = ThrottlePolicy()
    results = [recheck(conn, hasher, admin_id, pw="bad password!!", at=NOW + i, policy=policy) for i in range(5)]
    assert results[-1].locked
    calls = hasher.verify_calls
    locked = recheck(conn, hasher, admin_id, pw=GOOD_PW, at=NOW + 10, policy=policy)
    assert locked.locked and not locked.ok
    assert hasher.verify_calls == calls  # a locked attempt does no password work
    assert ("auth.lockout", "denied") in audit_rows(conn)


def test_recheck_shares_lock_with_sign_in(conn, hasher, admin_id):
    for i in range(5):
        service.authenticate_password(conn, hasher, "alice", "bad password!!", ip=IP, user_agent="UA", now_ms=NOW + i)
    assert recheck(conn, hasher, admin_id, at=NOW + 10).locked


def test_recheck_success_clears_failures(conn, hasher, admin_id):
    for i in range(3):
        recheck(conn, hasher, admin_id, pw="bad password!!", at=NOW + i)
    assert recheck(conn, hasher, admin_id, at=NOW + 5).ok
    assert conn.execute("SELECT COUNT(*) FROM auth_throttle").fetchone()[0] == 0


def test_recheck_refuses_disabled_unknown_and_password_login_off(conn, hasher, admin_id):
    assert not recheck(conn, hasher, 9999).ok
    assert not recheck(conn, hasher, admin_id, password_login_enabled=False).ok
    conn.execute("UPDATE admins SET is_disabled = 1 WHERE id = ?", (admin_id,))
    assert not recheck(conn, hasher, admin_id).ok


# ---- change_password -------------------------------------------------------------------------

def test_change_password_success_revokes_other_sessions_only(conn, hasher, admin_id):
    _, keep = new_session(conn, admin_id)
    _, other = new_session(conn, admin_id)
    result = change_password(conn, hasher, admin_id, GOOD_PW, NEW_PW, ip=IP, now_ms=NOW + 1000,
                             keep_session_id=keep.id)
    assert result.ok
    row = conn.execute("SELECT password_hash, password_changed_ms FROM admins WHERE id=?", (admin_id,)).fetchone()
    assert hasher.verify(row["password_hash"], NEW_PW) and not hasher.verify(row["password_hash"], GOOD_PW)
    assert row["password_changed_ms"] == NOW + 1000
    revoked = {r["id"]: r["revoked_ms"] for r in conn.execute("SELECT id, revoked_ms FROM sessions")}
    assert revoked[keep.id] is None and revoked[other.id] == NOW + 1000
    event = conn.execute("SELECT * FROM audit_events WHERE action='account.password_change'").fetchone()
    assert event["outcome"] == "success" and event["ip"] == IP and event["actor_name"] == "alice"
    assert NEW_PW not in json.dumps([dict(r) for r in conn.execute("SELECT * FROM audit_events")])


def test_change_password_wrong_current_changes_nothing(conn, hasher, admin_id):
    before = conn.execute("SELECT password_hash FROM admins").fetchone()[0]
    result = change_password(conn, hasher, admin_id, "wrong current one", NEW_PW, ip=IP, now_ms=NOW)
    assert not result.ok and not result.locked
    assert conn.execute("SELECT password_hash FROM admins").fetchone()[0] == before
    assert audit_rows(conn)[-1] == ("account.password_change", "failure")


def test_change_password_is_throttled(conn, hasher, admin_id):
    results = [change_password(conn, hasher, admin_id, "wrong current one", NEW_PW, ip=IP, now_ms=NOW + i)
               for i in range(5)]
    assert results[-1].locked
    assert change_password(conn, hasher, admin_id, GOOD_PW, NEW_PW, ip=IP, now_ms=NOW + 10).locked


@pytest.mark.parametrize("new, message", [("short", "at least 12"), (GOOD_PW, "differ"), ("password", "at least 12"),
                                          ("alice" + "x" * 2, "at least 12")])
def test_change_password_rejects_bad_new_password(conn, hasher, admin_id, new, message):
    with pytest.raises(AccountError, match=message):
        change_password(conn, hasher, admin_id, GOOD_PW, new, ip=IP, now_ms=NOW)
    assert hasher.verify(conn.execute("SELECT password_hash FROM admins").fetchone()[0], GOOD_PW)


def test_bad_new_password_is_not_counted_as_a_failed_sign_in(conn, hasher, admin_id):
    for i in range(10):
        with pytest.raises(AccountError):
            change_password(conn, hasher, admin_id, GOOD_PW, "short", ip=IP, now_ms=NOW + i)
    assert conn.execute("SELECT COUNT(*) FROM auth_throttle").fetchone()[0] == 0


def test_change_password_honours_minimum_length(conn, hasher, admin_id):
    with pytest.raises(AccountError, match="at least 20"):
        change_password(conn, hasher, admin_id, GOOD_PW, NEW_PW, ip=IP, now_ms=NOW, min_length=20)


def test_new_password_works_for_sign_in_afterwards(conn, hasher, admin_id):
    change_password(conn, hasher, admin_id, GOOD_PW, NEW_PW, ip=IP, now_ms=NOW)
    assert service.authenticate_password(conn, hasher, "alice", NEW_PW, ip=IP, user_agent="UA", now_ms=NOW + 1).ok
    assert not service.authenticate_password(conn, hasher, "alice", GOOD_PW, ip=IP, user_agent="UA", now_ms=NOW + 2).ok


# ---- session listing and own-session revoke --------------------------------------------------

def test_list_for_admin_shows_only_usable_sessions_without_secrets(conn, hasher, admin_id):
    other = service.create_admin(conn, hasher, "bob", GOOD_PW, now_ms=NOW)
    _, mine = new_session(conn, admin_id, at=NOW)
    _, revoked = new_session(conn, admin_id, at=NOW)
    sessions.revoke_session(conn, revoked.id, NOW)
    _, idle = new_session(conn, admin_id, at=NOW - 3_600_000)
    _, bobs = new_session(conn, other, at=NOW)
    rows = sessions.list_for_admin(conn, admin_id, NOW + 1000, idle_s=1800)
    assert [r["id"] for r in rows] == [mine.id]
    assert set(rows[0].keys()) == {"id", "auth_method", "created_ms", "last_seen_ms", "expires_ms", "ip", "user_agent"}
    assert bobs.id not in [r["id"] for r in rows]


def test_list_for_admin_hides_expired(conn, admin_id):
    sessions.create_session(conn, admin_id, "password", IP, "UA", NOW, max_s=60)
    assert sessions.list_for_admin(conn, admin_id, NOW + 61_000) == []


def test_revoke_own_only_touches_own_sessions(conn, hasher, admin_id):
    other = service.create_admin(conn, hasher, "bob", GOOD_PW, now_ms=NOW)
    _, mine = new_session(conn, admin_id)
    _, bobs = new_session(conn, other)
    assert not sessions.revoke_own(conn, admin_id, bobs.id, NOW)
    assert conn.execute("SELECT revoked_ms FROM sessions WHERE id=?", (bobs.id,)).fetchone()[0] is None
    assert sessions.revoke_own(conn, admin_id, mine.id, NOW + 5)
    assert not sessions.revoke_own(conn, admin_id, mine.id, NOW + 6)  # already revoked
    assert not sessions.revoke_own(conn, admin_id, 424242, NOW)


# ---- limits ----------------------------------------------------------------------------------

def put(conn, key, value):
    conn.execute("INSERT OR REPLACE INTO settings(key, value, updated_ms) VALUES (?,?,?)",
                 (key, json.dumps(value), 1))


def test_limits_default_when_settings_are_missing(conn):
    assert limits.load(conn) == limits.Limits()
    assert limits.Limits().throttle == ThrottlePolicy()


def test_limits_read_valid_settings(conn):
    put(conn, "auth.session_idle_s", 600)
    put(conn, "auth.session_max_s", 7200)
    put(conn, "auth.reauth_window_s", 120)
    put(conn, "auth.password_min_length", 16)
    put(conn, "auth.throttle", {"max_failures": 3, "window_s": 600, "lockout_s": 300, "lockout_max_s": 3600})
    got = limits.load(conn)
    assert (got.idle_s, got.max_s, got.reauth_s, got.min_password_length) == (600, 7200, 120, 16)
    assert got.throttle == ThrottlePolicy(3, 600, 300, 3600)


@pytest.mark.parametrize("key, bad", [
    ("auth.session_idle_s", 5), ("auth.session_idle_s", 10**9), ("auth.session_idle_s", "600"),
    ("auth.session_idle_s", True), ("auth.session_idle_s", 1.5), ("auth.session_idle_s", None),
    ("auth.session_max_s", 0), ("auth.session_max_s", -1), ("auth.reauth_window_s", 99999),
    ("auth.password_min_length", 4), ("auth.password_min_length", 100000),
])
def test_limits_ignore_bad_values(conn, key, bad):
    put(conn, key, bad)
    assert limits.load(conn) == limits.Limits()


def test_limits_ignore_non_object_throttle(conn):
    # settings.value has a json_valid CHECK, so a broken row cannot exist; a list where an
    # object is expected is the realistic bad case for auth.throttle.
    put(conn, "auth.throttle", [1, 2, 3])
    assert limits.load(conn).throttle == ThrottlePolicy()


@pytest.mark.parametrize("value", [
    {"max_failures": 1, "window_s": 900, "lockout_s": 900, "lockout_max_s": 86400},     # too low: no protection
    {"max_failures": 5, "window_s": 900, "lockout_s": 900},                              # missing key
    {"max_failures": 5, "window_s": 900, "lockout_s": 900, "lockout_max_s": 100},        # max below base
    {"max_failures": "5", "window_s": 900, "lockout_s": 900, "lockout_max_s": 86400},    # wrong type
])
def test_limits_ignore_bad_throttle(conn, value):
    put(conn, "auth.throttle", value)
    assert limits.load(conn).throttle == ThrottlePolicy()


def test_one_bad_setting_does_not_discard_the_good_ones(conn):
    put(conn, "auth.session_idle_s", 5)
    put(conn, "auth.reauth_window_s", 120)
    got = limits.load(conn)
    assert got.idle_s == limits.DEFAULT_IDLE_S and got.reauth_s == 120
