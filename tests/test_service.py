import pytest

from guard.auth import service, sessions
from guard.auth.service import AccountError, authenticate_password, create_admin, set_password
from guard.auth.throttle import ThrottlePolicy

from conftest import GOOD_PW, NOW, FakeHasher

IP = "203.0.113.7"


def login(conn, hasher, user="alice", pw=GOOD_PW, at=NOW, ip=IP, **kw):
    return authenticate_password(conn, hasher, user, pw, ip=ip, user_agent="UA", now_ms=at, **kw)


def audit_actions(conn):
    return [(r["action"], r["outcome"]) for r in conn.execute("SELECT action, outcome FROM audit_events ORDER BY id")]


def test_create_admin_stores_hash_and_audits(conn, hasher):
    aid = create_admin(conn, hasher, "Bob.Smith", GOOD_PW, now_ms=NOW, display_name="Bob", actor_name="cli:me")
    row = conn.execute("SELECT * FROM admins WHERE id=?", (aid,)).fetchone()
    assert row["password_hash"].startswith("$argon2id$") and GOOD_PW not in row["password_hash"]
    assert len(row["webauthn_user_handle"]) == 32 and row["is_disabled"] == 0 and row["role"] == "admin"
    assert audit_actions(conn) == [("admin.create", "success")]


@pytest.mark.parametrize("name", ["ab", "a" * 65, "has space", "semi;colon", "ééé", "x/y", ""])
def test_bad_usernames(conn, hasher, name):
    with pytest.raises(AccountError, match="username"):
        create_admin(conn, hasher, name, GOOD_PW, now_ms=NOW)


def test_weak_password_is_rejected_without_a_row(conn, hasher):
    with pytest.raises(AccountError, match="password"):
        create_admin(conn, hasher, "carol", "short", now_ms=NOW)
    assert conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0] == 0


def test_duplicate_username_is_case_insensitive(conn, hasher, admin_id):
    with pytest.raises(AccountError, match="taken"):
        create_admin(conn, hasher, "ALICE", GOOD_PW, now_ms=NOW)
    assert conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1  # failed create left no audit row


def test_successful_login_creates_a_valid_session(conn, hasher, admin_id):
    res = login(conn, hasher, user=" Alice ")
    assert res.ok and not res.locked and res.admin_id == admin_id
    assert sessions.validate_session(conn, res.token, NOW + 1).admin_id == admin_id
    assert conn.execute("SELECT last_login_ms FROM admins").fetchone()[0] == NOW
    assert audit_actions(conn)[-1] == ("auth.login", "success")


def test_wrong_password_unknown_user_and_disabled_all_fail_alike(conn, hasher, admin_id):
    create_admin(conn, hasher, "dave", GOOD_PW, now_ms=NOW)
    conn.execute("UPDATE admins SET is_disabled=1 WHERE username='dave'")
    for user, pw in (("alice", "wrong password!!"), ("nobody", GOOD_PW), ("dave", GOOD_PW)):
        res = login(conn, hasher, user=user, pw=pw)
        assert (res.ok, res.token, res.session, res.retry_after_s) == (False, None, None, 0)
    assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0


def test_unusable_accounts_still_cost_a_hash_verification(conn, hasher, admin_id):
    before = hasher.verify_calls
    login(conn, hasher, user="nobody")
    assert hasher.verify_calls == before + 1
    conn.execute("UPDATE admins SET password_hash=NULL")
    login(conn, hasher)
    assert hasher.verify_calls == before + 2


def test_password_login_can_be_switched_off(conn, hasher, admin_id):
    assert not login(conn, hasher, password_login_enabled=False).ok


def test_failures_are_audited_without_the_password(conn, hasher, admin_id):
    login(conn, hasher, pw="Tr0ub4dor&3-wrong")
    row = conn.execute("SELECT * FROM audit_events WHERE action='auth.login_failed'").fetchone()
    assert row["outcome"] == "failure" and row["actor_name"] == "alice" and row["ip"] == IP
    dump = " ".join(str(tuple(r)) for t in ("audit_events", "admins", "sessions", "auth_throttle")
                    for r in conn.execute(f"SELECT * FROM {t}"))
    assert "Tr0ub4dor" not in dump and GOOD_PW not in dump


def test_lockout_after_five_failures_blocks_even_the_right_password(conn, hasher, admin_id):
    for i in range(4):
        assert login(conn, hasher, pw="wrong password!!", at=NOW + i).retry_after_s == 0
    assert login(conn, hasher, pw="wrong password!!", at=NOW + 4).retry_after_s == 900
    res = login(conn, hasher, at=NOW + 5_000)
    assert not res.ok and res.locked and 890 <= res.retry_after_s <= 900
    assert ("auth.lockout", "denied") in audit_actions(conn)
    assert login(conn, hasher, at=NOW + 4 + 901_000).ok


def test_attempts_while_locked_are_not_counted(conn, hasher, admin_id):
    for i in range(5):
        login(conn, hasher, pw="wrong password!!", at=NOW + i)
    for i in range(50):
        login(conn, hasher, pw="wrong password!!", at=NOW + 1000 + i)
    assert login(conn, hasher, at=NOW + 4 + 901_000).ok  # still only a 15 minute lock


def test_lock_is_identical_for_real_and_nonexistent_usernames(conn, hasher, admin_id):
    waits = []
    for user in ("alice", "ghost"):
        for i in range(5):
            login(conn, hasher, user=user, pw="x" * 12, at=NOW, ip=f"198.51.100.{1 + len(waits) * 10 + i}")
        waits.append(login(conn, hasher, user=user, at=NOW + 1000, ip="198.51.100.200").retry_after_s)
    assert waits[0] == waits[1] > 0


def test_one_ip_guessing_many_usernames_gets_locked(conn, hasher, admin_id):
    for i in range(5):
        login(conn, hasher, user=f"user{i}", pw="x" * 12, at=NOW + i)
    assert login(conn, hasher, user="alice", at=NOW + 10).locked


def test_success_clears_the_failure_counters(conn, hasher, admin_id):
    for i in range(4):
        login(conn, hasher, pw="wrong password!!", at=NOW + i)
    assert login(conn, hasher, at=NOW + 10).ok
    assert conn.execute("SELECT COUNT(*) FROM auth_throttle").fetchone()[0] == 0


def test_ip_forms_are_canonicalised(conn, hasher, admin_id):
    assert service.canonical_ip("::ffff:203.0.113.7") == "203.0.113.7"
    assert service.canonical_ip("2001:0DB8::0001") == "2001:db8::1"
    assert service.canonical_ip("not an ip") == "invalid"
    assert login(conn, hasher, ip="not an ip").ok  # recorded as "invalid", never crashes
    assert conn.execute("SELECT ip FROM sessions").fetchone()[0] == "invalid"


def test_custom_policy_is_honoured(conn, hasher, admin_id):
    pol = ThrottlePolicy(max_failures=2, lockout_s=60)
    login(conn, hasher, pw="x" * 12, policy=pol)
    assert login(conn, hasher, pw="x" * 12, policy=pol, at=NOW + 1).retry_after_s == 60


def test_hash_is_upgraded_on_login_when_parameters_change(conn, admin_id):
    new = FakeHasher(params="p2")
    old_hash = conn.execute("SELECT password_hash FROM admins").fetchone()[0]
    assert authenticate_password(conn, new, "alice", GOOD_PW, ip=IP, user_agent="", now_ms=NOW).ok
    assert conn.execute("SELECT password_hash FROM admins").fetchone()[0] != old_hash
    assert authenticate_password(conn, new, "alice", GOOD_PW, ip=IP, user_agent="", now_ms=NOW + 1).ok


def test_set_password_revokes_other_sessions_and_audits(conn, hasher, admin_id):
    keep = login(conn, hasher)
    other = login(conn, hasher, at=NOW + 1)
    set_password(conn, hasher, admin_id, "a brand new passphrase", now_ms=NOW + 2, keep_session_id=keep.session.id)
    assert sessions.validate_session(conn, keep.token, NOW + 3) is not None
    assert sessions.validate_session(conn, other.token, NOW + 3) is None
    assert not login(conn, hasher, at=NOW + 4).ok and login(conn, hasher, pw="a brand new passphrase", at=NOW + 5).ok
    assert ("account.password_change", "success") in audit_actions(conn)


def test_set_password_validates_and_rejects_unknown_admin(conn, hasher, admin_id):
    with pytest.raises(AccountError):
        set_password(conn, hasher, admin_id, "short", now_ms=NOW)
    with pytest.raises(AccountError, match="no such"):
        set_password(conn, hasher, 999, GOOD_PW, now_ms=NOW)
    assert login(conn, hasher).ok  # original password still works
