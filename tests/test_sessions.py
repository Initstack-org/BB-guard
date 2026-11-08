import base64

from guard.auth import sessions
from guard.auth.sessions import ReauthTracker, create_session, validate_session

from conftest import NOW

MIN = 60_000


def make(conn, admin_id, at=NOW, **kw):
    return create_session(conn, admin_id, "password", "203.0.113.5", "UA", at, **kw)


def test_token_is_random_and_only_its_hash_is_stored(conn, admin_id):
    t1, i1 = make(conn, admin_id)
    t2, _ = make(conn, admin_id)
    assert t1 != t2 and len(base64.urlsafe_b64decode(t1 + "=")) == 32
    stored = conn.execute("SELECT token_hash FROM sessions WHERE id=?", (i1.id,)).fetchone()[0]
    assert stored == sessions.hash_token(t1) and t1.encode() not in bytes(stored)
    assert t1 not in str(conn.execute("SELECT * FROM sessions").fetchall())


def test_valid_session_round_trips(conn, admin_id):
    token, info = make(conn, admin_id)
    got = validate_session(conn, token, NOW + MIN)
    assert got is not None and got.id == info.id and got.admin_id == admin_id


def test_absent_garbage_and_oversized_tokens_are_rejected(conn, admin_id):
    make(conn, admin_id)
    for bad in (None, "", "garbage", "A" * 200, "éé", "!!!!"):
        assert validate_session(conn, bad, NOW) is None


def test_token_with_extra_illegal_characters_is_rejected(conn, admin_id):
    token, _ = make(conn, admin_id)
    assert validate_session(conn, token[:10] + "!" + token[10:], NOW) is None
    assert validate_session(conn, token + "!", NOW) is None
    assert validate_session(conn, token + "\n", NOW) is None


def test_idle_and_absolute_expiry(conn, admin_id):
    token, _ = make(conn, admin_id, max_s=3600)
    assert validate_session(conn, token, NOW + 29 * MIN, idle_s=1800) is not None
    assert validate_session(conn, token, NOW + 29 * MIN + 31 * MIN, idle_s=1800) is None  # idle > 30 min
    token2, _ = make(conn, admin_id, max_s=3600)
    # kept active, but the absolute lifetime still ends it
    for m in range(0, 61, 20):
        validate_session(conn, token2, NOW + m * MIN)
    assert validate_session(conn, token2, NOW + 61 * MIN) is None


def test_last_seen_is_extended_at_most_once_a_minute(conn, admin_id):
    token, info = make(conn, admin_id)
    validate_session(conn, token, NOW + 30_000)
    assert conn.execute("SELECT last_seen_ms FROM sessions WHERE id=?", (info.id,)).fetchone()[0] == NOW
    validate_session(conn, token, NOW + 61_000)
    assert conn.execute("SELECT last_seen_ms FROM sessions WHERE id=?", (info.id,)).fetchone()[0] == NOW + 61_000


def test_revoked_session_and_disabled_admin_are_rejected(conn, admin_id):
    token, info = make(conn, admin_id)
    sessions.revoke_session(conn, info.id, NOW)
    assert validate_session(conn, token, NOW + 1) is None
    token2, _ = make(conn, admin_id)
    conn.execute("UPDATE admins SET is_disabled=1 WHERE id=?", (admin_id,))
    assert validate_session(conn, token2, NOW + 1) is None


def test_revoke_all_can_spare_one_session(conn, admin_id):
    (ta, ia), (tb, _) = make(conn, admin_id), make(conn, admin_id)
    assert sessions.revoke_all_for_admin(conn, admin_id, NOW, except_id=ia.id) == 1
    assert validate_session(conn, ta, NOW + 1) is not None and validate_session(conn, tb, NOW + 1) is None
    assert sessions.revoke_all_for_admin(conn, admin_id, NOW) == 1


def test_cleanup_removes_expired_and_old_revoked_only(conn, admin_id):
    _, expired = make(conn, admin_id, at=NOW - 100 * 3600_000, max_s=3600)
    _, old_revoked = make(conn, admin_id)
    _, recent_revoked = make(conn, admin_id)
    _, live = make(conn, admin_id)
    sessions.revoke_session(conn, old_revoked.id, NOW - 8 * 24 * 3600_000)
    sessions.revoke_session(conn, recent_revoked.id, NOW - 3600_000)
    assert sessions.cleanup_sessions(conn, NOW) == 2
    left = {r[0] for r in conn.execute("SELECT id FROM sessions")}
    assert left == {recent_revoked.id, live.id} and expired.id not in left


def test_reauth_tracker_falls_back_to_creation_time(conn, admin_id):
    _, info = make(conn, admin_id)
    tr = ReauthTracker()
    assert tr.is_recent(info, NOW + 299_000, 300) and not tr.is_recent(info, NOW + 301_000, 300)
    tr.mark(info.id, NOW + 400_000)
    assert tr.is_recent(info, NOW + 600_000, 300)
    tr.forget(info.id)
    assert not tr.is_recent(info, NOW + 600_000, 300)
