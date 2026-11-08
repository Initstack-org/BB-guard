from guard.auth import throttle
from guard.auth.throttle import ThrottlePolicy, check, record_failure

T0 = 1_000_000_000_000
P = ThrottlePolicy()
S = 1000


def fail(conn, key, at):
    return record_failure(conn, key, at, P)


def test_no_lock_before_the_limit(conn):
    for i in range(4):
        assert fail(conn, "ip:1.1.1.1", T0 + i * S) == 0
    assert check(conn, "ip:1.1.1.1", T0 + 5 * S) == 0


def test_fifth_failure_locks_for_fifteen_minutes(conn):
    for i in range(4):
        fail(conn, "k:aaaa", T0 + i * S)
    assert fail(conn, "k:aaaa", T0 + 4 * S) == 900
    assert check(conn, "k:aaaa", T0 + 4 * S) == 900
    assert check(conn, "k:aaaa", T0 + 4 * S + 899 * S) == 1
    assert check(conn, "k:aaaa", T0 + 4 * S + 900 * S) == 0


def test_check_rounds_up(conn):
    for i in range(5):
        fail(conn, "k:aaaa", T0)
    assert check(conn, "k:aaaa", T0 + 899_001) == 1


def test_lock_doubles_and_caps_at_a_day(conn):
    now, seen = T0, []
    for _ in range(5):
        seen.append(fail(conn, "k:aaaa", now))
    assert seen[-1] == 900
    for expected in (1800, 3600, 7200, 14400, 28800, 57600, 86400, 86400):
        now += check(conn, "k:aaaa", now) * S  # wait out the lock, then fail again
        assert fail(conn, "k:aaaa", now) == expected


def test_old_failures_age_out_of_the_window(conn):
    for i in range(4):
        fail(conn, "k:aaaa", T0 + i * S)
    assert fail(conn, "k:aaaa", T0 + 901 * S) == 0  # window restarted: this is failure number 1
    assert conn.execute("SELECT failures FROM auth_throttle").fetchone()[0] == 1


def test_escalation_resets_after_a_quiet_window_following_the_lock(conn):
    for i in range(5):
        fail(conn, "k:aaaa", T0)
    lock_end = T0 + 900 * S
    assert fail(conn, "k:aaaa", lock_end + 899 * S) == 1800  # not quiet long enough
    lock_end2 = lock_end + 899 * S + 1800 * S
    assert fail(conn, "k:aaaa", lock_end2 + 901 * S) == 0  # quiet: starts over


def test_clear_and_cleanup(conn):
    for i in range(5):
        fail(conn, "k:aaaa", T0)
    fail(conn, "k:bbbb", T0)
    throttle.clear(conn, "k:aaaa")
    assert check(conn, "k:aaaa", T0) == 0
    assert throttle.cleanup(conn, T0 + 10 * S) == 0  # still inside the window
    assert throttle.cleanup(conn, T0 + 901 * S) == 1
    assert conn.execute("SELECT COUNT(*) FROM auth_throttle").fetchone()[0] == 0


def test_cleanup_never_deletes_an_active_lock(conn):
    for i in range(5):
        fail(conn, "k:aaaa", T0)
    assert throttle.cleanup(conn, T0 + 899 * S) == 0
    assert check(conn, "k:aaaa", T0 + 899 * S) > 0


def test_keys_are_normalised():
    assert throttle.user_key(" Alice ") == throttle.user_key("alice")
    assert throttle.ip_key("2001:0db8:0:0:0:0:0:1") == throttle.ip_key("2001:db8::1")
    assert throttle.ip_key("junk") == "ip:invalid"
    assert "alice" not in throttle.user_key("alice")
