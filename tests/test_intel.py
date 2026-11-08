"""Stage 5 library tests: reputation policy, IPLogs parsing and cache, Tor feed, manual IP rules.

Standard library and SQLite only (no Starlette). Not yet run anywhere (see PROGRESS.md).
"""

import json

import pytest

from guard import audit
from guard.intel import iplogs, iprules, policy, tor
from guard.intel.policy import Decision, Intel

NOW = 1_800_000_000_000
POLICY = {"tor": {"block": True}, "vpn_detected": {"block": True}, "vpn_likely": {"block": False},
          "proxy": {"block": True}, "relay": {"block": False}, "min_confidence": None}


def ok(**flags):
    return Intel(status="ok", **flags)


# ---- policy ----------------------------------------------------------------------------------

def test_hosting_only_never_blocks():
    """The 8.8.8.8 fixture: hosting true, everything else false."""
    assert policy.evaluate(ok(is_hosting=True, is_vpn=False, is_proxy=False, is_tor=False,
                              is_relay=False), False, POLICY).action == "allow"


def test_hosting_and_crawler_cannot_block_even_with_a_hostile_policy():
    hostile = dict(POLICY, hosting={"block": True}, crawler={"block": True})
    assert policy.evaluate(ok(is_hosting=True, is_crawler=True), False, hostile).action == "allow"


@pytest.mark.parametrize("intel,tor_hit,detection", [
    (ok(is_vpn=True, confidence="high"), False, "vpn_detected"),
    (ok(is_proxy=True), False, "proxy"),
    (ok(is_tor=True), False, "tor"),
    (Intel(), True, "tor"),                                   # local Tor list works with no IPLogs data
    (Intel(status="error"), True, "tor"),
])
def test_blocking_categories(intel, tor_hit, detection):
    d = policy.evaluate(intel, tor_hit, POLICY)
    assert d.action == "deny" and d.detection == detection and d.reason


def test_low_confidence_vpn_is_flag_only_by_default():
    d = policy.evaluate(ok(is_vpn=True, confidence="Low"), False, POLICY)
    assert d.action == "allow" and d.flags == ("vpn_likely",)


def test_relay_is_flag_only_by_default():
    assert policy.evaluate(ok(is_relay=True), False, POLICY).action == "allow"


def test_policy_can_be_switched():
    p = dict(POLICY, relay={"block": True})
    assert policy.evaluate(ok(is_relay=True), False, p).action == "deny"
    p = dict(POLICY, tor={"block": False})
    assert policy.evaluate(Intel(), True, p).action == "allow"


@pytest.mark.parametrize("intel", [
    Intel(), Intel(status="error"), Intel(status="skipped"),
    Intel(status="ok", is_vpn=True, expired_beyond_grace=True)])
def test_unknown_data_fails_open(intel):
    d = policy.evaluate(intel, False, POLICY)
    assert d == Decision("allow", "unknown")


@pytest.mark.parametrize("bad", [None, [], "x", {"tor": "yes"}, {"tor": {"block": "true"}}])
def test_malformed_policy_never_blocks_and_never_raises(bad):
    assert policy.evaluate(ok(is_vpn=True, is_proxy=True), False, bad).action == "allow"


# ---- IPLogs parsing --------------------------------------------------------------------------

GOOD = {"verdict": "clean", "score": 3, "is_vpn": False, "is_proxy": False, "is_tor": False,
        "is_relay": False, "is_hosting": True, "is_crawler": False, "confidence": "high",
        "reputation": "good", "signals": ["a", "b"],
        "ip_info": {"asn": 15169, "org": "Google LLC", "isp": "Google", "country": "US",
                    "prefix": "8.8.8.0/24", "latitude": 37.4, "longitude": -122.0}}


def test_parse_response_reads_the_fields_and_drops_coordinates():
    out = iplogs.parse_response(GOOD)
    assert out["is_hosting"] == 1 and out["is_vpn"] == 0 and out["asn"] == "15169"
    assert out["score"] == 3.0 and json.loads(out["signals"]) == ["a", "b"]
    assert "latitude" not in out and "longitude" not in out


def test_missing_fields_become_null():
    out = iplogs.parse_response({})
    assert out["is_vpn"] is None and out["verdict"] is None and out["asn"] is None


@pytest.mark.parametrize("payload", [
    [], "x", {"is_vpn": "yes"}, {"is_tor": 1}, {"score": "high"}, {"score": True},
    {"verdict": ["a"]}, {"ip_info": "x"}, {"signals": "x"}, {"verdict": "a\x00b"}])
def test_wrong_types_are_an_error_not_a_guess(payload):
    with pytest.raises(iplogs.IntelError):
        iplogs.parse_response(payload)


def test_oversized_signals_are_dropped_not_stored():
    out = iplogs.parse_response({"signals": ["x" * 100] * 100})
    assert out["signals"] is None


@pytest.mark.parametrize("ip,public", [("8.8.8.8", True), ("10.0.0.1", False), ("127.0.0.1", False),
                                        ("192.168.1.148", False), ("169.254.1.1", False),
                                        ("224.0.0.1", False), ("::1", False), ("fe80::1", False),
                                        ("2001:4860:4860::8888", True), ("garbage", False)])
def test_only_public_addresses_are_sent_out(ip, public):
    assert iplogs.is_public(ip) is public


# ---- IPLogs lookup and cache -----------------------------------------------------------------

class Net:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, body, headers, timeout):
        self.calls.append(json.loads(body))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def reply(payload=GOOD, status=200, headers=None):
    return status, headers or {}, json.dumps(payload).encode()


def do_lookup(conn, net, ip="8.8.8.8", now=NOW, rate=None, force=False):
    return iplogs.lookup(conn, ip, now, fetch=net, rate=rate, ttl_ok_s=86400, ttl_error_s=300, force=force)


def test_lookup_stores_and_caches(conn):
    net = Net(reply())
    assert do_lookup(conn, net) == "ok"
    assert net.calls == [{"ip": "8.8.8.8"}]
    assert do_lookup(conn, net, now=NOW + 1000) == "cached"       # no second call
    row = conn.execute("SELECT * FROM ip_intel WHERE ip = '8.8.8.8'").fetchone()
    assert row["status"] == "ok" and row["is_hosting"] == 1 and row["expires_ms"] == NOW + 86400_000


def test_expired_entry_is_refreshed(conn):
    net = Net(reply(), reply(dict(GOOD, is_vpn=True)))
    do_lookup(conn, net)
    assert do_lookup(conn, net, now=NOW + 86400_000 + 1) == "ok"
    assert conn.execute("SELECT is_vpn FROM ip_intel").fetchone()[0] == 1


def test_private_address_is_skipped_and_never_sent(conn):
    net = Net()
    assert do_lookup(conn, net, ip="192.168.1.5") == "skipped"
    assert net.calls == []
    assert conn.execute("SELECT status FROM ip_intel").fetchone()[0] == "skipped"


@pytest.mark.parametrize("response,kind", [
    (reply(status=500), "server_error"), (reply(status=403), "http_error"),
    ((200, {}, b"not json"), "bad_response"), (reply([1, 2]), "bad_response"),
    ((200, {}, b"x" * (iplogs.MAX_RESPONSE_BYTES + 1)), "bad_response")])
def test_errors_are_recorded_as_unknown_with_a_retry_time(conn, response, kind):
    assert do_lookup(conn, Net(response)) == "error"
    row = conn.execute("SELECT * FROM ip_intel").fetchone()
    assert row["status"] == "error" and row["error_kind"] == kind and row["retry_after_ms"] == NOW + 300_000
    assert do_lookup(conn, Net(), now=NOW + 1000) == "backoff"     # no hammering


def test_network_failure_is_an_error_after_one_retry(conn, monkeypatch):
    monkeypatch.setattr(iplogs.time, "sleep", lambda s: None)
    net = Net(OSError("down"), OSError("down"))
    assert do_lookup(conn, net) == "error" and len(net.calls) == 2


def test_failure_never_overwrites_good_data(conn):
    do_lookup(conn, Net(reply(dict(GOOD, is_vpn=True))))
    do_lookup(conn, Net(reply(status=500)), now=NOW + 86400_000 + 1)
    row = conn.execute("SELECT * FROM ip_intel").fetchone()
    assert row["status"] == "ok" and row["is_vpn"] == 1 and row["error_kind"] == "server_error"
    # usable within the stale grace, unknown beyond it
    assert iplogs.load_intel(conn, "8.8.8.8", NOW + 86400_000 + 5, 7 * 86400).usable
    assert not iplogs.load_intel(conn, "8.8.8.8", NOW + 86400_000 + 8 * 86400_000, 7 * 86400).usable


def test_429_pauses_everything_and_honours_retry_after(conn):
    rate = iplogs.RateLimiter(30)
    assert do_lookup(conn, Net(reply(status=429, headers={"Retry-After": "600"})), rate=rate) == "error"
    assert conn.execute("SELECT retry_after_ms FROM ip_intel").fetchone()[0] == NOW + 600_000
    assert do_lookup(conn, Net(), ip="1.1.1.1", now=NOW + 1000, rate=rate) == "rate_limited"


def test_local_rate_limit():
    rate = iplogs.RateLimiter(2)
    assert [rate.allow(100.0), rate.allow(100.1), rate.allow(100.2)] == [True, True, False]
    assert rate.allow(161.0) is True


def test_force_ignores_a_fresh_cache(conn):
    net = Net(reply(), reply())
    do_lookup(conn, net)
    assert do_lookup(conn, net, now=NOW + 5, force=True) == "ok" and len(net.calls) == 2


def test_load_intel_missing_and_needs_lookup(conn):
    assert iplogs.load_intel(conn, "8.8.8.8", NOW, 0) == Intel()
    assert iplogs.needs_lookup(conn, "8.8.8.8", NOW) is True
    assert iplogs.needs_lookup(conn, "10.0.0.1", NOW) is False
    do_lookup(conn, Net(reply()))
    assert iplogs.needs_lookup(conn, "8.8.8.8", NOW + 10) is False
    assert iplogs.needs_lookup(conn, "not-an-ip", NOW) is False


def test_the_stored_hosting_fixture_does_not_block_end_to_end(conn):
    do_lookup(conn, Net(reply()))
    intel = iplogs.load_intel(conn, "8.8.8.8", NOW + 5, 0)
    assert intel.is_hosting is True
    assert policy.evaluate(intel, False, POLICY).action == "allow"


# ---- Tor feed --------------------------------------------------------------------------------

def feed(n, start=1):
    return "# comment\n" + "\n".join(f"198.51.{start + i // 250}.{i % 250 + 1}" for i in range(n)) + "\n"


def tor_update(conn, text, now=NOW, status=200, min_entries=10, min_ratio=0.5):
    return tor.update(conn, now, fetch=lambda: (status, text.encode()), min_entries=min_entries,
                      min_ratio=min_ratio)


def test_good_list_replaces_the_active_set(conn):
    replaced, msg = tor_update(conn, feed(20))
    assert replaced and tor.is_exit(conn, "198.51.1.1") and not tor.is_exit(conn, "8.8.8.8")
    state = tor.state(conn)
    assert state["entry_count"] == 20 and state["fetched_ms"] == NOW and state["last_error"] is None


@pytest.mark.parametrize("text,status", [
    ("198.51.1.1\nnot-an-ip\n", 200), (feed(5), 200), (feed(20), 503), ("", 200)])
def test_bad_download_keeps_last_known_good(conn, text, status):
    tor_update(conn, feed(20))
    replaced, msg = tor_update(conn, text, now=NOW + 1000, status=status)
    assert not replaced and msg
    assert tor.is_exit(conn, "198.51.1.1")
    state = tor.state(conn)
    assert state["entry_count"] == 20 and state["fetched_ms"] == NOW and state["consecutive_failures"] == 1
    assert state["last_error"] and state["last_attempt_ms"] == NOW + 1000


def test_collapse_against_the_previous_list_is_rejected(conn):
    tor_update(conn, feed(100), min_entries=10)
    replaced, msg = tor_update(conn, feed(30), min_entries=10, min_ratio=0.5)
    assert not replaced and "previous" in msg and tor.state(conn)["entry_count"] == 100


def test_network_error_is_recorded_not_raised(conn):
    def boom():
        raise OSError("no route")
    replaced, msg = tor.update(conn, NOW, fetch=boom, min_entries=10, min_ratio=0.5)
    assert not replaced and "OSError" in msg or "no route" in msg


def test_success_resets_the_failure_counter(conn):
    tor_update(conn, "bad")
    tor_update(conn, feed(20), now=NOW + 5)
    assert tor.state(conn)["consecutive_failures"] == 0


def test_is_exit_handles_junk_and_mapped_addresses(conn):
    tor_update(conn, feed(20))
    assert tor.is_exit(conn, "garbage") is False
    assert tor.is_exit(conn, "::ffff:198.51.1.1") is True


# ---- manual IP rules -------------------------------------------------------------------------

def rule(conn, admin_id, mode, ip="203.0.113.9", note="because", expires=None, now=NOW):
    return iprules.set_rule(conn, ip, mode, note, expires, admin_id=admin_id, admin_name="alice",
                            ip="198.51.100.1", now_ms=now)


def test_block_and_allow_need_a_note(conn, admin_id):
    for mode in ("block", "allow"):
        with pytest.raises(iprules.RuleError):
            rule(conn, admin_id, mode, note="  ")
    assert rule(conn, admin_id, "monitor", note="") == "set"


def test_set_replace_and_clear(conn, admin_id):
    rule(conn, admin_id, "block")
    rule(conn, admin_id, "allow", note="reviewed", now=NOW + 5)
    row = iprules.active_rule(conn, "203.0.113.9", NOW + 10)
    assert row["mode"] == "allow" and row["note"] == "reviewed"
    assert row["created_ms"] == NOW and row["updated_ms"] == NOW + 5
    assert rule(conn, admin_id, "none") == "cleared"
    assert iprules.active_rule(conn, "203.0.113.9", NOW + 10) is None


def test_every_change_is_audited_with_who_and_why(conn, admin_id):
    rule(conn, admin_id, "block", note="scraping")
    rule(conn, admin_id, "none")
    rows = conn.execute("SELECT action, actor_name, target_id, detail FROM audit_events"
                        " WHERE action LIKE 'ip_rule.%' ORDER BY id").fetchall()
    assert [r["action"] for r in rows] == ["ip_rule.set", "ip_rule.clear"]
    assert rows[0]["actor_name"] == "alice" and rows[0]["target_id"] == "203.0.113.9"
    assert json.loads(rows[0]["detail"])["note"] == "scraping"


@pytest.mark.parametrize("ip", ["", "999.1.1.1", "evil.example.com", "203.0.113.0/24", "1.2.3.4 5"])
def test_bad_addresses_are_rejected(conn, admin_id, ip):
    with pytest.raises(iprules.RuleError):
        rule(conn, admin_id, "block", ip=ip)


def test_addresses_are_stored_canonically(conn, admin_id):
    rule(conn, admin_id, "block", ip="::ffff:203.0.113.9")
    assert conn.execute("SELECT ip FROM ip_rules").fetchone()[0] == "203.0.113.9"


def test_expiry_must_be_in_the_future(conn, admin_id):
    with pytest.raises(iprules.RuleError):
        rule(conn, admin_id, "block", expires=NOW)


def test_expired_rule_is_inactive_then_swept_with_audit(conn, admin_id):
    rule(conn, admin_id, "block", expires=NOW + 1000)
    assert iprules.active_rule(conn, "203.0.113.9", NOW + 500) is not None
    assert iprules.active_rule(conn, "203.0.113.9", NOW + 1000) is None
    assert iprules.sweep_expired(conn, NOW + 2000) == 1
    assert conn.execute("SELECT COUNT(*) FROM ip_rules").fetchone()[0] == 0
    assert conn.execute("SELECT actor_name FROM audit_events WHERE action = 'ip_rule.expire'").fetchone()[0] == "system"
    assert iprules.sweep_expired(conn, NOW + 3000) == 0


def test_rule_changes_bump_the_change_counter(conn, admin_id):
    before = conn.execute("SELECT value FROM change_counters WHERE name = 'ip_rules'").fetchone()[0]
    rule(conn, admin_id, "block")
    rule(conn, admin_id, "none")
    after = conn.execute("SELECT value FROM change_counters WHERE name = 'ip_rules'").fetchone()[0]
    assert after == before + 2


def test_clearing_a_missing_rule_is_harmless(conn, admin_id):
    assert rule(conn, admin_id, "none", ip="203.0.113.77") == "cleared"
    assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE action = 'ip_rule.clear'").fetchone()[0] == 0
