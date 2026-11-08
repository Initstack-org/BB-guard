import dataclasses
import json

import pytest

from guard.ingest.parser import MAX_LINE_BYTES, ParseError, parse_line, parse_trusted
from ingest_helpers import log_dict, log_line

TRUSTED = parse_trusted(["192.168.1.148"])
HOSTS = frozenset({"initstack.org", "www.initstack.org"})


def parse(raw, trusted=TRUSTED, hosts=HOSTS):
    return parse_line(raw.rstrip(b"\n"), trusted=trusted, managed_hosts=hosts)


def test_a_normal_line_becomes_a_record():
    rec = parse(log_line(7, uid="12", un="bob"))
    assert rec.ts_ms == 1_800_000_007_250
    assert rec.ip == "203.0.113.7"
    assert (rec.method, rec.host, rec.path, rec.query) == ("GET", "initstack.org", "/forum-1.html", "page=7")
    assert (rec.status, rec.bytes_in, rec.bytes_out, rec.duration_ms) == (200, 300, 1500, 12)
    assert rec.user_agent == "TestAgent/1.0"
    assert rec.referrer == "https://example.org/a"
    assert (rec.mybb_uid, rec.mybb_username) == (12, "bob")
    assert rec.managed is True
    assert rec.outcome == "allowed"
    assert rec.request_id == bytes.fromhex(f"{8:032x}")
    assert rec.peer_mismatch is False


# ---- trusted client IP ----------------------------------------------------------------------------

def test_the_trusted_connector_may_set_the_client_ip():
    assert parse(log_line(ip="198.51.100.9", peer="192.168.1.148")).ip == "198.51.100.9"


def test_an_untrusted_peer_cannot_set_the_client_ip():
    rec = parse(log_line(ip="198.51.100.9", peer="203.0.113.50"))
    assert rec.ip == "203.0.113.50"
    assert rec.peer_mismatch is True


def test_an_untrusted_peer_that_matches_the_ip_is_not_a_mismatch():
    rec = parse(log_line(ip="203.0.113.50", peer="203.0.113.50"))
    assert rec.ip == "203.0.113.50"
    assert rec.peer_mismatch is False


def test_a_missing_peer_field_falls_back_to_the_ip_field():
    d = log_dict(ip="198.51.100.9")
    del d["peer"]
    rec = parse(json.dumps(d).encode())
    assert (rec.ip, rec.peer_mismatch) == ("198.51.100.9", False)


def test_trusted_connectors_can_be_cidr_ranges_and_ipv6():
    nets = parse_trusted(["10.0.0.0/8", "fd00::/8"])
    assert parse(log_line(ip="9.9.9.9", peer="10.1.2.3"), trusted=nets).ip == "9.9.9.9"
    assert parse(log_line(ip="9.9.9.9", peer="fd00::5"), trusted=nets).ip == "9.9.9.9"
    assert parse(log_line(ip="9.9.9.9", peer="11.1.2.3"), trusted=nets).ip == "11.1.2.3"


def test_no_trusted_connectors_means_the_peer_always_wins():
    assert parse(log_line(ip="9.9.9.9", peer="203.0.113.1"), trusted=()).ip == "203.0.113.1"


def test_ipv4_mapped_addresses_are_unmapped():
    assert parse(log_line(ip="::ffff:198.51.100.9")).ip == "198.51.100.9"


def test_bad_trusted_connector_setting_is_rejected():
    with pytest.raises(ValueError):
        parse_trusted(["not-an-ip"])


# ---- unusable lines -------------------------------------------------------------------------------

@pytest.mark.parametrize("raw", [
    b"", b"not json", b"[1,2,3]", b'"a string"', b"null", b"{", b"\xff\xfe\x00",
    json.dumps(log_dict(t="")).encode(), json.dumps(log_dict(t="abc")).encode(),
    json.dumps(log_dict(t="-5")).encode(), json.dumps(log_dict(t="1e99")).encode(),
    json.dumps(log_dict(ip="")).encode(), json.dumps(log_dict(ip="nope")).encode(),
    json.dumps(log_dict(peer="nope")).encode(),
    b"[" * 100000,
])
def test_unusable_lines_raise_parse_error(raw):
    with pytest.raises(ParseError):
        parse(raw)


def test_an_over_long_line_is_rejected():
    with pytest.raises(ParseError):
        parse(b"{" + b" " * MAX_LINE_BYTES + b"}")


def test_parse_errors_never_echo_the_line():
    try:
        parse(b'{"password": "hunter2"')
    except ParseError as exc:
        assert "hunter2" not in str(exc)


# ---- outcomes -------------------------------------------------------------------------------------

@pytest.mark.parametrize("gd,expected", [
    ("allowed", "allowed"), ("allow", "allowed"), ("denied", "denied"), ("deny", "denied"),
    ("DENIED", "denied"), ("overridden", "overridden"), ("monitored", "monitored"),
    ("", "unchecked"), ("something-else", "unchecked"),
])
def test_decision_mapping(gd, expected):
    assert parse(log_line(gd=gd)).outcome == expected


def test_block_fields_fill_in_when_the_guard_fields_are_empty():
    rec = parse(log_line(gd="", gt="", gr="", gx="", bd="denied", bt="url_rule", br="url:12", bx="Path is closed"))
    assert (rec.outcome, rec.detection, rec.rule_ref, rec.reason) == ("denied", "url_rule", "url:12", "Path is closed")


def test_guard_fields_win_over_block_fields():
    rec = parse(log_line(gd="monitored", gt="reputation", bd="denied", bt="url_rule"))
    assert (rec.outcome, rec.detection) == ("monitored", "reputation")


def test_an_unknown_detection_is_dropped():
    assert parse(log_line(gd="denied", gt="made_up")).detection is None


def test_rule_and_reason_are_bounded():
    rec = parse(log_line(gd="denied", gr="r" * 500, gx="x" * 500))
    assert len(rec.rule_ref) == 64 and len(rec.reason) == 200


# ---- other fields ---------------------------------------------------------------------------------

def test_unmanaged_hosts_are_flagged():
    assert parse(log_line(h="203.0.113.1")).managed is False
    assert parse(log_line(h="WWW.InitStack.org:443")).managed is True


def test_unknown_methods_become_other():
    assert parse(log_line(m="PROPFIND")).method == "OTHER"


def test_garbage_numbers_become_zero():
    rec = parse(log_line(s="abc", bi="-5", bo="x", d="nan"))
    assert (rec.status, rec.bytes_in, rec.bytes_out, rec.duration_ms) == (0, 0, 0, 0)
    assert parse(log_line(s="1000")).status == 0
    assert parse(log_line(bo="9" * 40)).bytes_out == 10**15


def test_mybb_identity_needs_both_parts():
    assert parse(log_line(uid="0", un="guest")).mybb_uid is None
    assert parse(log_line(uid="4", un="")).mybb_uid is None
    assert parse(log_line(uid="4", un="amy")).mybb_username == "amy"


def test_a_missing_request_id_falls_back_to_a_digest_of_the_line():
    raw = log_line(id="")
    first, second = parse(raw), parse(raw)
    assert len(first.request_id) == 16
    assert first.request_id == second.request_id  # replaying the same line deduplicates
    assert parse(log_line(5, id="")).request_id != first.request_id
    assert len(parse(log_line(id="zz" * 16)).request_id) == 16  # 32 characters but not hex


def test_hostile_values_leave_no_secret_in_any_field():
    rec = parse(log_line(
        u="/member.php?action=do_login&username=bob&password=hunter2&my_post_key=abcdef0123456789abcdef0123456789",
        ref="https://evil.example/?token=hunter2", ua="Agent\r\nInjected-Header: x"))
    assert "hunter2" not in repr(rec)
    assert "abcdef0123456789abcdef0123456789" not in repr(rec)
    assert "\r" not in rec.user_agent and "\n" not in rec.user_agent


def test_the_record_is_immutable():
    rec = parse(log_line())
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.ip = "1.2.3.4"


# ---- invalid UTF-8 from the client (Nginx escape=json passes bytes >= 0x80 through) ------------------

def _with_ua_bytes(ua_bytes: bytes) -> bytes:
    return json.dumps(log_dict(ua="@@"), ensure_ascii=False).encode().replace(b"@@", ua_bytes)


@pytest.mark.parametrize("ua_bytes", [b"Agent\xff/1.0", b"Agent\xed\xa0\x80/1.0", b"Agent\xc0\xaf/1.0"])
def test_invalid_utf8_keeps_the_request_and_stores_valid_text(ua_bytes):
    rec = parse(_with_ua_bytes(ua_bytes))
    assert rec.ip == "203.0.113.7" and rec.user_agent.startswith("Agent")
    rec.user_agent.encode("utf-8")  # must not raise: SQLite needs valid text


def test_a_json_escaped_lone_surrogate_is_neutralized_everywhere():
    rec = parse(json.dumps(log_dict(ua="a\ud800b", ref="http://e.org/\udfff", u="/p\ud800?q=\ud800",
                                    un="n\ud800", uid="3")).encode())
    for value in (rec.user_agent, rec.referrer, rec.path, rec.query, rec.mybb_username):
        value.encode("utf-8")
