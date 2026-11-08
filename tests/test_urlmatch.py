"""URL rule matching, safety rails and deterministic resolution (pure logic, standard library only).
Not yet run anywhere (see PROGRESS.md)."""

import random

import pytest

from guard import urlmatch
from guard.urlmatch import Rule, RuleError

HOSTS = ["initstack.org", "www.initstack.org"]
NOW = 1_800_000_000_000


# ---- parse_target ----------------------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("/private", ("/private", None)),
    ("/private/", ("/private", None)),
    ("/", ("/", None)),
    ("/a/../b", ("/b", None)),
    ("/%2e%2e/admin", ("/admin", None)),
    ("//x/../y", None),                                     # protocol-relative: rejected below
    ("/a#fragment", ("/a", None)),
    ("/a//b/./c", ("/a/b/c", None)),
    ("https://initstack.org/a/b?x=1", ("/a/b", {"x": "1"})),
    ("http://WWW.InitStack.org./a", ("/a", None)),
    ("https://initstack.org", ("/", None)),
    ("/forum?fid=3&page=2", ("/forum", {"fid": "3", "page": "2"})),
])
def test_parse_target(text, expected):
    if expected is None:
        with pytest.raises(RuleError):
            urlmatch.parse_target(text, HOSTS)
    else:
        assert urlmatch.parse_target(text, HOSTS) == expected


@pytest.mark.parametrize("text", [
    "", "   ", "private", "ftp://initstack.org/a", "javascript:alert(1)", "https://evil.example.com/a",
    "https://initstack.org.evil.com/a", "/a\x00b", "/a\nb", "/a?token=1", "/a?my_post_key=x",
    "/a?x=1&x=2", "/a?=1", "/" + "a" * 3000, "//host/path"])
def test_bad_targets_are_rejected(text):
    with pytest.raises(RuleError):
        urlmatch.parse_target(text, HOSTS)


def test_scope_ip():
    assert urlmatch.parse_scope_ip("") is None and urlmatch.parse_scope_ip(None) is None
    assert urlmatch.parse_scope_ip("::ffff:203.0.113.9") == "203.0.113.9"
    with pytest.raises(RuleError):
        urlmatch.parse_scope_ip("203.0.113.0/24")


# ---- covers: segment boundaries, no substring ------------------------------------------------

@pytest.mark.parametrize("pattern,kind,path,hit", [
    ("/private", "prefix", "/private", True),
    ("/private", "prefix", "/private/", True),
    ("/private", "prefix", "/private/x/y", True),
    ("/private", "prefix", "/privateer", False),
    ("/private", "prefix", "/x/private", False),
    ("/private", "prefix", "/PRIVATE", False),            # paths are case-sensitive
    ("/a", "exact", "/a/", True),
    ("/a", "exact", "/a/b", False),
    ("/a", "exact", "/ab", False),
    ("/", "prefix", "/anything/at/all", True),
    ("/", "exact", "/", True),
    ("/", "exact", "/x", False),
])
def test_covers(pattern, kind, path, hit):
    assert urlmatch.covers(pattern, kind, path) is hit


def test_request_parts_normalizes_like_ingest():
    assert urlmatch.request_parts("/private/../public//x/", "")[0] == "/public/x"
    assert urlmatch.request_parts("/a", "k=1&k=2&z")[1] == {"k": {"1", "2"}, "z": {""}}


def test_encoded_dot_segments_cannot_slip_past_a_prefix_rule():
    path, _ = urlmatch.request_parts("/public/%2e%2e/private/secret", "")
    assert urlmatch.covers("/private", "prefix", path)


# ---- safety rails ----------------------------------------------------------------------------

PROT = ["/_guard/", "/admincp/"]


def test_site_wide_deny_needs_the_setting():
    with pytest.raises(RuleError, match="whole site"):
        urlmatch.check_safety("/", "prefix", "deny", protected=[], allow_site_wide=False)
    urlmatch.check_safety("/", "prefix", "deny", protected=[], allow_site_wide=True)
    urlmatch.check_safety("/", "prefix", "allow", protected=PROT, allow_site_wide=False)  # allow is harmless
    urlmatch.check_safety("/", "exact", "deny", protected=[], allow_site_wide=False)      # only the home page


@pytest.mark.parametrize("pattern,kind", [
    ("/_guard", "prefix"), ("/_guard", "exact"), ("/_guard/x", "exact"), ("/_guard/x", "prefix"),
    ("/admincp", "prefix"), ("/", "prefix")])
def test_deny_over_a_protected_path_is_refused(pattern, kind):
    with pytest.raises(RuleError):
        urlmatch.check_safety(pattern, kind, "deny", protected=PROT, allow_site_wide=True)


@pytest.mark.parametrize("pattern,kind", [("/_", "prefix"), ("/_guardian", "prefix"), ("/admin", "prefix"),
                                           ("/private", "prefix"), ("/other", "exact")])
def test_neighbouring_paths_are_not_protected(pattern, kind):
    urlmatch.check_safety(pattern, kind, "deny", protected=PROT, allow_site_wide=False)


# ---- resolution ------------------------------------------------------------------------------

def R(id, pattern, kind="prefix", action="deny", **kw):
    return Rule(id=id, pattern=pattern, match_type=kind, action=action, **kw)


def win(rules, path, ip="198.51.100.5", query=None, now=NOW):
    got = urlmatch.winner(rules, ip, path, query or {}, now)
    return got.id if got else None


def test_no_rules_no_match():
    assert win([], "/x") is None
    assert win([R(1, "/a")], "/b") is None


def test_exact_beats_prefix():
    rules = [R(1, "/private"), R(2, "/private/public", "exact", "allow")]
    assert win(rules, "/private/public") == 2
    assert win(rules, "/private/other") == 1


def test_longer_prefix_beats_shorter():
    rules = [R(1, "/a"), R(2, "/a/b", action="allow")]
    assert win(rules, "/a/b/c") == 2 and win(rules, "/a/x") == 1


def test_per_address_beats_global_even_over_exact():
    rules = [R(1, "/x", "exact"), R(2, "/x", action="allow", scope_ip="203.0.113.9")]
    assert win(rules, "/x", ip="203.0.113.9") == 2
    assert win(rules, "/x", ip="203.0.113.10") == 1


def test_query_match_beats_none_and_all_pairs_are_required():
    rules = [R(1, "/f", "exact"), R(2, "/f", "exact", "allow", query_match=(("a", "1"), ("b", "2")))]
    assert win(rules, "/f", query={"a": {"1"}, "b": {"2"}, "extra": {"z"}}) == 2   # extra keys are fine
    assert win(rules, "/f", query={"a": {"1"}}) == 1                                 # one pair missing
    assert win(rules, "/f", query={"a": {"9"}, "b": {"2"}}) == 1


def test_repeated_query_keys_cannot_dodge_a_rule():
    rules = [R(1, "/f", "exact", query_match=(("a", "1"),))]
    assert win(rules, "/f", query={"a": {"0", "1"}}) == 1


def test_priority_then_deny_before_allow_then_id():
    assert win([R(1, "/a", priority=50), R(2, "/a", priority=10)], "/a") == 2
    assert win([R(1, "/a", action="allow"), R(2, "/a", action="deny")], "/a") == 2
    assert win([R(5, "/a"), R(3, "/a")], "/a") == 3


def test_disabled_expired_and_other_address_rules_are_ignored_and_labelled():
    rules = [R(1, "/a", enabled=False), R(2, "/a", expires_ms=NOW - 1), R(3, "/a", scope_ip="203.0.113.1"),
             R(4, "/a", expires_ms=NOW + 1000)]
    assert win(rules, "/a") == 4
    status = {v.rule.id: v.status for v in urlmatch.evaluate(rules, "198.51.100.5", "/a", {}, NOW)}
    assert status == {1: "disabled", 2: "expired", 3: "other_address", 4: "winner"}


def test_evaluate_labels_every_rule_and_marks_one_winner():
    rules = [R(1, "/a"), R(2, "/a/b"), R(3, "/zzz"), R(4, "/a/b", query_match=(("q", "1"),))]
    out = {v.rule.id: v.status for v in urlmatch.evaluate(rules, "198.51.100.5", "/a/b/c", {}, NOW)}
    assert out == {2: "winner", 1: "matched", 3: "no_match_path", 4: "no_match_query"}


def test_resolution_is_independent_of_input_order():
    rules = [R(1, "/a", priority=5), R(2, "/a/b", action="allow"), R(3, "/a/b/c", "exact"),
             R(4, "/a", scope_ip="198.51.100.5", action="allow", priority=900),
             R(5, "/a/b", query_match=(("k", "v"),)), R(6, "/", priority=0)]
    expected = win(rules, "/a/b/c", query={"k": {"v"}})
    for seed in range(25):
        shuffled = rules[:]
        random.Random(seed).shuffle(shuffled)
        assert win(shuffled, "/a/b/c", query={"k": {"v"}}) == expected
    assert expected == 4   # the per-address rule wins before anything else is compared


def test_a_deny_on_one_path_cannot_leak_to_the_rest_of_the_site():
    rules = [R(1, "/private")]
    for path in ("/", "/privacy", "/privateer", "/index.php", "/x/private"):
        assert win(rules, path) is None
