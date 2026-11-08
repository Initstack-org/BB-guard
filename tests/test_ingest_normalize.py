import pytest

from guard.ingest import normalize as n


# ---- paths ----------------------------------------------------------------------------------------

def test_dot_segments_cannot_climb_above_the_root():
    assert n.normalize_uri("/../../etc/passwd").path == "/etc/passwd"
    assert n.normalize_uri("/%2e%2e/%2E%2e/x").path == "/x"
    assert n.normalize_uri("/a/b/../c").path == "/a/c"


def test_repeated_slashes_collapse_and_trailing_slash_is_kept():
    assert n.normalize_uri("//a///b/").path == "/a/b/"
    assert n.normalize_uri("/a/b/.").path == "/a/b/"
    assert n.normalize_uri("/a/..").path == "/"
    assert n.normalize_uri("/").path == "/"
    assert n.normalize_uri("").path == "/"


def test_percent_decoding_happens_exactly_once():
    assert n.normalize_uri("/a%2Fb").path == "/a/b"
    assert n.normalize_uri("/a%252Fb").path == "/a%2Fb"


def test_backslash_nul_and_control_characters_are_neutralized():
    assert n.normalize_uri("/a\\b").path == "/a/b"
    for raw in ("/a%00b", "/a%0d%0ab", "/a%09b", "/a%7fb"):
        path = n.normalize_uri(raw).path
        assert "\ufffd" in path
        assert not any(ord(ch) < 32 or ord(ch) == 127 for ch in path)


def test_invalid_utf8_is_replaced():
    assert n.normalize_uri("/%ff%fe").path == "/\ufffd\ufffd"


def test_long_path_is_truncated_and_flagged():
    result = n.normalize_uri("/" + "a" * 3000)
    assert len(result.path) == n.PATH_MAX
    assert result.path_truncated is True
    assert n.normalize_uri("/short").path_truncated is False


def test_fragment_is_dropped_and_absolute_form_is_reduced_to_path_and_query():
    assert n.normalize_uri("/a#frag").path == "/a"
    absolute = n.normalize_uri("http://evil.example/a/b?x=1")
    assert (absolute.path, absolute.query) == ("/a/b", "x=1")
    assert n.normalize_uri("http://evil.example").path == "/"


def test_a_question_mark_inside_an_encoded_path_stays_in_the_path():
    result = n.normalize_uri("/a%3Fb?c=1")
    assert result.path == "/a?b"
    assert result.query == "c=1"


# ---- query redaction ------------------------------------------------------------------------------

@pytest.mark.parametrize("key", [
    "password", "PASS", "passwd", "pwd", "my_post_key", "access_token", "sessionid", "api_key",
    "auth", "Authorization", "code", "signature", "csrf", "csrf_token", "sid", "secret", "client_secret",
])
def test_sensitive_keys_lose_their_values(key):
    assert n.redact_query(f"{key}=hunter2&a=1") == f"{key}=[redacted]&a=1"


def test_an_encoded_sensitive_key_is_still_recognized():
    assert n.redact_query("pass%77ord=hunter2") == "pass%77ord=[redacted]"
    assert n.redact_query("PaSsWoRd=hunter2") == "PaSsWoRd=[redacted]"


def test_ordinary_parameters_are_kept():
    assert n.redact_query("action=login&page=2&q=hello+world") == "action=login&page=2&q=hello+world"


def test_long_secret_looking_values_are_redacted_even_under_innocent_keys():
    assert n.redact_query("x=" + "0123456789abcdef" * 2) == "x=[redacted]"
    assert n.redact_query("x=" + "AbCd0123" * 8) == "x=[redacted]"
    assert n.redact_query("0123456789abcdef0123456789abcdef") == "[redacted]"


def test_a_long_plain_word_is_not_mistaken_for_a_secret():
    value = "a-very-long-thread-title-slug-without-digits"
    assert n.redact_query(f"q={value}") == f"q={value}"


def test_query_is_capped_and_empty_queries_are_none():
    assert len(n.redact_query("a=" + "x" * 5000)) == n.QUERY_MAX
    assert n.redact_query("") is None
    assert n.redact_query("&&&") is None


def test_secrets_never_survive_normalize_uri():
    result = n.normalize_uri("/member.php?action=do_login&password=hunter2&my_post_key=abc123&sid=zzz")
    assert "hunter2" not in result.query
    assert "abc123" not in result.query
    assert "zzz" not in result.query
    assert "action=do_login" in result.query


# ---- small fields ---------------------------------------------------------------------------------

def test_method_is_uppercased_and_restricted():
    assert n.normalize_method("get") == "GET"
    assert n.normalize_method("PROPFIND") == "OTHER"
    assert n.normalize_method("") == "OTHER"
    assert n.normalize_method(None) == "OTHER"


def test_host_is_lowercased_with_port_and_trailing_dot_removed():
    assert n.normalize_host("WWW.InitStack.org.:443") == "www.initstack.org"
    assert n.normalize_host("initstack.org") == "initstack.org"
    assert n.normalize_host("[::1]:8080") == "::1"
    assert n.normalize_host("") == "_"
    assert len(n.normalize_host("a" * 1000)) <= n.HOST_MAX


def test_canonical_ip():
    assert n.canonical_ip("::ffff:1.2.3.4") == "1.2.3.4"
    assert n.canonical_ip("2001:DB8:0:0:0:0:0:1") == "2001:db8::1"
    assert n.canonical_ip(" 10.0.0.1 ") == "10.0.0.1"
    assert n.canonical_ip("fe80::1%eth0") == "fe80::1"
    for bad in ("", "not-an-ip", "1.2.3", "999.1.1.1"):
        with pytest.raises(ValueError):
            n.canonical_ip(bad)


def test_mybb_identity_requires_a_positive_integer_and_a_name():
    assert n.clean_mybb_identity("5", "bob") == (5, "bob")
    for uid, name in (("0", "bob"), ("-3", "bob"), ("abc", "bob"), ("", "bob"), ("5", ""), ("5", "  "),
                      ("12345678901", "bob"), ("５", "bob"), (None, "bob")):
        assert n.clean_mybb_identity(uid, name) == (None, None)


def test_user_agent_and_referrer_cleaning():
    assert n.clean_user_agent("-") is None
    assert n.clean_user_agent("") is None
    assert len(n.clean_user_agent("x" * 1000)) == n.UA_MAX
    assert n.clean_user_agent("a\r\nb") == "a\ufffd\ufffdb"
    assert n.clean_referrer("https://e.org/a?token=abc#frag") == "https://e.org/a"
    assert n.clean_referrer("-") is None
    assert len(n.clean_referrer("https://e.org/" + "x" * 3000)) == n.REFERRER_MAX


def test_safe_excerpt_redacts_and_cuts():
    raw = b'{"u":"/x?password=hunter2&session=abc","k":"0123456789abcdef0123456789abcdef"}'
    text = n.safe_excerpt(raw)
    assert "hunter2" not in text and "abc\"" not in text and "0123456789abcdef" not in text
    assert len(n.safe_excerpt(b"x " * 1000)) <= n.EXCERPT_MAX
    assert "\n" not in n.safe_excerpt(b"a\nb\rc")
