from guard.auth import csrf

KEY = b"k" * 32
OTHER = b"o" * 32
ORIGIN = "https://guard.example.org"


def test_tokens_are_deterministic_and_bound_to_key_and_session():
    h = b"h" * 32
    assert csrf.session_token(KEY, h) == csrf.session_token(KEY, h)
    assert csrf.session_token(KEY, h) != csrf.session_token(OTHER, h)
    assert csrf.session_token(KEY, h) != csrf.session_token(KEY, b"x" * 32)


def test_session_and_pre_session_tokens_do_not_collide():
    assert csrf.session_token(KEY, b"abc") != csrf.pre_session_token(KEY, "abc")


def test_verify():
    tok = csrf.pre_session_token(KEY, "cookie")
    assert csrf.verify(tok, tok)
    assert not csrf.verify(tok, None) and not csrf.verify(tok, "") and not csrf.verify(tok, tok + "x")
    assert not csrf.verify(tok, "é" * len(tok))  # non-ASCII input must not crash


def test_origin_ok():
    assert csrf.origin_ok(ORIGIN, ORIGIN, None)
    assert csrf.origin_ok(ORIGIN, "HTTPS://Guard.Example.org/", None)
    assert csrf.origin_ok(ORIGIN, None, ORIGIN + "/admin/page?x=1")
    for origin in ("https://evil.example", "null", "", "http://guard.example.org",
                   "https://guard.example.org.evil.example", "https://guard.example.org:8443"):
        assert not csrf.origin_ok(ORIGIN, origin, ORIGIN + "/ok")  # Origin wins over Referer
    assert not csrf.origin_ok(ORIGIN, None, "https://evil.example/https://guard.example.org/")
    assert not csrf.origin_ok(ORIGIN, None, None)
    assert not csrf.origin_ok(ORIGIN, None, "not a url")


def test_export_fetch_ok():
    assert csrf.export_fetch_ok(ORIGIN, "same-origin", None) and csrf.export_fetch_ok(ORIGIN, "none", None)
    assert not csrf.export_fetch_ok(ORIGIN, "cross-site", ORIGIN) and not csrf.export_fetch_ok(ORIGIN, "same-site", None)
    assert csrf.export_fetch_ok(ORIGIN, None, ORIGIN) and not csrf.export_fetch_ok(ORIGIN, None, "https://evil.example")
    assert not csrf.export_fetch_ok(ORIGIN, None, None)
