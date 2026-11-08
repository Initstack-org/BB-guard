import pytest

from guard.auth import passwords
from guard.auth.passwords import validate_new_password as check


def test_good_password():
    assert check("correct horse battery staple", username="alice") == []


def test_length_boundaries():
    assert check("a" * 11) and check("a" * 12) == []
    assert check("a" * 1024) == [] and check("a" * 1025)
    assert check("abcd", min_length=4) == []


@pytest.mark.parametrize("pw", ["administrator", "Administrator", "ADMINISTRATOR"])
def test_common_passwords_rejected_case_insensitively(pw):
    assert any("common" in p for p in check(pw))


def test_username_equal_rejected_case_insensitively():
    assert any("username" in p for p in check("SomeLongUsername", username="somelongusername"))


def test_nul_and_whitespace_rejected():
    assert any("NUL" in p for p in check("a" * 12 + "\x00"))
    assert any("whitespace" in p for p in check(" " * 12))


def test_length_counts_characters_not_bytes():
    assert check("é" * 12) == []


def test_missing_argon2_is_a_clear_error():
    try:
        import argon2  # noqa: F401
    except ImportError:
        with pytest.raises(passwords.MissingDependency, match="argon2-cffi"):
            passwords.Argon2Hasher()
    else:  # pragma: no cover
        h = passwords.Argon2Hasher(time_cost=1, memory_cost=8, parallelism=1)
        stored = h.hash("pw")
        assert stored.startswith("$argon2id$") and h.verify(stored, "pw") and not h.verify(stored, "x")
        assert not h.verify("garbage", "pw")
