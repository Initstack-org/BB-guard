"""Shared fixtures. Tests use a fake password hasher so they run without argon2-cffi."""

import hashlib

import pytest

from guard import db

NOW = 1_800_000_000_000  # a fixed "now" in epoch milliseconds
GOOD_PW = "correct horse battery staple"


class FakeHasher:
    """Implements the Hasher protocol. Hashes look like argon2id so the schema CHECK passes;
    the stored value never contains the password itself."""

    def __init__(self, params: str = "p1"):
        self.params = params
        self.verify_calls = 0

    def hash(self, password: str) -> str:
        return f"$argon2id$fake${self.params}${hashlib.sha256(password.encode()).hexdigest()}"

    def verify(self, stored_hash: str, password: str) -> bool:
        self.verify_calls += 1
        return stored_hash.rsplit("$", 1)[-1] == hashlib.sha256(password.encode()).hexdigest()

    def needs_rehash(self, stored_hash: str) -> bool:
        return stored_hash.split("$")[3] != self.params


@pytest.fixture
def conn():
    c = db.connect(":memory:")
    db.migrate(c)
    yield c
    c.close()


@pytest.fixture
def hasher():
    return FakeHasher()


@pytest.fixture
def admin_id(conn, hasher):
    from guard.auth import service
    return service.create_admin(conn, hasher, "alice", GOOD_PW, now_ms=NOW)
