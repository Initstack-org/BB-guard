"""Password hashing (argon2id via argon2-cffi) and new-password rules.

argon2-cffi is imported lazily so the rest of the package can be tested without it.
Passwords are never logged, audited or passed on a command line.
"""

from __future__ import annotations

from typing import Protocol

MAX_PASSWORD_CHARS = 1024

# A short local list of obvious choices (docs/SUBSYSTEMS.md section 7.1). Compared after lower-casing.
_COMMON = frozenset("""
password passw0rd p@ssw0rd letmein welcome admin administrator qwerty iloveyou monkey dragon
changeme changeme123 123456 1234567 12345678 123456789 1234567890 111111 000000 qwertyuiop
qwerty123 abc123 football baseball master hello freedom whatever trustno1 sunshine princess
""".split())


class Hasher(Protocol):
    def hash(self, password: str) -> str: ...
    def verify(self, stored_hash: str, password: str) -> bool: ...
    def needs_rehash(self, stored_hash: str) -> bool: ...


class MissingDependency(RuntimeError):
    pass


class Argon2Hasher:
    """argon2id with documented parameters: t=3, m=64 MiB, p=4 (argon2-cffi defaults are
    lower; these follow the OWASP-style recommendation for interactive logins)."""

    def __init__(self, time_cost: int = 3, memory_cost: int = 65536, parallelism: int = 4):
        try:
            import argon2  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise MissingDependency("argon2-cffi is not installed (pip install argon2-cffi)") from exc
        self._argon2 = argon2
        self._ph = argon2.PasswordHasher(time_cost=time_cost, memory_cost=memory_cost,
                                         parallelism=parallelism, type=argon2.Type.ID)

    def hash(self, password: str) -> str:
        return self._ph.hash(password)

    def verify(self, stored_hash: str, password: str) -> bool:
        try:
            return bool(self._ph.verify(stored_hash, password))
        except (self._argon2.exceptions.VerifyMismatchError,
                self._argon2.exceptions.VerificationError,
                self._argon2.exceptions.InvalidHashError):
            return False

    def needs_rehash(self, stored_hash: str) -> bool:
        return self._ph.check_needs_rehash(stored_hash)


def validate_new_password(password: str, *, username: str = "", min_length: int = 12) -> list[str]:
    """Return a list of reasons the password is unacceptable (empty list means fine)."""
    problems = []
    if len(password) < min_length:
        problems.append(f"must be at least {min_length} characters")
    if len(password) > MAX_PASSWORD_CHARS:
        problems.append(f"must be at most {MAX_PASSWORD_CHARS} characters")
    lowered = password.lower()
    if lowered in _COMMON:
        problems.append("is too common")
    if username and lowered == username.lower():
        problems.append("must not equal the username")
    if "\x00" in password:
        problems.append("contains a NUL character")
    if password and password.strip() == "":
        problems.append("must not be only whitespace")
    return problems
