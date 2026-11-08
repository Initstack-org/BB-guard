"""Admin accounts and password sign-in (docs/SUBSYSTEMS.md section 7.1 and 7.2).

No web framework here: the future web layer calls these functions. Time is passed in so every
path is testable.
"""

from __future__ import annotations

import ipaddress
import os
import re
import sqlite3
from dataclasses import dataclass

from .. import audit
from ..db import transaction
from . import sessions, throttle
from .passwords import Hasher, validate_new_password

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,64}$")
_DUMMY_PASSWORD = "dummy-password-for-timing-only"


class AccountError(Exception):
    """Raised for rejected account changes; the message is safe to show to an admin."""


def canonical_ip(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.compressed


def create_admin(conn: sqlite3.Connection, hasher: Hasher, username: str, password: str, *,
                 now_ms: int, display_name: str = "", created_by: int | None = None,
                 actor_name: str = "", min_length: int = 12) -> int:
    """Create an enabled admin with an argon2id password. Returns the new admin id."""
    if not USERNAME_RE.match(username):
        raise AccountError("username must be 3 to 64 characters: letters, digits, dot, dash, underscore")
    problems = validate_new_password(password, username=username, min_length=min_length)
    if problems:
        raise AccountError("password " + "; ".join(problems))
    pw_hash = hasher.hash(password)
    try:
        with transaction(conn):
            cur = conn.execute(
                "INSERT INTO admins(username, display_name, password_hash, password_changed_ms,"
                " webauthn_user_handle, created_ms, created_by) VALUES (?,?,?,?,?,?,?)",
                (username, display_name[:100], pw_hash, now_ms, os.urandom(32), now_ms, created_by))
            admin_id = cur.lastrowid
            audit.record(conn, "admin.create", "success", actor_admin_id=created_by,
                         actor_name=actor_name, target_type="admin", target_id=str(admin_id),
                         detail={"username": username}, ts_ms=now_ms)
    except sqlite3.IntegrityError as exc:
        raise AccountError("that username is already taken") from exc
    return admin_id


def set_password(conn: sqlite3.Connection, hasher: Hasher, admin_id: int, new_password: str, *,
                 now_ms: int, actor_admin_id: int | None = None, actor_name: str = "",
                 action: str = "account.password_change", keep_session_id: int | None = None,
                 min_length: int = 12, ip: str = "") -> None:
    """Set a new password and revoke the admin's other sessions."""
    row = conn.execute("SELECT username FROM admins WHERE id = ?", (admin_id,)).fetchone()
    if row is None:
        raise AccountError("no such administrator")
    problems = validate_new_password(new_password, username=row["username"], min_length=min_length)
    if problems:
        raise AccountError("password " + "; ".join(problems))
    new_hash = hasher.hash(new_password)
    with transaction(conn):
        conn.execute("UPDATE admins SET password_hash = ?, password_changed_ms = ? WHERE id = ?",
                     (new_hash, now_ms, admin_id))
        sessions.revoke_all_for_admin(conn, admin_id, now_ms, except_id=keep_session_id)
        audit.record(conn, action, "success", actor_admin_id=actor_admin_id, actor_name=actor_name,
                     target_type="admin", target_id=str(admin_id), ip=ip, ts_ms=now_ms)


@dataclass(frozen=True)
class PasswordCheck:
    """Outcome of re-checking a signed-in admin's password. `retry_after_s` > 0 means locked."""
    ok: bool
    retry_after_s: int = 0

    @property
    def locked(self) -> bool:
        return self.retry_after_s > 0


def check_admin_password(conn: sqlite3.Connection, hasher: Hasher, admin_id: int, password: str, *,
                         ip: str, now_ms: int, action: str,
                         policy: throttle.ThrottlePolicy = throttle.ThrottlePolicy(),
                         password_login_enabled: bool = True) -> PasswordCheck:
    """Re-check the password of an admin who already has a session (re-authentication, password
    change). Uses the same throttle keys as sign-in (docs/API.md route limit L1), so a stolen
    session cannot be used to guess the password without limit. A failure is audited as `action`
    with outcome `failure`; a lock as `auth.lockout`. Success is audited by the caller."""
    ip = canonical_ip(ip)
    row = conn.execute("SELECT id, username, password_hash, is_disabled FROM admins WHERE id = ?",
                       (admin_id,)).fetchone()
    if row is None or row["is_disabled"]:
        return PasswordCheck(False)
    ukey, ikey = throttle.user_key(row["username"]), throttle.ip_key(ip)
    wait = max(throttle.check(conn, ukey, now_ms), throttle.check(conn, ikey, now_ms))
    if wait:
        audit.record(conn, "auth.lockout", "denied", actor_admin_id=row["id"],
                     actor_name=row["username"], ip=ip, detail={"retry_after_s": wait}, ts_ms=now_ms)
        return PasswordCheck(False, retry_after_s=wait)
    if row["password_hash"] is not None and password_login_enabled:
        ok = hasher.verify(row["password_hash"], password)
    else:
        hasher.verify(_dummy_hash(hasher), password)  # comparable work; no password sign-in here
        ok = False
    if not ok:
        locked = max(throttle.record_failure(conn, ukey, now_ms, policy),
                     throttle.record_failure(conn, ikey, now_ms, policy))
        audit.record(conn, action, "failure", actor_admin_id=row["id"], actor_name=row["username"],
                     ip=ip, detail={"reason": "wrong_password", "locked_for_s": locked} if locked
                     else {"reason": "wrong_password"}, ts_ms=now_ms)
        return PasswordCheck(False, retry_after_s=locked)
    throttle.clear(conn, ukey, ikey)
    return PasswordCheck(True)


def change_password(conn: sqlite3.Connection, hasher: Hasher, admin_id: int, current_password: str,
                    new_password: str, *, ip: str, now_ms: int, keep_session_id: int | None = None,
                    min_length: int = 12,
                    policy: throttle.ThrottlePolicy = throttle.ThrottlePolicy(),
                    password_login_enabled: bool = True) -> PasswordCheck:
    """Change the signed-in admin's own password. The current password is checked first (and
    throttled); a bad or reused new password then raises AccountError and is not counted as a
    failed sign-in. On success the admin's other sessions are revoked."""
    check = check_admin_password(conn, hasher, admin_id, current_password, ip=ip, now_ms=now_ms,
                                 action="account.password_change", policy=policy,
                                 password_login_enabled=password_login_enabled)
    if not check.ok:
        return check
    if new_password == current_password:
        raise AccountError("password must differ from the current one")
    row = conn.execute("SELECT username FROM admins WHERE id = ?", (admin_id,)).fetchone()
    set_password(conn, hasher, admin_id, new_password, now_ms=now_ms, actor_admin_id=admin_id,
                 actor_name=row["username"], keep_session_id=keep_session_id, min_length=min_length,
                 ip=canonical_ip(ip))
    return check


@dataclass(frozen=True)
class LoginResult:
    ok: bool
    token: str | None = None
    session: sessions.SessionInfo | None = None
    admin_id: int | None = None
    retry_after_s: int = 0  # > 0 means locked out

    @property
    def locked(self) -> bool:
        return self.retry_after_s > 0


def authenticate_password(conn: sqlite3.Connection, hasher: Hasher, username: str, password: str, *,
                          ip: str, user_agent: str, now_ms: int,
                          policy: throttle.ThrottlePolicy = throttle.ThrottlePolicy(),
                          session_max_s: int = 43200,
                          password_login_enabled: bool = True) -> LoginResult:
    """Check a username and password. The caller shows one generic message for any failure;
    `retry_after_s` is the only distinguishable outcome (a lock applies to everyone alike)."""
    ip = canonical_ip(ip)
    ukey, ikey = throttle.user_key(username), throttle.ip_key(ip)
    wait = max(throttle.check(conn, ukey, now_ms), throttle.check(conn, ikey, now_ms))
    if wait:
        audit.record(conn, "auth.lockout", "denied", ip=ip, detail={"retry_after_s": wait}, ts_ms=now_ms)
        return LoginResult(False, retry_after_s=wait)

    row = conn.execute("SELECT id, username, password_hash, is_disabled FROM admins WHERE username = ?",
                       (username.strip(),)).fetchone()
    usable = (row is not None and not row["is_disabled"] and row["password_hash"] is not None
              and password_login_enabled)
    if usable:
        ok = hasher.verify(row["password_hash"], password)
    else:
        # Do comparable work for unknown or unusable accounts so timing does not reveal them.
        hasher.verify(_dummy_hash(hasher), password)
        ok = False

    if not ok:
        locked = max(throttle.record_failure(conn, ukey, now_ms, policy),
                     throttle.record_failure(conn, ikey, now_ms, policy))
        audit.record(conn, "auth.login_failed", "failure", ip=ip, ts_ms=now_ms,
                     actor_admin_id=row["id"] if row is not None else None,
                     actor_name=row["username"] if row is not None else "",
                     detail={"locked_for_s": locked} if locked else None)
        return LoginResult(False, retry_after_s=locked)

    new_hash = hasher.hash(password) if hasher.needs_rehash(row["password_hash"]) else None
    with transaction(conn):
        if new_hash:
            conn.execute("UPDATE admins SET password_hash = ? WHERE id = ?", (new_hash, row["id"]))
        conn.execute("UPDATE admins SET last_login_ms = ? WHERE id = ?", (now_ms, row["id"]))
        token, info = sessions.create_session(conn, row["id"], "password", ip, user_agent, now_ms,
                                              max_s=session_max_s)
        throttle.clear(conn, ukey, ikey)
        audit.record(conn, "auth.login", "success", actor_admin_id=row["id"], actor_name=row["username"],
                     ip=ip, detail={"method": "password"}, ts_ms=now_ms)
    return LoginResult(True, token=token, session=info, admin_id=row["id"])


_dummy_cache: dict[int, str] = {}


def _dummy_hash(hasher: Hasher) -> str:
    key = id(hasher)
    if key not in _dummy_cache:
        _dummy_cache[key] = hasher.hash(_DUMMY_PASSWORD)
    return _dummy_cache[key]
