"""Server-side sessions (docs/SUBSYSTEMS.md section 7.2, decision D7).

The cookie carries 32 random bytes; the database stores only their SHA-256.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import sqlite3
import threading
from dataclasses import dataclass

TOUCH_INTERVAL_MS = 60_000
REVOKED_KEEP_MS = 7 * 24 * 3600 * 1000


def hash_token(token: str) -> bytes:
    return hashlib.sha256(_decode(token)).digest()


def _decode(token: str) -> bytes:
    pad = "=" * (-len(token) % 4)
    try:
        return base64.urlsafe_b64decode(token + pad)
    except (ValueError, TypeError):
        return token.encode("utf-8", "replace")  # still hashes to a value that matches nothing


def _new_token() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")


@dataclass(frozen=True)
class SessionInfo:
    id: int
    admin_id: int
    token_hash: bytes
    auth_method: str
    created_ms: int
    expires_ms: int


class ReauthTracker:
    """When each session last proved its password or passkey.

    Held in memory because the sessions table has no column for it (docs/API.md route class R).
    A restart forgets it, which only means admins are asked to re-authenticate sooner (fail safe).
    Falls back to the session's creation time.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._at: dict[int, int] = {}

    def mark(self, session_id: int, now_ms: int) -> None:
        with self._lock:
            self._at[session_id] = now_ms

    def forget(self, session_id: int) -> None:
        with self._lock:
            self._at.pop(session_id, None)

    def is_recent(self, info: SessionInfo, now_ms: int, window_s: int) -> bool:
        with self._lock:
            last = self._at.get(info.id, info.created_ms)
        return now_ms - last <= window_s * 1000


def create_session(conn: sqlite3.Connection, admin_id: int, auth_method: str, ip: str,
                   user_agent: str, now_ms: int, *, max_s: int = 43200) -> tuple[str, SessionInfo]:
    """Create a session; returns (cookie token, info). The token is never stored."""
    token = _new_token()
    token_hash = hash_token(token)
    expires = now_ms + max_s * 1000
    cur = conn.execute(
        "INSERT INTO sessions(token_hash, admin_id, auth_method, created_ms, last_seen_ms,"
        " expires_ms, ip, user_agent) VALUES (?,?,?,?,?,?,?,?)",
        (token_hash, admin_id, auth_method, now_ms, now_ms, expires, ip[:45], user_agent[:256]))
    return token, SessionInfo(cur.lastrowid, admin_id, token_hash, auth_method, now_ms, expires)


def validate_session(conn: sqlite3.Connection, token: str | None, now_ms: int, *,
                     idle_s: int = 1800) -> SessionInfo | None:
    """Return the session if the token is valid, unexpired, not idle, not revoked and the
    account is enabled; otherwise None. Extends last_seen at most once a minute."""
    if not token or len(token) > 128:
        return None
    row = conn.execute(
        "SELECT s.id, s.admin_id, s.token_hash, s.auth_method, s.created_ms, s.expires_ms,"
        " s.last_seen_ms, s.revoked_ms, a.is_disabled FROM sessions s"
        " JOIN admins a ON a.id = s.admin_id WHERE s.token_hash = ?", (hash_token(token),)).fetchone()
    if row is None or row["revoked_ms"] is not None or row["is_disabled"]:
        return None
    if now_ms >= row["expires_ms"] or now_ms - row["last_seen_ms"] > idle_s * 1000:
        return None
    if now_ms - row["last_seen_ms"] >= TOUCH_INTERVAL_MS:
        conn.execute("UPDATE sessions SET last_seen_ms = ? WHERE id = ?", (now_ms, row["id"]))
    return SessionInfo(row["id"], row["admin_id"], bytes(row["token_hash"]), row["auth_method"],
                       row["created_ms"], row["expires_ms"])


def revoke_session(conn: sqlite3.Connection, session_id: int, now_ms: int) -> None:
    conn.execute("UPDATE sessions SET revoked_ms = ? WHERE id = ? AND revoked_ms IS NULL",
                 (now_ms, session_id))


def list_for_admin(conn: sqlite3.Connection, admin_id: int, now_ms: int, *,
                   idle_s: int = 1800) -> list[sqlite3.Row]:
    """The admin's usable sessions (not revoked, expired or idle), newest activity first.
    Rows carry no token and no token hash."""
    return conn.execute(
        "SELECT id, auth_method, created_ms, last_seen_ms, expires_ms, ip, user_agent FROM sessions"
        " WHERE admin_id = ? AND revoked_ms IS NULL AND expires_ms > ? AND last_seen_ms >= ?"
        " ORDER BY last_seen_ms DESC, id DESC LIMIT 100",
        (admin_id, now_ms, now_ms - idle_s * 1000)).fetchall()


def revoke_own(conn: sqlite3.Connection, admin_id: int, session_id: int, now_ms: int) -> bool:
    """Revoke one session, but only if it belongs to `admin_id`. False if there was nothing to revoke."""
    cur = conn.execute("UPDATE sessions SET revoked_ms = ? WHERE id = ? AND admin_id = ?"
                       " AND revoked_ms IS NULL", (now_ms, session_id, admin_id))
    return cur.rowcount == 1


def revoke_all_for_admin(conn: sqlite3.Connection, admin_id: int, now_ms: int, *,
                         except_id: int | None = None) -> int:
    cur = conn.execute(
        "UPDATE sessions SET revoked_ms = ? WHERE admin_id = ? AND revoked_ms IS NULL"
        " AND (? IS NULL OR id <> ?)", (now_ms, admin_id, except_id, except_id))
    return cur.rowcount


def cleanup_sessions(conn: sqlite3.Connection, now_ms: int) -> int:
    """Delete expired sessions and revoked ones older than a week (hourly job)."""
    cur = conn.execute(
        "DELETE FROM sessions WHERE expires_ms < ? OR (revoked_ms IS NOT NULL AND revoked_ms < ?)",
        (now_ms, now_ms - REVOKED_KEEP_MS))
    return cur.rowcount
