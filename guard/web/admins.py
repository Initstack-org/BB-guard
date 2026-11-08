"""Administrators page data and actions (docs/API.md section 10.1).

Admins are disabled, never deleted. Disabling revokes all of that admin's sessions. The signed-in
admin cannot disable themselves, and the last enabled admin can never be disabled, so the dashboard
cannot be locked out from here. Creating an admin and setting a password reuse guard.auth.service.
"""

from __future__ import annotations

import sqlite3

from .. import audit
from ..auth import sessions
from ..db import transaction


class AdminActionError(Exception):
    """A rejected action; the message is safe to show and `status` is the HTTP status to use."""

    def __init__(self, message: str, status: int = 409):
        super().__init__(message)
        self.status = status


def list_admins(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT a.id, a.username, a.display_name, a.is_disabled, a.last_login_ms, a.created_ms,"
        " c.username AS created_by_name,"
        " (SELECT COUNT(*) FROM passkeys p WHERE p.admin_id = a.id) AS passkey_count"
        " FROM admins a LEFT JOIN admins c ON c.id = a.created_by"
        " ORDER BY a.username COLLATE NOCASE").fetchall()


def _target(conn: sqlite3.Connection, admin_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT id, username, is_disabled FROM admins WHERE id = ?",
                       (admin_id,)).fetchone()
    if row is None:
        raise AdminActionError("No such administrator.", 404)
    return row


def disable(conn: sqlite3.Connection, target_id: int, *, actor_id: int, actor_name: str, ip: str,
            now_ms: int) -> None:
    with transaction(conn):
        row = _target(conn, target_id)
        if row["id"] == actor_id:
            raise AdminActionError("You cannot disable your own account.")
        if row["is_disabled"]:
            raise AdminActionError("That account is already disabled.")
        enabled = conn.execute("SELECT COUNT(*) FROM admins WHERE is_disabled = 0").fetchone()[0]
        if enabled <= 1:
            raise AdminActionError("The last enabled administrator cannot be disabled.")
        conn.execute("UPDATE admins SET is_disabled = 1, disabled_ms = ? WHERE id = ?",
                     (now_ms, row["id"]))
        revoked = sessions.revoke_all_for_admin(conn, row["id"], now_ms)
        audit.record(conn, "admin.disable", "success", actor_admin_id=actor_id, actor_name=actor_name,
                     ip=ip, target_type="admin", target_id=str(row["id"]),
                     detail={"username": row["username"], "sessions_revoked": revoked}, ts_ms=now_ms)


def enable(conn: sqlite3.Connection, target_id: int, *, actor_id: int, actor_name: str, ip: str,
           now_ms: int) -> None:
    with transaction(conn):
        row = _target(conn, target_id)
        if not row["is_disabled"]:
            raise AdminActionError("That account is already enabled.")
        conn.execute("UPDATE admins SET is_disabled = 0, disabled_ms = NULL WHERE id = ?", (row["id"],))
        audit.record(conn, "admin.enable", "success", actor_admin_id=actor_id, actor_name=actor_name,
                     ip=ip, target_type="admin", target_id=str(row["id"]),
                     detail={"username": row["username"]}, ts_ms=now_ms)
