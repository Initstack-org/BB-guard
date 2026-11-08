"""Manual IP rules (docs/SUBSYSTEMS.md section 3.5).

Four modes, one row per address: `none` (IPLogs only: the row is deleted), `allow`, `block`, `monitor`.
Every change records who, when and why. A note is mandatory for allow and block. Expiry is optional;
`sweep_expired` removes finished rules and writes an audit event for each.
"""

from __future__ import annotations

import sqlite3

from .. import audit
from ..db import transaction
from ..ingest.normalize import canonical_ip

MODES = ("none", "allow", "block", "monitor")
NOTE_MAX = 500
MAX_RULES = 5000


class RuleError(ValueError):
    """A rejected change; the message is safe to show to an admin."""


def parse_ip(text: str) -> str:
    try:
        return canonical_ip((text or "")[:64])
    except ValueError:
        raise RuleError("That is not a valid IP address.") from None


def active_rule(conn: sqlite3.Connection, ip: str, now_ms: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM ip_rules WHERE ip = ? AND (expires_ms IS NULL OR expires_ms > ?)",
        (ip, now_ms)).fetchone()


def set_rule(conn: sqlite3.Connection, ip_text: str, mode: str, note: str, expires_ms: int | None, *,
             admin_id: int, admin_name: str, ip: str, now_ms: int) -> str:
    """Apply a mode to an address. Returns "set" or "cleared". Raises RuleError."""
    if mode not in MODES:
        raise RuleError("Choose a mode.")
    target = parse_ip(ip_text)
    if mode == "none":
        clear_rule(conn, target, admin_id=admin_id, admin_name=admin_name, ip=ip, now_ms=now_ms)
        return "cleared"
    note = (note or "").strip()
    if any(ord(c) < 32 for c in note):
        raise RuleError("The note must not contain control characters.")
    if len(note) > NOTE_MAX:
        raise RuleError(f"The note must be at most {NOTE_MAX} characters.")
    if mode in ("allow", "block") and not note:
        raise RuleError("A note saying why is required for allow and block.")
    if expires_ms is not None and expires_ms <= now_ms:
        raise RuleError("The expiry must be in the future.")
    with transaction(conn):
        old = conn.execute("SELECT mode FROM ip_rules WHERE ip = ?", (target,)).fetchone()
        if old is None:
            if conn.execute("SELECT COUNT(*) FROM ip_rules").fetchone()[0] >= MAX_RULES:
                raise RuleError(f"There are already {MAX_RULES} IP rules.")
            conn.execute(
                "INSERT INTO ip_rules(ip, mode, note, expires_ms, created_ms, created_by, updated_ms,"
                " updated_by) VALUES (?,?,?,?,?,?,?,?)",
                (target, mode, note, expires_ms, now_ms, admin_id, now_ms, admin_id))
        else:
            conn.execute(
                "UPDATE ip_rules SET mode = ?, note = ?, expires_ms = ?, updated_ms = ?, updated_by = ?"
                " WHERE ip = ?", (mode, note, expires_ms, now_ms, admin_id, target))
        audit.record(conn, "ip_rule.set", "success", actor_admin_id=admin_id, actor_name=admin_name,
                     ip=ip, target_type="ip", target_id=target, ts_ms=now_ms,
                     detail={"mode": mode, "previous": old["mode"] if old else "none",
                             "expires_ms": expires_ms, "note": note})
    return "set"


def clear_rule(conn: sqlite3.Connection, target: str, *, admin_id: int, admin_name: str, ip: str,
               now_ms: int) -> bool:
    with transaction(conn):
        old = conn.execute("SELECT mode FROM ip_rules WHERE ip = ?", (target,)).fetchone()
        if old is None:
            return False
        conn.execute("DELETE FROM ip_rules WHERE ip = ?", (target,))
        audit.record(conn, "ip_rule.clear", "success", actor_admin_id=admin_id, actor_name=admin_name,
                     ip=ip, target_type="ip", target_id=target, ts_ms=now_ms,
                     detail={"previous": old["mode"]})
    return True


def sweep_expired(conn: sqlite3.Connection, now_ms: int) -> int:
    """Delete rules whose expiry has passed, auditing each. Returns how many were removed."""
    with transaction(conn):
        rows = conn.execute("SELECT ip, mode FROM ip_rules WHERE expires_ms IS NOT NULL AND expires_ms <= ?",
                            (now_ms,)).fetchall()
        for row in rows:
            conn.execute("DELETE FROM ip_rules WHERE ip = ?", (row["ip"],))
            audit.record(conn, "ip_rule.expire", "success", actor_name="system", target_type="ip",
                         target_id=row["ip"], ts_ms=now_ms, detail={"previous": row["mode"]})
    return len(rows)


def list_rules(conn: sqlite3.Connection, now_ms: int, limit: int = 500) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT r.*, a.username AS created_by_name FROM ip_rules r LEFT JOIN admins a ON a.id = r.created_by"
        " ORDER BY r.updated_ms DESC LIMIT ?", (limit,)).fetchall()
