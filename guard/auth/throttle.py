"""Persistent sign-in throttle (docs/SUBSYSTEMS.md section 7.2, SCHEMA.md auth_throttle).

Defaults: 5 failures in 15 minutes lock for 15 minutes; every further failure doubles the lock
(5th: 900 s, 6th: 1800 s, 7th: 3600 s ...) up to 24 hours. The counter resets after a quiet
window. Attempts made while locked are rejected without being counted, so an attacker cannot
extend a lock indefinitely by hammering it.

Known trade-off: the per-username key means anyone who knows an admin username can lock that
username out of password sign-in for up to 24 hours. Passkey sign-in is throttled by IP only,
and the CLI can always reset things (docs/ARCHITECTURE.md limitations).
"""

from __future__ import annotations

import hashlib
import ipaddress
import sqlite3
from dataclasses import dataclass


@dataclass(frozen=True)
class ThrottlePolicy:
    max_failures: int = 5
    window_s: int = 900
    lockout_s: int = 900
    lockout_max_s: int = 86400


def ip_key(ip: str) -> str:
    try:
        ip = ipaddress.ip_address(ip).compressed
    except ValueError:
        ip = "invalid"
    return f"ip:{ip}"


def user_key(username: str) -> str:
    digest = hashlib.sha256(username.strip().lower().encode("utf-8")).hexdigest()
    return f"user:{digest[:32]}"


def check(conn: sqlite3.Connection, key: str, now_ms: int) -> int:
    """Seconds until the key may try again, or 0 if it is not locked."""
    row = conn.execute("SELECT locked_until_ms FROM auth_throttle WHERE key = ?", (key,)).fetchone()
    if row is None or row["locked_until_ms"] <= now_ms:
        return 0
    return max(1, -(-(row["locked_until_ms"] - now_ms) // 1000))


def record_failure(conn: sqlite3.Connection, key: str, now_ms: int,
                   policy: ThrottlePolicy = ThrottlePolicy()) -> int:
    """Count one failure; returns seconds locked for (0 if not locked)."""
    row = conn.execute("SELECT failures, first_failure_ms, last_failure_ms, locked_until_ms"
                       " FROM auth_throttle WHERE key = ?", (key,)).fetchone()
    window_ms = policy.window_s * 1000
    if row is None:
        failures, first = 1, now_ms
    else:
        failures, first = row["failures"], row["first_failure_ms"]
        escalated = failures >= policy.max_failures
        if escalated:
            # Quiet means a full window with no failures *after the lock ended*; measuring from
            # the last failure alone would reset the escalation as soon as a lock expired.
            quiet = now_ms - max(row["last_failure_ms"], row["locked_until_ms"]) > window_ms
            if quiet:
                failures, first = 0, now_ms
        elif now_ms - first > window_ms:
            failures, first = 0, now_ms
        failures += 1
    locked_for = 0
    if failures >= policy.max_failures:
        locked_for = min(policy.lockout_s * (2 ** (failures - policy.max_failures)),
                         policy.lockout_max_s)
    locked_until = now_ms + locked_for * 1000 if locked_for else 0
    conn.execute(
        "INSERT INTO auth_throttle(key, failures, first_failure_ms, last_failure_ms, locked_until_ms)"
        " VALUES (?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET failures=excluded.failures,"
        " first_failure_ms=excluded.first_failure_ms, last_failure_ms=excluded.last_failure_ms,"
        " locked_until_ms=excluded.locked_until_ms",
        (key, failures, first, now_ms, locked_until))
    return locked_for


def clear(conn: sqlite3.Connection, *keys: str) -> None:
    for key in keys:
        conn.execute("DELETE FROM auth_throttle WHERE key = ?", (key,))


def cleanup(conn: sqlite3.Connection, now_ms: int, policy: ThrottlePolicy = ThrottlePolicy()) -> int:
    """Delete rows with no failure and no lock for longer than the window (hourly job)."""
    cur = conn.execute(
        "DELETE FROM auth_throttle WHERE max(last_failure_ms, locked_until_ms) < ?",
        (now_ms - policy.window_s * 1000,))
    return cur.rowcount
