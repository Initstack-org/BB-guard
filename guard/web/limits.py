"""Sign-in and session limits read from the settings table (docs/SCHEMA.md section 6).

The defaults are the proposals in docs/SUBSYSTEMS.md section 7. A stored value that is missing,
is not valid JSON, has the wrong type or falls outside the allowed range is ignored and the
default is used, so a bad settings row can never switch a protection off or lock everyone out.
The bounds are deliberately tight: they are the safe range, not a hard security ceiling, and the
settings page (Stage 8) will validate against the same numbers.

Read once per request; the table is tiny and SQLite keeps it in cache.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from ..auth.throttle import ThrottlePolicy

DEFAULT_IDLE_S = 1800
DEFAULT_MAX_S = 43200
DEFAULT_REAUTH_S = 300
DEFAULT_MIN_PASSWORD_LENGTH = 12

KEYS = ("auth.session_idle_s", "auth.session_max_s", "auth.reauth_window_s",
        "auth.password_min_length", "auth.throttle")

# (lowest, highest) accepted value for each integer setting.
BOUNDS = {
    "auth.session_idle_s": (60, 7 * 86400),
    "auth.session_max_s": (300, 30 * 86400),
    "auth.reauth_window_s": (30, 3600),
    "auth.password_min_length": (12, 256),  # never below the default of 12
}
THROTTLE_BOUNDS = {
    "max_failures": (3, 20),
    "window_s": (60, 86400),
    "lockout_s": (60, 86400),
    "lockout_max_s": (60, 30 * 86400),
}


@dataclass(frozen=True)
class Limits:
    idle_s: int = DEFAULT_IDLE_S
    max_s: int = DEFAULT_MAX_S
    reauth_s: int = DEFAULT_REAUTH_S
    min_password_length: int = DEFAULT_MIN_PASSWORD_LENGTH
    throttle: ThrottlePolicy = ThrottlePolicy()


def _int_in_range(value, bounds: tuple[int, int]) -> int | None:
    # bool is a subclass of int; true/false must not count as 1/0.
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    low, high = bounds
    return value if low <= value <= high else None


def _throttle(value) -> ThrottlePolicy:
    if not isinstance(value, dict):
        return ThrottlePolicy()
    parsed = {}
    for name, bounds in THROTTLE_BOUNDS.items():
        number = _int_in_range(value.get(name), bounds)
        if number is None:
            return ThrottlePolicy()
        parsed[name] = number
    if parsed["lockout_max_s"] < parsed["lockout_s"]:
        return ThrottlePolicy()
    return ThrottlePolicy(**parsed)


def load(conn: sqlite3.Connection) -> Limits:
    raw: dict[str, object] = {}
    marks = ",".join("?" for _ in KEYS)
    for row in conn.execute(f"SELECT key, value FROM settings WHERE key IN ({marks})", KEYS):
        try:
            raw[row["key"]] = json.loads(row["value"])
        except ValueError:
            continue

    def pick(key: str, default: int) -> int:
        found = _int_in_range(raw.get(key), BOUNDS[key])
        return default if found is None else found

    return Limits(
        idle_s=pick("auth.session_idle_s", DEFAULT_IDLE_S),
        max_s=pick("auth.session_max_s", DEFAULT_MAX_S),
        reauth_s=pick("auth.reauth_window_s", DEFAULT_REAUTH_S),
        min_password_length=pick("auth.password_min_length", DEFAULT_MIN_PASSWORD_LENGTH),
        throttle=_throttle(raw.get("auth.throttle")))
