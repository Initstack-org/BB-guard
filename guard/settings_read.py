"""Read one setting from the database with its registry default (shared by the non-web modules).

A missing row, malformed JSON or a value that no longer passes its type check yields the default, so
a damaged settings table can never make enforcement stricter or crash a lookup.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from .web import settings_registry


def get(conn: sqlite3.Connection, key: str) -> Any:
    setting = settings_registry.BY_KEY[key]  # KeyError on a typo is deliberate: it is a code bug
    row = conn.execute("SELECT key, value, updated_ms FROM settings WHERE key = ?", (key,)).fetchone()
    value = settings_registry.effective_value(setting, row)
    kind = setting.kind
    if kind == "bool" and not isinstance(value, bool):
        return setting.default
    if kind == "int" and (isinstance(value, bool) or not isinstance(value, int)):
        return setting.default
    if kind == "number" and (isinstance(value, bool) or not isinstance(value, (int, float))):
        return setting.default
    if kind in ("str", "enum", "tz") and not isinstance(value, str):
        return setting.default
    if kind == "strlist" and not (isinstance(value, list) and all(isinstance(v, str) for v in value)):
        return setting.default
    if kind == "json" and not isinstance(value, (dict, list)):
        return setting.default
    return value
