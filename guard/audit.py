"""Append-only audit log writer (docs/SUBSYSTEMS.md section 7.4, SCHEMA.md audit_events)."""

from __future__ import annotations

import json
import sqlite3

from .db import now_ms

# Defence in depth for rule 1/12: audit details must never carry secrets. Any detail
# key containing one of these fragments is rejected loudly rather than stored.
_FORBIDDEN_KEY_FRAGMENTS = ("password", "passwd", "secret", "token", "cookie", "authorization",
                            "challenge", "private", "api_key", "apikey", "signature", "credential_id")


class AuditError(ValueError):
    pass


def _check_detail(obj, path="detail") -> None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            lowered = str(key).lower()
            if any(frag in lowered for frag in _FORBIDDEN_KEY_FRAGMENTS):
                raise AuditError(f"audit {path}.{key}: key name looks like a secret")
            _check_detail(value, f"{path}.{key}")
    elif isinstance(obj, (list, tuple)):
        for i, item in enumerate(obj):
            _check_detail(item, f"{path}[{i}]")
    elif not isinstance(obj, (str, int, float, bool, type(None))):
        raise AuditError(f"audit {path}: unsupported value type {type(obj).__name__}")


def record(conn: sqlite3.Connection, action: str, outcome: str, *,
           actor_admin_id: int | None = None, actor_name: str = "", ip: str = "",
           target_type: str = "", target_id: str = "", detail: dict | None = None,
           ts_ms: int | None = None) -> int:
    """Insert one audit event and return its id. Long text is truncated to the column limits."""
    detail_json = None
    if detail is not None:
        _check_detail(detail)
        detail_json = json.dumps(detail, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
        if len(detail_json) > 4096:
            detail_json = json.dumps({"truncated": True}, separators=(",", ":"))
    cur = conn.execute(
        "INSERT INTO audit_events(ts_ms, actor_admin_id, actor_name, ip, action, outcome,"
        " target_type, target_id, detail) VALUES (?,?,?,?,?,?,?,?,?)",
        (ts_ms if ts_ms is not None else now_ms(), actor_admin_id, actor_name[:64], ip[:45],
         action[:64], outcome, target_type[:32], str(target_id)[:128], detail_json))
    return cur.lastrowid
