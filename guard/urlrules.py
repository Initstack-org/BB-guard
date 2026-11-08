"""URL access rules in the database (docs/SUBSYSTEMS.md section 4): add, edit, enable, delete, load,
sweep and the test/preview that explains which rule wins. All SQL is parameterized.
"""

from __future__ import annotations

import json
import sqlite3

from . import audit, settings_read, urlmatch
from .db import transaction
from .urlmatch import RuleError

DESC_MAX = 300
NOTES_MAX = 2000


def _row_to_rule(row: sqlite3.Row) -> urlmatch.Rule:
    query = tuple(sorted(json.loads(row["query_match"]).items())) if row["query_match"] else ()
    return urlmatch.Rule(id=row["id"], pattern=row["pattern"], match_type=row["match_type"],
                         action=row["action"], scope_ip=row["scope_ip"], priority=row["priority"],
                         query_match=query, enabled=bool(row["enabled"]), expires_ms=row["expires_ms"])


def load_rules(conn: sqlite3.Connection) -> list[urlmatch.Rule]:
    return [_row_to_rule(r) for r in conn.execute("SELECT * FROM url_rules")]


def _text(value: str, limit: int, label: str) -> str:
    value = (value or "").strip()
    if len(value) > limit:
        raise RuleError(f"{label} must be at most {limit} characters.")
    if any(ord(c) < 32 and c not in "\n\t" for c in value):
        raise RuleError(f"{label} must not contain control characters.")
    return value


def _priority(value) -> int:
    try:
        number = int(str(value).strip())
    except ValueError:
        raise RuleError("Priority must be a whole number from 0 to 1000000.") from None
    if not 0 <= number <= 1_000_000:
        raise RuleError("Priority must be a whole number from 0 to 1000000.")
    return number


def add_rule(conn: sqlite3.Connection, target: str, match_type: str, action: str, *, scope_ip: str = "",
             priority="100", enabled: bool = True, expires_ms: int | None = None, description: str = "",
             notes: str = "", admin_id: int, admin_name: str, ip: str, now_ms: int) -> int:
    """Validate and insert one rule. Returns its id. Raises RuleError with a safe message."""
    if match_type not in ("exact", "prefix"):
        raise RuleError("Choose exact or prefix.")
    if action not in ("allow", "deny"):
        raise RuleError("Choose allow or deny.")
    hosts = settings_read.get(conn, "site.hosts")
    pattern, query = urlmatch.parse_target(target, hosts)
    scope = urlmatch.parse_scope_ip(scope_ip)
    urlmatch.check_safety(pattern, match_type, action,
                          protected=settings_read.get(conn, "enforcement.protected_paths"),
                          allow_site_wide=settings_read.get(conn, "enforcement.allow_site_wide_url_deny"))
    description = _text(description, DESC_MAX, "The description")
    notes = _text(notes, NOTES_MAX, "The notes")
    prio = _priority(priority)
    if expires_ms is not None and expires_ms <= now_ms:
        raise RuleError("The expiry must be in the future.")
    query_json = json.dumps(query, sort_keys=True, separators=(",", ":")) if query else None
    with transaction(conn):
        if conn.execute("SELECT COUNT(*) FROM url_rules").fetchone()[0] >= settings_read.get(conn, "limits.url_rules_max"):
            raise RuleError("The maximum number of URL rules has been reached.")
        try:
            cur = conn.execute(
                "INSERT INTO url_rules(pattern, match_type, query_match, action, scope_ip, priority, enabled,"
                " expires_ms, description, notes, created_ms, created_by, updated_ms, updated_by)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (pattern, match_type, query_json, action, scope, prio, int(enabled), expires_ms, description,
                 notes, now_ms, admin_id, now_ms, admin_id))
        except sqlite3.IntegrityError:
            raise RuleError("An identical rule already exists.") from None
        rule_id = cur.lastrowid
        audit.record(conn, "url_rule.add", "success", actor_admin_id=admin_id, actor_name=admin_name, ip=ip,
                     target_type="url_rule", target_id=str(rule_id), ts_ms=now_ms,
                     detail={"pattern": pattern, "match": match_type, "action": action, "scope": scope,
                             "query": query, "priority": prio, "expires_ms": expires_ms})
    return rule_id


def update_rule(conn: sqlite3.Connection, rule_id: int, *, priority, expires_ms: int | None,
                description: str, notes: str, admin_id: int, admin_name: str, ip: str, now_ms: int) -> None:
    """Edit the fields that cannot change what the rule matches (priority, expiry, text)."""
    prio = _priority(priority)
    description = _text(description, DESC_MAX, "The description")
    notes = _text(notes, NOTES_MAX, "The notes")
    if expires_ms is not None and expires_ms <= now_ms:
        raise RuleError("The expiry must be in the future.")
    with transaction(conn):
        if conn.execute("SELECT 1 FROM url_rules WHERE id = ?", (rule_id,)).fetchone() is None:
            raise RuleError("No such rule.")
        conn.execute("UPDATE url_rules SET priority = ?, expires_ms = ?, description = ?, notes = ?,"
                     " updated_ms = ?, updated_by = ? WHERE id = ?",
                     (prio, expires_ms, description, notes, now_ms, admin_id, rule_id))
        audit.record(conn, "url_rule.update", "success", actor_admin_id=admin_id, actor_name=admin_name, ip=ip,
                     target_type="url_rule", target_id=str(rule_id), ts_ms=now_ms,
                     detail={"priority": prio, "expires_ms": expires_ms})


def set_enabled(conn: sqlite3.Connection, rule_id: int, enabled: bool, *, admin_id: int, admin_name: str,
                ip: str, now_ms: int) -> None:
    with transaction(conn):
        row = conn.execute("SELECT pattern, match_type, action FROM url_rules WHERE id = ?",
                           (rule_id,)).fetchone()
        if row is None:
            raise RuleError("No such rule.")
        if enabled and row["action"] == "deny":
            # Re-check: settings may have changed since the rule was written.
            urlmatch.check_safety(row["pattern"], row["match_type"], "deny",
                                  protected=settings_read.get(conn, "enforcement.protected_paths"),
                                  allow_site_wide=settings_read.get(conn, "enforcement.allow_site_wide_url_deny"))
        conn.execute("UPDATE url_rules SET enabled = ?, updated_ms = ?, updated_by = ? WHERE id = ?",
                     (int(enabled), now_ms, admin_id, rule_id))
        audit.record(conn, "url_rule.enable" if enabled else "url_rule.disable", "success",
                     actor_admin_id=admin_id, actor_name=admin_name, ip=ip, target_type="url_rule",
                     target_id=str(rule_id), ts_ms=now_ms, detail={"pattern": row["pattern"]})


def delete_rule(conn: sqlite3.Connection, rule_id: int, *, admin_id: int, admin_name: str, ip: str,
                now_ms: int) -> None:
    with transaction(conn):
        row = conn.execute("SELECT pattern, match_type, action FROM url_rules WHERE id = ?",
                           (rule_id,)).fetchone()
        if row is None:
            raise RuleError("No such rule.")
        conn.execute("DELETE FROM url_rules WHERE id = ?", (rule_id,))
        audit.record(conn, "url_rule.delete", "success", actor_admin_id=admin_id, actor_name=admin_name, ip=ip,
                     target_type="url_rule", target_id=str(rule_id), ts_ms=now_ms,
                     detail={"pattern": row["pattern"], "match": row["match_type"], "action": row["action"]})


def sweep_expired(conn: sqlite3.Connection, now_ms: int) -> int:
    """Remove rules past their expiry, auditing each. Returns how many were removed."""
    with transaction(conn):
        rows = conn.execute("SELECT id, pattern FROM url_rules WHERE expires_ms IS NOT NULL AND expires_ms <= ?",
                            (now_ms,)).fetchall()
        for row in rows:
            conn.execute("DELETE FROM url_rules WHERE id = ?", (row["id"],))
            audit.record(conn, "url_rule.expire", "success", actor_name="system", target_type="url_rule",
                         target_id=str(row["id"]), ts_ms=now_ms, detail={"pattern": row["pattern"]})
    return len(rows)


def list_rows(conn: sqlite3.Connection, limit: int = 2000) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM url_rules ORDER BY id DESC LIMIT ?", (limit,)).fetchall()


def preview(conn: sqlite3.Connection, test_url: str, test_ip: str, now_ms: int) -> dict:
    """The test/preview: every rule, what happened to it for this URL and address, and the winner.
    Writes nothing. Uses the same `urlmatch.evaluate` as enforcement, so the two cannot diverge."""
    hosts = settings_read.get(conn, "site.hosts")
    text = (test_url or "").strip()
    if "://" in text.split("?", 1)[0]:
        pattern, _ = urlmatch.parse_target(text.split("?", 1)[0], hosts)  # validates the host
        raw_path, _, raw_query = text.split("#", 1)[0].partition("?")
        raw_path = "/" + raw_path.split("://", 1)[1].partition("/")[2]
    else:
        if not text.startswith("/") or text.startswith("//"):
            raise RuleError("Enter a path starting with / or a full URL on a managed host.")
        raw_path, _, raw_query = text.split("#", 1)[0].partition("?")
    path, query = urlmatch.request_parts(raw_path, raw_query)
    address = urlmatch.parse_scope_ip(test_ip) or ""
    verdicts = urlmatch.evaluate(load_rules(conn), address, path, query, now_ms)
    won = next((v.rule for v in verdicts if v.status == "winner"), None)
    return {"path": path, "ip": address, "verdicts": verdicts, "winner": won,
            "decision": won.action if won else "allow (no rule matches)"}
