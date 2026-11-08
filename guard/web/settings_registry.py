"""Settings registry and typed validation for the General Settings page (docs/SCHEMA.md section 6,
docs/API.md section 10.4).

Every key has a type, a default and bounds. A missing row in `settings` means "use the default".
Values are validated here and nowhere trusted: out-of-range numbers, wrong types and malformed JSON
are rejected with a message that is safe to show. The auth.* bounds are the same numbers that
guard/web/limits.py enforces when reading, so what the page accepts the reader also accepts.

Not editable here: retention.* and backup.* (they belong to the Backups and Retention page, whose
preview step protects against deleting data by accident). They are listed read-only.
No secret is ever a setting (decision D9).
"""

from __future__ import annotations

import json
import math
import re
import sqlite3
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .. import audit
from ..db import transaction
from . import limits

MAX_JSON_CHARS = 8000
_HOST = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")
_PARAM = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_VALUE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_POLICY_CATEGORIES = ("tor", "vpn_detected", "vpn_likely", "proxy", "relay")


class SettingError(Exception):
    """A rejected value; the message is safe to show to an admin."""


@dataclass(frozen=True)
class Setting:
    key: str
    group: str
    kind: str                      # bool int number str enum tz strlist json
    default: Any
    desc: str
    low: float | None = None
    high: float | None = None
    choices: tuple = ()
    item_check: Callable[[str], str] | None = None
    max_items: int = 20
    validator: Callable[[Any], None] | None = None
    editable: bool = True
    confirm: bool = False          # the admin must type "confirm" to change or reset it


# ---- item and structure checks ---------------------------------------------------------------

def _host(item: str) -> str:
    item = item.lower()
    if len(item) > 253 or not _HOST.match(item):
        raise SettingError(f"'{item[:60]}' is not a valid host name.")
    return item


def _path(item: str) -> str:
    if (not item.startswith("/") or len(item) > 200 or any(c in item for c in "?# \t\r\n\x00")
            or any(ord(c) < 32 for c in item)):
        raise SettingError(f"'{item[:60]}' must be a path starting with / (no spaces, ? or #).")
    return item


def _check_paths(value: Any) -> None:
    if not isinstance(value, list) or len(value) > 20:
        raise SettingError("Enter a list of at most 20 entries.")
    for entry in value:
        if not isinstance(entry, dict) or set(entry) != {"path", "param", "values"}:
            raise SettingError('Each entry needs exactly "path", "param" and "values".')
        _path(entry["path"]) if isinstance(entry["path"], str) else _bad("path must be text")
        if not isinstance(entry["param"], str) or not _PARAM.match(entry["param"]):
            raise SettingError('"param" must be 1 to 64 letters, digits, dash or underscore.')
        values = entry["values"]
        if (not isinstance(values, list) or not 1 <= len(values) <= 20
                or not all(isinstance(v, str) and _VALUE.match(v) for v in values)):
            raise SettingError('"values" must be 1 to 20 short words (letters, digits, dot, dash, underscore).')


def _bad(message: str):
    raise SettingError(message.capitalize() + ".")


def _check_policy(value: Any) -> None:
    expected = set(_POLICY_CATEGORIES) | {"min_confidence"}
    if not isinstance(value, dict) or set(value) != expected:
        raise SettingError("The policy needs exactly: " + ", ".join(sorted(expected)) +
                           ". Hosting and crawler can never block, so they are not listed.")
    for name in _POLICY_CATEGORIES:
        entry = value[name]
        if not isinstance(entry, dict) or set(entry) != {"block"} or not isinstance(entry["block"], bool):
            raise SettingError(f'"{name}" must look like {{"block": true}} or {{"block": false}}.')
    if value["min_confidence"] is not None:
        raise SettingError('"min_confidence" must stay null until the meaning of the IPLogs '
                           "confidence field has been verified.")


def _check_throttle(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != set(limits.THROTTLE_BOUNDS):
        raise SettingError("Needs exactly: " + ", ".join(limits.THROTTLE_BOUNDS) + ".")
    for name, (low, high) in limits.THROTTLE_BOUNDS.items():
        number = value[name]
        if isinstance(number, bool) or not isinstance(number, int) or not low <= number <= high:
            raise SettingError(f'"{name}" must be a whole number from {low} to {high}.')
    if value["lockout_max_s"] < value["lockout_s"]:
        raise SettingError('"lockout_max_s" must not be smaller than "lockout_s".')


def _int(key: str, group: str, default: int, desc: str, low: int, high: int, **kw) -> Setting:
    return Setting(key, group, "int", default, desc, low=low, high=high, **kw)


def _bool(key: str, group: str, default: bool, desc: str, **kw) -> Setting:
    return Setting(key, group, "bool", default, desc, **kw)


_B = limits.BOUNDS

REGISTRY: tuple[Setting, ...] = (
    Setting("site.hosts", "Site", "strlist", ["initstack.org", "www.initstack.org"],
            "Host names Guard manages. Requests for other hosts are recorded but never enforced.",
            item_check=_host, max_items=20),
    Setting("site.appeal_url", "Site", "str", "",
            "Where the block page tells a blocked visitor to appeal. Empty for none.", high=300),
    Setting("ui.default_timezone", "Site", "tz", "UTC", "Time zone shown to new administrators."),
    Setting("enforcement.mode", "Enforcement", "enum", "enforce",
            "monitor_only pauses every denial and only records what would have happened.",
            choices=("enforce", "monitor_only"), confirm=True),
    Setting("enforcement.paths", "Enforcement", "json",
            [{"path": "/member.php", "param": "action",
              "values": ["login", "do_login", "register", "do_register"]}],
            "Where reputation checks (VPN, proxy, Tor) apply. Widening this blocks ordinary browsing.",
            validator=_check_paths, confirm=True),
    _bool("enforcement.allow_site_wide_url_deny", "Enforcement", False,
          "Lets a URL rule deny the whole site. Leave off unless you mean it.", confirm=True),
    Setting("enforcement.protected_paths", "Enforcement", "strlist", ["/_guard/"],
            "Path prefixes no URL deny rule may cover. Add your MyBB admin directory.",
            item_check=_path, max_items=50, confirm=True),
    _bool("intel.iplogs.enabled", "IP intelligence", True, "Look up IP reputation with IPLogs."),
    _int("intel.iplogs.rate_per_minute", "IP intelligence", 30, "Most IPLogs lookups per minute.", 1, 600),
    _int("intel.ttl_ok_s", "IP intelligence", 86400, "Seconds a successful lookup is reused.", 300, 30 * 86400),
    _int("intel.ttl_error_s", "IP intelligence", 300, "Seconds before retrying a failed lookup.", 30, 86400),
    _int("intel.stale_grace_s", "IP intelligence", 604800,
         "Seconds an expired lookup may still be used when IPLogs is down.", 0, 30 * 86400),
    _bool("intel.tor.enabled", "IP intelligence", True, "Download the Tor exit-node list."),
    _int("intel.tor.interval_s", "IP intelligence", 10800, "Seconds between Tor list downloads.", 900, 7 * 86400),
    _int("intel.tor.min_entries", "IP intelligence", 500,
         "A downloaded Tor list with fewer entries is rejected.", 0, 100000),
    Setting("intel.tor.min_ratio", "IP intelligence", "number", 0.5,
            "A downloaded list smaller than this fraction of the last one is rejected.", low=0, high=1),
    Setting("intel.policy", "IP intelligence", "json",
            {"tor": {"block": True}, "vpn_detected": {"block": True}, "vpn_likely": {"block": False},
             "proxy": {"block": True}, "relay": {"block": False}, "min_confidence": None},
            "Which detections block at login and registration. Hosting alone never blocks.",
            validator=_check_policy),
    _bool("auth.password_login_enabled", "Sign-in", True,
          "Allow password sign-in. Can only be turned off when every enabled administrator has a passkey.",
          confirm=True),
    _int("auth.session_idle_s", "Sign-in", limits.DEFAULT_IDLE_S, "Seconds of inactivity before sign-out.",
         *_B["auth.session_idle_s"]),
    _int("auth.session_max_s", "Sign-in", limits.DEFAULT_MAX_S, "Longest a session can last, in seconds.",
         *_B["auth.session_max_s"]),
    _int("auth.reauth_window_s", "Sign-in", limits.DEFAULT_REAUTH_S,
         "How recently the password must be confirmed for sensitive changes, in seconds.",
         *_B["auth.reauth_window_s"]),
    _int("auth.password_min_length", "Sign-in", limits.DEFAULT_MIN_PASSWORD_LENGTH,
         "Shortest accepted new password (never below 12).", *_B["auth.password_min_length"]),
    Setting("auth.throttle", "Sign-in", "json",
            {"max_failures": 5, "window_s": 900, "lockout_s": 900, "lockout_max_s": 86400},
            "Failed sign-ins allowed, the counting window, and lockout lengths, in seconds.",
            validator=_check_throttle),
    _int("export.csv_max_rows", "Limits", 100000, "Most rows in one CSV export.", 1000, 1_000_000),
    _int("limits.url_rules_max", "Limits", 2000, "Most URL access rules.", 10, 10000),
    _bool("block_page.use_custom", "Limits", True, "Show the custom block page instead of the built-in one."),
    _bool("mybb.injections_enabled", "Limits", True, "Global switch: off stops every MyBB injection."),
    _int("retention.requests_days", "Retention (managed on the Backups and Retention page)", 90,
         "Days raw requests are kept.", 1, 3650, editable=False),
    _int("retention.rollups_days", "Retention (managed on the Backups and Retention page)", 730,
         "Days hourly totals are kept.", 7, 3650, editable=False),
    _int("retention.audit_days", "Retention (managed on the Backups and Retention page)", 365,
         "Days audit events are kept.", 30, 3650, editable=False),
    _int("retention.ingest_errors_max", "Retention (managed on the Backups and Retention page)", 1000,
         "Most ingest error notes kept.", 100, 100000, editable=False),
    _int("retention.rollup_min_hits", "Retention (managed on the Backups and Retention page)", 10,
         "Per-URL hourly totals are kept only for URLs with this many hits.", 1, 1000, editable=False),
    _int("retention.versions_keep", "Retention (managed on the Backups and Retention page)", 100,
         "Versions kept per injection and for the block page.", 5, 1000, editable=False),
    _int("backup.daily_keep", "Retention (managed on the Backups and Retention page)", 14,
         "Daily backups kept.", 1, 60, editable=False),
    _int("backup.weekly_keep", "Retention (managed on the Backups and Retention page)", 8,
         "Weekly backups kept.", 0, 52, editable=False),
)

BY_KEY: dict[str, Setting] = {s.key: s for s in REGISTRY}
assert len(BY_KEY) == len(REGISTRY), "duplicate settings key"


# ---- parsing ---------------------------------------------------------------------------------

def parse(setting: Setting, raw: str) -> Any:
    """Turn the text an admin typed into a validated value. Raises SettingError."""
    raw = raw if isinstance(raw, str) else ""
    if "\x00" in raw:
        raise SettingError("The value contains a NUL character.")
    kind = setting.kind
    if kind == "bool":
        if raw.strip() not in ("true", "false"):
            raise SettingError("Choose on or off.")
        return raw.strip() == "true"
    if kind in ("int", "number"):
        text = raw.strip()
        try:
            number = int(text) if kind == "int" else float(text)
        except ValueError:
            raise SettingError("Enter a number." if kind == "number" else "Enter a whole number.") from None
        if isinstance(number, float) and not math.isfinite(number):
            raise SettingError("Enter a number.")
        if not setting.low <= number <= setting.high:
            raise SettingError(f"Must be from {setting.low:g} to {setting.high:g}.")
        return number
    if kind == "str":
        text = raw.strip()
        if len(text) > (setting.high or 300):
            raise SettingError(f"Must be at most {int(setting.high or 300)} characters.")
        if any(ord(c) < 32 for c in text):
            raise SettingError("Must not contain control characters.")
        if setting.key == "site.appeal_url" and text:
            parts = urlsplit(text)
            if parts.scheme not in ("http", "https") or not parts.netloc:
                raise SettingError("Must be empty or a full http(s) address.")
        return text
    if kind == "enum":
        if raw.strip() not in setting.choices:
            raise SettingError("Choose one of: " + ", ".join(setting.choices) + ".")
        return raw.strip()
    if kind == "tz":
        name = raw.strip()
        try:
            if not name or len(name) > 64:
                raise ValueError
            ZoneInfo(name)
        except (ZoneInfoNotFoundError, ValueError, OSError):
            raise SettingError("Enter an IANA time zone name such as UTC or America/Indiana/Indianapolis.") from None
        return name
    if kind == "strlist":
        items = [line.strip() for line in raw.splitlines() if line.strip()]
        if not 1 <= len(items) <= setting.max_items:
            raise SettingError(f"Enter 1 to {setting.max_items} lines.")
        items = [setting.item_check(i) if setting.item_check else i for i in items]
        if len(set(items)) != len(items):
            raise SettingError("Each line must be different.")
        return items
    if kind == "json":
        if len(raw) > MAX_JSON_CHARS:
            raise SettingError("Too long.")
        try:
            value = json.loads(raw)
        except ValueError:
            raise SettingError("That is not valid JSON.") from None
        setting.validator(value)
        return value
    raise SettingError("Unsupported setting type.")  # pragma: no cover


def display(setting: Setting, value: Any) -> str:
    """The text shown in the form for a value."""
    if setting.kind == "bool":
        return "true" if value else "false"
    if setting.kind == "strlist":
        return "\n".join(value)
    if setting.kind == "json":
        return json.dumps(value, indent=2, sort_keys=True)
    return str(value)


# ---- reading and writing ---------------------------------------------------------------------

def stored(conn: sqlite3.Connection) -> dict[str, sqlite3.Row]:
    return {r["key"]: r for r in conn.execute("SELECT key, value, updated_ms FROM settings")}


def effective_value(setting: Setting, row: sqlite3.Row | None) -> Any:
    if row is None:
        return setting.default
    try:
        return json.loads(row["value"])
    except ValueError:
        return setting.default


def _check_password_login(conn: sqlite3.Connection, value: Any) -> None:
    if value is False:
        missing = conn.execute(
            "SELECT COUNT(*) FROM admins a WHERE a.is_disabled = 0 AND NOT EXISTS"
            " (SELECT 1 FROM passkeys p WHERE p.admin_id = a.id)").fetchone()[0]
        if missing:
            raise SettingError("Password sign-in can only be turned off when every enabled "
                               f"administrator has a passkey ({missing} still without one).")


def _check_confirm(setting: Setting, confirm: str) -> None:
    if setting.confirm and (confirm or "").strip().lower() != "confirm":
        raise SettingError('Type "confirm" in the confirmation box to change this setting.')


def set_value(conn: sqlite3.Connection, key: str, raw: str, *, confirm: str, admin_id: int,
              admin_name: str, ip: str, now_ms: int) -> Any:
    setting = BY_KEY.get(key)
    if setting is None:
        raise SettingError("Unknown setting.")
    if not setting.editable:
        raise SettingError("This setting is managed on the Backups and Retention page.")
    value = parse(setting, raw)
    _check_confirm(setting, confirm)
    if key == "auth.password_login_enabled":
        _check_password_login(conn, value)
    with transaction(conn):
        row = conn.execute("SELECT key, value, updated_ms FROM settings WHERE key = ?", (key,)).fetchone()
        old = effective_value(setting, row)
        conn.execute(
            "INSERT INTO settings(key, value, updated_ms, updated_by) VALUES (?,?,?,?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_ms = excluded.updated_ms,"
            " updated_by = excluded.updated_by",
            (key, json.dumps(value, separators=(",", ":"), sort_keys=True), now_ms, admin_id))
        audit.record(conn, "settings.update", "success", actor_admin_id=admin_id, actor_name=admin_name,
                     ip=ip, target_type="setting", target_id=key, detail={"old": old, "new": value},
                     ts_ms=now_ms)
    return value


def reset_value(conn: sqlite3.Connection, key: str, *, confirm: str, admin_id: int, admin_name: str,
                ip: str, now_ms: int) -> bool:
    setting = BY_KEY.get(key)
    if setting is None:
        raise SettingError("Unknown setting.")
    if not setting.editable:
        raise SettingError("This setting is managed on the Backups and Retention page.")
    _check_confirm(setting, confirm)
    if key == "auth.password_login_enabled":
        _check_password_login(conn, setting.default)
    with transaction(conn):
        row = conn.execute("SELECT key, value, updated_ms FROM settings WHERE key = ?", (key,)).fetchone()
        if row is None:
            return False
        conn.execute("DELETE FROM settings WHERE key = ?", (key,))
        audit.record(conn, "settings.reset", "success", actor_admin_id=admin_id, actor_name=admin_name,
                     ip=ip, target_type="setting", target_id=key,
                     detail={"old": effective_value(setting, row), "new": setting.default}, ts_ms=now_ms)
    return True
