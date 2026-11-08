"""Audit Log page queries (docs/API.md section 10.2, GOAL.md section 1.A).

Pure functions: filter parsing and one parameterized keyset query, so they can be tested without
the web stack. Nothing here writes. Paging uses a (ts_ms, id) keyset cursor, newest first, as
API.md section 1 requires for audit_events (offset paging would slow down as the table grows).

Filter values are never put into SQL text; only fixed column names are. The action filter is an
exact match, or a prefix when the value ends with "." (for example "auth." for every sign-in event).
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DEFAULT_SIZE = 50
MAX_SIZE = 200
OUTCOMES = ("success", "failure", "denied")
DETAIL_PREVIEW_CHARS = 300

_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CURSOR = re.compile(r"^(\d{1,16})\.(\d{1,16})$")


class FilterError(ValueError):
    """A filter value the page cannot use; the message is safe to show to the admin."""


@dataclass(frozen=True)
class Filters:
    actor: str = ""
    action: str = ""
    outcome: str = ""
    target_type: str = ""
    target_id: str = ""
    from_ms: int | None = None      # inclusive
    to_ms: int | None = None        # exclusive
    from_date: str = ""             # as typed, to refill the form
    to_date: str = ""
    size: int = DEFAULT_SIZE
    cursor: tuple[int, int] | None = None


def _tz(name: str):
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        return timezone.utc


def _day_start_ms(day: str, tz) -> int:
    try:
        parsed = datetime.strptime(day, "%Y-%m-%d")
    except ValueError as exc:
        raise FilterError("Dates must be real calendar dates in the form YYYY-MM-DD.") from exc
    return int(parsed.replace(tzinfo=tz).timestamp() * 1000)


def parse_filters(params, tz_name: str = "UTC") -> Filters:
    """Build Filters from a mapping of query parameters (first value of each). Raises FilterError."""
    def text(name: str, limit: int) -> str:
        value = (params.get(name) or "").strip()
        if len(value) > limit:
            raise FilterError(f"The {name.replace('_', ' ')} filter is too long.")
        if any(ord(c) < 32 for c in value):
            raise FilterError(f"The {name.replace('_', ' ')} filter contains control characters.")
        return value

    tz = _tz(tz_name)
    outcome = text("outcome", 16)
    if outcome and outcome not in OUTCOMES:
        raise FilterError("Outcome must be success, failure or denied.")

    from_date, to_date = text("from", 10), text("to", 10)
    from_ms = to_ms = None
    if from_date:
        if not _DATE.match(from_date):
            raise FilterError("Dates must be real calendar dates in the form YYYY-MM-DD.")
        from_ms = _day_start_ms(from_date, tz)
    if to_date:
        if not _DATE.match(to_date):
            raise FilterError("Dates must be real calendar dates in the form YYYY-MM-DD.")
        # "to" names a day and includes all of it, so the bound is the start of the next day.
        to_ms = _day_start_ms((datetime.strptime(to_date, "%Y-%m-%d") + timedelta(days=1))
                              .strftime("%Y-%m-%d"), tz)
    if from_ms is not None and to_ms is not None and from_ms >= to_ms:
        raise FilterError("The start date must not be after the end date.")

    size = DEFAULT_SIZE
    raw_size = (params.get("size") or "").strip()
    if raw_size:
        if not raw_size.isdigit() or not 1 <= int(raw_size) <= MAX_SIZE:
            raise FilterError(f"Page size must be a number from 1 to {MAX_SIZE}.")
        size = int(raw_size)

    cursor = None
    raw_cursor = (params.get("before") or "").strip()
    if raw_cursor:
        match = _CURSOR.match(raw_cursor)
        if not match:
            raise FilterError("That page link is not valid.")
        cursor = (int(match.group(1)), int(match.group(2)))

    return Filters(actor=text("actor", 64), action=text("action", 64), outcome=outcome,
                   target_type=text("target_type", 32), target_id=text("target_id", 128),
                   from_ms=from_ms, to_ms=to_ms, from_date=from_date, to_date=to_date,
                   size=size, cursor=cursor)


def _prefix_upper_bound(prefix: str) -> str:
    return prefix[:-1] + chr(ord(prefix[-1]) + 1)


def query(conn: sqlite3.Connection, f: Filters) -> tuple[list[sqlite3.Row], str | None]:
    """Return (rows, next_cursor) for the filters, newest first. next_cursor is None on the last page."""
    where, args = [], []
    if f.actor:
        where.append("actor_name = ? COLLATE NOCASE")
        args.append(f.actor)
    if f.action:
        if f.action.endswith(".") and len(f.action) > 1:
            where.append("action >= ? AND action < ?")
            args.extend([f.action, _prefix_upper_bound(f.action)])
        else:
            where.append("action = ?")
            args.append(f.action)
    if f.outcome:
        where.append("outcome = ?")
        args.append(f.outcome)
    if f.target_type:
        where.append("target_type = ?")
        args.append(f.target_type)
    if f.target_id:
        where.append("target_id = ?")
        args.append(f.target_id)
    if f.from_ms is not None:
        where.append("ts_ms >= ?")
        args.append(f.from_ms)
    if f.to_ms is not None:
        where.append("ts_ms < ?")
        args.append(f.to_ms)
    if f.cursor is not None:
        where.append("(ts_ms < ? OR (ts_ms = ? AND id < ?))")
        args.extend([f.cursor[0], f.cursor[0], f.cursor[1]])

    sql = ("SELECT id, ts_ms, actor_name, ip, action, outcome, target_type, target_id, detail "
           "FROM audit_events")
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY ts_ms DESC, id DESC LIMIT ?"
    args.append(f.size + 1)

    rows = conn.execute(sql, args).fetchall()
    if len(rows) > f.size:
        rows = rows[:f.size]
        last = rows[-1]
        return rows, f"{last['ts_ms']}.{last['id']}"
    return rows, None


def detail_preview(detail: str | None) -> str:
    """The stored detail JSON, shortened for a table cell. It is already secret-free (audit.py)."""
    if not detail:
        return ""
    if len(detail) <= DETAIL_PREVIEW_CHARS:
        return detail
    return detail[:DETAIL_PREVIEW_CHARS] + "…"
