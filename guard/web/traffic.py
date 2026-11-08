"""Visitors and URL History queries (docs/API.md 7.1 and 7.3, GOAL.md sections 1.B and 1.C).

Pure functions over SQLite: filter parsing, parameterized keyset queries, time-series buckets and CSV
rows. Nothing here writes, and nothing here imports the web stack, so it is testable on its own.

Rules this module follows:
- Filter values never go into SQL text; only fixed column names chosen here do.
- Every list is bounded (page size 1 to 200) and uses a keyset cursor, except the "most accessed in a
  period" ranking, which is a top-N list.
- CSV cells that a spreadsheet could read as a formula are prefixed with an apostrophe.
- Byte counts are HTTP traffic through this site only (GOAL.md section 1.C).
"""

from __future__ import annotations

import csv
import io
import re
import sqlite3
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ..auth.service import canonical_ip

DEFAULT_SIZE = 50
MAX_SIZE = 200
CSV_MAX_ROWS = 100_000
HOUR_MS = 3_600_000
DAY_MS = 86_400_000
PRESETS = {"24h": 24 * HOUR_MS, "7d": 7 * DAY_MS, "30d": 30 * DAY_MS}
MAX_CUSTOM_DAYS = 366
HOURLY_UP_TO_MS = 48 * HOUR_MS      # ranges this short are graphed per hour, longer ones per day
RAW_SERIES_MAX_HITS = 50_000        # URLs with more hits are graphed from the hourly rollup
PER_VISITOR_SUMMARY_ROWS = 100
PER_VISITOR_BREAKDOWN_ROWS = 50_000  # method and status counts use at most this many recent requests

VISITOR_SORTS = {"last_seen": "last_seen_ms", "requests": "request_count"}
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CURSOR = re.compile(r"^(\d{1,16})\.(\d{1,16})$")
_IP_TEXT = re.compile(r"^[0-9a-f:.]{1,45}$")
_STATUS = re.compile(r"^([1-5])(\d\d|xx)$")
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


class FilterError(ValueError):
    """A filter value the page cannot use; the message is safe to show to the admin."""


# ---------------------------------------------------------------------------------------------
# Small helpers


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


def _next_day(day: str) -> str:
    return (datetime.strptime(day, "%Y-%m-%d") + timedelta(days=1)).strftime("%Y-%m-%d")


def _text(params, name: str, limit: int) -> str:
    value = (params.get(name) or "").strip()
    if len(value) > limit:
        raise FilterError(f"The {name.replace('_', ' ')} filter is too long.")
    if any(ord(c) < 32 for c in value):
        raise FilterError(f"The {name.replace('_', ' ')} filter contains control characters.")
    return value


def _upper_bound(prefix: str) -> str:
    return prefix[:-1] + chr(ord(prefix[-1]) + 1)


def _size(params) -> int:
    raw = (params.get("size") or "").strip()
    if not raw:
        return DEFAULT_SIZE
    if not raw.isdigit() or not 1 <= int(raw) <= MAX_SIZE:
        raise FilterError(f"Page size must be a number from 1 to {MAX_SIZE}.")
    return int(raw)


def _cursor(params) -> tuple[int, int] | None:
    raw = (params.get("before") or "").strip()
    if not raw:
        return None
    match = _CURSOR.match(raw)
    if not match:
        raise FilterError("That page link is not valid.")
    return int(match.group(1)), int(match.group(2))


def _dates(params, tz) -> tuple[int | None, int | None, str, str]:
    """(from_ms inclusive, to_ms exclusive, from text, to text). Each bound is optional."""
    from_date, to_date = _text(params, "from", 10), _text(params, "to", 10)
    from_ms = to_ms = None
    if from_date:
        if not _DATE.match(from_date):
            raise FilterError("Dates must be real calendar dates in the form YYYY-MM-DD.")
        from_ms = _day_start_ms(from_date, tz)
    if to_date:
        if not _DATE.match(to_date):
            raise FilterError("Dates must be real calendar dates in the form YYYY-MM-DD.")
        to_ms = _day_start_ms(_next_day(to_date), tz)  # "to" names a day and includes all of it
    if from_ms is not None and to_ms is not None and from_ms >= to_ms:
        raise FilterError("The start date must not be after the end date.")
    return from_ms, to_ms, from_date, to_date


def _ip_filter(params) -> tuple[str, str, str]:
    """(text as typed, exact canonical address, prefix). At most one of the last two is set."""
    text = _text(params, "ip", 45).lower()
    if not text:
        return "", "", ""
    if not _IP_TEXT.match(text):
        raise FilterError("The address filter may only contain digits, letters a to f, dots and colons.")
    exact = canonical_ip(text)
    if exact != "invalid":
        return text, exact, ""
    return text, "", text


def _status_filter(params) -> tuple[str, int | None, int | None]:
    """(text as typed, low, high inclusive). '404' is exact, '4xx' is a whole class."""
    text = _text(params, "status", 3).lower()
    if not text:
        return "", None, None
    match = _STATUS.match(text)
    if not match:
        raise FilterError("Status must be a code such as 404, or a class such as 4xx.")
    if match.group(2) == "xx":
        base = int(match.group(1)) * 100
        return text, base, base + 99
    code = int(text)
    return text, code, code


def human_bytes(n: int) -> str:
    """1536 -> '1.5 KiB'. Binary units, labelled as such."""
    value = float(max(0, int(n)))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{int(value)} B" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{int(n)} B"  # unreachable; keeps type checkers calm


def csv_safe(cell):
    """Stop spreadsheets from running a cell as a formula (CSV injection). Numbers pass through."""
    if isinstance(cell, str) and cell.startswith(_FORMULA_START):
        return "'" + cell
    return cell


def iso_utc(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") \
        + f"{int(ms) % 1000:03d}Z"


# ---------------------------------------------------------------------------------------------
# Visitors


@dataclass(frozen=True)
class VisitorFilters:
    ip_text: str = ""
    ip_exact: str = ""
    ip_prefix: str = ""
    from_ms: int | None = None
    to_ms: int | None = None
    from_date: str = ""
    to_date: str = ""
    sort: str = "last_seen"
    size: int = DEFAULT_SIZE
    cursor: tuple[int, int] | None = None


def parse_visitor_filters(params, tz_name: str = "UTC") -> VisitorFilters:
    tz = _tz(tz_name)
    ip_text, ip_exact, ip_prefix = _ip_filter(params)
    from_ms, to_ms, from_date, to_date = _dates(params, tz)
    sort = _text(params, "sort", 16) or "last_seen"
    if sort not in VISITOR_SORTS:
        raise FilterError("Sort must be last_seen or requests.")
    return VisitorFilters(ip_text, ip_exact, ip_prefix, from_ms, to_ms, from_date, to_date, sort,
                          _size(params), _cursor(params))


def _visitor_where(f: VisitorFilters) -> tuple[list[str], list]:
    where, args = [], []
    if f.ip_exact:
        where.append("ip = ?")
        args.append(f.ip_exact)
    elif f.ip_prefix:
        where.append("ip >= ? AND ip < ?")
        args.extend([f.ip_prefix, _upper_bound(f.ip_prefix)])
    # "Seen between" means the visitor's first-to-last-seen span overlaps the range.
    if f.from_ms is not None:
        where.append("last_seen_ms >= ?")
        args.append(f.from_ms)
    if f.to_ms is not None:
        where.append("first_seen_ms < ?")
        args.append(f.to_ms)
    return where, args


_VISITOR_COLUMNS = ("id, ip, first_seen_ms, last_seen_ms, request_count, bytes_in, bytes_out, "
                    "denied_count")


def visitor_page(conn: sqlite3.Connection, f: VisitorFilters) -> tuple[list[sqlite3.Row], str | None]:
    """(rows, next cursor) newest-seen first, or busiest first when sorted by requests."""
    column = VISITOR_SORTS[f.sort]
    where, args = _visitor_where(f)
    if f.cursor is not None:
        where.append(f"({column} < ? OR ({column} = ? AND id < ?))")
        args.extend([f.cursor[0], f.cursor[0], f.cursor[1]])
    sql = f"SELECT {_VISITOR_COLUMNS} FROM visitors"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += f" ORDER BY {column} DESC, id DESC LIMIT ?"
    args.append(f.size + 1)
    rows = conn.execute(sql, args).fetchall()
    if len(rows) > f.size:
        rows = rows[:f.size]
        return rows, f"{rows[-1][column]}.{rows[-1]['id']}"
    return rows, None


def visitor_rows_for_csv(conn: sqlite3.Connection, f: VisitorFilters, limit: int = CSV_MAX_ROWS):
    """Up to `limit` visitor rows matching the filters (cursor and size are ignored)."""
    column = VISITOR_SORTS[f.sort]
    where, args = _visitor_where(f)
    sql = f"SELECT {_VISITOR_COLUMNS} FROM visitors"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += f" ORDER BY {column} DESC, id DESC LIMIT ?"
    args.append(limit + 1)
    return conn.execute(sql, args).fetchall()


def visitor_by_ip(conn: sqlite3.Connection, ip: str) -> sqlite3.Row | None:
    canon = canonical_ip(ip.strip())
    if canon == "invalid":
        return None
    return conn.execute(f"SELECT {_VISITOR_COLUMNS} FROM visitors WHERE ip = ?", (canon,)).fetchone()


def visitor_urls(conn: sqlite3.Connection, visitor_id: int, limit: int = PER_VISITOR_SUMMARY_ROWS):
    """(rows, total distinct URLs): the URLs this visitor requested, most hits first."""
    rows = conn.execute(
        "SELECT u.id AS url_id, u.host, u.path, vu.hits, vu.first_seen_ms, vu.last_seen_ms "
        "FROM visitor_urls vu JOIN urls u ON u.id = vu.url_id WHERE vu.visitor_id = ? "
        "ORDER BY vu.hits DESC, u.id LIMIT ?", (visitor_id, limit)).fetchall()
    total = conn.execute("SELECT COUNT(*) FROM visitor_urls WHERE visitor_id = ?", (visitor_id,)).fetchone()[0]
    return rows, total


def visitor_agents(conn: sqlite3.Connection, visitor_id: int, limit: int = PER_VISITOR_SUMMARY_ROWS):
    return conn.execute(
        "SELECT ua.value, vua.hits, vua.first_seen_ms, vua.last_seen_ms "
        "FROM visitor_user_agents vua JOIN user_agents ua ON ua.id = vua.ua_id "
        "WHERE vua.visitor_id = ? ORDER BY vua.last_seen_ms DESC, ua.id LIMIT ?",
        (visitor_id, limit)).fetchall()


def visitor_accounts(conn: sqlite3.Connection, visitor_id: int):
    return conn.execute(
        "SELECT a.uid, a.username, va.hits, va.first_seen_ms, va.last_seen_ms "
        "FROM visitor_accounts va JOIN mybb_accounts a ON a.uid = va.mybb_uid "
        "WHERE va.visitor_id = ? ORDER BY va.last_seen_ms DESC, a.uid", (visitor_id,)).fetchall()


def visitor_breakdown(conn: sqlite3.Connection, visitor_id: int, column: str,
                      from_ms: int | None = None, to_ms: int | None = None):
    """Counts of `method` or `status` over the visitor's most recent requests in the range."""
    if column not in ("method", "status"):
        raise ValueError("column must be method or status")
    where, args = ["visitor_id = ?"], [visitor_id]
    if from_ms is not None:
        where.append("ts_ms >= ?")
        args.append(from_ms)
    if to_ms is not None:
        where.append("ts_ms < ?")
        args.append(to_ms)
    args.append(PER_VISITOR_BREAKDOWN_ROWS)
    return conn.execute(
        f"SELECT {column} AS value, COUNT(*) AS n FROM (SELECT {column} FROM requests "
        f"WHERE {' AND '.join(where)} ORDER BY ts_ms DESC LIMIT ?) GROUP BY {column} "
        f"ORDER BY n DESC, {column}", args).fetchall()


# ---------------------------------------------------------------------------------------------
# Requests (used by the visitor page and the URL page)


@dataclass(frozen=True)
class RequestFilters:
    visitor_id: int | None = None
    url_id: int | None = None
    status_lo: int | None = None
    status_hi: int | None = None
    from_ms: int | None = None
    to_ms: int | None = None
    size: int = DEFAULT_SIZE
    cursor: tuple[int, int] | None = None


_REQUEST_COLUMNS = ("r.id, r.ts_ms, v.ip, u.host, u.path, r.query, r.method, r.status, r.bytes_in, "
                    "r.bytes_out, r.duration_ms, r.outcome, r.reason")
_REQUEST_FROM = ("FROM requests r JOIN visitors v ON v.id = r.visitor_id "
                 "JOIN urls u ON u.id = r.url_id")


def _request_where(f: RequestFilters) -> tuple[list[str], list]:
    where, args = [], []
    if f.visitor_id is not None:
        where.append("r.visitor_id = ?")
        args.append(f.visitor_id)
    if f.url_id is not None:
        where.append("r.url_id = ?")
        args.append(f.url_id)
    if f.status_lo is not None:
        where.append("r.status BETWEEN ? AND ?")
        args.extend([f.status_lo, f.status_hi])
    if f.from_ms is not None:
        where.append("r.ts_ms >= ?")
        args.append(f.from_ms)
    if f.to_ms is not None:
        where.append("r.ts_ms < ?")
        args.append(f.to_ms)
    return where, args


def request_page(conn: sqlite3.Connection, f: RequestFilters) -> tuple[list[sqlite3.Row], str | None]:
    where, args = _request_where(f)
    if f.cursor is not None:
        where.append("(r.ts_ms < ? OR (r.ts_ms = ? AND r.id < ?))")
        args.extend([f.cursor[0], f.cursor[0], f.cursor[1]])
    sql = f"SELECT {_REQUEST_COLUMNS} {_REQUEST_FROM}"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY r.ts_ms DESC, r.id DESC LIMIT ?"
    args.append(f.size + 1)
    rows = conn.execute(sql, args).fetchall()
    if len(rows) > f.size:
        rows = rows[:f.size]
        return rows, f"{rows[-1]['ts_ms']}.{rows[-1]['id']}"
    return rows, None


def request_rows_for_csv(conn: sqlite3.Connection, f: RequestFilters, limit: int = CSV_MAX_ROWS):
    where, args = _request_where(f)
    sql = f"SELECT {_REQUEST_COLUMNS} {_REQUEST_FROM}"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY r.ts_ms DESC, r.id DESC LIMIT ?"
    args.append(limit + 1)
    return conn.execute(sql, args).fetchall()


def request_detail(conn: sqlite3.Connection, request_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT r.id, r.ts_ms, v.ip, v.id AS visitor_id, u.id AS url_id, u.host, u.path, "
        "u.path_truncated, r.query, r.method, r.status, r.bytes_in, r.bytes_out, r.duration_ms, "
        "r.managed, r.outcome, r.detection, r.rule_ref, r.reason, r.mybb_uid, a.username AS mybb_username, "
        "ua.value AS user_agent, ref.value AS referrer "
        "FROM requests r JOIN visitors v ON v.id = r.visitor_id JOIN urls u ON u.id = r.url_id "
        "LEFT JOIN user_agents ua ON ua.id = r.ua_id LEFT JOIN referrers ref ON ref.id = r.referrer_id "
        "LEFT JOIN mybb_accounts a ON a.uid = r.mybb_uid WHERE r.id = ?", (request_id,)).fetchone()


def parse_request_filters(params, tz_name: str, *, visitor_id: int | None = None,
                          url_id: int | None = None) -> tuple[RequestFilters, dict]:
    """Filters for a request list plus the values to refill the form with."""
    tz = _tz(tz_name)
    from_ms, to_ms, from_date, to_date = _dates(params, tz)
    status_text, lo, hi = _status_filter(params)
    f = RequestFilters(visitor_id=visitor_id, url_id=url_id, status_lo=lo, status_hi=hi, from_ms=from_ms,
                       to_ms=to_ms, size=_size(params), cursor=_cursor(params))
    return f, {"from_date": from_date, "to_date": to_date, "status": status_text}


CSV_REQUEST_HEADER = ["time_utc", "ip", "method", "host", "path", "query", "status",
                      "bytes_received", "bytes_sent", "duration_ms", "outcome", "reason"]
CSV_VISITOR_HEADER = ["ip", "first_seen_utc", "last_seen_utc", "requests", "bytes_received",
                      "bytes_sent", "denied_requests"]


def requests_to_csv(rows) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(CSV_REQUEST_HEADER)
    for r in rows:
        writer.writerow([csv_safe(x) for x in (
            iso_utc(r["ts_ms"]), r["ip"], r["method"], r["host"], r["path"], r["query"] or "",
            r["status"], r["bytes_in"], r["bytes_out"], r["duration_ms"], r["outcome"],
            r["reason"] or "")])
    return out.getvalue()


def visitors_to_csv(rows) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(CSV_VISITOR_HEADER)
    for r in rows:
        writer.writerow([csv_safe(x) for x in (
            r["ip"], iso_utc(r["first_seen_ms"]), iso_utc(r["last_seen_ms"]), r["request_count"],
            r["bytes_in"], r["bytes_out"], r["denied_count"])])
    return out.getvalue()


# ---------------------------------------------------------------------------------------------
# URL history


@dataclass(frozen=True)
class UrlListFilters:
    q: str = ""
    period: str = "all"             # all, 24h, 7d or 30d
    size: int = DEFAULT_SIZE
    cursor: tuple[int, int] | None = None


def normalize_url_query(text: str) -> str:
    """Accept a path or a pasted URL; the search is by path only (queries are per request)."""
    text = text.strip()
    if "://" in text:
        try:
            text = urlsplit(text).path or "/"
        except ValueError as exc:
            raise FilterError("That does not look like a valid URL.") from exc
    return text.split("?", 1)[0].split("#", 1)[0]


def parse_url_list_filters(params) -> UrlListFilters:
    q = normalize_url_query(_text(params, "q", 400))
    if len(q) > 200:
        raise FilterError("The search is too long.")
    period = _text(params, "period", 8) or "all"
    if period != "all" and period not in PRESETS:
        raise FilterError("Period must be all, 24h, 7d or 30d.")
    return UrlListFilters(q, period, _size(params), _cursor(params))


def _like_pattern(q: str) -> str:
    escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def url_ranking(conn: sqlite3.Connection, f: UrlListFilters, now_ms: int):
    """(rows, next cursor). All time: from the URL table, keyset paged. A period: a top-N list."""
    where, args = [], []
    if f.q:
        where.append("u.path LIKE ? ESCAPE '\\'")
        args.append(_like_pattern(f.q))
    if f.period == "all":
        if f.cursor is not None:
            where.append("(u.hit_count < ? OR (u.hit_count = ? AND u.id > ?))")
            args.extend([f.cursor[0], f.cursor[0], f.cursor[1]])
        sql = ("SELECT u.id, u.host, u.path, u.path_truncated, u.hit_count AS hits, u.first_seen_ms, "
               "u.last_seen_ms FROM urls u")
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY u.hit_count DESC, u.id ASC LIMIT ?"
        args.append(f.size + 1)
        rows = conn.execute(sql, args).fetchall()
        if len(rows) > f.size:
            rows = rows[:f.size]
            return rows, f"{rows[-1]['hits']}.{rows[-1]['id']}"
        return rows, None
    start = now_ms - PRESETS[f.period]
    sql = ("SELECT u.id, u.host, u.path, u.path_truncated, COUNT(*) AS hits, MIN(r.ts_ms) AS first_seen_ms, "
           "MAX(r.ts_ms) AS last_seen_ms FROM requests r JOIN urls u ON u.id = r.url_id "
           "WHERE r.ts_ms >= ? AND r.ts_ms <= ?")
    args = [start, now_ms] + args
    if where:
        sql += " AND " + " AND ".join(where)
    sql += " GROUP BY u.id ORDER BY hits DESC, u.id ASC LIMIT ?"
    args.append(f.size)
    return conn.execute(sql, args).fetchall(), None


def url_by_id(conn: sqlite3.Connection, url_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, host, path, path_truncated, first_seen_ms, last_seen_ms, hit_count FROM urls WHERE id = ?",
        (url_id,)).fetchone()


@dataclass(frozen=True)
class Range:
    from_ms: int
    to_ms: int          # exclusive
    key: str            # 24h, 7d, 30d or custom
    from_date: str = ""
    to_date: str = ""


@dataclass(frozen=True)
class UrlDetailFilters:
    url_id: int
    range: Range
    ip_text: str
    ip_exact: str
    ip_prefix: str
    status_text: str
    status_lo: int | None
    status_hi: int | None
    size: int
    cursor: tuple[int, int] | None


def parse_range(params, tz_name: str, now_ms: int, default: str = "7d") -> Range:
    tz = _tz(tz_name)
    from_ms, to_ms, from_date, to_date = _dates(params, tz)
    if from_date or to_date:
        end = to_ms if to_ms is not None else now_ms + 1
        start = from_ms if from_ms is not None else end - 30 * DAY_MS
        if start >= end:
            raise FilterError("The start date must not be after the end date.")
        if end - start > MAX_CUSTOM_DAYS * DAY_MS:
            raise FilterError(f"A custom range can be at most {MAX_CUSTOM_DAYS} days.")
        return Range(start, end, "custom", from_date, to_date)
    key = _text(params, "range", 8) or default
    if key not in PRESETS:
        raise FilterError("Range must be 24h, 7d or 30d.")
    return Range(now_ms - PRESETS[key], now_ms + 1, key)


def parse_url_detail_filters(params, tz_name: str, now_ms: int) -> UrlDetailFilters:
    raw = (params.get("id") or "").strip()
    if not raw.isdigit() or len(raw) > 16:
        raise FilterError("Choose a URL from the list.")
    ip_text, ip_exact, ip_prefix = _ip_filter(params)
    status_text, lo, hi = _status_filter(params)
    return UrlDetailFilters(int(raw), parse_range(params, tz_name, now_ms), ip_text, ip_exact, ip_prefix,
                            status_text, lo, hi, _size(params), _cursor(params))


def resolve_visitor_ids(conn: sqlite3.Connection, ip_exact: str, ip_prefix: str,
                        limit: int = 500) -> list[int] | None:
    """None when no address filter is set; else the matching visitor ids (possibly empty)."""
    if ip_exact:
        row = conn.execute("SELECT id FROM visitors WHERE ip = ?", (ip_exact,)).fetchone()
        return [row["id"]] if row else []
    if ip_prefix:
        rows = conn.execute("SELECT id FROM visitors WHERE ip >= ? AND ip < ? ORDER BY id LIMIT ?",
                            (ip_prefix, _upper_bound(ip_prefix), limit)).fetchall()
        return [r["id"] for r in rows]
    return None


def url_requests_filter(f: UrlDetailFilters, visitor_ids: list[int] | None) -> RequestFilters | None:
    """RequestFilters for the URL page, or None when the address filter matches nobody.

    A prefix that matches several visitors is narrowed to the first one in `resolve_visitor_ids`'s
    order only when exactly one matched; several matches use an IN list through `url_requests_for_ids`.
    """
    if visitor_ids is not None and not visitor_ids:
        return None
    single = visitor_ids[0] if visitor_ids and len(visitor_ids) == 1 else None
    return RequestFilters(visitor_id=single, url_id=f.url_id, status_lo=f.status_lo, status_hi=f.status_hi,
                          from_ms=f.range.from_ms, to_ms=f.range.to_ms, size=f.size, cursor=f.cursor)


def url_summary(conn: sqlite3.Connection, url_id: int, from_ms: int, to_ms: int,
                visitor_ids: list[int] | None = None, status_lo: int | None = None,
                status_hi: int | None = None) -> dict:
    """Totals for one URL over [from_ms, to_ms) with the page's address and status filters."""
    where, args = ["url_id = ?", "ts_ms >= ?", "ts_ms < ?"], [url_id, from_ms, to_ms]
    if visitor_ids is not None:
        if not visitor_ids:
            return {"visits": 0, "unique_ips": 0, "bytes_in": 0, "bytes_out": 0, "denied": 0}
        where.append("visitor_id IN (%s)" % ",".join("?" * len(visitor_ids)))
        args.extend(visitor_ids)
    if status_lo is not None:
        where.append("status BETWEEN ? AND ?")
        args.extend([status_lo, status_hi])
    row = conn.execute(
        "SELECT COUNT(*) AS visits, COUNT(DISTINCT visitor_id) AS unique_ips, "
        "COALESCE(SUM(bytes_in), 0) AS bytes_in, COALESCE(SUM(bytes_out), 0) AS bytes_out, "
        "COALESCE(SUM(outcome = 'denied'), 0) AS denied FROM requests WHERE " + " AND ".join(where),
        args).fetchone()
    return dict(row)


def url_requests_page(conn: sqlite3.Connection, f: UrlDetailFilters, visitor_ids: list[int] | None):
    """Request rows for the URL page. Several matching visitors are handled with an IN list."""
    base = url_requests_filter(f, visitor_ids)
    if base is None:
        return [], None
    if visitor_ids is not None and len(visitor_ids) > 1:
        where, args = _request_where(base)
        where.append("r.visitor_id IN (%s)" % ",".join("?" * len(visitor_ids)))
        args.extend(visitor_ids)
        if f.cursor is not None:
            where.append("(r.ts_ms < ? OR (r.ts_ms = ? AND r.id < ?))")
            args.extend([f.cursor[0], f.cursor[0], f.cursor[1]])
        sql = (f"SELECT {_REQUEST_COLUMNS} {_REQUEST_FROM} WHERE " + " AND ".join(where)
               + " ORDER BY r.ts_ms DESC, r.id DESC LIMIT ?")
        args.append(f.size + 1)
        rows = conn.execute(sql, args).fetchall()
        if len(rows) > f.size:
            rows = rows[:f.size]
            return rows, f"{rows[-1]['ts_ms']}.{rows[-1]['id']}"
        return rows, None
    return request_page(conn, base)


def url_requests_for_csv(conn: sqlite3.Connection, f: UrlDetailFilters, visitor_ids: list[int] | None,
                         limit: int = CSV_MAX_ROWS):
    base = url_requests_filter(f, visitor_ids)
    if base is None:
        return []
    if visitor_ids is not None and len(visitor_ids) > 1:
        where, args = _request_where(base)
        where.append("r.visitor_id IN (%s)" % ",".join("?" * len(visitor_ids)))
        args.extend(visitor_ids)
        sql = (f"SELECT {_REQUEST_COLUMNS} {_REQUEST_FROM} WHERE " + " AND ".join(where)
               + " ORDER BY r.ts_ms DESC, r.id DESC LIMIT ?")
        args.append(limit + 1)
        return conn.execute(sql, args).fetchall()
    return request_rows_for_csv(conn, base, limit)


# ---------------------------------------------------------------------------------------------
# Graph data


@dataclass(frozen=True)
class Bucket:
    start_ms: int
    label: str
    full_label: str
    requests: int
    bytes_in: int
    bytes_out: int


def url_series(conn: sqlite3.Connection, url_id: int, hit_count: int, from_ms: int, to_ms: int,
               tz_name: str) -> tuple[str, list[Bucket]]:
    """('hour' or 'day', buckets) for one URL over [from_ms, to_ms), in the admin's time zone.

    Busy URLs (more than RAW_SERIES_MAX_HITS hits) are read from the hourly rollup, which exists only for
    URLs above the `retention.rollup_min_hits` threshold; others are counted from the request rows.
    Daily buckets group whole UTC hours by local date, so a half-hour time zone is off by up to 30 minutes
    at a day edge.
    """
    tz = _tz(tz_name)
    first_hour = from_ms - from_ms % HOUR_MS
    if hit_count > RAW_SERIES_MAX_HITS:
        rows = conn.execute(
            "SELECT hour_ms, requests, bytes_in, bytes_out FROM rollup_url_hourly "
            "WHERE url_id = ? AND hour_ms >= ? AND hour_ms < ?", (url_id, first_hour, to_ms)).fetchall()
    else:
        rows = conn.execute(
            "SELECT ts_ms - ts_ms % 3600000 AS hour_ms, COUNT(*) AS requests, "
            "COALESCE(SUM(bytes_in), 0) AS bytes_in, COALESCE(SUM(bytes_out), 0) AS bytes_out "
            "FROM requests WHERE url_id = ? AND ts_ms >= ? AND ts_ms < ? GROUP BY 1",
            (url_id, first_hour, to_ms)).fetchall()
    by_hour = {r["hour_ms"]: (r["requests"], r["bytes_in"], r["bytes_out"]) for r in rows}

    if to_ms - from_ms <= HOURLY_UP_TO_MS:
        buckets = []
        for start in range(first_hour, to_ms, HOUR_MS):
            when = datetime.fromtimestamp(start / 1000, tz)
            req, bin_, bout = by_hour.get(start, (0, 0, 0))
            buckets.append(Bucket(start, when.strftime("%H:%M"), when.strftime("%Y-%m-%d %H:%M %Z"),
                                  req, bin_, bout))
        return "hour", buckets

    per_day: dict[date, list[int]] = {}
    for hour, (req, bin_, bout) in by_hour.items():
        day = datetime.fromtimestamp(hour / 1000, tz).date()
        acc = per_day.setdefault(day, [0, 0, 0])
        acc[0] += req
        acc[1] += bin_
        acc[2] += bout
    day = datetime.fromtimestamp(from_ms / 1000, tz).date()
    last = datetime.fromtimestamp((to_ms - 1) / 1000, tz).date()
    buckets = []
    while day <= last:
        req, bin_, bout = per_day.get(day, [0, 0, 0])
        start = int(datetime(day.year, day.month, day.day, tzinfo=tz).timestamp() * 1000)
        buckets.append(Bucket(start, day.strftime("%m-%d"), day.isoformat(), req, bin_, bout))
        day += timedelta(days=1)
    return "day", buckets


# ---------------------------------------------------------------------------------------------
# Dashboard overview (GOAL.md section 1.A)

OVERVIEW_HOURS = 24


def site_overview(conn: sqlite3.Connection, now_ms: int, tz_name: str) -> dict:
    """Site-wide totals and an hourly series for the last OVERVIEW_HOURS hourly buckets.

    The window is this hour so far plus the 23 hours before it, read from `rollup_site_hourly` (one row
    per hour, written by ingest for every request), so the cost does not grow with traffic. `visitors`
    is the number of addresses whose most recent request falls in the window, which for a window that
    ends now is exactly the addresses active in it.
    """
    tz = _tz(tz_name)
    last_hour = now_ms - now_ms % HOUR_MS
    first_hour = last_hour - (OVERVIEW_HOURS - 1) * HOUR_MS
    end_ms = last_hour + HOUR_MS
    rows = conn.execute(
        "SELECT hour_ms, requests, bytes_in, bytes_out, denied FROM rollup_site_hourly "
        "WHERE hour_ms >= ? AND hour_ms < ?", (first_hour, end_ms)).fetchall()
    by_hour = {r["hour_ms"]: (r["requests"], r["bytes_in"], r["bytes_out"], r["denied"]) for r in rows}
    buckets = []
    for start in range(first_hour, end_ms, HOUR_MS):
        when = datetime.fromtimestamp(start / 1000, tz)
        req, bin_, bout, _ = by_hour.get(start, (0, 0, 0, 0))
        buckets.append(Bucket(start, when.strftime("%H:%M"), when.strftime("%Y-%m-%d %H:%M %Z"),
                              req, bin_, bout))
    visitors = conn.execute("SELECT COUNT(*) FROM visitors WHERE last_seen_ms >= ? AND last_seen_ms < ?",
                            (first_hour, end_ms)).fetchone()[0]
    return {"requests": sum(v[0] for v in by_hour.values()), "bytes_in": sum(v[1] for v in by_hour.values()),
            "bytes_out": sum(v[2] for v in by_hour.values()), "denied": sum(v[3] for v in by_hour.values()),
            "visitors": visitors, "buckets": buckets, "from_ms": first_hour, "to_ms": end_ms}


def ingest_status(conn: sqlite3.Connection) -> dict:
    """What the log reader has done so far (the single `ingest_state` row). Counters are zero and the
    times are None before the first pass."""
    row = conn.execute(
        "SELECT last_request_ms, updated_ms, lines_total, bad_lines_total, peer_mismatch_total "
        "FROM ingest_state WHERE id = 1").fetchone()
    if row is None:
        return {"last_request_ms": None, "updated_ms": 0, "lines_total": 0, "bad_lines_total": 0,
                "peer_mismatch_total": 0}
    return dict(row)
