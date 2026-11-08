"""Write parsed requests and their aggregates to SQLite (docs/SUBSYSTEMS.md section 2.6, SCHEMA.md S4).

One call to `write_batch` is one transaction: the request rows, every aggregate they touch, the rollups,
the ingest errors and the new log-file position all commit together. A crash therefore re-reads at most
the last uncommitted batch and can never double-count it.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from guard.db import transaction
from guard.ingest import normalize
from guard.ingest.parser import Record

VISITOR_UA_CAP = 100
VISITOR_ACCOUNT_CAP = 20
HOUR_MS = 3_600_000
DETAIL_MAX = 300

DEFAULT_HOSTS = ("initstack.org", "www.initstack.org")


@dataclass(frozen=True)
class IngestSettings:
    managed_hosts: frozenset = frozenset(DEFAULT_HOSTS)
    rollup_min_hits: int = 10
    errors_max: int = 1000


@dataclass(frozen=True)
class Position:
    """Where reading stops. `dev`/`inode` identify the file; `head_hash` is SHA-256 of its first 256 bytes."""
    dev: int | None = None
    inode: int | None = None
    head_hash: bytes | None = None
    offset: int = 0


@dataclass(frozen=True)
class BatchResult:
    written: int = 0
    duplicates: int = 0
    bad_lines: int = 0
    peer_mismatches: int = 0


def read_settings(conn: sqlite3.Connection) -> IngestSettings:
    """Ingest settings from the settings table; a missing or invalid value falls back to its default."""
    defaults = IngestSettings()

    def load(key: str):
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        if row is None:
            return None
        try:
            return json.loads(row[0])
        except ValueError:
            return None

    hosts = load("site.hosts")
    managed = defaults.managed_hosts
    if isinstance(hosts, list) and hosts and len(hosts) <= 50 and all(isinstance(h, str) and h.strip() for h in hosts):
        managed = frozenset(normalize.normalize_host(h) for h in hosts)

    def bounded(key: str, default: int, low: int, high: int) -> int:
        value = load(key)
        if isinstance(value, int) and not isinstance(value, bool) and low <= value <= high:
            return value
        return default

    return IngestSettings(
        managed_hosts=managed,
        rollup_min_hits=bounded("retention.rollup_min_hits", defaults.rollup_min_hits, 1, 1_000_000),
        errors_max=bounded("retention.ingest_errors_max", defaults.errors_max, 10, 100_000),
    )


def _one(conn: sqlite3.Connection, sql: str, params: tuple):
    cur = conn.execute(sql, params)
    try:
        return cur.fetchone()
    finally:
        cur.close()


def _write_record(conn: sqlite3.Connection, rec: Record, settings: IngestSettings) -> bool:
    """Write one request and its aggregates. Returns False if the request id was already stored."""
    if _one(conn, "SELECT 1 FROM requests WHERE request_id = ?", (rec.request_id,)) is not None:
        return False
    ts = rec.ts_ms
    denied = 1 if rec.outcome == "denied" else 0

    visitor_id = _one(conn, """
        INSERT INTO visitors(ip, first_seen_ms, last_seen_ms, request_count, bytes_in, bytes_out, denied_count)
        VALUES (?, ?, ?, 1, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
          first_seen_ms = MIN(first_seen_ms, excluded.first_seen_ms),
          last_seen_ms  = MAX(last_seen_ms, excluded.last_seen_ms),
          request_count = request_count + 1,
          bytes_in      = bytes_in + excluded.bytes_in,
          bytes_out     = bytes_out + excluded.bytes_out,
          denied_count  = denied_count + excluded.denied_count
        RETURNING id""", (rec.ip, ts, ts, rec.bytes_in, rec.bytes_out, denied))[0]

    url_id, hit_count = _one(conn, """
        INSERT INTO urls(host, path, path_truncated, first_seen_ms, last_seen_ms, hit_count)
        VALUES (?, ?, ?, ?, ?, 1)
        ON CONFLICT(host, path) DO UPDATE SET
          first_seen_ms  = MIN(first_seen_ms, excluded.first_seen_ms),
          last_seen_ms   = MAX(last_seen_ms, excluded.last_seen_ms),
          hit_count      = hit_count + 1,
          path_truncated = MAX(path_truncated, excluded.path_truncated)
        RETURNING id, hit_count""", (rec.host, rec.path, 1 if rec.path_truncated else 0, ts, ts))

    ua_id = None
    if rec.user_agent is not None:
        ua_id = _one(conn, """
            INSERT INTO user_agents(value, first_seen_ms, last_seen_ms) VALUES (?, ?, ?)
            ON CONFLICT(value) DO UPDATE SET
              first_seen_ms = MIN(first_seen_ms, excluded.first_seen_ms),
              last_seen_ms  = MAX(last_seen_ms, excluded.last_seen_ms)
            RETURNING id""", (rec.user_agent, ts, ts))[0]

    referrer_id = None
    if rec.referrer is not None:
        referrer_id = _one(conn, """
            INSERT INTO referrers(value, first_seen_ms, last_seen_ms) VALUES (?, ?, ?)
            ON CONFLICT(value) DO UPDATE SET
              first_seen_ms = MIN(first_seen_ms, excluded.first_seen_ms),
              last_seen_ms  = MAX(last_seen_ms, excluded.last_seen_ms)
            RETURNING id""", (rec.referrer, ts, ts))[0]

    if rec.mybb_uid is not None:
        conn.execute("""
            INSERT INTO mybb_accounts(uid, username, first_seen_ms, last_seen_ms, request_count)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(uid) DO UPDATE SET
              username      = CASE WHEN excluded.last_seen_ms >= last_seen_ms THEN excluded.username ELSE username END,
              first_seen_ms = MIN(first_seen_ms, excluded.first_seen_ms),
              last_seen_ms  = MAX(last_seen_ms, excluded.last_seen_ms),
              request_count = request_count + 1""", (rec.mybb_uid, rec.mybb_username, ts, ts))

    conn.execute("""
        INSERT INTO requests(request_id, ts_ms, visitor_id, url_id, method, query, status, bytes_in, bytes_out,
                             duration_ms, ua_id, referrer_id, mybb_uid, managed, outcome, detection, rule_ref, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (rec.request_id, ts, visitor_id, url_id, rec.method, rec.query, rec.status, rec.bytes_in, rec.bytes_out,
         rec.duration_ms, ua_id, referrer_id, rec.mybb_uid, 1 if rec.managed else 0, rec.outcome,
         rec.detection, rec.rule_ref, rec.reason))

    conn.execute("""
        INSERT INTO visitor_urls(visitor_id, url_id, first_seen_ms, last_seen_ms, hits) VALUES (?, ?, ?, ?, 1)
        ON CONFLICT(visitor_id, url_id) DO UPDATE SET
          first_seen_ms = MIN(first_seen_ms, excluded.first_seen_ms),
          last_seen_ms  = MAX(last_seen_ms, excluded.last_seen_ms),
          hits          = hits + 1""", (visitor_id, url_id, ts, ts))

    if ua_id is not None:
        _bump_capped(conn, "visitor_user_agents", "ua_id", visitor_id, ua_id, ts, VISITOR_UA_CAP)
    if rec.mybb_uid is not None:
        _bump_capped(conn, "visitor_accounts", "mybb_uid", visitor_id, rec.mybb_uid, ts, VISITOR_ACCOUNT_CAP)

    hour = ts - ts % HOUR_MS
    conn.execute("""
        INSERT INTO rollup_site_hourly(hour_ms, requests, bytes_in, bytes_out, denied) VALUES (?, 1, ?, ?, ?)
        ON CONFLICT(hour_ms) DO UPDATE SET
          requests  = requests + 1,
          bytes_in  = bytes_in + excluded.bytes_in,
          bytes_out = bytes_out + excluded.bytes_out,
          denied    = denied + excluded.denied""", (hour, rec.bytes_in, rec.bytes_out, denied))

    # Per-URL hourly rollups exist only for URLs with at least `rollup_min_hits` hits (SCHEMA.md S5).
    # The request that reaches the threshold also backfills the earlier hours from the raw rows.
    if hit_count > settings.rollup_min_hits:
        conn.execute("""
            INSERT INTO rollup_url_hourly(hour_ms, url_id, requests, bytes_in, bytes_out, denied)
            VALUES (?, ?, 1, ?, ?, ?)
            ON CONFLICT(hour_ms, url_id) DO UPDATE SET
              requests  = requests + 1,
              bytes_in  = bytes_in + excluded.bytes_in,
              bytes_out = bytes_out + excluded.bytes_out,
              denied    = denied + excluded.denied""", (hour, url_id, rec.bytes_in, rec.bytes_out, denied))
    elif hit_count == settings.rollup_min_hits:
        conn.execute("""
            INSERT INTO rollup_url_hourly(hour_ms, url_id, requests, bytes_in, bytes_out, denied)
            SELECT ts_ms - ts_ms % 3600000, url_id, COUNT(*), SUM(bytes_in), SUM(bytes_out), SUM(outcome = 'denied')
            FROM requests WHERE url_id = ? GROUP BY 1
            ON CONFLICT(hour_ms, url_id) DO UPDATE SET
              requests  = excluded.requests,
              bytes_in  = excluded.bytes_in,
              bytes_out = excluded.bytes_out,
              denied    = excluded.denied""", (url_id,))
    return True


def _bump_capped(conn, table: str, column: str, visitor_id: int, value: int, ts: int, cap: int) -> None:
    """Count a hit on a per-visitor summary row; new rows are only created below the cap.

    `table` and `column` are constants chosen by this module, never input.
    """
    cur = conn.execute(
        f"UPDATE {table} SET hits = hits + 1, first_seen_ms = MIN(first_seen_ms, ?), "
        f"last_seen_ms = MAX(last_seen_ms, ?) WHERE visitor_id = ? AND {column} = ?",
        (ts, ts, visitor_id, value))
    if cur.rowcount == 0:
        count = _one(conn, f"SELECT COUNT(*) FROM {table} WHERE visitor_id = ?", (visitor_id,))[0]
        if count < cap:
            conn.execute(
                f"INSERT INTO {table}(visitor_id, {column}, first_seen_ms, last_seen_ms, hits) VALUES (?, ?, ?, ?, 1)",
                (visitor_id, value, ts, ts))


def write_batch(conn: sqlite3.Connection, records: list[Record], bad_lines: list[tuple[str, str]],
                gaps: list[str], position: Position, *, settings: IngestSettings, now_ms: int) -> BatchResult:
    """Commit one batch and the new file position in a single transaction.

    `bad_lines` holds (reason, redacted excerpt) pairs; `gaps` holds gap notices.
    """
    written = duplicates = mismatches = 0
    newest = 0
    with transaction(conn):
        for rec in records:
            if _write_record(conn, rec, settings):
                written += 1
                newest = max(newest, rec.ts_ms)
                if rec.peer_mismatch:
                    mismatches += 1
            else:
                duplicates += 1
        for reason, excerpt in bad_lines:
            detail = f"{reason}: {excerpt}" if excerpt else reason
            conn.execute("INSERT INTO ingest_errors(ts_ms, kind, detail) VALUES (?, 'parse', ?)",
                         (now_ms, detail[:DETAIL_MAX]))
        for notice in gaps:
            conn.execute("INSERT INTO ingest_errors(ts_ms, kind, detail) VALUES (?, 'gap', ?)",
                         (now_ms, notice[:DETAIL_MAX]))
        if bad_lines or gaps:
            conn.execute(
                "DELETE FROM ingest_errors WHERE id <= COALESCE("
                "(SELECT id FROM ingest_errors ORDER BY id DESC LIMIT 1 OFFSET ?), 0)", (settings.errors_max,))
        conn.execute("""
            UPDATE ingest_state SET
              file_dev = ?, file_inode = ?, head_hash = ?, file_offset = ?, updated_ms = ?,
              last_request_ms = CASE WHEN ? > 0 THEN MAX(COALESCE(last_request_ms, 0), ?) ELSE last_request_ms END,
              lines_total = lines_total + ?,
              bad_lines_total = bad_lines_total + ?,
              peer_mismatch_total = peer_mismatch_total + ?
            WHERE id = 1""",
            (position.dev, position.inode, position.head_hash, position.offset, now_ms,
             newest, newest, len(records) + len(bad_lines), len(bad_lines), mismatches))
    return BatchResult(written=written, duplicates=duplicates, bad_lines=len(bad_lines),
                       peer_mismatches=mismatches)


def load_position(conn: sqlite3.Connection) -> Position:
    row = conn.execute(
        "SELECT file_dev, file_inode, head_hash, file_offset FROM ingest_state WHERE id = 1").fetchone()
    if row is None:
        return Position()
    head = bytes(row["head_hash"]) if row["head_hash"] is not None else None
    return Position(row["file_dev"], row["file_inode"], head, row["file_offset"])
