"""One ingest pass: read new log lines, parse them, commit them (docs/SUBSYSTEMS.md section 2).

`ingest_once` is what the service's background task and the `ingest` CLI command call. It does a single
bounded batch; `drain` repeats it until the log is caught up.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass

from guard.db import now_ms as _now_ms
from guard.ingest import normalize, tailer, writer
from guard.ingest.parser import ParseError, parse_line, parse_trusted


@dataclass(frozen=True)
class PassResult:
    lines: int = 0
    written: int = 0
    duplicates: int = 0
    bad_lines: int = 0
    peer_mismatches: int = 0
    gaps: int = 0

    @property
    def idle(self) -> bool:
        return self.lines == 0 and self.gaps == 0


def ingest_once(conn: sqlite3.Connection, log_path: str, trusted_connectors, *,
                now: float | None = None, max_lines: int = tailer.MAX_LINES,
                max_read: int = tailer.MAX_READ) -> PassResult:
    """Read and commit at most one batch. Raises sqlite3.Error or OSError; the caller records health."""
    now = time.time() if now is None else now
    settings = writer.read_settings(conn)
    trusted = parse_trusted(trusted_connectors)
    saved = writer.load_position(conn)

    read = tailer.read_next(log_path, saved, now=now, max_lines=max_lines, max_read=max_read)
    if not read.lines and not read.changed and not read.gaps:
        return PassResult()

    records, bad = [], []
    for raw in read.lines:
        try:
            records.append(parse_line(raw, trusted=trusted, managed_hosts=settings.managed_hosts))
        except ParseError as exc:
            bad.append((str(exc), normalize.safe_excerpt(raw)))

    result = writer.write_batch(conn, records, bad, read.gaps, read.position,
                                settings=settings, now_ms=int(now * 1000))
    return PassResult(lines=len(read.lines), written=result.written, duplicates=result.duplicates,
                      bad_lines=result.bad_lines, peer_mismatches=result.peer_mismatches,
                      gaps=len(read.gaps))


def drain(conn: sqlite3.Connection, log_path: str, trusted_connectors, *, max_passes: int = 10_000,
          now: float | None = None) -> PassResult:
    """Run `ingest_once` until it has nothing to do (or `max_passes`). Returns the summed result."""
    total = PassResult()
    for _ in range(max_passes):
        one = ingest_once(conn, log_path, trusted_connectors, now=now)
        if one.idle:
            break
        total = PassResult(*(getattr(total, f) + getattr(one, f) for f in
                             ("lines", "written", "duplicates", "bad_lines", "peer_mismatches", "gaps")))
    return total


def record_health(conn: sqlite3.Connection, *, ok: bool, error: str | None = None,
                  now_ms: int | None = None) -> None:
    """Heartbeat for the `ingest` component, used for notifications (SCHEMA.md S12)."""
    ts = _now_ms() if now_ms is None else now_ms
    if ok:
        conn.execute("""
            INSERT INTO component_health(component, state, heartbeat_ms, last_ok_ms) VALUES ('ingest', 'ok', ?, ?)
            ON CONFLICT(component) DO UPDATE SET state = 'ok', heartbeat_ms = excluded.heartbeat_ms,
                                                 last_ok_ms = excluded.last_ok_ms""", (ts, ts))
    else:
        conn.execute("""
            INSERT INTO component_health(component, state, heartbeat_ms, last_error_ms, last_error)
            VALUES ('ingest', 'error', ?, ?, ?)
            ON CONFLICT(component) DO UPDATE SET state = 'error', heartbeat_ms = excluded.heartbeat_ms,
                                                 last_error_ms = excluded.last_error_ms,
                                                 last_error = excluded.last_error""",
                     (ts, ts, (error or "unknown error")[:300]))
