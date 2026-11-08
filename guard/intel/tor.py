"""Independent Tor exit-node feed (docs/SUBSYSTEMS.md section 3.3).

A new list replaces the active one only if it validates (HTTP 200, size bound, every line an IP
address, a plausible count, not a collapse against the previous list). Otherwise the last-known-good
list stays in place and the failure is recorded for the UI. The network is injected.
"""

from __future__ import annotations

import hashlib
import sqlite3
import urllib.request
from typing import Callable

from ..ingest.normalize import canonical_ip

TOR_URL = "https://check.torproject.org/torbulkexitlist"
MAX_BYTES = 2 * 1024 * 1024
MAX_LINES = 50000

# fetch() -> (http_status, body_bytes). May raise OSError.
FetchText = Callable[[], tuple]


class TorFeedError(Exception):
    pass


def default_fetch() -> tuple:
    req = urllib.request.Request(TOR_URL, headers={"User-Agent": "initstack-guard"})
    with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - constant https URL
        return resp.status, resp.read(MAX_BYTES + 1)


def parse_list(text: str) -> set[str]:
    """One address per line; blank lines and # comments are ignored; anything else is an error."""
    found: set[str] = set()
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            found.add(canonical_ip(line))
        except ValueError:
            raise TorFeedError(f"line {number} is not an IP address") from None
        if len(found) > MAX_LINES:
            raise TorFeedError("too many entries")
    return found


def validate(new: set, previous_count: int, *, min_entries: int, min_ratio: float) -> None:
    if len(new) < min_entries:
        raise TorFeedError(f"only {len(new)} entries (minimum {min_entries})")
    if previous_count > 0 and len(new) < previous_count * min_ratio:
        raise TorFeedError(f"{len(new)} entries is less than {min_ratio:.0%} of the previous {previous_count}")


def _record_failure(conn: sqlite3.Connection, message: str, now_ms: int) -> None:
    conn.execute(
        "UPDATE tor_feed_state SET last_attempt_ms = ?, last_error = ?,"
        " consecutive_failures = consecutive_failures + 1 WHERE id = 1", (now_ms, message[:300]))


def update(conn: sqlite3.Connection, now_ms: int, *, fetch: FetchText, min_entries: int,
           min_ratio: float) -> tuple[bool, str]:
    """Download, validate and swap in a new list. Returns (replaced, message). Never raises."""
    previous = conn.execute("SELECT entry_count FROM tor_feed_state WHERE id = 1").fetchone()[0]
    try:
        status, body = fetch()
        if status != 200:
            raise TorFeedError(f"HTTP {status}")
        if len(body) > MAX_BYTES:
            raise TorFeedError("list is too large")
        ips = parse_list(body.decode("utf-8"))
        validate(ips, previous, min_entries=min_entries, min_ratio=min_ratio)
    except (TorFeedError, OSError, TimeoutError, UnicodeDecodeError) as exc:
        message = str(exc) or type(exc).__name__
        _record_failure(conn, message, now_ms)
        return False, message
    digest = hashlib.sha256("\n".join(sorted(ips)).encode()).hexdigest()
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM tor_exit_nodes")
        conn.executemany("INSERT INTO tor_exit_nodes(ip) VALUES (?)", [(ip,) for ip in sorted(ips)])
        conn.execute(
            "UPDATE tor_feed_state SET fetched_ms = ?, entry_count = ?, digest = ?, last_attempt_ms = ?,"
            " last_error = NULL, consecutive_failures = 0 WHERE id = 1", (now_ms, len(ips), digest, now_ms))
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")
    return True, f"{len(ips)} exit nodes"


def is_exit(conn: sqlite3.Connection, ip_text: str) -> bool:
    try:
        ip = canonical_ip(ip_text)
    except ValueError:
        return False
    return conn.execute("SELECT 1 FROM tor_exit_nodes WHERE ip = ?", (ip,)).fetchone() is not None


def state(conn: sqlite3.Connection) -> sqlite3.Row:
    return conn.execute("SELECT * FROM tor_feed_state WHERE id = 1").fetchone()
