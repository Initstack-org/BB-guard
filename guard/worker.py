"""Background worker inside `guard serve` (docs/SUBSYSTEMS.md sections 3 and 8.1).

One thread with its own SQLite connection. Every tick it:
- looks up queued addresses with IPLogs (de-duplicated, bounded, rate limited);
- every 30 seconds removes expired IP rules and URL rules (each removal is audited);
- refreshes the Tor exit list when it is due (and retries a failed download no sooner than every 15 minutes).
It never raises: any error is recorded in `component_health` and the loop carries on.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from typing import Callable

from . import db, settings_read, urlrules
from .intel import iplogs, iprules, tor

QUEUE_MAX = 1000
SWEEP_EVERY_S = 30
TOR_RETRY_MS = 15 * 60 * 1000
PER_TICK = 5


class Worker:
    def __init__(self, db_path: str, *, token: str = "", tick_s: float = 2.0,
                 clock: Callable[[], int] = db.now_ms, fetch: iplogs.Fetch | None = None,
                 tor_fetch: tor.FetchText | None = None, report=None):
        self.db_path = db_path
        self.tick_s = tick_s
        self.clock = clock
        self._fetch = fetch or iplogs.default_fetch(token)
        self._tor_fetch = tor_fetch or tor.default_fetch
        self._report = report or (lambda text: None)
        self._queue: list[str] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._rate: iplogs.RateLimiter | None = None
        self._last_sweep_ms = 0

    def enqueue(self, ip: str) -> bool:
        """Thread-safe and non-blocking. Returns False when the address is already queued or the queue is full."""
        with self._lock:
            if ip in self._queue or len(self._queue) >= QUEUE_MAX:
                return False
            self._queue.append(ip)
            return True

    def _take(self) -> list[str]:
        with self._lock:
            taken, self._queue = self._queue[:PER_TICK], self._queue[PER_TICK:]
        return taken

    def _health(self, conn: sqlite3.Connection, component: str, ok: bool, error: str = "") -> None:
        ts = self.clock()
        try:
            if ok:
                conn.execute(
                    "INSERT INTO component_health(component, state, heartbeat_ms, last_ok_ms) VALUES (?, 'ok', ?, ?)"
                    " ON CONFLICT(component) DO UPDATE SET state = 'ok', heartbeat_ms = excluded.heartbeat_ms,"
                    " last_ok_ms = excluded.last_ok_ms", (component, ts, ts))
            else:
                conn.execute(
                    "INSERT INTO component_health(component, state, heartbeat_ms, last_error_ms, last_error)"
                    " VALUES (?, 'warn', ?, ?, ?) ON CONFLICT(component) DO UPDATE SET state = 'warn',"
                    " heartbeat_ms = excluded.heartbeat_ms, last_error_ms = excluded.last_error_ms,"
                    " last_error = excluded.last_error", (component, ts, ts, (error or "unknown")[:300]))
        except sqlite3.Error:
            pass  # health reporting must never stop the worker

    def run_round(self, conn: sqlite3.Connection) -> None:
        """One tick. Public so tests can drive it without a thread."""
        now = self.clock()
        if settings_read.get(conn, "intel.iplogs.enabled"):
            rate_cfg = settings_read.get(conn, "intel.iplogs.rate_per_minute")
            if self._rate is None or self._rate.per_minute != rate_cfg:
                self._rate = iplogs.RateLimiter(rate_cfg)
            for ip in self._take():
                iplogs.lookup(conn, ip, now, fetch=self._fetch, rate=self._rate,
                              ttl_ok_s=settings_read.get(conn, "intel.ttl_ok_s"),
                              ttl_error_s=settings_read.get(conn, "intel.ttl_error_s"))
        if now - self._last_sweep_ms >= SWEEP_EVERY_S * 1000:
            self._last_sweep_ms = now
            iprules.sweep_expired(conn, now)
            urlrules.sweep_expired(conn, now)
        if settings_read.get(conn, "intel.tor.enabled"):
            state = tor.state(conn)
            interval_ms = settings_read.get(conn, "intel.tor.interval_s") * 1000
            last_ok = state["fetched_ms"] or 0
            last_try = state["last_attempt_ms"] or 0
            due = now - last_ok >= interval_ms and now - last_try >= (TOR_RETRY_MS if state["last_error"] else 0)
            if due:
                replaced, message = tor.update(
                    conn, now, fetch=self._tor_fetch,
                    min_entries=settings_read.get(conn, "intel.tor.min_entries"),
                    min_ratio=settings_read.get(conn, "intel.tor.min_ratio"))
                self._health(conn, "tor_feed", replaced, "" if replaced else message)
                self._report(f"tor feed: {'updated, ' if replaced else 'kept last list, '}{message}")

    def _loop(self) -> None:
        conn = None
        while not self._stop.is_set():
            try:
                if conn is None:
                    conn = db.connect(self.db_path)
                self.run_round(conn)
            except Exception as exc:  # noqa: BLE001 - the loop must survive anything
                self._report(f"worker: {type(exc).__name__}: {exc} (will retry)")
                if conn is not None:
                    try:
                        conn.close()
                    except sqlite3.Error:
                        pass
                    conn = None
                time.sleep(1)
            self._stop.wait(self.tick_s)
        if conn is not None:
            conn.close()

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("worker already started")
        self._thread = threading.Thread(target=self._loop, name="guard-worker", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
