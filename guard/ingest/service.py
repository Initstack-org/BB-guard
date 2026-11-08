"""Run ingest inside `guard serve` as a background thread (docs/SUBSYSTEMS.md section 2).

The thread has its own SQLite connection (a connection must not be shared between threads), reads new
lines from the Nginx JSON spool file every few seconds, and records an `ingest` health heartbeat. It never
raises: a missing log file, a locked database or any SQLite or OS error is recorded as an error heartbeat
and retried on the next round, so a broken log can never take the dashboard down with it.
"""

from __future__ import annotations

import os
import sqlite3
import threading

from guard import db
from guard.ingest import runner

DEFAULT_INTERVAL_S = 5.0


class IngestThread:
    def __init__(self, db_path: str, log_path: str, trusted_connectors, *,
                 interval_s: float = DEFAULT_INTERVAL_S, report=None):
        self.db_path = db_path
        self.log_path = log_path
        self.trusted = tuple(trusted_connectors)
        self.interval_s = interval_s
        self._report = report or (lambda text: None)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_error: str | None = None

    # -- one round --------------------------------------------------------------------------

    def run_round(self, conn: sqlite3.Connection) -> runner.PassResult | None:
        """One catch-up pass. Returns the result, or None when the round failed (already reported)."""
        if not os.path.isfile(self.log_path):
            error = f"access log not found: {self.log_path}"
            try:
                runner.record_health(conn, ok=False, error=error)
            except sqlite3.Error:
                pass
            self._note(error)
            return None
        result, error = runner.drain_with_health(conn, self.log_path, self.trusted)
        self._note(error)
        if result is not None and not result.idle:
            self._report(f"ingest: lines={result.lines} written={result.written} "
                         f"duplicates={result.duplicates} bad_lines={result.bad_lines}")
        return result

    def _note(self, error: str | None) -> None:
        """Report an error once, and report recovery once."""
        if error and error != self._last_error:
            self._report(f"ingest: {error} (will retry)")
        elif not error and self._last_error:
            self._report("ingest: recovered")
        self._last_error = error

    # -- thread -----------------------------------------------------------------------------

    def _loop(self) -> None:
        conn = None
        while not self._stop.is_set():
            try:
                if conn is None:
                    conn = db.connect(self.db_path)
                self.run_round(conn)
            except Exception as exc:  # noqa: BLE001 - the loop must survive anything
                self._note(f"{type(exc).__name__}: {exc}")
                if conn is not None:
                    try:
                        conn.close()
                    except sqlite3.Error:
                        pass
                    conn = None
            self._stop.wait(self.interval_s)
        if conn is not None:
            conn.close()

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("ingest thread already started")
        self._thread = threading.Thread(target=self._loop, name="guard-ingest", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
