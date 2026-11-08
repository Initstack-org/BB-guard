"""SQLite connection helpers and the migration runner (docs/SCHEMA.md section 1 and 5)."""

from __future__ import annotations

import contextlib
import hashlib
import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

MIN_SQLITE = (3, 37, 0)
MIGRATIONS_DIR = Path(__file__).parent / "migrations"
_NAME_RE = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")


class MigrationError(Exception):
    pass


def now_ms() -> int:
    return int(time.time() * 1000)


def check_sqlite() -> list[str]:
    """Return a list of problems (empty list means the SQLite build is usable)."""
    problems = []
    if sqlite3.sqlite_version_info < MIN_SQLITE:
        problems.append(
            f"SQLite {sqlite3.sqlite_version} is older than required "
            f"{'.'.join(map(str, MIN_SQLITE))} (STRICT tables)")
    try:
        sqlite3.connect(":memory:").execute("SELECT json_valid('{}'), json_type('[]')").fetchone()
    except sqlite3.Error as exc:
        problems.append(f"SQLite JSON functions unavailable: {exc}")
    return problems


def connect(path: str, *, readonly: bool = False) -> sqlite3.Connection:
    """Open a connection with the per-connection pragmas from SCHEMA.md section 1.

    The connection is in autocommit mode (isolation_level=None); use `transaction()`
    for explicit write transactions.
    """
    if readonly:
        # The path is percent-encoded: a raw "#" or "?" would otherwise end the path early.
        conn = sqlite3.connect(f"file:{quote(str(path), safe='/')}?mode=ro", uri=True, isolation_level=None)
    else:
        conn = sqlite3.connect(path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


@contextlib.contextmanager
def transaction(conn: sqlite3.Connection):
    """BEGIN IMMEDIATE ... COMMIT, rolling back on any exception."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def split_statements(script: str) -> list[str]:
    """Split a SQL script into statements (trigger bodies stay in one piece)."""
    statements: list[str] = []
    buf: list[str] = []
    for line in script.splitlines():
        if not buf and (not line.strip() or line.lstrip().startswith("--")):
            continue
        buf.append(line)
        candidate = "\n".join(buf)
        if sqlite3.complete_statement(candidate):
            statements.append(candidate)
            buf = []
    if "\n".join(buf).strip():
        raise MigrationError("migration ends with an incomplete statement")
    return statements


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.sql.encode("utf-8")).hexdigest()


def load_migrations(directory: Path | str = MIGRATIONS_DIR) -> list[Migration]:
    found = []
    for path in sorted(Path(directory).iterdir()):
        match = _NAME_RE.match(path.name)
        if not match:
            continue
        found.append(Migration(int(match.group(1)), match.group(2), path.read_text(encoding="utf-8")))
    for expected, mig in enumerate(found, 1):
        if mig.version != expected:
            raise MigrationError(f"migration numbering has a gap or duplicate near {mig.version:04d}")
    return found


def current_version(conn: sqlite3.Connection) -> int:
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'").fetchone()
    if not exists:
        return 0
    row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
    return row[0] or 0


def migrate(conn: sqlite3.Connection, migrations: list[Migration] | None = None,
            *, up_to: int | None = None) -> list[int]:
    """Apply pending migrations, each in its own transaction. Returns versions applied.

    Refuses to run when the database is newer than the code, or when an applied
    migration's file has been edited since it was applied.
    """
    migrations = load_migrations() if migrations is None else migrations
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        " version INTEGER PRIMARY KEY, name TEXT NOT NULL,"
        " checksum TEXT NOT NULL, applied_ms INTEGER NOT NULL) STRICT")
    applied = {r["version"]: r["checksum"] for r in
               conn.execute("SELECT version, checksum FROM schema_migrations")}
    by_version = {m.version: m for m in migrations}
    newer = sorted(v for v in applied if v not in by_version)
    if newer:
        raise MigrationError(
            f"database has migration(s) {newer} that this code does not know; refusing to start")
    for version, checksum in applied.items():
        if by_version[version].checksum != checksum:
            raise MigrationError(
                f"migration {version:04d} was changed after it was applied (checksum mismatch)")
    done = []
    for mig in migrations:
        if mig.version in applied or (up_to is not None and mig.version > up_to):
            continue
        with transaction(conn):
            for stmt in split_statements(mig.sql):
                conn.execute(stmt)
            conn.execute(
                "INSERT INTO schema_migrations(version, name, checksum, applied_ms) VALUES (?,?,?,?)",
                (mig.version, mig.name, mig.checksum, now_ms()))
        done.append(mig.version)
    return done


def enable_wal(conn: sqlite3.Connection) -> str:
    """Set WAL mode once per database (cannot run inside a transaction)."""
    return conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
