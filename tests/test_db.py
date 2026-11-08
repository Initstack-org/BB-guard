import sqlite3

import pytest

from guard import db


def write_migrations(tmp_path, files):
    d = tmp_path / "m"
    d.mkdir()
    for name, sql in files.items():
        (d / name).write_text(sql)
    return d


def test_all_migrations_apply_and_are_recorded():
    c = db.connect(":memory:")
    assert db.migrate(c) == [1, 2, 3, 4, 5, 6]
    assert db.current_version(c) == 6
    assert db.migrate(c) == []  # idempotent
    names = {r["name"] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for t in ("admins", "sessions", "audit_events", "passkeys", "requests", "ip_rules", "url_rules",
              "block_page_versions", "injections", "settings", "auth_throttle"):
        assert t in names


def test_current_version_of_empty_database_is_zero():
    assert db.current_version(db.connect(":memory:")) == 0


def test_sqlite_is_usable_here():
    assert db.check_sqlite() == []


def test_foreign_keys_are_enforced(conn):
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO sessions(token_hash, admin_id, auth_method, created_ms, last_seen_ms,"
                     " expires_ms, ip) VALUES (zeroblob(32), 999, 'password', 1, 1, 2, '1.2.3.4')")


def test_failed_migration_rolls_back_and_keeps_earlier_ones(tmp_path):
    d = write_migrations(tmp_path, {
        "0001_a.sql": "CREATE TABLE a (x INTEGER) STRICT;",
        "0002_b.sql": "CREATE TABLE b (x INTEGER) STRICT;\nCREATE TABLE a (x INTEGER) STRICT;",  # fails
    })
    c = db.connect(":memory:")
    with pytest.raises(sqlite3.Error):
        db.migrate(c, db.load_migrations(d))
    assert db.current_version(c) == 1
    assert c.execute("SELECT 1 FROM sqlite_master WHERE name='b'").fetchone() is None


def test_edited_applied_migration_is_refused(tmp_path):
    d = write_migrations(tmp_path, {"0001_a.sql": "CREATE TABLE a (x INTEGER) STRICT;"})
    c = db.connect(":memory:")
    db.migrate(c, db.load_migrations(d))
    (d / "0001_a.sql").write_text("CREATE TABLE a (x INTEGER, y INTEGER) STRICT;")
    with pytest.raises(db.MigrationError, match="checksum"):
        db.migrate(c, db.load_migrations(d))


def test_database_newer_than_code_is_refused(tmp_path):
    d = write_migrations(tmp_path, {"0001_a.sql": "CREATE TABLE a (x INTEGER) STRICT;",
                                    "0002_b.sql": "CREATE TABLE b (x INTEGER) STRICT;"})
    c = db.connect(":memory:")
    db.migrate(c, db.load_migrations(d))
    (d / "0002_b.sql").unlink()
    with pytest.raises(db.MigrationError, match="does not know"):
        db.migrate(c, db.load_migrations(d))


def test_migration_numbering_gap_is_refused(tmp_path):
    d = write_migrations(tmp_path, {"0001_a.sql": "SELECT 1;", "0003_c.sql": "SELECT 1;"})
    with pytest.raises(db.MigrationError, match="gap"):
        db.load_migrations(d)


def test_up_to_stops_early():
    c = db.connect(":memory:")
    assert db.migrate(c, up_to=2) == [1, 2]
    assert db.migrate(c) == [3, 4, 5, 6]


def test_split_statements_keeps_trigger_bodies_whole():
    sql = ("-- comment\nCREATE TABLE t (x INTEGER);\n"
           "CREATE TRIGGER g AFTER INSERT ON t\nBEGIN UPDATE t SET x = 1; END;\n")
    parts = db.split_statements(sql)
    assert len(parts) == 2 and parts[1].startswith("CREATE TRIGGER") and parts[1].rstrip().endswith("END;")


def test_incomplete_statement_is_an_error():
    with pytest.raises(db.MigrationError):
        db.split_statements("CREATE TABLE t (x INTEGER")


def test_transaction_rolls_back_on_error(conn):
    with pytest.raises(RuntimeError):
        with db.transaction(conn):
            conn.execute("INSERT INTO settings(key, value, updated_ms) VALUES ('k', '1', 1)")
            raise RuntimeError("boom")
    assert conn.execute("SELECT COUNT(*) FROM settings").fetchone()[0] == 0


def test_file_database_wal_and_readonly(tmp_path):
    path = str(tmp_path / "g.db")
    c = db.connect(path)
    db.migrate(c)
    assert db.enable_wal(c) == "wal"
    c.close()
    ro = db.connect(path, readonly=True)
    assert db.current_version(ro) == 6
    with pytest.raises(sqlite3.OperationalError):
        ro.execute("DELETE FROM settings")
    ro.close()


def test_readonly_path_with_special_characters(tmp_path):
    d = tmp_path / "dir with space #1 ? x"
    d.mkdir()
    path = str(d / "g.db")
    c = db.connect(path)
    db.migrate(c)
    c.close()
    assert db.current_version(db.connect(path, readonly=True)) == 6


def test_settings_changes_bump_change_counter(conn):
    before = conn.execute("SELECT value FROM change_counters WHERE name='settings'").fetchone()[0]
    conn.execute("INSERT INTO settings(key, value, updated_ms) VALUES ('a', '1', 1)")
    conn.execute("UPDATE settings SET value='2' WHERE key='a'")
    conn.execute("DELETE FROM settings WHERE key='a'")
    assert conn.execute("SELECT value FROM change_counters WHERE name='settings'").fetchone()[0] == before + 3
