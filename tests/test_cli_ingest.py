"""The `ingest` CLI command and the GUARD_ACCESS_LOG setting."""

import pytest

from guard import cli, db
from guard.config import ConfigError, load_config

from conftest import FakeHasher
from ingest_helpers import log_line, write_log

KEY = "cd" * 32


@pytest.fixture
def setup(tmp_path):
    log = tmp_path / "access.jsonl"
    env = tmp_path / "guard.env"
    env.write_text(f"GUARD_DB_PATH={tmp_path / 'g.db'}\nGUARD_EXTERNAL_ORIGIN=https://guard.example.org\n"
                   f"GUARD_TRUSTED_CONNECTORS=192.168.1.148\nGUARD_ACCESS_LOG={log}\n")
    sec = tmp_path / "secrets.env"
    sec.write_text(f"GUARD_SECRET_KEY={KEY}\n")
    return ["--env", str(env), "--secrets", str(sec)], tmp_path / "g.db", log


def run(setup, *args):
    out = []
    code = cli.main([*setup[0], *args], out=out.append, hasher=FakeHasher(), prompt=lambda _p: "")
    return code, "\n".join(out)


def counts(db_path):
    conn = db.connect(str(db_path), readonly=True)
    try:
        return (conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0],
                conn.execute("SELECT COUNT(*) FROM visitors").fetchone()[0])
    finally:
        conn.close()


def test_one_pass_ingests_and_a_second_pass_finds_nothing_new(setup):
    run(setup, "migrate")
    write_log(setup[2], 5)
    code, out = run(setup, "ingest")
    assert code == 0 and "lines=5 written=5 duplicates=0 bad_lines=0" in out
    assert counts(setup[1]) == (5, 1)
    code, out = run(setup, "ingest")
    assert code == 0 and "lines=0 written=0" in out
    assert counts(setup[1]) == (5, 1)


def test_later_passes_read_only_the_new_lines(setup):
    run(setup, "migrate")
    write_log(setup[2], 3)
    run(setup, "ingest")
    write_log(setup[2], 2, start=3)
    code, out = run(setup, "ingest")
    assert code == 0 and "lines=2 written=2" in out
    assert counts(setup[1])[0] == 5


def test_a_bad_line_is_counted_not_fatal(setup):
    run(setup, "migrate")
    write_log(setup[2], 2)
    with open(setup[2], "ab") as fh:
        fh.write(b"this is not json\n")
    write_log(setup[2], 1, start=2)
    code, out = run(setup, "ingest")
    assert code == 0 and "written=3" in out and "bad_lines=1" in out
    assert counts(setup[1])[0] == 3


def test_health_is_recorded_after_a_pass(setup):
    run(setup, "migrate")
    write_log(setup[2], 1)
    run(setup, "ingest")
    conn = db.connect(str(setup[1]), readonly=True)
    row = conn.execute("SELECT state, heartbeat_ms, last_ok_ms FROM component_health WHERE component='ingest'").fetchone()
    conn.close()
    assert row["state"] == "ok" and row["heartbeat_ms"] and row["last_ok_ms"]


def test_no_access_log_setting_is_a_clean_error(tmp_path):
    env = tmp_path / "guard.env"
    env.write_text(f"GUARD_DB_PATH={tmp_path / 'g.db'}\nGUARD_EXTERNAL_ORIGIN=https://guard.example.org\n")
    sec = tmp_path / "secrets.env"
    sec.write_text(f"GUARD_SECRET_KEY={KEY}\n")
    files = ["--env", str(env), "--secrets", str(sec)]
    out = []
    cli.main([*files, "migrate"], out=out.append)
    out.clear()
    assert cli.main([*files, "ingest"], out=out.append) == 1 and "GUARD_ACCESS_LOG" in out[0]


def test_ingest_before_migrate_says_to_migrate(setup):
    write_log(setup[2], 1)
    code, out = run(setup, "ingest")
    assert code == 1 and "migrate" in out


def test_missing_log_file_is_reported_not_treated_as_empty(setup):
    run(setup, "migrate")
    code, out = run(setup, "ingest")
    assert code == 1 and "does not exist" in out


@pytest.mark.parametrize("interval", ["0", "3601", "-5"])
def test_bad_interval_is_rejected(setup, interval):
    run(setup, "migrate")
    write_log(setup[2], 1)
    code, out = run(setup, "ingest", "--follow", "--interval", interval)
    assert code == 1 and "--interval" in out


def test_follow_keeps_reading_until_interrupted(setup, monkeypatch):
    run(setup, "migrate")
    write_log(setup[2], 2)
    sleeps = []

    def fake_sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 1:
            write_log(setup[2], 3, start=2)  # new traffic arrives while Guard is waiting
        else:
            raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_sleep", fake_sleep)
    code, out = run(setup, "ingest", "--follow", "--interval", "7")
    assert code == 0 and sleeps == [7, 7]
    assert "lines=2 written=2" in out and "lines=3 written=3" in out and "ingest: stopped" in out
    assert counts(setup[1])[0] == 5


def test_follow_survives_a_vanishing_log_and_reports_the_error_once(setup, monkeypatch):
    run(setup, "migrate")
    write_log(setup[2], 1)
    calls = []

    def boom(*a, **k):
        raise OSError("disk went away")

    def fake_sleep(_s):
        calls.append(1)
        if len(calls) >= 3:
            raise KeyboardInterrupt

    from guard.ingest import runner
    monkeypatch.setattr(runner, "drain", boom)
    monkeypatch.setattr(cli, "_sleep", fake_sleep)
    code, out = run(setup, "ingest", "--follow")
    assert code == 0 and out.count("will retry") == 1  # three failed passes, one message
    conn = db.connect(str(setup[1]), readonly=True)
    row = conn.execute("SELECT state, last_error FROM component_health WHERE component='ingest'").fetchone()
    conn.close()
    assert row["state"] == "error" and "disk went away" in row["last_error"]


def test_one_pass_failure_exits_nonzero_and_records_health(setup, monkeypatch):
    run(setup, "migrate")
    write_log(setup[2], 1)

    def boom(*a, **k):
        raise OSError("permission denied")

    from guard.ingest import runner
    monkeypatch.setattr(runner, "drain", boom)
    code, out = run(setup, "ingest")
    assert code == 1 and "permission denied" in out


def test_connections_are_closed_after_ingest(setup):
    run(setup, "migrate")
    write_log(setup[2], 1)
    run(setup, "ingest")
    assert cli._open_connections == []


# --- GUARD_ACCESS_LOG in the configuration ---

def _env(**over):
    base = {"GUARD_DB_PATH": "/x.db", "GUARD_EXTERNAL_ORIGIN": "https://guard.example.org",
            "GUARD_SECRET_KEY": KEY}
    base.update(over)
    return base


def test_access_log_defaults_to_empty():
    assert load_config(environ=_env()).access_log == ""


def test_access_log_is_read():
    assert load_config(environ=_env(GUARD_ACCESS_LOG="/var/log/nginx/guard/access.jsonl")).access_log \
        == "/var/log/nginx/guard/access.jsonl"


@pytest.mark.parametrize("path", ["access.jsonl", "./access.jsonl", "~/access.jsonl", "/a\0b"])
def test_access_log_must_be_absolute(path):
    with pytest.raises(ConfigError, match="GUARD_ACCESS_LOG"):
        load_config(environ=_env(GUARD_ACCESS_LOG=path))
