import sqlite3

import pytest

from guard import cli, db
from guard.auth.passwords import MissingDependency

from conftest import GOOD_PW, FakeHasher

KEY = "cd" * 32


@pytest.fixture
def files(tmp_path):
    env = tmp_path / "guard.env"
    env.write_text(f"GUARD_DB_PATH={tmp_path / 'g.db'}\nGUARD_EXTERNAL_ORIGIN=https://guard.example.org\n")
    sec = tmp_path / "secrets.env"
    sec.write_text(f"GUARD_SECRET_KEY={KEY}\n")
    return ["--env", str(env), "--secrets", str(sec)], tmp_path / "g.db"


def run(files, *args, passwords=(), hasher=None):
    out, it = [], iter(passwords)
    code = cli.main([*files[0], *args], out=out.append, hasher=hasher or FakeHasher(),
                    prompt=lambda _p: next(it))
    return code, "\n".join(out)


def test_migrate_then_doctor(files):
    code, out = run(files, "doctor")  # before migrate the database does not exist: report it, do not crash
    assert code == 1 and "configuration or database" in out
    code, out = run(files, "migrate")
    assert code == 0 and "[1, 2, 3, 4, 5, 6]" in out and "wal" in out
    assert run(files, "migrate")[1].startswith("applied migrations: none")
    code, out = run(files, "doctor")
    assert "schema version 6 of 6" in out and "RP ID: guard.example.org" in out


def test_create_admin_list_and_reset(files):
    run(files, "migrate")
    code, out = run(files, "create-admin", "alice", "--display-name", "Alice", passwords=[GOOD_PW, GOOD_PW])
    assert code == 0 and "created administrator alice" in out and GOOD_PW not in out
    code, out = run(files, "list-admins")
    assert code == 0 and "alice\tenabled" in out
    code, out = run(files, "reset-password", "alice", passwords=["another long passphrase"] * 2)
    assert code == 0 and "sessions were revoked" in out
    conn = db.connect(str(files[1]))
    actions = [r[0] for r in conn.execute("SELECT action FROM audit_events ORDER BY id")]
    assert actions == ["admin.create", "admin.password_reset"]
    actor = conn.execute("SELECT actor_name FROM audit_events").fetchone()[0]
    assert actor.startswith("cli:")
    text = " ".join(str(tuple(r)) for t in ("admins", "audit_events") for r in conn.execute(f"SELECT * FROM {t}"))
    assert GOOD_PW not in text and "another long passphrase" not in text


def test_mismatched_passwords_create_nothing(files):
    run(files, "migrate")
    code, out = run(files, "create-admin", "alice", passwords=[GOOD_PW, "different one entirely"])
    assert code == 1 and "did not match" in out
    assert "alice" not in run(files, "list-admins")[1]


def test_weak_password_and_bad_username_are_reported(files):
    run(files, "migrate")
    assert "at least 12" in run(files, "create-admin", "alice", passwords=["short", "short"])[1]
    assert run(files, "create-admin", "x y", passwords=[GOOD_PW, GOOD_PW])[0] == 1


def test_duplicate_admin_and_unknown_reset(files):
    run(files, "migrate")
    run(files, "create-admin", "alice", passwords=[GOOD_PW] * 2)
    assert "taken" in run(files, "create-admin", "ALICE", passwords=[GOOD_PW] * 2)[1]
    assert run(files, "reset-password", "nobody")[1] == "no such administrator"


def test_commands_before_migrate_give_a_friendly_error_not_a_traceback(files):
    for args, pw in ((("create-admin", "alice"), [GOOD_PW] * 2), (("list-admins",), []), (("reset-password", "a"), [])):
        code, out = run(files, *args, passwords=pw)
        assert code == 1 and "migrate" in out, (args, out)


def test_missing_config_is_a_clean_error(tmp_path):
    code = cli.main(["--env", str(tmp_path / "nope.env"), "migrate"], out=lambda _m: None)
    assert code == 1


def test_missing_setting_is_a_clean_error(tmp_path):
    env = tmp_path / "e.env"
    env.write_text("GUARD_DB_PATH=/x\n")
    out = []
    assert cli.main(["--env", str(env), "migrate"], out=out.append) == 1 and "missing required setting" in out[0]


def test_doctor_reports_missing_argon2(files, monkeypatch):
    def boom(*a, **k):
        raise MissingDependency("argon2-cffi is not installed (pip install argon2-cffi)")
    monkeypatch.setattr(cli, "Argon2Hasher", boom)
    run(files, "migrate")
    code, out = run(files, "doctor")
    assert code == 1 and "argon2-cffi is not installed" in out


def test_default_hasher_missing_dependency_is_clean(files, monkeypatch):
    def boom(*a, **k):
        raise MissingDependency("argon2-cffi is not installed")
    monkeypatch.setattr(cli, "Argon2Hasher", boom)
    run(files, "migrate")
    out = []
    code = cli.main([*files[0], "create-admin", "alice"], out=out.append, prompt=lambda _p: GOOD_PW)
    assert code == 1 and "argon2" in out[0]


def test_connections_are_closed_after_each_command(files):
    run(files, "migrate")
    assert cli._open_connections == []


def test_passwords_are_refused_when_stdin_is_not_a_terminal(files, monkeypatch):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO(GOOD_PW + "\n" + GOOD_PW + "\n"))
    run(files, "migrate")
    out = []
    code = cli.main([*files[0], "create-admin", "alice"], out=out.append, hasher=FakeHasher())
    assert code == 1 and "terminal" in out[0]
