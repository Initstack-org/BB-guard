"""guard-admin: operator commands, run on the server as the service user.

    python -m guard.cli [--env FILE] [--secrets FILE] <command>

Commands: doctor, migrate, create-admin, reset-password, list-admins.
Passwords are read with a no-echo prompt only: never from argv, the environment or a pipe.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from typing import Callable

from . import db
from .auth import service
from .auth.passwords import Argon2Hasher, Hasher, MissingDependency
from .config import ConfigError, load_config


def _prompt_new_password(prompt: Callable[[str], str]) -> str:
    first = prompt("New password: ")
    if first != prompt("Repeat password: "):
        raise service.AccountError("the two passwords did not match")
    return first


def _tty_prompt(text: str) -> str:
    """getpass falls back to reading a pipe (with only a warning), so refuse that explicitly."""
    if not sys.stdin.isatty():
        raise service.AccountError("passwords can only be typed at a terminal, not read from a pipe or file")
    return getpass.getpass(text)


_open_connections: list = []


def _open(args, *, readonly: bool = False):
    cfg = load_config(args.env, args.secrets)
    conn = db.connect(cfg.db_path, readonly=readonly)
    _open_connections.append(conn)
    return cfg, conn


def cmd_doctor(args, out, **_) -> int:
    problems = db.check_sqlite()
    out(f"SQLite {db.sqlite3.sqlite_version}: " + ("ok" if not problems else "; ".join(problems)))
    try:
        Argon2Hasher()
        out("argon2-cffi: ok")
    except MissingDependency as exc:
        problems.append(str(exc))
        out(f"argon2-cffi: {exc}")
    try:
        cfg, conn = _open(args, readonly=True)
    except (ConfigError, OSError, db.sqlite3.Error) as exc:
        out(f"configuration or database: {exc}")
        return 1
    version = db.current_version(conn)
    latest = len(db.load_migrations())
    out(f"schema version {version} of {latest}" + ("" if version == latest else " (run: migrate)"))
    out(f"database: {cfg.db_path}; RP ID: {cfg.rp_id}")
    return 0 if not problems else 1


def cmd_migrate(args, out, **_) -> int:
    problems = db.check_sqlite()
    if problems:
        out("; ".join(problems))
        return 1
    cfg, conn = _open(args)
    applied = db.migrate(conn)
    mode = db.enable_wal(conn)
    out(f"applied migrations: {applied or 'none'}; journal mode {mode}")
    return 0


def cmd_create_admin(args, out, hasher: Hasher, prompt, **_) -> int:
    cfg, conn = _open(args)
    password = _prompt_new_password(prompt)
    admin_id = service.create_admin(
        conn, hasher, args.username, password, now_ms=db.now_ms(), display_name=args.display_name or "",
        actor_name=f"cli:{getpass.getuser()}")
    out(f"created administrator {args.username} (id {admin_id})")
    return 0


def cmd_reset_password(args, out, hasher: Hasher, prompt, **_) -> int:
    cfg, conn = _open(args)
    row = conn.execute("SELECT id FROM admins WHERE username = ?", (args.username,)).fetchone()
    if row is None:
        out("no such administrator")
        return 1
    password = _prompt_new_password(prompt)
    service.set_password(conn, hasher, row["id"], password, now_ms=db.now_ms(),
                         actor_name=f"cli:{getpass.getuser()}", action="admin.password_reset")
    out(f"password reset for {args.username}; their sessions were revoked")
    return 0


def cmd_list_admins(args, out, **_) -> int:
    cfg, conn = _open(args, readonly=True)
    for row in conn.execute("SELECT id, username, is_disabled, last_login_ms FROM admins ORDER BY id"):
        out(f"{row['id']}\t{row['username']}\t{'disabled' if row['is_disabled'] else 'enabled'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="guard-admin")
    parser.add_argument("--env", default=os.environ.get("GUARD_ENV_FILE"))
    parser.add_argument("--secrets", default=os.environ.get("GUARD_SECRETS_FILE"))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor").set_defaults(func=cmd_doctor)
    sub.add_parser("migrate").set_defaults(func=cmd_migrate)
    p = sub.add_parser("create-admin")
    p.add_argument("username")
    p.add_argument("--display-name")
    p.set_defaults(func=cmd_create_admin)
    p = sub.add_parser("reset-password")
    p.add_argument("username")
    p.set_defaults(func=cmd_reset_password)
    sub.add_parser("list-admins").set_defaults(func=cmd_list_admins)
    return parser


def main(argv=None, *, out=print, hasher: Hasher | None = None, prompt=_tty_prompt) -> int:
    args = build_parser().parse_args(argv)
    try:
        if hasher is None and args.command in ("create-admin", "reset-password"):
            hasher = Argon2Hasher()
        return args.func(args, out, hasher=hasher, prompt=prompt)
    except (ConfigError, service.AccountError, db.MigrationError, MissingDependency) as exc:
        out(f"error: {exc}")
        return 1
    except db.sqlite3.Error as exc:
        out(f"error: database problem: {exc}. If this database is new, run the migrate command first.")
        return 1
    finally:
        while _open_connections:
            _open_connections.pop().close()


if __name__ == "__main__":
    sys.exit(main())
