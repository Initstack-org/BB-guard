"""guard-admin: operator commands, run on the server as the service user.

    python -m guard.cli [--env FILE] [--secrets FILE] <command>

Commands: doctor, migrate, create-admin, reset-password, list-admins, ingest, serve.
Passwords are read with a no-echo prompt only: never from argv, the environment or a pipe.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
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


def cmd_ingest(args, out, **_) -> int:
    """Read new lines from the Nginx JSON spool file into the database (docs/SUBSYSTEMS.md section 2).

    One pass by default (catches up, prints a summary, exits). With --follow it keeps going until
    interrupted, which is what a systemd unit would run until ingest is built into the service.
    """
    from .ingest import runner  # noqa: PLC0415
    cfg, conn = _open(args)
    if not cfg.access_log:
        out("error: GUARD_ACCESS_LOG is not set (the Nginx JSON access log to read)")
        return 1
    version = db.current_version(conn)
    if version != len(db.load_migrations()):
        out(f"error: database schema is at version {version}; run the migrate command first")
        return 1
    if args.interval < 1 or args.interval > 3600:
        out("error: --interval must be between 1 and 3600 seconds")
        return 1

    def summary(res) -> str:
        return (f"lines={res.lines} written={res.written} duplicates={res.duplicates} "
                f"bad_lines={res.bad_lines} peer_mismatches={res.peer_mismatches} gaps={res.gaps}")

    def one_pass():
        """Returns (result, None) or (None, error text). Health is recorded either way."""
        try:
            res = runner.drain(conn, cfg.access_log, cfg.trusted_connectors)
            runner.record_health(conn, ok=True)
            return res, None
        except (db.sqlite3.Error, OSError) as exc:
            text = f"{type(exc).__name__}: {exc}"
            try:
                runner.record_health(conn, ok=False, error=text)
            except db.sqlite3.Error:
                pass  # the database itself is the problem; the error is still reported below
            return None, text

    if not args.follow:
        if not os.path.isfile(cfg.access_log):
            out(f"error: ingest failed: {cfg.access_log} does not exist or is not a file")
            return 1
        res, err = one_pass()
        if err:
            out(f"error: ingest failed: {err}")
            return 1
        out("ingest: " + summary(res))
        return 0

    out(f"ingest: following {cfg.access_log} every {args.interval}s (Ctrl-C to stop)")
    if not os.path.isfile(cfg.access_log):
        out("warning: the log file does not exist yet; waiting for it")
    last_error = None
    try:
        while True:
            res, err = one_pass()
            if err and err != last_error:
                out(f"error: ingest failed: {err} (will retry)")
            elif res is not None and not res.idle:
                out("ingest: " + summary(res))
            last_error = err
            _sleep(args.interval)
    except KeyboardInterrupt:
        out("ingest: stopped")
    return 0


_sleep = time.sleep  # tests replace this


def cmd_serve(args, out, **_) -> int:
    """Run the dashboard listener (Stage 2 web layer). The internal listener comes in Stage 6."""
    try:
        import uvicorn  # noqa: PLC0415
    except ImportError:
        out("error: uvicorn is not installed (pip install uvicorn)")
        return 1
    from .web.app import create_app  # noqa: PLC0415
    cfg = load_config(args.env, args.secrets)
    conn = db.connect(cfg.db_path, readonly=True)
    try:
        version = db.current_version(conn)
    finally:
        conn.close()
    if version != len(db.load_migrations()):
        out(f"error: database schema is at version {version}; run the migrate command first")
        return 1
    app = create_app(cfg)  # raises MissingDependency when argon2-cffi is not installed
    host, port = cfg.dashboard_bind
    tls = {}
    if cfg.tls_cert:
        for path in (cfg.tls_cert, cfg.tls_key):
            if not os.path.isfile(path):
                out(f"error: TLS file {path} does not exist")
                return 1
        tls = {"ssl_certfile": cfg.tls_cert, "ssl_keyfile": cfg.tls_key}
    out(f"dashboard listening on {host}:{port} (origin {cfg.external_origin})"
        + (" with TLS" if tls else ""))
    if cfg.dashboard_on_lan:
        out(f"note: LAN listener. Only loopback and these trusted connectors may connect: "
            f"{', '.join(cfg.trusted_connectors)}. Their CF-Connecting-IP header is used as the client address.")
    # No proxy header handling and no access log: client IP rules live in guard.web.app.client_ip,
    # and request lines are not logged (docs/ARCHITECTURE.md section 8, GOAL.md rule 12).
    ingest_thread = None
    if not cfg.access_log:
        out("note: GUARD_ACCESS_LOG is not set, so no requests are being recorded")
    elif getattr(args, "no_ingest", False):
        out("note: ingest is off (--no-ingest); run the ingest command separately to record requests")
    else:
        from .ingest.service import IngestThread  # noqa: PLC0415
        ingest_thread = IngestThread(cfg.db_path, cfg.access_log, cfg.trusted_connectors, report=out)
        ingest_thread.start()
        out(f"ingest: reading {cfg.access_log} in the background every {ingest_thread.interval_s:g}s")
    try:
        uvicorn.run(app, host=host, port=port, proxy_headers=False, server_header=False, access_log=False,
                    **tls)
    finally:
        if ingest_thread is not None:
            ingest_thread.stop()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guard", formatter_class=argparse.RawDescriptionHelpFormatter,
        description="InitStack Guard: operator commands. Run migrate first on a new database, then "
                    "create-admin, then serve.",
        epilog="Settings come from --env and --secrets files (KEY=VALUE) and GUARD_* environment variables.\n"
               "Passwords are typed at a terminal prompt only.\n"
               "Docs: README.md (install and commands), PROGRESS.md (status), CHANGES.md (log), docs/.\n"
               "Run `guard <command> --help` for a command's own options.")
    parser.add_argument("--env", default=os.environ.get("GUARD_ENV_FILE"),
                        help="non-secret settings file (default: $GUARD_ENV_FILE)")
    parser.add_argument("--secrets", default=os.environ.get("GUARD_SECRETS_FILE"),
                        help="secrets file (default: $GUARD_SECRETS_FILE)")
    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")
    sub.add_parser("doctor", help="check SQLite, argon2-cffi, configuration and schema version"
                   ).set_defaults(func=cmd_doctor)
    sub.add_parser("migrate", help="apply pending database migrations and enable WAL mode"
                   ).set_defaults(func=cmd_migrate)
    p = sub.add_parser("create-admin", help="create an administrator (how the first one is made)")
    p.add_argument("username")
    p.add_argument("--display-name", help="name shown in the dashboard")
    p.set_defaults(func=cmd_create_admin)
    p = sub.add_parser("reset-password", help="set a new password and sign that administrator out")
    p.add_argument("username")
    p.set_defaults(func=cmd_reset_password)
    sub.add_parser("list-admins", help="list administrators").set_defaults(func=cmd_list_admins)
    p = sub.add_parser("ingest", help="read the Nginx JSON access log into the database")
    p.add_argument("--follow", action="store_true", help="keep running instead of one pass")
    p.add_argument("--interval", type=int, default=5, help="seconds between passes with --follow (default 5)")
    p.set_defaults(func=cmd_ingest)
    p = sub.add_parser("serve", help="run the dashboard (and ingest, when GUARD_ACCESS_LOG is set)")
    p.add_argument("--no-ingest", action="store_true",
                   help="do not read the access log in the background")
    p.set_defaults(func=cmd_serve)
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
