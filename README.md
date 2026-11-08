# InitStack Guard

A self-hosted control panel for `initstack.org`. It records every HTTP request that passes through
Nginx, moderates IPs (IPLogs, a Tor exit-node feed and manual rules), enforces URL access rules with
a custom block page, manages MyBB HTML/topbar injections, and is protected by its own
passkey-capable login. No paid services.

**Status: early development.** Only the Stage 2 library layer exists (configuration, database
migrations, audit log, password sign-in logic, sessions, CSRF checks, and an admin command-line
tool). There is **no web application yet**, so nothing can be installed or deployed. See
[PROGRESS.md](PROGRESS.md) for exactly what is done and what has been run, and
[CHANGES.md](CHANGES.md) for the running log.

## Documents

| File | What it is |
|---|---|
| [GOAL.md](GOAL.md) | What "done" means: acceptance criteria, rules, stage plan |
| [PROGRESS.md](PROGRESS.md) | Where each stage and criterion stands, open blockers |
| [CHANGES.md](CHANGES.md) | Log of major changes |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Design decisions, trust boundaries, known limitations |
| [docs/SUBSYSTEMS.md](docs/SUBSYSTEMS.md) | Detailed design of each subsystem |
| [docs/SCHEMA.md](docs/SCHEMA.md) | Database schema |
| [docs/API.md](docs/API.md) | Routes and route classes |

`docs/SPEC.md` (the original requirements document) is not in the repository yet.

## Layout

```
guard/              Python package
  auth/             passwords, sessions, throttle, CSRF, account service
  migrations/       SQL migrations 0001 to 0006
  config.py         env-file configuration
  db.py             SQLite helpers and migration runner
  audit.py          append-only audit log writer
  cli.py            admin command-line tool
tests/              pytest suite
deploy/             nginx and systemd files (empty so far)
docs/               design documents
```

## Requirements

- Python 3.10 or newer
- SQLite 3.37 or newer, with the JSON functions (the schema uses STRICT tables)
- `argon2-cffi` (password hashing)
- `pytest` (tests only)

There is no pinned requirements file yet. For now:

```
python3 -m venv .venv
. .venv/bin/activate
pip install argon2-cffi pytest
```

## Run the tests

```
pytest
```

The tests use a fake password hasher, so they pass without `argon2-cffi`. The real
`Argon2Hasher` is not covered by them. Tests have so far been run only in Claude's sandbox
(see PROGRESS.md), not on a Mac or the server.

## Configuration

Guard reads two plain `KEY=VALUE` files (parsed, never executed). Real environment variables
beginning with `GUARD_` override file values.

`guard.env` (not secret):

```
GUARD_DB_PATH=/var/lib/guard/guard.db
GUARD_EXTERNAL_ORIGIN=https://guard.example.org
GUARD_TRUSTED_CONNECTORS=192.168.1.148
# optional, loopback only (defaults shown)
GUARD_DASHBOARD_BIND=127.0.0.1:8787
GUARD_INTERNAL_BIND=127.0.0.1:8788
GUARD_EXPORT_DIR=
GUARD_BACKUP_DIR=
```

`secrets.env` (keep it out of git; restrict its permissions, e.g. `chmod 600`):

```
GUARD_SECRET_KEY=<64 hex characters>
```

Generate a key with:

```
python3 -c "import secrets; print(secrets.token_hex(32))"
```

`GUARD_EXTERNAL_ORIGIN` must be `https://host` with no path. Its hostname is used as the WebAuthn
RP ID.

## Admin command-line tool

```
python -m guard --env guard.env --secrets secrets.env <command>
```

| Command | What it does |
|---|---|
| `doctor` | Checks the SQLite build, argon2-cffi, configuration and schema version |
| `migrate` | Applies pending migrations and enables WAL mode |
| `create-admin USERNAME [--display-name NAME]` | Creates an administrator (this is how the first one is made; there is no public registration) |
| `reset-password USERNAME` | Sets a new password and revokes that admin's sessions |
| `list-admins` | Lists administrators |

Passwords are typed at a terminal prompt only. They are never taken from arguments, the
environment, or a pipe. Run `migrate` before any other command that touches the database.

## Not built yet

Web application and login routes, passkeys, traffic ingest and visitor/URL history, IP
intelligence and moderation, URL rules, block page, MyBB plugin and injections, dashboard UI,
install/upgrade/backup/restore/rollback/uninstall scripts. Install, backup, restore and rollback
instructions will be added here when those exist.

## Known limitations

Design limitations are listed in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) section 13. Gaps found
in the current code are listed at the end of [PROGRESS.md](PROGRESS.md).
