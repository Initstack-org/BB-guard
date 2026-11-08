# InitStack Guard

A self-hosted control panel for `initstack.org`. It records every HTTP request that passes through
Nginx, moderates IPs (IPLogs, a Tor exit-node feed and manual rules), enforces URL access rules with
a custom block page, manages MyBB HTML/topbar injections, and is protected by its own
passkey-capable login. No paid services.

**Status: early development. Not installable or deployable yet.** What exists: configuration,
database migrations, an audit log, password sign-in, sessions, CSRF checks, an admin command-line
tool, a first dashboard (sign-in plus five pages, below), and a library that turns Nginx JSON access
logs into database rows (not wired to anything yet). See [PROGRESS.md](PROGRESS.md) for exactly what
is done and what has been run, and [CHANGES.md](CHANGES.md) for the running log.

## Documents

| File | What it is |
|---|---|
| [GOAL.md](GOAL.md) | What "done" means: acceptance criteria, rules, stage plan |
| [PROGRESS.md](PROGRESS.md) | Where each stage and criterion stands, what was run, open blockers |
| [CHANGES.md](CHANGES.md) | Log of major changes |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Design decisions, trust boundaries, known limitations |
| [docs/SUBSYSTEMS.md](docs/SUBSYSTEMS.md) | Detailed design of each subsystem |
| [docs/SCHEMA.md](docs/SCHEMA.md) | Database schema |
| [docs/API.md](docs/API.md) | Routes and route classes (a plan; section 0 says what is built) |

`docs/SPEC.md` (the original requirements document) is not in the repository yet.

## What works today

Dashboard pages (sign in with an administrator created from the command line):

| Page | Route | Notes |
|---|---|---|
| Dashboard | `/` | Shell only, no data yet |
| Administrators | `/admins` | Create, disable, enable, set another administrator's password |
| Authentication | `/account` | Change password, confirm password again, sign out other sessions. No passkeys yet |
| Audit Log | `/audit` | Filter and page through audit events |
| General Settings | `/settings` | Edit typed, validated settings. Only the `auth.*` settings affect running code so far |

The other ten sidebar items are shown greyed out. Ingest (`guard/ingest/`) can be run by hand with
`python -m guard ingest` (see the command table); nothing starts it automatically yet.

## Layout

```
guard/              Python package
  auth/             passwords, sessions, throttle, CSRF, account service
  ingest/           Nginx JSON log -> SQLite: parser, normalize/redact, tailer, writer, runner
  migrations/       SQL migrations 0001 to 0006
  web/              Starlette app, page modules, templates/, static/
  config.py         env-file configuration
  db.py             SQLite helpers and migration runner
  audit.py          append-only audit log writer
  cli.py            admin command-line tool
tests/              pytest suite
deploy/             nginx and systemd files (empty so far)
docs/               design documents
```

## Requirements

- Python 3.10 or newer is the target. The tests also passed on Python 3.9.6 on the owner's Mac
  (`zoneinfo` needs the system time zone database or the `tzdata` package).
- SQLite 3.37 or newer, with the JSON functions (the schema uses STRICT tables)
- `argon2-cffi` (password hashing)
- `starlette`, `jinja2`, `uvicorn` (dashboard; the web tests skip themselves when Starlette is missing)
- `pytest` (tests only)

There is no pinned requirements file yet. For now:

```
python3 -m venv .venv
. .venv/bin/activate
pip install starlette jinja2 uvicorn argon2-cffi pytest
```

## Run the tests

```
pytest
```

The tests use a fake password hasher, so they pass without `argon2-cffi`; the real `Argon2Hasher`
is not covered. The web tests drive the app directly and do not need `httpx`. PROGRESS.md lists which
test files have been run, where, and which have not.

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
# Nginx JSON access log read by `ingest` (absolute path; the design uses the path below)
GUARD_ACCESS_LOG=/var/log/nginx/guard/access.jsonl
# Optional: let the tunnel connector reach the dashboard directly (see "Behind a Cloudflare tunnel")
# GUARD_DASHBOARD_ALLOW_LAN=1
# GUARD_DASHBOARD_BIND=192.168.1.50:8787
# Optional: serve HTTPS from Guard itself (local testing; see "Trying it locally")
# GUARD_TLS_CERT=/absolute/path/tls.crt
# GUARD_TLS_KEY=/absolute/path/tls.key
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
RP ID, and the dashboard answers `421` to any request whose `Host` header is not that hostname.
Session cookies are `Secure` and use the `__Host-` prefix, so the dashboard is meant to be reached
over HTTPS through Nginx. Signing in over plain HTTP on `localhost` is untested and may not work in
every browser.

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
| `ingest [--follow] [--interval N]` | Reads new lines from `GUARD_ACCESS_LOG` into the database. One pass by default; `--follow` repeats every N seconds (default 5) until Ctrl-C. Records an `ingest` health heartbeat. Needs `migrate` first. Never run against a real Nginx log yet |
| `serve` | Runs the dashboard on `GUARD_DASHBOARD_BIND`. Refuses to start while migrations are pending. Never run on a real machine yet |

Passwords are typed at a terminal prompt only. They are never taken from arguments, the
environment, or a pipe. Run `migrate` before any other command that touches the database.

## Trying it locally (no proxy)

The dashboard needs HTTPS in the browser. For local testing, Guard can serve HTTPS itself with a
throwaway self-signed certificate (your browser will warn once):

```
cat > .local/tls.cnf <<'EOF'
[req]
distinguished_name=dn
x509_extensions=v3
prompt=no
[dn]
CN=localhost
[v3]
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
openssl req -x509 -newkey rsa:2048 -nodes -keyout .local/tls.key -out .local/tls.crt -days 30 -config .local/tls.cnf
```

then in `guard.env`: `GUARD_EXTERNAL_ORIGIN=https://localhost:8787`, `GUARD_TLS_CERT` and
`GUARD_TLS_KEY` as absolute paths to those two files. Run `serve` and open `https://localhost:8787`.
Do not use a self-signed certificate in production; there, HTTPS is Cloudflare's.

## Behind a Cloudflare tunnel (no Nginx in front of the dashboard)

The browser talks HTTPS to Cloudflare; `cloudflared` can then talk plain HTTP to Guard. Guard's
`Secure` cookies and `https://` origin refer to what the browser sees, so this works. Settings:

```
GUARD_EXTERNAL_ORIGIN=https://guard.initstack.org
GUARD_TRUSTED_CONNECTORS=192.168.1.148
GUARD_DASHBOARD_ALLOW_LAN=1
GUARD_DASHBOARD_BIND=<this machine's private address>:8787
```

and point the tunnel's ingress for `guard.initstack.org` at `http://<that address>:8787`.
Cloudflared passes the public hostname as `Host`, which the host check requires.

What Guard does in this mode:

- Only a **specific private IP address** is accepted for the bind (never `0.0.0.0`, never a public
  address or a name), and `GUARD_TRUSTED_CONNECTORS` must be set. The internal listener can never be
  on the LAN.
- **Only loopback and the trusted connectors can connect.** Any other machine on the LAN gets a bare
  `403` before the login page. This is enforced by Guard itself, so it does not depend on a firewall
  (a firewall rule limiting the port to the connector is still sensible).
- When the connection really comes from a trusted connector, Guard uses its `CF-Connecting-IP`
  header as the client address, so the sign-in throttle and the audit log see each visitor's own
  address instead of lumping everyone together as the connector. A missing or malformed header falls
  back to the connector's address. `X-Forwarded-For` and every other header are ignored, and
  `CF-Connecting-IP` is ignored from every other peer.
- The traffic between the connector and Guard is plain HTTP on your LAN. Anyone who can sniff that
  segment can read sign-in forms. Keep it on a trusted network.

## Not built yet

Passkeys; running ingest inside the service; Visitors, IP Intelligence and URL History pages,
graphs and CSV export; IP intelligence and moderation; URL rules and enforcement; the block page;
the MyBB plugin and injections; the internal listener Nginx calls; Backups and Retention and API
Settings pages; install, upgrade, backup, restore, rollback and uninstall scripts and the Nginx and
systemd files. Install, backup, restore and rollback instructions will be added here when those
exist.

## Known limitations

Design limitations are listed in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) section 13. Gaps found
in the current code, and everything that has and has not been run, are in
[PROGRESS.md](PROGRESS.md).
