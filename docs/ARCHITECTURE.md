# InitStack Guard: Architecture

> **Status:** Stage 1 draft v0.1, written 2026-11-08, awaiting owner review.
> **Source:** `GOAL.md` only. The original requirements document (`docs/SPEC.md`) was not available. Where this file and the spec disagree, the spec wins and this file gets fixed.
> **Companion docs:** [SUBSYSTEMS.md](SUBSYSTEMS.md) (detailed designs), [SCHEMA.md](SCHEMA.md) (SQLite schema), [API.md](API.md) (route plan).
> **Nothing described here is built, installed or applied to any server yet.**

## Contents
1. What is being built
2. Context and trust boundaries
3. Key decisions
4. Process model
5. How one request is handled
6. Decision pipeline
7. What happens when something fails
8. Trusted client IP
9. Nginx integration (sketch)
10. Deployment layout
11. Repository layout
12. How each stage will be verified
13. Known limitations
14. Open questions and the assumption used for each
15. Facts to collect from the server

---

## 1. What is being built

InitStack Guard is a self-hosted control panel for `initstack.org`. Nginx records every request it handles. Guard reads those records into SQLite, shows them in a dashboard, decides allow or deny for each request from local data only, serves a custom block page, manages MyBB HTML injections through a small MyBB plugin, and protects its own login with passkeys. No paid services. The only outbound calls are to IPLogs and the Tor Project.

## 2. Context and trust boundaries

```
 Visitors --> Cloudflare --> cloudflared connector --> Nginx (Ubuntu server)
                             192.168.1.148                |
                             the ONLY trusted source      |
                             of CF-Connecting-IP          |
        +-------------------------------------------------+---------------------+
        | forum server block (initstack.org)              | dashboard server block
        |  1. real_ip sets the client IP                  | (proposed: guard.initstack.org)
        |  2. auth_request -> 127.0.0.1:8788 /check       |  proxy_pass -> 127.0.0.1:8787
        |  3. deny -> block page; allow -> PHP-FPM/MyBB   |
        |  4. JSON access log -> spool file               |
        v                                                 v
  MyBB + Guard plugin <-- export/mybb-injections.json -- Guard (one process, user "guard")
  (adds X-Guard-Uid / X-Guard-User                        dashboard :8787 | internal :8788
   response headers; Nginx logs and hides them)           ingest, lookups, Tor feed, jobs
                                                          SQLite (WAL)
                                                               | outbound HTTPS only
                                                               v
                                                   iplogs.com   check.torproject.org
```

- **Internet and Cloudflare:** untrusted.
- **Tunnel connector (192.168.1.148):** trusted for exactly one thing, the `CF-Connecting-IP` header. Every other peer's forwarded headers are ignored.
- **Nginx:** trusted. The only caller of Guard's internal listener.
- **Guard:** runs as an unprivileged user with no sudo. It never edits Nginx or MyBB files. Deployment scripts (run by an operator) do that, with backups.
- **MyBB and PHP-FPM:** a separate trust domain. It can read Guard's export file but cannot write it, and Guard never reads the MyBB database (so it never needs the MyBB DB password).
- **Outbound:** only the two hard-coded endpoints above. No user-supplied URLs are ever fetched.

## 3. Key decisions

All are proposals for the owner to confirm or overrule.

| # | Decision | Why (and what was rejected) |
|---|---|---|
| D1 | Python 3.12 (3.10+ tolerated), FastAPI + Uvicorn, Jinja2, stdlib `sqlite3`, `webauthn` (py_webauthn), `argon2-cffi`, `httpx`. Versions pinned. | Maintained libraries only; WebAuthn and password hashing are never hand-rolled. Flask has fewer validation tools; Django is heavier and does not fit the planned folder layout. |
| D2 | One Guard process with two loopback listeners: dashboard `127.0.0.1:8787`, internal `127.0.0.1:8788`. | The internal routes (`/check`, `/block`, health) cannot be reached through the public dashboard vhost, by construction. One process keeps the rule snapshot and passkey challenges in memory with no cross-process sync. |
| D3 | Enforcement is Nginx `auth_request` to the internal listener. Answers come from an in-memory snapshot. Tight timeouts, fail open. | Meets "no external calls in the request path" and "fails open when Guard is down". Fallback if fail-open cannot be proven in Stage 6: Guard writes Nginx deny/map include files and an operator reloads. |
| D4 | Monitoring comes from Nginx's own JSON access log, not from `/check`. | Recording continues while Guard is down and catches up after restart. |
| D5 | The decision stored for a request is the one Guard returned at the time. Ingest never re-derives it. | One source of truth. |
| D6 | SQLite in WAL mode. All timestamps are integer epoch milliseconds in UTC. Conversion to the admin's timezone happens only when displaying. | No timezone ambiguity; cheap range scans. |
| D7 | Server-side sessions. The database stores only a SHA-256 of the cookie token. The CSRF token is derived from the session. | A leaked database cannot be used to hijack a session. |
| D8 | WebAuthn challenges live in process memory only: single use, 5-minute expiry. | Rule 1 (never store challenge data). Cost: a restart cancels pending sign-ins, which is harmless. |
| D9 | Secrets live only in `secrets.env`. The web UI shows whether a secret is configured but never edits one. Secrets are set with `guard-admin secrets set`. | Rule 12; smaller blast radius if the dashboard is compromised. |
| D10 | The dashboard gets its own hostname (proposed `guard.initstack.org`), not a path on the forum. | The forum serves user content and admin-injected JavaScript. A separate origin keeps the admin session away from it and gives WebAuthn a stable RP ID. Needs owner decision (Q1). |
| D11 | MyBB gets injections from a plugin reading an atomically replaced JSON file. Guard learns the MyBB user from a response header the plugin adds. | No Nginx body rewriting, no MyBB DB access, no cookie parsing. |
| D12 | The block page runs no JavaScript (enforced by CSP). Placeholders are filled by strict substitution, never by Jinja. | Prevents template injection and script execution on the forum origin. |
| D13 | Backups use the SQLite online backup API from a systemd timer. Restore is CLI-only. | A web-triggered restore that replaces the live database is too dangerous. |
| D14 | One admin role in v1 (all admins equal). | Roles were not requested. The `role` column is reserved. |

## 4. Process model

- systemd runs `python -m guard` as user `guard` (service `initstack-guard`).
- Inside the process: the dashboard app, the internal app, and background tasks: log tailer and ingest writer, IP-lookup worker, Tor feed updater, rule-expiry sweeper, snapshot reconciler.
- `/check` is `async`, touches neither the database nor the network, and reads an immutable **Snapshot** (IP rules, compiled URL rules, cached reputation, Tor set, settings). A new Snapshot is built and swapped in atomically whenever any of those change, and reconciled against the database every 30 seconds. Target latency is under 1 ms.
- Dashboard handlers are plain `def` functions run in the threadpool, each with its own read connection. Writes go through one writer connection behind a lock. The ingest writer commits in batches.
- Single worker by design. Not horizontally scalable, and it does not need to be for one forum.
- systemd timers run short-lived CLI jobs: nightly backup, weekly maintenance.

## 5. How one request is handled

1. Visitor, Cloudflare, connector (192.168.1.148), Nginx.
2. Nginx `real_ip`: because the peer is the trusted connector, `$remote_addr` becomes the `CF-Connecting-IP` value. For any other peer the header is ignored.
3. `auth_request` sends a bodyless subrequest to `127.0.0.1:8788/check` carrying the client IP, method, host and raw request URI. Timeouts are short (connect 250 ms, read 500 ms).
4. Guard normalizes the URL, runs the decision pipeline (section 6) against the Snapshot, and answers `204` (allow) or `403` (deny) with `X-Guard-*` headers saying what happened. If the IP has no cached verdict, Guard queues a background lookup. It never waits for one.
5. **Deny:** Nginx `error_page 403` goes to an internal location that proxies to `/block`. Guard renders the published block page and returns `403`, `Cache-Control: no-store` and a restrictive CSP.
6. **Allow:** the request goes on to PHP-FPM and MyBB. The Guard plugin adds `X-Guard-Uid` and `X-Guard-User` response headers when a MyBB user is logged in. Nginx logs them and strips them before the response leaves.
7. **Always:** Nginx appends one JSON line to the spool file (no cookies, authorization headers or bodies).
8. Guard's tailer reads new lines, redacts and normalizes them, and commits visitor, URL, request and rollup rows plus the new file offset in one transaction.
9. A newly seen public IP gets a lookup queued (IPLogs, rate limited, in the background). The result is cached and used by later `/check` calls. It is never used to delay the request that triggered it.

## 6. Decision pipeline

A pure function `decide(ip, method, host, raw_uri, now, snapshot)`. No I/O.

**Layer 0, preconditions.** A host outside `site.hosts` is allowed and not managed. If the global `enforcement.mode` is `monitor_only`, every deny below is downgraded to `monitored` and the request passes.

**Layer 1, manual IP rule** (one per IP; no row means "IPLogs-only"):

| Mode | Effect |
|---|---|
| none (IPLogs-only) | Layer 3 applies normally. |
| `allow` | Layer 3 is skipped. If layer 3 would have denied, the request is recorded as `overridden` with the suppressed reason. |
| `block` | Deny site-wide, detection `manual_ip_block`. Layers 2 and 3 are not reached. |
| `monitor` | Layer 3 is skipped. If it would have denied, the request is recorded as `monitored` with the suppressed reason. |

**Layer 2, URL rules** (global and per-IP, evaluated independently of layer 1). The winning rule decides: deny gives detection `url_rule`. An `allow` rule only counters a broader URL deny; it does not touch layers 1 or 3. Matching and precedence are in SUBSYSTEMS.md section 4.

**Layer 3, reputation** (only on enforcement paths, default `member.php?action=login|do_login|register|do_register`, plus any extra real steps found in MyBB 1.8.41 during Stage 7). Inputs are the cached IPLogs result and the Tor set. The policy decides per category (Tor, VPN, proxy, relay) with a configurable minimum confidence. **Hosting and crawler flags are informational and can never cause a deny.** Missing, errored or expired data (beyond the stale grace) means "unknown", and unknown means allow.

When several layers would deny, the reported reason is the first in this order: IP block, URL rule, reputation.

Request outcome vocabulary: `allowed`, `denied`, `overridden`, `monitored`, and `unchecked` (Nginx logged the request but Guard did not answer, for example because it was down).

## 7. What happens when something fails

| Failure | Forum | Enforcement | Monitoring |
|---|---|---|---|
| Guard down or slower than the timeouts | Unaffected (fails open) | Paused entirely, including manual blocks and URL rules | Nginx still logs; ingest catches up on restart; those rows are `unchecked` |
| IPLogs down, rate limited or slow | Unaffected | Reputation falls back to stale cache within the grace period, then "unknown" (allow). Manual IP and URL rules are unaffected | None |
| Tor feed update fails or fails validation | Unaffected | Last-known-good list keeps being used; UI shows its age | None |
| SQLite slow or locked | Unaffected (`/check` uses memory) | Snapshot refresh delayed | Ingest pauses; the spool file keeps growing |
| Spool file missing or rotated unexpectedly | Unaffected | None | Tailer re-syncs; a gap notice appears in the UI |
| Disk full | Nginx keeps serving | None | Ingest stalls; notification |
| MyBB export file missing or invalid | Unaffected | None | MyBB user unknown; no injections applied (plugin fails safe) |

## 8. Trusted client IP

- Nginx's `real_ip` module is the only place trust is decided: `set_real_ip_from 192.168.1.148; real_ip_header CF-Connecting-IP;`.
- The JSON log records both `$remote_addr` (after real_ip) and `$realip_remote_addr` (the actual peer). Ingest checks them: if the peer is not a trusted connector, it uses the peer address and counts a mismatch.
- The dashboard vhost sets `X-Guard-Client-Ip $remote_addr` (overwriting anything the client sent). The dashboard listener honours that header only when the TCP peer is loopback; otherwise it uses the peer address.
- Guard never reads `X-Forwarded-For`, `CF-Connecting-IP` or similar itself.
- Stage 9 tests: a request from an untrusted peer carrying a forged `CF-Connecting-IP` is logged and decided under the peer's address.

## 9. Nginx integration (sketch)

Illustrative only, to be validated in Stage 6 against the server's real Nginx build. Nothing is applied until backups exist and `nginx -t` passes, and changes are loaded with `reload`, never `restart`.

```nginx
# http{} level
set_real_ip_from 192.168.1.148;
real_ip_header   CF-Connecting-IP;
real_ip_recursive off;

upstream guard_internal { server 127.0.0.1:8788; keepalive 16; }

log_format guard_json escape=json
  '{"t":"$msec","ip":"$remote_addr","peer":"$realip_remote_addr","m":"$request_method",'
  '"h":"$host","u":"$request_uri","s":"$status","bi":"$request_length","bo":"$bytes_sent",'
  '"d":"$request_time","ua":"$http_user_agent","ref":"$http_referer","id":"$request_id",'
  '"gd":"$guard_decision","gt":"$guard_detection","gr":"$guard_rule","gx":"$guard_reason",'
  '"bd":"$upstream_http_x_guard_block_decision","bt":"$upstream_http_x_guard_block_detection",'
  '"br":"$upstream_http_x_guard_block_rule","bx":"$upstream_http_x_guard_block_reason",'
  '"uid":"$upstream_http_x_guard_uid","un":"$upstream_http_x_guard_user"}';

# forum server{}
access_log /var/log/nginx/guard/access.jsonl guard_json buffer=32k flush=2s;
auth_request /_guard/check;
auth_request_set $guard_decision  $upstream_http_x_guard_decision;
auth_request_set $guard_detection $upstream_http_x_guard_detection;
auth_request_set $guard_rule      $upstream_http_x_guard_rule;
auth_request_set $guard_reason    $upstream_http_x_guard_reason;
error_page 403 = @guard_block;
# existing MyBB handling stays as it is, plus:
#   fastcgi_hide_header X-Guard-Uid;  fastcgi_hide_header X-Guard-User;

location = /_guard/check {
    internal;
    proxy_pass http://guard_internal/check;
    proxy_http_version 1.1;  proxy_set_header Connection "";
    proxy_pass_request_body off;  proxy_set_header Content-Length "";
    proxy_set_header X-Guard-Ip     $remote_addr;
    proxy_set_header X-Guard-Method $request_method;
    proxy_set_header X-Guard-Host   $host;
    proxy_set_header X-Guard-Uri    $request_uri;
    proxy_connect_timeout 250ms;  proxy_read_timeout 500ms;
    proxy_intercept_errors on;
    error_page 500 502 503 504 = @guard_open;      # fail open
}
location @guard_open  { internal; return 204; }
location @guard_block {
    internal;  auth_request off;
    proxy_pass http://guard_internal/block;        # same X-Guard-* request headers as above
}
```

Points Stage 6 must prove against the real build, not assume:
- `error_page` inside the `auth_request` subrequest really converts a dead or slow Guard into an allow.
- Nginx resets some per-request module state on internal redirects, so the `$guard_*` variables may be empty for denied requests. The design therefore also logs the `X-Guard-Block-*` headers from the `/block` response, and ingest merges the two sets.
- The `Ubuntu nginx` package includes `ngx_http_realip_module` and `ngx_http_auth_request_module` (check with `nginx -V`).

Do not log `$http_cookie`, `$http_authorization`, `$request_body` or `$cookie_*`. A test will scan the shipped config for them.

## 10. Deployment layout

| Path | Owner and mode | Contents |
|---|---|---|
| `/opt/initstack-guard/` | `root:guard` 0750 | Code and virtualenv (read-only to the service) |
| `/etc/initstack-guard/guard.env` | `root:guard` 0640 | Non-secret config (bind addresses, external origin, trusted connectors, paths) |
| `/etc/initstack-guard/secrets.env` | `guard:guard` 0600 | Secrets (session key, optional API credentials) |
| `/var/lib/initstack-guard/` | `guard:guard` 0700 | `guard.sqlite3` (+ `-wal`, `-shm`) |
| `/var/lib/initstack-guard/export/` | `guard:<php group>` 0750; file 0640 | `mybb-injections.json` (readable by PHP, not writable) |
| `/var/log/nginx/guard/` | `root:guard` 0750; files 0640 | `access.jsonl` spool, rotated daily, 3 days kept |
| `/var/backups/initstack-guard/` | `guard:guard` 0700 | Database backups; `rollback/` (root) holds timestamped copies of any Nginx or MyBB file before it is changed |

The service logs to journald (no log files, no secrets). The unit file is hardened (`NoNewPrivileges`, `ProtectSystem=strict`, `ReadWritePaths` limited to the data and backup directories, `PrivateTmp`, `ProtectHome`, empty capability set, address families limited to UNIX/IPv4/IPv6). Exact values are finalized in Stage 8.

## 11. Repository layout

```
guard/
  GOAL.md  CHANGES.md  PROGRESS.md  README.md (Stage 8)
  docs/            SPEC.md (missing)  ARCHITECTURE.md  SUBSYSTEMS.md  SCHEMA.md  API.md
  guard/           the Python package
    config.py  db.py  audit.py  cli.py  __main__.py
    migrations/    0001_core.sql ... 0006_injections.sql (see SCHEMA.md section 5)
    auth/          passwords, sessions, csrf, passkeys, ratelimit
    ingest/        tailer, parser, redact, normalize, writer, rollup
    intel/         iplogs client, tor feed, cache, policy, lookup worker
    rules/         ip rules, url rules, matcher, engine, snapshot
    enforce/       internal app (/check, /block), block page rendering
    mybb/          injection export
    jobs/          backup, retention, maintenance
    web/           dashboard app, routes, templates/, static/
  mybb_plugin/     PHP plugin source (inc/plugins/initstack_guard.php)
  deploy/          nginx/  systemd/  scripts/ (install, upgrade, backup, restore, rollback, uninstall)
  tests/           unit/  integration/  fixtures/  nginx/
```

## 12. How each stage will be verified

| Stage | Evidence that will exist | Run with |
|---|---|---|
| 2 | Tests for hashing and rehash, sessions (expiry, revoke), CSRF accept and reject, rate limits, audit events, migrations on a fresh DB, `create-admin` CLI | `pytest` |
| 3 | WebAuthn tests with a software authenticator built on `cryptography`: valid registration and sign-in; wrong challenge, origin or RP ID; bad signature; missing user verification; sign-count regression; unknown or revoked credential | `pytest` |
| 4 | Parser, redaction and URL-normalization tests with hostile fixtures; tailer tests (rotation, partial line, restart mid-batch, bad lines); URL-history queries; CSV export including formula-injection cases | `pytest` |
| 5 | IPLogs client against recorded fixtures (ok, 429, timeout, bad JSON, the 8.8.8.8 hosting-only case); cache TTL and stale grace; policy matrix; Tor feed validation and last-known-good | `pytest`, no network |
| 6 | Rule-resolution tables; safety-rail tests; block page render and escaping; preview and block-page headers; Nginx test with a throwaway instance (allow, deny, Guard stopped, forged header) | `pytest` plus an `nginx` binary (skipped if absent) |
| 7 | Export-schema tests; `php -l` on the plugin; MyBB 1.8.41 test install: activate and deactivate leave templates clean, all-page and path scopes work | scripts plus manual checklist |
| 8 | Install, upgrade, backup, restore, rollback and uninstall scripts exercised on a scratch machine or in dry-run mode | `shellcheck` plus checklist |
| 9 | Full test run, lint, route-authorization sweep, spoofed-header tests, outage tests, honest limitations list | `pytest`, `ruff` |

Claude can read and write files on this Mac but cannot run commands on it, and its own sandbox lacks FastAPI, webauthn, argon2 and pytest and has no network. So: pure-Python logic (normalization, redaction, matching, policy) will be written to import without third-party packages so it can be smoke-tested in the sandbox, but the full suite is run by the owner, and `PROGRESS.md` records only what has actually been run and by whom.

## 13. Known limitations

1. **First request from a new IP gets no reputation verdict**, because lookups are never synchronous. The lookup starts when Guard first sees the IP (on any page), so by the time a visitor reaches the registration form it is usually cached, but this is not guaranteed.
2. **While Guard is down nothing is enforced**, including manual blocks. Logging continues. (Optional later hardening: export permanent manual blocks as Nginx rules.)
3. **Cloudflare-cached responses never reach Nginx**, so they are neither logged nor enforceable. "Every request" means every request that reaches Nginx.
4. **Byte counts are Nginx's view**: `$request_length` (request line, headers, body) and `$bytes_sent` (response headers and body) on the connection from the connector. They are not edge or wire bytes. The UI says so.
5. **MyBB user identity** exists only once the plugin is installed and only for requests PHP handles (not static files).
6. **Raw query strings sit briefly in the Nginx spool file** before Guard redacts them. The spool is 0640, kept 3 days. Nginx's existing default logs are outside Guard's control and should be reviewed separately.
7. **A compromised connector host could forge client IPs.** That is the cost of trusting `CF-Connecting-IP` from it.
8. **SQLite is single-writer.** The design is sized for roughly 100k requests per day; beyond that, retention and rollups need tuning.
9. **Scanner traffic creates many distinct URLs.** Bounded by path-length caps, retention and orphan cleanup.
10. **Block page scripts never run** (CSP). Injection scripts do run, in visitors' browsers, and the UI says so.
11. **Passkeys are tied to the dashboard hostname.** Changing it invalidates them; password login and CLI recovery remain.
12. **Reputation quality is IPLogs's.** The meaning of its `confidence` field is not yet verified (see SUBSYSTEMS.md section 3).
13. **Development is on macOS, production on Ubuntu.** The Nginx integration tests need Linux or a Homebrew `nginx`.

## 14. Open questions and the assumption used for each

Work proceeds on the assumption shown until the owner says otherwise.

| # | Question | Assumption used |
|---|---|---|
| Q1 | Dashboard hostname and exposure? | Dedicated `guard.initstack.org` through the same Cloudflare tunnel. LAN-only or a path on the forum are alternatives. |
| Q2 | Does a manual IP block deny the whole site or only login and registration? | Whole site. |
| Q3 | Does an IP Allow override also bypass URL deny rules? | No. URL rules are separate; use a per-IP URL allow rule for exceptions. |
| Q4 | Single IPs only, or CIDR ranges too? | Single IPs only. |
| Q5 | Need a read-only admin role? | No; one role. |
| Q6 | Which hosts are managed? | `initstack.org` and `www.initstack.org`. |
| Q7 | Default reputation policy at login and registration? | Block Tor, block IPLogs `vpn_detected` and proxies; flag only `vpn_likely` and relay; hosting never blocks. |
| Q8 | Traffic volume and retention? | At most 100k requests per day; raw requests 90 days, hourly rollups 2 years, audit log 1 year. |
| Q9 | Notifications? | In-app only, derived from component health (feed stale, lookup failures, backup failed, ingest lag). No email or webhooks (out of scope). |
| Q10 | Appeal URL? | Blank. The placeholder renders empty and the default page hides the appeal line. |
| Q11 | Backups? | Nightly, keep 14 daily and 8 weekly, local disk only. No off-box copy unless asked. |
| Q12 | Server OS, Python and SQLite versions? | Ubuntu 22.04 or newer, Python 3.10+, SQLite 3.37+ (checked by `guard-admin doctor`). |

## 15. Facts to collect from the server

Needed before Stages 6 to 8. I cannot run commands on the server, so please paste the output when ready.

- OS and tool versions: `lsb_release -a`, `python3 --version`, `python3 -c "import sqlite3; print(sqlite3.sqlite_version)"`.
- `nginx -V` (to confirm the realip and auth_request modules) and the current `initstack.org` server block(s) and config layout.
- How cloudflared reaches Nginx (host, port, scheme) and whether `real_ip` is already configured.
- MyBB root path and version, the PHP-FPM pool user and group, and any `open_basedir` setting.
- Free disk space and current Nginx log retention.
