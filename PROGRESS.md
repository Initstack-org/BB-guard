# PROGRESS

Status of each stage and acceptance item for InitStack Guard. `GOAL.md` defines what "done" means; this file says where things stand. Nothing is marked done without code and tests (GOAL rule 11).

**Last updated:** 2026-11-08

## Stage status

| Stage | Deliverable | Status | Evidence |
|---|---|---|---|
| 1 | Architecture, schema, API plan | **Written, awaiting owner review** | `docs/ARCHITECTURE.md`, `docs/SUBSYSTEMS.md`, `docs/SCHEMA.md`, `docs/API.md` |
| 2 | Backend foundation (config, migrations, admin CLI, auth, sessions, CSRF, audit) | **Code written; password sign-in end to end; first green run on the Mac for the part written before the Administrators page.** Exit criterion not yet met (see below) | Library: `guard/config.py`, `db.py`, `audit.py`, `cli.py`, `auth/*`, `migrations/0001`-`0006`. Web: `guard/web/*`, templates, `static/style.css`, `cli.py serve` |
| 3 | Passkeys | Not started | |
| 4 | Traffic monitoring | **Partial: ingest library plus a CLI command.** Parser, normalizer and redaction, restart-safe tailer, transactional writer with rollups, one-pass runner, and `python -m guard ingest [--follow]` with the `GUARD_ACCESS_LOG` setting and a health heartbeat. Not run inside the service; no Nginx log config; no Visitors or URL History pages, graphs, CSV export. | `guard/ingest/*`, `guard/cli.py` `cmd_ingest`, `tests/test_ingest_*.py` (142 tests), `tests/test_cli_ingest.py` (new, not run) |
| 5 | IP intelligence and moderation | Not started (schema only: migration 0004) | |
| 6 | URL rules, block page, enforcement | Not started (schema only: migration 0005) | |
| 7 | MyBB plugin and injection manager | Not started (schema only: migration 0006) | |
| 8 | Full UI and deployment | **Partial: 5 of the 15 sidebar pages are live** (Dashboard shell, Administrators, Authentication, Audit Log, General Settings). No deployment files: `deploy/nginx` and `deploy/systemd` are empty. | `guard/web/app.py` `NAV` |
| 9 | Verification | Not started | |

Stage 1 exit criterion is "reviewed by owner". That has not happened, so Stage 1 is not complete.

Stage 2 code was started before that review (by an earlier session, not logged at the time). If the review changes the design, that code may need rework. The Stage 2 exit criterion is "all tests pass on a machine with dependencies installed; first admin can sign in". Tests passed on the Mac for everything written up to the Audit Log and account pages. Still open: nobody has run `guard serve` or signed in through a browser, the real `Argon2Hasher` has only been installed, never exercised (tests use a fake hasher), and the Administrators and General Settings tests have not been run anywhere. So the criterion is **not yet met**.

## Live dashboard pages

| Sidebar item | Route | State |
|---|---|---|
| Dashboard | `/` | Shell only, no data yet |
| Administrators | `/admins` | Built: list, create, disable, enable, set another admin's password. Tests written, not run |
| Authentication / Passkeys | `/account` | Password change, re-authentication, own sessions. **No passkeys** (Stage 3) and no profile edit (display name, time zone, theme) |
| Audit Log | `/audit` | Built: filters, keyset paging. Tests passed on the Mac |
| General Settings | `/settings` | Built: full registry, typed validation. Tests written, not run. Only `auth.*` settings are read by running code; `ingest` reads three more (`site.hosts`, `retention.rollup_min_hits`, `retention.ingest_errors_max`) but is not running anywhere |

Greyed out, no route: Visitors, IP Intelligence, URL History, IP Rules, URL Access Rules, Block Page, HTML Injections, Injection History / Versions, API Settings, Backups and Retention.

## Acceptance criteria (GOAL.md section 1)

"Not started" means no code exists. Design coverage says whether the Stage 1 docs plan the item.

| Item | Area | Design coverage | Code and tests |
|---|---|---|---|
| A | Dashboard UI | Route and page list in API.md | **Partial.** Sidebar has the exact GOAL sections; 5 of 15 pages live; dark/light follows the browser setting only. Sidebar is not collapsible; no top-bar search, notifications or breadcrumbs |
| B | Visitor monitoring | SUBSYSTEMS 2, SCHEMA 5.3, API 7.1 | **Partial.** Ingest library records every field GOAL B lists and redacts secrets (unit tests). No visitor pages, search or detail view; ingest not running |
| C | URL history | SCHEMA 5.3 and 9, API 7.3 | **Partial.** Per-URL counts and hourly rollups are written by ingest. No page, graphs or CSV export |
| D | IP intelligence and moderation | SUBSYSTEMS 3, SCHEMA 5.4, API 7.2 and 8.1 | Not started (schema only) |
| E | Enforcement scope | ARCHITECTURE 6, SUBSYSTEMS 3.4 | Not started |
| F | URL access rules | SUBSYSTEMS 4, SCHEMA 5.5, API 8.2 | Not started (schema only) |
| G | Block page editor | SUBSYSTEMS 5, SCHEMA 5.5, API 8.3 | Not started (schema only) |
| H | MyBB injection manager | SUBSYSTEMS 6, SCHEMA 5.6, API 9 | Not started (schema only) |
| I | Authentication and passkeys | SUBSYSTEMS 7, SCHEMA 5.1 and 5.2, API 4 and 5 | **Partial.** Password side done: argon2id check, lockout, sessions, CSRF and Origin checks, audit, CLI first admin, login and logout, account page, administrators page, `__Host-` cookies, route classes A/W/R, host check, trusted client IP. Not built: passkeys, passkey re-authentication, profile edit |
| J | Security and deployment | ARCHITECTURE 8 to 10, SUBSYSTEMS 8 | Not started |
| K | Data management | SCHEMA (whole file), API 10.5 | **Partial.** Migrations 0001-0006 and runner; settings registry; ingest writes the traffic tables. Not started: backup and restore, CSV export, retention and cleanup jobs |

## What has actually been run

- **Owner's Mac, Python 3.9.6, 2026-11-08 (later run): 539 passed, 0 failed** (full suite, real pytest). This includes the Administrators, General Settings, ingest and `ingest` CLI test files that had not been run before. Still never exercised: the real `Argon2Hasher`, `guard serve`, any browser sign-in, and ingest on a real log.
- **Owner's Mac, 2026-11-08, by hand (SQLite 3.54.0, Python 3.9.6):** `doctor` (clean error before the database existed, then schema 6 of 6, argon2-cffi ok), `migrate` (all six applied, WAL), `create-admin` with the **real `Argon2Hasher`**, and `ingest` on a one-line hand-made log (first pass wrote 1, second pass found nothing new). The stored row had `token=abc` redacted to `token=[redacted]`. `guard serve` started and stopped cleanly. Over curl: `/login` with the right Host returned 200 with the CSP and a `__Host-` Secure HttpOnly cookie and no Server header; a wrong or missing Host returned 421, including for `/healthz` (the 200 case for `/healthz` was not checked). Still never exercised: any browser sign-in, ingest on a real Nginx log, SQLite 3.37.
- **Earlier Mac run, Python 3.9.6, Starlette 0.49.3, pytest 8.4.2:** first run 288 collected, 286 passed, 2 failed; both failures were fixed (a real `connect(readonly=True)` bug on WAL databases, and a wrong test) and a second run passed. That covers the library layer, the web layer (50), the account page (40) and the Audit Log page (31). The code therefore runs on Python 3.9 as well as the 3.12 and 3.13 used earlier.
- **Written after the 539-test run, not run anywhere:** `tests/test_web_lan.py` (about 60 cases: client IP rules per peer and header, the LAN connection gate, sign-in and per-address throttle through a simulated connector, LAN-bind config rules) and the code it covers (`guard/config.py`, `guard/web/app.py`, `guard/cli.py`). Never tried with a real `cloudflared`.
- **Not run on the Mac (superseded by the 539-test run above):** `tests/test_web_admins.py` (about 45 cases), `tests/test_web_settings.py` (about 60), the four `tests/test_ingest_*.py` files (142 cases, including the new ones for hostile bytes), and `tests/test_cli_ingest.py` (about 25 cases: the `ingest` command and `GUARD_ACCESS_LOG`). The last file has not been run anywhere, not even in the sandbox.
- **Ingest tests, 2026-11-08T12:01Z, Claude's sandbox only** (Python 3.12.3, SQLite 3.45.1): 142 passed, using the real files copied from the Mac but a small **stand-in test runner, not pytest** (the sandbox has no pytest and no network). The stand-in was checked by breaking the code on purpose: 13 tests failed, and with the new parser fix reverted, 3 failed. It supports only fixtures, `parametrize`, `raises` and `tmp_path`. Run real `pytest` on the Mac to confirm.
- **SCHEMA.md DDL, 2026-11-08, sandbox only:** the six migrations apply to an empty database; 100 constraint, trigger and foreign-key checks pass; 26 query plans use the intended indexes on 200,000 synthetic rows (details in SCHEMA.md section 11).
- **Not run anywhere:** `Argon2Hasher`, `guard serve` and uvicorn startup, any browser sign-in, anything on SQLite 3.37 (the oldest supported), the web tests for Administrators and General Settings (the sandbox has no Starlette), any ingest run against a real Nginx log.
- Nothing has been installed or changed on the server, Nginx or MyBB.

## Bugs found by testing and fixed

- 2026-11-08: ingest could be stalled by one request. A User-Agent containing the bytes `ED A0 80` passed the parser as a lone surrogate, SQLite refused to store it, the batch rolled back and was re-read on every pass. A User-Agent with an invalid byte (for example `FF`) made the parser reject the line, so that request was never recorded. Fixed in `parser.py` and `normalize.py`, with tests. Found by reading the code, not by an earlier test.

## Open blockers and questions

Blockers for treating Stage 2 as done:
1. **Owner review of the four Stage 1 documents** (Stage 1 exit criterion).
2. **`docs/SPEC.md` is missing.** `GOAL.md` says the original requirements document is the source of truth. Everything so far is built from `GOAL.md`. If you have the document, save it as `docs/SPEC.md`.
3. **Server facts** listed in ARCHITECTURE.md section 15 and the JSON-function check in SCHEMA.md section 12. Needed before Stages 6 to 8, and to write the real Nginx `log_format`.
4. **Run `pytest` on the Mac** and report the result, so the admins, settings and ingest tests have a real run.

Not blockers yet, but needed before the stage named:
- **IPLogs authentication, rate limits and the meaning of `confidence`** are unverified. Needed before Stage 5.
- **MyBB 1.8.41 hooks and any extra login or registration steps** are unverified. Needed before Stage 7.

Decisions waiting for the owner (each document ends with its own list): ARCHITECTURE.md section 14 (Q1 to Q12), SCHEMA.md section 12, API.md section 13. Also new: **should a batch that fails for another reason be retried line by line, with the bad line set aside as an ingest error?** Today any future poison line would stall ingest again.

## Deviations from the design docs (owner to confirm)

- **Starlette instead of FastAPI** (ARCHITECTURE D1). No `/docs`, `/redoc` or `/openapi.json` exist at all; validation is hand-written.
- **Pages post HTML forms and redirect** instead of the JSON endpoints in API.md sections 5 and 10 (account, administrators, settings). Target ids and setting keys travel in form fields, not paths. Account password change is class W (it asks for the current password), not R. Every settings change is class R.
- **Not built from API.md:** `/api/v1/audit*` and the audit CSV export, `/api/v1/settings` registry endpoint, `PATCH /api/v1/admins/{id}`, `/api/v1/account` profile routes, `expected_updated_ms` lost-update checks.
- **Logout** marks the session revoked instead of deleting the row.
- **No forced password change** for a new administrator (API.md open item 1).

## Known limitations so far

The design's limitations are listed in ARCHITECTURE.md section 13. Claude cannot run commands on the Mac or the server; its sandbox lacks pytest, Starlette, FastAPI, argon2-cffi and `webauthn`, and has no network. This file records only what was actually run and by whom.

Known gaps in the web layer: the pre-session cookie lasts 15 minutes, so a login page left open longer needs a refresh; no rate limit on `/login` GET or on failed CSRF checks beyond the sign-in throttle; the sidebar is not collapsible and there is no top-bar search (Stage 8); the login page is not themed beyond `prefers-color-scheme`; `retention.*` and `backup.*` settings are shown read-only because their page is not built.

Known gaps in the library code: failed or locked sign-in attempts each write an audit row, so a flood of attempts grows the audit table until retention cleanup exists; the code sets no restrictive permissions on the database file and does not check env-file permissions (deployment scripts must); a per-username lock lets anyone who knows an admin username lock that account out of password sign-in for up to 24 hours (documented in `throttle.py`).

Known gaps in ingest: not started by the service (only by hand with the `ingest` command); `ingest --follow` is a plain loop with no systemd unit yet; a missing log file is an error for a single pass but only a warning with `--follow`; the `ingest_state` row and `component_health` heartbeat are written only when a caller runs a pass; sums in `visitors` could in theory exceed SQLite's 64-bit integer range only after about 9,000 records each at the 10^15 per-field cap, which real Nginx output cannot produce; a batch that fails for any reason other than the hostile bytes fixed above is retried unchanged forever (see the open question).
