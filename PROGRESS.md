# PROGRESS

Status of each stage and acceptance item for InitStack Guard. `GOAL.md` defines what "done" means; this file says where things stand. Nothing is marked done without code and tests (GOAL rule 11).

**Last updated:** 2026-11-08T08:56Z

## Stage status

| Stage | Deliverable | Status | Evidence |
|---|---|---|---|
| 1 | Architecture, schema, API plan | **Written, awaiting owner review** | `docs/ARCHITECTURE.md`, `docs/SUBSYSTEMS.md`, `docs/SCHEMA.md`, `docs/API.md` |
| 2 | Backend foundation (config, migrations, admin CLI, auth, sessions, CSRF, audit) | **Code written for password sign-in end to end; not yet run on the Mac or server** | Library layer: `guard/config.py`, `db.py`, `audit.py`, `cli.py`, `auth/*`, `migrations/0001`-`0006`, 129 tests. Web layer: `guard/web/app.py`, templates, `static/style.css`, `cli.py serve`, `tests/test_web.py` (50 tests) and `tests/web_client.py`. All passed in Claude's sandbox only. |
| 3 | Passkeys | Not started | |
| 4 | Traffic monitoring | Not started | |
| 5 | IP intelligence and moderation | Not started | |
| 6 | URL rules, block page, enforcement | Not started | |
| 7 | MyBB plugin and injection manager | Not started | |
| 8 | Full UI and deployment | Not started | |
| 9 | Verification | Not started | |

Stage 1 exit criterion is "reviewed by owner". That has not happened, so Stage 1 is not complete.

Stage 2 code was started before that review (by an earlier session, not logged at the time; found on 2026-11-08). If the review changes the design, that code may need rework. The Stage 2 exit criterion is "all tests pass on a machine with dependencies installed; first admin can sign in". The code for that now exists (CLI creates the admin, `serve` starts the dashboard, `/login/password` signs in), but nobody has run it on a real machine with argon2-cffi, so the criterion is **not yet met**. Passkey sign-in is Stage 3 and is not built.

## Acceptance criteria (GOAL.md section 1)

"Not started" means no code exists. Design coverage says whether the Stage 1 docs plan the item.

| Item | Area | Design coverage | Code and tests |
|---|---|---|---|
| A | Dashboard UI | Route and page list in API.md; layout details left to Stage 8 | Not started |
| B | Visitor monitoring | SUBSYSTEMS 2, SCHEMA 5.3, API 7.1 | Not started |
| C | URL history | SCHEMA 5.3 and 9, API 7.3 | Not started |
| D | IP intelligence and moderation | SUBSYSTEMS 3, SCHEMA 5.4, API 7.2 and 8.1 | Not started |
| E | Enforcement scope | ARCHITECTURE 6, SUBSYSTEMS 3.4 | Not started |
| F | URL access rules | SUBSYSTEMS 4, SCHEMA 5.5, API 8.2 | Not started |
| G | Block page editor | SUBSYSTEMS 5, SCHEMA 5.5, API 8.3 | Not started |
| H | MyBB injection manager | SUBSYSTEMS 6, SCHEMA 5.6, API 9 | Not started |
| I | Authentication and passkeys | SUBSYSTEMS 7, SCHEMA 5.1 and 5.2, API 4 and 5 | **Partial.** Code and tests (sandbox): argon2id password check, lockout, sessions, CSRF and Origin checks, audit, CLI first admin, login and logout routes, `__Host-` cookies, route classes A/W/R, host check, trusted client IP. Not built: passkeys, the account page (change password, sessions list), re-authentication routes, and the pre-session cookie is not yet tied to anything beyond the login CSRF token. |
| J | Security and deployment | ARCHITECTURE 8 to 10, SUBSYSTEMS 8 | Not started |
| K | Data management | SCHEMA (whole file), API 10.5 | **Partial.** Migrations 0001-0006 and the migration runner have code and tests (sandbox). Not started: backup and restore, CSV export, retention and cleanup jobs. |

## What has actually been run

- **SCHEMA.md DDL, 2026-11-08, in Claude's sandbox only** (SQLite 3.45.1, Python 3.12.3 standard library): the six migrations apply to an empty database; 100 constraint, trigger and foreign-key checks pass; 26 query plans use the intended indexes on 200,000 synthetic rows. Details and limits are in SCHEMA.md section 11. The scripts were scratch files, not kept in the project.
- **Stage 2 test suite, 2026-11-08, in Claude's sandbox only** (Python 3.13.18, SQLite 3.53.1, pytest 9.1.1): 129 passed. The sandbox could not copy files from the Mac, so Claude rebuilt the package there from the file contents it read, ran the tests, then applied the fixes to the Mac files and checked the byte sizes match. Tests use a fake password hasher.
- **Web layer tests, 2026-11-08T08:56Z, in Claude's sandbox only** (Python 3.13.18, Starlette 1.7.0, Jinja2 3.1.6, pytest 9.1.1): 50 passed. They drive the ASGI app directly with a small client in `tests/web_client.py` (httpx is not needed). They cover sign-in success and failure, identical errors for unknown user and wrong password, login CSRF (missing, wrong, other browser's token), Origin/Referer checks, lockout with `Retry-After`, session idle expiry, disabled accounts, logout revoking the session server-side, CSRF tokens bound to a session, the host check (421), loopback-only `X-Guard-Client-Ip`, forged `X-Forwarded-For` and `CF-Connecting-IP` having no effect, cookie flags, security headers and CSP, static path traversal, `/docs` `/redoc` `/openapi.json` returning 404, internal paths not existing on the dashboard, and a route sweep (every route has a class; unauthenticated, no-CSRF, wrong-Origin and expired-session requests are refused; class R refuses a session older than 300 s). To run them here, Claude rebuilt a trimmed copy of the earlier library modules in the sandbox, so the sandbox ran those copies, not the files on the Mac. The new web files on the Mac were checked against the sandbox copies by byte size (all match).
- **Not run anywhere:** `Argon2Hasher` (argon2-cffi was not installed in the sandbox), `guard-admin serve` and `uvicorn` startup (the `serve` command was written but never executed), the web tests against the real six migrations (the sandbox had only a trimmed 0001), anything on SQLite 3.37 (the oldest supported version), anything on the Mac or the server.
- Nothing has been installed or changed on the server, Nginx or MyBB.

## Open blockers and questions

Blockers for starting Stage 2:
1. **Owner review of the four Stage 1 documents** (Stage 1 exit criterion).
2. **`docs/SPEC.md` is missing.** `GOAL.md` says the original requirements document is the source of truth, and it was not available to this project. Everything so far is built from `GOAL.md`. If you have the document, save it as `docs/SPEC.md` so the design can be checked against it.
3. **Server facts** listed in ARCHITECTURE.md section 15 (OS, Python and SQLite versions, `nginx -V`, existing server block, cloudflared route, MyBB and PHP-FPM details, free disk) and the JSON-function check in SCHEMA.md section 12.

Not blockers yet, but needed before the stage named:
- **IPLogs authentication, rate limits and the meaning of `confidence`** are unverified (the official docs page could not be fetched). Needed before Stage 5.
- **MyBB 1.8.41 hooks and any extra login or registration steps** are unverified. Needed before Stage 7.

Decisions waiting for the owner (each document ends with its own list):
- ARCHITECTURE.md section 14: Q1 to Q12 (dashboard hostname, whether a manual block covers the whole site, CIDR support, retention, and so on). Work proceeds on the stated assumptions.
- SCHEMA.md section 12: disk and retention, per-URL rollup threshold, new settings, hard-deleted passkeys, admins never deleted.
- API.md section 13: how a new administrator gets an initial password, whether injection preview may run scripts, no backup download, the new limits and re-authentication list.

## Known limitations so far

The design's limitations are listed in ARCHITECTURE.md section 13 (for example: no verdict for the first request from a new IP, nothing enforced while Guard is down, Cloudflare-cached responses never reach Nginx). Claude cannot run commands on the Mac or the server. Its sandbox has pytest but lacks argon2-cffi, FastAPI and `webauthn`, so anything needing those, and any run on the Mac or server, has to be done by the owner. This file records only what was actually run and by whom.

Known gaps in the Stage 2 web layer: session idle (30 min), absolute (12 h) and re-authentication (5 min) limits are constants in `guard/web/app.py`, not yet read from settings (only `auth.password_login_enabled` is read); the pre-session cookie lasts 15 minutes and a login page left open longer needs a refresh; there is no rate limit on `/login` GET or on failed CSRF checks beyond the sign-in throttle; the sidebar is not collapsible and has no top-bar search (Stage 8); the login page is not themed beyond prefers-color-scheme.

Known gaps in the Stage 2 library code, found while testing and not fixed: failed or locked sign-in attempts each write an audit row, so a flood of attempts grows the audit table until retention cleanup (retention is not built yet); the code does not set restrictive permissions on the database file or check the permissions of the env files (deployment scripts must do it, GOAL section 1.J); a per-username lock lets anyone who knows an admin username lock that account out of password sign-in for up to 24 hours (documented in `throttle.py`).
