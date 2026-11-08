# InitStack Guard: Route Plan (API)

> **Status:** Stage 1 draft v0.1, written 2026-11-08, awaiting owner review. Partly implemented since: see section 0.
> **Source:** `GOAL.md`, [ARCHITECTURE.md](ARCHITECTURE.md), [SUBSYSTEMS.md](SUBSYSTEMS.md) and [SCHEMA.md](SCHEMA.md). `docs/SPEC.md` was not available; where it disagrees with this file, the spec wins.
> **The sections after section 0 are the plan, not a description of the code.** Paths, field names and limits are proposals.

## 0. Implementation status (2026-11-08T12:01Z)

Built, on Starlette rather than FastAPI (so `/docs`, `/redoc` and `/openapi.json` do not exist at all), with every route registered under one class (P, A, W or R) and a test sweep that fails on any route without one:

| Route | Class | Differs from this plan |
|---|---|---|
| `GET /login`, `POST /login/password`, `GET /healthz`, `/static` | P | None. Passkey sign-in routes are not built |
| `POST /logout` | W | Session row is marked revoked, not deleted |
| `GET /` | A | Shell only |
| `GET /account`, `POST /api/v1/account/password`, `POST /api/v1/reauth/password`, `POST /api/v1/account/sessions/revoke`, `POST /api/v1/account/sessions/revoke-others` | A / W | HTML form posts that redirect, not JSON. Password change is W, not R. Session revoke takes `session_id` in the form, not the path. Profile, passkey and passkey re-authentication routes not built |
| `GET /admins`, `POST /api/v1/admins`, `/api/v1/admins/disable`, `/enable`, `/password` | A / R | Form posts; `admin_id` in the form, not the path. No JSON list, no display-name edit |
| `GET /audit` | A | The page queries the database itself. `/api/v1/audit*` and the audit CSV export are not built |
| `GET /settings`, `POST /api/v1/settings/set`, `/api/v1/settings/reset` | A / R | Every change is class R; key in the form; no JSON registry endpoint and no `expected_updated_ms` |

Not built at all: the internal listener (section 3), sections 6 (except `/`), 7, 8 and 9, API Settings (10.3) and Backups and Retention (10.5). Which tests have been run, and where, is in `PROGRESS.md`.

## Contents
1. Listeners and conventions
2. Route classes (authentication, CSRF, rate limits)
3. Internal listener (Nginx only)
4. Public dashboard routes and sign-in
5. Account, passkeys and sessions
6. Overview, search, notifications, health
7. Traffic: visitors, requests, IP intelligence, URL history, exports
8. Security: IP rules, URL access rules, block page
9. MyBB: injections
10. Administration: administrators, audit log, settings, backups and retention
11. Audit action names
12. Route authorization sweep (Stage 9 test)
13. Open items for the owner

---

## 1. Listeners and conventions

**Two listeners, one process** (decision D2).

| Listener | Bind | Reached by | Contains |
|---|---|---|---|
| Dashboard | `127.0.0.1:8787` | Nginx vhost for the dashboard hostname (proposed `guard.initstack.org`) | Pages, JSON API, preview endpoints, static files |
| Internal | `127.0.0.1:8788` | The forum server block's `auth_request` and `error_page` only | `/check`, `/block`, `/healthz`, `/readyz` |

The internal routes do not exist on the dashboard listener, so they cannot be reached through the public vhost by construction.

**Dashboard rules that apply to every route**
- **Host check.** Requests whose `Host` is not the configured dashboard hostname get `421` and are not logged as admin activity.
- **Client IP.** The dashboard honours `X-Guard-Client-Ip` only when the TCP peer is loopback (ARCHITECTURE section 8). It never reads `X-Forwarded-For` or `CF-Connecting-IP`.
- **No generated API docs.** FastAPI's `/docs`, `/redoc` and `/openapi.json` are disabled in production (they would describe every route to anyone who can reach the vhost).
- **Pages vs JSON.** Pages are server-rendered Jinja2 (autoescape on). Data for tables and charts is fetched from `/api/v1/...` JSON endpoints by script served from `/static/` (no inline scripts, no third-party scripts).
- **Headers.** Every response: `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, `Cache-Control: no-store` for pages and JSON. Pages: `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`. Preview responses use their own CSP (section 8.3).
- **Time.** Timestamps in JSON are integer epoch milliseconds UTC (`*_ms`). Query parameters use `from_ms` and `to_ms`, or `range` (`24h`, `7d`, `30d`). The UI converts to the admin's timezone.
- **IPs** in paths and bodies must parse as an IP address and are canonicalized (SCHEMA section 1) before use. Anything else is `400`.

**JSON conventions**
- Success: `{"data": ...}`. Lists add `"page": {"size": n, "next": cursor-or-null, "total": n-or-null}`.
- Error: `{"error": {"code": "...", "message": "...", "fields": {"name": "reason"}}}`. `fields` appears only for validation errors. Messages never echo secrets or request bodies.
- Status codes: `400` validation, `401` not signed in (pages redirect to `/login` instead), `403` forbidden / CSRF failure / re-authentication needed (`code: reauth_required`), `404`, `409` conflict (duplicate rule, stale `base_version`, last-admin rule), `413` body too large, `429` rate limited with `Retry-After`, `503` writer busy.
- **Pagination.** Default page size 50, maximum 200. Lists over `requests` and `audit_events` use a keyset cursor on `(ts_ms, id)` (offset paging would slow down as the tables grow). Small tables (rules, admins, passkeys, injections, versions) use `page` and `size`.
- **Sorting** uses an allow-list per endpoint: `sort=<column>` and `dir=asc|desc`. Anything not on the list is `400`.
- **Range limits.** Raw-request queries accept at most 7 days per call; longer ranges read rollups only (SUBSYSTEMS 2.8). Every query has a hard row limit.
- **Lost updates.** Editable resources return `updated_ms`. `PUT` for IP rules, URL rules and settings may send `expected_updated_ms`; a mismatch is `409`. Injection saves send `base_version` (section 9).
- **Request body cap.** 64 KB by default; 256 KB for block page and injection saves (their ceilings are 200 KB and 3 x 100 KB in the schema).

---

## 2. Route classes

Every route is registered with exactly one class. A route with no class fails the Stage 9 sweep (section 12).

| Class | Meaning | Authentication | CSRF | Notes |
|---|---|---|---|---|
| **I** | Internal listener | Loopback peer only (checked in code as well as by the bind address) | None (no cookies, no browser) | Accepts any method, ignores bodies (section 3) |
| **P** | Public dashboard route | None | Pre-session token for sign-in forms (section 4) | Explicit allow-list, nothing else is public |
| **A** | Admin read | Valid session, account enabled | Not needed for `GET`; exports also check `Sec-Fetch-Site` / `Origin` (section 7.6) | |
| **W** | Admin write | Valid session, account enabled | Required: HMAC token from the session in a header or hidden field, plus `Origin` / `Referer` check | Audited |
| **R** | Admin write needing recent re-authentication | As W | As W | The session must have authenticated (password or passkey) within `auth.reauth_window_s`, default 300 s. Otherwise `403 reauth_required` and the UI asks again |

Rate-limit classes (counters live in memory except the sign-in throttle, which is in `auth_throttle`):

| Limit | Applies to | Proposed default |
|---|---|---|
| **L1** sign-in throttle | Password and passkey sign-in and re-auth endpoints | Per `auth.throttle`: five failures in 15 minutes lock for 15 minutes, doubling per repeat up to 24 hours. Keyed by IP and by hashed username; same message for unknown users and wrong passwords |
| **L2** outbound / heavy actions | IP re-check, Tor refresh, IPLogs test, backup now, retention run | 10 per minute per admin, and one run at a time per action |
| **L3** exports | CSV exports | One running export per admin; row cap `export.csv_max_rows` |
| **L4** preview stash | Block page and injection previews | 5 stored previews per admin, 5 minute lifetime, 200 KB each, held in memory |

Unlisted limits mean "no extra limit beyond the session". All numbers are proposals (section 13).

---

## 3. Internal listener (class I)

Only Nginx calls these. They read request headers set by Nginx (ARCHITECTURE section 9) and never trust anything from the original visitor except what Nginx copied into the `X-Guard-*` headers.

| Method | Path | Purpose | Details |
|---|---|---|---|
| any | `/check` | `auth_request` target: allow or deny | Input headers: `X-Guard-Ip`, `X-Guard-Method`, `X-Guard-Host`, `X-Guard-Uri`. Output: `204` allow or `403` deny, plus `X-Guard-Decision` (`allowed`, `denied`, `overridden`, `monitored`), `X-Guard-Detection`, `X-Guard-Rule`, `X-Guard-Reason`. Uses only the in-memory Snapshot; no database, no network; may enqueue an IP lookup but never waits for it (D3). Missing or malformed input headers produce `204` with an empty decision (counted as an error), never a `5xx`. Target under 1 ms. |
| any | `/block` | Renders the published block page for a denied request | Same `X-Guard-*` input plus the decision headers. Output: `403`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, the block page CSP (SUBSYSTEMS 5.2), and `X-Guard-Block-Decision/-Detection/-Rule/-Reason` response headers so Nginx can log them. |
| `GET` | `/healthz` | Liveness | `200 {"status":"ok"}` as long as the event loop answers. Used by systemd and the deploy scripts. |
| `GET` | `/readyz` | Readiness with component detail | Component states from `component_health`, Snapshot generation and age, ingest lag. `503` while the Snapshot has never been built. Contains no secrets. |

Notes:
- `/check` and `/block` accept any method because the HTTP method Nginx uses for the `auth_request` subrequest has to be confirmed against the real Nginx build in Stage 6. The visitor's real method travels in `X-Guard-Method`.
- The internal app has no cookies, no sessions and no CORS.
- Because Nginx owns the real `$remote_addr`, `X-Guard-Ip` is trusted only because the listener is loopback and only Nginx talks to it.

---

## 4. Public dashboard routes and sign-in (class P)

| Method | Path | Class | Purpose | Details |
|---|---|---|---|---|
| `GET` | `/login` | P | Sign-in page | Sets a short-lived pre-session cookie `__Host-guard_pre` (random, `HttpOnly`, `Secure`, `SameSite=Lax`) used to derive the login CSRF token. Shows the passkey button, and the password form only when `auth.password_login_enabled` is true. Redirects to `/` if already signed in. |
| `POST` | `/login/password` | P, L1 | Password sign-in | Body: username, password, pre-session CSRF token. Same error for unknown user and wrong password. On success: new session cookie `__Host-guard_session` (`HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`), the pre-session cookie is cleared, `last_login_ms` updated, rehash if argon2 parameters changed. Audit `auth.login`. |
| `POST` | `/login/passkey/options` | P, L1 | Start passkey sign-in | Returns WebAuthn request options with a 32-byte challenge held in memory, single use, 5 minute expiry, tied to the pre-session cookie (D8). Does not reveal whether a username exists (discoverable credentials; no username needed). |
| `POST` | `/login/passkey/verify` | P, L1 | Finish passkey sign-in | Verifies challenge, origin, RP ID, signature, user verification and sign count with the `webauthn` library. Unknown or revoked credential: generic failure. Audit `auth.login` or `auth.login_failed`. |
| `POST` | `/logout` | W | Sign out | Deletes the session row, clears the cookie. Audit `auth.logout`. |
| `GET` | `/healthz` | P | Liveness for the dashboard process | `{"status":"ok"}` only, no detail (the detailed view is `/api/v1/health`, class A). |
| `GET` | `/static/{path}` | P | CSS, JS, fonts, images shipped with Guard | Served from one directory; path traversal rejected; long cache with content hashes. No admin data. |

Anything else not listed in this document is not public.

---

## 5. Account, passkeys and sessions

"Self" means the signed-in admin; these routes never take another admin's id.

| Method | Path | Class | Purpose | Details |
|---|---|---|---|---|
| `GET` | `/account` | A | Page: profile, passkeys, sessions | This is the **Authentication / Passkeys** sidebar page. |
| `GET` | `/api/v1/account` | A | Profile | Username, display name, timezone, theme, whether a password is set, passkey count. |
| `PATCH` | `/api/v1/account` | W | Update display name, timezone (IANA name, validated), theme | Audit `account.update`. |
| `POST` | `/api/v1/account/password` | R | Change own password | Body: current password, new password (minimum length `auth.password_min_length`, obvious-password check). Revokes the admin's other sessions. Audit `account.password_change`. |
| `POST` | `/api/v1/reauth/password` | W, L1 | Re-authenticate with password | Refreshes the session's "authenticated at" time. Audit `auth.reauth`. |
| `POST` | `/api/v1/reauth/passkey/options` | W, L1 | Start passkey re-auth | Challenge in memory, bound to the session. |
| `POST` | `/api/v1/reauth/passkey/verify` | W, L1 | Finish passkey re-auth | As sign-in verification. |
| `GET` | `/api/v1/passkeys` | A | List own passkeys | Name, created, last used, transports, backup flags, truncated credential id hash. Never the public key or full credential id. |
| `POST` | `/api/v1/passkeys/register/options` | R | Start registering a passkey | Excludes already-registered credential ids. Challenge in memory, bound to the session. |
| `POST` | `/api/v1/passkeys/register/verify` | R | Finish registering | Body includes the new passkey's name (unique per admin, case-insensitive). Audit `passkey.add`. |
| `PATCH` | `/api/v1/passkeys/{id}` | W | Rename own passkey | Audit `passkey.rename`. |
| `DELETE` | `/api/v1/passkeys/{id}` | R | Revoke (delete) own passkey | `409` if it is the last passkey and password login is disabled (never leave an account with no sign-in method). Audit `passkey.revoke` with name and credential id hash prefix (SCHEMA S8). |
| `GET` | `/api/v1/account/sessions` | A | List own sessions | Created, last seen, expires, IP, User-Agent, current-session flag. Never the token or its hash. |
| `DELETE` | `/api/v1/account/sessions/{id}` | W | Revoke one of own sessions | Audit `session.revoke`. |
| `POST` | `/api/v1/account/sessions/revoke-others` | W | Revoke all own sessions except the current one | Audit `session.revoke_others`. |

---

## 6. Overview, search, notifications, health

| Method | Path | Class | Purpose | Details |
|---|---|---|---|---|
| `GET` | `/` | A | **Dashboard** page | Cards and charts from the endpoints below. |
| `GET` | `/api/v1/overview` | A | Dashboard numbers | `range` 24h, 7d or 30d: requests, bytes in, bytes out, unique visitors, denied, overridden, monitored, top URLs, top IPs, series (hourly from `rollup_site_hourly`). Byte labels follow "HTTP traffic seen by Nginx for this site". |
| `GET` | `/api/v1/search` | A | Top-bar global search | Query `q` (at most 200 characters). Classified as an IP (exact or prefix), a path (starts with `/`) or free text matched against admin page names. Returns at most 10 results per kind, each a link into the UI. Parameterized, bounded, uses the indexes in SCHEMA section 7. |
| `GET` | `/api/v1/notifications` | A | Notification list | Derived from `component_health` on each call (SCHEMA S12): stale Tor feed, repeated lookup failures, ingest lag, spool gap, backup failure, low disk. Nothing is stored or dismissed per admin in v1. |
| `GET` | `/api/v1/health` | A | Component detail | State, heartbeat, last OK, last error for each background component, Snapshot age, ingest position and lag, peer-mismatch counter, SQLite and schema versions. |

---

## 7. Traffic

### 7.1 Visitors (page: **Visitors**)

| Method | Path | Class | Purpose | Details |
|---|---|---|---|---|
| `GET` | `/visitors` | A | Visitors page | |
| `GET` | `/api/v1/visitors` | A | Search and list | Params: `q` (exact IP, or prefix on the canonical text), `from_ms`/`to_ms` filtering on `last_seen_ms`, `sort` in (`last_seen_ms`, `first_seen_ms`, `request_count`, `bytes_in`, `bytes_out`, `denied_count`), `dir`, `page`, `size`. Includes manual rule mode and cached intel flags per row. |
| `GET` | `/visitors/{ip}` | A | **Per-IP view** page | Combines the sections below with intel and moderation (this is the "IP view" of GOAL D). |
| `GET` | `/api/v1/visitors/{ip}` | A | Summary | First/last seen, request count, byte totals, denied count, manual rule, intel summary, cache age. Totals are "since first seen"; raw rows are kept for `retention.requests_days` (SCHEMA S4), and the response says both. `404` if the IP was never seen. |
| `GET` | `/api/v1/visitors/{ip}/requests` | A | Requests by this IP | Date range, `method`, `status`, `outcome`, `path` filters; keyset cursor; range at most 7 days. |
| `GET` | `/api/v1/visitors/{ip}/urls` | A | URLs this IP requested | Per URL: path, hits, first/last seen (from `visitor_urls`), sortable by hits or last seen. |
| `GET` | `/api/v1/visitors/{ip}/user-agents` | A | User-Agent history | Value, hits, first/last seen; capped list with an `and_more` flag (SCHEMA 5.3). |
| `GET` | `/api/v1/visitors/{ip}/accounts` | A | MyBB accounts seen | Uid, username, hits, first/last seen; capped with `and_more`. |
| `GET` | `/api/v1/visitors/{ip}/breakdown` | A | Method and status distributions | Computed on demand from `requests` for the chosen range (default 7 days), not stored. |
| `GET` | `/api/v1/requests/{id}` | A | Single request detail | Every recorded field: UTC time, IP, method, host, path, redacted query, status, bytes, duration, User-Agent, referrer, MyBB account, outcome, detection, rule reference, reason. |
| `GET` | `/requests/{id}` | A | Request detail page | |

### 7.2 IP intelligence (page: **IP Intelligence**)

| Method | Path | Class | Purpose | Details |
|---|---|---|---|---|
| `GET` | `/ip-intel` | A | IP Intelligence page | Lookup box, recently flagged IPs, Tor feed state, lookup queue status. |
| `GET` | `/api/v1/ip-intel` | A | Cached results | Filters: `flag` in (`vpn`, `proxy`, `tor`, `relay`, `hosting`, `crawler`), `status`, `verdict`, date of fetch; sort by `data_fetched_ms` or `score`; paginated. |
| `GET` | `/api/v1/ip-intel/{ip}` | A | One cached result | Flags, verdict, score, confidence and reputation exactly as received, ASN, organisation, ISP, country, prefix, signals, cache age, status, error count, `retry_after_ms`. Latitude and longitude do not exist. Cache miss returns `404` and never triggers a lookup. |
| `POST` | `/api/v1/ip-intel/{ip}/recheck` | W, L2 | Queue a fresh lookup | Public addresses only (private and reserved addresses are `skipped`). Returns `202` and the queue position; never waits for IPLogs. The hard-coded IPLogs endpoint is the only thing ever contacted. Audit `intel.recheck`. |
| `GET` | `/api/v1/tor-feed` | A | Tor feed state | Fetched time, entry count, digest, last attempt, last error, consecutive failures. |
| `POST` | `/api/v1/tor-feed/refresh` | W, L2 | Refresh now | Same validation as the scheduled update; on failure the last-known-good list stays active. Returns `202`. Audit `tor_feed.refresh`. |

Moderation actions for one IP are in section 8.1.

### 7.3 URL history (page: **URL History**)

| Method | Path | Class | Purpose | Details |
|---|---|---|---|---|
| `GET` | `/url-history` | A | URL History page | Search box, ranked most-accessed table, selected-URL detail. |
| `GET` | `/api/v1/urls` | A | Search and rank | Params: `q`, `match` in (`exact`, `prefix`), `host`, `from_ms`/`to_ms`, `sort` in (`hits`, `last_seen_ms`, `unique_ips`), `dir`, `page`, `size`. With no date range, ranks by all-time `hit_count`; with a range, sums `rollup_url_hourly`. Notes thresholded rollups (SCHEMA S5) in the response when they affect a range query. |
| `GET` | `/api/v1/urls/{id}` | A | One URL | Host, path, first/last seen, total visits, unique IP count, whether the path was truncated. |
| `GET` | `/api/v1/urls/{id}/requests` | A | Every recorded request to this URL | Filters: `from_ms`/`to_ms` (at most 7 days), `ip`, `status`, `method`, `outcome`; keyset cursor. |
| `GET` | `/api/v1/urls/{id}/ips` | A | Unique IPs for this URL | IP, hits, first/last seen from `visitor_urls`; sortable; paginated. |
| `GET` | `/api/v1/urls/{id}/series` | A | Graph data | Params: `metric` in (`requests`, `bytes_in`, `bytes_out`), `range` (24h, 7d, 30d) or `from_ms`/`to_ms`, `bucket` (`hour` or `day`). Response names the unit (`requests`, `bytes`) and the timezone it was bucketed in. |
| `GET` | `/api/v1/traffic/series` | A | Site-wide graph data | Same parameters, from `rollup_site_hourly`. |

### 7.4 Notes on wording

All byte figures are labelled "HTTP traffic seen by Nginx for this site" and never "bandwidth" (GOAL C, ARCHITECTURE limitation 4). Totals are labelled "total since first seen; raw rows kept for N days" (SCHEMA S4).

### 7.5 Redaction

No endpoint returns anything that was not stored, and the stored query string is already redacted by ingest (SUBSYSTEMS 2.3). There are no routes that return request bodies, cookies or headers, because none are stored.

### 7.6 CSV exports

| Method | Path | Class | Purpose | Details |
|---|---|---|---|---|
| `GET` | `/api/v1/export/visitors.csv` | A, L3 | Visitor list as CSV | Same filters as `/api/v1/visitors`. |
| `GET` | `/api/v1/export/url-history.csv` | A, L3 | Filtered URL history records as CSV | Same filters as `/api/v1/urls/{id}/requests`, or for a prefix search across the matching URLs. |
| `GET` | `/api/v1/export/requests.csv` | A, L3 | Filtered requests as CSV | Same filters as the request lists. |

- Streamed, capped at `export.csv_max_rows`; the file says so in a trailing comment row if the cap was hit.
- Cells beginning with `=`, `+`, `-`, `@`, tab or CR are prefixed with a single quote (SUBSYSTEMS 2.8).
- `SameSite=Lax` cookies are sent on cross-site top-level navigations, so a hostile page could make an admin's browser start an export. Exports therefore require `Sec-Fetch-Site` to be `same-origin` or `none`, or a matching `Origin`; anything else is `403`.
- Every export is audited (`export.csv`) with the endpoint, filters and row count.

---

## 8. Security

### 8.1 IP rules (page: **IP Rules**)

Modes in the API are `allow`, `block` and `monitor`. "IPLogs-only" means **no rule**, so it is `DELETE`, never a stored value (SCHEMA section 4).

| Method | Path | Class | Purpose | Details |
|---|---|---|---|---|
| `GET` | `/ip-rules` | A | IP Rules page | |
| `GET` | `/api/v1/ip-rules` | A | List rules | Filters: `mode`, `q` (IP prefix), `expiring_before_ms`, `note` text; sort by `updated_ms`, `expires_ms`, `ip`. |
| `GET` | `/api/v1/ip-rules/{ip}` | A | One rule | Mode, note, expiry, created/updated by and when. History comes from the audit log (SCHEMA 5.4). |
| `PUT` | `/api/v1/ip-rules/{ip}` | W | Create or change a rule | Body: `mode`, `note` (required, 1 to 500 characters, for `allow` and `block`), optional `expires_ms` (must be in the future), optional `expected_updated_ms`. Records who, when and why. A new Snapshot is built within one second. Audit `ip_rule.set` with previous and new mode. |
| `DELETE` | `/api/v1/ip-rules/{ip}` | W | Back to IPLogs-only | Removes the rule. Audit `ip_rule.clear`. |
| `POST` | `/api/v1/ip-rules/bulk-clear-expired` | W | Remove expired rules now | The 30 second sweeper does this anyway (SUBSYSTEMS 3.5); this is only a manual button. Audit `ip_rule.expire` per rule. |

Single addresses only (assumption Q4). CIDR input is rejected with a clear message.

### 8.2 URL access rules (page: **URL Access Rules**)

| Method | Path | Class | Purpose | Details |
|---|---|---|---|---|
| `GET` | `/url-rules` | A | URL Access Rules page | |
| `GET` | `/api/v1/url-rules` | A | List rules | Filters: `action`, `enabled`, `scope` (`global` or an IP), `match_type`, `q`; sort by `priority`, `updated_ms`, `pattern`. |
| `POST` | `/api/v1/url-rules` | W | Create a rule | Body accepts a full URL or a path in `url`; the server normalizes it exactly as ingest does (SUBSYSTEMS 4.2) and returns the stored pattern. Fields: `match_type`, optional `query_match` (object of exact key/value pairs), `action`, optional `scope_ip`, `priority`, `enabled`, optional `expires_ms`, `description`, `notes`. A full URL whose host is not managed is `400`. Safety rails (SUBSYSTEMS 4.4): a site-wide `deny` prefix, a rule covering `enforcement.protected_paths`, or exceeding `limits.url_rules_max` is `400` (the site-wide case needs `enforcement.allow_site_wide_url_deny` and a typed confirmation field). Duplicate identity is `409` (`uq_url_rules_identity`). Audit `url_rule.create`. |
| `GET` | `/api/v1/url-rules/{id}` | A | One rule | |
| `PUT` | `/api/v1/url-rules/{id}` | W | Replace a rule | Same validation and rails as create; optional `expected_updated_ms`. Audit `url_rule.update` with a before/after summary. |
| `PATCH` | `/api/v1/url-rules/{id}` | W | Enable or disable | Body `{"enabled": true|false}`. Audit `url_rule.enable` / `url_rule.disable`. |
| `DELETE` | `/api/v1/url-rules/{id}` | W | Delete a rule | Audit `url_rule.delete` with the pattern. |
| `POST` | `/api/v1/url-rules/test` | W | Test and preview | Body: a URL or path and an IP. Returns every matching rule in resolution order, marks the winner and says why each other rule lost (SUBSYSTEMS 4.5). Writes nothing and is not audited. It calls the same matching function as `/check`, so preview cannot differ from enforcement. It uses `POST` only so that it is CSRF-protected like the other rule routes. |

### 8.3 Block page editor (page: **Block Page**)

Versions are append-only (SCHEMA S9). A "draft" is simply an unpublished version.

| Method | Path | Class | Purpose | Details |
|---|---|---|---|---|
| `GET` | `/block-page` | A | Editor page | Source textarea, preview iframe, history list, enable switch. |
| `GET` | `/api/v1/block-page` | A | Current state | Published version id and time, whether the custom page is in use (`block_page.use_custom`), whether the built-in default is the one being served and why, the built-in default HTML. |
| `GET` | `/api/v1/block-page/versions` | A | History | Id, note, author, created, published flag, `restored_from`; paginated. |
| `GET` | `/api/v1/block-page/versions/{id}` | A | One version with its HTML | |
| `GET` | `/api/v1/block-page/versions/{a}/diff/{b}` | A | Text diff between two versions | |
| `POST` | `/api/v1/block-page/versions` | W | Save a new version (not published) | Body: `html` (at most 200 KB measured in bytes), `note`. Validates UTF-8 and size. Placeholders are not validated further because unknown ones render as plain text (SUBSYSTEMS 5.2). Audit `block_page.save`. |
| `POST` | `/api/v1/block-page/versions/{id}/publish` | W | Publish a version | Clears the previous published row and sets this one in one transaction. Audit `block_page.publish`. |
| `POST` | `/api/v1/block-page/versions/{id}/restore` | W | Restore an older version | Inserts a **new** version copying the old one with `restored_from` set. Body `{"publish": false}` by default; `true` publishes it in the same transaction. Audit `block_page.restore`. |
| `PUT` | `/api/v1/block-page/enabled` | W | Use custom page or built-in default | Writes `block_page.use_custom`. Audit `settings.update`. |
| `POST` | `/api/v1/block-page/preview` | W, L4 | Stash unsaved HTML for preview | Body: `html`. Returns a single-use-per-view token held in memory only; nothing is written to the database. |
| `GET` | `/preview/block-page/{token}` | A | Preview response, for the sandboxed iframe | Rendered with sample placeholder values using the same substitution as `/block`. Headers: `Content-Security-Policy: sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'self'`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`. The parent page embeds it with `<iframe sandbox>` (no `allow-scripts`, no `allow-same-origin`), so saved HTML can never run against the admin session. |
| `GET` | `/preview/block-page/version/{id}` | A | Preview of a saved version | Same headers and rendering. |

Stage 6 tests assert the iframe `sandbox` attribute and the preview CSP header (GOAL G, rule 9).

---

## 9. MyBB injections

`injections` holds the current state; `injection_versions` is append-only history of **content and placement** (position, targeting, priority, HTML, CSS, JS). Name, description and enabled flag are not versioned, so a rollback never switches an injection on or off (SCHEMA 5.6).

| Method | Path | Class | Purpose | Details |
|---|---|---|---|---|
| `GET` | `/injections` | A | **HTML Injections** page | Prominent notice: JavaScript runs in every visitor's browser. |
| `GET` | `/api/v1/injections` | A | List | Name, description, enabled, position, targeting, priority, current version, updated; filters `enabled`, `q`. |
| `POST` | `/api/v1/injections` | W | Create | Starts **disabled**. Validates sizes (100 KB each for HTML, CSS, JS), position, targeting list (each target an exact or prefix path), UTF-8 and NUL bytes. The content is stored exactly as written, never rewritten (GOAL H). Creates version 1 and bumps the export generation. Audit `injection.create`. |
| `GET` | `/api/v1/injections/{id}` | A | One injection | |
| `PUT` | `/api/v1/injections/{id}/content` | W | Save content or placement | Body: `position`, `targeting_mode`, `targets`, `priority`, `html`, `css`, `js`, `note`, `base_version`. `409` if `base_version` is not the current version. Creates a new version. Audit `injection.save`. |
| `PATCH` | `/api/v1/injections/{id}` | W | Change name, description or enabled flag | Does not create a version. Audit `injection.update` or `injection.enable` / `injection.disable`. |
| `DELETE` | `/api/v1/injections/{id}` | R | Delete injection and its history | Body must repeat the injection's name as typed confirmation. Audit `injection.delete` with name and last version number. |
| `GET` | `/injections/history` | A | **Injection History / Versions** page | Per injection or across all. |
| `GET` | `/api/v1/injections/{id}/versions` | A | Version list | Version number, note, author, created, `restored_from_version`; paginated. |
| `GET` | `/api/v1/injections/{id}/versions/{version}` | A | One version with content | |
| `GET` | `/api/v1/injections/{id}/versions/{a}/diff/{b}` | A | Diff of two versions | |
| `POST` | `/api/v1/injections/{id}/versions/{version}/rollback` | W | Roll back | Writes a **new** version with `restored_from_version` set and applies its content and placement to the injection. Does not change `enabled`. Audit `injection.rollback`. |
| `POST` | `/api/v1/injections/preview` | W, L4 | Stash unsaved HTML, CSS (and JS as source) for preview | Body: the fields to preview. In-memory only. |
| `GET` | `/preview/injection/{token}` | A | Preview response for the sandboxed iframe | HTML and CSS are rendered inside a mock forum page. **Scripts do not run in preview** (CSP `sandbox` without `allow-scripts`); the JS is shown as source with a notice. See open item 2. |
| `GET` | `/api/v1/mybb/export` | A | Export state | Generation, last written time, content hash, last error, count of enabled injections, `mybb.injections_enabled` switch. |
| `POST` | `/api/v1/mybb/export/rewrite` | W | Rewrite the export file now | Atomic write (temp file, `fsync`, rename, mode 0640). Audit `mybb.export_rewrite`. |

Export-file updates after every injection or setting change happen automatically (the exporter watches `change_counters.injections` and `settings`); the route above exists for recovery.

---

## 10. Administration

### 10.1 Administrators (page: **Administrators**)

Admins are disabled, never deleted (SCHEMA S7). One role in v1 (D14).

| Method | Path | Class | Purpose | Details |
|---|---|---|---|---|
| `GET` | `/admins` | A | Administrators page | |
| `GET` | `/api/v1/admins` | A | List | Username, display name, disabled flag, last login, passkey count, created by and when. |
| `POST` | `/api/v1/admins` | R | Create an administrator | Body: username (3 to 64 characters, unique ignoring case), display name, initial password. There is no public registration and no invitation link in v1 (open item 1). Audit `admin.create`. |
| `PATCH` | `/api/v1/admins/{id}` | W | Change another admin's display name | Audit `admin.update`. |
| `POST` | `/api/v1/admins/{id}/disable` | R | Disable an account | Revokes all of that admin's sessions. `409` if it is the signed-in admin or the last enabled admin. Audit `admin.disable`. |
| `POST` | `/api/v1/admins/{id}/enable` | R | Re-enable an account | Audit `admin.enable`. |
| `POST` | `/api/v1/admins/{id}/password` | R | Set a new password for another admin | Revokes that admin's sessions. Audit `admin.password_reset`. |

Account recovery for locked-out admins is CLI only: `guard-admin reset-password`, `guard-admin revoke-passkeys`, `guard-admin create-admin` (SUBSYSTEMS 7.1).

### 10.2 Audit log (page: **Audit Log**)

| Method | Path | Class | Purpose | Details |
|---|---|---|---|---|
| `GET` | `/audit` | A | Audit Log page | |
| `GET` | `/api/v1/audit` | A | Search | Filters: `from_ms`/`to_ms`, `actor`, `action`, `outcome`, `target_type`, `target_id`; keyset cursor. |
| `GET` | `/api/v1/audit/{id}` | A | One event | The `detail` JSON never contains secrets or request bodies (SUBSYSTEMS 7.4). |
| `GET` | `/api/v1/export/audit.csv` | A, L3 | Filtered audit events as CSV | Same export rules as section 7.6. |

There are no routes that edit or delete audit events; only the retention job removes them (SCHEMA S9).

### 10.3 API Settings (page: **API Settings**)

Non-secret settings for the two outbound integrations. **Secrets are never editable here** (D9): the page shows whether an IPLogs credential is configured (yes or no) and tells the admin to set it with `guard-admin secrets set`.

| Method | Path | Class | Purpose | Details |
|---|---|---|---|---|
| `GET` | `/settings/api` | A | API Settings page | |
| `GET` | `/api/v1/settings/api` | A | Current values and status | `intel.iplogs.*`, `intel.ttl_*`, `intel.tor.*`, `intel.policy` with defaults and sources; credential configured flag; last IPLogs success and error; Tor feed state. |
| `PUT` | `/api/v1/settings/api` | W | Update these settings | Typed validation per key (SCHEMA section 6). The hosting and crawler categories have no switch and cannot be set to block (GOAL rule 5). `intel.policy.min_confidence` stays null until IPLogs `confidence` is verified. Audit `settings.update` with changed keys and old/new values (never secrets). |
| `POST` | `/api/v1/settings/api/test-iplogs` | W, L2 | Test the IPLogs connection | Sends one lookup for a fixed public test address to the hard-coded endpoint and reports status, latency and whether the response parsed. Result is not written to `ip_intel`. Audit `settings.test_iplogs`. |

### 10.4 General settings (page: **General Settings**)

| Method | Path | Class | Purpose | Details |
|---|---|---|---|---|
| `GET` | `/settings` | A | General Settings page | |
| `GET` | `/api/v1/settings` | A | Whole registry | Every key with type, default, effective value, source (`default` or `custom`), and `updated_ms`/`updated_by` when custom. Secrets do not exist here. |
| `PUT` | `/api/v1/settings/{key}` | W | Set one key | Typed validation; unknown keys are `404`. Hard ceilings from the DDL cannot be raised. `expected_updated_ms` optional. Audit `settings.update`. |
| `DELETE` | `/api/v1/settings/{key}` | W | Reset to default | Deletes the row. Audit `settings.reset`. |

Keys that need re-authentication (class R instead of W) and, where stated, a typed confirmation: `enforcement.mode` (switching to `monitor_only` pauses all denials), `enforcement.paths` (widening enforcement beyond login and registration), `enforcement.allow_site_wide_url_deny`, `enforcement.protected_paths`, `auth.password_login_enabled` (and only if every enabled admin has a passkey), `auth.session_*`, `site.hosts`. The route stays `PUT /api/v1/settings/{key}`; the check is by key.

### 10.5 Backups and retention (page: **Backups and Retention**)

Restore is CLI-only (D13). **There is no backup download route in v1** because a backup holds password hashes, passkey public keys, visitor IPs and audit data; copying it off the box is an operator decision (open item 3).

| Method | Path | Class | Purpose | Details |
|---|---|---|---|---|
| `GET` | `/backups` | A | Backups and Retention page | |
| `GET` | `/api/v1/backups` | A | List backups | Read from the JSON manifests beside the files (SCHEMA S11): name, kind (daily, weekly, manual), time, size, SHA-256, schema version. Also free disk space on the backup volume. |
| `POST` | `/api/v1/backups` | W, L2 | Back up now | Online backup API to a temp file, `PRAGMA integrity_check`, rename into place, manifest written. Returns `202` and a job id. Audit `backup.create`. |
| `GET` | `/api/v1/jobs/{id}` | A | Job status | State (`running`, `ok`, `failed`), start, end, short message. Jobs live in memory; a restart forgets them (the backup file and manifest are the record). |
| `GET` | `/api/v1/retention` | A | Retention settings and database facts | `retention.*` values, row counts per table, oldest raw request, database size, WAL size, last weekly job result. |
| `POST` | `/api/v1/retention/preview` | W | What would a shorter retention delete? | Body: proposed `retention.*` values. Returns row counts per table that the next cleanup would remove. Writes nothing. |
| `PUT` | `/api/v1/retention` | R | Apply retention values | Body: the values and `confirm: true`. For any value shorter than the current one, the preview must have been run in the same session within 10 minutes with the same values, or the call is `409`. Audit `retention.update`. |
| `POST` | `/api/v1/retention/run` | R, L2 | Run cleanup now | Same bounded-batch job as the weekly timer (SCHEMA section 9). Returns `202` and a job id. Audit `retention.run` with row counts removed. |

`VACUUM` is not exposed; it is a manual operator step (SUBSYSTEMS 8.3).

---

## 11. Audit action names

Dotted lower-case names, stored in `audit_events.action` (maximum 64 characters). `outcome` is `success`, `failure` or `denied` (for example a failed CSRF check or a missing re-authentication).

| Area | Actions |
|---|---|
| Authentication | `auth.login`, `auth.login_failed`, `auth.logout`, `auth.reauth`, `auth.lockout`, `auth.csrf_failure`, `auth.reauth_required` |
| Account and sessions | `account.update`, `account.password_change`, `session.revoke`, `session.revoke_others` |
| Passkeys | `passkey.add`, `passkey.rename`, `passkey.revoke`, `passkey.sign_count_regression` |
| Administrators | `admin.create`, `admin.update`, `admin.disable`, `admin.enable`, `admin.password_reset` |
| Rules | `ip_rule.set`, `ip_rule.clear`, `ip_rule.expire`, `url_rule.create`, `url_rule.update`, `url_rule.enable`, `url_rule.disable`, `url_rule.delete` |
| Block page | `block_page.save`, `block_page.publish`, `block_page.restore` |
| Injections | `injection.create`, `injection.save`, `injection.update`, `injection.enable`, `injection.disable`, `injection.delete`, `injection.rollback`, `mybb.export_rewrite` |
| Intelligence | `intel.recheck`, `tor_feed.refresh` |
| Settings | `settings.update`, `settings.reset`, `settings.test_iplogs` |
| Data | `export.csv`, `backup.create`, `backup.restore` (written by the CLI), `retention.update`, `retention.run` |
| System | `migration.apply` (written by the CLI) |

Audit events written by the CLI use `actor_name` of the operating-system user and an empty `actor_admin_id`.

---

## 12. Route authorization sweep (Stage 9 test)

- Every route is registered through one helper that requires a class from section 2. The helper stores the class in a registry.
- **Sweep test 1:** walk the framework's route table. Fail on any route not in the registry, or any class P route not on the explicit allow-list in section 4.
- **Sweep test 2:** for every class A, W and R route, call it with no session (expect `401` or a redirect to `/login`), with an expired session, with a disabled account's session, and, for W and R, with a valid session but no CSRF token and with a wrong `Origin` (expect `403`).
- **Sweep test 3:** for every class R route, call it with a session older than `auth.reauth_window_s` and expect `403 reauth_required`.
- **Sweep test 4:** assert `/docs`, `/redoc` and `/openapi.json` return `404` on both listeners.
- **Sweep test 5:** assert none of the section 3 paths respond on the dashboard listener, and that the internal listener rejects a non-loopback peer.
- **Spoofed-header tests:** a request to the dashboard listener from a non-loopback peer with `X-Guard-Client-Ip` is logged under the peer address; `CF-Connecting-IP` and `X-Forwarded-For` have no effect on either listener.
- Tests that need the web stack run on the owner's machine or the server (ARCHITECTURE section 12); the registry walk itself can be written without third-party packages.

---

## 13. Open items for the owner

1. **Initial password for a new administrator.** SCHEMA.md has no "must change password" flag and no invitation token table, so in v1 the creating admin types an initial password and shares it outside Guard. Options: accept that (the new admin changes it at first sign-in by habit, not enforcement); add a `must_change_password` column to `admins` in migration 0001; or add invitation links (needs a token table and a schema change). Please choose.
2. **Injection preview and JavaScript.** The plan runs no scripts in preview, so the admin cannot see script behaviour before enabling. Alternative: allow scripts in the sandboxed preview iframe (opaque origin, so it still cannot touch the admin session) behind an explicit "run scripts in this preview" checkbox. Preview scripts would then run in the admin's own browser. Please choose.
3. **No backup download.** Confirm that backups stay on the server and are copied off by the operator if wanted.
4. **New proposals not in the earlier docs:** the re-authentication window `auth.reauth_window_s` (300 s, now added to the SCHEMA.md settings registry), the L2 limit (10 per minute per admin), the preview stash limits (5 per admin, 5 minutes, 200 KB), the 10-minute retention-preview validity, and which settings need re-authentication (section 10.4). Confirm or change.
5. **Typed confirmation wording** for destructive actions (injection delete, site-wide URL deny, switching enforcement to `monitor_only`) is a UI detail left for Stage 8.
6. **Dashboard hostname (Q1)** still decides the cookie scope, the WebAuthn RP ID and the `Origin` check in this document. Everything here assumes a dedicated hostname.
