# InitStack Guard: Subsystem Designs

> **Status:** Stage 1 draft v0.1, written 2026-11-08, awaiting owner review.
> **Source:** `GOAL.md` and `ARCHITECTURE.md`. `docs/SPEC.md` was not available; where it disagrees with this file, the spec wins.
> **Companions:** [ARCHITECTURE.md](ARCHITECTURE.md), [SCHEMA.md](SCHEMA.md) (exact tables) and [API.md](API.md) (routes). Where this file and SCHEMA.md differ on storage details, SCHEMA.md wins.
> **Nothing described here is built or applied to any server yet.**

## Contents
1. Conventions
2. Ingest (Nginx log to SQLite)
3. IP intelligence (IPLogs, Tor feed, policy)
4. URL access rules
5. Block page
6. MyBB injections
7. Authentication and passkeys
8. Background jobs, backups and retention

---

## 1. Conventions

- **Time:** integer epoch milliseconds, UTC, everywhere in storage and APIs. Conversion to the admin's timezone happens only in the UI layer. Graph and table headers always name the unit and the timezone.
- **IPs:** stored in canonical text form (`ipaddress.ip_address(...).compressed`). IPv4-mapped IPv6 addresses are unmapped to IPv4. Private, loopback, link-local and reserved addresses are recorded but never sent to external services.
- **Pure core:** normalization, redaction, URL matching, the decision pipeline and the reputation policy are plain Python with no third-party imports and no I/O, so they can be tested without the web stack.
- **Parameterized SQL only.** No string-built queries; sort columns and directions come from allow-lists.
- **Output escaping:** Jinja2 autoescape on; no `|safe` except for the sandboxed preview and injection previews, which are served from separate responses with their own CSP.
- **Errors:** a subsystem failure degrades that subsystem and is surfaced as a health state; it never takes down `/check` (ARCHITECTURE.md section 7).
- **Settings:** stored in the `settings` table with typed validation; secrets are never settings (decision D9).

---

## 2. Ingest (Nginx log to SQLite)

### 2.1 Input
One JSON object per line in `/var/log/nginx/guard/access.jsonl`, in the `guard_json` format from ARCHITECTURE.md section 9. Fields: `t` (epoch seconds with milliseconds), `ip`, `peer`, `m`, `h`, `u` (raw request URI), `s`, `bi`, `bo`, `d` (seconds), `ua`, `ref`, `id`, the `g*` decision fields, the `b*` block fields, `uid`, `un`.

### 2.2 Tailer
- Tracks the log file by device, inode and a hash of its first bytes, plus the read offset, in the single `ingest_state` row, committed in the same transaction as the rows it produced. A crash therefore re-reads at most the last uncommitted batch and never double-counts.
- Reads only complete lines (ending in `\n`). A trailing partial line is left for the next pass.
- Rotation: if the inode changes or the file shrinks, finish the old file by its saved inode if it still exists (`access.jsonl.1`), then start the new file at offset 0. If the old file is gone, record a **gap notice** (shown in the UI) and continue.
- Polls every 1 second; batches up to 500 lines or 1 second; backs off when SQLite is busy. The spool file simply grows while ingest is paused.
- Malformed lines are counted and the first 200 bytes (after redaction) kept in a bounded `ingest_errors` ring (max 1,000 rows). They never stop ingestion.
- Idempotence: `request_id` holds the decoded 16-byte Nginx `$request_id` and has a unique index; duplicates are skipped. A line without a valid id gets the first 16 bytes of a BLAKE2b digest of the raw line, so replaying it still deduplicates.

### 2.3 Normalization
- **Host:** lowercased, port stripped, trailing dot removed. Hosts outside `site.hosts` are stored but flagged unmanaged.
- **Path:** the raw URI is split at the first `?`. The path is percent-decoded once, then checked: NUL bytes, backslashes and invalid UTF-8 are replaced or flagged; `.` and `..` segments are resolved; repeated slashes collapsed. The decoded-normalized form is what is matched and displayed; the length is capped at 2,048 characters (longer paths are truncated and flagged).
- **Query:** parsed into `key=value` pairs. Any key matching the sensitive list (case-insensitive substring: `pass`, `pwd`, `token`, `key`, `secret`, `session`, `sid`, `auth`, `code`, `signature`, `csrf`, `my_post_key`) has its value replaced with `[redacted]`. The remaining query is kept but capped at 1,024 characters. Values of non-sensitive keys that look like long hex or base64 secrets (32+ characters) are also redacted.
- **Method:** upper-cased, restricted to a known list; anything else stored as `OTHER`.
- **User-Agent and referrer:** capped (512 and 1,024 characters). The referrer's query string is dropped.
- **MyBB identity:** `uid` and `un` are used only if the uid is a positive integer and the name is non-empty; otherwise null. Guests (uid 0) are null.

### 2.4 Trusted IP check
For each line, if `peer` is not in the trusted connector list, the stored IP is `peer` (not `ip`) and a mismatch counter is incremented. This is defence in depth over the Nginx `real_ip` configuration (ARCHITECTURE.md section 8).

### 2.5 Outcome mapping
`gd` (the decision Guard returned) maps to `allowed`, `denied`, `overridden`, `monitored`. An empty `gd` maps to `unchecked`. For denied requests the `b*` fields are merged in if the `g*` fields are empty (ARCHITECTURE.md section 9, second bullet). Ingest never re-derives a decision (D5).

### 2.6 Rows written per request
All of these are written in the same transaction as the file offset (SCHEMA.md decision S4).
- `visitors` (one per IP): first and last seen, request count, bytes in and out, denied count, upserted.
- `urls` (one per normalized host + path): first and last seen, hit count, upserted. Orphans (no remaining requests) are removed by retention.
- `requests`: one row. Repeated strings (User-Agent, referrer, MyBB account) are interned in the `user_agents`, `referrers` and `mybb_accounts` dictionary tables, so the row stores integers.
- `visitor_urls`, `visitor_user_agents`, `visitor_accounts`: per-IP aggregates for the visitor view. The User-Agent and account lists are capped in code (100 and 20 per visitor); requests beyond the cap are still stored and the UI shows "and more".
- `rollup_site_hourly` and `rollup_url_hourly`: counters per hour (and per URL) for requests, bytes in, bytes out and denied. Graphs read rollups, not raw rows. Per-URL rollups are kept only for URLs with at least `retention.rollup_min_hits` total hits (SCHEMA.md decision S5).

### 2.7 Never stored
Passwords, cookies, authorization headers, request bodies and passkey data are not in the log format, so they cannot reach ingest. A test scans the shipped Nginx config for the forbidden variables (`$http_cookie`, `$http_authorization`, `$request_body`, `$cookie_*`), and a second test feeds hostile fixture lines through the parser and asserts that no secret-looking value survives into any column.

### 2.8 Queries
- Visitor search by IP: exact IP, or prefix on the textual form; paginated (default 50, max 200); date range on `last_seen` or on request time.
- URL history: path exact or prefix; per URL totals, unique IPs, ranked most-accessed table, series by requests, bytes in and bytes out at 24h, 7d, 30d or custom ranges. Ranges up to 7 days read raw or hourly rollups; longer ranges read rollups only. Every query has a hard row limit.
- CSV export: streams filtered records, capped at a configurable maximum (default 100,000 rows). Cells that start with `=`, `+`, `-`, `@`, tab or CR are prefixed with a single quote to prevent spreadsheet formula injection.
- UI wording: byte figures are labelled "HTTP traffic seen by Nginx for this site", never "bandwidth" or "network".

---

## 3. IP intelligence (IPLogs, Tor feed, policy)

### 3.1 IPLogs client
- Endpoint: `POST https://iplogs.com/v1/check`, JSON body `{"ip": "<address>"}`. The URL is hard-coded; no user-supplied URL is ever fetched (SSRF).
- **Unverified:** authentication scheme, rate limits, free-tier limits and the meaning of the `confidence` field. The official documentation page could not be fetched during Stage 1, so these come from the project's public README and third-party pages. Before Stage 5 starts, the owner or Claude must check the current docs and this section is updated. Until then the client treats credentials as optional, reads a bearer token from `secrets.env` if present, and enforces a conservative local rate limit (default 30 lookups per minute, configurable).
- Response fields used: `verdict`, `score`, `is_vpn`, `is_proxy`, `is_tor`, `is_relay`, `is_hosting`, `is_crawler`, `confidence`, `reputation`, and `ip_info` (ASN, org, ISP, country, prefix), plus `signals`. Latitude and longitude are discarded and never stored (out of scope).
- Defensive parsing: unknown fields ignored; missing fields become null; wrong types make the whole response an error rather than a guess. Response size capped at 64 KB. Timeout 5 seconds; at most one retry with jitter on connection errors; none on 4xx.
- 429 or `Retry-After`: the worker pauses all lookups until that time.
- Errors are stored as a short-lived negative cache entry (default 5 minutes) with status `error`. An error is **unknown**, never evidence of malice.

### 3.2 Lookup worker and cache
- Triggers: a new public IP seen by ingest or `/check`; a manual "recheck" from the UI; a cache entry past its TTL when the IP is active.
- A bounded in-memory queue de-duplicates by IP. `/check` only enqueues; it never waits.
- Cache table `ip_intel` keyed by IP: the verdict fields, `data_fetched_ms`, `expires_ms`, `retry_after_ms` and `status` (`ok`, `error`, `skipped`). TTL defaults: 24 hours for ok, 5 minutes before retrying after an error, configurable. A failed lookup never overwrites good data; it only records the error and sets `retry_after_ms`. Entries past TTL remain usable for a **stale grace** (default 7 days) when a refresh fails.
- Guard never makes one external call per HTTP request; the number of calls is bounded by distinct IPs and the TTL.
- Private, loopback and reserved IPs are marked `skipped` and never sent out.

### 3.3 Tor exit feed
- Source: the Tor Project's bulk exit list, from a hard-coded HTTPS URL, on a configurable schedule (default every 3 hours, with jitter).
- Validation before replacing the active set: HTTP 200, size within bounds, every line parses as an IP address, at least a minimum plausible count (default 500) and not less than 50% of the previous set. A failed validation keeps the **last-known-good** list and records the error; the UI shows list age.
- Stored as a set in memory plus the `tor_feed_state` row (fetched_at, count, digest, last_error). The Tor set is checked locally, independent of IPLogs.

### 3.4 Reputation policy
- Applies only when the request path is on an enforcement path (default `member.php?action=login|do_login|register|do_register`; Stage 7 adds any further real MyBB 1.8.41 steps) and enforcement is not `monitor_only`.
- Per-category switches and a minimum confidence, all configurable. Proposed defaults (Q7): block Tor, block `vpn_detected` and proxy; flag-only for `vpn_likely` and relay; **hosting and crawler never block**.
- Output: `deny` or `allow`, plus a reason string and a confidence value that the UI shows ("Blocked: VPN detected, confidence high").
- Missing, error, expired-beyond-grace or low-confidence data results in **allow** with reason `unknown`.
- Existing sessions are never rechecked or disconnected; the policy runs only on the enforcement paths.
- Required fixture: the 8.8.8.8 hosting-only response must produce `allow`.

### 3.5 Manual IP rules
- One row per IP, in one of four modes: `none` (IPLogs-only; row deleted), `allow`, `block`, `monitor`.
- Optional expiry; a sweeper reverts expired rules and writes an audit event. Every change records who, when and why (note is mandatory for `block` and `allow`).
- Single IPs only in v1 (Q4); the schema leaves room for a prefix column.
- A change triggers a new Snapshot within one second.

### 3.6 Per-IP view
Shows flags and verdict, ASN/org/ISP/country/prefix, cache age and status, request and transfer totals, denied-request count, top URLs, User-Agent history, MyBB accounts seen, manual rule with notes and history, and action buttons for the four modes.

---

## 4. URL access rules

### 4.1 Rule model
Fields: `id`, `pattern` (normalized path), `match_type` (`exact` or `prefix`), optional `query_match` (exact key/value pairs required), `action` (`allow` or `deny`), `scope` (`global` or a single IP), `priority` (integer, lower number wins), `enabled`, optional `expires_at`, `description`, `notes`, created/updated by and when.

### 4.2 Input handling
- The admin enters a full URL or a path. If a full URL is given, the host must be a managed host (or is rejected); the path and query are extracted. The pattern is normalized with exactly the same function as ingest (section 2.3), so the stored pattern and the request path are comparable.
- Prefix matches are on **path segment boundaries**: pattern `/private` matches `/private` and `/private/x`, not `/privateer`. Substring and regex matching do not exist.
- Query matching: all listed keys must be present with exactly the listed values; extra keys in the request are allowed. A rule without `query_match` ignores the query.

### 4.3 Resolution (deterministic)
1. Collect enabled, unexpired rules whose scope fits the visitor's IP and whose pattern matches.
2. Sort by: per-IP scope before global; then more specific match first (exact before prefix, longer prefix before shorter, with query match before without); then lower `priority` number; then `deny` before `allow`; then lower `id`.
3. The first rule wins. Its action is the URL decision.

An `allow` rule only counters a broader URL deny. It does not override IP blocks or reputation (Q3).

### 4.4 Safety rails
- A rule with prefix `/` (or an empty path) and action `deny` is rejected by default. It requires turning on an explicit "allow site-wide URL deny" setting and a typed confirmation.
- Rules that would deny the dashboard hostname, `/_guard/`, or the MyBB admin login recovery paths listed in settings are rejected.
- A deny rule is limited to the managed hosts; unmanaged hosts are never affected.
- Maximum pattern length 2,048; maximum number of rules (default 2,000) to bound Snapshot size.
- The Snapshot compiles rules into a dictionary for exact matches and a segment trie for prefixes, so lookup does not scan all rules.

### 4.5 Test and preview
`POST` a URL and an IP; the response lists every rule that matched, in resolution order, marks the winner, and explains why the others lost. Nothing is written. The same function powers `/check`, so preview and enforcement cannot diverge.

---

## 5. Block page

### 5.1 Storage and versions
- `block_page_versions`: one row per saved version (HTML, author, time, note, `published` flag). Exactly one version is published. Restore creates a new version copying an older one; history is never rewritten.
- A built-in default page ships with the code and is used whenever no version is published, the published HTML fails the size cap (default 200 KB), or the setting "use custom page" is off.

### 5.2 Rendering
- Placeholders `{{ visitor_ip }}`, `{{ block_reason }}`, `{{ detection_type }}`, `{{ timestamp }}`, `{{ appeal_url }}` are replaced by a single-pass strict substitution (a regex over exactly those five names). Values are HTML-escaped first. Unknown placeholders are left as plain text. Jinja is never applied to admin HTML (D12).
- `appeal_url` must be `https`, `http` or `mailto`; otherwise it renders empty. If blank, the default page hides the appeal line.
- Served from the internal listener at `/block` with status `403`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, and a CSP of `default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`. No scripts run, and no third-party resources load.

### 5.3 Editor and preview
- Editor: a plain `<textarea>` source editor (no third-party editor dependency), save-as-draft, publish, enable/disable, history list with diff, restore.
- Preview: rendered with sample values inside an `<iframe sandbox>` (no `allow-scripts`, no `allow-same-origin`), loaded from a separate preview endpoint that sends its own strict CSP. Saved HTML can therefore never reach the admin session. A test asserts the sandbox attribute and the CSP header.

---

## 6. MyBB injections

### 6.1 Model
Each injection: `name`, `description`, `html`, `css`, optional `js`, `enabled`, `position` (`top`, `after_header`, `before_footer`, subject to hooks verified on MyBB 1.8.41 in Stage 7), `targeting` (`all` or a path list, each entry exact or prefix), `priority`. Every save creates a version row; rollback restores a version as a new version.

### 6.2 Validation, not rewriting
Validation checks size caps (HTML, CSS, JS each 100 KB by default), position and target syntax, and that the content is valid UTF-8 with no NUL bytes. The admin's HTML is stored and delivered exactly as written. The UI states plainly that **JS runs in every visitor's browser** and that CSS/HTML can alter the forum's appearance and behaviour.

### 6.3 Delivery
- Guard writes `export/mybb-injections.json` atomically (temp file in the same directory, `fsync`, `rename`), file mode 0640, group readable by PHP. The JSON holds a schema version, a generation counter, a timestamp, and the enabled injections in final render order.
- A small MyBB 1.8 plugin (`mybb_plugin/inc/plugins/initstack_guard.php`) reads the file with a short in-process cache keyed on mtime, selects injections for the current script path, and outputs them through supported hooks and template variables, not Nginx body rewriting.
- The plugin **fails safe**: a missing, unreadable, oversized or invalid file means no injections and no error to visitors. It never writes to Guard's data.
- The same plugin adds `X-Guard-Uid` and `X-Guard-User` response headers for logged-in users (Nginx logs and strips them).
- Activate and deactivate must leave MyBB templates clean (tested in Stage 7).
- Static files bypass PHP, so they carry no MyBB identity (known limitation 5).

---

## 7. Authentication and passkeys

### 7.1 Accounts
- No public registration. The first admin is created with `guard-admin create-admin` (prompts for the password without echo; the password is never taken from argv or the environment). Further admins are created by existing admins in the UI, who can disable (not delete) accounts.
- Passwords: argon2id via `argon2-cffi` with documented parameters; automatic rehash on login when parameters change; minimum length 12; a short local list of obvious passwords is rejected. Password login can be turned off in settings once a passkey exists, but not if it would leave an account with no recovery path.
- Recovery: `guard-admin reset-password` and `guard-admin revoke-passkeys` on the server. Passkeys are never the only way back in.

### 7.2 Sessions and CSRF
- Session token: 32 random bytes, sent as a cookie `__Host-guard_session` (`HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`). The database stores only its SHA-256 hash (D7).
- Idle timeout (default 30 minutes) and absolute lifetime (default 12 hours); logout deletes the row; disabling an account revokes its sessions; password change revokes the others.
- CSRF: a token derived from the session with HMAC (key from `secrets.env`) is required on every state-changing request (`POST`, `PUT`, `PATCH`, `DELETE`) via a header or hidden field. Requests also have their `Origin` or `Referer` checked against the configured external origin. Missing or wrong tokens return 403 and an audit event.
- Rate limiting: per IP and per username on login and passkey endpoints, with exponential delay and lockout counters stored in SQLite so a restart does not reset them. Failures return the same message for unknown users and wrong passwords.

### 7.3 Passkeys (WebAuthn)
- Library: `webauthn` (py_webauthn). No custom signature or CBOR handling.
- Registration and authentication options are generated server-side with a random 32-byte challenge, held **in memory only**, single use, expiring after 5 minutes, bound to the session or the sign-in attempt (D8).
- Verification passes the configured RP ID (the dashboard hostname) and the exact expected origin. User verification is required for passkey sign-in. The stored sign count is checked: a regression is rejected and audited unless the authenticator reports a zero counter (as many platform authenticators do).
- Multiple passkeys per account, each with a name, created and last-used dates, and a revoke action (re-authentication required). Credential IDs are unique. Revoking the last passkey is allowed only if password login is enabled.
- Revoking **deletes** the passkey row. The audit event records the passkey's name and the first 8 hex characters of the SHA-256 of its credential ID (SCHEMA.md decision S8).
- Stored per credential: ID, public key, sign count, transports, AAGUID, name, timestamps. No challenge data is stored (rule 1).

### 7.4 Authorization and audit
- Every dashboard route is behind an `require_admin` dependency by default; public routes (login page, static assets, health) are an explicit allow-list. A Stage 9 test walks the route table and fails on any unlisted unauthenticated route.
- Audit events: sign-in success and failure, logout, passkey add and remove, password change, admin create and disable, every settings change, every IP and URL rule change, block page publish, injection change, backup and restore, CSRF failures. Each has actor, time, IP, action, target and a short detail. Details never contain secrets or request bodies.

---

## 8. Background jobs, backups and retention

### 8.1 In-process tasks
Tailer and writer (section 2), lookup worker and Tor updater (section 3), rule-expiry sweeper (every 30 seconds), snapshot reconciler (every 30 seconds), session and rate-limit cleanup (hourly). Each reports a heartbeat and last error into the `component_health` table that feeds the in-app notifications (Q9; notifications are derived, not stored, SCHEMA.md decision S12): stale Tor feed, repeated lookup failures, ingest lag, spool gap, backup failure, low disk.

### 8.2 Backups
- A systemd timer runs `guard-admin backup` nightly: SQLite online backup API to a temp file, `PRAGMA integrity_check`, then rename into `/var/backups/initstack-guard/` with mode 0600. Retention: 14 daily and 8 weekly (Q11), configurable.
- Restore is CLI-only: `guard-admin restore <file>` stops nothing by itself; the restore script stops the service, verifies the backup, keeps a copy of the current database, replaces it, runs migrations, and starts the service (D13).
- The dashboard lists backups and can trigger a backup now, but cannot restore.

### 8.3 Retention and cleanup
- Defaults (Q8): raw requests 90 days, hourly rollups 2 years, audit log 1 year, `ingest_errors` ring 1,000 rows, expired sessions removed daily.
- A weekly job deletes in bounded batches (for example 10,000 rows per transaction) so it never holds the writer lock for long, removes orphaned `urls` and `visitors` with no remaining requests and no manual rule, and runs `PRAGMA optimize`. `VACUUM` is manual only.
- Changing retention to a shorter period shows how many rows will be deleted and requires confirmation.

### 8.4 Migrations
Numbered SQL files in `guard/migrations/`, applied in order inside a transaction, recorded in a `schema_migrations` table with a checksum. The service refuses to start if the database is newer than the code. A backup is taken automatically before a migration that changes existing tables.

---

## Open items
- IPLogs authentication, rate limits and `confidence` semantics must be verified against the official docs before Stage 5.
- Exact tables, indexes and settings defaults are in SCHEMA.md; every route with its authentication, CSRF and rate-limit class is in API.md.
