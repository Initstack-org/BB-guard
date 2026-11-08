# GOAL: InitStack Guard

**One-line goal:** a self-hosted control panel for `initstack.org` that records every HTTP request
passing through Nginx, moderates IPs (IPLogs + Tor feed + manual rules), enforces URL access rules
with a custom block page, manages MyBB HTML/topbar injections, and is protected by its own
passkey-capable login. No paid services. Modular, tested, deployable on the existing Ubuntu server.

The original requirements document ("InitStack Guard - Project Requirements and Claude Build
Prompt") is the source of truth. Save your copy as `docs/SPEC.md`. This file is the condensed,
checkable version of it. If they disagree, the spec wins and this file gets fixed.

Status of each item lives in `PROGRESS.md`, not here.

---

## 1. Definition of done (acceptance criteria)

### A. Dashboard UI (spec section 2)
- Cloudflare-style layout: persistent left sidebar that collapses/expands, top bar (global search,
  notifications, account menu), breadcrumbs on inner pages, responsive (desktop/tablet/mobile),
  dark and light themes.
- Sidebar sections, exactly: **Overview** (Dashboard) / **Traffic** (Visitors, IP Intelligence,
  URL History) / **Security** (IP Rules, URL Access Rules, Block Page) / **MyBB** (HTML Injections,
  Injection History/Versions) / **Administration** (Administrators, Authentication/Passkeys, Audit
  Log, API Settings, General Settings, Backups and Retention).
- Consistent tables, filters, pagination, cards, charts. Clear status indicators for allowed,
  blocked, overridden, monitoring-only.

### B. Visitor monitoring (section 3)
- Every request through Nginx is recorded: UTC timestamp (shown in the admin's timezone), client
  IP, method, path + redacted query, host, status, bytes received, bytes sent, duration,
  User-Agent, referrer, MyBB UID/username when reliably known, allowed/denied/monitored, rule or
  reason for a denial.
- Visitor search by IP: first/last seen, request count, byte totals, all timestamps, every URL
  with per-URL hit count, methods, status codes, User-Agent history, MyBB account, IP intel,
  moderation status. Date-range filters, pagination, single-request detail view.
- Never stored: passwords, session cookies, authorization headers, passkey challenge data, POST
  bodies. Sensitive query params (password, token, key, session, auth...) are redacted.

### C. URL history (first-class feature)
- Search a URL/path; every recorded request to it; total visits; unique IP count; timestamps, IPs,
  methods, statuses, transfer sizes; filters (date range, IP, status); ranked most-accessed table;
  requests / bytes-in / bytes-out graphs over time (24h, 7d, 30d, custom; units and time zone
  labelled); CSV export of filtered records.
- Byte counts are HTTP traffic through this site only. The UI must not claim more.

### D. IP intelligence and moderation (section 4)
- IPLogs integration (`POST https://iplogs.com/v1/check`, body `{"ip": "..."}`), following current
  IPLogs docs for auth / rate limits / free tier; credentials configurable and stored outside
  source. Uses verdict, score, is_vpn/proxy/tor/relay/hosting/crawler, confidence, reputation,
  ip_info (ASN, org, ISP, country, prefix), signals.
- Independent Tor exit-node feed: configurable schedule, validated download, last-known-good kept
  if an update fails.
- **Hosting alone never blocks.** VPN/proxy/Tor/relay decision logic is configurable and shows
  reason + confidence. An API outage is "unknown", never proof of malice (fail open by default).
- Per-IP view: flags, ISP/ASN/org/country/prefix, request and transfer totals, URL history,
  manual status + notes, denied-request count.
- Actions: Whitelist/Allow override, Manual block, IPLogs-only (clear overrides), Monitor only;
  optional expiry; who/when/why recorded. Lookups cached with configurable TTL; never one external
  call per HTTP request.

### E. Enforcement scope (section 5)
- Monitor everyone, but reputation enforcement applies only to MyBB login and registration by
  default (`member.php?action=login|do_login|register|do_register`, plus any extra real steps found
  in MyBB 1.8.41). No blocking of ordinary browsing for VPN/proxy/Tor/hosting. Existing users are
  not rechecked or disconnected.
- Manual IP rules and URL rules are separate and follow their own targets.

### F. URL access rules (section 6)
- Add a rule by entering a URL or path. Exact and path-prefix match, optional query match,
  enable/disable, global or per-IP, allow/deny, optional expiry, description + notes, priority with
  deterministic conflict resolution, and a test/preview that explains which rule matches a given
  URL + IP.
- Safe matching only: normalize host/path, no substring matching, and an overly broad rule must
  not be able to deny the whole site by accident.

### G. Block page editor (section 7)
- HTML source editor, preview, save and publish, enable/disable, version history + restore, safe
  built-in default page, placeholders `{{ visitor_ip }}`, `{{ block_reason }}`,
  `{{ detection_type }}`, `{{ timestamp }}`, `{{ appeal_url }}` (values HTML-escaped).
- Preview must be isolated (sandboxed / separate origin) so saved HTML can never run against the
  admin session. Served locally; no third-party dependencies.

### H. MyBB injection manager (section 8)
- Multiple independent injections, each with name, description, HTML, CSS, optional JS, enabled
  flag, position (top / after header / before footer, within available MyBB hooks), targeting
  (all MyBB URLs or an explicit path list; exact or prefix), priority, preview, version history +
  rollback.
- Delivered by a small MyBB 1.8 plugin using supported hooks/templates, not Nginx body rewriting.
  Sync from Guard must be private and authenticated (current design: atomic JSON file).
- JS runs in visitors' browsers: say so in the UI. Configuration is validated, but the admin's
  HTML is never silently rewritten.

### I. Authentication and passkeys (section 9)
- Own login system, separate from MyBB. WebAuthn/FIDO2 via a maintained library (no hand-rolled
  crypto): register, sign in, multiple passkeys per account, names, created/last-used dates,
  revoke. Correct challenge, origin, RP ID, signature, user-verification and replay handling.
- Password fallback (argon2id) when enabled; HttpOnly + Secure + SameSite cookies; CSRF on every
  state change; session expiry + logout; rate limiting; account disablement; audit log of sign-ins,
  failures, passkey add/remove, admin changes. No public registration: first admin via CLI.
  Passkeys are never the only recovery method.

### J. Security and deployment (section 10)
- Dedicated unprivileged service account, venv with pinned dependencies, loopback or Unix socket
  only, dashboard behind Nginx, auth + authorization on every admin route, parameterized SQL,
  escaped output, SSRF/path-traversal/command-injection protections, secrets only in
  permission-restricted env files, restrictive permissions on DB/backups/logs, migrations,
  automatic backups, configurable retention + cleanup, clean restart behaviour, health checks,
  logs without secrets, rollback copies of Nginx/MyBB files before any change.
- Trusted client IP: only the real tunnel connector may set the client IP (currently
  `192.168.1.148` via `CF-Connecting-IP`). Never trust forwarded headers from anyone else.
- Nginx writes structured JSON access logs; Python ingests them reliably. No synchronous external
  API calls in the Nginx request path.

### K. Data management (section 11)
- SQLite tables for admins, passkeys, sessions, visitor IPs, requests, IP intel cache, IP rules,
  URL rules, block page versions, injections + versions, audit events, settings, Tor feed state.
  Indexes on IP, timestamp, URL/path, status. Bounded, paginated queries.
- DB backup and restore, CSV export (visitors, URL history), retention setting, safe cleanup
  jobs, schema migrations.

---

## 2. Non-negotiable rules
1. Never log or store passwords, session cookies, auth headers, passkey challenge data or POST bodies.
2. Never trust `CF-Connecting-IP` or any forwarded header except from the trusted connector.
3. IPLogs is never called synchronously from the Nginx path; decisions come from cache.
4. Reputation checks fail open on API errors; manual IP/URL rules keep working regardless.
5. `is_hosting` alone never blocks anything.
6. Reputation enforcement is limited to login/registration unless an admin changes the setting.
7. Use a maintained WebAuthn library. No custom crypto.
8. Parameterized SQL only; escape all output; CSRF on every state change.
9. Block page preview is sandboxed/isolated from the admin origin.
10. Before touching Nginx or MyBB: timestamped backup, show the change, `nginx -t`, then
    `reload` (never restart). Never print or request the MyBB DB password.
11. Do not call a feature done until its code and tests exist. State limitations honestly.
12. No credentials, API keys or passkey secrets in logs, docs or source.

## 3. Explicitly out of scope
Automated threat hunting, complex anomaly detection, unrequested alerting, geographic maps (so
lat/lon from IPLogs is not stored), general network monitoring beyond this site's HTTP traffic,
paid security-service integrations. Do not add them.

## 4. Stage plan and exit criteria
| Stage | Deliverable | Exit criterion |
|---|---|---|
| 1 | Architecture, schema, API plan | Reviewed by owner |
| 2 | Backend foundation: config, migrations, admin CLI, auth, sessions, CSRF, audit | All tests pass on a machine with dependencies installed; first admin can sign in |
| 3 | Passkeys | Register/sign in/list/revoke work; tests for challenge, origin/RP ID, replay, invalid creds |
| 4 | Traffic monitoring | Nginx JSON logs ingested restart-safely; visitor + URL history, graphs, CSV, redaction tested |
| 5 | IP intelligence + moderation | IPLogs + Tor feed cached; four modes + expiry + audit; 8.8.8.8 hosting-only fixture does not block |
| 6 | URL rules, block page, enforcement | Deterministic rule resolution tested; preview isolated; Nginx integration validated; fails open when Guard is down |
| 7 | MyBB plugin + injection manager | Works on MyBB 1.8.41 for all-page and selected-path scopes; clean activate/deactivate |
| 8 | Full UI + deployment | All sidebar pages; install/upgrade/backup/restore/rollback/uninstall scripts and checklist |
| 9 | Verification | Tests, lint, route-authorization sweep, spoofed-header tests, outage tests, honest limitations list |

The project is **done** when every stage's exit criterion is met, `PROGRESS.md` shows no open
blockers, and the README documents install, operation, backup, restore, rollback and known
limitations.
