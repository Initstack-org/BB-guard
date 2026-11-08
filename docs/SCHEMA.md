# InitStack Guard: SQLite Schema

> **Status:** Stage 1 draft v0.1, written 2026-11-08, awaiting owner review.
> **Source:** `GOAL.md` section 1.K, [ARCHITECTURE.md](ARCHITECTURE.md) and [SUBSYSTEMS.md](SUBSYSTEMS.md). `docs/SPEC.md` was not available; where it disagrees with this file, the spec wins.
> **Companions:** [API.md](API.md) (route plan).
> **Nothing here is applied to any database yet.** The DDL in section 5 was run only in a scratch sandbox (section 11 says exactly what was and was not checked).

## Contents
1. Scope and conventions
2. Schema decisions
3. Tables at a glance
4. Enumerations
5. The DDL (six migrations)
6. Settings registry
7. Index map
8. Size estimate
9. Retention and deletion order
10. Personal data inventory
11. What was verified, and what was not
12. Open items for the owner

---

## 1. Scope and conventions

- **Engine:** SQLite 3.37 or newer. The schema uses `STRICT` tables (3.37) and the JSON functions `json_valid` and `json_type`. `guard-admin doctor` must check both the version and that the JSON functions exist (some SQLite builds omit them).
- **Per connection:** `PRAGMA foreign_keys=ON`, `busy_timeout=5000`, `synchronous=NORMAL`. **Once per database:** `PRAGMA journal_mode=WAL` (decision D6). The database lives on a local disk, never a network filesystem.
- **Time:** every timestamp is an integer count of **milliseconds since the Unix epoch, UTC**, in a column ending `_ms`. For a request, `ts_ms` is Nginx's `$msec`: the moment the log line was written, which is when the response finished, not when the request started. Conversion to the admin's timezone happens only in the UI.
- **Booleans:** `INTEGER` 0 or 1 with a `CHECK`.
- **Hard ceilings:** length and size limits are `CHECK` constraints, so they hold even if application code has a bug. Settings may lower a limit but never raise it above the ceiling in the DDL.
- **IP addresses:** canonical text (`ipaddress.ip_address(...).compressed`, IPv4-mapped IPv6 unmapped). Prefix search is a range comparison (`ip >= ? AND ip < ?`), not `LIKE`, so it can use the index.
- **Names:** `idx_<table>_<columns>` for indexes, `uq_...` for unique indexes, `trg_...` for triggers.
- **JSON columns** are validated with `json_valid`. Where a shape matters (`query_match`, `targets`), `json_type` pins it to an object or an array.
- **No table holds WebAuthn challenges, passwords in clear, cookies, authorization headers or request bodies.** That is deliberate (rule 1, decision D8).

---

## 2. Schema decisions

All are proposals for the owner to confirm or overrule. They continue the numbering style of ARCHITECTURE.md but use the prefix **S**.

| # | Decision | Why, and what was rejected |
|---|---|---|
| S1 | Every table is `STRICT` and carries `CHECK` constraints for enumerations, lengths and shapes. | A second line of defence behind application validation. SQLite's default typing would accept text in an integer column. Cost: needs SQLite 3.37 or newer, which matches assumption Q12. |
| S2 | Repeated strings are interned in small dictionary tables: `user_agents`, `referrers`, `mybb_accounts`. A request row stores only integers. | A User-Agent is about 100 bytes; storing it per request would dominate the table. Fewer copies of personal data is also better. Cost: a renamed MyBB user shows the latest name on old requests. |
| S3 | **No foreign key** on `requests.ua_id`, `requests.referrer_id`, `requests.mybb_uid`, `visitor_user_agents.ua_id` and `visitor_accounts.mybb_uid`. Dictionary rows carry `last_seen_ms`, and retention deletes dictionary rows older than the raw-request cutoff after the requests are gone. Foreign keys stay where the child column leads an index (`visitor_id`, `url_id`). | Without an index on the child column, SQLite scans the whole child table for every parent row deleted. Measured in the sandbox: 6.3 ms per deleted parent row over 200,000 child rows, against 0.004 ms with no foreign key. That grows linearly, so at 9 million rows it would be roughly 0.3 s per row, and a cleanup of thousands of rows would take many minutes while holding the writer. Indexing the child columns instead would add about 18 bytes per request per column. |
| S4 | Aggregates (`visitors`, `urls`, `visitor_urls`, `visitor_user_agents`, `visitor_accounts`, `mybb_accounts`, the rollups) are written by the ingest writer in the **same transaction** as the request rows and the file offset. | They cannot disagree with `requests` after a crash. They are counted "since first seen" and survive deletion of raw rows, so the UI labels them "total since first seen; raw rows kept for N days". |
| S5 | Site-wide hourly rollups are kept for the full rollup retention. **Per-URL hourly rollups are kept only for URLs with at least `retention.rollup_min_hits` total hits** (default 10); rollup rows of rarer URLs are deleted when their raw rows expire. | Scanner traffic produces huge numbers of URLs hit once. Unbounded per-URL rollups would grow about as fast as the raw table and defeat the 90-day raw limit. This extends SUBSYSTEMS.md section 2.6 and needs the owner's agreement. |
| S6 | The reason, detection and rule of a decision are copied onto the request row (`detection`, `rule_ref`, `reason`). `rule_ref` is plain text (`ip:203.0.113.7`, `url:12`) with no foreign key. | Rules get edited and deleted; history must still read correctly. `reason` is the sentence shown in the UI. |
| S7 | Admins are never deleted in v1; they are disabled. Foreign keys to `admins` use the default `NO ACTION`, so a stray `DELETE FROM admins` fails for anyone with history. `passkeys` and `sessions` cascade. | Preserves audit history (tested). |
| S8 | Revoking a passkey **deletes its row**. The audit event records the passkey's name and the first 8 hex characters of the SHA-256 of its credential ID. | A revoked credential can never authenticate, and the same authenticator can be registered again without a unique-key clash. Soft revocation was rejected for that reason. |
| S9 | `audit_events` rejects `UPDATE` (trigger). `block_page_versions` rejects changes to its content columns, and `injection_versions` rejects any `UPDATE` (triggers). `DELETE` is allowed only because retention needs it; only the retention code path deletes. | Version history must never be rewritten (GOAL G, H). A trigger is a guardrail against bugs, not against someone with SQL access who can drop it. |
| S10 | A `change_counters` table, bumped by triggers on `settings`, `ip_rules`, `url_rules`, `block_page_versions` and `injections`, tells the 30-second Snapshot reconciler what changed without reading the tables. The `intel` and `tor` counters are bumped by code. | Triggers cannot be forgotten by a new code path. Bulk Tor list replacement would fire thousands of triggers, so that one is explicit. |
| S11 | Backups are **not** listed in the database. Each backup file has a small JSON manifest beside it (schema version, size, SHA-256, kind); the Backups page reads the directory. | A restore replaces the database, so a table of backups inside it would forget backups made after the restored copy. |
| S12 | `component_health` is a table of heartbeats and last errors. Notifications are derived from it and are not stored; there is no per-admin "dismissed" state in v1. | SUBSYSTEMS.md section 8.1 called it a view; heartbeats need somewhere to live. Stored notifications were not requested. |

**Differences from the earlier docs**, so a reviewer can see them in one place: `request_id` is a 16-byte `BLOB` (SUBSYSTEMS 2.2 said a unique index on the id); `visitor_urls`, `visitor_user_agents` and `visitor_accounts` are new aggregates (2.6); per-URL rollups are thresholded (S5); `ip_intel` keeps earlier good data when a lookup fails and tracks `retry_after_ms` separately (3.1, 3.2); `component_health` is a table (8.1); revoking a passkey deletes it (7.3). SUBSYSTEMS.md has been edited to match.

---

## 3. Tables at a glance

30 tables, 35 named indexes, 18 triggers. "Writer" is the only component that inserts or updates the table; the Snapshot reads `settings`, `ip_rules`, `url_rules`, `ip_intel`, `tor_exit_nodes` and the published `block_page_versions` row.

| Migration (stage) | Table | Writer | Purpose |
|---|---|---|---|
| 0001 (2) | `admins` | dashboard, CLI | Administrator accounts, preferences (timezone, theme), WebAuthn user handle |
| | `settings` | dashboard, CLI | Runtime settings as JSON (section 6) |
| | `sessions` | auth | Server-side sessions; only a SHA-256 of the cookie token is stored |
| | `auth_throttle` | auth | Failed-login counters and lockouts, surviving restarts |
| | `audit_events` | everything | Append-only audit log |
| | `change_counters` | triggers, code | Change detection for the Snapshot |
| | `component_health` | background tasks | Heartbeats and last errors that feed notifications |
| 0002 (3) | `passkeys` | auth | WebAuthn credentials |
| 0003 (4) | `visitors` | ingest | One row per IP: first/last seen, totals |
| | `urls` | ingest | One row per host + normalized path |
| | `requests` | ingest | One row per request that reached Nginx |
| | `user_agents`, `referrers`, `mybb_accounts` | ingest | Dictionaries for repeated strings (S2) |
| | `visitor_urls` | ingest | Per IP and URL: hits and first/last seen |
| | `visitor_user_agents`, `visitor_accounts` | ingest | Per IP: User-Agent history and MyBB accounts seen |
| | `rollup_site_hourly`, `rollup_url_hourly` | ingest | Hourly counters for graphs and rankings |
| | `ingest_state` | ingest | Log file position (one row) |
| | `ingest_errors` | ingest | Bounded ring of parse errors and gap notices |
| 0004 (5) | `ip_intel` | lookup worker | Cached IPLogs result per IP |
| | `tor_exit_nodes`, `tor_feed_state` | Tor updater | Last-known-good exit list and feed status |
| | `ip_rules` | dashboard, sweeper | Manual IP moderation (allow, block, monitor) |
| 0005 (6) | `url_rules` | dashboard, sweeper | URL access rules |
| | `block_page_versions` | dashboard | Block page HTML history; one published |
| 0006 (7) | `injections` | dashboard | Current state of each MyBB injection |
| | `injection_versions` | dashboard | Immutable history of injection content |
| | `mybb_export_state` | exporter | Generation counter and hash of the exported JSON file |

Coverage of `GOAL.md` section 1.K: admins, passkeys, sessions, visitor IPs (`visitors`), requests, IP intel cache, IP rules, URL rules, block page versions, injections and versions, audit events, settings and Tor feed state are all present. Everything else in the list above supports them.

---

## 4. Enumerations

| Column | Allowed values | Meaning |
|---|---|---|
| `requests.outcome` | `allowed`, `denied`, `overridden`, `monitored`, `unchecked` | What Guard decided. `unchecked`: Nginx logged the request but Guard did not answer. A plain 403 from MyBB or Nginx is `allowed` with status 403; only `outcome = 'denied'` means Guard blocked it. |
| `requests.detection` | `manual_ip_block`, `url_rule`, `reputation`, or NULL | Which layer produced (or would have produced) the denial. For `overridden` and `monitored` it is the suppressed detection. |
| `requests.method` | `GET HEAD POST PUT DELETE PATCH OPTIONS TRACE CONNECT OTHER` | Anything else is stored as `OTHER`. |
| `ip_rules.mode` | `allow`, `block`, `monitor` | "IPLogs-only" is the absence of a row, never a stored value. |
| `url_rules.action` / `match_type` | `allow`/`deny`; `exact`/`prefix` | |
| `ip_intel.status` | `ok`, `error`, `skipped` | `skipped` for private and reserved addresses. |
| `ingest_errors.kind` | `parse`, `gap` | |
| `sessions.auth_method` | `password`, `passkey` | |
| `injections.position` | `top`, `after_header`, `before_footer` | Final list depends on the MyBB 1.8.41 hooks verified in Stage 7. |
| `audit_events.outcome` | `success`, `failure`, `denied` | |
| `component_health.state` | `ok`, `warn`, `error`, `unknown` | |

---

## 5. The DDL

Six migrations, one per stage that needs them, so each stage can be built and tested on its own. The runner (Stage 2) applies each file inside one transaction and records its checksum in `schema_migrations`, a table the runner itself creates before migration 0001. Nothing else touches that table.

### 5.1 `0001_core.sql` (Stage 2)

```sql
-- 0001_core.sql (Stage 2): admins, settings, sessions, auth throttle, audit log,
-- change counters, component health.
-- Conventions: STRICT tables; every timestamp is integer epoch milliseconds (UTC), suffix _ms.

CREATE TABLE admins (
  id                   INTEGER PRIMARY KEY,
  username             TEXT    NOT NULL UNIQUE COLLATE NOCASE CHECK (length(username) BETWEEN 3 AND 64),
  display_name         TEXT    NOT NULL DEFAULT '' CHECK (length(display_name) <= 100),
  password_hash        TEXT    CHECK (password_hash IS NULL OR password_hash LIKE '$argon2id$%'),
  password_changed_ms  INTEGER,
  webauthn_user_handle BLOB    NOT NULL UNIQUE CHECK (length(webauthn_user_handle) BETWEEN 16 AND 64),
  timezone             TEXT    NOT NULL DEFAULT 'UTC' CHECK (length(timezone) BETWEEN 1 AND 64),
  theme                TEXT    NOT NULL DEFAULT 'system' CHECK (theme IN ('system','light','dark')),
  role                 TEXT    NOT NULL DEFAULT 'admin' CHECK (role IN ('admin')),
  is_disabled          INTEGER NOT NULL DEFAULT 0 CHECK (is_disabled IN (0,1)),
  disabled_ms          INTEGER,
  created_ms           INTEGER NOT NULL,
  created_by           INTEGER REFERENCES admins(id),
  last_login_ms        INTEGER
) STRICT;

CREATE TABLE settings (
  key        TEXT    PRIMARY KEY CHECK (length(key) BETWEEN 1 AND 100),
  value      TEXT    NOT NULL CHECK (json_valid(value) AND length(value) <= 16384),
  updated_ms INTEGER NOT NULL,
  updated_by INTEGER REFERENCES admins(id)
) STRICT, WITHOUT ROWID;

CREATE TABLE sessions (
  id           INTEGER PRIMARY KEY,
  token_hash   BLOB    NOT NULL UNIQUE CHECK (length(token_hash) = 32),
  admin_id     INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  auth_method  TEXT    NOT NULL CHECK (auth_method IN ('password','passkey')),
  created_ms   INTEGER NOT NULL,
  last_seen_ms INTEGER NOT NULL,
  expires_ms   INTEGER NOT NULL,
  ip           TEXT    NOT NULL CHECK (length(ip) BETWEEN 2 AND 45),
  user_agent   TEXT    NOT NULL DEFAULT '' CHECK (length(user_agent) <= 256),
  revoked_ms   INTEGER
) STRICT;
CREATE INDEX idx_sessions_admin   ON sessions(admin_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_ms);

CREATE TABLE auth_throttle (
  key              TEXT    PRIMARY KEY CHECK (length(key) BETWEEN 4 AND 80),
  failures         INTEGER NOT NULL DEFAULT 0 CHECK (failures >= 0),
  first_failure_ms INTEGER NOT NULL,
  last_failure_ms  INTEGER NOT NULL,
  locked_until_ms  INTEGER NOT NULL DEFAULT 0
) STRICT, WITHOUT ROWID;
CREATE INDEX idx_auth_throttle_last ON auth_throttle(last_failure_ms);

CREATE TABLE audit_events (
  id             INTEGER PRIMARY KEY,
  ts_ms          INTEGER NOT NULL,
  actor_admin_id INTEGER REFERENCES admins(id),
  actor_name     TEXT    NOT NULL DEFAULT '' CHECK (length(actor_name) <= 64),
  ip             TEXT    NOT NULL DEFAULT '' CHECK (length(ip) <= 45),
  action         TEXT    NOT NULL CHECK (length(action) BETWEEN 1 AND 64),
  outcome        TEXT    NOT NULL CHECK (outcome IN ('success','failure','denied')),
  target_type    TEXT    NOT NULL DEFAULT '' CHECK (length(target_type) <= 32),
  target_id      TEXT    NOT NULL DEFAULT '' CHECK (length(target_id) <= 128),
  detail         TEXT    CHECK (detail IS NULL OR (json_valid(detail) AND length(detail) <= 4096))
) STRICT;
CREATE INDEX idx_audit_ts        ON audit_events(ts_ms);
CREATE INDEX idx_audit_actor_ts  ON audit_events(actor_admin_id, ts_ms);
CREATE INDEX idx_audit_action_ts ON audit_events(action, ts_ms);
CREATE INDEX idx_audit_target    ON audit_events(target_type, target_id, ts_ms);
CREATE TRIGGER trg_audit_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;

CREATE TABLE change_counters (
  name  TEXT    PRIMARY KEY,
  value INTEGER NOT NULL DEFAULT 0
) STRICT, WITHOUT ROWID;
INSERT INTO change_counters(name) VALUES
  ('settings'),('ip_rules'),('url_rules'),('block_page'),('intel'),('tor'),('injections');

CREATE TRIGGER trg_settings_ai AFTER INSERT ON settings
BEGIN UPDATE change_counters SET value = value + 1 WHERE name = 'settings'; END;
CREATE TRIGGER trg_settings_au AFTER UPDATE ON settings
BEGIN UPDATE change_counters SET value = value + 1 WHERE name = 'settings'; END;
CREATE TRIGGER trg_settings_ad AFTER DELETE ON settings
BEGIN UPDATE change_counters SET value = value + 1 WHERE name = 'settings'; END;

CREATE TABLE component_health (
  component     TEXT    PRIMARY KEY CHECK (length(component) BETWEEN 1 AND 32),
  state         TEXT    NOT NULL CHECK (state IN ('ok','warn','error','unknown')),
  heartbeat_ms  INTEGER,
  last_ok_ms    INTEGER,
  last_error_ms INTEGER,
  last_error    TEXT    CHECK (last_error IS NULL OR length(last_error) <= 300),
  detail        TEXT    CHECK (detail IS NULL OR (json_valid(detail) AND length(detail) <= 1024))
) STRICT, WITHOUT ROWID;
```

Notes:
- `webauthn_user_handle` is random bytes, never derived from the username, as WebAuthn requires of a user handle.
- `password_hash` may be NULL (an account that signs in only with a passkey). The CLI can always reset it (SUBSYSTEMS 7.1).
- Throttle keys are `ip:<address>` or `user:<first 32 hex of SHA-256 of the lower-cased username>`, never the raw attacker-supplied name, so the table cannot be filled with arbitrary text.
- `audit_events.detail` must never contain secrets, request bodies or passkey material (SUBSYSTEMS 7.4).

### 5.2 `0002_passkeys.sql` (Stage 3)

```sql
-- 0002_passkeys.sql (Stage 3). No table for WebAuthn challenges, by design (rule 1, decision D8).

CREATE TABLE passkeys (
  id              INTEGER PRIMARY KEY,
  admin_id        INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  credential_id   BLOB    NOT NULL UNIQUE CHECK (length(credential_id) BETWEEN 16 AND 1023),
  public_key      BLOB    NOT NULL,
  sign_count      INTEGER NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
  transports      TEXT    CHECK (transports IS NULL OR json_valid(transports)),
  aaguid          TEXT    CHECK (aaguid IS NULL OR length(aaguid) = 36),
  backup_eligible INTEGER CHECK (backup_eligible IS NULL OR backup_eligible IN (0,1)),
  backup_state    INTEGER CHECK (backup_state IS NULL OR backup_state IN (0,1)),
  name            TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
  created_ms      INTEGER NOT NULL,
  last_used_ms    INTEGER
) STRICT;
CREATE INDEX        idx_passkeys_admin      ON passkeys(admin_id);
CREATE UNIQUE INDEX uq_passkeys_admin_name  ON passkeys(admin_id, name COLLATE NOCASE);
```

Notes:
- The 16 to 1023 byte range matches what WebAuthn allows for a credential ID (maximum 1023 bytes).
- `public_key` is whatever encoding the `webauthn` library returns; the schema does not interpret it.
- Revoking deletes the row (S8).

### 5.3 `0003_traffic.sql` (Stage 4)

```sql
-- 0003_traffic.sql (Stage 4): visitors, URLs, requests, dictionaries, aggregates, rollups, ingest state.

CREATE TABLE visitors (
  id            INTEGER PRIMARY KEY,
  ip            TEXT    NOT NULL UNIQUE CHECK (length(ip) BETWEEN 2 AND 45),
  first_seen_ms INTEGER NOT NULL,
  last_seen_ms  INTEGER NOT NULL,
  request_count INTEGER NOT NULL DEFAULT 0,
  bytes_in      INTEGER NOT NULL DEFAULT 0,
  bytes_out     INTEGER NOT NULL DEFAULT 0,
  denied_count  INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX idx_visitors_last_seen ON visitors(last_seen_ms);
CREATE INDEX idx_visitors_requests  ON visitors(request_count);

CREATE TABLE urls (
  id             INTEGER PRIMARY KEY,
  host           TEXT    NOT NULL CHECK (length(host) BETWEEN 1 AND 255),
  path           TEXT    NOT NULL CHECK (substr(path, 1, 1) = '/' AND length(path) <= 2048),
  path_truncated INTEGER NOT NULL DEFAULT 0 CHECK (path_truncated IN (0,1)),
  first_seen_ms  INTEGER NOT NULL,
  last_seen_ms   INTEGER NOT NULL,
  hit_count      INTEGER NOT NULL DEFAULT 0,
  UNIQUE (host, path)
) STRICT;
CREATE INDEX idx_urls_path      ON urls(path);
CREATE INDEX idx_urls_hits      ON urls(hit_count);
CREATE INDEX idx_urls_last_seen ON urls(last_seen_ms);

CREATE TABLE user_agents (
  id            INTEGER PRIMARY KEY,
  value         TEXT    NOT NULL UNIQUE CHECK (length(value) <= 512),
  first_seen_ms INTEGER NOT NULL,
  last_seen_ms  INTEGER NOT NULL
) STRICT;
CREATE INDEX idx_user_agents_last_seen ON user_agents(last_seen_ms);

CREATE TABLE referrers (
  id            INTEGER PRIMARY KEY,
  value         TEXT    NOT NULL UNIQUE CHECK (length(value) <= 1024),
  first_seen_ms INTEGER NOT NULL,
  last_seen_ms  INTEGER NOT NULL
) STRICT;
CREATE INDEX idx_referrers_last_seen ON referrers(last_seen_ms);

CREATE TABLE mybb_accounts (
  uid           INTEGER PRIMARY KEY CHECK (uid > 0),
  username      TEXT    NOT NULL CHECK (length(username) BETWEEN 1 AND 120),
  first_seen_ms INTEGER NOT NULL,
  last_seen_ms  INTEGER NOT NULL,
  request_count INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX idx_mybb_accounts_username  ON mybb_accounts(username COLLATE NOCASE);
CREATE INDEX idx_mybb_accounts_last_seen ON mybb_accounts(last_seen_ms);

CREATE TABLE requests (
  id          INTEGER PRIMARY KEY,
  request_id  BLOB    NOT NULL UNIQUE CHECK (length(request_id) = 16),
  ts_ms       INTEGER NOT NULL,
  visitor_id  INTEGER NOT NULL REFERENCES visitors(id),
  url_id      INTEGER NOT NULL REFERENCES urls(id),
  method      TEXT    NOT NULL CHECK (method IN
                ('GET','HEAD','POST','PUT','DELETE','PATCH','OPTIONS','TRACE','CONNECT','OTHER')),
  query       TEXT    CHECK (query IS NULL OR length(query) <= 1024),
  status      INTEGER NOT NULL CHECK (status BETWEEN 0 AND 999),
  bytes_in    INTEGER NOT NULL DEFAULT 0 CHECK (bytes_in  >= 0),
  bytes_out   INTEGER NOT NULL DEFAULT 0 CHECK (bytes_out >= 0),
  duration_ms INTEGER NOT NULL DEFAULT 0 CHECK (duration_ms >= 0),
  ua_id       INTEGER,   -- user_agents.id; deliberately no FOREIGN KEY (decision S3)
  referrer_id INTEGER,   -- referrers.id;   deliberately no FOREIGN KEY (decision S3)
  mybb_uid    INTEGER,   -- mybb_accounts.uid; deliberately no FOREIGN KEY (decision S3)
  managed     INTEGER NOT NULL DEFAULT 1 CHECK (managed IN (0,1)),
  outcome     TEXT    NOT NULL CHECK (outcome IN ('allowed','denied','overridden','monitored','unchecked')),
  detection   TEXT    CHECK (detection IS NULL OR detection IN ('manual_ip_block','url_rule','reputation')),
  rule_ref    TEXT    CHECK (rule_ref IS NULL OR length(rule_ref) <= 64),
  reason      TEXT    CHECK (reason IS NULL OR length(reason) <= 200)
) STRICT;
CREATE INDEX idx_requests_ts         ON requests(ts_ms);
CREATE INDEX idx_requests_visitor_ts ON requests(visitor_id, ts_ms);
CREATE INDEX idx_requests_url_ts     ON requests(url_id, ts_ms);
CREATE INDEX idx_requests_status_ts  ON requests(status, ts_ms);
CREATE INDEX idx_requests_flagged_ts ON requests(ts_ms) WHERE outcome <> 'allowed';

CREATE TABLE visitor_urls (
  visitor_id    INTEGER NOT NULL REFERENCES visitors(id),
  url_id        INTEGER NOT NULL REFERENCES urls(id),
  first_seen_ms INTEGER NOT NULL,
  last_seen_ms  INTEGER NOT NULL,
  hits          INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (visitor_id, url_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX idx_visitor_urls_url       ON visitor_urls(url_id);
CREATE INDEX idx_visitor_urls_last_seen ON visitor_urls(last_seen_ms);

CREATE TABLE visitor_user_agents (
  visitor_id    INTEGER NOT NULL REFERENCES visitors(id),
  ua_id         INTEGER NOT NULL,   -- no FOREIGN KEY (decision S3)
  first_seen_ms INTEGER NOT NULL,
  last_seen_ms  INTEGER NOT NULL,
  hits          INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (visitor_id, ua_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX idx_visitor_user_agents_last_seen ON visitor_user_agents(last_seen_ms);

CREATE TABLE visitor_accounts (
  visitor_id    INTEGER NOT NULL REFERENCES visitors(id),
  mybb_uid      INTEGER NOT NULL,   -- no FOREIGN KEY (decision S3)
  first_seen_ms INTEGER NOT NULL,
  last_seen_ms  INTEGER NOT NULL,
  hits          INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (visitor_id, mybb_uid)
) STRICT, WITHOUT ROWID;
CREATE INDEX idx_visitor_accounts_uid       ON visitor_accounts(mybb_uid);
CREATE INDEX idx_visitor_accounts_last_seen ON visitor_accounts(last_seen_ms);

CREATE TABLE rollup_site_hourly (
  hour_ms  INTEGER PRIMARY KEY CHECK (hour_ms % 3600000 = 0),
  requests INTEGER NOT NULL DEFAULT 0,
  bytes_in INTEGER NOT NULL DEFAULT 0,
  bytes_out INTEGER NOT NULL DEFAULT 0,
  denied   INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE rollup_url_hourly (
  hour_ms  INTEGER NOT NULL CHECK (hour_ms % 3600000 = 0),
  url_id   INTEGER NOT NULL REFERENCES urls(id),
  requests INTEGER NOT NULL DEFAULT 0,
  bytes_in INTEGER NOT NULL DEFAULT 0,
  bytes_out INTEGER NOT NULL DEFAULT 0,
  denied   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (hour_ms, url_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX idx_rollup_url_hourly_url ON rollup_url_hourly(url_id, hour_ms);

CREATE TABLE ingest_state (
  id                  INTEGER PRIMARY KEY CHECK (id = 1),
  file_dev            INTEGER,
  file_inode          INTEGER,
  head_hash           BLOB    CHECK (head_hash IS NULL OR length(head_hash) = 32),
  file_offset         INTEGER NOT NULL DEFAULT 0 CHECK (file_offset >= 0),
  updated_ms          INTEGER NOT NULL DEFAULT 0,
  last_request_ms     INTEGER,
  lines_total         INTEGER NOT NULL DEFAULT 0,
  bad_lines_total     INTEGER NOT NULL DEFAULT 0,
  peer_mismatch_total INTEGER NOT NULL DEFAULT 0
) STRICT;
INSERT INTO ingest_state(id) VALUES (1);

CREATE TABLE ingest_errors (
  id     INTEGER PRIMARY KEY,
  ts_ms  INTEGER NOT NULL,
  kind   TEXT    NOT NULL CHECK (kind IN ('parse','gap')),
  detail TEXT    NOT NULL CHECK (length(detail) <= 300)
) STRICT;
```

Notes:
- **`request_id`** holds the decoded Nginx `$request_id` (16 bytes). If a log line has no valid id, ingest uses the first 16 bytes of a BLAKE2b digest of the raw line, so replaying the same line still deduplicates.
- **`managed = 0`** marks requests whose `Host` is outside `site.hosts` (scanners hitting the bare IP, for example). They are recorded and never enforced.
- **`ingest_state`** identifies the log file by device, inode and a hash of its first bytes (`head_hash`, set once at least 256 bytes have been read), so a rotated file that reuses an inode number is still noticed. The tailer algorithm itself is Stage 4 work.
- **Per-IP User-Agent and account lists are capped in code** (100 distinct User-Agents and 20 accounts per visitor). Requests beyond the cap are still stored; only the summary row is skipped and the UI shows "and more".
- **Per-IP method and status distributions** are computed from `requests` on demand for the chosen date range (default 7 days), not stored.

### 5.4 `0004_intel_ip_rules.sql` (Stage 5)

```sql
-- 0004_intel_ip_rules.sql (Stage 5): IP intelligence cache, Tor feed, manual IP rules.

CREATE TABLE ip_intel (
  ip              TEXT    PRIMARY KEY CHECK (length(ip) BETWEEN 2 AND 45),
  status          TEXT    NOT NULL CHECK (status IN ('ok','error','skipped')),
  data_fetched_ms INTEGER,                      -- when the data below was fetched; NULL if never fetched
  expires_ms      INTEGER,                      -- end of the TTL for that data; NULL if no data
  retry_after_ms  INTEGER NOT NULL DEFAULT 0,   -- earliest time for the next lookup (errors, 429)
  verdict         TEXT,
  score           REAL,
  is_vpn          INTEGER CHECK (is_vpn      IS NULL OR is_vpn      IN (0,1)),
  is_proxy        INTEGER CHECK (is_proxy    IS NULL OR is_proxy    IN (0,1)),
  is_tor          INTEGER CHECK (is_tor      IS NULL OR is_tor      IN (0,1)),
  is_relay        INTEGER CHECK (is_relay    IS NULL OR is_relay    IN (0,1)),
  is_hosting      INTEGER CHECK (is_hosting  IS NULL OR is_hosting  IN (0,1)),
  is_crawler      INTEGER CHECK (is_crawler  IS NULL OR is_crawler  IN (0,1)),
  confidence      TEXT,                         -- as received (JSON scalar text); meaning unverified
  reputation      TEXT,                         -- as received; meaning unverified
  asn             TEXT,
  org             TEXT,
  isp             TEXT,
  country         TEXT,
  prefix          TEXT,
  signals         TEXT    CHECK (signals IS NULL OR (json_valid(signals) AND length(signals) <= 4096)),
  error_kind      TEXT    CHECK (error_kind IS NULL OR length(error_kind) <= 32),
  error_ms        INTEGER,
  error_count     INTEGER NOT NULL DEFAULT 0 CHECK (error_count >= 0)
) STRICT, WITHOUT ROWID;
CREATE INDEX idx_ip_intel_expires ON ip_intel(expires_ms);

CREATE TABLE tor_exit_nodes (
  ip TEXT PRIMARY KEY CHECK (length(ip) BETWEEN 2 AND 45)
) STRICT, WITHOUT ROWID;

CREATE TABLE tor_feed_state (
  id                   INTEGER PRIMARY KEY CHECK (id = 1),
  fetched_ms           INTEGER,
  entry_count          INTEGER NOT NULL DEFAULT 0,
  digest               TEXT,
  last_attempt_ms      INTEGER,
  last_error           TEXT CHECK (last_error IS NULL OR length(last_error) <= 300),
  consecutive_failures INTEGER NOT NULL DEFAULT 0
) STRICT;
INSERT INTO tor_feed_state(id) VALUES (1);

CREATE TABLE ip_rules (
  ip         TEXT    PRIMARY KEY CHECK (length(ip) BETWEEN 2 AND 45),
  mode       TEXT    NOT NULL CHECK (mode IN ('allow','block','monitor')),
  note       TEXT    NOT NULL DEFAULT '' CHECK (length(note) <= 500 AND (mode = 'monitor' OR length(note) >= 1)),
  expires_ms INTEGER,
  created_ms INTEGER NOT NULL,
  created_by INTEGER REFERENCES admins(id),
  updated_ms INTEGER NOT NULL,
  updated_by INTEGER REFERENCES admins(id)
) STRICT, WITHOUT ROWID;
CREATE INDEX idx_ip_rules_expires ON ip_rules(expires_ms) WHERE expires_ms IS NOT NULL;

CREATE TRIGGER trg_ip_rules_ai AFTER INSERT ON ip_rules
BEGIN UPDATE change_counters SET value = value + 1 WHERE name = 'ip_rules'; END;
CREATE TRIGGER trg_ip_rules_au AFTER UPDATE ON ip_rules
BEGIN UPDATE change_counters SET value = value + 1 WHERE name = 'ip_rules'; END;
CREATE TRIGGER trg_ip_rules_ad AFTER DELETE ON ip_rules
BEGIN UPDATE change_counters SET value = value + 1 WHERE name = 'ip_rules'; END;
```

Notes:
- **A failed lookup never overwrites good data.** It sets `error_kind`, `error_ms`, `error_count` and `retry_after_ms` and leaves the earlier verdict in place, so the stale-grace rule (SUBSYSTEMS 3.2) still has something to use. A row with `status = 'error'` and no data means the IP has never been checked successfully, which the policy treats as "unknown", i.e. allow.
- A lookup is due when `expires_ms` is NULL or past, and `retry_after_ms` has passed.
- **`confidence` and `reputation` are stored exactly as received** (as JSON scalar text) because their type and meaning in the IPLogs response are not yet verified (SUBSYSTEMS 3.1). Stage 5 should replace them with typed columns once the official documentation is checked.
- Latitude and longitude from IPLogs have no column, so they cannot be stored (out of scope in `GOAL.md`).
- The history of changes to an IP rule (who, when, why, previous mode) lives in `audit_events` (`target_type = 'ip_rule'`), not in a second table; the row itself holds the current rule.

### 5.5 `0005_url_rules_block_page.sql` (Stage 6)

```sql
-- 0005_url_rules_block_page.sql (Stage 6): URL access rules and block page versions.

CREATE TABLE url_rules (
  id          INTEGER PRIMARY KEY,
  pattern     TEXT    NOT NULL CHECK (substr(pattern, 1, 1) = '/' AND length(pattern) <= 2048),
  match_type  TEXT    NOT NULL CHECK (match_type IN ('exact','prefix')),
  query_match TEXT    CHECK (query_match IS NULL OR
                (json_valid(query_match) AND json_type(query_match) = 'object' AND length(query_match) <= 1024)),
  action      TEXT    NOT NULL CHECK (action IN ('allow','deny')),
  scope_ip    TEXT    CHECK (scope_ip IS NULL OR length(scope_ip) BETWEEN 2 AND 45),
  priority    INTEGER NOT NULL DEFAULT 100 CHECK (priority BETWEEN 0 AND 1000000),
  enabled     INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  expires_ms  INTEGER,
  description TEXT    NOT NULL DEFAULT '' CHECK (length(description) <= 300),
  notes       TEXT    NOT NULL DEFAULT '' CHECK (length(notes) <= 2000),
  created_ms  INTEGER NOT NULL,
  created_by  INTEGER REFERENCES admins(id),
  updated_ms  INTEGER NOT NULL,
  updated_by  INTEGER REFERENCES admins(id)
) STRICT;
CREATE UNIQUE INDEX uq_url_rules_identity
  ON url_rules (COALESCE(scope_ip, ''), match_type, pattern, COALESCE(query_match, ''), action);
CREATE INDEX idx_url_rules_expires ON url_rules(expires_ms) WHERE expires_ms IS NOT NULL;

CREATE TRIGGER trg_url_rules_ai AFTER INSERT ON url_rules
BEGIN UPDATE change_counters SET value = value + 1 WHERE name = 'url_rules'; END;
CREATE TRIGGER trg_url_rules_au AFTER UPDATE ON url_rules
BEGIN UPDATE change_counters SET value = value + 1 WHERE name = 'url_rules'; END;
CREATE TRIGGER trg_url_rules_ad AFTER DELETE ON url_rules
BEGIN UPDATE change_counters SET value = value + 1 WHERE name = 'url_rules'; END;

CREATE TABLE block_page_versions (
  id            INTEGER PRIMARY KEY,
  html          TEXT    NOT NULL CHECK (length(CAST(html AS BLOB)) <= 204800),
  note          TEXT    NOT NULL DEFAULT '' CHECK (length(note) <= 300),
  created_ms    INTEGER NOT NULL,
  created_by    INTEGER REFERENCES admins(id),
  restored_from INTEGER REFERENCES block_page_versions(id),
  published     INTEGER NOT NULL DEFAULT 0 CHECK (published IN (0,1)),
  published_ms  INTEGER
) STRICT;
CREATE UNIQUE INDEX uq_block_page_published ON block_page_versions(published) WHERE published = 1;
CREATE TRIGGER trg_block_page_versions_immutable
  BEFORE UPDATE OF html, note, created_ms, created_by, restored_from ON block_page_versions
BEGIN SELECT RAISE(ABORT, 'block page versions are immutable'); END;

CREATE TRIGGER trg_block_page_ai AFTER INSERT ON block_page_versions
BEGIN UPDATE change_counters SET value = value + 1 WHERE name = 'block_page'; END;
CREATE TRIGGER trg_block_page_au AFTER UPDATE ON block_page_versions
BEGIN UPDATE change_counters SET value = value + 1 WHERE name = 'block_page'; END;
CREATE TRIGGER trg_block_page_ad AFTER DELETE ON block_page_versions
BEGIN UPDATE change_counters SET value = value + 1 WHERE name = 'block_page'; END;
```

Notes:
- **Rules have no host column.** A rule applies to every managed host (`site.hosts`). A per-host rule would need a new column and migration; none was requested.
- `uq_url_rules_identity` rejects exact duplicates, including two global rules (where `scope_ip` is NULL). `query_match` is stored as canonical JSON (keys sorted, no spaces) by the application so equal rules compare equal.
- The safety rail against a site-wide deny (`deny` + `prefix` + `/`) is in application code, not the schema, because the "allow site-wide URL deny" setting can lift it deliberately.
- The 200 KB ceiling on block page HTML is in bytes (`CAST ... AS BLOB`), not characters.
- Publishing is two statements in one transaction: clear the old `published = 1`, then set the new one. The partial unique index guarantees at most one published version at any moment.
- "Restore" inserts a new row copying an old one and sets `restored_from`; it never edits history.

### 5.6 `0006_injections.sql` (Stage 7)

```sql
-- 0006_injections.sql (Stage 7): MyBB injections, versions, export state.

CREATE TABLE injections (
  id              INTEGER PRIMARY KEY,
  name            TEXT    NOT NULL UNIQUE COLLATE NOCASE CHECK (length(name) BETWEEN 1 AND 100),
  description     TEXT    NOT NULL DEFAULT '' CHECK (length(description) <= 500),
  enabled         INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0,1)),
  position        TEXT    NOT NULL CHECK (position IN ('top','after_header','before_footer')),
  targeting_mode  TEXT    NOT NULL DEFAULT 'all' CHECK (targeting_mode IN ('all','paths')),
  targets         TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(targets) AND json_type(targets) = 'array' AND length(targets) <= 8192),
  priority        INTEGER NOT NULL DEFAULT 100 CHECK (priority BETWEEN 0 AND 1000000),
  html            TEXT    NOT NULL DEFAULT '' CHECK (length(CAST(html AS BLOB)) <= 102400),
  css             TEXT    NOT NULL DEFAULT '' CHECK (length(CAST(css  AS BLOB)) <= 102400),
  js              TEXT    NOT NULL DEFAULT '' CHECK (length(CAST(js   AS BLOB)) <= 102400),
  current_version INTEGER NOT NULL DEFAULT 0 CHECK (current_version >= 0),
  created_ms      INTEGER NOT NULL,
  created_by      INTEGER REFERENCES admins(id),
  updated_ms      INTEGER NOT NULL,
  updated_by      INTEGER REFERENCES admins(id)
) STRICT;
CREATE INDEX idx_injections_enabled ON injections(enabled, priority);

CREATE TABLE injection_versions (
  id                    INTEGER PRIMARY KEY,
  injection_id          INTEGER NOT NULL REFERENCES injections(id) ON DELETE CASCADE,
  version               INTEGER NOT NULL CHECK (version >= 1),
  position              TEXT    NOT NULL CHECK (position IN ('top','after_header','before_footer')),
  targeting_mode        TEXT    NOT NULL CHECK (targeting_mode IN ('all','paths')),
  targets               TEXT    NOT NULL CHECK (json_valid(targets) AND json_type(targets) = 'array' AND length(targets) <= 8192),
  priority              INTEGER NOT NULL CHECK (priority BETWEEN 0 AND 1000000),
  html                  TEXT    NOT NULL CHECK (length(CAST(html AS BLOB)) <= 102400),
  css                   TEXT    NOT NULL CHECK (length(CAST(css  AS BLOB)) <= 102400),
  js                    TEXT    NOT NULL CHECK (length(CAST(js   AS BLOB)) <= 102400),
  note                  TEXT    NOT NULL DEFAULT '' CHECK (length(note) <= 300),
  restored_from_version INTEGER CHECK (restored_from_version IS NULL OR restored_from_version >= 1),
  created_ms            INTEGER NOT NULL,
  created_by            INTEGER REFERENCES admins(id),
  UNIQUE (injection_id, version)
) STRICT;
CREATE TRIGGER trg_injection_versions_immutable BEFORE UPDATE ON injection_versions
BEGIN SELECT RAISE(ABORT, 'injection versions are immutable'); END;

CREATE TABLE mybb_export_state (
  id           INTEGER PRIMARY KEY CHECK (id = 1),
  generation   INTEGER NOT NULL DEFAULT 0,
  written_ms   INTEGER,
  content_hash TEXT,
  last_error   TEXT CHECK (last_error IS NULL OR length(last_error) <= 300)
) STRICT;
INSERT INTO mybb_export_state(id) VALUES (1);

CREATE TRIGGER trg_injections_ai AFTER INSERT ON injections
BEGIN UPDATE change_counters SET value = value + 1 WHERE name = 'injections'; END;
CREATE TRIGGER trg_injections_au AFTER UPDATE ON injections
BEGIN UPDATE change_counters SET value = value + 1 WHERE name = 'injections'; END;
CREATE TRIGGER trg_injections_ad AFTER DELETE ON injections
BEGIN UPDATE change_counters SET value = value + 1 WHERE name = 'injections'; END;
```

Notes:
- **`injections` holds the current state and is the only table the exporter reads.** `injection_versions` is an append-only history written at every save, including the first (version 1).
- **What a version captures:** `position`, `targeting_mode`, `targets`, `priority`, `html`, `css`, `js`. **What it does not:** `name`, `description` and `enabled`. Rolling back restores content and placement but never switches an injection on or off. Rollback writes a new version with `restored_from_version` set.
- **New injections start disabled** (`enabled DEFAULT 0`) so JavaScript never reaches visitors before the admin has previewed it. The application may override this deliberately.
- `targets` is a JSON array of `{"path": "...", "match": "exact" | "prefix"}` objects. The schema pins only "an array"; the object shape is validated in code.
- Deleting an injection deletes its history (cascade). The UI asks for a typed confirmation, and the audit event records the injection's name and last version number.
- The column is called `position`, which SQLite accepts without quoting (tested).

---

## 6. Settings registry

Settings live in the `settings` table as JSON. **A missing row means the default below applies**; rows are written only when an admin changes a value. The "Source" column says where the default comes from: **docs** (an earlier design document, named) or **new** (proposed here, not yet agreed). Secrets are never settings (decision D9).

| Key | Type | Default | Source |
|---|---|---|---|
| `site.hosts` | list of strings | `["initstack.org","www.initstack.org"]` | docs: ARCHITECTURE Q6 |
| `site.appeal_url` | string | `""` | docs: ARCHITECTURE Q10 |
| `ui.default_timezone` | IANA name | `"UTC"` | new |
| `enforcement.mode` | `"enforce"` or `"monitor_only"` | `"enforce"` | docs: ARCHITECTURE 6 |
| `enforcement.paths` | list of `{path, param, values}` | `[{"path":"/member.php","param":"action","values":["login","do_login","register","do_register"]}]` | docs: GOAL E |
| `enforcement.allow_site_wide_url_deny` | bool | `false` | docs: SUBSYSTEMS 4.4 |
| `enforcement.protected_paths` | list of path prefixes no URL deny rule may cover | `["/_guard/"]` (the owner adds the MyBB admin directory) | docs: SUBSYSTEMS 4.4; default new |
| `intel.iplogs.enabled` | bool | `true` | new |
| `intel.iplogs.rate_per_minute` | int | `30` | docs: SUBSYSTEMS 3.1 |
| `intel.ttl_ok_s` / `intel.ttl_error_s` / `intel.stale_grace_s` | int seconds | `86400` / `300` / `604800` | docs: SUBSYSTEMS 3.2 |
| `intel.tor.enabled` | bool | `true` | new |
| `intel.tor.interval_s` | int seconds | `10800` | docs: SUBSYSTEMS 3.3 |
| `intel.tor.min_entries` / `intel.tor.min_ratio` | int / number | `500` / `0.5` | docs: SUBSYSTEMS 3.3 |
| `intel.policy` | object per category plus `min_confidence` | `{"tor":{"block":true},"vpn_detected":{"block":true},"vpn_likely":{"block":false},"proxy":{"block":true},"relay":{"block":false},"min_confidence":null}`; hosting and crawler have no switch because they can never block | docs: ARCHITECTURE Q7. `min_confidence: null` means "no threshold until the meaning of IPLogs `confidence` is verified" |
| `auth.password_login_enabled` | bool | `true` | docs: GOAL I |
| `auth.session_idle_s` / `auth.session_max_s` | int seconds | `1800` / `43200` | docs: SUBSYSTEMS 7.2 |
| `auth.password_min_length` | int | `12` | docs: SUBSYSTEMS 7.1 |
| `auth.reauth_window_s` | int seconds | `300` | new (API.md section 2: how recent a sign-in must be for sensitive changes) |
| `auth.throttle` | `{max_failures, window_s, lockout_s, lockout_max_s}` | `{5, 900, 900, 86400}`: five failures in 15 minutes lock for 15 minutes, doubling per repeat up to 24 hours | new |
| `retention.requests_days` | int | `90` | docs: ARCHITECTURE Q8 |
| `retention.rollups_days` | int | `730` | docs: ARCHITECTURE Q8 |
| `retention.audit_days` | int | `365` | docs: ARCHITECTURE Q8 |
| `retention.ingest_errors_max` | int | `1000` | docs: SUBSYSTEMS 8.3 |
| `retention.rollup_min_hits` | int | `10` | new (S5) |
| `retention.versions_keep` | int per injection and for the block page | `100` (the published or current version is never deleted) | new |
| `backup.daily_keep` / `backup.weekly_keep` | int | `14` / `8` | docs: ARCHITECTURE Q11 |
| `export.csv_max_rows` | int | `100000` | docs: SUBSYSTEMS 2.8 |
| `limits.url_rules_max` | int | `2000` | docs: SUBSYSTEMS 4.4 |
| `block_page.use_custom` | bool | `true` | docs: SUBSYSTEMS 5.1 |
| `mybb.injections_enabled` | bool, a global off switch for every injection | `true` | new |

Size limits for the block page (200 KB) and for each injection field (100 KB) are hard ceilings in the DDL, not settings.

---

## 7. Index map

Each row was run with `EXPLAIN QUERY PLAN` on SQLite 3.45.1 against 200,000 synthetic requests after `ANALYZE`, and used the index shown with no full scan of `requests`. Stage 4 repeats this check on the server's own SQLite version and keeps it as a test.

| Feature | Query shape | Index used |
|---|---|---|
| Recent requests | `ORDER BY ts_ms DESC LIMIT n` | `idx_requests_ts` |
| One IP's requests in a date range | `visitor_id = ? AND ts_ms BETWEEN ? AND ?` | `idx_requests_visitor_ts` |
| One URL's requests in a date range | `url_id = ? AND ts_ms BETWEEN ? AND ?` | `idx_requests_url_ts` |
| Requests by status | `status = ? AND ts_ms BETWEEN ? AND ?` | `idx_requests_status_ts` |
| Denied / overridden / monitored | `outcome <> 'allowed' AND ts_ms BETWEEN ? AND ?` (add `AND outcome = 'denied'` to narrow) | `idx_requests_flagged_ts` (partial) |
| Visitor by exact IP, or by IP prefix | `ip = ?`, or `ip >= ? AND ip < ?` | `UNIQUE(ip)` |
| Recent visitors, top visitors | `ORDER BY last_seen_ms DESC`, `ORDER BY request_count DESC` | `idx_visitors_last_seen`, `idx_visitors_requests` |
| URL by host and path, or by path prefix | `host = ? AND path = ?`, or `path >= ? AND path < ?` | `UNIQUE(host, path)`, `idx_urls_path` |
| All-time most accessed URLs | `ORDER BY hit_count DESC LIMIT n` | `idx_urls_hits` |
| Ranked URLs in a date range | `SUM(requests)` over `hour_ms BETWEEN ? AND ?` grouped by `url_id` | `rollup_url_hourly` primary key |
| Graph series for one URL | `url_id = ? AND hour_ms BETWEEN ? AND ?` | `idx_rollup_url_hourly_url` |
| URLs hit by one IP | `visitor_id = ?` | `visitor_urls` primary key |
| Unique IPs of one URL (all-time) | `COUNT(*) WHERE url_id = ?` | `idx_visitor_urls_url` |
| Audit log by time, by target | `ORDER BY ts_ms DESC`, `target_type = ? AND target_id = ?` | `idx_audit_ts`, `idx_audit_target` |
| Session lookup, expiry sweep | `token_hash = ?`, `expires_ms < ?` | `UNIQUE(token_hash)`, `idx_sessions_expires` |
| IP rule and URL rule expiry sweeps | `expires_ms IS NOT NULL AND expires_ms <= ?` | `idx_ip_rules_expires`, `idx_url_rules_expires` (partial) |
| IP intel entries due for refresh | `expires_ms < ? AND retry_after_ms <= ?` | `idx_ip_intel_expires` |
| Retention: oldest raw requests, stale User-Agents | `ts_ms < ? ORDER BY ts_ms LIMIT 10000`, `last_seen_ms < ?` | `idx_requests_ts`, `idx_user_agents_last_seen` |

Two rules for query code, both from the partial-index test:
1. **Write the literal term `outcome <> 'allowed'`** in every query that lists non-allowed requests. A lone `outcome = 'denied'` does not use the partial index (the plan fell back to `idx_requests_ts`). A bound parameter (`outcome <> ?`) also used the partial index on SQLite 3.45.1, but I did not rely on that, because older versions were not tested.
2. **Run `PRAGMA optimize`** (already in the weekly job, SUBSYSTEMS 8.3) so the planner has statistics. The plans above were produced after `ANALYZE`.

Indexes that exist but were **not** plan-tested: `idx_sessions_admin`, `idx_auth_throttle_last`, `idx_passkeys_admin`, `uq_passkeys_admin_name`, `idx_mybb_accounts_username`, `idx_visitor_accounts_uid`, `idx_injections_enabled`, and the `*_last_seen` indexes other than the User-Agent one (they follow the same pattern and exist for retention deletes).

---

## 8. Size estimate

**Measured on synthetic data in the sandbox:** 200,000 generated requests (skewed IP and URL popularity, 15% with a query string, 1% denied, realistic User-Agent and referrer strings). Real traffic will differ, especially scanner traffic, so treat this as an order of magnitude and re-measure in Stage 4.

| Part of `requests` | Bytes per request |
|---|---|
| Table rows | 78 |
| Unique index on `request_id` | 28 |
| `idx_requests_ts` | 17 |
| `idx_requests_visitor_ts` | 19 |
| `idx_requests_url_ts` | 19 |
| `idx_requests_status_ts` | 20 |
| `idx_requests_flagged_ts` (partial) | under 1 |
| **Total** | **about 180** |

In that run the aggregates (`visitor_urls`, `rollup_url_hourly`) were about 0.1 MB each and the dictionaries were negligible, but real scanner traffic will make them larger.

Projection at 180 bytes per request and the proposed 90-day raw retention (assumption Q8):

| Requests per day | Raw rows at 90 days | Database size | One uncompressed backup | Worst case: 14 daily + 8 weekly backups |
|---|---|---|---|---|
| 1,000 | 90,000 | about 16 MB | about 16 MB | about 0.4 GB |
| 10,000 | 900,000 | about 160 MB | about 160 MB | about 3.6 GB |
| 100,000 | 9,000,000 | about 1.6 GB | about 1.6 GB | about 36 GB |

The 100,000 per day row is the upper bound assumed in ARCHITECTURE.md Q8. Backups need that much extra free disk, plus temporary space equal to one database while a backup is being written. Whether backups are compressed is a Stage 8 decision; compression was not measured. **If the server has little disk, the cheapest lever is `retention.requests_days`.**

---

## 9. Retention and deletion order

The weekly job (SUBSYSTEMS 8.3) deletes in batches of about 10,000 rows per transaction so it never holds the single writer for long. The order matters because of the foreign keys:

1. `requests` with `ts_ms` below the cutoff, in batches: `DELETE FROM requests WHERE id IN (SELECT id FROM requests WHERE ts_ms < ? ORDER BY ts_ms LIMIT 10000)`. The `SELECT` part was plan-checked (it uses `idx_requests_ts`).
2. `visitor_urls`, `visitor_user_agents`, `visitor_accounts` rows with `last_seen_ms` below the cutoff.
3. `rollup_url_hourly` rows for URLs under `retention.rollup_min_hits` total hits whose raw rows are gone (S5), then rollups older than `retention.rollups_days` (both rollup tables).
4. `visitors` with `last_seen_ms` below the cutoff **and** no remaining requests (`NOT EXISTS`; the foreign key would also refuse, using `idx_requests_visitor_ts`).
5. `urls` with `last_seen_ms` below the cutoff and no remaining requests or rollup rows.
6. Dictionary rows (`user_agents`, `referrers`, `mybb_accounts`) with `last_seen_ms` below the raw-request cutoff (S3).
7. `audit_events` older than `retention.audit_days`; `ingest_errors` trimmed to the newest `retention.ingest_errors_max`; expired or revoked `sessions` older than 7 days; `auth_throttle` rows idle longer than the throttle window; old `block_page_versions` and `injection_versions` beyond `retention.versions_keep` (never the published or current one).

Totals on `visitors`, `urls` and the other aggregates keep their all-time values after raw rows go; the UI says so (S4). Shortening retention shows how many rows will be deleted and needs confirmation.

---

## 10. Personal data inventory

| Data | Where | Kept for |
|---|---|---|
| Visitor IP addresses | `visitors`, `ip_intel`, `ip_rules`, `url_rules.scope_ip`, `sessions.ip`, `audit_events.ip` | Visitors and intel: until the raw-request cutoff passes with no activity. Rules: until an admin removes them. Admin session and audit IPs: session lifetime and audit retention. |
| User-Agent strings | `user_agents`, `sessions.user_agent` | Raw-request retention (sessions: session lifetime) |
| Referrers (query string dropped) | `referrers` | Raw-request retention |
| MyBB user id and username | `mybb_accounts`, `visitor_accounts`, `requests.mybb_uid` | Raw-request retention |
| Admin usernames, display names, passkey names | `admins`, `passkeys`, `audit_events.actor_name` | While the account exists; audit copies follow audit retention |
| Query strings, with sensitive parameters redacted before storage | `requests.query` | Raw-request retention |

**Never stored anywhere:** passwords in clear, session cookies or tokens (only a SHA-256 of Guard's own session token), authorization headers, POST bodies, WebAuthn challenges, latitude and longitude, API keys (they live only in `secrets.env`).

Limitation: v1 has no tool to erase one person's IP across all tables on request. Retention removes data in bulk; a targeted erasure would be a later feature and was not requested.

---

## 11. What was verified, and what was not

**Run on 2026-11-08 in Claude's sandbox** (Linux, SQLite 3.45.1, Python 3.12.3 standard library, scratch files outside the project). The SQL in section 5 is the set of files that was tested.

- The six migrations apply in order to an empty database: 30 tables, 35 named indexes, 18 triggers. Every table is `STRICT`. `PRAGMA integrity_check` returns `ok` and `PRAGMA foreign_key_check` returns nothing.
- A migration that fails part-way inside `BEGIN ... COMMIT` leaves no partial DDL after `ROLLBACK`.
- 100 behaviour checks pass. They cover: rejected bad enumeration values, lengths and types; case-insensitive uniqueness; the argon2id-shaped hash check; invalid JSON in `settings`; `query_match` and `targets` shape; duplicate URL rules including the NULL-scope case; the IP-rule note requirement; one published block page only; immutable block page and injection versions; append-only audit log; foreign keys (unknown visitor, URL in use, admin with history); cascades (admin to passkeys and sessions, injection to versions); and change-counter triggers.
- 26 query plans use the intended index on 200,000 synthetic rows (section 7).
- The size figures in section 8 and the foreign-key cost in S3 (6.3 ms per deleted parent row versus 0.004 ms).

**Not verified:**
- **SQLite 3.37.x**, the oldest version this design supports and the one Ubuntu 22.04 ships. By my reading of SQLite's release history every feature used arrived in or before 3.37.0, but I could not check offline and ran nothing on that version. Whether the server's SQLite build includes the JSON functions is unknown. `guard-admin doctor` must check both before Stage 2 relies on them.
- Anything involving the real service: WAL under concurrent readers and writer, disk-full behaviour, the migration runner (not written), and the ingest, rollup and retention SQL (Stage 4 and 8).
- Real traffic size and mix (section 8 is synthetic).
- That the final `idx_*_last_seen` retention indexes behave like the User-Agent one (not plan-tested).

Stage 2 turns this into tests: a fresh-database migration test, the constraint and trigger checks above, and the query-plan assertions, all run with `pytest`.

---

## 12. Open items for the owner

1. **Disk and retention (Q8, Q11).** At the 100,000 requests per day upper bound, 90 days of raw requests is about 1.6 GB and the worst-case backup set is about 36 GB uncompressed. Please confirm real traffic and free disk, or choose a shorter `retention.requests_days`.
2. **Per-URL rollup threshold (S5).** Agree that per-URL hourly rollups are kept only for URLs with at least 10 hits, or choose another number.
3. **New settings not in the earlier docs:** the global injections off switch, the login throttle numbers, `retention.versions_keep`, `intel.*.enabled`, `auth.reauth_window_s`. Confirm or strike.
4. **Server facts for Stage 2:** the output of `python3 -c "import sqlite3; print(sqlite3.sqlite_version)"` and `python3 -c "import sqlite3; print(sqlite3.connect(':memory:').execute(\"select json_valid('{}')\").fetchone())"` (already listed in ARCHITECTURE.md section 15, plus the second command).
5. **Admins are never deleted (S7)** and **revoked passkeys are hard-deleted (S8).** Confirm.
6. **`intel.policy.min_confidence`** stays unset until IPLogs's `confidence` field is documented and checked (SUBSYSTEMS 3.1).
