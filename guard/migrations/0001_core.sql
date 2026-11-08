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
