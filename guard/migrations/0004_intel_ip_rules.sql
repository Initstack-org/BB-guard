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
