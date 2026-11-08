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
