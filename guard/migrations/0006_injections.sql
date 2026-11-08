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
