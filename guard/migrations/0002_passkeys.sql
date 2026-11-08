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
