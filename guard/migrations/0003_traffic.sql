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
