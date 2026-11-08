import dataclasses
import json
import sqlite3

import pytest

from guard.ingest import writer
from guard.ingest.parser import parse_line, parse_trusted
from guard.ingest.writer import IngestSettings, Position
from ingest_helpers import TRUSTED, log_line

NOW_MS = 1_900_000_000_000
SETTINGS = IngestSettings(rollup_min_hits=3)


def rec(i=0, **over):
    return parse_line(log_line(i, **over).rstrip(b"\n"), trusted=parse_trusted(TRUSTED),
                      managed_hosts=SETTINGS.managed_hosts)


def write(conn, records, *, bad=(), gaps=(), position=Position(1, 2, None, 100), settings=SETTINGS):
    return writer.write_batch(conn, list(records), list(bad), list(gaps), position, settings=settings, now_ms=NOW_MS)


def count(conn, table):
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_one_request_fills_every_table(conn):
    result = write(conn, [rec(0, uid="5", un="bob")])
    assert (result.written, result.duplicates) == (1, 0)
    for table in ("visitors", "urls", "requests", "user_agents", "referrers", "mybb_accounts",
                  "visitor_urls", "visitor_user_agents", "visitor_accounts", "rollup_site_hourly"):
        assert count(conn, table) == 1, table
    row = conn.execute("SELECT * FROM requests").fetchone()
    assert (row["method"], row["status"], row["bytes_in"], row["bytes_out"], row["duration_ms"]) == ("GET", 200, 300, 1500, 12)
    assert (row["managed"], row["outcome"], row["mybb_uid"]) == (1, "allowed", 5)
    assert row["query"] == "page=0"
    assert row["ts_ms"] == 1_800_000_000_250


def test_aggregates_add_up(conn):
    write(conn, [rec(i) for i in range(6)])
    visitor = conn.execute("SELECT * FROM visitors").fetchone()
    assert visitor["ip"] == "203.0.113.7"
    assert (visitor["request_count"], visitor["bytes_in"], visitor["bytes_out"], visitor["denied_count"]) == (6, 1800, 9000, 0)
    assert visitor["first_seen_ms"] == 1_800_000_000_250 and visitor["last_seen_ms"] == 1_800_000_005_250
    urls = {r["path"]: r["hit_count"] for r in conn.execute("SELECT path, hit_count FROM urls")}
    assert urls == {"/forum-0.html": 2, "/forum-1.html": 2, "/forum-2.html": 2}
    assert conn.execute("SELECT SUM(hits) FROM visitor_urls").fetchone()[0] == 6
    assert conn.execute("SELECT hits FROM visitor_user_agents").fetchone()[0] == 6
    site = conn.execute("SELECT * FROM rollup_site_hourly").fetchone()
    assert site["hour_ms"] % 3_600_000 == 0
    assert (site["requests"], site["bytes_in"], site["bytes_out"]) == (6, 1800, 9000)


def test_aggregates_do_not_depend_on_arrival_order(conn):
    write(conn, [rec(5), rec(1), rec(3)])
    visitor = conn.execute("SELECT first_seen_ms, last_seen_ms FROM visitors").fetchone()
    assert (visitor[0], visitor[1]) == (1_800_000_001_250, 1_800_000_005_250)


def test_a_replayed_request_is_skipped_and_counts_nothing(conn):
    write(conn, [rec(0), rec(1)])
    result = write(conn, [rec(0), rec(1), rec(2)])
    assert (result.written, result.duplicates) == (1, 2)
    assert count(conn, "requests") == 3
    assert conn.execute("SELECT request_count FROM visitors").fetchone()[0] == 3
    assert conn.execute("SELECT SUM(hit_count) FROM urls").fetchone()[0] == 3


def test_duplicates_inside_one_batch_are_skipped(conn):
    result = write(conn, [rec(0), rec(0)])
    assert (result.written, result.duplicates) == (1, 1)


def test_denied_requests_are_counted_everywhere(conn):
    write(conn, [rec(0, gd="denied", gt="manual_ip_block", gr="ip:203.0.113.7", gx="Blocked by an administrator"),
                 rec(1, gd="overridden", gt="url_rule"), rec(2, gd="monitored"), rec(3)])
    assert conn.execute("SELECT denied_count FROM visitors").fetchone()[0] == 1
    assert conn.execute("SELECT denied FROM rollup_site_hourly").fetchone()[0] == 1
    outcomes = {r[0]: r[1] for r in conn.execute("SELECT outcome, COUNT(*) FROM requests GROUP BY outcome")}
    assert outcomes == {"denied": 1, "overridden": 1, "monitored": 1, "allowed": 1}
    denied = conn.execute("SELECT * FROM requests WHERE outcome = 'denied'").fetchone()
    assert (denied["detection"], denied["rule_ref"], denied["reason"]) == (
        "manual_ip_block", "ip:203.0.113.7", "Blocked by an administrator")


def test_requests_for_unmanaged_hosts_are_recorded_but_flagged(conn):
    write(conn, [rec(0, h="203.0.113.1")])
    assert conn.execute("SELECT managed FROM requests").fetchone()[0] == 0


def test_dictionary_rows_are_shared_between_requests(conn):
    write(conn, [rec(0), rec(1), rec(2, ua="Other/2")])
    assert count(conn, "user_agents") == 2
    assert count(conn, "referrers") == 1
    assert count(conn, "visitor_user_agents") == 2


def test_requests_without_ua_referrer_or_account_leave_those_ids_null(conn):
    write(conn, [rec(0, ua="-", ref="")])
    row = conn.execute("SELECT ua_id, referrer_id, mybb_uid FROM requests").fetchone()
    assert tuple(row) == (None, None, None)
    assert count(conn, "user_agents") == 0 and count(conn, "mybb_accounts") == 0


def test_the_mybb_name_follows_the_newest_request(conn):
    write(conn, [rec(5, uid="9", un="new_name")])
    write(conn, [rec(1, uid="9", un="old_name")])  # an older request arriving late
    row = conn.execute("SELECT username, request_count, first_seen_ms FROM mybb_accounts").fetchone()
    assert (row[0], row[1], row[2]) == ("new_name", 2, 1_800_000_001_250)
    write(conn, [rec(8, uid="9", un="newest")])
    assert conn.execute("SELECT username FROM mybb_accounts").fetchone()[0] == "newest"


def test_per_visitor_user_agent_list_is_capped_but_every_request_is_stored(conn):
    total = writer.VISITOR_UA_CAP + 5
    write(conn, [rec(i, ua=f"Agent/{i}") for i in range(total)])
    assert count(conn, "requests") == total
    assert count(conn, "visitor_user_agents") == writer.VISITOR_UA_CAP
    write(conn, [rec(total, ua="Agent/0")])  # an already-listed agent still counts its hit
    assert conn.execute("SELECT hits FROM visitor_user_agents WHERE ua_id = "
                        "(SELECT id FROM user_agents WHERE value = 'Agent/0')").fetchone()[0] == 2


def test_per_visitor_account_list_is_capped(conn):
    total = writer.VISITOR_ACCOUNT_CAP + 3
    write(conn, [rec(i, uid=str(i + 1), un=f"user{i}") for i in range(total)])
    assert count(conn, "visitor_accounts") == writer.VISITOR_ACCOUNT_CAP
    assert count(conn, "mybb_accounts") == total


def test_an_over_long_path_is_stored_truncated_and_flagged(conn):
    write(conn, [rec(0, u="/" + "a" * 3000)])
    row = conn.execute("SELECT path, path_truncated FROM urls").fetchone()
    assert len(row[0]) == 2048 and row[1] == 1


# ---- per-URL rollups ------------------------------------------------------------------------------

def rollup(conn):
    return [tuple(r) for r in conn.execute("SELECT url_id, requests, bytes_in, bytes_out, denied "
                                           "FROM rollup_url_hourly ORDER BY url_id, hour_ms")]


def test_rare_urls_get_no_url_rollup(conn):
    write(conn, [rec(0, u="/rare"), rec(1, u="/rare")])  # 2 hits, threshold 3
    assert rollup(conn) == []
    assert conn.execute("SELECT requests FROM rollup_site_hourly").fetchone()[0] == 2


def test_the_threshold_request_backfills_the_earlier_hours(conn):
    # three requests in three different hours; the third reaches the threshold
    write(conn, [rec(0, u="/hot", t="1800000000.0"), rec(1, u="/hot", t="1800003600.0", gd="denied")])
    assert rollup(conn) == []
    write(conn, [rec(2, u="/hot", t="1800007200.0")])
    assert rollup(conn) == [(1, 1, 300, 1500, 0), (1, 1, 300, 1500, 1), (1, 1, 300, 1500, 0)]


def test_hits_after_the_threshold_update_the_rollup_incrementally(conn):
    write(conn, [rec(i, u="/hot", t="1800000000.0") for i in range(5)])
    assert rollup(conn) == [(1, 5, 1500, 7500, 0)]
    write(conn, [rec(9, u="/hot", t="1800000100.0")])
    assert rollup(conn) == [(1, 6, 1800, 9000, 0)]


def test_rollup_totals_match_the_raw_rows(conn):
    write(conn, [rec(i, u=f"/p{i % 2}", t=f"{1800000000 + i * 1700}.0", gd="denied" if i % 7 == 0 else "allowed")
                 for i in range(40)])
    raw = conn.execute("SELECT url_id, COUNT(*), SUM(bytes_out), SUM(outcome = 'denied') "
                       "FROM requests GROUP BY url_id ORDER BY url_id").fetchall()
    rolled = conn.execute("SELECT url_id, SUM(requests), SUM(bytes_out), SUM(denied) "
                          "FROM rollup_url_hourly GROUP BY url_id ORDER BY url_id").fetchall()
    assert [tuple(r) for r in raw] == [tuple(r) for r in rolled]
    site = conn.execute("SELECT SUM(requests), SUM(denied) FROM rollup_site_hourly").fetchone()
    assert tuple(site) == (40, sum(1 for i in range(40) if i % 7 == 0))


# ---- ingest state and errors ----------------------------------------------------------------------

def test_position_and_totals_are_saved_with_the_batch(conn):
    head = b"\x01" * 32
    write(conn, [rec(0), rec(1, ip="1.2.3.4", peer="9.9.9.9")], bad=[("not valid JSON", "junk")],
          position=Position(11, 22, head, 4096))
    state = dict(conn.execute("SELECT * FROM ingest_state").fetchone())
    assert (state["file_dev"], state["file_inode"], bytes(state["head_hash"]), state["file_offset"]) == (11, 22, head, 4096)
    assert (state["lines_total"], state["bad_lines_total"], state["peer_mismatch_total"]) == (3, 1, 1)
    assert state["last_request_ms"] == 1_800_000_001_250
    assert state["updated_ms"] == NOW_MS
    assert writer.load_position(conn) == Position(11, 22, head, 4096)
    write(conn, [rec(2)], position=Position(11, 22, head, 5000))
    again = conn.execute("SELECT lines_total, file_offset FROM ingest_state").fetchone()
    assert tuple(again) == (4, 5000)


def test_a_late_old_batch_does_not_move_last_request_backwards(conn):
    write(conn, [rec(9)])
    write(conn, [rec(1)])
    assert conn.execute("SELECT last_request_ms FROM ingest_state").fetchone()[0] == 1_800_000_009_250


def test_bad_lines_and_gaps_go_to_the_error_ring(conn):
    write(conn, [], bad=[("not valid JSON", "x" * 400)], gaps=["log file was rotated"])
    rows = [tuple(r) for r in conn.execute("SELECT kind, detail FROM ingest_errors ORDER BY id")]
    assert rows[0][0] == "parse" and rows[0][1].startswith("not valid JSON: ") and len(rows[0][1]) <= 300
    assert rows[1] == ("gap", "log file was rotated")


def test_the_error_ring_is_bounded(conn):
    settings = IngestSettings(errors_max=10)
    for _ in range(5):
        write(conn, [], bad=[("bad", str(i)) for i in range(8)], settings=settings)
    assert count(conn, "ingest_errors") == 10
    newest = conn.execute("SELECT MAX(id) FROM ingest_errors").fetchone()[0]
    assert newest == 40  # the newest rows are the ones kept


def test_a_failing_batch_rolls_back_everything_including_the_position(conn):
    write(conn, [rec(0)], position=Position(1, 2, None, 100))
    good, bad = rec(1), dataclasses.replace(rec(2), status=5000)  # violates the status CHECK
    with pytest.raises(sqlite3.IntegrityError):
        write(conn, [good, bad], position=Position(1, 2, None, 999))
    assert count(conn, "requests") == 1
    assert conn.execute("SELECT request_count FROM visitors").fetchone()[0] == 1
    assert conn.execute("SELECT file_offset FROM ingest_state").fetchone()[0] == 100
    assert not conn.in_transaction


# ---- settings -------------------------------------------------------------------------------------

def put(conn, key, value):
    conn.execute("INSERT INTO settings(key, value, updated_ms) VALUES (?, ?, 0)", (key, json.dumps(value)))


def test_default_settings(conn):
    s = writer.read_settings(conn)
    assert s.managed_hosts == frozenset({"initstack.org", "www.initstack.org"})
    assert (s.rollup_min_hits, s.errors_max) == (10, 1000)


def test_settings_are_read_and_normalized(conn):
    put(conn, "site.hosts", ["Forum.Example.org", "example.org."])
    put(conn, "retention.rollup_min_hits", 25)
    put(conn, "retention.ingest_errors_max", 500)
    s = writer.read_settings(conn)
    assert s.managed_hosts == frozenset({"forum.example.org", "example.org"})
    assert (s.rollup_min_hits, s.errors_max) == (25, 500)


@pytest.mark.parametrize("hosts", [[], "initstack.org", [1, 2], [""], None, ["a"] * 51])
def test_invalid_host_settings_fall_back_to_defaults(conn, hosts):
    put(conn, "site.hosts", hosts)
    assert writer.read_settings(conn).managed_hosts == IngestSettings().managed_hosts


@pytest.mark.parametrize("value", [0, -1, 10**9, "5", True, 1.5, None])
def test_invalid_numeric_settings_fall_back_to_defaults(conn, value):
    put(conn, "retention.rollup_min_hits", value)
    put(conn, "retention.ingest_errors_max", value)
    s = writer.read_settings(conn)
    assert (s.rollup_min_hits, s.errors_max) == (10, 1000)
