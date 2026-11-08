import json
import os
import time

import pytest

from guard.ingest import runner, tailer
from guard.ingest.writer import Position, load_position
from ingest_helpers import TRUSTED, log_line, write_log


@pytest.fixture
def log(tmp_path):
    return str(tmp_path / "access.jsonl")


def count(conn, table="requests"):
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def gaps(conn):
    return [r[0] for r in conn.execute("SELECT detail FROM ingest_errors WHERE kind = 'gap'")]


def drain(conn, log, now=None):
    return runner.drain(conn, log, TRUSTED, now=time.time() if now is None else now)


# ---- reading --------------------------------------------------------------------------------------

def test_a_missing_log_file_is_idle_not_an_error(conn, log):
    assert runner.ingest_once(conn, log, TRUSTED).idle
    assert count(conn) == 0


def test_first_run_reads_the_whole_file(conn, log):
    write_log(log, 25)
    result = drain(conn, log)
    assert (result.lines, result.written, result.bad_lines, result.gaps) == (25, 25, 0, 0)
    assert load_position(conn).offset == os.path.getsize(log)


def test_only_complete_lines_are_read(conn, log):
    write_log(log, 3)
    whole = log_line(3)
    with open(log, "ab") as fh:
        fh.write(whole[:50])
    assert drain(conn, log).written == 3
    offset = load_position(conn).offset
    with open(log, "ab") as fh:
        fh.write(whole[50:])
    assert drain(conn, log).written == 1
    assert load_position(conn).offset == offset + len(whole)
    assert count(conn) == 4


def test_nothing_is_read_twice(conn, log):
    write_log(log, 5)
    drain(conn, log)
    assert drain(conn, log).idle
    write_log(log, 2, start=5)
    assert drain(conn, log).written == 2
    assert count(conn) == 7


def test_batches_are_bounded(conn, log):
    write_log(log, 12)
    first = runner.ingest_once(conn, log, TRUSTED, max_lines=5)
    assert first.lines == 5
    assert drain(conn, log).written == 7


def test_a_restart_resumes_from_the_committed_position(conn, log):
    write_log(log, 4)
    drain(conn, log)
    write_log(log, 3, start=4)
    # a "new process": nothing but the database carries over
    assert drain(conn, log).written == 3
    assert count(conn) == 7


def test_a_crash_before_commit_re_reads_the_batch_without_double_counting(conn, log):
    write_log(log, 6)
    saved = load_position(conn)
    first = tailer.read_next(log, saved, now=time.time())  # read, but "crash" before write_batch
    second = tailer.read_next(log, saved, now=time.time())
    assert first.lines == second.lines and len(first.lines) == 6
    drain(conn, log)
    assert count(conn) == 6
    # replaying the same lines (as after a crash between the commit and the position update) changes nothing
    result = runner.ingest_once(conn, log, TRUSTED)
    assert result.idle and conn.execute("SELECT request_count FROM visitors").fetchone()[0] == 6


def test_a_bad_line_does_not_stop_ingestion(conn, log):
    write_log(log, 2)
    with open(log, "ab") as fh:
        fh.write(b"this is not json password=hunter2\n")
        fh.write(b'{"t": "1800000100.0", "ip": "not-an-ip"}\n')
    write_log(log, 2, start=2)
    result = drain(conn, log)
    assert (result.written, result.bad_lines) == (4, 2)
    details = " | ".join(r[0] for r in conn.execute("SELECT detail FROM ingest_errors"))
    assert "hunter2" not in details and "not valid JSON" in details and "bad client ip" in details
    assert conn.execute("SELECT bad_lines_total FROM ingest_state").fetchone()[0] == 2


def test_an_over_long_unterminated_line_cannot_grow_without_bound(conn, log):
    write_log(log, 1)
    with open(log, "ab") as fh:
        fh.write(b"x" * (tailer.MAX_LINE + 10))  # no newline yet
    result = runner.ingest_once(conn, log, TRUSTED)
    assert (result.written, result.bad_lines) == (1, 1)
    with open(log, "ab") as fh:
        fh.write(b"\n")
        fh.write(log_line(1))
    assert drain(conn, log).written == 1  # the rest of the long line is junk, then the next real line parses


def test_hostile_lines_leave_no_secret_in_the_database(conn, log):
    write_log(log, 1, u="/member.php?action=do_login&password=hunter2&my_post_key=abc&sid=sss&"
                        "x=0123456789abcdef0123456789abcdef", ref="https://e.org/?token=hunter2")
    drain(conn, log)
    stored = json.dumps([[str(v) for v in row] for table in ("requests", "urls", "referrers")
                         for row in conn.execute(f"SELECT * FROM {table}")])
    for secret in ("hunter2", "sss", "0123456789abcdef0123456789abcdef"):
        assert secret not in stored
    assert "action=do_login" in stored


# ---- rotation, truncation, replacement ------------------------------------------------------------

def test_rotation_finishes_the_old_file_then_starts_the_new_one_with_no_gap(conn, log):
    write_log(log, 5)
    drain(conn, log)
    os.rename(log, log + ".1")
    write_log(log + ".1", 2, start=5)   # written to the old file just before the rotation completed
    write_log(log, 3, start=7)          # the new file
    long_ago = time.time() + 60         # the rotated file has been quiet for a while
    result = drain(conn, log, now=long_ago)
    assert result.written == 5 and result.gaps == 0
    assert count(conn) == 10
    assert gaps(conn) == []


def test_a_recently_written_rotated_file_is_waited_for(conn, log):
    write_log(log, 3)
    drain(conn, log)
    os.rename(log, log + ".1")
    write_log(log, 2, start=3)
    now = time.time()
    assert runner.ingest_once(conn, log, TRUSTED, now=now).idle   # old file may still be written: wait
    assert count(conn) == 3
    assert drain(conn, log, now=now + 60).written == 2
    assert gaps(conn) == []


def test_rotation_where_the_old_file_is_gone_records_a_gap(conn, log):
    write_log(log, 4)
    drain(conn, log)
    # moved somewhere ingest does not look (not "<log>.1"); keeping it alive also guarantees the new
    # file gets a different inode, which a delete-and-recreate does not (inode numbers get reused)
    os.rename(log, log + ".elsewhere")
    write_log(log, 2, start=4)
    result = drain(conn, log)
    assert (result.written, result.gaps) == (2, 1)
    assert "rotated" in gaps(conn)[0]
    assert count(conn) == 6
    assert drain(conn, log).idle


def test_truncation_records_a_gap_and_restarts(conn, log):
    write_log(log, 8)
    drain(conn, log)
    with open(log, "wb") as fh:
        fh.write(log_line(100))
    result = drain(conn, log)
    assert (result.written, result.gaps) == (1, 1)
    assert "truncated" in gaps(conn)[0] or "replaced" in gaps(conn)[0]


def test_a_replaced_file_with_the_same_inode_is_noticed_by_its_head_hash(conn, log):
    write_log(log, 3)
    drain(conn, log)
    saved = load_position(conn)
    assert saved.head_hash is not None
    # same device and inode and a size that is not smaller, but different content
    forged = Position(saved.dev, saved.inode, b"\x00" * 32, saved.offset)
    result = tailer.read_next(log, forged, now=time.time())
    assert result.gaps and "replaced" in result.gaps[0]
    assert len(result.lines) == 3 and result.position.offset == saved.offset


def test_after_a_drained_rotation_with_no_new_file_the_next_file_starts_cleanly(conn, log):
    write_log(log, 2)
    drain(conn, log)
    os.rename(log, log + ".1")
    drain(conn, log, now=time.time() + 60)        # old file drained, new file not there yet
    assert load_position(conn).inode is None
    os.remove(log + ".1")
    write_log(log, 3, start=2)
    result = drain(conn, log)
    assert (result.written, result.gaps) == (3, 0)


# ---- health ---------------------------------------------------------------------------------------

def test_health_heartbeat(conn):
    runner.record_health(conn, ok=True, now_ms=1000)
    row = conn.execute("SELECT state, heartbeat_ms, last_ok_ms FROM component_health WHERE component='ingest'").fetchone()
    assert tuple(row) == ("ok", 1000, 1000)
    runner.record_health(conn, ok=False, error="x" * 1000, now_ms=2000)
    row = conn.execute("SELECT state, last_ok_ms, last_error_ms, length(last_error) FROM component_health").fetchone()
    assert tuple(row) == ("error", 1000, 2000, 300)
    runner.record_health(conn, ok=True, now_ms=3000)
    assert conn.execute("SELECT state, last_ok_ms FROM component_health").fetchone()[0] == "ok"
