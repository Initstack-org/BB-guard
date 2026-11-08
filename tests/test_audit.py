import json
import sqlite3

import pytest

from guard import audit


def test_record_writes_a_row(conn):
    eid = audit.record(conn, "x.y", "success", actor_name="n", ip="1.2.3.4", target_type="t",
                       target_id=5, detail={"b": 1, "a": "z"}, ts_ms=123)
    row = conn.execute("SELECT * FROM audit_events WHERE id=?", (eid,)).fetchone()
    assert (row["ts_ms"], row["action"], row["outcome"], row["target_id"]) == (123, "x.y", "success", "5")
    assert json.loads(row["detail"]) == {"a": "z", "b": 1}


@pytest.mark.parametrize("key", ["password", "new_password", "Token", "session_cookie", "Authorization",
                                 "challenge", "api_key", "signature", "credential_id", "private_key"])
def test_secret_looking_detail_keys_are_rejected(conn, key):
    with pytest.raises(audit.AuditError):
        audit.record(conn, "a", "success", detail={key: "v"})
    with pytest.raises(audit.AuditError):
        audit.record(conn, "a", "success", detail={"outer": [{key: "v"}]})
    assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0


def test_unsupported_detail_value_types_are_rejected(conn):
    with pytest.raises(audit.AuditError):
        audit.record(conn, "a", "success", detail={"x": b"bytes"})


def test_oversized_detail_is_replaced_not_stored(conn):
    eid = audit.record(conn, "a", "success", detail={"big": "x" * 5000})
    stored = conn.execute("SELECT detail FROM audit_events WHERE id=?", (eid,)).fetchone()[0]
    assert json.loads(stored) == {"truncated": True}


def test_long_text_is_truncated_to_column_limits(conn):
    eid = audit.record(conn, "a" * 100, "success", actor_name="n" * 100, ip="1" * 100, target_type="t" * 100,
                       target_id="i" * 500)
    row = conn.execute("SELECT * FROM audit_events WHERE id=?", (eid,)).fetchone()
    assert (len(row["action"]), len(row["actor_name"]), len(row["ip"]), len(row["target_type"]),
            len(row["target_id"])) == (64, 64, 45, 32, 128)


def test_invalid_outcome_is_rejected_by_the_schema(conn):
    with pytest.raises(sqlite3.IntegrityError):
        audit.record(conn, "a", "maybe")


def test_audit_rows_cannot_be_updated(conn):
    eid = audit.record(conn, "a", "success")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("UPDATE audit_events SET outcome='failure' WHERE id=?", (eid,))
