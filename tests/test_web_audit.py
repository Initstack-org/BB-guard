"""Audit Log page: filter parsing, keyset paging and the page itself (docs/API.md 10.2).

The first group needs only the standard library and SQLite; the page tests need Starlette and Jinja2
and use the same `env` fixture as tests/test_web.py. Not yet run anywhere (see PROGRESS.md).
"""

import pytest

from guard import audit
from guard.web import audit_log
from guard.web.audit_log import FilterError, Filters, parse_filters, query

from tests.test_web import env, sign_in  # noqa: F401
from tests.web_client import Client

T0 = 1_800_000_000_000


def seed(conn, n=5, **kw):
    for i in range(n):
        audit.record(conn, kw.get("action", "auth.login"), kw.get("outcome", "success"),
                     actor_name=kw.get("actor", "alice"), ip="203.0.113.5", ts_ms=T0 + i * 1000)


# ---- filter parsing --------------------------------------------------------------------------

def test_defaults():
    f = parse_filters({})
    assert f == Filters()


@pytest.mark.parametrize("params", [
    {"outcome": "bogus"}, {"from": "2026-13-01"}, {"from": "yesterday"}, {"to": "2026-1-1"},
    {"from": "2026-02-01", "to": "2026-01-01"}, {"size": "0"}, {"size": "201"}, {"size": "x"},
    {"before": "abc"}, {"before": "1.2.3"}, {"actor": "a" * 65}, {"action": "a\x00b"},
    {"target_id": "x" * 129}])
def test_bad_filters_are_rejected(params):
    with pytest.raises(FilterError):
        parse_filters(params)


def test_date_range_is_inclusive_of_the_end_day_in_the_admin_timezone():
    f = parse_filters({"from": "2026-11-08", "to": "2026-11-08"}, "America/Indiana/Indianapolis")
    assert f.to_ms - f.from_ms == 24 * 3600 * 1000
    utc = parse_filters({"from": "2026-11-08"}, "UTC")
    assert f.from_ms - utc.from_ms == 5 * 3600 * 1000  # EST is UTC-5 on that date


def test_unknown_timezone_falls_back_to_utc():
    assert parse_filters({"from": "2026-11-08"}, "Not/AZone").from_ms == \
        parse_filters({"from": "2026-11-08"}, "UTC").from_ms


# ---- query -----------------------------------------------------------------------------------

def test_newest_first_and_keyset_paging_covers_every_row_once(conn):
    seed(conn, 7)
    audit.record(conn, "auth.logout", "success", actor_name="alice", ts_ms=T0 + 3000)  # same ts as one row
    seen, cursor = [], None
    while True:
        rows, cursor = query(conn, Filters(size=3, cursor=parse_filters({"before": cursor}).cursor
                                           if cursor else None))
        seen += [r["id"] for r in rows]
        if cursor is None:
            break
    assert len(seen) == 8 and len(set(seen)) == 8
    ordered = [r["ts_ms"] for r in conn.execute("SELECT ts_ms FROM audit_events ORDER BY id")]
    assert seen[0] == conn.execute("SELECT id FROM audit_events ORDER BY ts_ms DESC, id DESC").fetchone()[0]
    assert len(ordered) == 8


def test_last_page_has_no_cursor(conn):
    seed(conn, 3)
    rows, cursor = query(conn, Filters(size=3))
    assert len(rows) == 3 and cursor is None


def test_filters_combine(conn):
    seed(conn, 2)
    audit.record(conn, "auth.login_failed", "failure", actor_name="Bob", ts_ms=T0 + 9000)
    audit.record(conn, "passkey.add", "success", actor_name="alice", target_type="passkey",
                 target_id="7", ts_ms=T0 + 9500)
    assert len(query(conn, Filters(actor="bob"))[0]) == 1                  # case-insensitive
    assert len(query(conn, Filters(action="auth."))[0]) == 3               # prefix
    assert len(query(conn, Filters(action="auth.login"))[0]) == 2          # exact
    assert len(query(conn, Filters(outcome="failure"))[0]) == 1
    assert len(query(conn, Filters(target_type="passkey", target_id="7"))[0]) == 1
    assert len(query(conn, Filters(from_ms=T0 + 9000))[0]) == 2
    assert len(query(conn, Filters(to_ms=T0 + 9000))[0]) == 2              # exclusive upper bound


def test_filter_values_are_not_sql(conn):
    seed(conn, 2)
    for value in ("' OR 1=1 --", "%", "_", "auth.%"):
        assert query(conn, Filters(action=value))[0] == []
        assert query(conn, Filters(actor=value))[0] == []
    assert conn.execute("SELECT count(*) FROM audit_events").fetchone()[0] == 2


def test_lone_dot_is_an_exact_match_not_a_prefix(conn):
    seed(conn, 1)
    assert query(conn, Filters(action="."))[0] == []


def test_detail_preview_truncates():
    assert audit_log.detail_preview(None) == ""
    assert audit_log.detail_preview("{}") == "{}"
    assert len(audit_log.detail_preview("x" * 1000)) == audit_log.DETAIL_PREVIEW_CHARS + 1


# ---- the page --------------------------------------------------------------------------------

def signed_in(env):
    client, response = sign_in(env)
    assert response.status == 303
    return client


def test_audit_route_is_class_a(env):
    assert env.app.state.route_classes[("/audit", "GET")] == "A"


def test_audit_requires_a_session(env):
    r = Client(env.app).get("/audit")
    assert r.status == 303 and r.header("location") == "/login"


def test_page_lists_events_and_marks_nav(env):
    page = signed_in(env).get("/audit")
    assert page.status == 200
    assert "Audit Log" in page.text and "auth.login" in page.text and "alice" in page.text
    assert 'href="/audit"' in page.text and 'aria-current="page"' in page.text
    text = page.text.lower()
    assert "<script" not in text and "<style" not in text and " style=" not in text


def test_page_filters_by_action_prefix(env):
    seed(env.conn, 2, action="passkey.add")
    page = signed_in(env).get("/audit?action=passkey.")
    assert "passkey.add" in page.text and "auth.login" not in page.text.split("<tbody>")[1]


def test_bad_filter_shows_error_and_status_400(env):
    page = signed_in(env).get("/audit?outcome=nope")
    assert page.status == 400 and "Outcome must be" in page.text


def test_filter_values_are_escaped_in_the_form(env):
    page = signed_in(env).get('/audit?actor=%22%3E%3Cscript%3Ealert(1)%3C/script%3E')
    assert "<script>alert" not in page.text and "&lt;script&gt;" in page.text


def test_stored_values_are_escaped_in_the_table(env):
    audit.record(env.conn, "x.test", "success", actor_name="<b>eve</b>", ts_ms=env.clock() + 1,
                 detail={"note": "<script>alert(1)</script>"})
    page = signed_in(env).get("/audit")
    assert "<b>eve</b>" not in page.text and "<script>alert" not in page.text


def test_older_link_appears_and_keeps_filters(env):
    seed(env.conn, 5, action="x.seed")
    page = signed_in(env).get("/audit?action=x.seed&size=2")
    assert "Older events" in page.text
    link = page.text.split('href="/audit?')[1].split('"')[0].replace("&amp;", "&")
    assert "before=" in link and "action=x.seed" in link and "size=2" in link
    second = signed_in(env).get("/audit?" + link)
    assert second.status == 200


def test_audit_page_does_not_write_to_the_audit_log(env):
    client = signed_in(env)
    before = env.conn.execute("SELECT count(*) FROM audit_events").fetchone()[0]
    client.get("/audit")
    assert env.conn.execute("SELECT count(*) FROM audit_events").fetchone()[0] == before
