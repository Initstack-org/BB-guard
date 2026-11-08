"""Visitors and URL History queries, charts and CSV helpers (guard/web/traffic.py, charts.py).

Pure functions over SQLite, so these need only pytest. Rows are written through the real ingest parser
and writer (tests/traffic_helpers.py). Not yet run anywhere (see PROGRESS.md).
"""

import pytest

from guard.web import charts, traffic
from guard.web.traffic import FilterError
from tests.traffic_helpers import T0_MS, seed

H = traffic.HOUR_MS
D = traffic.DAY_MS
NOW = T0_MS + 60_000  # a minute after the seeded requests, which all fall within a few seconds of T0


# ---- helpers ---------------------------------------------------------------------------------

def test_human_bytes():
    assert traffic.human_bytes(0) == "0 B"
    assert traffic.human_bytes(1023) == "1023 B"
    assert traffic.human_bytes(1536) == "1.5 KiB"
    assert traffic.human_bytes(5 * 1024 ** 3) == "5.0 GiB"
    assert traffic.human_bytes(-5) == "0 B"


@pytest.mark.parametrize("cell", ["=1+1", "+1", "-1", "@SUM(A1)", "\tx", "\rx"])
def test_csv_safe_prefixes_formulas(cell):
    assert traffic.csv_safe(cell) == "'" + cell


def test_csv_safe_leaves_normal_values_alone():
    assert traffic.csv_safe("/forum.html") == "/forum.html"
    assert traffic.csv_safe(42) == 42
    assert traffic.csv_safe("") == ""


def test_iso_utc():
    assert traffic.iso_utc(T0_MS + 250) == "2027-01-15T08:00:00.250Z"


def test_requests_to_csv_header_units_and_escaping():
    rows = [{"ts_ms": T0_MS, "ip": "203.0.113.7", "method": "GET", "host": "initstack.org", "path": "/a",
             "query": "=cmd|' /C calc'!A0", "status": 200, "bytes_in": 10, "bytes_out": 20,
             "duration_ms": 5, "outcome": "allowed", "reason": None}]
    text = traffic.requests_to_csv(rows)
    lines = text.split("\r\n")
    assert lines[0] == ",".join(traffic.CSV_REQUEST_HEADER)
    assert "bytes_received" in lines[0] and "bytes_sent" in lines[0] and "time_utc" in lines[0]
    assert "'=cmd" in lines[1] and ",=cmd" not in lines[1]
    assert lines[1].startswith("2027-01-15T08:00:00.000Z,203.0.113.7,GET")


def test_visitors_to_csv():
    rows = [{"ip": "203.0.113.7", "first_seen_ms": T0_MS, "last_seen_ms": T0_MS + 1000, "request_count": 3,
             "bytes_in": 1, "bytes_out": 2, "denied_count": 0}]
    lines = traffic.visitors_to_csv(rows).split("\r\n")
    assert lines[0] == ",".join(traffic.CSV_VISITOR_HEADER)
    assert lines[1].startswith("203.0.113.7,2027-01-15T08:00:00.000Z,2027-01-15T08:00:01.000Z,3,1,2,0")


# ---- visitor filters -------------------------------------------------------------------------

def test_visitor_filter_defaults():
    f = traffic.parse_visitor_filters({})
    assert f == traffic.VisitorFilters()


@pytest.mark.parametrize("params", [
    {"ip": "not an ip!"}, {"ip": "zzz"}, {"ip": "1" * 46}, {"sort": "bogus"}, {"from": "2027-13-01"},
    {"to": "yesterday"}, {"from": "2027-02-01", "to": "2027-01-01"}, {"size": "0"}, {"size": "201"},
    {"before": "abc"}, {"before": "1.2.3"}, {"ip": "1\x002"}])
def test_bad_visitor_filters_are_rejected(params):
    with pytest.raises(FilterError):
        traffic.parse_visitor_filters(params)


def test_visitor_ip_filter_modes():
    exact = traffic.parse_visitor_filters({"ip": "2001:DB8:0:0:0:0:0:1"})
    assert exact.ip_exact == "2001:db8::1" and exact.ip_prefix == ""
    prefix = traffic.parse_visitor_filters({"ip": "203.0.113."})
    assert prefix.ip_exact == "" and prefix.ip_prefix == "203.0.113."


# ---- visitor queries -------------------------------------------------------------------------

@pytest.fixture
def three_visitors(conn):
    seed(conn, 3, start=0, ip="203.0.113.7")
    seed(conn, 2, start=10, ip="198.51.100.2")
    seed(conn, 1, start=20, ip="2001:db8::1")
    return conn


def test_visitor_page_orders_by_last_seen_and_pages_without_gaps(three_visitors):
    rows, cursor = traffic.visitor_page(three_visitors, traffic.VisitorFilters(size=2))
    assert [r["ip"] for r in rows] == ["2001:db8::1", "198.51.100.2"] and cursor
    f = traffic.parse_visitor_filters({"before": cursor, "size": "2"})
    rest, cursor2 = traffic.visitor_page(three_visitors, f)
    assert [r["ip"] for r in rest] == ["203.0.113.7"] and cursor2 is None


def test_visitor_page_sorts_by_requests(three_visitors):
    rows, _ = traffic.visitor_page(three_visitors, traffic.parse_visitor_filters({"sort": "requests"}))
    assert [r["request_count"] for r in rows] == [3, 2, 1]


def test_sorted_by_requests_pages_with_ties(conn):
    for n, ip in enumerate(["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]):
        seed(conn, 1, start=n, ip=ip)  # every visitor has exactly one request
    seen, cursor = [], None
    while True:
        f = traffic.parse_visitor_filters({"sort": "requests", "size": "2", **({"before": cursor} if cursor else {})})
        rows, cursor = traffic.visitor_page(conn, f)
        seen += [r["ip"] for r in rows]
        if cursor is None:
            break
    assert sorted(seen) == ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]


def test_visitor_ip_filters(three_visitors):
    def ips(**params):
        rows, _ = traffic.visitor_page(three_visitors, traffic.parse_visitor_filters(params))
        return sorted(r["ip"] for r in rows)
    assert ips(ip="203.0.113.7") == ["203.0.113.7"]
    assert ips(ip="203.0.113.") == ["203.0.113.7"]
    assert ips(ip="198.") == ["198.51.100.2"]
    assert ips(ip="2001:db8") == ["2001:db8::1"]
    assert ips(ip="2001:DB8::1") == ["2001:db8::1"]
    assert ips(ip="203.0.113.70") == []     # an exact address, not a prefix of another one
    assert ips() and len(ips()) == 3


def test_visitor_date_filter_uses_overlap(three_visitors):
    def count(**params):
        rows, _ = traffic.visitor_page(three_visitors, traffic.parse_visitor_filters(params, "UTC"))
        return len(rows)
    assert count(**{"from": "2027-01-15", "to": "2027-01-15"}) == 3
    assert count(**{"from": "2027-01-16"}) == 0
    assert count(**{"to": "2027-01-14"}) == 0


def test_visitor_filter_values_are_not_sql(three_visitors):
    for value in ("' OR 1=1 --", "%", "_"):
        with pytest.raises(FilterError):
            traffic.parse_visitor_filters({"ip": value})
    assert three_visitors.execute("SELECT count(*) FROM visitors").fetchone()[0] == 3


def test_visitor_by_ip_accepts_non_canonical_text(three_visitors):
    assert traffic.visitor_by_ip(three_visitors, " 203.0.113.7 ")["request_count"] == 3
    assert traffic.visitor_by_ip(three_visitors, "2001:0DB8::1")["ip"] == "2001:db8::1"
    assert traffic.visitor_by_ip(three_visitors, "203.0.113.99") is None
    assert traffic.visitor_by_ip(three_visitors, "nonsense") is None


def test_visitor_summaries(conn):
    seed(conn, 2, start=0, ip="203.0.113.7", u="/a.html", ua="AgentOne/1.0")
    seed(conn, 1, start=5, ip="203.0.113.7", u="/b.html", ua="AgentTwo/2.0", m="POST", s="404",
         uid="7", un="alice")
    vid = traffic.visitor_by_ip(conn, "203.0.113.7")["id"]
    urls, total = traffic.visitor_urls(conn, vid)
    assert total == 2 and [(u["path"], u["hits"]) for u in urls] == [("/a.html", 2), ("/b.html", 1)]
    agents = traffic.visitor_agents(conn, vid)
    assert [a["value"] for a in agents] == ["AgentTwo/2.0", "AgentOne/1.0"]   # newest first
    accounts = traffic.visitor_accounts(conn, vid)
    assert [(a["uid"], a["username"]) for a in accounts] == [(7, "alice")]
    assert [(m["value"], m["n"]) for m in traffic.visitor_breakdown(conn, vid, "method")] == \
        [("GET", 2), ("POST", 1)]
    assert [(s["value"], s["n"]) for s in traffic.visitor_breakdown(conn, vid, "status")] == \
        [(200, 2), (404, 1)]
    with pytest.raises(ValueError):
        traffic.visitor_breakdown(conn, vid, "ip; DROP TABLE requests")


def test_visitor_breakdown_respects_the_date_range(conn):
    seed(conn, 2, start=0, ip="203.0.113.7")
    vid = traffic.visitor_by_ip(conn, "203.0.113.7")["id"]
    assert traffic.visitor_breakdown(conn, vid, "method", T0_MS + 10_000_000, None) == []
    assert traffic.visitor_breakdown(conn, vid, "method", None, T0_MS - 1) == []
    assert len(traffic.visitor_breakdown(conn, vid, "method", T0_MS, T0_MS + 5000)) == 1


# ---- request lists ---------------------------------------------------------------------------

def test_request_page_keyset_covers_every_row_once(conn):
    seed(conn, 7, start=0, ip="203.0.113.7")
    vid = traffic.visitor_by_ip(conn, "203.0.113.7")["id"]
    seen, cursor = [], None
    while True:
        f = traffic.RequestFilters(visitor_id=vid, size=3,
                                   cursor=traffic.parse_visitor_filters({"before": cursor}).cursor if cursor else None)
        rows, cursor = traffic.request_page(conn, f)
        seen += [r["id"] for r in rows]
        if cursor is None:
            break
    assert len(seen) == 7 and len(set(seen)) == 7
    newest = conn.execute("SELECT id FROM requests ORDER BY ts_ms DESC, id DESC").fetchone()[0]
    assert seen[0] == newest


def test_request_filters_status_and_dates(conn):
    seed(conn, 2, start=0, ip="203.0.113.7", s="200")
    seed(conn, 1, start=5, ip="203.0.113.7", s="404")
    seed(conn, 1, start=6, ip="203.0.113.7", s="503")
    vid = traffic.visitor_by_ip(conn, "203.0.113.7")["id"]

    def count(**params):
        f, _ = traffic.parse_request_filters(params, "UTC", visitor_id=vid)
        return len(traffic.request_page(conn, f)[0])
    assert count() == 4
    assert count(status="404") == 1
    assert count(status="4xx") == 1
    assert count(status="5xx") == 1
    assert count(status="2xx") == 2
    assert count(**{"from": "2027-01-16"}) == 0
    assert count(**{"from": "2027-01-15", "to": "2027-01-15"}) == 4


@pytest.mark.parametrize("status", ["99", "abc", "6xx", "20", "2x", "1000"])
def test_bad_status_filters_are_rejected(status):
    with pytest.raises(FilterError):
        traffic.parse_request_filters({"status": status}, "UTC")


def test_request_detail_joins_everything(conn):
    seed(conn, 1, start=0, ip="203.0.113.7", ua="Agent/1.0", ref="https://example.org/x", uid="7", un="alice")
    rid = conn.execute("SELECT id FROM requests").fetchone()[0]
    row = traffic.request_detail(conn, rid)
    assert row["ip"] == "203.0.113.7" and row["user_agent"] == "Agent/1.0"
    assert row["referrer"] == "https://example.org/x" and row["mybb_username"] == "alice"
    assert row["outcome"] == "allowed" and row["host"] == "initstack.org"
    assert traffic.request_detail(conn, rid + 1000) is None


# ---- URL history -----------------------------------------------------------------------------

def test_url_query_normalisation():
    assert traffic.normalize_url_query("https://initstack.org/a.html?x=1#top") == "/a.html"
    assert traffic.normalize_url_query("https://initstack.org") == "/"
    assert traffic.normalize_url_query("/a.html?x=1") == "/a.html"
    assert traffic.normalize_url_query("  /plain ") == "/plain"


@pytest.mark.parametrize("params", [{"period": "1y"}, {"size": "0"}, {"before": "x"}, {"q": "x" * 401},
                                    {"q": "a\x00b"}])
def test_bad_url_list_filters_are_rejected(params):
    with pytest.raises(FilterError):
        traffic.parse_url_list_filters(params)


@pytest.fixture
def urls_db(conn):
    seed(conn, 3, start=0, u="/a.html", ip="203.0.113.7", s="200")
    seed(conn, 1, start=10, u="/b.html", ip="198.51.100.2", s="404")
    seed(conn, 1, start=20, u="/x_y.html", ip="198.51.100.2", s="200")
    seed(conn, 1, start=21, u="/xzy.html", ip="198.51.100.2", s="200")
    return conn


def test_url_ranking_all_time_is_ordered_and_paged(urls_db):
    f = traffic.parse_url_list_filters({"size": "2"})
    rows, cursor = traffic.url_ranking(urls_db, f, NOW)
    assert rows[0]["path"] == "/a.html" and rows[0]["hits"] == 3 and cursor
    seen = [r["path"] for r in rows]
    while cursor:
        f = traffic.parse_url_list_filters({"size": "2", "before": cursor})
        rows, cursor = traffic.url_ranking(urls_db, f, NOW)
        seen += [r["path"] for r in rows]
    assert sorted(seen) == ["/a.html", "/b.html", "/x_y.html", "/xzy.html"]


def test_url_search_matches_part_of_the_path_and_escapes_wildcards(urls_db):
    def paths(**params):
        rows, _ = traffic.url_ranking(urls_db, traffic.parse_url_list_filters(params), NOW)
        return sorted(r["path"] for r in rows)
    assert paths(q="a.ht") == ["/a.html"]
    assert paths(q="A.HTML") == ["/a.html"]                      # case-insensitive
    assert paths(q="https://initstack.org/b.html?x=1") == ["/b.html"]
    assert paths(q="x_y") == ["/x_y.html"]                       # an underscore is not "any character"
    assert "/a.html" not in paths(q="%")                          # a percent sign is not a wildcard
    assert paths(q="nothing-like-this") == []
    assert len(paths()) == 4


def test_url_ranking_for_a_period_is_a_top_list(urls_db):
    f = traffic.parse_url_list_filters({"period": "24h"})
    rows, cursor = traffic.url_ranking(urls_db, f, NOW)
    assert cursor is None and rows[0]["path"] == "/a.html" and rows[0]["hits"] == 3
    assert traffic.url_ranking(urls_db, f, T0_MS + 3 * D)[0] == []    # nothing in the last 24 hours then


def test_url_summary_and_filters(urls_db):
    a = urls_db.execute("SELECT id FROM urls WHERE path = '/a.html'").fetchone()[0]
    b = urls_db.execute("SELECT id FROM urls WHERE path = '/b.html'").fetchone()[0]
    full = traffic.url_summary(urls_db, a, T0_MS - H, T0_MS + H)
    assert full == {"visits": 3, "unique_ips": 1, "bytes_in": 900, "bytes_out": 4500, "denied": 0}
    b_sum = traffic.url_summary(urls_db, b, T0_MS - H, T0_MS + H)
    assert b_sum["visits"] == 1
    assert traffic.url_summary(urls_db, b, T0_MS - H, T0_MS + H, status_lo=400, status_hi=499)["visits"] == 1
    assert traffic.url_summary(urls_db, b, T0_MS - H, T0_MS + H, status_lo=200, status_hi=299)["visits"] == 0
    assert traffic.url_summary(urls_db, a, T0_MS + H, T0_MS + 2 * H)["visits"] == 0
    assert traffic.url_summary(urls_db, a, T0_MS - H, T0_MS + H, visitor_ids=[])["visits"] == 0


def test_url_detail_filters_and_address_resolution(urls_db):
    a = urls_db.execute("SELECT id FROM urls WHERE path = '/a.html'").fetchone()[0]
    f = traffic.parse_url_detail_filters({"id": str(a), "ip": "203.0.113.", "status": "2xx"}, "UTC", NOW)
    ids = traffic.resolve_visitor_ids(urls_db, f.ip_exact, f.ip_prefix)
    assert len(ids) == 1
    rows, cursor = traffic.url_requests_page(urls_db, f, ids)
    assert len(rows) == 3 and cursor is None
    none = traffic.parse_url_detail_filters({"id": str(a), "ip": "10.9.9.9"}, "UTC", NOW)
    ids_none = traffic.resolve_visitor_ids(urls_db, none.ip_exact, none.ip_prefix)
    assert ids_none == [] and traffic.url_requests_page(urls_db, none, ids_none) == ([], None)
    assert traffic.url_requests_for_csv(urls_db, none, ids_none) == []
    assert traffic.resolve_visitor_ids(urls_db, "", "") is None


def test_prefix_matching_several_visitors_uses_all_of_them(conn):
    seed(conn, 1, start=0, u="/a.html", ip="203.0.113.7")
    seed(conn, 1, start=1, u="/a.html", ip="203.0.113.8")
    seed(conn, 1, start=2, u="/a.html", ip="198.51.100.2")
    url_id = conn.execute("SELECT id FROM urls").fetchone()[0]
    f = traffic.parse_url_detail_filters({"id": str(url_id), "ip": "203.0.113."}, "UTC", NOW)
    ids = traffic.resolve_visitor_ids(conn, f.ip_exact, f.ip_prefix)
    assert len(ids) == 2
    rows, _ = traffic.url_requests_page(conn, f, ids)
    assert sorted(r["ip"] for r in rows) == ["203.0.113.7", "203.0.113.8"]
    assert len(traffic.url_requests_for_csv(conn, f, ids)) == 2
    assert traffic.url_summary(conn, url_id, T0_MS - H, T0_MS + H, ids)["unique_ips"] == 2


@pytest.mark.parametrize("params", [{}, {"id": "abc"}, {"id": "-1"}, {"id": "1" * 17}])
def test_url_detail_needs_a_numeric_id(params):
    with pytest.raises(FilterError):
        traffic.parse_url_detail_filters(params, "UTC", T0_MS)


# ---- ranges ----------------------------------------------------------------------------------

def test_range_presets():
    r = traffic.parse_range({}, "UTC", T0_MS)
    assert r.key == "7d" and r.to_ms == T0_MS + 1 and r.to_ms - r.from_ms == 7 * D + 1
    assert traffic.parse_range({"range": "24h"}, "UTC", T0_MS).key == "24h"
    assert traffic.parse_range({"range": "30d"}, "UTC", T0_MS).from_ms == T0_MS - 30 * D


def test_custom_range():
    r = traffic.parse_range({"from": "2027-01-10", "to": "2027-01-12"}, "UTC", T0_MS)
    assert r.key == "custom" and r.to_ms - r.from_ms == 3 * D
    only_from = traffic.parse_range({"from": "2027-01-10"}, "UTC", T0_MS)
    assert only_from.to_ms == T0_MS + 1
    only_to = traffic.parse_range({"to": "2027-01-12"}, "UTC", T0_MS)
    assert only_to.to_ms - only_to.from_ms == 30 * D


@pytest.mark.parametrize("params", [{"range": "1y"}, {"from": "2027-01-12", "to": "2027-01-10"},
                                    {"from": "2020-01-01", "to": "2027-01-01"}])
def test_bad_ranges_are_rejected(params):
    with pytest.raises(FilterError):
        traffic.parse_range(params, "UTC", T0_MS)


def test_range_follows_the_admin_time_zone():
    est = traffic.parse_range({"from": "2027-01-10", "to": "2027-01-10"}, "America/Indiana/Indianapolis", T0_MS)
    utc = traffic.parse_range({"from": "2027-01-10", "to": "2027-01-10"}, "UTC", T0_MS)
    assert est.from_ms - utc.from_ms == 5 * H


# ---- series ----------------------------------------------------------------------------------

@pytest.fixture
def series_db(conn):
    seed(conn, 3, start=0, u="/a.html", ip="203.0.113.7")          # T0 .. T0+2 s, 08:00 UTC
    seed(conn, 1, start=7200, u="/a.html", ip="203.0.113.7")        # two hours later
    return conn, conn.execute("SELECT id, hit_count FROM urls").fetchone()


def test_hourly_series_for_a_short_range(series_db):
    conn, url = series_db
    unit, buckets = traffic.url_series(conn, url["id"], url["hit_count"], T0_MS - 3 * H, T0_MS + 4 * H, "UTC")
    assert unit == "hour"
    by_label = {b.label: b.requests for b in buckets}
    assert by_label["08:00"] == 3 and by_label["10:00"] == 1 and sum(by_label.values()) == 4
    assert [b.start_ms for b in buckets] == sorted(b.start_ms for b in buckets)
    eight = next(b for b in buckets if b.label == "08:00")
    assert eight.bytes_in == 900 and eight.bytes_out == 4500


def test_daily_series_for_a_long_range_in_the_admin_time_zone(series_db):
    conn, url = series_db
    unit, buckets = traffic.url_series(conn, url["id"], url["hit_count"], T0_MS - 7 * D, T0_MS + 4 * H, "UTC")
    assert unit == "day" and len(buckets) == 8
    assert sum(b.requests for b in buckets) == 4 and buckets[-1].full_label == "2027-01-15"
    assert buckets[-1].requests == 4
    # In Indianapolis (UTC-5 in January) 08:00 and 10:00 UTC are 03:00 and 05:00 the same day.
    _, local = traffic.url_series(conn, url["id"], url["hit_count"], T0_MS - 7 * D, T0_MS + 4 * H,
                                  "America/Indiana/Indianapolis")
    assert local[-1].requests == 4


def test_series_uses_the_hourly_rollup_for_busy_urls(series_db):
    conn, url = series_db
    conn.execute("DELETE FROM rollup_url_hourly")
    conn.execute("INSERT INTO rollup_url_hourly(hour_ms, url_id, requests, bytes_in, bytes_out, denied) "
                 "VALUES (?, ?, 99, 1000, 2000, 0)", (T0_MS - T0_MS % H, url["id"]))
    unit, buckets = traffic.url_series(conn, url["id"], traffic.RAW_SERIES_MAX_HITS + 1,
                                       T0_MS - 3 * H, T0_MS + 4 * H, "UTC")
    assert unit == "hour" and {b.label: b.requests for b in buckets}["08:00"] == 99


def test_series_has_a_bucket_for_every_period_even_when_empty(series_db):
    conn, url = series_db
    _, buckets = traffic.url_series(conn, url["id"], url["hit_count"], T0_MS + 5 * D, T0_MS + 6 * D, "UTC")
    assert len(buckets) >= 2 and all(b.requests == 0 for b in buckets)


# ---- dashboard overview ----------------------------------------------------------------------

def test_site_overview_of_an_empty_database(conn):
    ov = traffic.site_overview(conn, NOW, "UTC")
    assert ov["requests"] == ov["visitors"] == ov["bytes_in"] == ov["bytes_out"] == ov["denied"] == 0
    assert len(ov["buckets"]) == traffic.OVERVIEW_HOURS == 24
    assert all(b.requests == 0 for b in ov["buckets"])


def test_site_overview_counts_the_last_24_hourly_buckets(conn):
    seed(conn, 3, start=0, ip="203.0.113.7")
    seed(conn, 2, start=10, ip="198.51.100.2", s="404")
    ov = traffic.site_overview(conn, NOW, "UTC")
    assert ov["requests"] == 5 and ov["visitors"] == 2
    assert ov["bytes_in"] == 1500 and ov["bytes_out"] == 7500
    assert ov["buckets"][-1].label == "08:00" and ov["buckets"][-1].requests == 5
    assert sum(b.requests for b in ov["buckets"]) == 5
    starts = [b.start_ms for b in ov["buckets"]]
    assert starts == sorted(starts) and starts[-1] - starts[0] == 23 * H
    assert ov["to_ms"] - ov["from_ms"] == 24 * H


def test_site_overview_leaves_out_older_traffic(conn):
    seed(conn, 3, start=0, ip="203.0.113.7")
    later = traffic.site_overview(conn, NOW + 3 * D, "UTC")
    assert later["requests"] == 0 and later["visitors"] == 0
    edge = traffic.site_overview(conn, NOW + 23 * H, "UTC")      # 07:01 next day: 08:00 is the first bucket
    assert edge["requests"] == 3 and edge["buckets"][0].label == "08:00"
    gone = traffic.site_overview(conn, NOW + 24 * H, "UTC")      # 08:01 next day: 08:00 has dropped out
    assert gone["requests"] == 0


def test_site_overview_labels_follow_the_admin_time_zone(conn):
    seed(conn, 1, start=0, ip="203.0.113.7")
    ov = traffic.site_overview(conn, NOW, "America/Indiana/Indianapolis")
    assert ov["buckets"][-1].label == "03:00" and ov["buckets"][-1].requests == 1


def test_ingest_status_before_and_after_a_write(conn):
    before = traffic.ingest_status(conn)
    assert before["last_request_ms"] is None and before["lines_total"] == 0 and before["updated_ms"] == 0
    seed(conn, 2, start=0, ip="203.0.113.7")
    after = traffic.ingest_status(conn)
    assert after["lines_total"] == 2 and after["bad_lines_total"] == 0
    assert T0_MS <= after["last_request_ms"] < T0_MS + 5000 and after["updated_ms"] == T0_MS


# ---- charts ----------------------------------------------------------------------------------

def test_bar_chart_is_an_escaped_svg_without_scripts_or_styles():
    svg = charts.bar_chart('<script>alert(1)</script>', [("a<b", "x&y", 5), ("c", "d", 0)],
                           value_text=lambda n: f"{n} <req>", note='per "hour"')
    assert svg.startswith("<svg") and svg.endswith("</svg>")
    assert "<script" not in svg and "<req>" not in svg and "a<b" not in svg
    assert "&lt;script&gt;" in svg and "x&amp;y" in svg
    assert " style=" not in svg and "<style" not in svg and "onload" not in svg.lower()


def test_bar_chart_handles_empty_and_all_zero_data():
    assert "<rect" not in charts.bar_chart("Empty", [], value_text=str)
    zero = charts.bar_chart("Zero", [("a", "a", 0), ("b", "b", 0)], value_text=str)
    assert zero.count("<rect") == 2 and 'height="0.00"' in zero


def test_bar_chart_labels_at_most_a_few_ticks():
    points = [(str(i), str(i), i) for i in range(100)]
    svg = charts.bar_chart("Many", points, value_text=str)
    assert svg.count("<rect") == 100
    assert svg.count('text-anchor="middle"') <= 13
