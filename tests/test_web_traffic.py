"""Visitors, request detail and URL History pages, CSV exports (docs/API.md 7.1 and 7.3).

Page tests need Starlette and Jinja2 and use the `env` fixture from tests/test_web.py. Requests are
written through the real ingest parser and writer. The web clock starts at T0, so each test moves it a
minute forward first: "now" must be after the seeded requests for the default 7-day range to show them.
Not yet run anywhere (see PROGRESS.md).
"""

import pytest

from tests.test_web import env, sign_in  # noqa: F401
from tests.traffic_helpers import seed
from tests.web_client import Client

ROUTES = ["/visitors", "/visitors/ip", "/visitors/request", "/visitors/export.csv", "/url-history",
          "/url-history/detail", "/url-history/export.csv"]


def signed_in(env):
    env.clock.now += 60_000
    client, response = sign_in(env)
    assert response.status == 303
    return client


@pytest.fixture
def data(env):
    seed(env.conn, 3, start=0, u="/a.html?page=1", ip="203.0.113.7", ua="AgentOne/1.0", s="200")
    seed(env.conn, 1, start=10, u="/b.html", ip="198.51.100.2", ua="<script>alert(1)</script>", s="404",
         ref="https://example.org/<b>x</b>")
    env.url_a = env.conn.execute("SELECT id FROM urls WHERE path = '/a.html'").fetchone()[0]
    env.url_b = env.conn.execute("SELECT id FROM urls WHERE path = '/b.html'").fetchone()[0]
    return env


def audit_actions(env):
    return [r["action"] for r in env.conn.execute("SELECT action FROM audit_events ORDER BY id")]


# ---- access control --------------------------------------------------------------------------

@pytest.mark.parametrize("path", ROUTES)
def test_routes_are_class_a(env, path):
    assert env.app.state.route_classes[(path, "GET")] == "A"


@pytest.mark.parametrize("path", ROUTES)
def test_routes_need_a_session(env, path):
    r = Client(env.app).get(path)
    assert r.status == 303 and r.header("location") == "/login"


def test_nav_links_are_live(data):
    page = signed_in(data).get("/visitors")
    assert 'href="/visitors"' in page.text and 'href="/url-history"' in page.text
    assert 'aria-current="page"' in page.text


# ---- visitors list ---------------------------------------------------------------------------

def test_visitors_page_lists_addresses_with_totals(data):
    page = signed_in(data).get("/visitors")
    assert page.status == 200
    assert "203.0.113.7" in page.text and "198.51.100.2" in page.text
    assert "/visitors/ip?ip=203.0.113.7" in page.text
    text = page.text.lower()
    assert "<script" not in text and "<style" not in text and " style=" not in text


def test_visitors_filter_by_address_and_prefix(data):
    client = signed_in(data)
    exact = client.get("/visitors?ip=203.0.113.7")
    assert "203.0.113.7" in exact.text.split("<tbody>")[1] and "198.51.100.2" not in exact.text.split("<tbody>")[1]
    prefix = client.get("/visitors?ip=198.")
    assert "198.51.100.2" in prefix.text.split("<tbody>")[1]


def test_visitors_bad_filter_is_400_with_a_message(data):
    page = signed_in(data).get("/visitors?sort=bogus")
    assert page.status == 400 and "Sort must be" in page.text


def test_visitors_filter_value_is_escaped(data):
    page = signed_in(data).get("/visitors?ip=%22%3E%3Cscript%3Ealert(1)%3C/script%3E")
    assert "<script>alert" not in page.text and page.status == 400


def test_visitors_paging_link_keeps_filters(data):
    page = signed_in(data).get("/visitors?size=1&sort=requests")
    assert "Next page" in page.text
    link = page.text.split('href="/visitors?')[1].split('"')[0].replace("&amp;", "&")
    assert "before=" in link and "size=1" in link and "sort=requests" in link


# ---- visitor detail --------------------------------------------------------------------------

def test_visitor_detail_shows_everything_the_spec_lists(data):
    page = signed_in(data).get("/visitors/ip?ip=203.0.113.7")
    assert page.status == 200
    for needle in ("203.0.113.7", "AgentOne/1.0", "/a.html", "GET", "200", "distinct URLs", "First seen"):
        assert needle in page.text
    assert "/url-history/detail?id=%d" % data.url_a in page.text


def test_visitor_detail_escapes_user_agent_and_referrer(data):
    client = signed_in(data)
    page = client.get("/visitors/ip?ip=198.51.100.2")
    assert "<script>alert" not in page.text and "&lt;script&gt;" in page.text
    rid = data.conn.execute("SELECT r.id FROM requests r JOIN visitors v ON v.id = r.visitor_id "
                            "WHERE v.ip = '198.51.100.2'").fetchone()[0]
    detail = client.get(f"/visitors/request?id={rid}")
    assert detail.status == 200 and "<b>x</b>" not in detail.text and "<script>alert" not in detail.text


def test_visitor_detail_unknown_or_malformed_address_is_404(data):
    client = signed_in(data)
    assert client.get("/visitors/ip?ip=10.9.9.9").status == 404
    page = client.get("/visitors/ip?ip=%3Cscript%3Ealert(1)%3C/script%3E")
    assert page.status == 404 and "<script>alert" not in page.text
    assert client.get("/visitors/ip").status == 404


def test_visitor_detail_status_filter_and_bad_filter(data):
    client = signed_in(data)
    ok = client.get("/visitors/ip?ip=203.0.113.7&status=4xx")
    assert ok.status == 200 and "No requests match." in ok.text
    bad = client.get("/visitors/ip?ip=203.0.113.7&status=abc")
    assert bad.status == 400 and "Status must be" in bad.text


# ---- request detail --------------------------------------------------------------------------

def test_request_detail_page(data):
    client = signed_in(data)
    rid = data.conn.execute("SELECT id FROM requests ORDER BY id LIMIT 1").fetchone()[0]
    page = client.get(f"/visitors/request?id={rid}")
    assert page.status == 200
    for needle in ("203.0.113.7", "initstack.org", "/a.html", "AgentOne/1.0", "1500 bytes", "300 bytes"):
        assert needle in page.text
    assert "2027-01-15T08:00:00.250Z" in page.text


@pytest.mark.parametrize("value", ["abc", "999999", "-1", "", "1" * 30])
def test_request_detail_bad_ids_are_404(data, value):
    assert signed_in(data).get(f"/visitors/request?id={value}").status == 404


# ---- URL history list ------------------------------------------------------------------------

def test_url_history_lists_most_accessed_first(data):
    page = signed_in(data).get("/url-history")
    body = page.text.split("<tbody>")[1]
    assert page.status == 200 and body.index("/a.html") < body.index("/b.html")
    assert "/url-history/detail?id=%d" % data.url_a in page.text


def test_url_history_search_by_path_and_pasted_url(data):
    client = signed_in(data)
    assert "/b.html" in client.get("/url-history?q=b.ht").text.split("<tbody>")[1]
    assert "/a.html" not in client.get("/url-history?q=b.ht").text.split("<tbody>")[1]
    pasted = client.get("/url-history?q=https%3A%2F%2Finitstack.org%2Fa.html%3Fx%3D1")
    assert "/a.html" in pasted.text.split("<tbody>")[1]


def test_url_history_period_and_errors(data):
    client = signed_in(data)
    assert client.get("/url-history?period=24h").status == 200
    bad = client.get("/url-history?period=forever")
    assert bad.status == 400 and "Period must be" in bad.text


# ---- URL detail ------------------------------------------------------------------------------

def test_url_detail_totals_graphs_and_requests(data):
    page = signed_in(data).get(f"/url-history/detail?id={data.url_a}")
    assert page.status == 200
    assert page.text.count("<svg") == 3 and "per day" in page.text
    for needle in ("visits in range", "unique addresses", "received", "sent", "203.0.113.7"):
        assert needle in page.text
    assert "<script" not in page.text.lower() and " style=" not in page.text.lower()
    stats = page.text.split('class="stats"')[1].split("</ul>")[0]
    assert ">3<" in stats and ">1<" in stats          # 3 visits, 1 unique address


def test_url_detail_short_range_graphs_per_hour(data):
    page = signed_in(data).get(f"/url-history/detail?id={data.url_a}&range=24h")
    assert page.status == 200 and "per hour" in page.text


def test_url_detail_custom_dates_and_filters(data):
    client = signed_in(data)
    page = client.get(f"/url-history/detail?id={data.url_a}&from=2027-01-14&to=2027-01-16&ip=203.0.113.&status=2xx")
    assert page.status == 200 and "203.0.113.7" in page.text
    empty = client.get(f"/url-history/detail?id={data.url_a}&ip=10.9.9.9")
    assert empty.status == 200 and "No requests match." in empty.text
    other_status = client.get(f"/url-history/detail?id={data.url_a}&status=5xx")
    assert "No requests match." in other_status.text


def test_url_detail_bad_filter_keeps_the_page_and_says_why(data):
    page = signed_in(data).get(f"/url-history/detail?id={data.url_a}&from=2027-99-99")
    assert page.status == 400 and "real calendar dates" in page.text and "/a.html" in page.text


def test_url_detail_unknown_or_bad_id(data):
    client = signed_in(data)
    assert client.get("/url-history/detail?id=999999").status == 404
    bad = client.get("/url-history/detail?id=abc")
    assert bad.status == 400 and "Choose a URL" in bad.text
    assert client.get("/url-history/detail").status == 400


def test_url_detail_range_links_and_export_link_keep_the_url(data):
    page = signed_in(data).get(f"/url-history/detail?id={data.url_a}")
    assert f"/url-history/detail?id={data.url_a}&amp;range=24h" in page.text
    assert f"/url-history/export.csv?id={data.url_a}" in page.text


# ---- CSV export ------------------------------------------------------------------------------

def test_url_export_is_a_csv_download_and_is_audited(data):
    client = signed_in(data)
    r = client.get(f"/url-history/export.csv?id={data.url_a}")
    assert r.status == 200 and "text/csv" in r.header("content-type")
    assert "attachment" in r.header("content-disposition") and f"url-history-{data.url_a}.csv" in r.header("content-disposition")
    assert r.header("x-guard-truncated") == "0"
    lines = r.text.strip().split("\r\n")
    assert lines[0].startswith("time_utc,ip,method") and len(lines) == 4
    assert all("203.0.113.7" in line for line in lines[1:])
    assert "export.url_history" in audit_actions(data)
    detail = data.conn.execute("SELECT detail FROM audit_events WHERE action = 'export.url_history'").fetchone()[0]
    assert '"rows":3' in detail.replace(" ", "")


def test_url_export_applies_filters(data):
    client = signed_in(data)
    r = client.get(f"/url-history/export.csv?id={data.url_a}&status=4xx")
    assert r.status == 200 and len(r.text.strip().split("\r\n")) == 1   # header only


def test_exports_reject_bad_filters_and_unknown_urls(data):
    client = signed_in(data)
    assert client.get(f"/url-history/export.csv?id={data.url_a}&status=zzz").status == 400
    assert client.get("/url-history/export.csv?id=999999").status == 404
    assert client.get("/url-history/export.csv").status == 400
    assert client.get("/visitors/export.csv?sort=bogus").status == 400


def test_visitors_export(data):
    client = signed_in(data)
    r = client.get("/visitors/export.csv")
    assert r.status == 200 and "text/csv" in r.header("content-type")
    lines = r.text.strip().split("\r\n")
    assert lines[0].startswith("ip,first_seen_utc") and len(lines) == 3
    assert "export.visitors" in audit_actions(data)
    filtered = client.get("/visitors/export.csv?ip=203.0.113.7")
    assert len(filtered.text.strip().split("\r\n")) == 2


# ---- dashboard overview ----------------------------------------------------------------------

def test_dashboard_on_an_empty_database_says_so_and_still_draws_graphs(env):
    page = signed_in(env).get("/")
    assert page.status == 200 and "<h1>Dashboard</h1>" in page.text
    assert "No requests recorded yet" in page.text and "No visitors recorded yet" in page.text
    assert page.text.count("<svg") == 2 and "per hour" in page.text


def test_dashboard_shows_totals_top_urls_recent_visitors_and_ingest_state(data):
    page = signed_in(data).get("/")
    assert page.status == 200
    stats = page.text.split('class="stats"')[1].split("</ul>")[0]
    assert ">4<" in stats and ">2<" in stats        # 4 requests from 2 addresses
    assert "/url-history/detail?id=%d" % data.url_a in page.text
    assert "/visitors/ip?ip=203.0.113.7" in page.text and "/visitors/ip?ip=198.51.100.2" in page.text
    assert "Last request recorded" in page.text and "No requests recorded yet" not in page.text
    lowered = page.text.lower()
    assert "<script" not in lowered and " style=" not in lowered and "<style" not in lowered


def test_dashboard_ignores_requests_older_than_24_hours(data):
    data.clock.now += 3 * 86_400_000
    page = signed_in(data).get("/")
    stats = page.text.split('class="stats"')[1].split("</ul>")[0]
    assert ">4<" not in stats and "No requests in this period." in page.text


def test_viewing_pages_does_not_write_to_the_audit_log(data):
    client = signed_in(data)
    before = data.conn.execute("SELECT count(*) FROM audit_events").fetchone()[0]
    for path in ("/", "/visitors", "/visitors/ip?ip=203.0.113.7", "/url-history",
                 f"/url-history/detail?id={data.url_a}"):
        assert client.get(path).status == 200
    assert data.conn.execute("SELECT count(*) FROM audit_events").fetchone()[0] == before
