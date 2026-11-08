"""Direct tunnel-connector access: client IP from CF-Connecting-IP, the LAN connection gate, and the
config rules for a LAN listener (docs/ARCHITECTURE.md section 8, GOAL.md rule 2)."""

import types

import pytest

pytest.importorskip("starlette")
pytest.importorskip("jinja2")

from starlette.requests import Request

from guard import db
from guard.auth import service
from guard.config import Config, ConfigError, load_config
from guard.web.app import client_ip, create_app, trusted_ip_set
from tests.test_web import ORIGIN, PASSWORD, Clock, FakeHasher, token_from
from tests.web_client import Client

CONNECTOR = "192.168.1.148"
KEY = "ab" * 32


def make_request(peer, headers=None, trusted=(CONNECTOR,)):
    app = types.SimpleNamespace(state=types.SimpleNamespace(trusted_ips=trusted_ip_set(trusted)))
    scope = {"type": "http", "method": "GET", "path": "/", "query_string": b"", "app": app,
             "client": (peer, 50000), "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]}
    return Request(scope)


# ---- client_ip ---------------------------------------------------------------------------------

@pytest.mark.parametrize("peer, headers, expected", [
    # the trusted connector may set the client address with CF-Connecting-IP
    (CONNECTOR, {"CF-Connecting-IP": "203.0.113.7"}, "203.0.113.7"),
    (CONNECTOR, {"CF-Connecting-IP": " 203.0.113.7 "}, "203.0.113.7"),
    (CONNECTOR, {"CF-Connecting-IP": "2001:DB8:0:0:0:0:0:1"}, "2001:db8::1"),
    ("::ffff:192.168.1.148", {"CF-Connecting-IP": "203.0.113.7"}, "203.0.113.7"),
    # a missing, empty or malformed header falls back to the connector's own address
    (CONNECTOR, {}, CONNECTOR),
    (CONNECTOR, {"CF-Connecting-IP": ""}, CONNECTOR),
    (CONNECTOR, {"CF-Connecting-IP": "not-an-ip"}, CONNECTOR),
    (CONNECTOR, {"CF-Connecting-IP": "203.0.113.7, 198.51.100.1"}, CONNECTOR),
    # other headers are never read, even from the connector
    (CONNECTOR, {"X-Forwarded-For": "203.0.113.7"}, CONNECTOR),
    (CONNECTOR, {"True-Client-IP": "203.0.113.7"}, CONNECTOR),
    (CONNECTOR, {"X-Guard-Client-Ip": "203.0.113.7"}, CONNECTOR),
    # any other peer is itself, whatever headers it sends
    ("203.0.113.5", {"CF-Connecting-IP": "198.51.100.9"}, "203.0.113.5"),
    ("192.168.1.77", {"CF-Connecting-IP": "198.51.100.9"}, "192.168.1.77"),
    ("192.168.1.77", {"X-Guard-Client-Ip": "198.51.100.9"}, "192.168.1.77"),
    # loopback (Nginx on the same machine) keeps using X-Guard-Client-Ip, and never CF-Connecting-IP
    ("127.0.0.1", {"X-Guard-Client-Ip": "198.51.100.9"}, "198.51.100.9"),
    ("127.0.0.1", {"CF-Connecting-IP": "198.51.100.9"}, "127.0.0.1"),
    ("127.0.0.1", {}, "127.0.0.1"),
])
def test_client_ip_rules(peer, headers, expected):
    assert client_ip(make_request(peer, headers)) == expected


def test_no_trusted_connectors_means_cf_header_is_ignored():
    req = make_request(CONNECTOR, {"CF-Connecting-IP": "203.0.113.7"}, trusted=())
    assert client_ip(req) == CONNECTOR


def test_unparseable_peer_never_matches_a_connector():
    for peer in ("", "invalid", "unix"):
        req = make_request(peer, {"CF-Connecting-IP": "203.0.113.7"}, trusted=("junk", ""))
        assert client_ip(req) == "invalid"


def test_trusted_set_drops_unparseable_entries():
    assert trusted_ip_set(("192.168.1.148", "junk", "::ffff:10.0.0.2")) == frozenset({"192.168.1.148", "10.0.0.2"})


# ---- the LAN listener end to end ---------------------------------------------------------------

@pytest.fixture
def lan(tmp_path):
    cfg = Config(db_path=str(tmp_path / "guard.sqlite3"), external_origin=ORIGIN,
                 trusted_connectors=(CONNECTOR,), dashboard_bind=("192.168.1.50", 8787),
                 secret_key=bytes(range(32)))
    conn = db.connect(cfg.db_path)
    db.migrate(conn)
    clock = Clock()
    service.create_admin(conn, FakeHasher(), "alice", PASSWORD, now_ms=clock())
    app = create_app(cfg, hasher=FakeHasher(), clock=clock)
    yield types.SimpleNamespace(cfg=cfg, conn=conn, clock=clock, app=app)
    conn.close()


def test_connector_and_loopback_may_connect(lan):
    assert Client(lan.app, peer=(CONNECTOR, 4000)).get("/healthz").status == 200
    assert Client(lan.app, peer=("127.0.0.1", 4000)).get("/healthz").status == 200


@pytest.mark.parametrize("peer", ["192.168.1.77", "203.0.113.5", "10.0.0.9", "::1x"])
def test_everyone_else_on_the_lan_gets_403_before_any_page(lan, peer):
    client = Client(lan.app, peer=(peer, 4000))
    for path in ("/login", "/healthz", "/", "/static/style.css"):
        r = client.get(path)
        assert r.status == 403 and r.text == "Forbidden", (peer, path)
        assert r.set_cookies() == []
    assert lan.conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1  # only admin.create


def test_a_forged_cf_header_from_a_neighbour_changes_nothing(lan):
    r = Client(lan.app, peer=("192.168.1.77", 4000)).get("/login", headers={"CF-Connecting-IP": CONNECTOR})
    assert r.status == 403


def test_loopback_only_deployment_still_reaches_untrusted_peers_for_host_check(tmp_path):
    # Without a LAN bind there is no connection gate (the listener is loopback, so there are no strangers).
    cfg = Config(db_path=str(tmp_path / "g.db"), external_origin=ORIGIN, trusted_connectors=(CONNECTOR,),
                 secret_key=bytes(range(32)))
    db.migrate(db.connect(cfg.db_path))
    app = create_app(cfg, hasher=FakeHasher())
    assert Client(app, peer=("203.0.113.5", 4000)).get("/healthz").status == 200


def test_sign_in_through_the_connector_records_each_visitors_own_address(lan):
    def login(cf_ip, password):
        client = Client(lan.app, peer=(CONNECTOR, 4000))
        h = {"CF-Connecting-IP": cf_ip}
        token = token_from(client.get("/login", headers=h))
        return client.post("/login/password", headers=h, form={
            "username": "alice", "password": password, "csrf_token": token})

    assert login("203.0.113.7", "wrong password entirely").status == 401
    assert login("198.51.100.20", PASSWORD).status == 303
    ips = {r[0] for r in lan.conn.execute("SELECT ip FROM audit_events WHERE action LIKE 'auth.%'")}
    assert {"203.0.113.7", "198.51.100.20"} <= ips and CONNECTOR not in ips
    assert [r[0] for r in lan.conn.execute("SELECT ip FROM sessions")] == ["198.51.100.20"]


def test_one_visitors_lockout_does_not_lock_everyone_behind_the_connector(lan):
    """The reason for reading CF-Connecting-IP: the sign-in throttle is per client address, so if every
    request looked like it came from the connector, one attacker would lock out all admins."""
    attacker = Client(lan.app, peer=(CONNECTOR, 4000))
    h_attacker = {"CF-Connecting-IP": "203.0.113.66"}
    token = token_from(attacker.get("/login", headers=h_attacker))
    locked = False
    for i in range(60):  # distinct usernames, so only the address counter can trip
        r = attacker.post("/login/password", headers=h_attacker, form={
            "username": f"nobody{i:02d}", "password": "wrong password entirely", "csrf_token": token})
        if r.status == 429:
            locked = True
            break
    assert locked, "the per-address throttle never engaged"
    # still locked for the attacker, even with the right password
    assert attacker.post("/login/password", headers=h_attacker, form={
        "username": "alice", "password": PASSWORD, "csrf_token": token}).status == 429
    # a different visitor through the same connector is unaffected
    other = Client(lan.app, peer=(CONNECTOR, 4001))
    h_other = {"CF-Connecting-IP": "198.51.100.20"}
    t2 = token_from(other.get("/login", headers=h_other))
    assert other.post("/login/password", headers=h_other, form={
        "username": "alice", "password": PASSWORD, "csrf_token": t2}).status == 303


def test_without_a_cf_header_the_connector_address_is_used(lan):
    client = Client(lan.app, peer=(CONNECTOR, 4000))
    token = token_from(client.get("/login"))
    client.post("/login/password", form={"username": "alice", "password": PASSWORD, "csrf_token": token})
    assert [r[0] for r in lan.conn.execute("SELECT ip FROM sessions")] == [CONNECTOR]


# ---- configuration -----------------------------------------------------------------------------

def env(**over):
    values = {"GUARD_DB_PATH": "/x.db", "GUARD_EXTERNAL_ORIGIN": "https://guard.example.org",
              "GUARD_SECRET_KEY": KEY, "GUARD_TRUSTED_CONNECTORS": CONNECTOR}
    values.update(over)
    return {k: v for k, v in values.items() if v is not None}


def test_lan_bind_needs_the_opt_in():
    with pytest.raises(ConfigError, match="loopback"):
        load_config(environ=env(GUARD_DASHBOARD_BIND="192.168.1.50:8787"))


@pytest.mark.parametrize("flag", ["1", "true", "YES", "on"])
def test_lan_bind_accepted_with_the_opt_in(flag):
    cfg = load_config(environ=env(GUARD_DASHBOARD_BIND="192.168.1.50:8787", GUARD_DASHBOARD_ALLOW_LAN=flag))
    assert cfg.dashboard_bind == ("192.168.1.50", 8787) and cfg.dashboard_on_lan


@pytest.mark.parametrize("bind", ["10.1.2.3:8787", "172.16.0.5:8787", "fd00::5:8787"])
def test_private_ranges_are_accepted(bind):
    assert load_config(environ=env(GUARD_DASHBOARD_BIND=bind, GUARD_DASHBOARD_ALLOW_LAN="1")).dashboard_on_lan


@pytest.mark.parametrize("bind", ["0.0.0.0:8787", "8.8.8.8:8787", "203.0.113.5:8787", "224.0.0.1:8787",
                                  "guard.lan:8787", "192.168.1.50:0", "192.168.1.50:70000", "192.168.1.50"])
def test_even_with_the_opt_in_only_a_specific_private_address_is_allowed(bind):
    with pytest.raises(ConfigError):
        load_config(environ=env(GUARD_DASHBOARD_BIND=bind, GUARD_DASHBOARD_ALLOW_LAN="1"))


def test_lan_bind_needs_trusted_connectors():
    with pytest.raises(ConfigError, match="TRUSTED_CONNECTORS"):
        load_config(environ=env(GUARD_DASHBOARD_BIND="192.168.1.50:8787", GUARD_DASHBOARD_ALLOW_LAN="1",
                                GUARD_TRUSTED_CONNECTORS=None))


def test_the_internal_listener_can_never_be_on_the_lan():
    with pytest.raises(ConfigError, match="loopback"):
        load_config(environ=env(GUARD_INTERNAL_BIND="192.168.1.50:8788", GUARD_DASHBOARD_ALLOW_LAN="1"))


def test_loopback_default_is_not_a_lan_listener():
    assert not load_config(environ=env()).dashboard_on_lan
    assert not load_config(environ=env(GUARD_DASHBOARD_BIND="localhost:9000")).dashboard_on_lan


def test_tls_files_default_to_off():
    cfg = load_config(environ=env())
    assert cfg.tls_cert == "" and cfg.tls_key == ""


def test_tls_files_are_read():
    cfg = load_config(environ=env(GUARD_TLS_CERT="/a/tls.crt", GUARD_TLS_KEY="/a/tls.key"))
    assert (cfg.tls_cert, cfg.tls_key) == ("/a/tls.crt", "/a/tls.key")


@pytest.mark.parametrize("over", [{"GUARD_TLS_CERT": "/a/tls.crt"}, {"GUARD_TLS_KEY": "/a/tls.key"}])
def test_tls_cert_and_key_come_together(over):
    with pytest.raises(ConfigError, match="together"):
        load_config(environ=env(**over))


def test_tls_paths_must_be_absolute():
    with pytest.raises(ConfigError, match="GUARD_TLS_CERT"):
        load_config(environ=env(GUARD_TLS_CERT="tls.crt", GUARD_TLS_KEY="/a/tls.key"))


@pytest.mark.parametrize("bad", ["not-an-ip", "192.168.1.0/24", "192.168.1.148, junk"])
def test_trusted_connectors_must_be_ip_addresses(bad):
    with pytest.raises(ConfigError, match="TRUSTED_CONNECTORS"):
        load_config(environ=env(GUARD_TRUSTED_CONNECTORS=bad))
