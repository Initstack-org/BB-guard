"""General Settings: registry validation (pure) and the page (docs/API.md 10.4, SCHEMA.md section 6).

Not yet run anywhere (see CHANGES.md).
"""

import json

import pytest

from guard.web import limits, settings_registry as reg
from guard.web.settings_registry import SettingError, parse

from conftest import NOW
from tests.test_web import env, sign_in, token_from  # noqa: F401

IP = "203.0.113.1"


def get(key):
    return reg.BY_KEY[key]


def stored_value(conn, key):
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return None if row is None else json.loads(row["value"])


def save(conn, admin_id, key, raw, confirm=""):
    return reg.set_value(conn, key, raw, confirm=confirm, admin_id=admin_id, admin_name="alice",
                         ip=IP, now_ms=NOW)


# ---- registry shape --------------------------------------------------------------------------

def test_every_editable_default_round_trips_through_parse():
    for s in reg.REGISTRY:
        if s.editable:
            assert parse(s, reg.display(s, s.default)) == s.default, s.key


def test_auth_bounds_match_the_reader():
    for key, (low, high) in limits.BOUNDS.items():
        assert (get(key).low, get(key).high) == (low, high), key


def test_registry_covers_the_documented_keys():
    for key in ("site.hosts", "enforcement.mode", "enforcement.paths", "intel.policy",
                "auth.password_login_enabled", "auth.throttle", "retention.requests_days",
                "export.csv_max_rows", "mybb.injections_enabled"):
        assert key in reg.BY_KEY


def test_retention_and_backup_keys_are_read_only():
    for s in reg.REGISTRY:
        assert s.editable == (not s.key.startswith(("retention.", "backup."))), s.key


def test_no_secret_like_keys():
    for s in reg.REGISTRY:
        assert not any(w in s.key for w in ("secret", "password_hash", "token", "api_key", "credential")), s.key


# ---- parse -----------------------------------------------------------------------------------

@pytest.mark.parametrize("key, raw", [
    ("auth.session_idle_s", "5"), ("auth.session_idle_s", "99999999"), ("auth.session_idle_s", "ten"),
    ("auth.session_idle_s", "1.5"), ("auth.session_idle_s", ""), ("auth.password_min_length", "8"),
    ("auth.reauth_window_s", "-1"), ("intel.tor.min_ratio", "1.5"), ("intel.tor.min_ratio", "nan"),
    ("intel.tor.min_ratio", "inf"), ("export.csv_max_rows", "1"), ("enforcement.mode", "off"),
    ("auth.password_login_enabled", "yes"), ("ui.default_timezone", "Mars/Base"),
    ("ui.default_timezone", "../etc/passwd"), ("ui.default_timezone", "America"),
    ("site.appeal_url", "javascript:alert(1)"), ("site.appeal_url", "example.org/appeal"),
    ("site.appeal_url", "x" * 301), ("site.hosts", ""), ("site.hosts", "bad host"),
    ("site.hosts", "under_score.org"), ("site.hosts", "a.org\na.org"),
    ("site.hosts", "\n".join(f"h{i}.org" for i in range(21))),
    ("enforcement.protected_paths", "no-slash"), ("enforcement.protected_paths", "/a b"),
    ("enforcement.protected_paths", "/a?x=1"), ("auth.throttle", "not json"),
    ("auth.session_idle_s", "6\x00"),
])
def test_bad_values_are_rejected(key, raw):
    with pytest.raises(SettingError):
        parse(get(key), raw)


def test_good_values_parse():
    assert parse(get("auth.session_idle_s"), " 600 ") == 600
    assert parse(get("auth.password_login_enabled"), "false") is False
    assert parse(get("intel.tor.min_ratio"), "0.25") == 0.25
    assert parse(get("enforcement.mode"), "monitor_only") == "monitor_only"
    assert parse(get("ui.default_timezone"), "America/Indiana/Indianapolis") == "America/Indiana/Indianapolis"
    assert parse(get("site.appeal_url"), "") == "" and parse(get("site.appeal_url"), "https://initstack.org/appeal")
    assert parse(get("site.hosts"), "InitStack.org\n www.initstack.org \n\n") == ["initstack.org", "www.initstack.org"]


def test_json_settings_validate_their_shape():
    paths = get("enforcement.paths")
    good = [{"path": "/member.php", "param": "action", "values": ["login"]}]
    assert parse(paths, json.dumps(good)) == good
    for bad in ([{"path": "member.php", "param": "action", "values": ["login"]}],
                [{"path": "/m", "param": "a b", "values": ["x"]}],
                [{"path": "/m", "param": "a", "values": []}],
                [{"path": "/m", "param": "a", "values": ["x"], "extra": 1}],
                {"path": "/m"}, "x", [{"path": 5, "param": "a", "values": ["x"]}]):
        with pytest.raises(SettingError):
            parse(paths, json.dumps(bad))


def test_policy_rejects_hosting_blocking_and_a_confidence_threshold():
    policy = get("intel.policy")
    good = json.loads(reg.display(policy, policy.default))
    assert parse(policy, json.dumps(good)) == good
    with_hosting = dict(good, hosting={"block": True})
    with pytest.raises(SettingError):
        parse(policy, json.dumps(with_hosting))
    with pytest.raises(SettingError, match="min_confidence"):
        parse(policy, json.dumps(dict(good, min_confidence=0.9)))
    with pytest.raises(SettingError):
        parse(policy, json.dumps(dict(good, tor={"block": "yes"})))
    missing = {k: v for k, v in good.items() if k != "proxy"}
    with pytest.raises(SettingError):
        parse(policy, json.dumps(missing))


def test_throttle_uses_the_readers_bounds():
    t = get("auth.throttle")
    ok = {"max_failures": 3, "window_s": 600, "lockout_s": 300, "lockout_max_s": 3600}
    assert parse(t, json.dumps(ok)) == ok
    for bad in (dict(ok, max_failures=1), dict(ok, max_failures=True), dict(ok, lockout_max_s=100),
                {k: v for k, v in ok.items() if k != "window_s"}, dict(ok, extra=1)):
        with pytest.raises(SettingError):
            parse(t, json.dumps(bad))


# ---- set and reset ---------------------------------------------------------------------------

def test_set_value_stores_audits_and_is_read_by_limits(conn, admin_id):
    counter = lambda: conn.execute("SELECT value FROM change_counters WHERE name='settings'").fetchone()[0]
    before = counter()
    assert save(conn, admin_id, "auth.session_idle_s", "600") == 600
    assert stored_value(conn, "auth.session_idle_s") == 600 and counter() > before
    assert limits.load(conn).idle_s == 600
    event = conn.execute("SELECT * FROM audit_events WHERE action='settings.update'").fetchone()
    assert event["target_type"] == "setting" and event["target_id"] == "auth.session_idle_s"
    assert json.loads(event["detail"]) == {"new": 600, "old": 1800}
    save(conn, admin_id, "auth.session_idle_s", "900")      # second save updates the same row
    assert conn.execute("SELECT COUNT(*) FROM settings").fetchone()[0] == 1


def test_set_value_rejects_bad_input_and_writes_nothing(conn, admin_id):
    for key, raw in (("auth.session_idle_s", "5"), ("nope.key", "1"), ("retention.requests_days", "30")):
        with pytest.raises(SettingError):
            save(conn, admin_id, key, raw)
    assert conn.execute("SELECT COUNT(*) FROM settings").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE action LIKE 'settings.%'").fetchone()[0] == 0


def test_confirm_keys_need_the_word_confirm(conn, admin_id):
    for key, raw in (("enforcement.mode", "monitor_only"), ("enforcement.allow_site_wide_url_deny", "true"),
                     ("enforcement.protected_paths", "/_guard/\n/admin/")):
        with pytest.raises(SettingError, match="confirm"):
            save(conn, admin_id, key, raw)
        with pytest.raises(SettingError, match="confirm"):
            save(conn, admin_id, key, raw, confirm="yes")
    assert conn.execute("SELECT COUNT(*) FROM settings").fetchone()[0] == 0
    save(conn, admin_id, "enforcement.mode", "monitor_only", confirm=" Confirm ")
    assert stored_value(conn, "enforcement.mode") == "monitor_only"


def test_password_login_can_only_be_turned_off_when_everyone_has_a_passkey(conn, admin_id):
    with pytest.raises(SettingError, match="passkey"):
        save(conn, admin_id, "auth.password_login_enabled", "false", confirm="confirm")
    assert stored_value(conn, "auth.password_login_enabled") is None
    conn.execute("INSERT INTO passkeys(admin_id, credential_id, public_key, name, created_ms)"
                 " VALUES (?, randomblob(16), x'00', 'laptop', 1)", (admin_id,))
    save(conn, admin_id, "auth.password_login_enabled", "false", confirm="confirm")
    assert stored_value(conn, "auth.password_login_enabled") is False


def test_a_disabled_admin_without_a_passkey_does_not_block_turning_password_login_off(conn, hasher, admin_id):
    from guard.auth import service
    other = service.create_admin(conn, hasher, "bob", "bobs long starting passphrase", now_ms=NOW)
    conn.execute("UPDATE admins SET is_disabled = 1 WHERE id = ?", (other,))
    conn.execute("INSERT INTO passkeys(admin_id, credential_id, public_key, name, created_ms)"
                 " VALUES (?, randomblob(16), x'00', 'k', 1)", (admin_id,))
    save(conn, admin_id, "auth.password_login_enabled", "false", confirm="confirm")


def test_reset_deletes_the_row_and_audits(conn, admin_id):
    save(conn, admin_id, "auth.session_idle_s", "600")
    assert reg.reset_value(conn, "auth.session_idle_s", confirm="", admin_id=admin_id, admin_name="alice",
                           ip=IP, now_ms=NOW) is True
    assert stored_value(conn, "auth.session_idle_s") is None and limits.load(conn).idle_s == 1800
    assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE action='settings.reset'").fetchone()[0] == 1
    assert reg.reset_value(conn, "auth.session_idle_s", confirm="", admin_id=admin_id, admin_name="alice",
                           ip=IP, now_ms=NOW) is False


def test_reset_of_confirm_keys_and_read_only_keys(conn, admin_id):
    with pytest.raises(SettingError, match="confirm"):
        reg.reset_value(conn, "enforcement.mode", confirm="", admin_id=admin_id, admin_name="a", ip=IP, now_ms=NOW)
    with pytest.raises(SettingError, match="Backups"):
        reg.reset_value(conn, "retention.audit_days", confirm="", admin_id=admin_id, admin_name="a", ip=IP, now_ms=NOW)
    with pytest.raises(SettingError, match="Unknown"):
        reg.reset_value(conn, "nope", confirm="", admin_id=admin_id, admin_name="a", ip=IP, now_ms=NOW)


def test_bad_stored_json_falls_back_to_the_default(conn):
    s = get("auth.session_idle_s")
    assert reg.effective_value(s, None) == 1800
    conn.execute("INSERT INTO settings(key, value, updated_ms) VALUES ('auth.session_idle_s', '700', 1)")
    assert reg.effective_value(s, reg.stored(conn)["auth.session_idle_s"]) == 700


# ---- the page --------------------------------------------------------------------------------

def signed_in(env):
    client, response = sign_in(env)
    assert response.status == 303
    return client


def post(client, path, **fields):
    token = token_from(client.get("/settings"))
    return client.post(path, form={"csrf_token": token, **fields})


def test_route_classes(env):
    classes = env.app.state.route_classes
    assert classes[("/settings", "GET")] == "A"
    assert classes[("/api/v1/settings/set", "POST")] == "R"
    assert classes[("/api/v1/settings/reset", "POST")] == "R"


def test_page_requires_a_session(env):
    from tests.web_client import Client
    r = Client(env.app).get("/settings")
    assert r.status == 303 and r.header("location") == "/login"


def test_page_lists_groups_and_keys_without_inline_script_or_style(env):
    page = signed_in(env).get("/settings")
    assert page.status == 200
    for text in ("General Settings", "auth.session_idle_s", "enforcement.mode", "intel.policy",
                 "Retention (managed on the Backups and Retention page)", "retention.requests_days"):
        assert text in page.text
    assert 'href="/settings"' in page.text and 'aria-current="page"' in page.text
    lowered = page.text.lower()
    assert "<script" not in lowered and "<style" not in lowered and " style=" not in lowered


def test_save_and_reset_through_the_page(env):
    client = signed_in(env)
    r = post(client, "/api/v1/settings/set", key="auth.session_idle_s", value="900")
    assert r.status == 303 and r.header("location") == "/settings?msg=saved"
    assert stored_value(env.conn, "auth.session_idle_s") == 900
    page = client.get("/settings?msg=saved")
    assert "Setting saved." in page.text and "changed" in page.text and "Reset to default" in page.text
    r = post(client, "/api/v1/settings/reset", key="auth.session_idle_s")
    assert r.status == 303 and r.header("location") == "/settings?msg=reset"
    assert stored_value(env.conn, "auth.session_idle_s") is None


def test_the_saved_limit_takes_effect_on_the_next_request(env):
    client = signed_in(env)
    post(client, "/api/v1/settings/set", key="auth.session_idle_s", value="60")
    env.clock.now += 120_000          # 2 minutes of inactivity against a 60 second limit
    assert client.get("/").status == 303


def test_invalid_value_shows_the_error_and_keeps_what_was_typed(env):
    r = post(signed_in(env), "/api/v1/settings/set", key="auth.session_idle_s", value="5")
    assert r.status == 400 and "auth.session_idle_s" in r.text and "Must be from" in r.text
    assert 'value="5"' in r.text
    assert stored_value(env.conn, "auth.session_idle_s") is None


def test_unknown_key_is_404_and_read_only_key_is_400(env):
    client = signed_in(env)
    assert post(client, "/api/v1/settings/set", key="nope", value="1").status == 404
    r = post(client, "/api/v1/settings/set", key="retention.requests_days", value="1")
    assert r.status == 400 and "Backups and Retention" in r.text
    assert post(client, "/api/v1/settings/reset", key="nope").status == 404


def test_confirm_is_required_through_the_page(env):
    client = signed_in(env)
    r = post(client, "/api/v1/settings/set", key="enforcement.mode", value="monitor_only")
    assert r.status == 400 and "confirm" in r.text
    r = post(client, "/api/v1/settings/set", key="enforcement.mode", value="monitor_only", confirm="confirm")
    assert r.status == 303 and stored_value(env.conn, "enforcement.mode") == "monitor_only"


def test_typed_values_are_escaped(env):
    r = post(signed_in(env), "/api/v1/settings/set", key="site.appeal_url", value='"><script>alert(1)</script>')
    assert r.status == 400 and "<script>alert" not in r.text


def test_changes_need_recent_reauthentication(env):
    client = signed_in(env)
    env.clock.now += 400_000
    r = post(client, "/api/v1/settings/set", key="auth.session_idle_s", value="900")
    assert r.status == 403 and stored_value(env.conn, "auth.session_idle_s") is None


def test_changes_need_a_csrf_token(env):
    client = signed_in(env)
    r = client.post("/api/v1/settings/set", form={"key": "auth.session_idle_s", "value": "900"})
    assert r.status == 403 and stored_value(env.conn, "auth.session_idle_s") is None
