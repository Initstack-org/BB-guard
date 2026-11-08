import base64

import pytest

from guard.config import ConfigError, load_config, parse_env_file

KEY = "ab" * 32  # 32 bytes as hex


def env(**over):
    values = {"GUARD_DB_PATH": "/var/lib/guard/g.db", "GUARD_EXTERNAL_ORIGIN": "https://guard.example.org",
              "GUARD_SECRET_KEY": KEY}
    values.update(over)
    return {k: v for k, v in values.items() if v is not None}


def test_minimal_config_uses_defaults():
    cfg = load_config(environ=env())
    assert cfg.dashboard_bind == ("127.0.0.1", 8787) and cfg.internal_bind == ("127.0.0.1", 8788)
    assert cfg.rp_id == "guard.example.org" and cfg.trusted_connectors == () and cfg.secret_key == bytes.fromhex(KEY)


def test_secret_key_is_not_shown_in_repr():
    assert KEY not in repr(load_config(environ=env()))


@pytest.mark.parametrize("missing", ["GUARD_DB_PATH", "GUARD_EXTERNAL_ORIGIN", "GUARD_SECRET_KEY"])
def test_missing_required_setting(missing):
    with pytest.raises(ConfigError, match=missing):
        load_config(environ=env(**{missing: None}))


@pytest.mark.parametrize("origin", ["http://guard.example.org", "https://guard.example.org/path",
                                    "https://guard.example.org?x=1", "guard.example.org", "https://"])
def test_bad_origins(origin):
    with pytest.raises(ConfigError):
        load_config(environ=env(GUARD_EXTERNAL_ORIGIN=origin))


def test_origin_trailing_slash_is_stripped():
    assert load_config(environ=env(GUARD_EXTERNAL_ORIGIN="https://g.example.org/")).external_origin == "https://g.example.org"


def test_secret_key_accepts_base64_and_rejects_short_or_junk():
    assert load_config(environ=env(GUARD_SECRET_KEY=base64.b64encode(b"k" * 40).decode())).secret_key == b"k" * 40
    for bad in ("abcd", "!!" * 40, base64.b64encode(b"short").decode()):
        with pytest.raises(ConfigError, match="SECRET_KEY"):
            load_config(environ=env(GUARD_SECRET_KEY=bad))


@pytest.mark.parametrize("bind", ["0.0.0.0:8787", "192.168.1.5:8787", "example.org:80", "127.0.0.1:abc", "8787"])
def test_binds_must_be_loopback_with_a_numeric_port(bind):
    with pytest.raises(ConfigError, match="loopback"):
        load_config(environ=env(GUARD_DASHBOARD_BIND=bind))


@pytest.mark.parametrize("bind", ["127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:99999"])
def test_port_must_be_in_range(bind):
    with pytest.raises(ConfigError, match="port"):
        load_config(environ=env(GUARD_INTERNAL_BIND=bind))


def test_loopback_binds_accepted():
    cfg = load_config(environ=env(GUARD_DASHBOARD_BIND="::1:9000", GUARD_INTERNAL_BIND="localhost:9001"))
    assert cfg.dashboard_bind == ("::1", 9000) and cfg.internal_bind == ("localhost", 9001)


def test_trusted_connectors_are_split_and_trimmed():
    cfg = load_config(environ=env(GUARD_TRUSTED_CONNECTORS=" 192.168.1.148 , 10.0.0.2,,"))
    assert cfg.trusted_connectors == ("192.168.1.148", "10.0.0.2")


def test_files_are_parsed_and_environment_overrides_them(tmp_path):
    f = tmp_path / "guard.env"
    f.write_text('# comment\n\nGUARD_DB_PATH="/a/b.db"\nGUARD_EXTERNAL_ORIGIN=https://one.example.org\n')
    s = tmp_path / "secrets.env"
    s.write_text(f"GUARD_SECRET_KEY={KEY}\n")
    cfg = load_config(str(f), str(s), environ={})
    assert cfg.db_path == "/a/b.db" and cfg.external_origin == "https://one.example.org"
    cfg = load_config(str(f), str(s), environ={"GUARD_DB_PATH": "/other.db", "NOT_GUARD": "x"})
    assert cfg.db_path == "/other.db"


def test_env_file_is_parsed_not_executed(tmp_path):
    f = tmp_path / "x.env"
    f.write_text("GUARD_A=$(echo hi)\nGUARD_B=`id`\n")
    assert parse_env_file(f) == {"GUARD_A": "$(echo hi)", "GUARD_B": "`id`"}


@pytest.mark.parametrize("line", ["no equals sign", "=novalue", "BAD KEY=1", "A-B=1"])
def test_bad_env_lines(tmp_path, line):
    f = tmp_path / "x.env"
    f.write_text(line + "\n")
    with pytest.raises(ConfigError):
        parse_env_file(f)
