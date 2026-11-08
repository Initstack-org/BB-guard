"""Configuration loading (standard library only).

Non-secret settings come from guard.env, secrets from secrets.env (see
docs/ARCHITECTURE.md section 10). Both are plain KEY=VALUE files and are parsed,
never executed. Real environment variables override file values.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


class ConfigError(Exception):
    pass


def parse_env_file(path: str | os.PathLike) -> dict[str, str]:
    """Parse KEY=VALUE lines. Blank lines and lines starting with # are ignored."""
    out: dict[str, str] = {}
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"cannot read {path}: {getattr(exc, 'strerror', None) or type(exc).__name__}") from exc
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ConfigError(f"{path}:{lineno}: expected KEY=VALUE")
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if not key.replace("_", "").isalnum():
            raise ConfigError(f"{path}:{lineno}: bad key name")
        out[key] = value
    return out


def _decode_key(text: str) -> bytes:
    """Accept a hex or base64 encoded key of at least 32 bytes."""
    text = text.strip()
    for decoder in (bytes.fromhex, lambda t: base64.b64decode(t, validate=True)):
        try:
            raw = decoder(text)
        except (ValueError, binascii.Error):
            continue
        if len(raw) >= 32:
            return raw
    raise ConfigError("GUARD_SECRET_KEY must be hex or base64 and decode to at least 32 bytes")


def _is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


_TRUE = ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Config:
    db_path: str
    external_origin: str
    trusted_connectors: tuple[str, ...]
    dashboard_bind: tuple[str, int] = ("127.0.0.1", 8787)
    internal_bind: tuple[str, int] = ("127.0.0.1", 8788)
    export_dir: str = ""
    backup_dir: str = ""
    access_log: str = ""  # Nginx JSON spool file read by ingest (docs/ARCHITECTURE.md section 9)
    secret_key: bytes = field(default=b"", repr=False)

    @property
    def rp_id(self) -> str:
        """WebAuthn RP ID: the dashboard hostname."""
        return urlsplit(self.external_origin).hostname or ""

    @property
    def dashboard_on_lan(self) -> bool:
        """True when the dashboard listens on a non-loopback (private LAN) address."""
        return not _is_loopback_host(self.dashboard_bind[0])


def load_config(env_path: str | None = None, secrets_path: str | None = None,
                environ: dict[str, str] | None = None) -> Config:
    values: dict[str, str] = {}
    if env_path:
        values.update(parse_env_file(env_path))
    if secrets_path:
        values.update(parse_env_file(secrets_path))
    values.update({k: v for k, v in (environ if environ is not None else os.environ).items()
                   if k.startswith("GUARD_")})

    def need(key: str) -> str:
        if not values.get(key):
            raise ConfigError(f"missing required setting {key}")
        return values[key]

    origin = need("GUARD_EXTERNAL_ORIGIN").rstrip("/")
    parts = urlsplit(origin)
    if parts.scheme != "https" or not parts.hostname or parts.path or parts.query:
        raise ConfigError("GUARD_EXTERNAL_ORIGIN must look like https://host (no path)")

    connectors = tuple(c.strip() for c in values.get("GUARD_TRUSTED_CONNECTORS", "").split(",") if c.strip())
    for c in connectors:
        try:
            ipaddress.ip_address(c)
        except ValueError:
            raise ConfigError(f"GUARD_TRUSTED_CONNECTORS: {c!r} is not an IP address") from None
    allow_lan = values.get("GUARD_DASHBOARD_ALLOW_LAN", "").strip().lower() in _TRUE

    def bind(key: str, default: tuple[str, int], *, lan_ok: bool = False) -> tuple[str, int]:
        raw = values.get(key)
        if not raw:
            return default
        host, _, port = raw.rpartition(":")
        if not port.isdigit() or not host:
            raise ConfigError(f"{key} must be a loopback address and port")
        if not 1 <= int(port) <= 65535:
            raise ConfigError(f"{key}: port must be between 1 and 65535")
        if _is_loopback_host(host):
            return host, int(port)
        if not lan_ok:
            raise ConfigError(f"{key} must be a loopback address and port")
        # Opt-in LAN listener (the tunnel connector reaches Guard directly). Only a specific private
        # address: never 0.0.0.0, never a public address, never a name.
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            raise ConfigError(f"{key} must be a loopback address or a specific private IP address") from None
        if ip.is_unspecified or ip.is_multicast or not ip.is_private:
            raise ConfigError(f"{key} must be a specific private IP address (not 0.0.0.0, not public)")
        if not connectors:
            raise ConfigError(f"{key}: listening on the LAN needs GUARD_TRUSTED_CONNECTORS (the only "
                              "addresses allowed to connect)")
        return host, int(port)

    access_log = values.get("GUARD_ACCESS_LOG", "")
    if access_log and (not os.path.isabs(access_log) or "\0" in access_log):
        raise ConfigError("GUARD_ACCESS_LOG must be an absolute file path")

    return Config(
        db_path=need("GUARD_DB_PATH"),
        external_origin=origin,
        trusted_connectors=connectors,
        dashboard_bind=bind("GUARD_DASHBOARD_BIND", ("127.0.0.1", 8787), lan_ok=allow_lan),
        internal_bind=bind("GUARD_INTERNAL_BIND", ("127.0.0.1", 8788)),
        export_dir=values.get("GUARD_EXPORT_DIR", ""),
        backup_dir=values.get("GUARD_BACKUP_DIR", ""),
        access_log=access_log,
        secret_key=_decode_key(need("GUARD_SECRET_KEY")),
    )
