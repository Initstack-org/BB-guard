"""Configuration loading (standard library only).

Non-secret settings come from guard.env, secrets from secrets.env (see
docs/ARCHITECTURE.md section 10). Both are plain KEY=VALUE files and are parsed,
never executed. Real environment variables override file values.
"""

from __future__ import annotations

import base64
import binascii
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


@dataclass(frozen=True)
class Config:
    db_path: str
    external_origin: str
    trusted_connectors: tuple[str, ...]
    dashboard_bind: tuple[str, int] = ("127.0.0.1", 8787)
    internal_bind: tuple[str, int] = ("127.0.0.1", 8788)
    export_dir: str = ""
    backup_dir: str = ""
    secret_key: bytes = field(default=b"", repr=False)

    @property
    def rp_id(self) -> str:
        """WebAuthn RP ID: the dashboard hostname."""
        return urlsplit(self.external_origin).hostname or ""


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

    def bind(key: str, default: tuple[str, int]) -> tuple[str, int]:
        raw = values.get(key)
        if not raw:
            return default
        host, _, port = raw.rpartition(":")
        if host not in ("127.0.0.1", "::1", "localhost") or not port.isdigit():
            raise ConfigError(f"{key} must be a loopback address and port")
        if not 1 <= int(port) <= 65535:
            raise ConfigError(f"{key}: port must be between 1 and 65535")
        return host, int(port)

    return Config(
        db_path=need("GUARD_DB_PATH"),
        external_origin=origin,
        trusted_connectors=connectors,
        dashboard_bind=bind("GUARD_DASHBOARD_BIND", ("127.0.0.1", 8787)),
        internal_bind=bind("GUARD_INTERNAL_BIND", ("127.0.0.1", 8788)),
        export_dir=values.get("GUARD_EXPORT_DIR", ""),
        backup_dir=values.get("GUARD_BACKUP_DIR", ""),
        secret_key=_decode_key(need("GUARD_SECRET_KEY")),
    )
