"""CSRF tokens and Origin checks (docs/SUBSYSTEMS.md section 7.2).

The token for a signed-in session is HMAC(secret_key, "csrf-v1:" + session token hash), so it needs
no storage. Sign-in forms use a token derived from a random pre-session cookie value instead.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from urllib.parse import urlsplit


def _mac(key: bytes, domain: bytes, value: bytes) -> str:
    digest = hmac.new(key, domain + value, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def session_token(key: bytes, session_token_hash: bytes) -> str:
    return _mac(key, b"csrf-v1:", session_token_hash)


def pre_session_token(key: bytes, pre_cookie_value: str) -> str:
    return _mac(key, b"csrf-pre-v1:", pre_cookie_value.encode("utf-8"))


def verify(expected: str, supplied: str | None) -> bool:
    if not supplied:
        return False
    return hmac.compare_digest(expected.encode("ascii"), supplied.encode("utf-8", "replace"))


def _origin_of(url: str) -> str | None:
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}".lower()


def origin_ok(allowed_origin: str, origin_header: str | None, referer_header: str | None) -> bool:
    """State-changing requests must carry an Origin (or, failing that, a Referer) that matches
    the configured external origin exactly. Neither header present means reject."""
    allowed = allowed_origin.lower().rstrip("/")
    if origin_header is not None:
        return origin_header.lower().rstrip("/") == allowed
    if referer_header:
        return _origin_of(referer_header) == allowed
    return False


def export_fetch_ok(allowed_origin: str, sec_fetch_site: str | None, origin_header: str | None) -> bool:
    """GET exports are not CSRF-token protected, so they must be same-origin or user-initiated
    (docs/API.md section 7.6)."""
    if sec_fetch_site is not None:
        return sec_fetch_site in ("same-origin", "none")
    if origin_header is not None:
        return origin_header.lower().rstrip("/") == allowed_origin.lower().rstrip("/")
    return False
