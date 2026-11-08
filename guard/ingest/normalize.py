"""Normalization and redaction of one access-log record (docs/SUBSYSTEMS.md section 2.3).

Pure standard-library code with no I/O, so it can be tested without the web stack. Everything here is
defensive: the input is attacker-controlled (paths, query strings, User-Agent strings), and anything
that survives into the database must be bounded, free of control characters, and free of secrets.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import unquote_plus, unquote_to_bytes

PATH_MAX = 2048
QUERY_MAX = 1024
UA_MAX = 512
REFERRER_MAX = 1024
HOST_MAX = 255
USERNAME_MAX = 120
EXCERPT_MAX = 200
REDACTED = "[redacted]"

METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT"})

# Case-insensitive substrings. A query key containing any of these has its value replaced.
# Over-matching (for example "sidebar" because of "sid") is deliberate: redacting too much is safe.
SENSITIVE_KEY_PARTS = (
    "pass", "pwd", "token", "key", "secret", "session", "sid", "auth", "code",
    "signature", "csrf", "my_post_key",
)

# A value of 32 or more characters made only of hex/base64/base64url characters looks like a secret.
_SECRETISH = re.compile(r"^[A-Za-z0-9+/=_\-]{32,}$")
# Used on free text (bad log lines), where there is no key/value structure to rely on.
_SECRETISH_RUN = re.compile(r"[A-Za-z0-9+/=_\-]{32,}")
_SENSITIVE_PAIR = re.compile(
    r"(?i)([A-Za-z0-9_.\-]*(?:" + "|".join(SENSITIVE_KEY_PARTS) + r")[A-Za-z0-9_.\-]*)=[^&\s\"',;]*")

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _looks_secret(text: str) -> bool:
    """32+ hex/base64-style characters that include a digit (so a long plain-letter slug is kept)."""
    return bool(_SECRETISH.match(text)) and any(ch.isdigit() for ch in text)


def strip_control(text: str) -> str:
    """Replace control characters (including NUL, CR and LF) with U+FFFD."""
    return _CONTROL.sub("\ufffd", text)


def clean_text(value: object, limit: int) -> str:
    """A bounded, control-free string. Non-strings become the empty string."""
    if not isinstance(value, str):
        return ""
    return strip_control(value)[:limit]


def canonical_ip(text: str) -> str:
    """Canonical text form of an IP address. IPv4-mapped IPv6 is unmapped; a scope id is dropped.

    Raises ValueError for anything that is not an IP address.
    """
    ip = ipaddress.ip_address(text.strip().split("%", 1)[0])
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.compressed


def normalize_host(value: str) -> str:
    """Lower-case, strip the port and a trailing dot. Never empty (the urls table requires a host)."""
    host = clean_text(value, HOST_MAX + 16).strip().lower()
    if host.startswith("["):  # IPv6 literal, possibly with a port: [::1]:443
        end = host.find("]")
        host = host[1:end] if end > 0 else host.lstrip("[")
    elif host.count(":") == 1:  # name:port or ipv4:port
        host = host.split(":", 1)[0]
    host = host.rstrip(".")[:HOST_MAX]
    return host or "_"


def normalize_method(value: str) -> str:
    method = clean_text(value, 16).strip().upper()
    return method if method in METHODS else "OTHER"


@dataclass(frozen=True)
class NormalizedUri:
    path: str
    query: str | None
    path_truncated: bool


def _resolve_segments(path: str) -> str:
    """Collapse repeated slashes and resolve "." and ".." (never climbing above the root)."""
    trailing = path.endswith("/") or path.endswith("/.") or path.endswith("/..")
    out: list[str] = []
    for seg in path.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if out:
                out.pop()
            continue
        out.append(seg)
    resolved = "/" + "/".join(out)
    if trailing and not resolved.endswith("/"):
        resolved += "/"
    return resolved


def normalize_path(raw_path: str) -> tuple[str, bool]:
    """Percent-decode once, then clean. Returns (path, truncated). Always starts with "/"."""
    decoded = unquote_to_bytes(raw_path).decode("utf-8", errors="replace")
    decoded = strip_control(decoded).replace("\\", "/")
    path = _resolve_segments(decoded)
    if len(path) > PATH_MAX:
        return path[:PATH_MAX], True
    return path, False


def redact_query(raw_query: str) -> str | None:
    """Redact sensitive values in a raw query string; cap the result. None when there is no query."""
    if not raw_query:
        return None
    parts: list[str] = []
    for part in raw_query.split("&"):
        if not part:
            continue
        key, sep, value = part.partition("=")
        key_decoded = unquote_plus(key, errors="replace").lower()
        if sep and any(frag in key_decoded for frag in SENSITIVE_KEY_PARTS):
            parts.append(f"{key}={REDACTED}")
        elif sep and _looks_secret(unquote_plus(value, errors="replace")):
            parts.append(f"{key}={REDACTED}")
        elif not sep and _looks_secret(key_decoded):
            parts.append(REDACTED)
        else:
            parts.append(part)
    query = strip_control("&".join(parts))[:QUERY_MAX]
    return query or None


def normalize_uri(raw_uri: str) -> NormalizedUri:
    """Split a raw request URI into a normalized path and a redacted query."""
    uri = raw_uri.split("#", 1)[0]
    if "://" in uri.split("?", 1)[0]:  # absolute-form request target: keep only the path and query
        rest = uri.split("://", 1)[1]
        slash = rest.find("/")
        uri = rest[slash:] if slash >= 0 else "/"
    raw_path, _, raw_query = uri.partition("?")
    path, truncated = normalize_path(raw_path)
    return NormalizedUri(path=path, query=redact_query(raw_query), path_truncated=truncated)


def clean_user_agent(value: object) -> str | None:
    text = clean_text(value, UA_MAX).strip()
    return None if text in ("", "-") else text


def clean_referrer(value: object) -> str | None:
    """The referrer with its query string and fragment dropped (SUBSYSTEMS 2.3)."""
    text = clean_text(value, REFERRER_MAX + 512).strip()
    if text in ("", "-"):
        return None
    text = text.split("#", 1)[0].split("?", 1)[0][:REFERRER_MAX]
    return text or None


def clean_mybb_identity(uid: object, username: object) -> tuple[int | None, str | None]:
    """A MyBB identity is used only when the uid is a positive integer and the name is non-empty."""
    if not isinstance(uid, str) or not uid.isascii() or not uid.isdigit() or len(uid) > 10:
        return None, None
    number = int(uid)
    name = clean_text(username, USERNAME_MAX).strip()
    if number <= 0 or not name:
        return None, None
    return number, name


def safe_excerpt(raw: bytes, limit: int = EXCERPT_MAX) -> str:
    """A short, redacted excerpt of a malformed log line for the ingest error ring.

    Redaction happens on a bounded prefix before the final cut, so a secret straddling the cut cannot
    leak half of itself.
    """
    text = strip_control(raw[:2000].decode("utf-8", errors="replace"))
    text = _SENSITIVE_PAIR.sub(lambda m: m.group(1) + "=" + REDACTED, text)
    text = _SECRETISH_RUN.sub(REDACTED, text)
    return text[:limit]
