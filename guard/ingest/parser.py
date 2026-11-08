"""Parse one Nginx JSON access-log line into a `Record` (docs/SUBSYSTEMS.md section 2).

Standard library only, no I/O. The log format is `guard_json` in docs/ARCHITECTURE.md section 9. The
format contains no cookies, authorization headers or request bodies, so none can reach this code; the
fields that can carry secrets (the request URI) are redacted by `normalize`.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass

from guard.ingest import normalize

MAX_LINE_BYTES = 64 * 1024
_MAX_COUNTER = 10**15

DECISIONS = {
    "allowed": "allowed", "allow": "allowed",
    "denied": "denied", "deny": "denied",
    "overridden": "overridden",
    "monitored": "monitored",
}
DETECTIONS = frozenset({"manual_ip_block", "url_rule", "reputation"})


class ParseError(Exception):
    """A log line that cannot be used. The message is short and never contains the line itself."""


@dataclass(frozen=True)
class Record:
    request_id: bytes  # 16 bytes
    ts_ms: int
    ip: str
    method: str
    host: str
    path: str
    path_truncated: bool
    query: str | None
    status: int
    bytes_in: int
    bytes_out: int
    duration_ms: int
    user_agent: str | None
    referrer: str | None
    mybb_uid: int | None
    mybb_username: str | None
    managed: bool
    outcome: str
    detection: str | None
    rule_ref: str | None
    reason: str | None
    peer_mismatch: bool  # the stored IP is the peer address because the peer is not a trusted connector


def parse_trusted(items) -> tuple:
    """Turn the configured trusted connectors (addresses or CIDR ranges) into network objects."""
    nets = []
    for item in items:
        try:
            nets.append(ipaddress.ip_network(str(item).strip(), strict=False))
        except ValueError as exc:
            raise ValueError(f"bad trusted connector {item!r}") from exc
    return tuple(nets)


def _is_trusted(ip_text: str, trusted: tuple) -> bool:
    ip = ipaddress.ip_address(ip_text)
    return any(ip.version == net.version and ip in net for net in trusted)


def _field(obj: dict, key: str) -> str:
    value = obj.get(key, "")
    if isinstance(value, bool) or value is None:
        return ""
    if isinstance(value, (int, float)):
        return str(value)
    return value if isinstance(value, str) else ""


def _count(text: str) -> int:
    """A non-negative integer from a log field; anything unusable is 0."""
    try:
        number = int(text.strip())
    except ValueError:
        try:
            number = int(float(text.strip()))
        except ValueError:
            return 0
    return min(max(number, 0), _MAX_COUNTER)


def _timestamp_ms(text: str) -> int:
    try:
        seconds = float(text)
    except ValueError as exc:
        raise ParseError("bad timestamp") from exc
    if not 0 < seconds < 32503680000:  # before the year 3000
        raise ParseError("timestamp out of range")
    return round(seconds * 1000)


def _duration_ms(text: str) -> int:
    try:
        seconds = float(text)
    except ValueError:
        return 0
    if seconds != seconds or seconds < 0:  # NaN or negative
        return 0
    return min(round(seconds * 1000), 10**9)


def _request_id(text: str, raw: bytes) -> bytes:
    text = text.strip()
    if len(text) == 32:
        try:
            return bytes.fromhex(text)
        except ValueError:
            pass
    # No usable id: a digest of the line, so replaying the same line still deduplicates.
    return hashlib.blake2b(raw, digest_size=16).digest()


def _status(text: str) -> int:
    try:
        value = int(text.strip())
    except ValueError:
        return 0
    return value if 0 <= value <= 999 else 0


def parse_line(raw: bytes, *, trusted: tuple, managed_hosts: frozenset) -> Record:
    """Parse one line (without its trailing newline). Raises ParseError when it is unusable.

    `trusted` is the result of `parse_trusted`; `managed_hosts` is the lower-case `site.hosts` set.
    """
    if len(raw) > MAX_LINE_BYTES:
        raise ParseError("line too long")
    try:
        obj = json.loads(raw)
    except (ValueError, RecursionError) as exc:  # includes UnicodeDecodeError and JSONDecodeError
        raise ParseError("not valid JSON") from exc
    if not isinstance(obj, dict):
        raise ParseError("not a JSON object")

    ts_ms = _timestamp_ms(_field(obj, "t"))

    # Trusted client IP (docs/ARCHITECTURE.md section 8, SUBSYSTEMS 2.4). The log carries both the
    # address after Nginx's real_ip handling ("ip") and the real TCP peer ("peer"). Only a trusted
    # connector may have set "ip"; for any other peer the peer address is what gets stored.
    try:
        ip = normalize.canonical_ip(_field(obj, "ip"))
    except ValueError as exc:
        raise ParseError("bad client ip") from exc
    mismatch = False
    peer_text = _field(obj, "peer").strip()
    if peer_text:
        try:
            peer = normalize.canonical_ip(peer_text)
        except ValueError as exc:
            raise ParseError("bad peer ip") from exc
        if not _is_trusted(peer, trusted):
            mismatch = peer != ip
            ip = peer

    uri = normalize.normalize_uri(_field(obj, "u"))
    host = normalize.normalize_host(_field(obj, "h"))

    # Outcome (SUBSYSTEMS 2.5). The decision Guard returned is copied, never re-derived. For denied
    # requests Nginx may have lost the g* variables on the internal redirect, so b* fills the gaps.
    decision = _field(obj, "gd").strip().lower() or _field(obj, "bd").strip().lower()
    outcome = DECISIONS.get(decision, "unchecked")
    detection = (_field(obj, "gt").strip().lower() or _field(obj, "bt").strip().lower())
    detection = detection if detection in DETECTIONS else None
    rule_ref = normalize.clean_text(_field(obj, "gr") or _field(obj, "br"), 64).strip() or None
    reason = normalize.clean_text(_field(obj, "gx") or _field(obj, "bx"), 200).strip() or None

    uid, username = normalize.clean_mybb_identity(_field(obj, "uid").strip(), _field(obj, "un"))

    return Record(
        request_id=_request_id(_field(obj, "id"), raw),
        ts_ms=ts_ms,
        ip=ip,
        method=normalize.normalize_method(_field(obj, "m")),
        host=host,
        path=uri.path,
        path_truncated=uri.path_truncated,
        query=uri.query,
        status=_status(_field(obj, "s")),
        bytes_in=_count(_field(obj, "bi")),
        bytes_out=_count(_field(obj, "bo")),
        duration_ms=_duration_ms(_field(obj, "d")),
        user_agent=normalize.clean_user_agent(_field(obj, "ua")),
        referrer=normalize.clean_referrer(_field(obj, "ref")),
        mybb_uid=uid,
        mybb_username=username,
        managed=host in managed_hosts,
        outcome=outcome,
        detection=detection,
        rule_ref=rule_ref,
        reason=reason,
        peer_mismatch=mismatch,
    )
