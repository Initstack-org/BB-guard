"""IPLogs client and the `ip_intel` cache (docs/SUBSYSTEMS.md sections 3.1 and 3.2).

Rules (GOAL.md): the URL is a constant (no user-supplied URL is ever fetched); a lookup is never made
per HTTP request, only per distinct address and TTL; an error is "unknown", never evidence of malice;
a failed lookup never overwrites good data; private and reserved addresses are never sent out;
latitude and longitude are discarded.

UNVERIFIED (PROGRESS.md): IPLogs authentication, rate limits and the response shape were not checked
against the official documentation. The token is optional and sent as a bearer token; the parser reads
the fields named in the design at the top level and `ip_info` and ignores everything else. If the real
response differs, `parse_response` fails closed to an error (never a guess), which means "unknown".

The network is injected (`fetch`), so everything here is testable without a connection.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
import time
import urllib.error
import urllib.request
from collections import deque
from typing import Callable

from ..ingest.normalize import canonical_ip
from .policy import Intel

IPLOGS_URL = "https://iplogs.com/v1/check"
MAX_RESPONSE_BYTES = 64 * 1024
TIMEOUT_S = 5.0
DEFAULT_RETRY_AFTER_S = 60

# fetch(body, headers, timeout_s) -> (http_status, response_headers, body_bytes). May raise OSError.
Fetch = Callable[[bytes, dict, float], tuple]

_BOOL_FIELDS = ("is_vpn", "is_proxy", "is_tor", "is_relay", "is_hosting", "is_crawler")
_INFO_FIELDS = (("asn", "asn"), ("org", "org"), ("isp", "isp"), ("country", "country"), ("prefix", "prefix"))


class IntelError(Exception):
    def __init__(self, kind: str, message: str = "", retry_after_s: int = 0):
        super().__init__(message or kind)
        self.kind = kind
        self.retry_after_s = retry_after_s


def is_public(ip_text: str) -> bool:
    """True for a globally routable unicast address; only those are ever sent to IPLogs."""
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    return bool(ip.is_global) and not ip.is_multicast


def default_fetch(token: str = "") -> Fetch:
    def fetch(body: bytes, headers: dict, timeout_s: float):
        hdrs = dict(headers)
        if token:
            hdrs["Authorization"] = "Bearer " + token
        req = urllib.request.Request(IPLOGS_URL, data=body, headers=hdrs, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310 - constant https URL
                return resp.status, dict(resp.headers), resp.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers or {}), exc.read(MAX_RESPONSE_BYTES + 1)
    return fetch


class RateLimiter:
    """At most `per_minute` lookups in any 60 seconds, and a global pause after a 429."""

    def __init__(self, per_minute: int):
        self.per_minute = max(1, per_minute)
        self._stamps: deque = deque()
        self._paused_until = 0.0

    def pause_until(self, when_s: float) -> None:
        self._paused_until = max(self._paused_until, when_s)

    def allow(self, now_s: float) -> bool:
        if now_s < self._paused_until:
            return False
        while self._stamps and now_s - self._stamps[0] >= 60:
            self._stamps.popleft()
        if len(self._stamps) >= self.per_minute:
            return False
        self._stamps.append(now_s)
        return True


# ---- parsing ---------------------------------------------------------------------------------

def _text(value, limit: int) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise IntelError("bad_response", "unexpected field type")
    text = str(value).strip()
    if any(ord(c) < 32 for c in text):
        raise IntelError("bad_response", "control character in a field")
    return text[:limit] or None


def parse_response(payload: object) -> dict:
    """Validate an IPLogs answer and return the `ip_intel` columns. Raises IntelError('bad_response')."""
    if not isinstance(payload, dict):
        raise IntelError("bad_response", "not a JSON object")
    out: dict = {}
    for name in _BOOL_FIELDS:
        value = payload.get(name)
        if value is not None and not isinstance(value, bool):
            raise IntelError("bad_response", f"{name} is not a boolean")
        out[name] = None if value is None else int(value)
    score = payload.get("score")
    if score is not None and (isinstance(score, bool) or not isinstance(score, (int, float))):
        raise IntelError("bad_response", "score is not a number")
    out["score"] = None if score is None else float(score)
    out["verdict"] = _text(payload.get("verdict"), 64)
    out["confidence"] = _text(payload.get("confidence"), 64)
    out["reputation"] = _text(payload.get("reputation"), 64)
    info = payload.get("ip_info")
    if info is not None and not isinstance(info, dict):
        raise IntelError("bad_response", "ip_info is not an object")
    info = info or {}
    for column, key in _INFO_FIELDS:
        out[column] = _text(info.get(key), 200)  # latitude / longitude are never read
    signals = payload.get("signals")
    encoded = None
    if signals is not None:
        if not isinstance(signals, (list, dict)):
            raise IntelError("bad_response", "signals is not a list or object")
        encoded = json.dumps(signals, separators=(",", ":"), ensure_ascii=False)
        if len(encoded) > 4096:
            encoded = None  # too large to keep; the flags above are what decisions use
    out["signals"] = encoded
    return out


def _call(fetch: Fetch, ip: str) -> dict:
    body = json.dumps({"ip": ip}).encode()
    headers = {"Content-Type": "application/json", "Accept": "application/json",
               "User-Agent": "initstack-guard"}
    last: Exception | None = None
    for attempt in range(2):  # one retry, only for connection-level errors
        try:
            status, resp_headers, data = fetch(body, headers, TIMEOUT_S)
            break
        except (OSError, TimeoutError) as exc:
            last = exc
            time.sleep(0.2 + 0.3 * attempt)
    else:
        raise IntelError("network", type(last).__name__)
    if status == 429:
        retry = DEFAULT_RETRY_AFTER_S
        for key, value in resp_headers.items():
            if str(key).lower() == "retry-after" and str(value).isdigit():
                retry = min(int(value), 86400)
        raise IntelError("rate_limit", "429", retry_after_s=retry)
    if status >= 500:
        raise IntelError("server_error", str(status))
    if status != 200:
        raise IntelError("http_error", str(status))
    if len(data) > MAX_RESPONSE_BYTES:
        raise IntelError("bad_response", "response too large")
    try:
        payload = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise IntelError("bad_response", "not JSON") from None
    return parse_response(payload)


# ---- cache -----------------------------------------------------------------------------------

_COLUMNS = ("verdict", "score", "is_vpn", "is_proxy", "is_tor", "is_relay", "is_hosting", "is_crawler",
            "confidence", "reputation", "asn", "org", "isp", "country", "prefix", "signals")


def _store_ok(conn: sqlite3.Connection, ip: str, data: dict, now_ms: int, ttl_s: int) -> None:
    cols = ", ".join(_COLUMNS)
    marks = ", ".join("?" for _ in _COLUMNS)
    updates = ", ".join(f"{c} = excluded.{c}" for c in _COLUMNS)
    conn.execute(
        f"INSERT INTO ip_intel(ip, status, data_fetched_ms, expires_ms, retry_after_ms, {cols},"
        f" error_kind, error_ms, error_count) VALUES (?, 'ok', ?, ?, 0, {marks}, NULL, NULL, 0)"
        f" ON CONFLICT(ip) DO UPDATE SET status = 'ok', data_fetched_ms = excluded.data_fetched_ms,"
        f" expires_ms = excluded.expires_ms, retry_after_ms = 0, {updates}, error_kind = NULL,"
        f" error_ms = NULL, error_count = 0",
        (ip, now_ms, now_ms + ttl_s * 1000, *(data[c] for c in _COLUMNS)))


def _store_error(conn: sqlite3.Connection, ip: str, err: IntelError, now_ms: int, retry_s: int) -> None:
    retry_ms = now_ms + max(retry_s, err.retry_after_s) * 1000
    # A failed lookup never touches good data: only the error and retry columns change.
    conn.execute(
        "INSERT INTO ip_intel(ip, status, retry_after_ms, error_kind, error_ms, error_count)"
        " VALUES (?, 'error', ?, ?, ?, 1)"
        " ON CONFLICT(ip) DO UPDATE SET retry_after_ms = excluded.retry_after_ms,"
        " error_kind = excluded.error_kind, error_ms = excluded.error_ms,"
        " error_count = ip_intel.error_count + 1",
        (ip, retry_ms, err.kind[:32], now_ms))


def _store_skipped(conn: sqlite3.Connection, ip: str) -> None:
    conn.execute("INSERT INTO ip_intel(ip, status) VALUES (?, 'skipped')"
                 " ON CONFLICT(ip) DO NOTHING", (ip,))


def lookup(conn: sqlite3.Connection, ip_text: str, now_ms: int, *, fetch: Fetch,
           rate: RateLimiter | None, ttl_ok_s: int, ttl_error_s: int, force: bool = False) -> str:
    """Refresh one address if the cache says it is due. Returns what happened:
    cached | skipped | backoff | rate_limited | ok | error. Never raises on network or parse trouble."""
    ip = canonical_ip(ip_text)
    if not is_public(ip):
        _store_skipped(conn, ip)
        return "skipped"
    row = conn.execute("SELECT status, expires_ms, retry_after_ms FROM ip_intel WHERE ip = ?",
                       (ip,)).fetchone()
    if row is not None and not force:
        if row["status"] == "ok" and (row["expires_ms"] or 0) > now_ms:
            return "cached"
        if row["retry_after_ms"] > now_ms:
            return "backoff"
    if rate is not None and not rate.allow(now_ms / 1000):
        return "rate_limited"
    try:
        data = _call(fetch, ip)
    except IntelError as err:
        if err.kind == "rate_limit" and rate is not None:
            rate.pause_until(now_ms / 1000 + err.retry_after_s)
        _store_error(conn, ip, err, now_ms, ttl_error_s)
        return "error"
    _store_ok(conn, ip, data, now_ms, ttl_ok_s)
    return "ok"


def _flag(value) -> bool | None:
    return None if value is None else bool(value)


def load_intel(conn: sqlite3.Connection, ip_text: str, now_ms: int, stale_grace_s: int) -> Intel:
    """The cached knowledge about an address, as the policy sees it. Missing row -> status "missing"."""
    try:
        ip = canonical_ip(ip_text)
    except ValueError:
        return Intel()
    row = conn.execute("SELECT * FROM ip_intel WHERE ip = ?", (ip,)).fetchone()
    if row is None:
        return Intel()
    if row["status"] != "ok":
        return Intel(status=row["status"])
    expired = (row["expires_ms"] or 0) + stale_grace_s * 1000 < now_ms
    return Intel(status="ok", is_vpn=_flag(row["is_vpn"]), is_proxy=_flag(row["is_proxy"]),
                 is_tor=_flag(row["is_tor"]), is_relay=_flag(row["is_relay"]),
                 is_hosting=_flag(row["is_hosting"]), is_crawler=_flag(row["is_crawler"]),
                 verdict=row["verdict"], confidence=row["confidence"], expired_beyond_grace=expired)


def needs_lookup(conn: sqlite3.Connection, ip_text: str, now_ms: int) -> bool:
    """True when a lookup would be worth making (no usable fresh data and not backing off)."""
    try:
        ip = canonical_ip(ip_text)
    except ValueError:
        return False
    if not is_public(ip):
        return False
    row = conn.execute("SELECT status, expires_ms, retry_after_ms FROM ip_intel WHERE ip = ?",
                       (ip,)).fetchone()
    if row is None:
        return True
    if row["status"] == "ok" and (row["expires_ms"] or 0) > now_ms:
        return False
    return row["retry_after_ms"] <= now_ms
