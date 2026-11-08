"""URL access rule matching (docs/SUBSYSTEMS.md section 4). Pure: standard library plus the ingest
normalizer, no I/O.

Safety properties (GOAL.md F):
- the pattern and the request path go through the same normalizer as ingest, so they are comparable;
- a prefix matches on path-segment boundaries (`/private` matches `/private` and `/private/x`, never
  `/privateer`); there is no substring or regex matching;
- a trailing slash never changes a match (`/a` and `/a/` are the same path);
- a deny that would cover the whole site, or a protected path, is rejected when the rule is written;
- resolution is deterministic: the same rules, address and URL always give the same winner.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from .ingest.normalize import PATH_MAX, SENSITIVE_KEY_PARTS, canonical_ip, normalize_path

MAX_QUERY_PAIRS = 10
MAX_QUERY_JSON = 1024


class RuleError(ValueError):
    """A rejected rule or target; the message is safe to show to an admin."""


@dataclass(frozen=True)
class Rule:
    id: int
    pattern: str
    match_type: str              # exact | prefix
    action: str                  # allow | deny
    scope_ip: str | None = None
    priority: int = 100
    query_match: tuple = ()      # ((key, value), ...) all required, sorted
    enabled: bool = True
    expires_ms: int | None = None


def trim(path: str) -> str:
    """Canonical comparison form: no trailing slash except for the root."""
    return path.rstrip("/") or "/"


def segment_count(pattern: str) -> int:
    return len([s for s in pattern.split("/") if s])


def _control(text: str) -> bool:
    return any(ord(c) < 32 or ord(c) == 127 for c in text)


def parse_target(text: str, managed_hosts) -> tuple[str, dict | None]:
    """An admin-entered URL or path -> (normalized pattern, required query pairs or None).

    A full URL must be http(s) on a managed host. Query values for sensitive-looking keys are refused so
    that no secret is ever stored in a rule.
    """
    text = (text or "").strip()
    if not text:
        raise RuleError("Enter a URL or a path.")
    if len(text) > PATH_MAX + 1024 or _control(text):
        raise RuleError("That URL is too long or contains control characters.")
    text = text.split("#", 1)[0]
    if "://" in text.split("?", 1)[0]:
        parts = urlsplit(text)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise RuleError("Only http and https URLs are accepted.")
        host = parts.hostname.lower().rstrip(".")
        if host not in {h.lower() for h in managed_hosts}:
            raise RuleError(f"{host[:100]} is not a host Guard manages (see General Settings, site.hosts).")
        raw_path, raw_query = parts.path or "/", parts.query
    else:
        if not text.startswith("/") or text.startswith("//"):
            raise RuleError("A path must start with a single /, or enter a full URL.")
        raw_path, _, raw_query = text.partition("?")
    path, truncated = normalize_path(raw_path)
    if truncated:
        raise RuleError("That path is too long.")
    query = None
    if raw_query:
        try:
            pairs = parse_qsl(raw_query, keep_blank_values=True, max_num_fields=MAX_QUERY_PAIRS)
        except ValueError:
            raise RuleError("Too many query parameters.") from None
        keys = [k for k, _ in pairs]
        if len(set(keys)) != len(keys):
            raise RuleError("Each query parameter may appear only once in a rule.")
        for key in keys:
            if not key or any(frag in key.lower() for frag in SENSITIVE_KEY_PARTS):
                raise RuleError(f"The query parameter '{key[:40]}' looks sensitive and cannot be used in a rule.")
        query = dict(pairs)
        if len(str(query)) > MAX_QUERY_JSON // 2:
            raise RuleError("The query part is too long.")
    return trim(path), query


def parse_scope_ip(text: str | None) -> str | None:
    text = (text or "").strip()
    if not text:
        return None
    try:
        return canonical_ip(text[:64])
    except ValueError:
        raise RuleError("The scope is not a valid IP address.") from None


def covers(pattern: str, match_type: str, path: str) -> bool:
    """Does a rule with this pattern match this (already normalized) path?"""
    p = trim(path)
    if match_type == "exact":
        return p == pattern
    return pattern == "/" or p == pattern or p.startswith(pattern + "/")


def overlaps_protected(pattern: str, match_type: str, protected: str) -> bool:
    """Could a rule with this pattern match any path under a protected prefix?"""
    prot = trim(protected)
    if match_type == "prefix" and (pattern == "/" or prot == pattern or prot.startswith(pattern + "/")):
        return True
    return pattern == prot or pattern.startswith(prot + "/")


def check_safety(pattern: str, match_type: str, action: str, *, protected, allow_site_wide: bool) -> None:
    """Reject a deny rule that could lock admins out or take the whole site down by accident."""
    if action != "deny":
        return
    if match_type == "prefix" and pattern == "/" and not allow_site_wide:
        raise RuleError("A deny on the whole site is refused. Turn on enforcement.allow_site_wide_url_deny "
                        "in General Settings first if you really mean it.")
    for prot in protected:
        if overlaps_protected(pattern, match_type, prot):
            raise RuleError(f"That rule would cover the protected path {prot[:60]}.")


def request_parts(raw_path: str, raw_query: str) -> tuple[str, dict]:
    """A request's normalized path and its query as {key: set(values)} (every occurrence counts)."""
    path, _ = normalize_path(raw_path or "/")
    query: dict = {}
    try:
        for key, value in parse_qsl(raw_query or "", keep_blank_values=True, max_num_fields=200):
            query.setdefault(key, set()).add(value)
    except ValueError:
        pass  # absurdly many parameters: treat the query as empty rather than failing a request
    return trim(path), query


def query_ok(required: tuple, query: dict) -> bool:
    return all(value in query.get(key, ()) for key, value in required)


def sort_key(rule: Rule) -> tuple:
    """Lower sorts first: per-address before global, exact before prefix, longer prefix first, query
    match before none, lower priority number, deny before allow, lower id."""
    return (0 if rule.scope_ip else 1, 0 if rule.match_type == "exact" else 1,
            -segment_count(rule.pattern), 0 if rule.query_match else 1, rule.priority,
            0 if rule.action == "deny" else 1, rule.id)


@dataclass(frozen=True)
class Verdict:
    rule: Rule
    status: str                  # winner | matched | no_match_path | no_match_query | other_address
    #                              | disabled | expired


def evaluate(rules, ip: str, path: str, query: dict, now_ms: int) -> list[Verdict]:
    """Every rule with what happened to it, ordered so the first `winner`/`matched` entry is the decision."""
    live, rest = [], []
    for rule in rules:
        if not rule.enabled:
            rest.append(Verdict(rule, "disabled"))
        elif rule.expires_ms is not None and rule.expires_ms <= now_ms:
            rest.append(Verdict(rule, "expired"))
        elif rule.scope_ip is not None and rule.scope_ip != ip:
            rest.append(Verdict(rule, "other_address"))
        elif not covers(rule.pattern, rule.match_type, path):
            rest.append(Verdict(rule, "no_match_path"))
        elif not query_ok(rule.query_match, query):
            rest.append(Verdict(rule, "no_match_query"))
        else:
            live.append(rule)
    live.sort(key=sort_key)
    matched = [Verdict(r, "winner" if i == 0 else "matched") for i, r in enumerate(live)]
    rest.sort(key=lambda v: (v.status, sort_key(v.rule)))
    return matched + rest


def winner(rules, ip: str, path: str, query: dict, now_ms: int) -> Rule | None:
    for verdict in evaluate(rules, ip, path, query, now_ms):
        if verdict.status == "winner":
            return verdict.rule
    return None
