"""The decision pipeline: one function that turns (address, URL) into allow / deny / override / monitor.

Order (docs/ARCHITECTURE.md section 6 and GOAL.md E, F):
 1. a host Guard does not manage is never enforced;
 2. a manual IP `block` denies;
 3. a URL access rule that wins with `deny` denies (an `allow` rule only counters a broader URL deny,
    it never overrides an IP block or reputation: decision Q3);
 4. a manual IP `allow` is an override, a manual IP `monitor` is monitoring only;
 5. reputation (Tor, VPN, proxy) is checked ONLY on the enforcement paths (MyBB login and registration
    by default), from the cache only. Hosting alone never blocks; unknown data allows.
 6. in `monitor_only` mode every denial is recorded as "monitored" and nothing is blocked.

This function only reads. It never calls an external service (GOAL rule 3). When the cache has nothing
usable for an address on an enforcement path it sets `needs_lookup` so the caller can queue one.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from . import settings_read, urlmatch, urlrules
from .ingest.normalize import canonical_ip, normalize_host
from .intel import iplogs, iprules, policy, tor


@dataclass(frozen=True)
class Verdict:
    outcome: str                 # allowed | denied | overridden | monitored
    reason: str = ""
    detection: str = ""          # ip_rule | url_rule | tor | vpn_detected | proxy | ...
    rule_id: int | None = None   # the URL rule that decided, if any
    needs_lookup: bool = False
    would_deny: bool = False     # monitored only because enforcement.mode is monitor_only


def on_enforcement_path(entries, path: str, query: dict, method: str) -> bool:
    """True when reputation checks apply to this request.

    An entry matches on its path plus either the named query parameter having one of the listed values,
    or the request being a POST: MyBB's login and registration forms send `action` in the POST body,
    which Nginx cannot see, so a POST to the path is treated as one of the steps. (ASSUMPTION to verify
    on MyBB 1.8.41, PROGRESS.md.)
    """
    here = urlmatch.trim(path)
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            continue
        if urlmatch.trim(entry["path"]) != here:
            continue
        if method.upper() == "POST":
            return True
        values = entry.get("values")
        param = entry.get("param")
        if isinstance(values, list) and isinstance(param, str) and any(
                isinstance(v, str) and v in query.get(param, ()) for v in values):
            return True
    return False


def _decide(conn: sqlite3.Connection, ip: str, path: str, query: dict, method: str, now_ms: int) -> Verdict:
    rule = iprules.active_rule(conn, ip, now_ms)
    if rule is not None and rule["mode"] == "block":
        return Verdict("denied", "Blocked by an administrator", detection="ip_rule")
    url_rule = urlmatch.winner(urlrules.load_rules(conn), ip, path, query, now_ms)
    if url_rule is not None and url_rule.action == "deny":
        return Verdict("denied", "This page is not available to you", detection="url_rule",
                       rule_id=url_rule.id)
    if rule is not None and rule["mode"] == "allow":
        return Verdict("overridden", "Allowed by an administrator", detection="ip_rule")
    if rule is not None and rule["mode"] == "monitor":
        return Verdict("monitored", "Monitoring only", detection="ip_rule")
    if not on_enforcement_path(settings_read.get(conn, "enforcement.paths"), path, query, method):
        return Verdict("allowed", "")
    intel = iplogs.load_intel(conn, ip, now_ms, settings_read.get(conn, "intel.stale_grace_s"))
    decision = policy.evaluate(intel, tor.is_exit(conn, ip), settings_read.get(conn, "intel.policy"))
    lookup = (not intel.usable) and settings_read.get(conn, "intel.iplogs.enabled") \
        and iplogs.needs_lookup(conn, ip, now_ms)
    if decision.action == "deny":
        return Verdict("denied", decision.reason, detection=decision.detection, needs_lookup=False)
    return Verdict("allowed", decision.reason, needs_lookup=bool(lookup))


def check(conn: sqlite3.Connection, ip_text: str, host: str, raw_path: str, raw_query: str, method: str,
          now_ms: int) -> Verdict:
    """The decision for one request. Never raises for bad input: an unusable address or host allows."""
    managed = {h.lower() for h in settings_read.get(conn, "site.hosts")}
    if normalize_host(host) not in managed:
        return Verdict("allowed", "unmanaged host")
    try:
        ip = canonical_ip(ip_text)
    except ValueError:
        return Verdict("allowed", "unknown client address")
    path, query = urlmatch.request_parts(raw_path, raw_query)
    verdict = _decide(conn, ip, path, query, method or "GET", now_ms)
    if verdict.outcome == "denied" and settings_read.get(conn, "enforcement.mode") == "monitor_only":
        return Verdict("monitored", "Would deny: " + verdict.reason, detection=verdict.detection,
                       rule_id=verdict.rule_id, would_deny=True)
    return verdict
