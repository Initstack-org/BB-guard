"""Reputation policy (docs/SUBSYSTEMS.md section 3.4). Pure: no I/O, standard library only.

Rules this module guarantees (GOAL.md rules 4 and 5):
- hosting and crawler flags are never read, so they can never block anything;
- missing, failed, skipped or expired-beyond-grace intelligence is "unknown" and allows;
- Tor is checked from the local exit list as well as the IPLogs flag, so it works when IPLogs is down.

ASSUMPTION (unverified, see PROGRESS.md): the meaning of the IPLogs `confidence` field is not known.
A VPN flag with a confidence word in LOW_CONFIDENCE counts as "vpn_likely" (flag only by default);
any other confidence counts as "vpn_detected". Replace this once the real documentation is checked.
"""

from __future__ import annotations

from dataclasses import dataclass

CATEGORIES = ("tor", "vpn_detected", "vpn_likely", "proxy", "relay")
LOW_CONFIDENCE = frozenset({"low", "medium", "likely", "possible", "uncertain"})

REASONS = {
    "tor": "Tor exit node",
    "vpn_detected": "VPN detected",
    "vpn_likely": "VPN likely",
    "proxy": "Proxy detected",
    "relay": "Relay detected",
}


@dataclass(frozen=True)
class Intel:
    """What is known about one address. status: ok | error | skipped | missing."""
    status: str = "missing"
    is_vpn: bool | None = None
    is_proxy: bool | None = None
    is_tor: bool | None = None
    is_relay: bool | None = None
    is_hosting: bool | None = None   # carried for display only; never used in a decision
    is_crawler: bool | None = None   # carried for display only; never used in a decision
    verdict: str | None = None
    confidence: str | None = None
    expired_beyond_grace: bool = False

    @property
    def usable(self) -> bool:
        return self.status == "ok" and not self.expired_beyond_grace


@dataclass(frozen=True)
class Decision:
    action: str                  # allow | deny
    reason: str                  # shown to the admin and in the block page
    detection: str = ""          # category that caused a deny, "" otherwise
    confidence: str = ""
    flags: tuple = ()            # categories seen but not blocking


def categories(intel: Intel, tor_hit: bool) -> list[str]:
    found: list[str] = []
    if tor_hit or (intel.usable and intel.is_tor):
        found.append("tor")
    if intel.usable:
        if intel.is_vpn:
            low = (intel.confidence or "").strip().lower() in LOW_CONFIDENCE
            found.append("vpn_likely" if low else "vpn_detected")
        if intel.is_proxy:
            found.append("proxy")
        if intel.is_relay:
            found.append("relay")
    return found


def _blocks(policy: object, category: str) -> bool:
    entry = policy.get(category) if isinstance(policy, dict) else None
    return isinstance(entry, dict) and entry.get("block") is True


def evaluate(intel: Intel, tor_hit: bool, policy: object) -> Decision:
    """Decide for one address on an enforcement path. Never raises on odd input."""
    found = categories(intel, tor_hit)
    confidence = intel.confidence or ""
    if not found:
        return Decision("allow", "clean" if intel.usable else "unknown")
    for category in found:
        if _blocks(policy, category):
            return Decision("deny", REASONS[category], detection=category, confidence=confidence)
    return Decision("allow", "flagged, not blocking: " + ", ".join(found), flags=tuple(found),
                    confidence=confidence)
