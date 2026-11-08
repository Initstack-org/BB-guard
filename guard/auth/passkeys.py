"""Passkeys (WebAuthn): registration, sign-in, re-authentication and management.

docs/SUBSYSTEMS.md section 7.3 and docs/API.md sections 4 and 5. No web framework here: the web layer
calls these functions, and time is passed in so every path is testable.

All cryptography, CBOR and COSE handling is done by the maintained `webauthn` package (py_webauthn)
behind the small `WebAuthnBackend` interface below. Nothing in this file parses authenticator data or
checks a signature (GOAL rule 7). What this file owns are the rules around the library:

- Challenges are random 32-byte values held in memory only, single use, expiring after five minutes and
  bound to the session (registration, re-authentication) or the pre-session cookie (sign-in). There is no
  challenge table (decision D8, GOAL rule 1). A restart forgets pending challenges, so a ceremony in
  progress simply has to be started again. This needs one Guard process, which is how it is run.
- The relying party ID is the dashboard hostname and the expected origin is the configured external
  origin, compared exactly. User verification is required for every registration and sign-in.
- A credential belongs to one administrator. Sign-in is username-less (discoverable credentials); the
  user handle the authenticator returns, when present, must match the administrator's.
- Sign-in failures are throttled by IP only (docs/SUBSYSTEMS.md 7.2), so nobody can lock an
  administrator out of passkey sign-in by naming them.
- Revoking deletes the row; the audit event keeps the name and the first 8 hex characters of the
  SHA-256 of the credential ID (SCHEMA.md decision S8). Public keys, credential IDs and challenges
  never reach the audit log.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import json
import os
import sqlite3
import threading
import unicodedata
import uuid
from dataclasses import dataclass
from typing import Protocol

from .. import audit
from ..db import transaction
from . import sessions, throttle
from .service import AccountError, LoginResult, PasswordCheck, canonical_ip

CHALLENGE_TTL_MS = 300_000       # five minutes (docs/SUBSYSTEMS.md 7.3)
MAX_PENDING_CHALLENGES = 2000    # bounds memory; the oldest pending challenge is dropped first
MAX_PASSKEYS_PER_ADMIN = 20
NAME_MAX = 64
RP_NAME = "InitStack Guard"
KNOWN_TRANSPORTS = ("usb", "nfc", "ble", "internal", "hybrid")


class PasskeyError(Exception):
    """A WebAuthn ceremony failed. `reason` is a short code for the audit log; it is never shown to the
    person as it stands (the web layer shows one generic sentence)."""

    def __init__(self, reason: str, *, regression: bool = False):
        super().__init__(reason)
        self.reason = reason
        self.regression = regression


class PasskeyUnavailable(RuntimeError):
    """The `webauthn` package is not installed."""


class PasskeyConflict(AccountError):
    """The request is valid but clashes with current state (HTTP 409)."""


class PasskeyNotFound(AccountError):
    """No such passkey or administrator for this caller (HTTP 404)."""


# ---------------------------------------------------------------------------------------------
# Challenges (in memory only)


class ChallengeStore:
    """Pending WebAuthn challenges. One per (purpose, binding); `take` removes it, so a challenge can be
    used once. A challenge for one purpose can never satisfy another (a registration challenge cannot
    sign anyone in)."""

    def __init__(self, *, ttl_ms: int = CHALLENGE_TTL_MS, max_entries: int = MAX_PENDING_CHALLENGES):
        self._ttl_ms = ttl_ms
        self._max = max_entries
        self._lock = threading.Lock()
        self._items: dict[tuple[str, str], tuple[bytes, int]] = {}

    def put(self, purpose: str, binding: str, challenge: bytes, now_ms: int) -> None:
        with self._lock:
            self._items.pop((purpose, binding), None)  # a new ceremony replaces the old one
            if len(self._items) >= self._max:
                for key in [k for k, (_, exp) in self._items.items() if exp <= now_ms]:
                    del self._items[key]
                while len(self._items) >= self._max:
                    del self._items[next(iter(self._items))]  # dicts keep insertion order: oldest first
            self._items[(purpose, binding)] = (challenge, now_ms + self._ttl_ms)

    def take(self, purpose: str, binding: str, now_ms: int) -> bytes | None:
        with self._lock:
            found = self._items.pop((purpose, binding), None)
        if found is None or found[1] <= now_ms:
            return None
        return found[0]

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


# ---------------------------------------------------------------------------------------------
# The library behind an interface


@dataclass(frozen=True)
class VerifiedKey:
    credential_id: bytes
    public_key: bytes
    sign_count: int
    aaguid: str | None
    transports: list[str] | None
    backup_eligible: bool | None
    backup_state: bool | None


@dataclass(frozen=True)
class VerifiedAssertion:
    new_sign_count: int
    backup_state: bool | None


class WebAuthnBackend(Protocol):
    def available(self) -> bool: ...

    def registration_options(self, *, rp_id: str, rp_name: str, user_handle: bytes, user_name: str,
                             user_display_name: str, challenge: bytes,
                             exclude: list[tuple[bytes, list[str] | None]]) -> dict: ...

    def verify_registration(self, credential: dict, *, challenge: bytes, rp_id: str,
                            origin: str) -> VerifiedKey: ...

    def authentication_options(self, *, rp_id: str, challenge: bytes,
                               allow: list[tuple[bytes, list[str] | None]]) -> dict: ...

    def verify_authentication(self, credential: dict, *, challenge: bytes, rp_id: str, origin: str,
                              public_key: bytes, sign_count: int) -> VerifiedAssertion: ...


def clean_transports(value) -> list[str] | None:
    """Keep only transport names we know, without duplicates; None when nothing is left."""
    if not isinstance(value, (list, tuple)):
        return None
    out: list[str] = []
    for item in value:
        if isinstance(item, str) and item in KNOWN_TRANSPORTS and item not in out:
            out.append(item)
    return out or None


def _aaguid_text(value) -> str | None:
    if isinstance(value, (bytes, bytearray)) and len(value) == 16:
        return str(uuid.UUID(bytes=bytes(value)))
    if isinstance(value, str) and len(value) == 36:
        return value
    return None


class LibraryBackend:
    """The real thing: py_webauthn (`pip install webauthn`, version 2 or later). Imported lazily, so the
    rest of Guard runs, and its tests pass, without the package."""

    def available(self) -> bool:
        return importlib.util.find_spec("webauthn") is not None

    def _lib(self):
        try:
            import webauthn  # noqa: PLC0415
            from webauthn.helpers import structs  # noqa: PLC0415
        except ImportError as exc:
            raise PasskeyUnavailable("the webauthn package is not installed (pip install webauthn)") from exc
        return webauthn, structs

    @staticmethod
    def _descriptors(structs, items):
        out = []
        for credential_id, transports in items:
            known = []
            for name in transports or []:
                try:
                    known.append(structs.AuthenticatorTransport(name))
                except ValueError:
                    continue
            out.append(structs.PublicKeyCredentialDescriptor(id=credential_id, transports=known or None))
        return out

    def registration_options(self, *, rp_id, rp_name, user_handle, user_name, user_display_name,
                             challenge, exclude) -> dict:
        lib, s = self._lib()
        options = lib.generate_registration_options(
            rp_id=rp_id, rp_name=rp_name, user_id=user_handle, user_name=user_name,
            user_display_name=user_display_name, challenge=challenge,
            attestation=s.AttestationConveyancePreference.NONE,
            authenticator_selection=s.AuthenticatorSelectionCriteria(
                resident_key=s.ResidentKeyRequirement.REQUIRED,
                user_verification=s.UserVerificationRequirement.REQUIRED),
            exclude_credentials=self._descriptors(s, exclude), timeout=CHALLENGE_TTL_MS)
        return json.loads(lib.options_to_json(options))

    def verify_registration(self, credential, *, challenge, rp_id, origin) -> VerifiedKey:
        lib, _ = self._lib()
        try:
            verified = lib.verify_registration_response(
                credential=credential, expected_challenge=challenge, expected_rp_id=rp_id,
                expected_origin=origin, require_user_verification=True)
        except Exception as exc:  # noqa: BLE001 - untrusted input: any parse or check failure is a rejection
            raise PasskeyError("registration_invalid:" + type(exc).__name__) from exc
        response = credential.get("response") if isinstance(credential, dict) else None
        device = getattr(getattr(verified, "credential_device_type", None), "value", None)
        backed_up = getattr(verified, "credential_backed_up", None)
        return VerifiedKey(
            credential_id=bytes(verified.credential_id), public_key=bytes(verified.credential_public_key),
            sign_count=int(verified.sign_count), aaguid=_aaguid_text(getattr(verified, "aaguid", None)),
            transports=clean_transports(response.get("transports") if isinstance(response, dict) else None),
            backup_eligible=None if device is None else device == "multi_device",
            backup_state=backed_up if isinstance(backed_up, bool) else None)

    def authentication_options(self, *, rp_id, challenge, allow) -> dict:
        lib, s = self._lib()
        options = lib.generate_authentication_options(
            rp_id=rp_id, challenge=challenge, timeout=CHALLENGE_TTL_MS,
            allow_credentials=self._descriptors(s, allow) or None,
            user_verification=s.UserVerificationRequirement.REQUIRED)
        return json.loads(lib.options_to_json(options))

    def verify_authentication(self, credential, *, challenge, rp_id, origin, public_key,
                              sign_count) -> VerifiedAssertion:
        lib, _ = self._lib()
        try:
            verified = lib.verify_authentication_response(
                credential=credential, expected_challenge=challenge, expected_rp_id=rp_id,
                expected_origin=origin, credential_public_key=public_key,
                credential_current_sign_count=sign_count, require_user_verification=True)
        except Exception as exc:  # noqa: BLE001 - untrusted input: any parse or check failure is a rejection
            # py_webauthn rejects a counter that did not increase (unless both are zero) with a message
            # that names the sign count. Use that only to label the audit event; a mismatch just makes
            # it an ordinary failed assertion.
            if "sign count" in str(exc).lower():
                raise PasskeyError("sign_count_regression", regression=True) from exc
            raise PasskeyError("assertion_invalid:" + type(exc).__name__) from exc
        backed_up = getattr(verified, "credential_backed_up", None)
        return VerifiedAssertion(new_sign_count=int(verified.new_sign_count),
                                 backup_state=backed_up if isinstance(backed_up, bool) else None)


# ---------------------------------------------------------------------------------------------
# Small helpers


def b64u_decode(text) -> bytes | None:
    if not isinstance(text, str) or not text or len(text) > 2048:
        return None
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError):
        return None


def credential_id_of(credential) -> bytes | None:
    """The credential ID a browser response names, or None if it is missing or malformed. `id` and
    `rawId` must agree when both are present."""
    if not isinstance(credential, dict):
        return None
    ident, raw = credential.get("id"), credential.get("rawId")
    if ident is not None and raw is not None and ident != raw:
        return None
    cid = b64u_decode(raw if raw is not None else ident)
    return cid if cid is not None and 16 <= len(cid) <= 1023 else None


def user_handle_of(credential):
    """The user handle in an assertion: bytes, None when absent, False when malformed."""
    response = credential.get("response") if isinstance(credential, dict) else None
    raw = response.get("userHandle") if isinstance(response, dict) else None
    if raw in (None, ""):
        return None
    decoded = b64u_decode(raw)
    return decoded if decoded is not None else False


def cred_hash(credential_id: bytes) -> str:
    """First 8 hex characters of SHA-256(credential ID): enough to tell passkeys apart in an audit entry,
    not enough to be a credential (SCHEMA.md decision S8)."""
    return hashlib.sha256(credential_id).hexdigest()[:8]


def clean_name(raw) -> str:
    if not isinstance(raw, str):
        raise AccountError("give the passkey a name")
    name = " ".join(raw.split())
    if not name:
        raise AccountError("give the passkey a name")
    if len(name) > NAME_MAX:
        raise AccountError(f"the name can be at most {NAME_MAX} characters")
    if any(unicodedata.category(ch).startswith("C") for ch in name):
        raise AccountError("the name contains characters that are not allowed")
    return name


def _name_taken(conn: sqlite3.Connection, admin_id: int, name: str, except_id: int | None = None) -> bool:
    row = conn.execute("SELECT 1 FROM passkeys WHERE admin_id = ? AND name = ? COLLATE NOCASE"
                       " AND (? IS NULL OR id <> ?)", (admin_id, name, except_id, except_id)).fetchone()
    return row is not None


def _admin_row(conn: sqlite3.Connection, admin_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT id, username, display_name, webauthn_user_handle, is_disabled,"
                       " password_hash FROM admins WHERE id = ?", (admin_id,)).fetchone()
    if row is None:
        raise PasskeyNotFound("no such administrator")
    return row


def _stored_transports(raw) -> list[str] | None:
    if not raw:
        return None
    try:
        return clean_transports(json.loads(raw))
    except ValueError:
        return None


def count_for_admin(conn: sqlite3.Connection, admin_id: int) -> int:
    return conn.execute("SELECT COUNT(*) FROM passkeys WHERE admin_id = ?", (admin_id,)).fetchone()[0]


def list_for_admin(conn: sqlite3.Connection, admin_id: int) -> list[dict]:
    """The admin's passkeys for display. Never the public key or the full credential ID."""
    rows = conn.execute(
        "SELECT id, credential_id, name, transports, backup_eligible, backup_state, created_ms,"
        " last_used_ms FROM passkeys WHERE admin_id = ? ORDER BY created_ms, id", (admin_id,)).fetchall()
    return [{"id": r["id"], "name": r["name"], "created_ms": r["created_ms"],
             "last_used_ms": r["last_used_ms"], "transports": _stored_transports(r["transports"]) or [],
             "synced": None if r["backup_eligible"] is None else bool(r["backup_eligible"]),
             "cred_hash": cred_hash(bytes(r["credential_id"]))} for r in rows]


def password_usable(conn: sqlite3.Connection, admin_id: int, password_login_enabled: bool) -> bool:
    """Whether the admin could still sign in with a password right now."""
    if not password_login_enabled:
        return False
    row = conn.execute("SELECT password_hash FROM admins WHERE id = ?", (admin_id,)).fetchone()
    return row is not None and row["password_hash"] is not None


# ---------------------------------------------------------------------------------------------
# Registration


def begin_registration(backend: WebAuthnBackend, store: ChallengeStore, conn: sqlite3.Connection,
                       admin_id: int, *, rp_id: str, binding: str, now_ms: int,
                       name: str | None = None) -> dict:
    """Registration options for the signed-in admin. `binding` is the session id. When `name` is given it
    is checked now, so a bad or taken name is reported before the device asks for a fingerprint."""
    admin = _admin_row(conn, admin_id)
    if name is not None:
        clean = clean_name(name)
        if _name_taken(conn, admin_id, clean):
            raise PasskeyConflict("you already have a passkey with that name")
    if count_for_admin(conn, admin_id) >= MAX_PASSKEYS_PER_ADMIN:
        raise PasskeyConflict(f"you can have at most {MAX_PASSKEYS_PER_ADMIN} passkeys")
    existing = conn.execute("SELECT credential_id, transports FROM passkeys WHERE admin_id = ?",
                            (admin_id,)).fetchall()
    challenge = os.urandom(32)
    options = backend.registration_options(
        rp_id=rp_id, rp_name=RP_NAME, user_handle=bytes(admin["webauthn_user_handle"]),
        user_name=admin["username"], user_display_name=admin["display_name"] or admin["username"],
        challenge=challenge,
        exclude=[(bytes(r["credential_id"]), _stored_transports(r["transports"])) for r in existing])
    store.put("register", binding, challenge, now_ms)
    return options


def finish_registration(backend: WebAuthnBackend, store: ChallengeStore, conn: sqlite3.Connection, *,
                        admin_id: int, actor_name: str, binding: str, credential, name,
                        rp_id: str, origin: str, ip: str, now_ms: int) -> dict:
    """Verify a new passkey and store it. Raises PasskeyError when the response does not verify (audited),
    AccountError (PasskeyConflict) when the name or credential clashes with an existing one."""
    ip = canonical_ip(ip)
    clean = clean_name(name)
    if _name_taken(conn, admin_id, clean):
        raise PasskeyConflict("you already have a passkey with that name")
    if count_for_admin(conn, admin_id) >= MAX_PASSKEYS_PER_ADMIN:
        raise PasskeyConflict(f"you can have at most {MAX_PASSKEYS_PER_ADMIN} passkeys")

    def fail(reason: str) -> PasskeyError:
        audit.record(conn, "passkey.add", "failure", actor_admin_id=admin_id, actor_name=actor_name, ip=ip,
                     detail={"reason": reason}, ts_ms=now_ms)
        return PasskeyError(reason)

    challenge = store.take("register", binding, now_ms)
    if challenge is None:
        raise fail("no_challenge")
    if not isinstance(credential, dict):
        raise fail("malformed")
    try:
        key = backend.verify_registration(credential, challenge=challenge, rp_id=rp_id, origin=origin)
    except PasskeyError as exc:
        raise fail(exc.reason) from exc
    if not 16 <= len(key.credential_id) <= 1023:
        raise fail("credential_id_length")
    try:
        with transaction(conn):
            cur = conn.execute(
                "INSERT INTO passkeys(admin_id, credential_id, public_key, sign_count, transports, aaguid,"
                " backup_eligible, backup_state, name, created_ms) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (admin_id, key.credential_id, key.public_key, max(0, key.sign_count),
                 json.dumps(key.transports) if key.transports else None, key.aaguid,
                 None if key.backup_eligible is None else int(key.backup_eligible),
                 None if key.backup_state is None else int(key.backup_state), clean, now_ms))
            passkey_id = cur.lastrowid
            audit.record(conn, "passkey.add", "success", actor_admin_id=admin_id, actor_name=actor_name,
                         ip=ip, target_type="passkey", target_id=str(passkey_id),
                         detail={"name": clean, "cred_hash": cred_hash(key.credential_id),
                                 "transports": key.transports or []}, ts_ms=now_ms)
    except sqlite3.IntegrityError as exc:
        text = str(exc).lower()
        if "unique" in text and "name" in text:
            raise PasskeyConflict("you already have a passkey with that name") from exc
        if "unique" in text:
            raise PasskeyConflict("that passkey is already registered") from exc
        raise AccountError("that passkey cannot be stored") from exc
    return {"id": passkey_id, "name": clean}


# ---------------------------------------------------------------------------------------------
# Sign-in (username-less, discoverable credentials)


def begin_signin(backend: WebAuthnBackend, store: ChallengeStore, *, rp_id: str, binding: str,
                 now_ms: int) -> dict:
    """Authentication options for the sign-in page. `binding` is the pre-session cookie value. No username
    is taken and nothing about any account is revealed."""
    challenge = os.urandom(32)
    options = backend.authentication_options(rp_id=rp_id, challenge=challenge, allow=[])
    store.put("signin", binding, challenge, now_ms)
    return options


def _touch(conn: sqlite3.Connection, passkey_id: int, verified: VerifiedAssertion, now_ms: int) -> None:
    conn.execute("UPDATE passkeys SET sign_count = ?, last_used_ms = ?,"
                 " backup_state = COALESCE(?, backup_state) WHERE id = ?",
                 (max(0, verified.new_sign_count), now_ms,
                  None if verified.backup_state is None else int(verified.backup_state), passkey_id))


_PASSKEY_ROW = ("SELECT p.id, p.admin_id, p.public_key, p.sign_count, p.name, a.username, a.is_disabled,"
                " a.webauthn_user_handle FROM passkeys p JOIN admins a ON a.id = p.admin_id"
                " WHERE p.credential_id = ?")


def _check_handle(credential, row) -> bool:
    handle = user_handle_of(credential)
    if handle is None:
        return True  # some authenticators omit it; the credential ID already identified the account
    return handle is not False and hmac.compare_digest(handle, bytes(row["webauthn_user_handle"]))


def finish_signin(backend: WebAuthnBackend, store: ChallengeStore, conn: sqlite3.Connection, *,
                  binding: str, credential, rp_id: str, origin: str, ip: str, user_agent: str, now_ms: int,
                  policy: throttle.ThrottlePolicy = throttle.ThrottlePolicy(),
                  session_max_s: int = 43200) -> LoginResult:
    """Verify an assertion and open a session. The caller shows one generic message for any failure;
    `retry_after_s` is the only distinguishable outcome (a lock applies to everyone alike)."""
    ip = canonical_ip(ip)
    ikey = throttle.ip_key(ip)
    wait = throttle.check(conn, ikey, now_ms)
    if wait:
        audit.record(conn, "auth.lockout", "denied", ip=ip, ts_ms=now_ms,
                     detail={"retry_after_s": wait, "method": "passkey"})
        return LoginResult(False, retry_after_s=wait)

    def fail(reason: str, row=None, regression: bool = False) -> LoginResult:
        locked = throttle.record_failure(conn, ikey, now_ms, policy)
        detail = {"method": "passkey", "reason": reason}
        if locked:
            detail["locked_for_s"] = locked
        audit.record(conn, "auth.login_failed", "failure", ip=ip, ts_ms=now_ms, detail=detail,
                     actor_admin_id=row["admin_id"] if row is not None else None,
                     actor_name=row["username"] if row is not None else "")
        if regression and row is not None:
            audit.record(conn, "passkey.sign_count_regression", "denied", ip=ip, ts_ms=now_ms,
                         actor_admin_id=row["admin_id"], actor_name=row["username"],
                         target_type="passkey", target_id=str(row["id"]), detail={"name": row["name"]})
        return LoginResult(False, retry_after_s=locked)

    challenge = store.take("signin", binding, now_ms)
    if challenge is None:
        return fail("no_challenge")
    credential_id = credential_id_of(credential)
    if credential_id is None:
        return fail("malformed")
    row = conn.execute(_PASSKEY_ROW, (credential_id,)).fetchone()
    if row is None:
        return fail("unknown_credential")
    if row["is_disabled"]:
        return fail("account_disabled", row)
    if not _check_handle(credential, row):
        return fail("user_handle_mismatch", row)
    try:
        verified = backend.verify_authentication(
            credential, challenge=challenge, rp_id=rp_id, origin=origin,
            public_key=bytes(row["public_key"]), sign_count=row["sign_count"])
    except PasskeyError as exc:
        return fail(exc.reason, row, exc.regression)

    with transaction(conn):
        _touch(conn, row["id"], verified, now_ms)
        conn.execute("UPDATE admins SET last_login_ms = ? WHERE id = ?", (now_ms, row["admin_id"]))
        token, info = sessions.create_session(conn, row["admin_id"], "passkey", ip, user_agent, now_ms,
                                              max_s=session_max_s)
        throttle.clear(conn, ikey)
        audit.record(conn, "auth.login", "success", actor_admin_id=row["admin_id"],
                     actor_name=row["username"], ip=ip, ts_ms=now_ms,
                     detail={"method": "passkey", "passkey": row["name"]})
    return LoginResult(True, token=token, session=info, admin_id=row["admin_id"])


# ---------------------------------------------------------------------------------------------
# Re-authentication with a passkey (class R routes)


def begin_reauth(backend: WebAuthnBackend, store: ChallengeStore, conn: sqlite3.Connection, admin_id: int,
                 *, rp_id: str, binding: str, now_ms: int) -> dict:
    """Authentication options limited to this admin's own passkeys. `binding` is the session id."""
    rows = conn.execute("SELECT credential_id, transports FROM passkeys WHERE admin_id = ?",
                        (admin_id,)).fetchall()
    if not rows:
        raise PasskeyNotFound("you have no passkeys to confirm with")
    challenge = os.urandom(32)
    options = backend.authentication_options(
        rp_id=rp_id, challenge=challenge,
        allow=[(bytes(r["credential_id"]), _stored_transports(r["transports"])) for r in rows])
    store.put("reauth", binding, challenge, now_ms)
    return options


def finish_reauth(backend: WebAuthnBackend, store: ChallengeStore, conn: sqlite3.Connection, admin_id: int,
                  *, binding: str, credential, rp_id: str, origin: str, ip: str, now_ms: int,
                  policy: throttle.ThrottlePolicy = throttle.ThrottlePolicy()) -> PasswordCheck:
    """Re-check a signed-in admin with one of their own passkeys. Uses the same throttle keys as password
    re-authentication (docs/API.md limit L1). Audited as `auth.reauth` with the method."""
    ip = canonical_ip(ip)
    admin = conn.execute("SELECT id, username, is_disabled FROM admins WHERE id = ?", (admin_id,)).fetchone()
    if admin is None or admin["is_disabled"]:
        return PasswordCheck(False)
    ukey, ikey = throttle.user_key(admin["username"]), throttle.ip_key(ip)
    wait = max(throttle.check(conn, ukey, now_ms), throttle.check(conn, ikey, now_ms))
    if wait:
        audit.record(conn, "auth.lockout", "denied", actor_admin_id=admin["id"], actor_name=admin["username"],
                     ip=ip, ts_ms=now_ms, detail={"retry_after_s": wait, "method": "passkey"})
        return PasswordCheck(False, retry_after_s=wait)

    def fail(reason: str, row=None, regression: bool = False) -> PasswordCheck:
        locked = max(throttle.record_failure(conn, ukey, now_ms, policy),
                     throttle.record_failure(conn, ikey, now_ms, policy))
        detail = {"method": "passkey", "reason": reason}
        if locked:
            detail["locked_for_s"] = locked
        audit.record(conn, "auth.reauth", "failure", actor_admin_id=admin["id"], actor_name=admin["username"],
                     ip=ip, ts_ms=now_ms, detail=detail)
        if regression and row is not None:
            audit.record(conn, "passkey.sign_count_regression", "denied", ip=ip, ts_ms=now_ms,
                         actor_admin_id=admin["id"], actor_name=admin["username"],
                         target_type="passkey", target_id=str(row["id"]), detail={"name": row["name"]})
        return PasswordCheck(False, retry_after_s=locked)

    challenge = store.take("reauth", binding, now_ms)
    if challenge is None:
        return fail("no_challenge")
    credential_id = credential_id_of(credential)
    if credential_id is None:
        return fail("malformed")
    row = conn.execute(_PASSKEY_ROW + " AND p.admin_id = ?", (credential_id, admin_id)).fetchone()
    if row is None:
        return fail("unknown_credential")  # also the answer for another administrator's passkey
    if not _check_handle(credential, row):
        return fail("user_handle_mismatch", row)
    try:
        verified = backend.verify_authentication(
            credential, challenge=challenge, rp_id=rp_id, origin=origin,
            public_key=bytes(row["public_key"]), sign_count=row["sign_count"])
    except PasskeyError as exc:
        return fail(exc.reason, row, exc.regression)
    with transaction(conn):
        _touch(conn, row["id"], verified, now_ms)
        throttle.clear(conn, ukey, ikey)
        audit.record(conn, "auth.reauth", "success", actor_admin_id=admin["id"], actor_name=admin["username"],
                     ip=ip, ts_ms=now_ms, detail={"method": "passkey", "passkey": row["name"]})
    return PasswordCheck(True)


# ---------------------------------------------------------------------------------------------
# Management


def rename(conn: sqlite3.Connection, admin_id: int, passkey_id: int, new_name, *, actor_name: str,
           ip: str, now_ms: int) -> str:
    """Rename one of the admin's own passkeys; returns the stored name."""
    clean = clean_name(new_name)
    with transaction(conn):
        row = conn.execute("SELECT id, name FROM passkeys WHERE id = ? AND admin_id = ?",
                           (passkey_id, admin_id)).fetchone()
        if row is None:
            raise PasskeyNotFound("no such passkey")
        if _name_taken(conn, admin_id, clean, except_id=passkey_id):
            raise PasskeyConflict("you already have a passkey with that name")
        if row["name"] == clean:
            return clean
        conn.execute("UPDATE passkeys SET name = ? WHERE id = ?", (clean, passkey_id))
        audit.record(conn, "passkey.rename", "success", actor_admin_id=admin_id, actor_name=actor_name,
                     ip=canonical_ip(ip), target_type="passkey", target_id=str(passkey_id),
                     detail={"from": row["name"], "to": clean}, ts_ms=now_ms)
    return clean


def revoke(conn: sqlite3.Connection, admin_id: int, passkey_id: int, *, actor_name: str, ip: str,
           now_ms: int, password_usable: bool) -> None:
    """Delete one of the admin's own passkeys. Refused when it is the last one and the admin could not
    sign in with a password afterwards: never leave an account with no way in."""
    with transaction(conn):
        row = conn.execute("SELECT id, name, credential_id FROM passkeys WHERE id = ? AND admin_id = ?",
                           (passkey_id, admin_id)).fetchone()
        if row is None:
            raise PasskeyNotFound("no such passkey")
        if count_for_admin(conn, admin_id) <= 1 and not password_usable:
            raise PasskeyConflict("this is your last passkey and password sign-in is not available, "
                                  "so removing it would lock you out")
        conn.execute("DELETE FROM passkeys WHERE id = ?", (passkey_id,))
        audit.record(conn, "passkey.revoke", "success", actor_admin_id=admin_id, actor_name=actor_name,
                     ip=canonical_ip(ip), target_type="passkey", target_id=str(passkey_id),
                     detail={"name": row["name"], "cred_hash": cred_hash(bytes(row["credential_id"]))},
                     ts_ms=now_ms)


def revoke_all_for_admin(conn: sqlite3.Connection, admin_id: int, *, actor_name: str, now_ms: int) -> int:
    """Operator recovery (`revoke-passkeys`): delete every passkey of one admin and sign them out.
    Refused when the admin has no password, because that would leave no way to sign in."""
    with transaction(conn):
        admin = _admin_row(conn, admin_id)
        if admin["password_hash"] is None:
            raise AccountError("that administrator has no password; set one with reset-password first")
        count = conn.execute("DELETE FROM passkeys WHERE admin_id = ?", (admin_id,)).rowcount
        revoked = sessions.revoke_all_for_admin(conn, admin_id, now_ms)
        audit.record(conn, "passkey.revoke", "success", actor_name=actor_name, target_type="admin",
                     target_id=str(admin_id), detail={"count": count, "sessions_revoked": revoked,
                                                      "via": "cli"}, ts_ms=now_ms)
    return count
