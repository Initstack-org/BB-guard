"""Test doubles for the passkey tests.

`FakeBackend` implements the `WebAuthnBackend` interface from guard/auth/passkeys.py without any
cryptography: a "credential" is a plain dict that carries the values a real browser response would
prove (challenge, origin, RP ID, a signature over the challenge and counter). It lets the tests exercise
every rule Guard owns around the library (challenge life cycle, binding, throttling, ownership, audit)
without the `webauthn` package. The real library is exercised separately in
tests/test_passkeys_library.py, which skips itself when the package is missing.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

from guard.auth import passkeys
from guard.auth.passkeys import PasskeyError, VerifiedAssertion, VerifiedKey

NOW = 1_800_000_000_000
GOOD_PW = "correct horse battery staple"
RP_ID = "guard.example.org"
ORIGIN = "https://guard.example.org"
IP = "203.0.113.7"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(public_key: bytes, challenge_b64u: str, counter: int) -> str:
    return b64u(hmac.new(public_key, f"{challenge_b64u}|{counter}".encode(), hashlib.sha256).digest())


class FakeAuthenticator:
    """One credential. `create` answers a registration ceremony, `get` answers a sign-in."""

    def __init__(self, credential_id: bytes | None = None, *, rp_id: str = RP_ID, origin: str = ORIGIN):
        self.credential_id = credential_id or os.urandom(32)
        self.public_key = hashlib.sha256(os.urandom(32)).digest()
        self.counter = 0
        self.rp_id = rp_id
        self.origin = origin

    def _base(self) -> dict:
        ident = b64u(self.credential_id)
        return {"id": ident, "rawId": ident, "type": "public-key", "clientExtensionResults": {}}

    def create(self, challenge_b64u: str, *, origin: str | None = None, rp_id: str | None = None,
               transports=("internal",), wrong_challenge: bool = False) -> dict:
        cred = self._base()
        cred["fake"] = {"challenge": b64u(os.urandom(32)) if wrong_challenge else challenge_b64u,
                        "origin": origin or self.origin, "rp_id": rp_id or self.rp_id,
                        "public_key": b64u(self.public_key), "sign_count": self.counter}
        cred["response"] = {"transports": list(transports)}
        return cred

    def get(self, challenge_b64u: str, *, origin: str | None = None, rp_id: str | None = None,
            user_handle=None, counter: int | None = None, bad_signature: bool = False) -> dict:
        self.counter = self.counter + 1 if counter is None else counter
        signature = b64u(os.urandom(32)) if bad_signature else _sign(self.public_key, challenge_b64u,
                                                                     self.counter)
        cred = self._base()
        cred["fake"] = {"challenge": challenge_b64u, "origin": origin or self.origin,
                        "rp_id": rp_id or self.rp_id, "signature": signature, "sign_count": self.counter}
        cred["response"] = {}
        if user_handle is not None:
            cred["response"]["userHandle"] = b64u(user_handle)
        return cred


class FakeBackend:
    def __init__(self, available: bool = True):
        self._available = available
        self.registration_calls: list[dict] = []
        self.authentication_calls: list[dict] = []

    def available(self) -> bool:
        return self._available

    def registration_options(self, *, rp_id, rp_name, user_handle, user_name, user_display_name,
                             challenge, exclude) -> dict:
        self.registration_calls.append({"rp_id": rp_id, "user_handle": user_handle, "user_name": user_name,
                                        "exclude": [cid for cid, _ in exclude]})
        return {"challenge": b64u(challenge), "rp": {"id": rp_id, "name": rp_name},
                "user": {"id": b64u(user_handle), "name": user_name, "displayName": user_display_name},
                "excludeCredentials": [{"id": b64u(cid), "type": "public-key"} for cid, _ in exclude],
                "authenticatorSelection": {"residentKey": "required", "userVerification": "required"}}

    def verify_registration(self, credential, *, challenge, rp_id, origin) -> VerifiedKey:
        fake = credential.get("fake") if isinstance(credential, dict) else None
        if not isinstance(fake, dict):
            raise PasskeyError("registration_invalid:Malformed")
        if fake.get("challenge") != b64u(challenge):
            raise PasskeyError("registration_invalid:Challenge")
        if fake.get("origin") != origin:
            raise PasskeyError("registration_invalid:Origin")
        if fake.get("rp_id") != rp_id:
            raise PasskeyError("registration_invalid:RpId")
        response = credential.get("response") or {}
        return VerifiedKey(credential_id=unb64u(credential["id"]), public_key=unb64u(fake["public_key"]),
                           sign_count=int(fake.get("sign_count", 0)), aaguid=None,
                           transports=passkeys.clean_transports(response.get("transports")),
                           backup_eligible=False, backup_state=False)

    def authentication_options(self, *, rp_id, challenge, allow) -> dict:
        self.authentication_calls.append({"rp_id": rp_id, "allow": [cid for cid, _ in allow]})
        out = {"challenge": b64u(challenge), "rpId": rp_id, "userVerification": "required"}
        if allow:
            out["allowCredentials"] = [{"id": b64u(cid), "type": "public-key"} for cid, _ in allow]
        return out

    def verify_authentication(self, credential, *, challenge, rp_id, origin, public_key,
                              sign_count) -> VerifiedAssertion:
        fake = credential.get("fake") if isinstance(credential, dict) else None
        if not isinstance(fake, dict):
            raise PasskeyError("assertion_invalid:Malformed")
        if fake.get("challenge") != b64u(challenge):
            raise PasskeyError("assertion_invalid:Challenge")
        if fake.get("origin") != origin:
            raise PasskeyError("assertion_invalid:Origin")
        if fake.get("rp_id") != rp_id:
            raise PasskeyError("assertion_invalid:RpId")
        counter = fake.get("sign_count")
        if not isinstance(counter, int) or counter < 0:
            raise PasskeyError("assertion_invalid:Counter")
        expected = _sign(public_key, fake["challenge"], counter)
        if not hmac.compare_digest(str(fake.get("signature", "")), expected):
            raise PasskeyError("assertion_invalid:Signature")
        # Same rule as py_webauthn: the counter must rise unless both sides are zero.
        if (counter > 0 or sign_count > 0) and counter <= sign_count:
            raise PasskeyError("sign_count_regression", regression=True)
        return VerifiedAssertion(new_sign_count=counter, backup_state=False)


def enroll(conn, backend, store, admin_id: int, *, name: str = "Laptop", authenticator=None,
           binding: str = "session-1", now_ms: int = NOW, actor_name: str = "alice"):
    """Run a whole registration ceremony through guard.auth.passkeys. Returns (authenticator, result)."""
    authn = authenticator or FakeAuthenticator()
    options = passkeys.begin_registration(backend, store, conn, admin_id, rp_id=RP_ID, binding=binding,
                                          now_ms=now_ms)
    created = passkeys.finish_registration(
        backend, store, conn, admin_id=admin_id, actor_name=actor_name, binding=binding,
        credential=authn.create(options["challenge"]), name=name, rp_id=RP_ID, origin=ORIGIN, ip=IP,
        now_ms=now_ms)
    return authn, created


def signin_credential(backend, store, authn: FakeAuthenticator, *, binding: str = "pre-1",
                      now_ms: int = NOW, **kwargs) -> dict:
    """Start a sign-in ceremony and answer it with `authn`."""
    options = passkeys.begin_signin(backend, store, rp_id=RP_ID, binding=binding, now_ms=now_ms)
    return authn.get(options["challenge"], **kwargs)


def admin_handle(conn, admin_id: int) -> bytes:
    return bytes(conn.execute("SELECT webauthn_user_handle FROM admins WHERE id = ?",
                              (admin_id,)).fetchone()[0])
