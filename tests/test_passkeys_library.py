"""The real WebAuthn library behind Guard's passkey code (py_webauthn, `pip install webauthn`).

A small software authenticator (ES256 key, "none" attestation, built with `cryptography` and `cbor2`)
answers registration and sign-in ceremonies exactly as a browser would relay them, so these tests check
that guard/auth/passkeys.py drives the library correctly: options ask for discoverable credentials with
user verification, good responses verify, and wrong origin, wrong RP ID, a tampered signature, missing
user verification, a signature by another key and a repeated counter are all refused.

These tests skip themselves when `webauthn` or `cbor2` is not installed. Install the real dependencies
(`pip install webauthn`) and run them: they are the only place the library itself is exercised.
"""

import hashlib
import json
import os
import struct

import pytest

pytest.importorskip("webauthn")
cbor2 = pytest.importorskip("cbor2")

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from guard.auth import passkeys  # noqa: E402
from guard.auth.passkeys import ChallengeStore, LibraryBackend, PasskeyError  # noqa: E402
from tests.passkey_helpers import IP, NOW, ORIGIN, RP_ID, admin_handle, b64u, unb64u  # noqa: E402

UP, UV, AT = 0x01, 0x04, 0x40


class SoftKey:
    """One credential with a real P-256 key."""

    def __init__(self):
        self.private = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)
        self.counter = 0

    def _cose(self) -> bytes:
        numbers = self.private.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"),
                            -3: numbers.y.to_bytes(32, "big")})

    @staticmethod
    def _client_data(kind: str, challenge: str, origin: str) -> bytes:
        return json.dumps({"type": kind, "challenge": challenge, "origin": origin,
                           "crossOrigin": False}).encode()

    def _envelope(self) -> dict:
        ident = b64u(self.credential_id)
        return {"id": ident, "rawId": ident, "type": "public-key", "clientExtensionResults": {}}

    def create(self, challenge: str, *, origin: str = ORIGIN, rp_id: str = RP_ID,
               flags: int = UP | UV | AT) -> dict:
        client_data = self._client_data("webauthn.create", challenge, origin)
        auth_data = (hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", self.counter)
                     + bytes(16) + struct.pack(">H", len(self.credential_id)) + self.credential_id
                     + self._cose())
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        cred = self._envelope()
        cred["response"] = {"clientDataJSON": b64u(client_data), "attestationObject": b64u(attestation),
                            "transports": ["internal"]}
        return cred

    def get(self, challenge: str, *, origin: str = ORIGIN, rp_id: str = RP_ID, flags: int = UP | UV,
            counter: int | None = None, user_handle: bytes | None = None, tamper: bool = False,
            signer=None) -> dict:
        self.counter = self.counter + 1 if counter is None else counter
        client_data = self._client_data("webauthn.get", challenge, origin)
        auth_data = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", self.counter)
        signature = (signer or self.private).sign(auth_data + hashlib.sha256(client_data).digest(),
                                                  ec.ECDSA(hashes.SHA256()))
        if tamper:
            signature = signature[:-1] + bytes([signature[-1] ^ 0x01])
        cred = self._envelope()
        cred["response"] = {"clientDataJSON": b64u(client_data), "authenticatorData": b64u(auth_data),
                            "signature": b64u(signature)}
        if user_handle is not None:
            cred["response"]["userHandle"] = b64u(user_handle)
        return cred


@pytest.fixture
def backend():
    return LibraryBackend()


@pytest.fixture
def store():
    return ChallengeStore()


def register(conn, backend, store, admin_id, key, *, name="Key", **create_kw):
    options = passkeys.begin_registration(backend, store, conn, admin_id, rp_id=RP_ID, binding="s", now_ms=NOW)
    created = passkeys.finish_registration(
        backend, store, conn, admin_id=admin_id, actor_name="alice", binding="s",
        credential=key.create(options["challenge"], **create_kw), name=name, rp_id=RP_ID, origin=ORIGIN,
        ip=IP, now_ms=NOW)
    return created


def sign_in(conn, backend, store, key, **get_kw):
    options = passkeys.begin_signin(backend, store, rp_id=RP_ID, binding="pre", now_ms=NOW)
    return passkeys.finish_signin(backend, store, conn, binding="pre",
                                  credential=key.get(options["challenge"], **get_kw), rp_id=RP_ID,
                                  origin=ORIGIN, ip=IP, user_agent="pytest", now_ms=NOW)


def failure_reasons(conn):
    return [json.loads(r["detail"])["reason"] for r in
            conn.execute("SELECT detail FROM audit_events WHERE action = 'auth.login_failed' ORDER BY id")]


def test_the_package_is_found(backend):
    assert backend.available() is True


def test_registration_options_ask_for_a_discoverable_key_with_user_verification(conn, admin_id, backend, store):
    options = passkeys.begin_registration(backend, store, conn, admin_id, rp_id=RP_ID, binding="s", now_ms=NOW)
    assert options["rp"]["id"] == RP_ID and options["attestation"] == "none"
    selection = options["authenticatorSelection"]
    assert selection["residentKey"] == "required" and selection["userVerification"] == "required"
    assert unb64u(options["user"]["id"]) == admin_handle(conn, admin_id)
    assert len(unb64u(options["challenge"])) == 32
    assert any(p["alg"] == -7 for p in options["pubKeyCredParams"])


def test_sign_in_options_do_not_name_an_account(backend, store):
    options = passkeys.begin_signin(backend, store, rp_id=RP_ID, binding="pre", now_ms=NOW)
    assert options["rpId"] == RP_ID and options["userVerification"] == "required"
    assert not options.get("allowCredentials")


def test_register_then_sign_in_with_the_real_library(conn, admin_id, backend, store):
    key = SoftKey()
    register(conn, backend, store, admin_id, key, name="Soft key")
    row = conn.execute("SELECT * FROM passkeys").fetchone()
    assert bytes(row["credential_id"]) == key.credential_id and len(bytes(row["public_key"])) > 32
    assert row["sign_count"] == 0 and row["backup_eligible"] == 0 and json.loads(row["transports"]) == ["internal"]
    assert row["aaguid"] == "00000000-0000-0000-0000-000000000000"
    first = sign_in(conn, backend, store, key, user_handle=admin_handle(conn, admin_id))
    assert first.ok and first.session.auth_method == "passkey"
    assert conn.execute("SELECT sign_count FROM passkeys").fetchone()[0] == 1
    assert sign_in(conn, backend, store, key).ok          # handle omitted: fine
    assert conn.execute("SELECT sign_count FROM passkeys").fetchone()[0] == 2


def test_reauthentication_with_the_real_library(conn, admin_id, backend, store):
    key = SoftKey()
    register(conn, backend, store, admin_id, key)
    options = passkeys.begin_reauth(backend, store, conn, admin_id, rp_id=RP_ID, binding="s", now_ms=NOW)
    assert [unb64u(c["id"]) for c in options["allowCredentials"]] == [key.credential_id]
    check = passkeys.finish_reauth(backend, store, conn, admin_id, binding="s",
                                   credential=key.get(options["challenge"]), rp_id=RP_ID, origin=ORIGIN,
                                   ip=IP, now_ms=NOW)
    assert check.ok


@pytest.mark.parametrize("override", [{"origin": "https://evil.example.org"}, {"rp_id": "evil.example.org"},
                                      {"flags": UP | AT}])   # last one: user verification missing
def test_registration_responses_that_should_not_verify_are_refused(conn, admin_id, backend, store, override):
    with pytest.raises(PasskeyError) as caught:
        register(conn, backend, store, admin_id, SoftKey(), **override)
    assert caught.value.reason.startswith("registration_invalid:")
    assert conn.execute("SELECT COUNT(*) FROM passkeys").fetchone()[0] == 0


def test_registration_for_a_different_challenge_is_refused(conn, admin_id, backend, store):
    passkeys.begin_registration(backend, store, conn, admin_id, rp_id=RP_ID, binding="s", now_ms=NOW)
    with pytest.raises(PasskeyError) as caught:
        passkeys.finish_registration(
            backend, store, conn, admin_id=admin_id, actor_name="alice", binding="s",
            credential=SoftKey().create(b64u(os.urandom(32))), name="Key", rp_id=RP_ID, origin=ORIGIN,
            ip=IP, now_ms=NOW)
    assert caught.value.reason.startswith("registration_invalid:")


@pytest.mark.parametrize("override", [{"origin": "https://evil.example.org"}, {"rp_id": "evil.example.org"},
                                      {"tamper": True}, {"flags": UP}])   # last one: no user verification
def test_assertions_that_should_not_verify_are_refused(conn, admin_id, backend, store, override):
    key = SoftKey()
    register(conn, backend, store, admin_id, key)
    result = sign_in(conn, backend, store, key, **override)
    assert not result.ok and result.token is None
    assert failure_reasons(conn)[-1].startswith("assertion_invalid:")
    assert conn.execute("SELECT sign_count FROM passkeys").fetchone()[0] == 0


def test_an_assertion_signed_by_another_key_is_refused(conn, admin_id, backend, store):
    key = SoftKey()
    register(conn, backend, store, admin_id, key)
    forged = sign_in(conn, backend, store, key, signer=ec.generate_private_key(ec.SECP256R1()))
    assert not forged.ok and failure_reasons(conn)[-1].startswith("assertion_invalid:")


def test_a_repeated_counter_is_refused_and_flagged(conn, admin_id, backend, store):
    key = SoftKey()
    register(conn, backend, store, admin_id, key)
    assert sign_in(conn, backend, store, key).ok                         # counter 1
    assert not sign_in(conn, backend, store, key, counter=1).ok          # a clone would repeat it
    assert failure_reasons(conn)[-1] == "sign_count_regression"
    event = conn.execute("SELECT outcome FROM audit_events WHERE action = 'passkey.sign_count_regression'"
                         ).fetchone()
    assert event["outcome"] == "denied"
    assert conn.execute("SELECT sign_count FROM passkeys").fetchone()[0] == 1


def test_an_authenticator_that_never_counts_can_sign_in(conn, admin_id, backend, store):
    key = SoftKey()
    register(conn, backend, store, admin_id, key)
    assert sign_in(conn, backend, store, key, counter=0).ok
    assert sign_in(conn, backend, store, key, counter=0).ok
