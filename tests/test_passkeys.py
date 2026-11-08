"""Passkey rules owned by Guard (guard/auth/passkeys.py), tested with a fake WebAuthn backend.

The cryptography is not tested here (that is the `webauthn` package's job, exercised in
tests/test_passkeys_library.py). These tests cover what Guard itself decides: single-use and expiring
challenges bound to the right session, origin and RP ID handed to the library, ownership, sign-count
replay handling, throttling by IP only, last-passkey protection and what reaches the audit log.
"""

import json
import os

import pytest

from guard.auth import passkeys, service, sessions, throttle
from guard.auth.passkeys import (CHALLENGE_TTL_MS, ChallengeStore, PasskeyConflict, PasskeyError,
                                 PasskeyNotFound)
from tests.passkey_helpers import (GOOD_PW, IP, NOW, ORIGIN, RP_ID, FakeAuthenticator, FakeBackend,
                                   admin_handle, b64u, enroll, signin_credential)


@pytest.fixture
def backend():
    return FakeBackend()


@pytest.fixture
def store():
    return ChallengeStore()


def audit_rows(conn, action=None):
    sql = "SELECT * FROM audit_events" + (" WHERE action = ?" if action else "") + " ORDER BY id"
    return conn.execute(sql, (action,) if action else ()).fetchall()


def finish_signin(backend, store, conn, credential, *, binding="pre-1", now_ms=NOW, ip=IP, **kw):
    return passkeys.finish_signin(backend, store, conn, binding=binding, credential=credential, rp_id=RP_ID,
                                  origin=ORIGIN, ip=ip, user_agent="pytest", now_ms=now_ms, **kw)


def second_admin(conn, hasher, name="bob"):
    return service.create_admin(conn, hasher, name, GOOD_PW, now_ms=NOW)


# ---- challenge store -------------------------------------------------------------------------

def test_challenge_is_single_use():
    store = ChallengeStore()
    store.put("signin", "a", b"c" * 32, NOW)
    assert store.take("signin", "a", NOW) == b"c" * 32
    assert store.take("signin", "a", NOW) is None


def test_challenge_expires_after_five_minutes():
    store = ChallengeStore()
    store.put("signin", "a", b"c" * 32, NOW)
    assert store.take("signin", "a", NOW + CHALLENGE_TTL_MS) is None
    store.put("signin", "a", b"c" * 32, NOW)
    assert store.take("signin", "a", NOW + CHALLENGE_TTL_MS - 1) == b"c" * 32


def test_challenge_purposes_and_bindings_are_separate():
    store = ChallengeStore()
    store.put("register", "1", b"r" * 32, NOW)
    assert store.take("signin", "1", NOW) is None
    assert store.take("reauth", "1", NOW) is None
    assert store.take("register", "2", NOW) is None
    assert store.take("register", "1", NOW) == b"r" * 32


def test_new_ceremony_replaces_the_pending_one():
    store = ChallengeStore()
    store.put("signin", "a", b"1" * 32, NOW)
    store.put("signin", "a", b"2" * 32, NOW)
    assert len(store) == 1
    assert store.take("signin", "a", NOW) == b"2" * 32


def test_challenge_store_is_bounded_and_drops_the_oldest():
    store = ChallengeStore(max_entries=3)
    for i in range(5):
        store.put("signin", str(i), bytes([i]) * 32, NOW)
    assert len(store) == 3
    assert store.take("signin", "0", NOW) is None and store.take("signin", "1", NOW) is None
    assert store.take("signin", "4", NOW) == bytes([4]) * 32


# ---- small helpers ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw, expected", [("Laptop", "Laptop"), ("  my   key ", "my key"),
                                           ("tab\tinside", "tab inside"), ("x" * 64, "x" * 64)])
def test_clean_name_accepts(raw, expected):
    assert passkeys.clean_name(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "x" * 65, "bell\x07", "nul\x00", None, 5, ["a"]])
def test_clean_name_rejects(raw):
    with pytest.raises(service.AccountError):
        passkeys.clean_name(raw)


def test_clean_transports_keeps_known_names_once():
    assert passkeys.clean_transports(["usb", "internal", "usb", "bogus", 3]) == ["usb", "internal"]
    assert passkeys.clean_transports(["bogus"]) is None
    assert passkeys.clean_transports("usb") is None and passkeys.clean_transports(None) is None


def test_credential_id_of_requires_agreeing_id_and_raw_id():
    cid = b64u(os.urandom(32))
    assert passkeys.credential_id_of({"id": cid, "rawId": cid}) is not None
    assert passkeys.credential_id_of({"id": cid}) is not None
    assert passkeys.credential_id_of({"id": cid, "rawId": b64u(os.urandom(32))}) is None
    assert passkeys.credential_id_of({"id": b64u(b"short")}) is None  # under 16 bytes
    assert passkeys.credential_id_of({"id": "!!!"}) is None
    assert passkeys.credential_id_of({"rawId": ""}) is None
    assert passkeys.credential_id_of("nope") is None and passkeys.credential_id_of(None) is None


def test_user_handle_of_reads_absent_and_present_handles():
    assert passkeys.user_handle_of({"response": {}}) is None
    assert passkeys.user_handle_of({"response": {"userHandle": ""}}) is None
    assert passkeys.user_handle_of({"response": {"userHandle": b64u(b"h" * 32)}}) == b"h" * 32
    assert passkeys.user_handle_of({}) is None


def test_library_backend_reports_missing_package():
    import importlib.util
    backend = passkeys.LibraryBackend()
    if importlib.util.find_spec("webauthn") is not None:
        pytest.skip("the webauthn package is installed")
    assert backend.available() is False
    with pytest.raises(passkeys.PasskeyUnavailable):
        backend.authentication_options(rp_id=RP_ID, challenge=b"c" * 32, allow=[])


# ---- registration ----------------------------------------------------------------------------

def test_registration_stores_the_key_and_audits_without_secrets(conn, admin_id, backend, store):
    authn, created = enroll(conn, backend, store, admin_id, name="Laptop")
    row = conn.execute("SELECT * FROM passkeys").fetchone()
    assert row["admin_id"] == admin_id and row["name"] == "Laptop" and created["id"] == row["id"]
    assert bytes(row["credential_id"]) == authn.credential_id
    assert bytes(row["public_key"]) == authn.public_key
    assert row["sign_count"] == 0 and row["created_ms"] == NOW and row["last_used_ms"] is None
    assert json.loads(row["transports"]) == ["internal"]
    (event,) = audit_rows(conn, "passkey.add")
    detail = json.loads(event["detail"])
    assert event["outcome"] == "success" and event["target_id"] == str(row["id"])
    assert detail == {"cred_hash": passkeys.cred_hash(authn.credential_id), "name": "Laptop",
                      "transports": ["internal"]}
    assert len(detail["cred_hash"]) == 8


def test_registration_options_carry_the_admin_handle_and_exclude_existing(conn, admin_id, backend, store):
    first, _ = enroll(conn, backend, store, admin_id, name="One")
    enroll(conn, backend, store, admin_id, name="Two")
    call = backend.registration_calls[-1]
    assert call["user_handle"] == admin_handle(conn, admin_id) and call["user_name"] == "alice"
    assert call["rp_id"] == RP_ID and call["exclude"] == [first.credential_id]


def test_registration_options_check_the_name_early(conn, admin_id, backend, store):
    enroll(conn, backend, store, admin_id, name="Laptop")
    with pytest.raises(PasskeyConflict):
        passkeys.begin_registration(backend, store, conn, admin_id, rp_id=RP_ID, binding="s", now_ms=NOW,
                                    name="laptop")
    with pytest.raises(service.AccountError):
        passkeys.begin_registration(backend, store, conn, admin_id, rp_id=RP_ID, binding="s", now_ms=NOW,
                                    name="   ")


def test_registration_options_for_unknown_admin_is_not_found(conn, backend, store):
    with pytest.raises(PasskeyNotFound):
        passkeys.begin_registration(backend, store, conn, 999, rp_id=RP_ID, binding="s", now_ms=NOW)


@pytest.mark.parametrize("override, reason", [
    ({"origin": "https://evil.example.org"}, "registration_invalid:Origin"),
    ({"rp_id": "evil.example.org"}, "registration_invalid:RpId"),
    ({"wrong_challenge": True}, "registration_invalid:Challenge")])
def test_registration_that_does_not_verify_stores_nothing(conn, admin_id, backend, store, override, reason):
    options = passkeys.begin_registration(backend, store, conn, admin_id, rp_id=RP_ID, binding="s", now_ms=NOW)
    credential = FakeAuthenticator().create(options["challenge"], **override)
    with pytest.raises(PasskeyError) as caught:
        passkeys.finish_registration(backend, store, conn, admin_id=admin_id, actor_name="alice", binding="s",
                                     credential=credential, name="Laptop", rp_id=RP_ID, origin=ORIGIN,
                                     ip=IP, now_ms=NOW)
    assert caught.value.reason == reason
    assert conn.execute("SELECT COUNT(*) FROM passkeys").fetchone()[0] == 0
    (event,) = audit_rows(conn, "passkey.add")
    assert event["outcome"] == "failure" and json.loads(event["detail"]) == {"reason": reason}


def test_registration_challenge_cannot_be_replayed(conn, admin_id, backend, store):
    authn = FakeAuthenticator()
    options = passkeys.begin_registration(backend, store, conn, admin_id, rp_id=RP_ID, binding="s", now_ms=NOW)
    credential = authn.create(options["challenge"])

    def finish(name):
        return passkeys.finish_registration(backend, store, conn, admin_id=admin_id, actor_name="alice",
                                            binding="s", credential=credential, name=name, rp_id=RP_ID,
                                            origin=ORIGIN, ip=IP, now_ms=NOW)

    finish("Laptop")
    with pytest.raises(PasskeyError) as caught:
        finish("Again")
    assert caught.value.reason == "no_challenge"
    assert conn.execute("SELECT COUNT(*) FROM passkeys").fetchone()[0] == 1


def test_registration_challenge_is_bound_to_the_session_and_expires(conn, admin_id, backend, store):
    options = passkeys.begin_registration(backend, store, conn, admin_id, rp_id=RP_ID, binding="s1", now_ms=NOW)
    credential = FakeAuthenticator().create(options["challenge"])
    for binding, when in (("s2", NOW), ("s1", NOW + CHALLENGE_TTL_MS + 1)):
        with pytest.raises(PasskeyError) as caught:
            passkeys.finish_registration(backend, store, conn, admin_id=admin_id, actor_name="alice",
                                         binding=binding, credential=credential, name="Laptop", rp_id=RP_ID,
                                         origin=ORIGIN, ip=IP, now_ms=when)
        assert caught.value.reason == "no_challenge"


def test_registration_rejects_non_object_credentials(conn, admin_id, backend, store):
    passkeys.begin_registration(backend, store, conn, admin_id, rp_id=RP_ID, binding="s", now_ms=NOW)
    with pytest.raises(PasskeyError) as caught:
        passkeys.finish_registration(backend, store, conn, admin_id=admin_id, actor_name="alice", binding="s",
                                     credential="not a dict", name="Laptop", rp_id=RP_ID, origin=ORIGIN,
                                     ip=IP, now_ms=NOW)
    assert caught.value.reason == "malformed"


def test_names_are_unique_per_admin_ignoring_case(conn, admin_id, hasher, backend, store):
    enroll(conn, backend, store, admin_id, name="Laptop")
    with pytest.raises(PasskeyConflict):
        enroll(conn, backend, store, admin_id, name="LAPTOP")
    bob = second_admin(conn, hasher)
    enroll(conn, backend, store, bob, name="Laptop", binding="s-bob", actor_name="bob")  # other admin: fine
    assert conn.execute("SELECT COUNT(*) FROM passkeys").fetchone()[0] == 2


def test_the_same_credential_cannot_be_registered_twice(conn, admin_id, backend, store):
    authn, _ = enroll(conn, backend, store, admin_id, name="One")
    with pytest.raises(PasskeyConflict) as caught:
        enroll(conn, backend, store, admin_id, name="Two", authenticator=authn)
    assert "already registered" in str(caught.value)
    assert conn.execute("SELECT COUNT(*) FROM passkeys").fetchone()[0] == 1


def test_an_admin_can_have_at_most_twenty_passkeys(conn, admin_id, backend, store):
    for i in range(passkeys.MAX_PASSKEYS_PER_ADMIN):
        conn.execute("INSERT INTO passkeys(admin_id, credential_id, public_key, name, created_ms)"
                     " VALUES (?,?,?,?,?)", (admin_id, os.urandom(32), b"pk", f"key {i}", NOW))
    with pytest.raises(PasskeyConflict):
        passkeys.begin_registration(backend, store, conn, admin_id, rp_id=RP_ID, binding="s", now_ms=NOW)
    with pytest.raises(PasskeyConflict):
        enroll(conn, backend, store, admin_id, name="one too many")


# ---- sign-in ---------------------------------------------------------------------------------

def test_signin_opens_a_passkey_session(conn, admin_id, backend, store):
    authn, _ = enroll(conn, backend, store, admin_id, name="Laptop")
    throttle.record_failure(conn, throttle.ip_key(IP), NOW)
    result = finish_signin(backend, store, conn, signin_credential(backend, store, authn), now_ms=NOW + 5)
    assert result.ok and result.admin_id == admin_id and result.token
    assert result.session.auth_method == "passkey"
    assert sessions.validate_session(conn, result.token, NOW + 6) is not None
    row = conn.execute("SELECT sign_count, last_used_ms FROM passkeys").fetchone()
    assert row["sign_count"] == 1 and row["last_used_ms"] == NOW + 5
    assert conn.execute("SELECT last_login_ms FROM admins").fetchone()[0] == NOW + 5
    assert conn.execute("SELECT COUNT(*) FROM auth_throttle").fetchone()[0] == 0  # earlier failure cleared
    (event,) = audit_rows(conn, "auth.login")
    assert event["outcome"] == "success" and event["actor_name"] == "alice"
    assert json.loads(event["detail"]) == {"method": "passkey", "passkey": "Laptop"}


def test_signin_options_name_no_account(backend, store):
    options = passkeys.begin_signin(backend, store, rp_id=RP_ID, binding="pre-1", now_ms=NOW)
    assert "allowCredentials" not in options and backend.authentication_calls[-1]["allow"] == []


def test_an_assertion_cannot_be_replayed(conn, admin_id, backend, store):
    authn, _ = enroll(conn, backend, store, admin_id)
    credential = signin_credential(backend, store, authn)
    assert finish_signin(backend, store, conn, credential).ok
    again = finish_signin(backend, store, conn, credential)
    assert not again.ok and again.token is None
    assert json.loads(audit_rows(conn, "auth.login_failed")[-1]["detail"])["reason"] == "no_challenge"


def test_a_stale_counter_is_refused_and_flagged(conn, admin_id, backend, store):
    authn, _ = enroll(conn, backend, store, admin_id)
    assert finish_signin(backend, store, conn, signin_credential(backend, store, authn)).ok  # counter 1
    clone = signin_credential(backend, store, authn, counter=1)  # a cloned key would repeat the counter
    result = finish_signin(backend, store, conn, clone)
    assert not result.ok
    assert conn.execute("SELECT sign_count FROM passkeys").fetchone()[0] == 1
    (event,) = audit_rows(conn, "passkey.sign_count_regression")
    assert event["outcome"] == "denied" and event["actor_name"] == "alice"
    assert json.loads(audit_rows(conn, "auth.login_failed")[-1]["detail"])["reason"] == "sign_count_regression"


def test_authenticators_that_never_count_can_still_sign_in(conn, admin_id, backend, store):
    authn, _ = enroll(conn, backend, store, admin_id)
    for _ in range(2):
        assert finish_signin(backend, store, conn, signin_credential(backend, store, authn, counter=0)).ok
    assert conn.execute("SELECT sign_count FROM passkeys").fetchone()[0] == 0


def test_unknown_credential_fails_generically(conn, admin_id, backend, store):
    enroll(conn, backend, store, admin_id)
    stranger = FakeAuthenticator()
    result = finish_signin(backend, store, conn, signin_credential(backend, store, stranger))
    assert not result.ok and not result.locked
    detail = json.loads(audit_rows(conn, "auth.login_failed")[-1]["detail"])
    assert detail == {"method": "passkey", "reason": "unknown_credential"}


def test_disabled_account_cannot_sign_in_with_a_passkey(conn, admin_id, backend, store):
    authn, _ = enroll(conn, backend, store, admin_id)
    conn.execute("UPDATE admins SET is_disabled = 1, disabled_ms = ? WHERE id = ?", (NOW, admin_id))
    result = finish_signin(backend, store, conn, signin_credential(backend, store, authn))
    assert not result.ok
    assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    assert json.loads(audit_rows(conn, "auth.login_failed")[-1]["detail"])["reason"] == "account_disabled"


def test_user_handle_must_match_when_present(conn, admin_id, backend, store):
    authn, _ = enroll(conn, backend, store, admin_id)
    handle = admin_handle(conn, admin_id)
    assert finish_signin(backend, store, conn, signin_credential(backend, store, authn,
                                                                 user_handle=handle)).ok
    assert finish_signin(backend, store, conn, signin_credential(backend, store, authn)).ok  # absent: fine
    wrong = signin_credential(backend, store, authn, user_handle=os.urandom(32))
    assert not finish_signin(backend, store, conn, wrong).ok
    malformed = signin_credential(backend, store, authn)
    malformed["response"]["userHandle"] = "***"
    assert not finish_signin(backend, store, conn, malformed).ok
    reasons = [json.loads(r["detail"])["reason"] for r in audit_rows(conn, "auth.login_failed")]
    assert reasons == ["user_handle_mismatch", "user_handle_mismatch"]


@pytest.mark.parametrize("override, reason", [
    ({"origin": "https://evil.example.org"}, "assertion_invalid:Origin"),
    ({"rp_id": "evil.example.org"}, "assertion_invalid:RpId"),
    ({"bad_signature": True}, "assertion_invalid:Signature")])
def test_assertions_that_do_not_verify_are_refused(conn, admin_id, backend, store, override, reason):
    authn, _ = enroll(conn, backend, store, admin_id)
    result = finish_signin(backend, store, conn, signin_credential(backend, store, authn, **override))
    assert not result.ok
    assert json.loads(audit_rows(conn, "auth.login_failed")[-1]["detail"])["reason"] == reason
    assert conn.execute("SELECT sign_count FROM passkeys").fetchone()[0] == 0


def test_assertion_for_another_challenge_is_refused(conn, admin_id, backend, store):
    authn, _ = enroll(conn, backend, store, admin_id)
    passkeys.begin_signin(backend, store, rp_id=RP_ID, binding="pre-1", now_ms=NOW)
    old = authn.get(b64u(os.urandom(32)))
    assert not finish_signin(backend, store, conn, old).ok


def test_signin_challenge_is_bound_expires_and_is_purpose_specific(conn, admin_id, backend, store):
    authn, _ = enroll(conn, backend, store, admin_id)
    credential = signin_credential(backend, store, authn, binding="pre-1")
    assert not finish_signin(backend, store, conn, credential, binding="pre-2").ok       # another browser
    credential = signin_credential(backend, store, authn, binding="pre-1")
    assert not finish_signin(backend, store, conn, credential, now_ms=NOW + CHALLENGE_TTL_MS + 1).ok
    store.put("register", "pre-1", os.urandom(32), NOW)                                  # wrong purpose
    assert not finish_signin(backend, store, conn, authn.get(b64u(os.urandom(32)))).ok
    reasons = {json.loads(r["detail"])["reason"] for r in audit_rows(conn, "auth.login_failed")}
    assert reasons == {"no_challenge"}


def test_signin_failures_lock_by_address_only(conn, admin_id, backend, store):
    authn, _ = enroll(conn, backend, store, admin_id)
    policy = throttle.ThrottlePolicy(max_failures=3, lockout_s=60)
    stranger = FakeAuthenticator()
    results = [finish_signin(backend, store, conn, signin_credential(backend, store, stranger), policy=policy)
               for _ in range(3)]
    assert [r.locked for r in results] == [False, False, True] and results[-1].retry_after_s == 60
    keys = [r["key"] for r in conn.execute("SELECT key FROM auth_throttle")]
    assert keys == [throttle.ip_key(IP)]   # nobody can lock alice out of passkeys by naming her
    locked = finish_signin(backend, store, conn, signin_credential(backend, store, authn), policy=policy)
    assert locked.locked and not locked.ok
    assert audit_rows(conn, "auth.lockout")
    later = NOW + 61_000
    ok = finish_signin(backend, store, conn, signin_credential(backend, store, authn, now_ms=later),
                       now_ms=later, policy=policy)
    assert ok.ok


def test_a_lock_on_another_address_does_not_affect_this_one(conn, admin_id, backend, store):
    authn, _ = enroll(conn, backend, store, admin_id)
    policy = throttle.ThrottlePolicy(max_failures=1, lockout_s=60)
    stranger = FakeAuthenticator()
    assert finish_signin(backend, store, conn, signin_credential(backend, store, stranger), policy=policy,
                         ip="198.51.100.9").locked
    assert finish_signin(backend, store, conn, signin_credential(backend, store, authn), policy=policy).ok


def test_no_key_material_reaches_the_audit_log(conn, admin_id, backend, store):
    authn, _ = enroll(conn, backend, store, admin_id)
    finish_signin(backend, store, conn, signin_credential(backend, store, authn))
    finish_signin(backend, store, conn, signin_credential(backend, store, authn, bad_signature=True))
    finish_signin(backend, store, conn, signin_credential(backend, store, FakeAuthenticator()))
    text = json.dumps([dict(r) for r in conn.execute("SELECT * FROM audit_events")], default=repr)
    for secret in (b64u(authn.credential_id), authn.credential_id.hex(), b64u(authn.public_key),
                   authn.public_key.hex()):
        assert secret not in text


# ---- re-authentication -----------------------------------------------------------------------

def reauth(backend, store, conn, admin_id, credential, *, binding="s1", now_ms=NOW, **kw):
    return passkeys.finish_reauth(backend, store, conn, admin_id, binding=binding, credential=credential,
                                  rp_id=RP_ID, origin=ORIGIN, ip=IP, now_ms=now_ms, **kw)


def reauth_credential(backend, store, conn, admin_id, authn, *, binding="s1", now_ms=NOW, **kw):
    options = passkeys.begin_reauth(backend, store, conn, admin_id, rp_id=RP_ID, binding=binding, now_ms=now_ms)
    return authn.get(options["challenge"], **kw)


def test_reauth_needs_a_passkey_to_offer(conn, admin_id, backend, store):
    with pytest.raises(PasskeyNotFound):
        passkeys.begin_reauth(backend, store, conn, admin_id, rp_id=RP_ID, binding="s1", now_ms=NOW)


def test_reauth_offers_only_the_admins_own_passkeys(conn, admin_id, hasher, backend, store):
    mine, _ = enroll(conn, backend, store, admin_id)
    bob = second_admin(conn, hasher)
    enroll(conn, backend, store, bob, binding="s-bob", actor_name="bob")
    passkeys.begin_reauth(backend, store, conn, admin_id, rp_id=RP_ID, binding="s1", now_ms=NOW)
    assert backend.authentication_calls[-1]["allow"] == [mine.credential_id]


def test_reauth_with_a_passkey_succeeds_and_is_audited(conn, admin_id, backend, store):
    authn, _ = enroll(conn, backend, store, admin_id, name="Laptop")
    check = reauth(backend, store, conn, admin_id, reauth_credential(backend, store, conn, admin_id, authn))
    assert check.ok
    assert conn.execute("SELECT sign_count FROM passkeys").fetchone()[0] == 1
    (event,) = audit_rows(conn, "auth.reauth")
    assert event["outcome"] == "success"
    assert json.loads(event["detail"]) == {"method": "passkey", "passkey": "Laptop"}


def test_reauth_refuses_another_admins_passkey(conn, admin_id, hasher, backend, store):
    enroll(conn, backend, store, admin_id)
    bob = second_admin(conn, hasher)
    bobs, _ = enroll(conn, backend, store, bob, binding="s-bob", actor_name="bob")
    options = passkeys.begin_reauth(backend, store, conn, admin_id, rp_id=RP_ID, binding="s1", now_ms=NOW)
    check = reauth(backend, store, conn, admin_id, bobs.get(options["challenge"]))
    assert not check.ok
    assert json.loads(audit_rows(conn, "auth.reauth")[-1]["detail"])["reason"] == "unknown_credential"
    assert conn.execute("SELECT sign_count FROM passkeys WHERE admin_id = ?", (bob,)).fetchone()[0] == 0


def test_reauth_challenge_is_single_use_and_bound_to_the_session(conn, admin_id, backend, store):
    authn, _ = enroll(conn, backend, store, admin_id)
    credential = reauth_credential(backend, store, conn, admin_id, authn)
    assert not reauth(backend, store, conn, admin_id, credential, binding="other-session").ok
    credential = reauth_credential(backend, store, conn, admin_id, authn)
    assert reauth(backend, store, conn, admin_id, credential).ok
    assert not reauth(backend, store, conn, admin_id, credential).ok


def test_reauth_failures_count_against_user_and_address(conn, admin_id, backend, store):
    authn, _ = enroll(conn, backend, store, admin_id)
    policy = throttle.ThrottlePolicy(max_failures=2, lockout_s=60)
    for _ in range(2):
        check = reauth(backend, store, conn, admin_id,
                       reauth_credential(backend, store, conn, admin_id, authn, bad_signature=True),
                       policy=policy)
    assert check.locked and check.retry_after_s == 60
    keys = {r["key"] for r in conn.execute("SELECT key FROM auth_throttle")}
    assert keys == {throttle.ip_key(IP), throttle.user_key("alice")}
    good = reauth(backend, store, conn, admin_id, reauth_credential(backend, store, conn, admin_id, authn),
                  policy=policy)
    assert good.locked and not good.ok


def test_reauth_for_a_disabled_admin_fails(conn, admin_id, backend, store):
    authn, _ = enroll(conn, backend, store, admin_id)
    credential = reauth_credential(backend, store, conn, admin_id, authn)
    conn.execute("UPDATE admins SET is_disabled = 1, disabled_ms = ? WHERE id = ?", (NOW, admin_id))
    assert not reauth(backend, store, conn, admin_id, credential).ok


# ---- listing, renaming, revoking -------------------------------------------------------------

def test_listing_shows_no_key_material(conn, admin_id, backend, store):
    authn, _ = enroll(conn, backend, store, admin_id, name="Laptop")
    (item,) = passkeys.list_for_admin(conn, admin_id)
    assert set(item) == {"id", "name", "created_ms", "last_used_ms", "transports", "synced", "cred_hash"}
    assert item["synced"] is False and item["transports"] == ["internal"]
    assert item["cred_hash"] == passkeys.cred_hash(authn.credential_id)
    assert passkeys.count_for_admin(conn, admin_id) == 1


def test_listing_is_per_admin(conn, admin_id, hasher, backend, store):
    enroll(conn, backend, store, admin_id, name="Mine")
    bob = second_admin(conn, hasher)
    assert passkeys.list_for_admin(conn, bob) == []


def test_rename_changes_the_name_and_audits(conn, admin_id, backend, store):
    _, created = enroll(conn, backend, store, admin_id, name="Laptop")
    name = passkeys.rename(conn, admin_id, created["id"], "  Work   laptop ", actor_name="alice", ip=IP,
                           now_ms=NOW + 1)
    assert name == "Work laptop"
    assert conn.execute("SELECT name FROM passkeys").fetchone()[0] == "Work laptop"
    (event,) = audit_rows(conn, "passkey.rename")
    assert json.loads(event["detail"]) == {"from": "Laptop", "to": "Work laptop"}


def test_renaming_to_the_current_name_is_not_audited_again(conn, admin_id, backend, store):
    _, created = enroll(conn, backend, store, admin_id, name="Laptop")
    for _ in range(2):   # a change of case is a real rename (once); repeating it changes nothing
        assert passkeys.rename(conn, admin_id, created["id"], "laptop", actor_name="alice", ip=IP,
                               now_ms=NOW) == "laptop"
    assert len(audit_rows(conn, "passkey.rename")) == 1


def test_rename_conflicts_and_ownership(conn, admin_id, hasher, backend, store):
    _, one = enroll(conn, backend, store, admin_id, name="One")
    enroll(conn, backend, store, admin_id, name="Two")
    with pytest.raises(PasskeyConflict):
        passkeys.rename(conn, admin_id, one["id"], "two", actor_name="alice", ip=IP, now_ms=NOW)
    bob = second_admin(conn, hasher)
    with pytest.raises(PasskeyNotFound):
        passkeys.rename(conn, bob, one["id"], "Mine now", actor_name="bob", ip=IP, now_ms=NOW)
    assert conn.execute("SELECT name FROM passkeys WHERE id = ?", (one["id"],)).fetchone()[0] == "One"


def test_revoke_deletes_the_row_and_audits_a_hash_only(conn, admin_id, backend, store):
    authn, first = enroll(conn, backend, store, admin_id, name="One")
    enroll(conn, backend, store, admin_id, name="Two")
    passkeys.revoke(conn, admin_id, first["id"], actor_name="alice", ip=IP, now_ms=NOW, password_usable=False)
    assert [r["name"] for r in conn.execute("SELECT name FROM passkeys")] == ["Two"]
    (event,) = audit_rows(conn, "passkey.revoke")
    assert json.loads(event["detail"]) == {"cred_hash": passkeys.cred_hash(authn.credential_id), "name": "One"}


def test_the_last_passkey_stays_when_no_password_could_replace_it(conn, admin_id, backend, store):
    _, only = enroll(conn, backend, store, admin_id)
    with pytest.raises(PasskeyConflict) as caught:
        passkeys.revoke(conn, admin_id, only["id"], actor_name="alice", ip=IP, now_ms=NOW,
                        password_usable=False)
    assert "lock you out" in str(caught.value)
    assert passkeys.count_for_admin(conn, admin_id) == 1 and not audit_rows(conn, "passkey.revoke")
    passkeys.revoke(conn, admin_id, only["id"], actor_name="alice", ip=IP, now_ms=NOW, password_usable=True)
    assert passkeys.count_for_admin(conn, admin_id) == 0


def test_revoke_only_touches_the_admins_own_passkeys(conn, admin_id, hasher, backend, store):
    _, one = enroll(conn, backend, store, admin_id)
    bob = second_admin(conn, hasher)
    with pytest.raises(PasskeyNotFound):
        passkeys.revoke(conn, bob, one["id"], actor_name="bob", ip=IP, now_ms=NOW, password_usable=True)
    with pytest.raises(PasskeyNotFound):
        passkeys.revoke(conn, admin_id, 99999, actor_name="alice", ip=IP, now_ms=NOW, password_usable=True)
    assert passkeys.count_for_admin(conn, admin_id) == 1


def test_a_revoked_passkey_can_no_longer_sign_in(conn, admin_id, backend, store):
    authn, first = enroll(conn, backend, store, admin_id, name="One")
    enroll(conn, backend, store, admin_id, name="Two")
    passkeys.revoke(conn, admin_id, first["id"], actor_name="alice", ip=IP, now_ms=NOW, password_usable=True)
    assert not finish_signin(backend, store, conn, signin_credential(backend, store, authn)).ok


def test_password_usable_needs_a_hash_and_the_setting(conn, admin_id):
    assert passkeys.password_usable(conn, admin_id, True) is True
    assert passkeys.password_usable(conn, admin_id, False) is False
    conn.execute("UPDATE admins SET password_hash = NULL WHERE id = ?", (admin_id,))
    assert passkeys.password_usable(conn, admin_id, True) is False
    assert passkeys.password_usable(conn, 999, True) is False


# ---- operator recovery -----------------------------------------------------------------------

def test_revoke_all_removes_every_passkey_and_signs_the_admin_out(conn, admin_id, backend, store):
    enroll(conn, backend, store, admin_id, name="One")
    enroll(conn, backend, store, admin_id, name="Two")
    token, _ = sessions.create_session(conn, admin_id, "passkey", IP, "ua", NOW)
    assert passkeys.revoke_all_for_admin(conn, admin_id, actor_name="cli:root", now_ms=NOW + 1) == 2
    assert passkeys.count_for_admin(conn, admin_id) == 0
    assert sessions.validate_session(conn, token, NOW + 2) is None
    (event,) = audit_rows(conn, "passkey.revoke")
    assert event["actor_name"] == "cli:root" and event["target_type"] == "admin"
    assert json.loads(event["detail"]) == {"count": 2, "sessions_revoked": 1, "via": "cli"}


def test_revoke_all_refuses_when_there_is_no_password(conn, admin_id, backend, store):
    enroll(conn, backend, store, admin_id)
    conn.execute("UPDATE admins SET password_hash = NULL WHERE id = ?", (admin_id,))
    with pytest.raises(service.AccountError):
        passkeys.revoke_all_for_admin(conn, admin_id, actor_name="cli:root", now_ms=NOW)
    assert passkeys.count_for_admin(conn, admin_id) == 1


def test_revoke_all_for_unknown_admin(conn):
    with pytest.raises(PasskeyNotFound):
        passkeys.revoke_all_for_admin(conn, 999, actor_name="cli:root", now_ms=NOW)
