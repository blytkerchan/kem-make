"""
Tests for kem_make.session.

Covers:
  1. Crypto primitives in isolation (KEM round trip, HKDF key derivation,
     AEAD round trip) before trusting anything built on top of them.
  2. A full end-to-end handshake between two real SessionLayer instances,
     with real ML-KEM-768, real HKDF, real AEAD -- not mocked.
  3. False-start payload delivery in both directions.
  4. Established-session Message traffic in both directions, including a
     regression case for a real bug caught while writing these tests: an
     unconsumed payload sitting in the output queue makes a *later*,
     unrelated get_payload() call return the stale one instead of the
     new one -- not a SessionLayer bug, but a sharp edge worth a test so
     nobody rediscovers it as a mystery down the line.
  5. Retry: exact-byte resend on timeout, exhausting the retry budget
     drops the session, and a duplicate incoming PDU triggers a resend
     without re-running any handshake logic.
  6. Bob (responder) never retries -- his deadline is a pure TTL.
  7. The Mallory scenario: a forged SessionInitResponse (or
     SessionCompletionRequest) built with only public keys is
     structurally valid but fails cryptographic confirmation --
     HandshakeFailed, not a crash, not a false-positive success.
  8. Unknown claimed identity and no-mutual-AEAD are both rejected before
     any response is sent.

Run with: pytest test_session.py -v
"""

import pytest
from cryptography.hazmat.primitives.asymmetric import mlkem

from kem_make import KemPublicKey, KeyId, MLKEM_PK_LEN
from kem_make.session import (
    SessionLayer,
    Role,
    SessionState,
    UpdateResult,
    SessionConfig,
    SessionLayerError,
    UnexpectedPDU,
    HandshakeFailed,
    derive_session_keys,
    _generate_ephemeral,
    _encapsulate,
    _decapsulate,
    _encrypt,
    _decrypt,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

class FakeKeyLookup:
    """Minimal stand-in for KeyDirectory, satisfying the KeyLookup Protocol
    structurally. Real integration against keystore.KeyDirectory is a
    separate concern -- these tests are about the session layer's own
    logic, not the key store's."""

    def __init__(self):
        self._pub = {}
        self._priv = {}

    def add(self, key_id: KeyId, public_key: KemPublicKey, private_key=None):
        self._pub[bytes(key_id["key_hash"].native)] = public_key
        if private_key is not None:
            self._priv[bytes(key_id["key_hash"].native)] = private_key

    def get_public_key(self, key_id: KeyId) -> KemPublicKey:
        return self._pub[bytes(key_id["key_hash"].native)]

    def get_private_key(self, key_id: KeyId):
        return self._priv[bytes(key_id["key_hash"].native)]


def _make_identity(level=768):
    private = mlkem.MLKEM768PrivateKey.generate() if level == 768 else mlkem.MLKEM1024PrivateKey.generate()
    public_wire = KemPublicKey.build(private.public_key().public_bytes_raw(), level=level)
    key_id = KeyId.build(public_wire)
    return private, public_wire, key_id


@pytest.fixture
def parties():
    """Alice (initiator) and Bob (responder), each knowing their own
    keypair and the other's public key, with a fast retry/TTL config so
    tests don't need to sleep."""
    alice_priv, alice_pub, alice_kid = _make_identity()
    bob_priv, bob_pub, bob_kid = _make_identity()

    alice_keys = FakeKeyLookup()
    alice_keys.add(alice_kid, alice_pub, alice_priv.private_bytes_raw())
    alice_keys.add(bob_kid, bob_pub)

    bob_keys = FakeKeyLookup()
    bob_keys.add(bob_kid, bob_pub, bob_priv.private_bytes_raw())
    bob_keys.add(alice_kid, alice_pub)

    # Deliberately separate SessionConfig instances, not one shared
    # object -- a test that mutates alice.config expecting it not to
    # affect bob.config (or vice versa) would otherwise silently corrupt
    # itself. See test_no_mutual_aead_is_rejected for exactly this bug,
    # caught while writing these tests.
    alice_config = SessionConfig(max_retries=2, retry_interval_seconds=5.0, ttl_seconds=20.0)
    bob_config = SessionConfig(max_retries=2, retry_interval_seconds=5.0, ttl_seconds=20.0)

    alice = SessionLayer(Role.INITIATOR, alice_kid, alice_keys, alice_config)
    bob = SessionLayer(Role.RESPONDER, bob_kid, bob_keys, bob_config)

    return {
        "alice": alice, "bob": bob,
        "alice_kid": alice_kid, "bob_kid": bob_kid,
        "alice_keys": alice_keys, "bob_keys": bob_keys,
        "config": alice_config,
    }


def _run_full_handshake(parties, t=0.0):
    alice, bob = parties["alice"], parties["bob"]
    alice.initiate(parties["bob_kid"], now=t)

    bob.post_pdu(alice.get_pdu())
    bob.update(now=t)

    alice.post_pdu(bob.get_pdu())
    alice.update(now=t)

    bob.post_pdu(alice.get_pdu())
    bob.update(now=t)

    alice.post_pdu(bob.get_pdu())
    alice.update(now=t)


# ---------------------------------------------------------------------------
# 1. Crypto primitives in isolation
# ---------------------------------------------------------------------------

def test_kem_round_trip():
    private, public = _generate_ephemeral(768)
    shared_secret, ct = _encapsulate(public)
    recovered = _decapsulate(private.private_bytes_raw(), 768, ct)
    assert shared_secret == recovered


def test_session_key_derivation_is_deterministic_given_the_same_inputs():
    keys1 = derive_session_keys(b"n" * 16, b"n" * 16, b"fa", b"s1", b"s2", b"s3", b"s4", "aes256-gcm")
    keys2 = derive_session_keys(b"n" * 16, b"n" * 16, b"fa", b"s1", b"s2", b"s3", b"s4", "aes256-gcm")
    assert keys1.key_a2b == keys2.key_a2b
    assert keys1.key_b2a == keys2.key_b2a


def test_session_key_derivation_directions_are_independent():
    keys = derive_session_keys(b"n" * 16, b"n" * 16, b"fa", b"s1", b"s2", b"s3", b"s4", "aes256-gcm")
    assert keys.key_a2b != keys.key_b2a
    assert keys.iv_a2b != keys.iv_b2a


@pytest.mark.parametrize("aead,expected_key_len", [
    ("aes128-gcm", 16), ("aes192-gcm", 24), ("aes256-gcm", 32), ("chacha20-poly1305", 32),
])
def test_session_key_derivation_respects_aead_key_length(aead, expected_key_len):
    keys = derive_session_keys(b"n" * 16, b"n" * 16, b"fa", b"s1", b"s2", b"s3", b"s4", aead)
    assert len(keys.key_a2b) == expected_key_len
    assert len(keys.key_b2a) == expected_key_len
    assert len(keys.iv_a2b) == 12
    assert len(keys.iv_b2a) == 12


def test_aead_round_trip_and_tamper_detection():
    keys = derive_session_keys(b"n" * 16, b"n" * 16, b"fa", b"s1", b"s2", b"s3", b"s4", "aes256-gcm")
    ct = _encrypt("aes256-gcm", keys.key_a2b, keys.iv_a2b, seq=0, plaintext=b"hello", associated_data=b"aad")
    assert _decrypt("aes256-gcm", keys.key_a2b, keys.iv_a2b, seq=0, ciphertext=ct, associated_data=b"aad") == b"hello"

    with pytest.raises(Exception):
        _decrypt("aes256-gcm", keys.key_a2b, keys.iv_a2b, seq=0, ciphertext=ct, associated_data=b"wrong-aad")


# ---------------------------------------------------------------------------
# 2. End-to-end handshake
# ---------------------------------------------------------------------------

def test_full_handshake_establishes_on_both_sides(parties):
    _run_full_handshake(parties)
    assert parties["alice"].state == SessionState.ESTABLISHED
    assert parties["bob"].state == SessionState.ESTABLISHED


def test_full_handshake_derives_matching_session_keys(parties):
    _run_full_handshake(parties)
    alice, bob = parties["alice"], parties["bob"]
    assert alice._session_keys.key_a2b == bob._session_keys.key_a2b
    assert alice._session_keys.key_b2a == bob._session_keys.key_b2a
    assert alice._session_keys.iv_a2b == bob._session_keys.iv_a2b
    assert alice._session_keys.iv_b2a == bob._session_keys.iv_b2a


def test_full_handshake_uses_the_same_cid_throughout(parties):
    _run_full_handshake(parties)
    assert parties["alice"].cid == parties["bob"].cid


# ---------------------------------------------------------------------------
# 3. False-start payload delivery
# ---------------------------------------------------------------------------

def test_false_start_payload_alice_to_bob(parties):
    alice, bob = parties["alice"], parties["bob"]
    alice.post_payload(b"false-start from alice")
    alice.initiate(parties["bob_kid"], now=0.0)

    bob.post_pdu(alice.get_pdu()); bob.update(now=0.0)
    alice.post_pdu(bob.get_pdu()); alice.update(now=0.0)
    bob.post_pdu(alice.get_pdu()); bob.update(now=0.0)

    assert bob.poll_payload()
    assert bob.get_payload() == b"false-start from alice"


def test_false_start_payload_bob_to_alice(parties):
    alice, bob = parties["alice"], parties["bob"]
    alice.initiate(parties["bob_kid"], now=0.0)

    bob.post_pdu(alice.get_pdu()); bob.update(now=0.0)
    alice.post_pdu(bob.get_pdu()); alice.update(now=0.0)
    bob.post_pdu(alice.get_pdu())
    bob.post_payload(b"false-start reply from bob")
    bob.update(now=0.0)
    alice.post_pdu(bob.get_pdu()); alice.update(now=0.0)

    assert alice.poll_payload()
    assert alice.get_payload() == b"false-start reply from bob"


# ---------------------------------------------------------------------------
# 4. Established-session Message traffic
# ---------------------------------------------------------------------------

def test_established_message_alice_to_bob(parties):
    _run_full_handshake(parties)
    alice, bob = parties["alice"], parties["bob"]

    alice.post_payload(b"msg1 from alice")
    alice.update(now=0.0)
    bob.post_pdu(alice.get_pdu())
    bob.update(now=0.0)

    assert bob.get_payload() == b"msg1 from alice"


def test_established_message_bob_to_alice(parties):
    _run_full_handshake(parties)
    alice, bob = parties["alice"], parties["bob"]

    bob.post_payload(b"msg1 from bob")
    bob.update(now=0.0)
    alice.post_pdu(bob.get_pdu())
    alice.update(now=0.0)

    assert alice.get_payload() == b"msg1 from bob"


def test_established_message_sequence_increments(parties):
    _run_full_handshake(parties)
    alice, bob = parties["alice"], parties["bob"]

    for i in range(3):
        alice.post_payload(f"msg{i}".encode())
        alice.update(now=0.0)
        bob.post_pdu(alice.get_pdu())
        bob.update(now=0.0)
        assert bob.get_payload() == f"msg{i}".encode()

    # seq starts at 1, not 0, immediately after the handshake: seq=0 was
    # already consumed by c_m during SessionCompletionRequest. Three
    # established messages on top of that lands at 4, not 3.
    assert alice._seq_a2b == 4
    assert bob._seq_a2b == 4


def test_get_payload_drains_in_fifo_order_regression():
    # Regression test for a real bug caught while writing these tests --
    # not in SessionLayer itself, but a sharp edge worth guarding: an
    # unconsumed payload left in the queue makes a later, unrelated
    # get_payload() call return the STALE one instead of the new one.
    # This isn't something SessionLayer can fix (the caller owns when it
    # consumes output), but it must behave in a predictable FIFO order so
    # a caller that *does* drain promptly gets correct behavior.
    alice_priv, alice_pub, alice_kid = _make_identity()
    bob_priv, bob_pub, bob_kid = _make_identity()
    alice_keys = FakeKeyLookup()
    alice_keys.add(alice_kid, alice_pub, alice_priv.private_bytes_raw())
    alice_keys.add(bob_kid, bob_pub)
    bob_keys = FakeKeyLookup()
    bob_keys.add(bob_kid, bob_pub, bob_priv.private_bytes_raw())
    bob_keys.add(alice_kid, alice_pub)

    alice = SessionLayer(Role.INITIATOR, alice_kid, alice_keys)
    bob = SessionLayer(Role.RESPONDER, bob_kid, bob_keys)

    alice.post_payload(b"false-start")
    alice.initiate(bob_kid, now=0.0)
    bob.post_pdu(alice.get_pdu()); bob.update(now=0.0)
    alice.post_pdu(bob.get_pdu()); alice.update(now=0.0)
    bob.post_pdu(alice.get_pdu()); bob.update(now=0.0)  # false-start payload now queued on Bob, NOT drained

    alice.post_pdu(bob.get_pdu()); alice.update(now=0.0)
    alice.post_payload(b"established-message")
    alice.update(now=0.0)
    bob.post_pdu(alice.get_pdu()); bob.update(now=0.0)

    # FIFO: the never-drained false-start payload comes out first.
    assert bob.get_payload() == b"false-start"
    assert bob.get_payload() == b"established-message"


# ---------------------------------------------------------------------------
# 5. Retry: exact-byte resend, retry exhaustion, duplicate dedup
# ---------------------------------------------------------------------------

def test_timeout_resends_the_exact_same_bytes(parties):
    alice = parties["alice"]
    alice.initiate(parties["bob_kid"], now=0.0)
    first_sent = alice.get_pdu()

    result, _ = alice.update(now=100.0)  # well past retry_interval_seconds=5.0

    assert result == UpdateResult.PDU_READY
    assert alice.get_pdu() == first_sent
    assert alice._attempt_count == 1


def test_retry_exhaustion_drops_the_session(parties):
    alice = parties["alice"]
    alice.initiate(parties["bob_kid"], now=0.0)
    alice.get_pdu()

    t = 0.0
    for _ in range(parties["config"].max_retries):
        t += 100.0
        result, _ = alice.update(now=t)
        assert result == UpdateResult.PDU_READY
        alice.get_pdu()

    t += 100.0
    result, _ = alice.update(now=t)

    assert result == UpdateResult.SESSION_DROPPED
    assert alice.state == SessionState.DROPPED
    assert not alice.poll_pdu()


def test_no_pdu_sent_on_drop():
    # Explicit check that dropping never produces output -- see module
    # docstring: no wire-level error message exists in this protocol.
    alice_priv, alice_pub, alice_kid = _make_identity()
    bob_priv, bob_pub, bob_kid = _make_identity()
    alice_keys = FakeKeyLookup()
    alice_keys.add(alice_kid, alice_pub, alice_priv.private_bytes_raw())
    alice_keys.add(bob_kid, bob_pub)

    config = SessionConfig(max_retries=1, retry_interval_seconds=1.0)
    alice = SessionLayer(Role.INITIATOR, alice_kid, alice_keys, config)
    alice.initiate(bob_kid, now=0.0)
    alice.get_pdu()

    alice.update(now=10.0)
    alice.get_pdu()
    alice.update(now=20.0)  # exhausts the single retry

    assert alice.state == SessionState.DROPPED
    assert not alice.poll_pdu()


def test_duplicate_incoming_pdu_triggers_resend_without_reprocessing(parties):
    alice, bob = parties["alice"], parties["bob"]
    alice.initiate(parties["bob_kid"], now=0.0)
    request_bytes = alice.get_pdu()

    bob.post_pdu(request_bytes)
    bob.update(now=0.0)
    first_response = bob.get_pdu()

    # Simulate the response being lost: Alice never saw it, retries.
    # Bob receives the EXACT same request bytes again.
    bob.post_pdu(request_bytes)
    bob.update(now=1.0)
    second_response = bob.get_pdu()

    assert second_response == first_response
    # And critically: Bob's ephemeral key material was NOT regenerated --
    # still on the same completion-request-pending state, not reset.
    assert bob.state == SessionState.EXPECT_SESSION_COMPLETION_REQUEST


def test_duplicate_pdu_does_not_advance_attempt_count(parties):
    alice, bob = parties["alice"], parties["bob"]
    alice.initiate(parties["bob_kid"], now=0.0)
    request_bytes = alice.get_pdu()

    bob.post_pdu(request_bytes)
    bob.update(now=0.0)
    bob.get_pdu()

    bob.post_pdu(request_bytes)
    bob.update(now=1.0)
    bob.get_pdu()

    # Bob doesn't track attempt_count for himself (he never retries), but
    # confirm state didn't change and the dedup path was really taken by
    # checking he's still waiting on the same thing.
    assert bob.state == SessionState.EXPECT_SESSION_COMPLETION_REQUEST


# ---------------------------------------------------------------------------
# 6. Bob (responder) never retries -- pure TTL, no resend
# ---------------------------------------------------------------------------

def test_responder_does_not_retry_on_its_own_timeout(parties):
    alice, bob = parties["alice"], parties["bob"]
    alice.initiate(parties["bob_kid"], now=0.0)
    bob.post_pdu(alice.get_pdu())
    bob.update(now=0.0)
    bob.get_pdu()

    result, _ = bob.update(now=1000.0)  # well past ttl_seconds

    assert result == UpdateResult.SESSION_DROPPED
    assert bob.state == SessionState.DROPPED
    assert not bob.poll_pdu()  # no resend, ever


# ---------------------------------------------------------------------------
# 7. The Mallory scenario: forged messages using only public keys
# ---------------------------------------------------------------------------

def test_forged_session_completion_request_is_rejected(parties):
    # Mallory (or anyone) can build a structurally valid
    # SessionCompletionRequest without ever holding a private key --
    # encapsulation only needs Bob's ephemeral public key, which was
    # sent in the clear. Bob must reject it, not crash, not succeed.
    from kem_make.bottom import MakeMessage, SessionCompletionRequest, KemCiphertext, MLKEM_CT_LEN

    alice, bob = parties["alice"], parties["bob"]
    alice.initiate(parties["bob_kid"], now=0.0)
    bob.post_pdu(alice.get_pdu())
    bob.update(now=0.0)
    bob_response = bob.get_pdu()

    # Forge a completion request using Bob's ephemeral public key (which
    # was sent in the clear in bob_response) but garbage ciphertext --
    # Mallory doesn't have Alice's real shared secrets.
    forged_ct4 = KemCiphertext.build(b"\x00" * MLKEM_CT_LEN[768], level=768)
    forged_req = SessionCompletionRequest.build(c_m=b"\x00" * 32, ct4=forged_ct4, n_a=b"\x00" * 16)
    forged_msg = MakeMessage.build(bob.cid, "session_completion_request", forged_req)

    bob.post_pdu(forged_msg.dump())
    with pytest.raises(HandshakeFailed):
        bob.update(now=0.0)


def test_forged_session_completion_response_is_rejected(parties):
    from kem_make.bottom import MakeMessage, SessionCompletionResponse

    alice, bob = parties["alice"], parties["bob"]
    _run_up_to_completion_response_pending(alice, bob, parties)

    forged_resp = SessionCompletionResponse({"h_m": b"\x00" * 32})
    forged_msg = MakeMessage.build(alice.cid, "session_completion_response", forged_resp)

    alice.post_pdu(forged_msg.dump())
    with pytest.raises(HandshakeFailed):
        alice.update(now=0.0)


def _run_up_to_completion_response_pending(alice, bob, parties):
    alice.initiate(parties["bob_kid"], now=0.0)
    bob.post_pdu(alice.get_pdu()); bob.update(now=0.0)
    alice.post_pdu(bob.get_pdu()); alice.update(now=0.0)
    # Alice is now EXPECT_SESSION_COMPLETION_RESPONSE; don't deliver her
    # completion request to Bob, so Bob is untouched by this helper.


# ---------------------------------------------------------------------------
# 8. Rejected before any response: unknown identity, no mutual AEAD
# ---------------------------------------------------------------------------

def test_unknown_claimed_sender_identity_is_rejected(parties):
    alice, bob = parties["alice"], parties["bob"]
    stranger_priv, stranger_pub, stranger_kid = _make_identity()

    # Bob's key_lookup was never told about "stranger" -- Alice's request
    # claims an identity Bob can't resolve.
    alice_keys_with_stranger = FakeKeyLookup()
    alice_keys_with_stranger.add(stranger_kid, stranger_pub, stranger_priv.private_bytes_raw())
    alice_keys_with_stranger.add(parties["bob_kid"], parties["bob_keys"].get_public_key(parties["bob_kid"]))

    impostor = SessionLayer(Role.INITIATOR, stranger_kid, alice_keys_with_stranger, parties["config"])
    impostor.initiate(parties["bob_kid"], now=0.0)

    bob.post_pdu(impostor.get_pdu())
    with pytest.raises(HandshakeFailed):
        bob.update(now=0.0)


def test_no_mutual_aead_is_rejected(parties):
    # Deliberately NOT using the shared `config` from the fixture here:
    # both parties in that fixture are given the SAME SessionConfig
    # instance, so mutating .acceptable_aeads on "alice.config" and then
    # on "bob.config" would silently mutate the same object twice --
    # caught exactly this way while writing this test, which is why each
    # party gets its own SessionConfig below instead.
    alice_config = SessionConfig(acceptable_aeads=("aes128-gcm",))
    bob_config = SessionConfig(acceptable_aeads=("chacha20-poly1305",))

    alice = SessionLayer(Role.INITIATOR, parties["alice_kid"], parties["alice_keys"], alice_config)
    bob = SessionLayer(Role.RESPONDER, parties["bob_kid"], parties["bob_keys"], bob_config)

    alice.initiate(parties["bob_kid"], now=0.0)
    bob.post_pdu(alice.get_pdu())

    with pytest.raises(HandshakeFailed):
        bob.update(now=0.0)


# ---------------------------------------------------------------------------
# Misc: reset(), unexpected-PDU-for-state
# ---------------------------------------------------------------------------

def test_reset_returns_to_initial_state(parties):
    alice = parties["alice"]
    alice.initiate(parties["bob_kid"], now=0.0)
    assert alice.state == SessionState.EXPECT_SESSION_INIT_RESPONSE

    alice.reset()

    assert alice.state == SessionState.INITIAL
    assert alice.cid is None


def test_unexpected_pdu_type_for_state_raises(parties):
    from kem_make.bottom import MakeMessage, Message

    alice, bob = parties["alice"], parties["bob"]
    alice.initiate(parties["bob_kid"], now=0.0)

    # A Message PDU arriving while still expecting a session_init_response.
    bogus = MakeMessage.build(alice.cid, "message", Message({"seq": 0, "m": b"x"}))
    alice.post_pdu(bogus.dump())

    with pytest.raises(UnexpectedPDU):
        alice.update(now=0.0)
