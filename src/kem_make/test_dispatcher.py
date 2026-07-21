"""
Tests for kem_make.dispatcher.

Covers:
  1. Basic single-candidate dispatch (no forgery in play) works end to end.
  2. The actual Mallory scenario: a forged SessionInitResponse, built
     using only public information (no private key), races against the
     real responder's genuine one under the same cid. Verified both
     orderings (forged-first and real-first), since order independence
     is the whole point of forking rather than committing to whichever
     response happens to arrive first.
  3. A byte-exact duplicate SessionInitResponse does not create an extra
     fork, consistent with session.py's own dedup guarantee.
  4. The per-cid candidate cap bounds how many forks a single cid can
     accumulate.
  5. Established-session payload routing works through the dispatcher.
  6. Promotion clears every sibling fork immediately, not just on the
     next update() tick.

Run with: pytest test_dispatcher.py -v
"""

import pytest
from cryptography.hazmat.primitives.asymmetric import mlkem

from kem_make import KemPublicKey, KeyId
from kem_make.bottom import MakeMessage, SessionInitResponse, AEAD_OIDS
from kem_make.dispatcher import Dispatcher
from kem_make.candidate import CandidateStore
from kem_make.session import SessionLayer, Role, SessionState, SessionConfig, UpdateResult
import kem_make.session as session_module


class FakeKeyLookup:
    def __init__(self):
        self._pub = {}
        self._priv = {}

    def add(self, key_id, public_key, private_key=None):
        self._pub[bytes(key_id["key_hash"].native)] = public_key
        if private_key is not None:
            self._priv[bytes(key_id["key_hash"].native)] = private_key

    def get_public_key(self, key_id):
        return self._pub[bytes(key_id["key_hash"].native)]

    def get_private_key(self, key_id):
        return self._priv[bytes(key_id["key_hash"].native)]


def _make_identity():
    private = mlkem.MLKEM768PrivateKey.generate()
    public_wire = KemPublicKey.build(private.public_key().public_bytes_raw(), level=768)
    key_id = KeyId.build(public_wire)
    return private, public_wire, key_id


@pytest.fixture
def parties():
    alice_priv, alice_pub, alice_kid = _make_identity()
    bob_priv, bob_pub, bob_kid = _make_identity()

    alice_keys = FakeKeyLookup()
    alice_keys.add(alice_kid, alice_pub, alice_priv.private_bytes_raw())
    alice_keys.add(bob_kid, bob_pub)

    bob_keys = FakeKeyLookup()
    bob_keys.add(bob_kid, bob_pub, bob_priv.private_bytes_raw())
    bob_keys.add(alice_kid, alice_pub)

    return {
        "alice_pub": alice_pub, "alice_kid": alice_kid, "alice_keys": alice_keys,
        "bob_pub": bob_pub, "bob_kid": bob_kid, "bob_keys": bob_keys,
    }


def _forge_session_init_response(cid, bob_kid, alice_pub, aead="aes256-gcm"):
    """Builds a structurally valid SessionInitResponse using only PUBLIC
    information -- exactly what a forger can do without holding Bob's
    (or anyone's) private key. Mirrors _handle_session_init_request's
    encapsulation steps, but against Alice's real public keys directly
    rather than resolving them through a key lookup, since a forger has
    no private key of their own to register anywhere."""
    forger_ephemeral_priv = mlkem.MLKEM768PrivateKey.generate()
    forger_ephemeral_pub = KemPublicKey.build(
        forger_ephemeral_priv.public_key().public_bytes_raw(), level=768,
    )
    _, forged_ct2 = session_module._encapsulate(alice_pub)
    _, forged_ct3 = session_module._encapsulate(alice_pub)
    resp = SessionInitResponse({
        "key_id_b": bob_kid,
        "pk_b_star": forger_ephemeral_pub,
        "ct2": forged_ct2,
        "ct3": forged_ct3,
        "n_b": b"m" * 16,
        "chosen_aead": AEAD_OIDS[aead],
    })
    return MakeMessage.build(cid, "session_init_response", resp).dump()


def _run_bob(bob: SessionLayer, pdu: bytes, now: float):
    """Feeds a PDU to a real Bob SessionLayer, tolerating (and reporting)
    a HandshakeFailed the way a real deployment would -- Bob simply
    produces no reply for a candidate that doesn't decrypt correctly."""
    bob.post_pdu(pdu)
    try:
        bob.update(now)
    except Exception:
        return None
    return bob.get_pdu() if bob.poll_pdu() else None


# ---------------------------------------------------------------------------
# 1. Basic single-candidate dispatch
# ---------------------------------------------------------------------------

def test_full_handshake_with_no_forgery(parties):
    alice_disp = Dispatcher(parties["alice_keys"])
    bob = SessionLayer(Role.RESPONDER, parties["bob_kid"], parties["bob_keys"])

    cid = alice_disp.initiate(parties["alice_kid"], parties["bob_kid"], now=0.0)
    request = alice_disp.get_pdu()

    response = _run_bob(bob, request, now=0.0)
    alice_disp.post_pdu(response, now=0.0)
    alice_disp.update(now=0.0)

    completion_request = alice_disp.get_pdu()
    completion_response = _run_bob(bob, completion_request, now=0.0)
    alice_disp.post_pdu(completion_response, now=0.0)
    alice_disp.update(now=0.0)

    assert cid in alice_disp._established
    assert alice_disp._established[cid].state is SessionState.ESTABLISHED
    assert cid not in alice_disp._initiator_forks


# ---------------------------------------------------------------------------
# 2. The actual Mallory scenario, both orderings
# ---------------------------------------------------------------------------

def test_forged_response_first_then_real_response_still_establishes_with_bob(parties):
    alice_disp = Dispatcher(parties["alice_keys"])
    bob = SessionLayer(Role.RESPONDER, parties["bob_kid"], parties["bob_keys"])

    cid = alice_disp.initiate(parties["alice_kid"], parties["bob_kid"], now=0.0)
    request = alice_disp.get_pdu()
    real_response = _run_bob(bob, request, now=0.0)

    forged_response = _forge_session_init_response(cid, parties["bob_kid"], parties["alice_pub"])

    # Forged response arrives FIRST.
    alice_disp.post_pdu(forged_response, now=0.0)
    alice_disp.update(now=0.0)
    assert len(alice_disp._initiator_forks[cid]) == 1

    # Real response arrives second.
    alice_disp.post_pdu(real_response, now=0.0)
    alice_disp.update(now=0.0)
    assert len(alice_disp._initiator_forks[cid]) == 2

    # Drain both resulting SessionCompletionRequests through the real Bob.
    while alice_disp.poll_pdu():
        pdu = alice_disp.get_pdu()
        reply = _run_bob(bob, pdu, now=0.0)
        if reply is not None:
            alice_disp.post_pdu(reply, now=0.0)
            alice_disp.update(now=0.0)

    assert cid in alice_disp._established
    assert cid not in alice_disp._initiator_forks


def test_real_response_first_then_forged_response_still_establishes_with_bob(parties):
    # Order independence check: the forged response arriving AFTER the
    # real one, and after the real one may have already been drained
    # through completion, must not disturb the already-winning candidate.
    alice_disp = Dispatcher(parties["alice_keys"])
    bob = SessionLayer(Role.RESPONDER, parties["bob_kid"], parties["bob_keys"])

    cid = alice_disp.initiate(parties["alice_kid"], parties["bob_kid"], now=0.0)
    request = alice_disp.get_pdu()
    real_response = _run_bob(bob, request, now=0.0)

    alice_disp.post_pdu(real_response, now=0.0)
    alice_disp.update(now=0.0)

    forged_response = _forge_session_init_response(cid, parties["bob_kid"], parties["alice_pub"])
    alice_disp.post_pdu(forged_response, now=0.0)
    alice_disp.update(now=0.0)
    assert len(alice_disp._initiator_forks[cid]) == 2

    while alice_disp.poll_pdu():
        pdu = alice_disp.get_pdu()
        reply = _run_bob(bob, pdu, now=0.0)
        if reply is not None:
            alice_disp.post_pdu(reply, now=0.0)
            alice_disp.update(now=0.0)

    assert cid in alice_disp._established
    assert cid not in alice_disp._initiator_forks


def test_forger_cannot_complete_even_if_they_try_to_respond_to_their_own_fork(parties):
    # Even if the forger plays the completion-response step too, they
    # cannot produce a matching h_m: doing so requires knowing s1, which
    # requires the real Bob's static private key -- which the forger
    # never had. This is the actual cryptographic guarantee, not just
    # "Bob happens to reject it."
    alice_disp = Dispatcher(parties["alice_keys"])
    cid = alice_disp.initiate(parties["alice_kid"], parties["bob_kid"], now=0.0)
    alice_disp.get_pdu()  # the original request; irrelevant to this test

    forged_response = _forge_session_init_response(cid, parties["bob_kid"], parties["alice_pub"])
    alice_disp.post_pdu(forged_response, now=0.0)
    alice_disp.update(now=0.0)

    completion_request = alice_disp.get_pdu()

    # The forger fabricates ANY h_m -- they have no way to compute the
    # correct one without s1.
    from kem_make.bottom import SessionCompletionResponse
    fake_completion_response = MakeMessage.build(
        cid, "session_completion_response", SessionCompletionResponse({"h_m": b"\x00" * 32}),
    ).dump()

    alice_disp.post_pdu(fake_completion_response, now=0.0)
    alice_disp.update(now=0.0)

    assert cid not in alice_disp._established


# ---------------------------------------------------------------------------
# 3. Duplicate SessionInitResponse does not create an extra fork
# ---------------------------------------------------------------------------

def test_duplicate_response_does_not_create_a_second_fork(parties):
    alice_disp = Dispatcher(parties["alice_keys"])
    bob = SessionLayer(Role.RESPONDER, parties["bob_kid"], parties["bob_keys"])

    cid = alice_disp.initiate(parties["alice_kid"], parties["bob_kid"], now=0.0)
    request = alice_disp.get_pdu()
    response = _run_bob(bob, request, now=0.0)

    alice_disp.post_pdu(response, now=0.0)
    alice_disp.update(now=0.0)
    assert len(alice_disp._initiator_forks[cid]) == 1

    alice_disp.post_pdu(response, now=0.0)  # exact same bytes again
    alice_disp.update(now=0.0)
    assert len(alice_disp._initiator_forks[cid]) == 1


# ---------------------------------------------------------------------------
# 4. Per-cid candidate cap
# ---------------------------------------------------------------------------

def test_per_cid_candidate_cap_bounds_forks(parties):
    store = CandidateStore(max_per_cid=2, max_total=100)
    alice_disp = Dispatcher(parties["alice_keys"], candidate_store=store)

    cid = alice_disp.initiate(parties["alice_kid"], parties["bob_kid"], now=0.0)
    alice_disp.get_pdu()

    for _ in range(5):
        forged = _forge_session_init_response(cid, parties["bob_kid"], parties["alice_pub"])
        alice_disp.post_pdu(forged, now=0.0)
        alice_disp.update(now=0.0)

    assert len(alice_disp._initiator_forks[cid]) <= 2


# ---------------------------------------------------------------------------
# 5. Established-session payload routing
# ---------------------------------------------------------------------------

def test_established_payload_routing(parties):
    alice_disp = Dispatcher(parties["alice_keys"])
    bob = SessionLayer(Role.RESPONDER, parties["bob_kid"], parties["bob_keys"])

    cid = alice_disp.initiate(parties["alice_kid"], parties["bob_kid"], now=0.0)
    response = _run_bob(bob, alice_disp.get_pdu(), now=0.0)
    alice_disp.post_pdu(response, now=0.0)
    alice_disp.update(now=0.0)
    completion_response = _run_bob(bob, alice_disp.get_pdu(), now=0.0)
    alice_disp.post_pdu(completion_response, now=0.0)
    alice_disp.update(now=0.0)
    assert cid in alice_disp._established

    alice_disp.post_payload(cid, b"hello over an established session")
    alice_disp.update(now=0.0)
    pdu = alice_disp.get_pdu()

    bob.post_pdu(pdu)
    bob.update(now=0.0)
    assert bob.get_payload() == b"hello over an established session"


def test_post_payload_to_unknown_cid_raises(parties):
    import uuid
    from kem_make.dispatcher import DispatcherError

    alice_disp = Dispatcher(parties["alice_keys"])
    with pytest.raises(DispatcherError):
        alice_disp.post_payload(uuid.uuid4(), b"nobody home")


# ---------------------------------------------------------------------------
# 6. Promotion clears siblings immediately
# ---------------------------------------------------------------------------

def test_promotion_clears_siblings_immediately_not_next_tick(parties):
    alice_disp = Dispatcher(parties["alice_keys"])
    bob = SessionLayer(Role.RESPONDER, parties["bob_kid"], parties["bob_keys"])

    cid = alice_disp.initiate(parties["alice_kid"], parties["bob_kid"], now=0.0)
    request = alice_disp.get_pdu()
    real_response = _run_bob(bob, request, now=0.0)

    forged_response = _forge_session_init_response(cid, parties["bob_kid"], parties["alice_pub"])
    alice_disp.post_pdu(forged_response, now=0.0)
    alice_disp.update(now=0.0)
    alice_disp.post_pdu(real_response, now=0.0)
    alice_disp.update(now=0.0)
    assert len(alice_disp._initiator_forks[cid]) == 2

    for pdu in [alice_disp.get_pdu(), alice_disp.get_pdu()]:
        reply = _run_bob(bob, pdu, now=0.0)
        if reply is not None:
            alice_disp.post_pdu(reply, now=0.0)
            alice_disp.update(now=0.0)
            # The instant the winning reply is processed, siblings must
            # already be gone -- not merely "will be cleaned up later".
            if cid in alice_disp._established:
                assert cid not in alice_disp._initiator_forks


# ---------------------------------------------------------------------------
# 7. Gaps found and fixed during review: post_payload on the initiator
#    side, update()'s return contract, close(), and immediate cleanup of
#    a responder session that fails validation
# ---------------------------------------------------------------------------

def test_post_payload_before_any_response_reaches_every_future_fork(parties):
    # Real gap found during review: post_payload() only ever checked
    # _established and _responder_sessions -- an initiator-side payload
    # queued before ANY SessionInitResponse had arrived had nowhere to
    # go. Also required fork() to actually copy _pending_payload, which
    # it didn't.
    alice_disp = Dispatcher(parties["alice_keys"])
    bob = SessionLayer(Role.RESPONDER, parties["bob_kid"], parties["bob_keys"])

    cid = alice_disp.initiate(parties["alice_kid"], parties["bob_kid"], now=0.0)
    alice_disp.post_payload(cid, b"false-start, queued before any response")

    response = _run_bob(bob, alice_disp.get_pdu(), now=0.0)
    alice_disp.post_pdu(response, now=0.0)
    alice_disp.update(now=0.0)

    completion_request = alice_disp.get_pdu()
    msg = MakeMessage.load(completion_request)
    c_m = msg["payload"].chosen["c_m"].native
    assert len(c_m) > 0  # non-empty: the queued payload was actually used, not the b"" fallback

    completion_response = _run_bob(bob, completion_request, now=0.0)
    alice_disp.post_pdu(completion_response, now=0.0)
    alice_disp.update(now=0.0)
    assert cid in alice_disp._established

    # And Bob genuinely received the queued payload as the false-start message.
    assert bob.get_payload() == b"false-start, queued before any response"


def test_post_payload_reaches_already_live_forks_too(parties):
    # Not just future forks -- a payload queued while a fork already
    # exists (mid-race) must reach that fork too, not only ones spawned
    # afterward.
    alice_disp = Dispatcher(parties["alice_keys"])
    cid = alice_disp.initiate(parties["alice_kid"], parties["bob_kid"], now=0.0)
    alice_disp.get_pdu()

    forged = _forge_session_init_response(cid, parties["bob_kid"], parties["alice_pub"])
    alice_disp.post_pdu(forged, now=0.0)
    alice_disp.update(now=0.0)
    assert len(alice_disp._initiator_forks[cid]) == 1

    alice_disp.post_payload(cid, b"queued mid-race")
    live_fork = alice_disp._initiator_forks[cid][0]
    assert live_fork._pending_payload == b"queued mid-race"


def test_post_payload_to_unknown_cid_still_raises(parties):
    import uuid
    from kem_make.dispatcher import DispatcherError

    alice_disp = Dispatcher(parties["alice_keys"])
    with pytest.raises(DispatcherError):
        alice_disp.post_payload(uuid.uuid4(), b"nobody home, not even a template")


def test_update_returns_pdu_ready_when_something_is_queued(parties):
    alice_disp = Dispatcher(parties["alice_keys"])
    alice_disp.initiate(parties["alice_kid"], parties["bob_kid"], now=0.0)
    # initiate() already queued the SessionInitRequest; update() should
    # report it, matching SessionLayer.update()'s own contract.
    result, deadline = alice_disp.update(now=0.0)
    assert result == UpdateResult.PDU_READY
    assert deadline > 0.0


def test_update_returns_nothing_ready_when_idle(parties):
    alice_disp = Dispatcher(parties["alice_keys"])
    result, deadline = alice_disp.update(now=0.0)
    assert result == UpdateResult.NOTHING_READY


def test_update_deadline_reflects_the_earliest_active_session(parties):
    from kem_make.session import SessionConfig as SC

    fast_config = SC(retry_interval_seconds=1.0, max_retries=1, ttl_seconds=5.0)
    alice_disp = Dispatcher(parties["alice_keys"], config=fast_config)
    alice_disp.initiate(parties["alice_kid"], parties["bob_kid"], now=0.0)
    alice_disp.get_pdu()

    result, deadline = alice_disp.update(now=0.0)
    # The one active fork's own deadline is now (retry_interval_seconds
    # after initiate()) -- Dispatcher's aggregate deadline must reflect
    # that, not some unrelated default.
    assert deadline == pytest.approx(1.0)


def test_close_removes_an_established_session(parties):
    alice_disp = Dispatcher(parties["alice_keys"])
    bob = SessionLayer(Role.RESPONDER, parties["bob_kid"], parties["bob_keys"])

    cid = alice_disp.initiate(parties["alice_kid"], parties["bob_kid"], now=0.0)
    response = _run_bob(bob, alice_disp.get_pdu(), now=0.0)
    alice_disp.post_pdu(response, now=0.0)
    alice_disp.update(now=0.0)
    completion_response = _run_bob(bob, alice_disp.get_pdu(), now=0.0)
    alice_disp.post_pdu(completion_response, now=0.0)
    alice_disp.update(now=0.0)
    assert cid in alice_disp._established

    alice_disp.close(cid)

    assert cid not in alice_disp._established
    with pytest.raises(Exception):
        alice_disp.post_payload(cid, b"should fail, session is closed")


def test_close_on_unknown_cid_is_a_harmless_no_op(parties):
    import uuid
    alice_disp = Dispatcher(parties["alice_keys"])
    alice_disp.close(uuid.uuid4())  # must not raise


# ---------------------------------------------------------------------------
# 8. post_pdu: direct coverage of every routing branch, including the ones
#    only ever exercised incidentally (or not at all) by the scenarios above.
# ---------------------------------------------------------------------------

def test_post_pdu_silently_drops_non_canonical_der(parties):
    # Mirrors test_bottom.py's own BER-rejection regression test: a valid
    # value re-encoded with a non-minimal (long-form where short-form
    # would do) length octet is valid BER but not canonical DER, so
    # MakeMessage.load() must raise NonCanonicalEncoding -- which post_pdu
    # is documented to swallow silently, same as session.py.
    import uuid
    from kem_make.bottom import SessionCompletionResponse

    alice_disp = Dispatcher(parties["alice_keys"])
    cid = uuid.uuid4()
    der = MakeMessage.build(
        cid, "session_completion_response", SessionCompletionResponse({"h_m": b"x" * 32}),
    ).dump()
    assert der[1] < 0x80  # precondition: short-form length, so this rewrite actually changes it
    ber = der[0:1] + bytes([0x81, der[1]]) + der[2:]  # same value, long-form length

    alice_disp.post_pdu(ber, now=0.0)  # must not raise

    assert not alice_disp._established
    assert not alice_disp._responder_sessions
    assert not alice_disp._initiator_forks
    assert not alice_disp.poll_pdu()
    assert not alice_disp.poll_payload()


def test_post_pdu_silently_drops_genuinely_malformed_bytes(parties):
    # Bytes that don't even parse as a MakeMessage SEQUENCE raise a plain
    # ValueError out of asn1crypto -- not NonCanonicalEncoding or
    # InvalidCorrelationId, both of which are for input that DOES parse
    # but fails a specific, named check. post_pdu's own docstring/comment
    # promises malformed input is silently dropped, full stop.
    alice_disp = Dispatcher(parties["alice_keys"])

    alice_disp.post_pdu(b"not a valid der blob at all", now=0.0)  # must not raise

    assert not alice_disp._established
    assert not alice_disp._responder_sessions
    assert not alice_disp._initiator_forks
    assert not alice_disp.poll_pdu()
    assert not alice_disp.poll_payload()


def test_post_pdu_silently_drops_invalid_correlation_id(parties):
    from kem_make.bottom import SessionCompletionResponse

    alice_disp = Dispatcher(parties["alice_keys"])
    bad = MakeMessage({
        "version": 0,
        "cid": b"\x00" * 8,  # too short: 64 bits, not the required 128
        "payload": ("session_completion_response", SessionCompletionResponse({"h_m": b"x" * 32})),
    }).dump()

    alice_disp.post_pdu(bad, now=0.0)  # must not raise

    assert not alice_disp._established
    assert not alice_disp._responder_sessions
    assert not alice_disp._initiator_forks
    assert not alice_disp.poll_pdu()
    assert not alice_disp.poll_payload()


def test_post_pdu_drops_pdu_for_a_completely_unknown_cid(parties):
    # Well-formed PDU, but neither a session_init_request nor a
    # session_init_response, and its cid matches no established session,
    # responder session, or initiator fork -- the final fallthrough in
    # post_pdu, nothing to route to.
    import uuid
    from kem_make.bottom import SessionCompletionResponse

    alice_disp = Dispatcher(parties["alice_keys"])
    unknown_cid = uuid.uuid4()
    der = MakeMessage.build(
        unknown_cid, "session_completion_response", SessionCompletionResponse({"h_m": b"y" * 32}),
    ).dump()

    alice_disp.post_pdu(der, now=0.0)  # must not raise

    assert not alice_disp._established
    assert not alice_disp._responder_sessions
    assert not alice_disp._initiator_forks
    assert not alice_disp.poll_pdu()
    assert not alice_disp.poll_payload()


def test_post_pdu_delivers_to_an_already_established_session(parties):
    # None of the scenarios above ever feed a PDU back into a Dispatcher
    # AFTER its session for that cid reached ESTABLISHED -- so the
    # `if cid in self._established` branch at the very top of post_pdu was
    # never actually exercised. Complete a real handshake, then have Bob
    # (a raw SessionLayer) send an application message back through
    # alice_disp.post_pdu() the same way the false-start/payload tests do
    # it in the other direction.
    alice_disp = Dispatcher(parties["alice_keys"])
    bob = SessionLayer(Role.RESPONDER, parties["bob_kid"], parties["bob_keys"])

    cid = alice_disp.initiate(parties["alice_kid"], parties["bob_kid"], now=0.0)
    response = _run_bob(bob, alice_disp.get_pdu(), now=0.0)
    alice_disp.post_pdu(response, now=0.0)
    alice_disp.update(now=0.0)
    completion_response = _run_bob(bob, alice_disp.get_pdu(), now=0.0)
    alice_disp.post_pdu(completion_response, now=0.0)
    alice_disp.update(now=0.0)
    assert cid in alice_disp._established

    bob.post_payload(b"hello from an already-established session")
    bob.update(now=0.0)
    assert bob.poll_pdu()
    pdu = bob.get_pdu()

    alice_disp.post_pdu(pdu, now=0.0)  # hits the `cid in self._established` branch directly

    assert alice_disp.poll_payload()
    assert alice_disp.get_payload() == (cid, b"hello from an already-established session")


def test_post_pdu_routes_session_completion_request_to_an_existing_responder_session(parties):
    # None of the scenarios above ever run Bob's side THROUGH a Dispatcher
    # -- Bob is always a raw SessionLayer -- so the
    # `if cid in self._responder_sessions` branch (reached for a
    # session_completion_request once a responder session already exists)
    # was never covered. Run the full handshake with Bob as a Dispatcher
    # too, with Alice as a raw SessionLayer on the other side.
    bob_disp = Dispatcher(parties["bob_keys"])
    alice = SessionLayer(Role.INITIATOR, parties["alice_kid"], parties["alice_keys"])

    alice.initiate(parties["bob_kid"], now=0.0)
    cid = alice.cid
    request = alice.get_pdu()

    bob_disp.post_pdu(request, now=0.0)  # session_init_request: creates the responder session
    assert cid in bob_disp._responder_sessions
    assert bob_disp.poll_pdu()
    response = bob_disp.get_pdu()

    alice.post_pdu(response)
    alice.update(now=0.0)
    completion_request = alice.get_pdu()

    # session_completion_request, routed to the responder session that
    # already exists for this cid -- the branch under test.
    bob_disp.post_pdu(completion_request, now=0.0)

    assert cid in bob_disp._established
    assert cid not in bob_disp._responder_sessions
    assert bob_disp.poll_pdu()
    completion_response = bob_disp.get_pdu()

    alice.post_pdu(completion_response)
    alice.update(now=0.0)
    assert alice.state is SessionState.ESTABLISHED


def test_responder_session_with_unknown_claimed_identity_is_cleaned_up_immediately(parties):
    # Real gap found during review: a responder session that fails
    # validation on its FIRST message (unknown claimed identity, in this
    # case) used to sit stuck at state=INITIAL in _responder_sessions
    # until its CandidateStore entry's TTL expired, rather than being
    # discarded right away -- _reap_responder() only ever checked for
    # ESTABLISHED or DROPPED, neither of which this hits.
    from kem_make.bottom import MakeMessage, SessionInitRequest, AeadAlgorithmList, AEAD_OIDS
    from kem_make import KemPublicKey
    from cryptography.hazmat.primitives.asymmetric import mlkem

    stranger_priv, stranger_pub, stranger_kid = _make_identity()
    bob_disp = Dispatcher(parties["bob_keys"])

    ephemeral_priv = mlkem.MLKEM768PrivateKey.generate()
    ephemeral_pub = KemPublicKey.build(ephemeral_priv.public_key().public_bytes_raw(), level=768)
    _, ct1 = session_module._encapsulate(parties["bob_pub"])

    req = SessionInitRequest({
        "ct1": ct1,
        "key_id_b": parties["bob_kid"],
        "pk_a_star": ephemeral_pub,
        "key_id_a": stranger_kid,  # bob's key_lookup was never told about "stranger"
        "acceptable_aeads": AeadAlgorithmList.build(["aes256-gcm"]),
    })
    import uuid as uuid_module
    cid = uuid_module.uuid4()
    forged_request = MakeMessage.build(cid, "session_init_request", req).dump()

    bob_disp.post_pdu(forged_request, now=0.0)

    assert cid not in bob_disp._responder_sessions, (
        "a responder session that failed identity validation on its first "
        "message must be cleaned up immediately, not left stuck at INITIAL"
    )
    assert not bob_disp._candidates.candidates_for(cid)


# ---------------------------------------------------------------------------
# 9. _update_responder_sessions: both `self._candidates.discard(cid)` calls
#    carried a "#HERE: this should cause a TypeError--unit test coverage?"
#    comment, questioning whether `cid` (a uuid.UUID, not the `bytes` its
#    type hint claims) actually works there. It does: CandidateStore.discard
#    just does a dict pop, and dispatcher.py uses uuid.UUID as the key
#    consistently everywhere it touches CandidateStore, so this is a stale
#    type-hint/reality mismatch, not a live bug. Both branches below are
#    otherwise unreachable through the public post_pdu()/update() surface
#    on their own -- post_pdu() always drains a responder session's queue
#    immediately via _deliver(), so by the time the periodic crank in
#    _update_responder_sessions runs, there is normally nothing left
#    queued for session.update() to reprocess or fail on. Reached here by
#    reaching into the live SessionLayer directly, the same way a queued
#    PDU that outlived its own delivery attempt would.
# ---------------------------------------------------------------------------

def test_update_responder_sessions_handshake_failure_does_not_raise_typeerror(parties):
    from kem_make.bottom import SessionCompletionRequest, KemCiphertext, MLKEM_CT_LEN

    bob_disp = Dispatcher(parties["bob_keys"])
    alice = SessionLayer(Role.INITIATOR, parties["alice_kid"], parties["alice_keys"])
    alice.initiate(parties["bob_kid"], now=0.0)
    cid = alice.cid

    bob_disp.post_pdu(alice.get_pdu(), now=0.0)
    assert cid in bob_disp._responder_sessions
    session = bob_disp._responder_sessions[cid]

    # A structurally valid but forged SessionCompletionRequest: c_m won't
    # decrypt under the real derived key, so processing it raises
    # HandshakeFailed. Queued directly on the session (bypassing
    # Dispatcher.post_pdu's own immediate _deliver()) so it's still
    # sitting there, unprocessed, when the crank runs.
    ct4 = KemCiphertext.build(b"\x11" * MLKEM_CT_LEN[768], level=768)
    forged = SessionCompletionRequest({"c_m": b"not-a-real-ciphertext", "ct4": ct4, "n_a": b"n" * 16})
    session.post_pdu(MakeMessage.build(cid, "session_completion_request", forged).dump())

    bob_disp.update(now=0.0)  # must not raise TypeError (or anything else)

    assert cid not in bob_disp._responder_sessions
    assert not bob_disp._candidates.candidates_for(cid)


def test_update_responder_sessions_ttl_drop_does_not_raise_typeerror(parties):
    fast_config = SessionConfig(retry_interval_seconds=1.0, max_retries=1, ttl_seconds=5.0)
    bob_disp = Dispatcher(parties["bob_keys"], config=fast_config)
    alice = SessionLayer(Role.INITIATOR, parties["alice_kid"], parties["alice_keys"], fast_config)
    alice.initiate(parties["bob_kid"], now=0.0)
    cid = alice.cid

    bob_disp.post_pdu(alice.get_pdu(), now=0.0)
    assert cid in bob_disp._responder_sessions

    # Never completes; well past ttl_seconds=5.0 -- the responder's own
    # SessionLayer._on_timeout() sets state=DROPPED (no retry for a
    # responder, pure TTL), which the crank must then clean up.
    bob_disp.update(now=100.0)  # must not raise TypeError (or anything else)

    assert cid not in bob_disp._responder_sessions
    assert not bob_disp._candidates.candidates_for(cid)
