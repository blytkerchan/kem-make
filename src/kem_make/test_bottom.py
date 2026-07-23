"""
Tests for kem_make.bottom

Covers:
  1. Basic round-trip through the versioned envelope.
  2. KEM public key / ciphertext length validation (build and load paths).
  3. Unknown-algorithm-OID rejection.
  4. KeyId: hash is over the whole KemPublicKey DER encoding, not raw key bytes.
  5. cid (correlation id) length validation.
  6. version DEFAULT(0) is omitted from the DER encoding.
  7. Optional "m" field on SessionCompletionResponse only: absent vs.
     present. SessionCompletionRequest has no such field -- c_m already
     carries the false-start payload, so a second field would duplicate
     it; a regression test confirms it stays that way. Separately,
     SessionCompletionRequest.c_m must never be empty: an empty
     ciphertext encrypts zero bytes, which is known plaintext regardless
     of key. Enforced on build(), on load(), and -- the guarantee that
     actually matters, since this type is constructed via a raw dict
     literal everywhere else in this codebase -- on dump() itself,
     regardless of how the object was constructed.
  8. AEAD negotiation: acceptable_aeads (SessionInitRequest, a list of bare
     OIDs, forward-compatible with unrecognized algorithms) and chosen_aead
     (SessionInitResponse, a single bare OID).
  9. Message: seq + payload only. No nonce field -- uniqueness now comes
     from (per-direction session key, seq), since each direction has its
     own independently derived key out of the same HKDF that produces the
     other session key material. seq alone is legitimately non-unique
     across the session (same value from each peer is expected).
  10. DER canonicality check: this is the regression test for the force=True
      bug -- a naive `obj.dump() != encoded_data` compares asn1crypto's cached
      original bytes against themselves and is a silent no-op. These tests
      fail loudly if that regresses.

Run with: pytest test_bottom.py -v
"""
# pylint: disable=missing-function-docstring, missing-class-docstring, redefined-outer-name, too-many-locals, too-many-statements, too-many-lines, duplicate-code

import hashlib
import uuid

import pytest
from asn1crypto.core import Sequence, OctetString
from asn1crypto.algos import AlgorithmIdentifier

from .bottom import (
    KemPublicKey,
    KemCiphertext,
    KeyId,
    AeadAlgorithmList,
    AEAD_OIDS,
    aead_name,
    SessionInitRequest,
    SessionInitResponse,
    SessionCompletionRequest,
    SessionCompletionResponse,
    Message,
    MakeMessage,
    MLKEM_PK_LEN,
    MLKEM_CT_LEN,
    MLKEM_OIDS,
    UnknownKemAlgorithm,
    KemLengthMismatch,
    InvalidCorrelationId,
    EmptyFalseStartPayload,
)

from .common import (
    NonCanonicalEncoding,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _pk(level=768, fill=b"\x00"):
    return KemPublicKey.build(fill * MLKEM_PK_LEN[level], level=level)


def _ct(level=768, fill=b"\x11"):
    return KemCiphertext.build(fill * MLKEM_CT_LEN[level], level=level)


# ---------------------------------------------------------------------------
# 1. Basic envelope round-trip
# ---------------------------------------------------------------------------

def test_envelope_round_trip():
    cid = uuid.uuid4()
    pk_a_star = _pk()
    pk_a_static = _pk(fill=b"\x22")
    pk_b_static = _pk(fill=b"\x33")
    ct1 = _ct()
    key_id_a = KeyId.build(pk_a_static)
    key_id_b = KeyId.build(pk_b_static)

    req = SessionInitRequest({
        "ct1": ct1,
        "key_id_b": key_id_b,
        "pk_a_star": pk_a_star,
        "key_id_a": key_id_a,
        "acceptable_aeads": AeadAlgorithmList.build(["aes256-gcm", "chacha20-poly1305"]),
    })

    msg = MakeMessage.build(cid, "session_init_request", req)
    der = msg.dump()

    parsed = MakeMessage.load(der)
    assert parsed.correlation_id == cid
    assert parsed["payload"].name == "session_init_request"
    assert parsed["payload"].chosen["ct1"]["ciphertext"].native == ct1["ciphertext"].native
    assert parsed["payload"].chosen["key_id_b"]["key_hash"].native == key_id_b["key_hash"].native
    assert parsed["payload"].chosen["acceptable_aeads"].native == [
        AEAD_OIDS["aes256-gcm"], AEAD_OIDS["chacha20-poly1305"],
    ]


# ---------------------------------------------------------------------------
# 2 & 3. KEM length / OID validation, build and load paths
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("level", [768, 1024])
def test_kem_public_key_build_accepts_correct_length(level):
    pk = KemPublicKey.build(b"\x00" * MLKEM_PK_LEN[level], level=level)
    assert len(pk["public_key"].native) == MLKEM_PK_LEN[level]


@pytest.mark.parametrize("level", [768, 1024])
def test_kem_ciphertext_build_accepts_correct_length(level):
    ct = KemCiphertext.build(b"\x00" * MLKEM_CT_LEN[level], level=level)
    assert len(ct["ciphertext"].native) == MLKEM_CT_LEN[level]


def test_kem_public_key_build_rejects_wrong_length():
    with pytest.raises(KemLengthMismatch):
        KemPublicKey.build(b"\x00" * (MLKEM_PK_LEN[768] - 1), level=768)


def test_kem_ciphertext_build_rejects_wrong_length():
    with pytest.raises(KemLengthMismatch):
        KemCiphertext.build(b"\x00" * (MLKEM_CT_LEN[768] + 1), level=768)


def test_kem_public_key_build_rejects_unsupported_level():
    with pytest.raises(UnknownKemAlgorithm):
        KemPublicKey.build(b"\x00" * 100, level=999)


def test_kem_public_key_load_rejects_truncated_key():
    pk = _pk()
    truncated = KemPublicKey({
        "algorithm": pk["algorithm"],
        "public_key": pk["public_key"].native[:-1],  # one byte short
    }).dump()
    with pytest.raises(KemLengthMismatch):
        KemPublicKey.load(truncated)


def test_kem_public_key_load_rejects_unknown_oid():
    bogus = KemPublicKey({
        "algorithm": AlgorithmIdentifier({"algorithm": "1.2.3.4.5"}),
        "public_key": b"\x00" * MLKEM_PK_LEN[768],
    }).dump()
    with pytest.raises(UnknownKemAlgorithm):
        KemPublicKey.load(bogus)


# ---------------------------------------------------------------------------
# 4. KeyId hashes the whole KemPublicKey DER encoding
# ---------------------------------------------------------------------------

def test_key_id_hashes_whole_structure_not_raw_key():
    pk = _pk()
    key_id = KeyId.build(pk)

    expected = hashlib.sha256(pk.dump()).digest()
    assert key_id["key_hash"].native == expected

    wrong = hashlib.sha256(pk["public_key"].native).digest()
    assert key_id["key_hash"].native != wrong


def test_key_id_changes_if_algorithm_differs_but_key_bytes_same():
    raw = b"\x00" * MLKEM_PK_LEN[768]
    pk_768 = KemPublicKey.build(raw, level=768)

    pk_relabeled = KemPublicKey({
        "algorithm": AlgorithmIdentifier({"algorithm": MLKEM_OIDS[1024]}),
        "public_key": raw,  # same bytes, different (bogus) algorithm label
    })

    assert KeyId.build(pk_768)["key_hash"].native != KeyId.build(pk_relabeled)["key_hash"].native


# ---------------------------------------------------------------------------
# 5. Correlation id length validation
# ---------------------------------------------------------------------------

def test_make_message_load_rejects_short_cid():
    pk = _pk()
    ct1 = _ct()
    req = SessionInitRequest({
        "ct1": ct1, "key_id_b": KeyId.build(pk), "pk_a_star": pk, "key_id_a": KeyId.build(pk),
        "acceptable_aeads": AeadAlgorithmList.build(["aes256-gcm"]),
    })

    bad = MakeMessage({
        "version": 0,
        "cid": b"\x00" * 8,  # too short: 64 bits, not 128
        "payload": ("session_init_request", req),
    }).dump()

    with pytest.raises(InvalidCorrelationId):
        MakeMessage.load(bad)


def test_make_message_build_rejects_short_cid_via_manual_construction():
    #pylint: disable=protected-access
    with pytest.raises(InvalidCorrelationId):
        MakeMessage({
            "version": 0,
            "cid": b"\x00" * 15,
            "payload": ("session_completion_response", SessionCompletionResponse({"h_m": b"x" * 32})),
        })._validate_cid()


def test_session_init_request_key_id_b_identifies_the_recipient_key_used_for_ct1():
    # key_id_b lets the recipient (Bob) pick the right private key if he
    # holds more than one, by comparing against a KeyId he computes
    # himself from each candidate public key -- it should NOT match a
    # different one of Bob's keys that ct1 wasn't actually encapsulated
    # against.
    pk_b_correct = _pk(fill=b"\x33")
    pk_b_other = _pk(fill=b"\x44")
    pk_a_star = _pk()
    ct1 = _ct()  # stands in for "encapsulated against pk_b_correct"

    req = SessionInitRequest({
        "ct1": ct1,
        "key_id_b": KeyId.build(pk_b_correct),
        "pk_a_star": pk_a_star,
        "key_id_a": KeyId.build(pk_a_star),
        "acceptable_aeads": AeadAlgorithmList.build(["aes256-gcm"]),
    })
    parsed = SessionInitRequest.load(req.dump())

    assert parsed["key_id_b"]["key_hash"].native == KeyId.build(pk_b_correct)["key_hash"].native
    assert parsed["key_id_b"]["key_hash"].native != KeyId.build(pk_b_other)["key_hash"].native


# ---------------------------------------------------------------------------
# 6. version DEFAULT(0) omission
# ---------------------------------------------------------------------------

def test_version_default_is_omitted_from_der():
    scr = SessionCompletionResponse({"h_m": b"x" * 32})
    msg_default = MakeMessage.build(uuid.uuid4(), "session_completion_response", scr, version=0)
    msg_explicit_nondefault = MakeMessage.build(uuid.uuid4(), "session_completion_response", scr, version=1)

    assert len(msg_default.dump()) < len(msg_explicit_nondefault.dump())
    assert MakeMessage.load(msg_default.dump())["version"].native == 0


# ---------------------------------------------------------------------------
# 7. Optional "m" field on SessionCompletionResponse only
#
# SessionCompletionRequest has no separate "m" field: c_m IS the
# false-start payload already, so a second field would duplicate it.
# ---------------------------------------------------------------------------

def test_session_completion_request_has_no_m_field():
    # Regression test: c_m already carries the false-start payload, so a
    # separate "m" field here would be redundant. Fails loudly if one is
    # ever reintroduced without updating this decision.
    assert [f[0] for f in SessionCompletionRequest._fields] == ["c_m", "ct4", "n_a"]


def test_session_completion_request_build_rejects_empty_c_m():
    ct4 = _ct()
    with pytest.raises(EmptyFalseStartPayload, match="known plaintext"):
        SessionCompletionRequest.build(c_m=b"", ct4=ct4, n_a=b"n" * 16)


def test_session_completion_request_dump_rejects_empty_c_m_via_raw_construction():
    # This is the real guarantee, not test_..._build_rejects_empty_c_m
    # above: SessionCompletionRequest is constructed via a raw dict
    # literal everywhere else in this codebase (tests included), not
    # exclusively through build(). dump() must catch an empty c_m
    # regardless of how the object was constructed, or "can't be sent"
    # would only hold for callers who happen to use build().
    ct4 = _ct()
    raw = SessionCompletionRequest({"c_m": b"", "ct4": ct4, "n_a": b"n" * 16})
    with pytest.raises(EmptyFalseStartPayload, match="known plaintext"):
        raw.dump()


def _dump_without_c_m_validation(c_m: bytes, ct4: "KemCiphertext", n_a: bytes) -> bytes:
    """Encode SessionCompletionRequest-shaped DER without going through
    SessionCompletionRequest.dump()'s own validation, so load()'s
    enforcement can be tested independently of dump()'s. Needed because
    dump() now validates too -- a plain SessionCompletionRequest(...).dump()
    can no longer be used to manufacture "bad" bytes for a load() test."""
    class _Unvalidated(Sequence):
        _fields = [("c_m", OctetString), ("ct4", KemCiphertext), ("n_a", OctetString)]

    return _Unvalidated({"c_m": c_m, "ct4": ct4, "n_a": n_a}).dump()


def test_session_completion_request_load_rejects_empty_c_m():
    ct4 = _ct()
    der = _dump_without_c_m_validation(b"", ct4, b"n" * 16)
    with pytest.raises(EmptyFalseStartPayload, match="known plaintext"):
        SessionCompletionRequest.load(der)


def test_session_completion_request_accepts_single_byte_c_m():
    ct4 = _ct()
    req = SessionCompletionRequest.build(c_m=b"x", ct4=ct4, n_a=b"n" * 16)
    parsed = SessionCompletionRequest.load(req.dump())
    assert parsed["c_m"].native == b"x"


def test_session_completion_response_m_absent():
    scr = SessionCompletionResponse({"h_m": b"h" * 32})
    parsed = SessionCompletionResponse.load(scr.dump())
    assert parsed["m"].native is None


def test_session_completion_response_m_present():
    scr = SessionCompletionResponse({"h_m": b"h" * 32, "m": b"early-response-data"})
    parsed = SessionCompletionResponse.load(scr.dump())
    assert parsed["m"].native == b"early-response-data"


def test_session_completion_response_m_absent_is_shorter_on_wire():
    without = SessionCompletionResponse({"h_m": b"h" * 32})
    with_m = SessionCompletionResponse({"h_m": b"h" * 32, "m": b"x"})
    assert len(without.dump()) < len(with_m.dump())


# ---------------------------------------------------------------------------
# 8. AEAD negotiation: acceptable_aeads (request) / chosen_aead (response)
# ---------------------------------------------------------------------------

def test_acceptable_aeads_round_trips_by_name():
    lst = AeadAlgorithmList.build(["aes256-gcm", "chacha20-poly1305"])
    parsed = AeadAlgorithmList.load(lst.dump())
    assert parsed.native == [AEAD_OIDS["aes256-gcm"], AEAD_OIDS["chacha20-poly1305"]]


def test_acceptable_aeads_round_trips_by_raw_oid():
    lst = AeadAlgorithmList.build([AEAD_OIDS["aes256-gcm"]])
    parsed = AeadAlgorithmList.load(lst.dump())
    assert parsed.native == [AEAD_OIDS["aes256-gcm"]]


def test_acceptable_aeads_rejects_empty_list():
    with pytest.raises(ValueError):
        AeadAlgorithmList.build([])


def test_acceptable_aeads_allows_unrecognized_oid():
    # Forward compatibility: the list is peer-advertised and may legitimately
    # contain algorithms this implementation doesn't recognize yet. This
    # must not raise.
    unregistered_but_valid_oid = "1.3.6.1.4.1.99999.1"
    lst = AeadAlgorithmList.build([unregistered_but_valid_oid])
    parsed = AeadAlgorithmList.load(lst.dump())
    assert parsed.native == [unregistered_but_valid_oid]
    assert aead_name(unregistered_but_valid_oid) is None


def test_session_init_response_chosen_aead_round_trips():
    pk = _pk()
    ct = _ct()
    resp = SessionInitResponse({
        "key_id_b": KeyId.build(pk),
        "pk_b_star": pk,
        "ct2": ct,
        "ct3": ct,
        "n_b": b"n" * 16,
        "chosen_aead": AEAD_OIDS["aes256-gcm"],
    })
    parsed = SessionInitResponse.load(resp.dump())
    assert parsed["chosen_aead"].native == AEAD_OIDS["aes256-gcm"]
    assert aead_name(parsed["chosen_aead"].native) == "aes256-gcm"


@pytest.mark.parametrize("name", ["aes256-gcm", "chacha20-poly1305"])
def test_all_known_aead_oids_round_trip(name):
    resp = SessionInitResponse({
        "key_id_b": KeyId.build(_pk()),
        "pk_b_star": _pk(),
        "ct2": _ct(),
        "ct3": _ct(),
        "n_b": b"n" * 16,
        "chosen_aead": AEAD_OIDS[name],
    })
    parsed = SessionInitResponse.load(resp.dump())
    assert aead_name(parsed["chosen_aead"].native) == name


# ---------------------------------------------------------------------------
# 9. Message: seq (per-direction, non-unique on its own) + payload
# ---------------------------------------------------------------------------

def test_message_round_trip():
    msg = Message({"seq": 1, "m": b"payload"})
    parsed = Message.load(msg.dump())
    assert parsed["seq"].native == 1
    assert parsed["m"].native == b"payload"


def test_message_requires_seq():
    with pytest.raises(Exception):
        Message({"m": b"payload"}).dump()


def test_message_requires_payload():
    with pytest.raises(Exception):
        Message({"seq": 1}).dump()


def test_message_has_no_nonce_field():
    # Nonce was removed: uniqueness now comes from (per-direction session
    # key, seq), not a per-message nonce. This test fails loudly if a
    # nonce field is ever reintroduced without updating this decision.
    assert [f[0] for f in Message._fields] == ["seq", "m"]


def test_message_same_seq_different_direction_is_permitted_by_the_structure():
    # The Message type itself does not (and should not) enforce cross-
    # direction uniqueness of seq -- each direction has its own derived
    # session key, so identical seq values from each side are expected and
    # safe, not a collision.
    msg_from_alice = Message({"seq": 5, "m": b"from alice"})
    msg_from_bob = Message({"seq": 5, "m": b"from bob"})

    assert msg_from_alice["seq"].native == msg_from_bob["seq"].native == 5
    assert msg_from_alice.dump() != msg_from_bob.dump()


@pytest.mark.parametrize("seq", [0, 1, 255, 4294967295])
def test_message_seq_various_magnitudes(seq):
    msg = Message({"seq": seq, "m": b"x"})
    parsed = Message.load(msg.dump())
    assert parsed["seq"].native == seq


# ---------------------------------------------------------------------------
# 9. DER canonicality enforcement (regression test for the force=True bug)
# ---------------------------------------------------------------------------

def test_legitimate_der_is_accepted():
    pk = _pk()
    der = pk.dump()
    KemPublicKey.load(der)  # must not raise


def test_non_minimal_length_ber_is_rejected():
    pk = _pk()
    der = pk.dump()

    assert der[1] == 0x82
    length_value = int.from_bytes(der[2:4], "big")
    padded_length = b"\x00" + length_value.to_bytes(2, "big")
    ber = der[0:1] + bytes([0x83]) + padded_length + der[4:]

    with pytest.raises(NonCanonicalEncoding):
        KemPublicKey.load(ber)


def test_canonicality_check_is_not_a_silent_noop():
    pk = _pk()
    der = pk.dump()
    loaded = KemPublicKey.load(der)

    naive_dump = loaded.dump()             # cached bytes: always equals input
    forced_dump = loaded.dump(force=True)  # re-derived from parsed values

    assert naive_dump == der   # demonstrates *why* the naive check is a no-op
    assert forced_dump == der  # and that the correct check still agrees on valid input


def test_indefinite_length_ber_fails_to_parse_at_all():
    pk = _pk()
    der = pk.dump()
    tag = der[0:1]
    content = der[2:]
    indefinite_ber = tag + b"\x80" + content + b"\x00\x00"

    with pytest.raises(Exception):
        KemPublicKey.load(indefinite_ber)
