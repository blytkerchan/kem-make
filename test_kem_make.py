"""
Tests for kem_make.py.

Covers:
  1. Basic round-trip through the versioned envelope.
  2. KEM public key / ciphertext length validation (build and load paths).
  3. Unknown-algorithm-OID rejection.
  4. KeyId: hash is over the whole KemPublicKey DER encoding, not raw key bytes.
  5. cid (correlation id) length validation.
  6. version DEFAULT(0) is omitted from the DER encoding.
  7. Optional "m" field on SessionCompletionRequest / SessionCompletionResponse:
     absent vs. present.
  8. Message: seq + nonce ("n") + payload ("m"), all mandatory; nonce is
     required precisely because seq is scoped per direction and therefore
     not unique across a session on its own.
  9. DER canonicality check: this is the regression test for the force=True
     bug -- a naive `obj.dump() != encoded_data` compares asn1crypto's cached
     original bytes against themselves and is a silent no-op. These tests
     fail loudly if that regresses.
  10. Cross-validation against the independently-authored kem-make.asn1
      schema, compiled with asn1tools, confirming both describe the same
      wire format for types that don't require open-type registration.

Run with: pytest test_kem_make.py -v
"""

import uuid

import pytest

from kem_make import (
    KemPublicKey,
    KemCiphertext,
    KeyId,
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
    ct1 = _ct()
    key_id_a = KeyId.build(pk_a_star)

    req = SessionInitRequest({
        "ct1": ct1,
        "pk_a_star": pk_a_star,
        "key_id_a": key_id_a,
    })

    msg = MakeMessage.build(cid, "session_init_request", req)
    der = msg.dump()

    parsed = MakeMessage.load(der)
    assert parsed.correlation_id == cid
    assert parsed["payload"].name == "session_init_request"
    assert parsed["payload"].chosen["ct1"]["ciphertext"].native == ct1["ciphertext"].native


# ---------------------------------------------------------------------------
# 2 & 3. KEM length / OID validation, build and load paths
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("level", [512, 768, 1024])
def test_kem_public_key_build_accepts_correct_length(level):
    pk = KemPublicKey.build(b"\x00" * MLKEM_PK_LEN[level], level=level)
    assert len(pk["public_key"].native) == MLKEM_PK_LEN[level]


@pytest.mark.parametrize("level", [512, 768, 1024])
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
    from asn1crypto.algos import AlgorithmIdentifier
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
    import hashlib

    pk = _pk()
    key_id = KeyId.build(pk)

    expected = hashlib.sha256(pk.dump()).digest()
    assert key_id["key_hash"].native == expected

    wrong = hashlib.sha256(pk["public_key"].native).digest()
    assert key_id["key_hash"].native != wrong


def test_key_id_changes_if_algorithm_differs_but_key_bytes_same():
    raw = b"\x00" * MLKEM_PK_LEN[768]
    pk_768 = KemPublicKey.build(raw, level=768)

    from asn1crypto.algos import AlgorithmIdentifier
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
    req = SessionInitRequest({"ct1": ct1, "pk_a_star": pk, "key_id_a": KeyId.build(pk)})

    bad = MakeMessage({
        "version": 0,
        "cid": b"\x00" * 8,  # too short: 64 bits, not 128
        "payload": ("session_init_request", req),
    }).dump()

    with pytest.raises(InvalidCorrelationId):
        MakeMessage.load(bad)


def test_make_message_build_rejects_short_cid_via_manual_construction():
    with pytest.raises(InvalidCorrelationId):
        MakeMessage({
            "version": 0,
            "cid": b"\x00" * 15,
            "payload": ("session_completion_response", SessionCompletionResponse({"h_m": b"x" * 32})),
        })._validate_cid()


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
# 7. Optional "m" field on SessionCompletionRequest / SessionCompletionResponse
# ---------------------------------------------------------------------------

def test_session_completion_request_m_absent():
    ct4 = _ct()
    req = SessionCompletionRequest({"c_m": b"c" * 16, "ct4": ct4, "n_a": b"n" * 16})
    parsed = SessionCompletionRequest.load(req.dump())
    assert parsed["m"].native is None


def test_session_completion_request_m_present():
    ct4 = _ct()
    req = SessionCompletionRequest({
        "c_m": b"c" * 16, "ct4": ct4, "n_a": b"n" * 16, "m": b"early",
    })
    parsed = SessionCompletionRequest.load(req.dump())
    assert parsed["m"].native == b"early"


def test_session_completion_response_m_absent():
    scr = SessionCompletionResponse({"h_m": b"h" * 32})
    parsed = SessionCompletionResponse.load(scr.dump())
    assert parsed["m"].native is None


def test_session_completion_response_m_present():
    scr = SessionCompletionResponse({"h_m": b"h" * 32, "m": b"early-response-data"})
    parsed = SessionCompletionResponse.load(scr.dump())
    assert parsed["m"].native == b"early-response-data"


def test_m_absent_is_shorter_on_wire():
    ct4 = _ct()
    without = SessionCompletionRequest({"c_m": b"c" * 16, "ct4": ct4, "n_a": b"n" * 16})
    with_m = SessionCompletionRequest({
        "c_m": b"c" * 16, "ct4": ct4, "n_a": b"n" * 16, "m": b"x",
    })
    assert len(without.dump()) < len(with_m.dump())


# ---------------------------------------------------------------------------
# 8. Message: seq (per-direction, non-unique) + mandatory nonce + payload
# ---------------------------------------------------------------------------

def test_message_round_trip():
    msg = Message({"seq": 1, "n": b"\x00" * 12, "m": b"payload"})
    parsed = Message.load(msg.dump())
    assert parsed["seq"].native == 1
    assert parsed["n"].native == b"\x00" * 12
    assert parsed["m"].native == b"payload"


def test_message_requires_nonce():
    # Nonce is mandatory precisely because seq is scoped per direction and
    # is therefore not unique across the session on its own.
    with pytest.raises(Exception):
        Message({"seq": 1, "m": b"payload"}).dump()


def test_message_requires_seq():
    with pytest.raises(Exception):
        Message({"n": b"\x00" * 12, "m": b"payload"}).dump()


def test_message_requires_payload():
    with pytest.raises(Exception):
        Message({"seq": 1, "n": b"\x00" * 12}).dump()


def test_message_same_seq_different_direction_is_permitted_by_the_structure():
    # The Message type itself does not (and should not) enforce cross-
    # direction uniqueness of seq -- that's the whole reason the nonce
    # exists. Two Messages with identical seq but different nonces must
    # both be valid, independently constructible values.
    msg_from_alice = Message({"seq": 5, "n": b"\xaa" * 12, "m": b"from alice"})
    msg_from_bob = Message({"seq": 5, "n": b"\xbb" * 12, "m": b"from bob"})

    assert msg_from_alice["seq"].native == msg_from_bob["seq"].native == 5
    assert msg_from_alice.dump() != msg_from_bob.dump()


@pytest.mark.parametrize("seq", [0, 1, 255, 4294967295])
def test_message_seq_various_magnitudes(seq):
    msg = Message({"seq": seq, "n": b"\x00" * 12, "m": b"x"})
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


# ---------------------------------------------------------------------------
# 10. Cross-validation against the independently-authored ASN.1 schema
# ---------------------------------------------------------------------------

def test_schema_matches_python_classes_for_session_completion_response():
    """
    Requires asn1tools (see requirements-dev.txt). Compiles kem-make.asn1
    independently and confirms it agrees byte-for-byte with asn1crypto on
    SessionCompletionResponse, both with and without the optional "m"
    field. Skips if the schema file or asn1tools isn't available, since
    this is a dev-only cross-check, not a runtime dependency of kem_make.py.
    """
    asn1tools = pytest.importorskip("asn1tools")
    import os

    schema_path = os.path.join(os.path.dirname(__file__), "kem-make.asn1")
    if not os.path.exists(schema_path):
        pytest.skip("kem-make.asn1 not found alongside this test file")

    schema = asn1tools.compile_files([schema_path], codec="der")

    scr_absent = SessionCompletionResponse({"h_m": b"h" * 16})
    assert scr_absent.dump() == schema.encode("SessionCompletionResponse", {"hM": b"h" * 16})

    scr_present = SessionCompletionResponse({"h_m": b"h" * 16, "m": b"fs"})
    assert scr_present.dump() == schema.encode(
        "SessionCompletionResponse", {"hM": b"h" * 16, "m": b"fs"}
    )

    decoded = schema.decode("SessionCompletionResponse", scr_present.dump())
    assert decoded == {"hM": b"h" * 16, "m": b"fs"}


def test_schema_matches_python_classes_for_message():
    """
    Cross-checks the new Message type (seq, n, m) against the schema,
    since it's the newest addition and hasn't been validated this way yet.
    """
    asn1tools = pytest.importorskip("asn1tools")
    import os

    schema_path = os.path.join(os.path.dirname(__file__), "kem-make.asn1")
    if not os.path.exists(schema_path):
        pytest.skip("kem-make.asn1 not found alongside this test file")

    schema = asn1tools.compile_files([schema_path], codec="der")

    msg = Message({"seq": 42, "n": b"\x01" * 12, "m": b"payload-bytes"})
    tools_der = schema.encode("Message", {"seq": 42, "n": b"\x01" * 12, "m": b"payload-bytes"})

    assert msg.dump() == tools_der

    decoded = schema.decode("Message", msg.dump())
    assert decoded == {"seq": 42, "n": b"\x01" * 12, "m": b"payload-bytes"}
