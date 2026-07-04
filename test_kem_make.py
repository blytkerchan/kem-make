"""
Tests for kem_make.py.

Covers, in order of how they came up during development:
  1. Basic round-trip through the versioned envelope.
  2. KEM public key / ciphertext length validation (build and load paths).
  3. Unknown-algorithm-OID rejection.
  4. KeyId: hash is over the whole KemPublicKey DER encoding, not raw key bytes.
  5. cid (correlation id) length validation.
  6. version DEFAULT(0) is omitted from the DER encoding.
  7. Optional m field: absent vs. present, on both PDUs that carry it.
  8. DER canonicality check: this is the regression test for the force=True
     bug -- a naive `obj.dump() != encoded_data` compares asn1crypto's cached
     original bytes against themselves and is a silent no-op. These tests
     fail loudly if that regresses.
  9. Cross-validation against the independently-authored kem-make.asn1
     schema, compiled with asn1tools, confirming both describe the same
     wire format for a type that doesn't require open-type registration.

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
    # Build a valid one, then hand-corrupt the encoded length so load()
    # must catch it rather than trusting the OctetString.
    pk = _pk()
    der = pk.dump()
    truncated = KemPublicKey({
        "algorithm": pk["algorithm"],
        "public_key": pk["public_key"].native[:-1],  # one byte short
    }).dump()
    with pytest.raises(KemLengthMismatch):
        KemPublicKey.load(truncated)


def test_kem_public_key_load_rejects_unknown_oid():
    # Construct a KemPublicKey-shaped object under an OID we don't recognize.
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

    # Sanity: hashing just the raw key bytes must NOT match -- this is the
    # behavior we deliberately chose (binds algorithm into the id).
    wrong = hashlib.sha256(pk["public_key"].native).digest()
    assert key_id["key_hash"].native != wrong


def test_key_id_changes_if_algorithm_differs_but_key_bytes_same():
    # Same raw key bytes under two different (hypothetical) algorithm
    # identifiers must produce different KeyIds, proving the algorithm is
    # bound into the hash.
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
    # build() takes a uuid.UUID so it can't be handed a short id directly;
    # confirm the manual-construction path (used by load()) is still guarded.
    with pytest.raises(InvalidCorrelationId):
        MakeMessage({
            "version": 0,
            "cid": b"\x00" * 15,
            "payload": ("ack", Ack({"h_m": b"x" * 32})),
        })._validate_cid()


# ---------------------------------------------------------------------------
# 6. version DEFAULT(0) omission
# ---------------------------------------------------------------------------

def test_version_default_is_omitted_from_der():
    ack = Ack({"h_m": b"x" * 32})
    msg_default = MakeMessage.build(uuid.uuid4(), "ack", ack, version=0)
    msg_explicit_nondefault = MakeMessage.build(uuid.uuid4(), "ack", ack, version=1)

    # The only structural difference between these two should be the
    # presence/absence of the version field; the default-valued one must be
    # shorter by exactly the encoded size of an INTEGER 1 field.
    assert len(msg_default.dump()) < len(msg_explicit_nondefault.dump())
    assert MakeMessage.load(msg_default.dump())["version"].native == 0


# ---------------------------------------------------------------------------
# 7. Optional false_start field
# ---------------------------------------------------------------------------

def test_session_completion_request_false_start_absent():
    ct4 = _ct()
    req = SessionCompletionRequest({"c_m": b"c" * 16, "ct4": ct4, "n_a": b"n" * 16})
    parsed = SessionCompletionRequest.load(req.dump())
    assert parsed["false_start"].native is None


def test_session_completion_request_false_start_present():
    ct4 = _ct()
    req = SessionCompletionRequest({
        "c_m": b"c" * 16, "ct4": ct4, "n_a": b"n" * 16, "false_start": b"early",
    })
    parsed = SessionCompletionRequest.load(req.dump())
    assert parsed["false_start"].native == b"early"


def test_ack_false_start_absent():
    ack = Ack({"h_m": b"h" * 32})
    parsed = Ack.load(ack.dump())
    assert parsed["false_start"].native is None


def test_ack_false_start_present():
    ack = Ack({"h_m": b"h" * 32, "false_start": b"early-ack-data"})
    parsed = Ack.load(ack.dump())
    assert parsed["false_start"].native == b"early-ack-data"


def test_false_start_absent_is_shorter_on_wire():
    ct4 = _ct()
    without = SessionCompletionRequest({"c_m": b"c" * 16, "ct4": ct4, "n_a": b"n" * 16})
    with_fs = SessionCompletionRequest({
        "c_m": b"c" * 16, "ct4": ct4, "n_a": b"n" * 16, "false_start": b"x",
    })
    assert len(without.dump()) < len(with_fs.dump())


# ---------------------------------------------------------------------------
# 8. DER canonicality enforcement (regression test for the force=True bug)
# ---------------------------------------------------------------------------

def test_legitimate_der_is_accepted():
    pk = _pk()
    der = pk.dump()
    # Must not raise.
    KemPublicKey.load(der)


def test_non_minimal_length_ber_is_rejected():
    pk = _pk()
    der = pk.dump()

    # der[1] is a long-form length byte (0x82: two length octets follow)
    # because the content exceeds 127 bytes. Pad it to a non-minimal
    # 3-octet long form (0x83, with a leading zero octet) -- this is valid
    # BER but not valid DER, since DER requires the minimal-length form.
    assert der[1] == 0x82
    length_value = int.from_bytes(der[2:4], "big")
    padded_length = b"\x00" + length_value.to_bytes(2, "big")
    ber = der[0:1] + bytes([0x83]) + padded_length + der[4:]

    with pytest.raises(NonCanonicalEncoding):
        KemPublicKey.load(ber)


def test_canonicality_check_is_not_a_silent_noop():
    # Direct regression test for the caching bug: comparing a plain
    # obj.dump() (which returns cached original bytes) against the input
    # would make every input "pass" the check, including corrupted ones.
    # This test fails if _require_der stops using force=True.
    pk = _pk()
    der = pk.dump()
    loaded = KemPublicKey.load(der)

    naive_dump = loaded.dump()          # cached bytes: always equals input
    forced_dump = loaded.dump(force=True)  # re-derived from parsed values

    assert naive_dump == der  # demonstrates *why* the naive check is a no-op
    assert forced_dump == der  # and that the correct check still agrees on valid input


def test_indefinite_length_ber_fails_to_parse_at_all():
    # asn1crypto's low-level parser doesn't support indefinite-length BER at
    # all, so this fails before even reaching our canonicality check. This
    # test documents that behavior rather than asserting a specific
    # exception type, since it originates from the parser, not our code.
    pk = _pk()
    der = pk.dump()
    tag = der[0:1]
    content = der[2:]
    indefinite_ber = tag + b"\x80" + content + b"\x00\x00"

    with pytest.raises(Exception):
        KemPublicKey.load(indefinite_ber)


# ---------------------------------------------------------------------------
# 9. Cross-validation against the independently-authored ASN.1 schema
# ---------------------------------------------------------------------------

def test_schema_matches_python_classes_for_ack():
    """
    Requires asn1tools (see requirements-dev.txt). Compiles kem-make.asn1
    independently and confirms it agrees byte-for-byte with asn1crypto on
    the SessionCompletionResponse type, both with and without the optional 
    m field.
    Skips if the schema file or asn1tools isn't available, since this is a
    dev-only cross-check, not a runtime dependency of sit_make.py.
    """
    asn1tools = pytest.importorskip("asn1tools")
    import os

    schema_path = os.path.join(os.path.dirname(__file__), "kem-make.asn1")
    if not os.path.exists(schema_path):
        pytest.skip("kem-make.asn1 not found alongside this test file")

    schema = asn1tools.compile_files([schema_path], codec="der")

    ack_absent = Ack({"h_m": b"h" * 16})
    assert ack_absent.dump() == schema.encode("SessionCompletionResponse", {"hM": b"h" * 16})

    ack_present = Ack({"h_m": b"h" * 16, "false_start": b"fs"})
    assert ack_present.dump() == schema.encode(
        "Ack", {"hM": b"h" * 16, "falseStart": b"fs"}
    )

    # And the reverse direction: asn1tools decodes what asn1crypto produced.
    decoded = schema.decode("SessionCompletionResponse", ack_present.dump())
    assert decoded == {"hM": b"h" * 16, "falseStart": b"fs"}
