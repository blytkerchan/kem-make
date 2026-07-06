"""
KEM-MAKE protocol message structures (DER only).

Defines the four KEM-MAKE protocol PDUs, wrapped in a versioned session
envelope carrying a 128-bit binary correlation id (cid).

Encoding rules
--------------
DER only. BER is intentionally not supported: all classes use asn1crypto's
DER-producing `.dump()` and reject non-canonical encodings on load()
because asn1crypto's core Sequence/Choice parsing is strict about definite
lengths and primitive/constructed forms as found on the wire; there is no
"lenient BER" mode enabled here. Do not add one.

Key hashing rule (see KeyId): the hash is always computed over the DER
encoding of the whole KemPublicKey SEQUENCE (algorithm + key bytes), never
over the raw key octets alone. This binds the algorithm identifier into the
key id and only requires DER's determinism -- never build the input to the
hash any other way (e.g. from a re-parsed/re-serialized copy that could in
principle take a different, still-valid BER encoding elsewhere in a mixed
toolchain).

Message sequence numbers (see Message): seq is scoped per direction (each
peer maintains its own independent counter), so the same seq value can
legitimately occur once from Alice and once from Bob within the same
session. This is safe because Alice's and Bob's session keys are
independently derived (two directional keys out of the same HKDF that
already produces the other session key material) -- so the pair
(direction key, seq) is what must be unique, not seq on its own. seq is
NOT a session-wide unique value by itself, and must not be treated as one
by any code outside this module (e.g. a replay cache keyed only by seq,
shared across both directions, would be wrong).

AEAD negotiation: SessionInitRequest advertises the initiator's acceptable
AEAD algorithms as a list of OBJECT IDENTIFIERs (not full
AlgorithmIdentifier structures -- this is capability negotiation, not the
AEAD's own per-message parameters). SessionInitResponse names the single
chosen algorithm the same way. Note that some AEAD OIDs (e.g. the AES-GCM
family per RFC 5084) require a present `parameters` field with actual
nonce/ICV-length data when used as a real AlgorithmIdentifier for
encryption -- that requirement does not apply here, since these fields
only carry the bare OID for negotiation purposes, analogous to how RFC
8103 defines SMIMECapability announcement (OID only, parameters omitted).
"""

from __future__ import annotations

import hashlib
import uuid

from asn1crypto.core import Sequence, SequenceOf, OctetString, Integer, Choice, ObjectIdentifier
from asn1crypto.algos import AlgorithmIdentifier, DigestAlgorithm


# ---------------------------------------------------------------------------
# ML-KEM algorithm identifiers (RFC 9935)
# ---------------------------------------------------------------------------

MLKEM_OIDS = {
    512: "2.16.840.1.101.3.4.4.1",
    768: "2.16.840.1.101.3.4.4.2",
    1024: "2.16.840.1.101.3.4.4.3",
}
_OID_TO_LEVEL = {v: k for k, v in MLKEM_OIDS.items()}

# FIPS 203 Table 3
MLKEM_PK_LEN = {512: 800, 768: 1184, 1024: 1568}
MLKEM_CT_LEN = {512: 768, 768: 1088, 1024: 1568}

CID_LEN = 16  # 128-bit binary UUID

# AEAD algorithm OIDs used for negotiation only (bare OID, no parameters).
# AES-GCM family: RFC 5084. ChaCha20-Poly1305: RFC 8103.
AEAD_OIDS = {
    "aes128-gcm": "2.16.840.1.101.3.4.1.6",
    "aes192-gcm": "2.16.840.1.101.3.4.1.26",
    "aes256-gcm": "2.16.840.1.101.3.4.1.46",
    "chacha20-poly1305": "1.2.840.113549.1.9.16.3.18",
}
_AEAD_OID_TO_NAME = {v: k for k, v in AEAD_OIDS.items()}


def aead_name(oid: str) -> "str | None":
    """Friendly name for a known AEAD OID, or None if unrecognized.

    Deliberately does not raise on an unrecognized OID: the acceptable-AEAD
    list is peer-supplied and may legitimately include algorithms this
    implementation doesn't know about yet (forward compatibility). Callers
    that need to reject unknown algorithms should do so explicitly at the
    point where they select/validate the chosen algorithm, not here.
    """
    return _AEAD_OID_TO_NAME.get(oid)


class UnknownKemAlgorithm(ValueError):
    pass


class KemLengthMismatch(ValueError):
    pass


class InvalidCorrelationId(ValueError):
    pass


class NonCanonicalEncoding(ValueError):
    """Raised when the input bytes parse but are not the unique DER encoding.

    DER is deterministic: for any value there is exactly one valid DER
    encoding. Re-dumping a correctly parsed object must therefore reproduce
    the input byte-for-byte. If it doesn't, the input was BER (or otherwise
    non-canonical) and must be rejected rather than silently accepted.
    """
    pass


def _require_der(cls, encoded_data: bytes, obj):
    # force=True is essential here: asn1crypto's Sequence/Choice cache the
    # original parsed bytes and hand them straight back on a plain dump(),
    # so a naive dump() vs. input comparison is a silent no-op -- it just
    # compares the cache against itself. force=True discards the cache and
    # re-derives bytes from the parsed field values, which is the actual
    # canonical DER re-encoding we need to compare against.
    rebuilt = obj.dump(force=True)
    if rebuilt != bytes(encoded_data):
        raise NonCanonicalEncoding(
            f"{cls.__name__}: input is not canonical DER (BER/non-minimal "
            f"encoding rejected)"
        )


def kem_alg(oid: str) -> AlgorithmIdentifier:
    # parameters MUST be absent for ML-KEM AlgorithmIdentifiers, not NULL.
    return AlgorithmIdentifier({"algorithm": oid})


# ---------------------------------------------------------------------------
# KEM public keys / ciphertexts, with length validation on both load and build
# ---------------------------------------------------------------------------

class KemPublicKey(Sequence):
    _fields = [
        ("algorithm", AlgorithmIdentifier),
        ("public_key", OctetString),
    ]

    def _validate_length(self):
        oid = self["algorithm"]["algorithm"].dotted
        level = _OID_TO_LEVEL.get(oid)
        if level is None:
            raise UnknownKemAlgorithm(f"unrecognized ML-KEM OID: {oid}")
        expected = MLKEM_PK_LEN[level]
        actual = len(self["public_key"].native)
        if actual != expected:
            raise KemLengthMismatch(
                f"ML-KEM-{level} public key: expected {expected} bytes, got {actual}"
            )

    @classmethod
    def load(cls, encoded_data, **kwargs):
        obj = super().load(encoded_data, **kwargs)
        _require_der(cls, encoded_data, obj)
        obj._validate_length()
        return obj

    @classmethod
    def build(cls, pk_bytes: bytes, level: int = 768) -> "KemPublicKey":
        if level not in MLKEM_OIDS:
            raise UnknownKemAlgorithm(f"unsupported ML-KEM level: {level}")
        obj = cls({
            "algorithm": kem_alg(MLKEM_OIDS[level]),
            "public_key": pk_bytes,
        })
        obj._validate_length()
        return obj


class KemCiphertext(Sequence):
    _fields = [
        ("algorithm", AlgorithmIdentifier),
        ("ciphertext", OctetString),
    ]

    def _validate_length(self):
        oid = self["algorithm"]["algorithm"].dotted
        level = _OID_TO_LEVEL.get(oid)
        if level is None:
            raise UnknownKemAlgorithm(f"unrecognized ML-KEM OID: {oid}")
        expected = MLKEM_CT_LEN[level]
        actual = len(self["ciphertext"].native)
        if actual != expected:
            raise KemLengthMismatch(
                f"ML-KEM-{level} ciphertext: expected {expected} bytes, got {actual}"
            )

    @classmethod
    def load(cls, encoded_data, **kwargs):
        obj = super().load(encoded_data, **kwargs)
        _require_der(cls, encoded_data, obj)
        obj._validate_length()
        return obj

    @classmethod
    def build(cls, ct_bytes: bytes, level: int = 768) -> "KemCiphertext":
        if level not in MLKEM_OIDS:
            raise UnknownKemAlgorithm(f"unsupported ML-KEM level: {level}")
        obj = cls({
            "algorithm": kem_alg(MLKEM_OIDS[level]),
            "ciphertext": ct_bytes,
        })
        obj._validate_length()
        return obj


# ---------------------------------------------------------------------------
# KeyId -- hash algorithm + hash of the whole KemPublicKey DER encoding
# ---------------------------------------------------------------------------

class KeyId(Sequence):
    _fields = [
        ("hash_algorithm", DigestAlgorithm),
        ("key_hash", OctetString),
    ]

    @classmethod
    def build(cls, kem_pk: KemPublicKey, digest: str = "sha256") -> "KeyId":
        digest_bytes = hashlib.new(digest, kem_pk.dump()).digest()
        return cls({
            "hash_algorithm": {"algorithm": digest},
            "key_hash": digest_bytes,
        })


# ---------------------------------------------------------------------------
# AEAD negotiation: a list of acceptable algorithms (request) or a single
# chosen one (response). Bare OIDs -- see module docstring for why.
# ---------------------------------------------------------------------------

class AeadAlgorithmList(SequenceOf):
    _child_spec = ObjectIdentifier

    @classmethod
    def build(cls, oids) -> "AeadAlgorithmList":
        """oids: iterable of dotted-string OIDs or AEAD_OIDS keys."""
        resolved = [AEAD_OIDS.get(o, o) for o in oids]
        if not resolved:
            raise ValueError("acceptable AEAD list must contain at least one OID")
        return cls([ObjectIdentifier(o) for o in resolved])


# ---------------------------------------------------------------------------
# MAKE protocol PDUs
# ---------------------------------------------------------------------------

class SessionInitRequest(Sequence):
    _fields = [
        ("ct1", KemCiphertext),
        ("key_id_b", KeyId),
        ("pk_a_star", KemPublicKey),
        ("key_id_a", KeyId),
        ("acceptable_aeads", AeadAlgorithmList),
    ]


class SessionInitResponse(Sequence):
    _fields = [
        ("key_id_b", KeyId),
        ("pk_b_star", KemPublicKey),
        ("ct2", KemCiphertext),
        ("ct3", KemCiphertext),
        ("n_b", OctetString),
        ("chosen_aead", ObjectIdentifier),
    ]


class SessionCompletionRequest(Sequence):
    _fields = [
        ("c_m", OctetString),
        ("ct4", KemCiphertext),
        ("n_a", OctetString),
        ("m", OctetString, {"implicit": 0, "optional": True}),
    ]


class SessionCompletionResponse(Sequence):
    _fields = [
        ("h_m", OctetString),
        ("m", OctetString, {"implicit": 0, "optional": True}),
    ]


class Message(Sequence):
    _fields = [
        ("seq", Integer),
        ("m", OctetString),
    ]


class MakePayload(Choice):
    _alternatives = [
        ("session_init_request", SessionInitRequest, {"implicit": 0}),
        ("session_init_response", SessionInitResponse, {"implicit": 1}),
        ("session_completion_request", SessionCompletionRequest, {"implicit": 2}),
        ("session_completion_response", SessionCompletionResponse, {"implicit": 3}),
        ("message", Message, {"implicit": 4}),
    ]


# ---------------------------------------------------------------------------
# Versioned session envelope: { version, cid, payload }
# ---------------------------------------------------------------------------

class MakeMessage(Sequence):
    _fields = [
        ("version", Integer, {"default": 0}),  # v1 == 0
        ("cid", OctetString),
        ("payload", MakePayload),
    ]

    def _validate_cid(self):
        actual = len(self["cid"].native)
        if actual != CID_LEN:
            raise InvalidCorrelationId(
                f"cid must be {CID_LEN} bytes (128-bit UUID), got {actual}"
            )

    @classmethod
    def load(cls, encoded_data, **kwargs):
        obj = super().load(encoded_data, **kwargs)
        _require_der(cls, encoded_data, obj)
        obj._validate_cid()
        return obj

    @classmethod
    def build(cls, cid: uuid.UUID, payload_name: str, payload_value, version: int = 0) -> "MakeMessage":
        obj = cls({
            "version": version,
            "cid": cid.bytes,
            "payload": MakePayload(name=payload_name, value=payload_value),
        })
        obj._validate_cid()
        return obj

    @property
    def correlation_id(self) -> uuid.UUID:
        return uuid.UUID(bytes=self["cid"].native)


# ---------------------------------------------------------------------------
# Example usage (not executed on import)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cid = uuid.uuid4()

    # Alice's ephemeral key for this session.
    pk_a_star = KemPublicKey.build(b"\x00" * MLKEM_PK_LEN[768], level=768)

    # Alice's own static public key -- key_id_a is computed from THIS, not
    # from pk_a_star, so Bob can look her up by her registered identity
    # rather than by a freshly generated, never-registered ephemeral key.
    pk_a_static = KemPublicKey.build(b"\x22" * MLKEM_PK_LEN[768], level=768)
    key_id_a = KeyId.build(pk_a_static)

    # Bob's static public key -- ct1 is encapsulated against this key.
    # key_id_b identifies which of Bob's keys it was, so Bob can pick the
    # matching private key directly instead of trying every one he holds.
    pk_b_static = KemPublicKey.build(b"\x33" * MLKEM_PK_LEN[768], level=768)
    key_id_b = KeyId.build(pk_b_static)

    ct1 = KemCiphertext.build(b"\x11" * MLKEM_CT_LEN[768], level=768)

    req = SessionInitRequest({
        "ct1": ct1,
        "key_id_b": key_id_b,
        "pk_a_star": pk_a_star,
        "key_id_a": key_id_a,
        "acceptable_aeads": AeadAlgorithmList.build(["aes256-gcm", "chacha20-poly1305"]),
    })

    msg = MakeMessage.build(cid, "session_init_request", req)
    der = msg.dump()
    print(f"cid={cid} version={msg['version'].native} bytes={len(der)}")

    parsed = MakeMessage.load(der)
    assert parsed.correlation_id == cid
    assert parsed["payload"].name == "session_init_request"
    print("round-trip OK")
