from typing import Any, Sequence

import asn1crypto
from behave import given, when, then
from behave.api.pending_step import StepNotImplementedError

from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from kem_make import KemPublicKey, KemCiphertext, KemLengthMismatch, UnknownKemAlgorithm

from asn1crypto.core import Sequence, SequenceOf, OctetString, Integer, Choice, ObjectIdentifier
from asn1crypto.algos import AlgorithmIdentifier, DigestAlgorithm

from kem_make.bottom import kem_alg


class FakeKemPublicKey(Sequence):
    """Fake ASN.1 structure for a KEM public key, used for testing purposes.
    This class has the same fields but none of the validations of the real KemPublicKey class, so it can be used to create invalid test cases.
    """
    _fields = [
        ("algorithm", AlgorithmIdentifier),
        ("public_key", OctetString),
    ]

    @classmethod
    def load(cls, encoded_data, **kwargs):
        obj = super().load(encoded_data, **kwargs)
        return obj

    @classmethod
    def build(cls, pk_bytes: bytes, oid) -> "FakeKemPublicKey":
        obj = cls({
            "algorithm": AlgorithmIdentifier({"algorithm": oid}),
            "public_key": pk_bytes,
        })
        return obj


@given(u'the ML-KEM AlgorithmIdentifier OIDs from RFC 9935')
def step_impl(_):
    # Nothing to do for this: the ML-KEM algorithm OIDs are defined in RFC 9935 and are not generated or computed by the implementation.
    pass


@given(u'the ML-KEM public key and ciphertext lengths from FIPS 203 Table 3')
def step_impl(_):
    # Nothing to do for this: the ML-KEM public key and ciphertext lengths are defined in FIPS 203 Table 3 and are not generated or computed by the implementation.
    pass

@given(u'{length:d} bytes of public key material for {algorithm}')
def step_impl(context: Any, length: int, algorithm: str):
    match (length, algorithm):
        case (1184, "ML-KEM-768"):
            # This is the correct length for ML-KEM-768 public key material.
            context.public_key_material = mlkem.MLKEM768PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            assert len(context.public_key_material) == 1184
        case (1568, "ML-KEM-1024"):
            # This is the correct length for ML-KEM-1024 public key material.
            context.public_key_material = mlkem.MLKEM1024PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            assert len(context.public_key_material) == 1568
        case _:
            # This is a negative test case: the length is not correct for any of the ML-KEM levels.
            context.public_key_material = b"\x00" * int(length)


@when(u'I build a KemPublicKey at level {level:d} from that key material')
def step_impl(context: Any, level: int):
    context.it_ = KemPublicKey.build(pk_bytes=context.public_key_material, level=level)


@then(u'the KemPublicKey is built successfully')
def step_impl(context):
    assert isinstance(context.it_, KemPublicKey)


@then(u'its algorithm OID is "{oid}"')
def step_impl(context, oid: str):
    assert context.it_["algorithm"]["algorithm"].dotted == oid


@then(u'its parameters field is absent, not NULL')
def step_impl(context):
    assert isinstance(context.it_["algorithm"]["parameters"], asn1crypto.core.Void)


@given(u'768 bytes of ciphertext material for ML-KEM-512')
def step_impl(context):
    raise StepNotImplementedError(u'Given 768 bytes of ciphertext material for ML-KEM-512')


@when(u'I build a KemCiphertext at level 512 from that ciphertext material')
def step_impl(context):
    raise StepNotImplementedError(u'When I build a KemCiphertext at level 512 from that ciphertext material')


@then(u'the KemCiphertext is built successfully')
def step_impl(context):
    assert isinstance(context.it_, KemCiphertext)


@given(u'{length:d} bytes of ciphertext material for {algorithm}')
def step_impl(context, length: int, algorithm: str):
    match (length, algorithm):
        case (1088, "ML-KEM-768"):
            # This is the correct length for ML-KEM-768 ciphertext material.
            (_, context.ciphertext_material) = mlkem.MLKEM768PrivateKey.generate().public_key().encapsulate()
            assert len(context.ciphertext_material) == 1088
        case (1568, "ML-KEM-1024"):
            # This is the correct length for ML-KEM-1024 ciphertext material.
            (_, context.ciphertext_material) = mlkem.MLKEM1024PrivateKey.generate().public_key().encapsulate()
            assert len(context.ciphertext_material) == 1568
        case _:
            # This is a negative test case: the length is not correct for any of the ML-KEM levels.
            context.ciphertext_material = b"\x00" * int(length)


@when(u'I build a KemCiphertext at level {level:d} from that ciphertext material')
def step_impl(context, level: int):
    context.it_ = KemCiphertext.build(ct_bytes=context.ciphertext_material, level=level)


@when(u'I attempt to build a KemPublicKey at level {level:d} from that key material')
def step_impl(context, level: int):
    try :
        context.it_ = KemPublicKey.build(pk_bytes=context.public_key_material, level=level)
    except KemLengthMismatch as e:
        context.kem_length_mismatch_error = e


@then(u'a KemLengthMismatch error is raised')
def step_impl(context):
    assert context.kem_length_mismatch_error is not None, "Expected a KemLengthMismatch error to be raised, but no error was raised."


@when(u'I attempt to build a KemCiphertext at level {level:d} from that ciphertext material')
def step_impl(context, level: int):
    try:
        context.it_ = KemCiphertext.build(ct_bytes=context.ciphertext_material, level=level)
    except KemLengthMismatch as e:
        context.kem_length_mismatch_error = e


@when(u'I attempt to build a KemPublicKey at level {level:d}')
def step_impl(context, level: int):
    try:
        context.it_ = KemPublicKey.build(pk_bytes=b'\000', level=level)
    except UnknownKemAlgorithm as e:
        context.unknown_kem_algorithm_error = e


@then(u'an UnknownKemAlgorithm error is raised')
def step_impl(context):
    assert context.unknown_kem_algorithm_error is not None, "Expected an UnknownKemAlgorithm error to be raised, but no error was raised."


@given(u'a DER-encoded KemPublicKey whose algorithm OID is "{oid}"')
def step_impl(context, oid):
    # This is a negative test case: the algorithm OID is not one of the ML-KEM OIDs defined in RFC 9935.
    context.der_encoded_kem_public_key = FakeKemPublicKey.build(pk_bytes=b'\000', oid=oid).dump()


@when(u'I load that KemPublicKey')
def step_impl(context):
    try:
        context.it_ = KemPublicKey.load(context.der_encoded_kem_public_key)
    except UnknownKemAlgorithm as e:
        context.unknown_kem_algorithm_error = e
    except KemLengthMismatch as e:
        context.kem_length_mismatch_error = e


@given(u'a valid ML-KEM-768 KemPublicKey')
def step_impl(context):
    context.public_key_material = mlkem.MLKEM768PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


@given(u'its public key bytes are truncated by one byte before encoding')
def step_impl(context):
    context.der_encoded_kem_public_key = FakeKemPublicKey.build(pk_bytes=context.public_key_material[:-1], oid="2.16.840.1.101.3.4.4.2").dump()  # Remove the last byte to truncate

