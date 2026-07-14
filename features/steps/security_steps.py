from typing import Any

import asn1crypto
from behave import given, when, then
from behave.api.pending_step import StepNotImplementedError

from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from kem_make import KemPublicKey

@given(u'the ML-KEM AlgorithmIdentifier OIDs from RFC 9935')
def step_impl(_):
    # Nothing to do for this: the ML-KEM algorithm OIDs are defined in RFC 9935 and are not generated or computed by the implementation.
    pass


@given(u'the ML-KEM public key and ciphertext lengths from FIPS 203 Table 3')
def step_impl(_):
    # Nothing to do for this: the ML-KEM public key and ciphertext lengths are defined in FIPS 203 Table 3 and are not generated or computed by the implementation.
    pass

@given(u'{length} bytes of public key material for {algorithm}')
def step_impl(context: Any, length: str, algorithm: str):
    match (int(length), algorithm):
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


@when(u'I build a KemPublicKey at level {level} from that key material')
def step_impl(context: Any, level: str):
    context.kem_public_key = KemPublicKey.build(pk_bytes=context.public_key_material, level=int(level))


@then(u'the KemPublicKey is built successfully')
def step_impl(context):
    assert isinstance(context.kem_public_key, KemPublicKey)


@then(u'its algorithm OID is "{oid}"')
def step_impl(context, oid: str):
    assert context.kem_public_key["algorithm"]["algorithm"].dotted == oid


@then(u'its parameters field is absent, not NULL')
def step_impl(context):
    assert isinstance(context.kem_public_key["algorithm"]["parameters"], asn1crypto.core.Void)


@given(u'768 bytes of ciphertext material for ML-KEM-512')
def step_impl(context):
    raise StepNotImplementedError(u'Given 768 bytes of ciphertext material for ML-KEM-512')


@when(u'I build a KemCiphertext at level 512 from that ciphertext material')
def step_impl(context):
    raise StepNotImplementedError(u'When I build a KemCiphertext at level 512 from that ciphertext material')


@then(u'the KemCiphertext is built successfully')
def step_impl(context):
    raise StepNotImplementedError(u'Then the KemCiphertext is built successfully')


@given(u'{length} bytes of ciphertext material for {algorithm}')
def step_impl(context, length: str, algorithm: str):
    raise StepNotImplementedError(u'Given {length} bytes of ciphertext material for {algorithm}')


@when(u'I build a KemCiphertext at level 768 from that ciphertext material')
def step_impl(context):
    raise StepNotImplementedError(u'When I build a KemCiphertext at level 768 from that ciphertext material')


@when(u'I build a KemCiphertext at level 1024 from that ciphertext material')
def step_impl(context):
    raise StepNotImplementedError(u'When I build a KemCiphertext at level 1024 from that ciphertext material')


@when(u'I attempt to build a KemPublicKey at level 768 from that key material')
def step_impl(context):
    raise StepNotImplementedError(u'When I attempt to build a KemPublicKey at level 768 from that key material')


@then(u'a KemLengthMismatch error is raised')
def step_impl(context):
    raise StepNotImplementedError(u'Then a KemLengthMismatch error is raised')


@when(u'I attempt to build a KemCiphertext at level 768 from that ciphertext material')
def step_impl(context):
    raise StepNotImplementedError(u'When I attempt to build a KemCiphertext at level 768 from that ciphertext material')


@when(u'I attempt to build a KemPublicKey at level 999')
def step_impl(context):
    raise StepNotImplementedError(u'When I attempt to build a KemPublicKey at level 999')


@then(u'an UnknownKemAlgorithm error is raised')
def step_impl(context):
    raise StepNotImplementedError(u'Then an UnknownKemAlgorithm error is raised')


@given(u'a DER-encoded KemPublicKey whose algorithm OID is "1.2.3.4.5"')
def step_impl(context):
    raise StepNotImplementedError(u'Given a DER-encoded KemPublicKey whose algorithm OID is "1.2.3.4.5"')


@when(u'I load that KemPublicKey')
def step_impl(context):
    raise StepNotImplementedError(u'When I load that KemPublicKey')


@given(u'a valid ML-KEM-768 KemPublicKey')
def step_impl(context):
    raise StepNotImplementedError(u'Given a valid ML-KEM-768 KemPublicKey')


@given(u'its public key bytes are truncated by one byte before encoding')
def step_impl(context):
    raise StepNotImplementedError(u'Given its public key bytes are truncated by one byte before encoding')
from behave.api.pending_step import StepNotImplementedError


