import hashlib

from behave import given, when
from behave.api.pending_step import StepNotImplementedError

from kem_make.bottom import KeyId
from kem_make.crypto_backend import create_mlkem_keypair


@given(u'a valid ML-KEM-768 KemPublicKey "pkA"')
def step_impl(context):
    context.pk_a = create_mlkem_keypair(level=768)


@when(u'I build a KeyId for "pkA" using digest algorithm "sha256"')
def step_impl(context):
    context.key_id_a = KeyId.build(context.pk_a[0], digest="sha256")


@then(u'the KeyId\'s key_hash equals the sha256 digest of the DER encoding of "pkA"')
def step_impl(context):
    expected = hashlib.sha256(context.pk_a[0].dump()).digest()
    assert context.key_id_a["key_hash"].native == expected


@then(u'the KeyId\'s hash_algorithm is "sha256"')
def step_impl(context):
    assert context.key_id_a["hash_algorithm"]["algorithm"].dotted == "2.16.840.1.101.3.4.2.1"


@then(u'the KeyId\'s key_hash does not equal the sha256 digest of the raw public key bytes of "pkA"')
def step_impl(context):
    not_expected = hashlib.sha256(context.pk_a[0]["public_key"].native).digest()
    assert context.key_id_a["key_hash"].native != not_expected


@given(u'the same raw public key bytes as "pkA" re-labelled as ML-KEM-1024, called "pkA_relabelled"')
def step_impl(context):
    context.pk_a_relabelled = context.pk_a[0].copy()
    context.pk_a_relabelled["algorithm"]["algorithm"] = "2.16.840.1.101.3.4.4.3"


@when(u'I build a KeyId for "pkA_relabelled" using digest algorithm "sha256"')
def step_impl(context):
    context.key_id_a_relabelled = KeyId.build(context.pk_a_relabelled, digest="sha256")


@then(u'the two KeyIds are not equal')
def step_impl(context):
    assert context.key_id_a != context.key_id_a_relabelled
