from behave import given, when
from behave.api.pending_step import StepNotImplementedError

from kem_make.common import NonCanonicalEncoding
from kem_make.crypto_backend import create_mlkem_keypair
from kem_make.keystore import DuplicateKey, PrivateKeyRequiresPublicKey, KeyNotFound, PrivateKeyUnwrapFailed, StoredPrivateKeyEntry, StoredPrivateKeyEntry

@given(u'a valid ML-KEM-768 KemPublicKey "pk"')
def step_impl(context):
    context.pk = create_mlkem_keypair(level=768)


@given(u'"pk" has already been added as a public key, with KeyId "kid"')
def step_impl(context):
    context.kid = context.key_directory.add_public_key(context.pk[0])


@given(u'a second valid ML-KEM-768 KemPublicKey "unregistered_pk" that was never added')
def step_impl(context):
    context.unregistered_key = create_mlkem_keypair(level=768)

@when(u'I attempt to add private key bytes for "unregistered_pk"')
def step_impl(context):
    try:
        context.key_directory.add_private_key(private_key_bytes=context.unregistered_key[1], public_key=context.unregistered_key[0])
        context.add_private_key_succeeded = True
    except Exception as e:
        context.add_private_key_succeeded = False
        context.add_private_key_exception = e


@then(u'adding the private key fails with PrivateKeyRequiresPublicKey')
def step_impl(context):
    assert context.add_private_key_succeeded is False
    assert isinstance(context.add_private_key_exception, PrivateKeyRequiresPublicKey)


@when(u'I add private key bytes for "pk"')
def step_impl(context):
    try:
        context.key_directory.add_private_key(private_key_bytes=context.pk[1], public_key=context.pk[0])
        context.add_private_key_succeeded = True
    except Exception as e:
        context.add_private_key_succeeded = False
        context.add_private_key_exception = e


@then(u'the private key is added successfully')
def step_impl(context):
    assert context.add_private_key_succeeded is True


@given(u'private key bytes have already been added for "pk"')
def step_impl(context):
    context.key_directory.add_private_key(private_key_bytes=context.pk[1], public_key=context.pk[0])


@when(u'I attempt to add private key bytes for "pk" again')
def step_impl(context):
    try:
        context.key_directory.add_private_key(private_key_bytes=context.pk[1], public_key=context.pk[0])
        context.add_private_key_succeeded = True
    except Exception as e:
        context.add_private_key_succeeded = False
        context.add_private_key_exception = e


@then(u'adding the private key fails with DuplicateKey')
def step_impl(context):
    assert context.add_private_key_succeeded is False
    assert isinstance(context.add_private_key_exception, DuplicateKey)


@when(u'I retrieve the private key for "kid"')
def step_impl(context):
    context.retrieved_private_key_bytes = context.key_directory.get_private_key(context.kid)


@then(u'the retrieved bytes equal the original private key bytes for "pk"')
def step_impl(context):
    assert context.retrieved_private_key_bytes == context.pk[1]


@when(u'I attempt to retrieve the private key for "kid"')
def step_impl(context):
    try:
        context.retrieved_private_key_bytes = context.key_directory.get_private_key(context.kid)
        context.retrieve_private_key_succeeded = True
    except Exception as e:
        context.retrieve_private_key_succeeded = False
        context.retrieve_private_key_exception = e


@then(u'retrieving the private key fails with KeyNotFound')
def step_impl(context):
    assert context.retrieve_private_key_succeeded is False
    assert isinstance(context.retrieve_private_key_exception, KeyNotFound)


@given(u'a second valid ML-KEM-768 KemPublicKey "pk2", added as a public key with KeyId "kid2"')
def step_impl(context):
    context.pk2 = create_mlkem_keypair(level=768)
    context.kid2 = context.key_directory.add_public_key(context.pk2[0])


@when(u'I add private key bytes for "pk" and separately for "pk2"')
def step_impl(context):
    context.key_directory.add_private_key(private_key_bytes=context.pk[1], public_key=context.pk[0])
    context.key_directory.add_private_key(private_key_bytes=context.pk2[1], public_key=context.pk2[0])


@then(u'the two stored entries have different key-encrypting-key salts')
def step_impl(context):
    # Read the stored private key entries for both keys and compare their salts
    kid_hex_id = context.key_directory._hex_of(context.kid)
    kid2_hex_id = context.key_directory._hex_of(context.kid2)
    path1 = context.key_directory._private_path(kid_hex_id)
    path2 = context.key_directory._private_path(kid2_hex_id)
    stored_entry1 = StoredPrivateKeyEntry.load(path1.read_bytes())
    stored_entry2 = StoredPrivateKeyEntry.load(path2.read_bytes())
    assert stored_entry1['kek_salt'] != stored_entry2['kek_salt']


@then(u'both private keys still decrypt correctly and independently of one another')
def step_impl(context):
    # Retrieve both private keys and check that they match the original bytes
    retrieved_pk1 = context.key_directory.get_private_key(context.kid)
    retrieved_pk2 = context.key_directory.get_private_key(context.kid2)
    assert retrieved_pk1 == context.pk[1]
    assert retrieved_pk2 == context.pk2[1]


@when(u'I inspect the stored private key entry\'s fields for "kid"')
def step_impl(context):
    kid_hex_id = context.key_directory._hex_of(context.kid)
    path = context.key_directory._private_path(kid_hex_id)
    context.stored_entry = StoredPrivateKeyEntry.load(path.read_bytes())


@then(u'the entry has a key-encrypting-key salt, a wrap algorithm identifier, and a wrapped key')
def step_impl(context):
    assert 'kek_salt' in context.stored_entry
    assert 'wrap_algorithm' in context.stored_entry
    assert 'wrapped_key' in context.stored_entry


@given(u'a byte in the stored wrapped private key for "kid" has been flipped')
def step_impl(context):
    context.execute_steps(u'When I inspect the stored private key entry\'s fields for "kid"')
    # pick a random byte in context.stored_entry['wrapped_key'] and flip it
    import random
    wrapped_key = bytearray(context.stored_entry['wrapped_key'].native)
    index_to_flip = random.randint(0, len(wrapped_key) - 1)
    wrapped_key[index_to_flip] ^= 0xFF  # Flip all bits of the selected byte
    context.stored_entry['wrapped_key'] = bytes(wrapped_key)
    # store back to disk at the original path
    kid_hex_id = context.key_directory._hex_of(context.kid)
    path = context.key_directory._private_path(kid_hex_id)
    path.write_bytes(context.stored_entry.dump())


@then(u'retrieving the private key fails with PrivateKeyUnwrapFailed')
def step_impl(context):
    context.execute_steps(u'When I attempt to retrieve the private key for "kid"')
    assert context.retrieve_private_key_succeeded is False
    assert isinstance(context.retrieve_private_key_exception, PrivateKeyUnwrapFailed)


@given(u'the stored private key file for "kid" has been rewritten with a non-minimal-length BER encoding')
def step_impl(context):
    context.execute_steps(u'When I inspect the stored private key entry\'s fields for "kid"')
    # Re-encode the entry, then pad its outer SEQUENCE length from the
    # canonical DER short form into a non-minimal long form (BER allows
    # this; DER does not), and write the result back to disk.
    der = context.stored_entry.dump()
    assert der[1] == 0x81  # short-form length, as produced by canonical DER
    non_minimal = der[0:1] + bytes([0x82, 0x00]) + der[2:]
    kid_hex_id = context.key_directory._hex_of(context.kid)
    path = context.key_directory._private_path(kid_hex_id)
    path.write_bytes(non_minimal)


@then(u'retrieving the private key fails with NonCanonicalEncoding')
def step_impl(context):
    context.execute_steps(u'When I attempt to retrieve the private key for "kid"')
    assert context.retrieve_private_key_succeeded is False
    assert isinstance(context.retrieve_private_key_exception, NonCanonicalEncoding)
