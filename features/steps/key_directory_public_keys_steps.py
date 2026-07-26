from behave.api.pending_step import StepNotImplementedError
from behave import when, then, given

from kem_make.common import NonCanonicalEncoding
from kem_make.keystore import AltIndex, AltIndexFile, DuplicateKey, KeyId, KeyNotFound, StoredPrivateKeyEntry, StoredPublicKeyEntry, _key_hash_equal


@when(u'I add "pk" as a public key')
def step_impl(context):
    try:
        context.kid = context.key_directory.add_public_key(context.pk[0])
        context.add_public_key_succeeded = True
    except Exception as e:
        context.add_public_key_exception = e
        context.add_public_key_succeeded = False


@then(u'a KeyId is returned')
def step_impl(context):
    assert isinstance(context.kid, KeyId)


@then(u'that KeyId\'s hash algorithm is SHA-256')
def step_impl(context):
    assert context.kid["hash_algorithm"]["algorithm"].dotted == "2.16.840.1.101.3.4.2.1"
    

@given(u'"pk" has already been added as a public key')
def step_impl(context):
    context.execute_steps(u'When I add "pk" as a public key')
    assert context.add_public_key_succeeded is True


@when(u'I attempt to add "pk" as a public key again')
def step_impl(context):
    context.execute_steps(u'When I add "pk" as a public key')
    assert context.add_public_key_succeeded is False


@then(u'adding the public key fails with DuplicateKey')
def step_impl(context):
    assert context.add_public_key_succeeded is False
    assert isinstance(context.add_public_key_exception, DuplicateKey)


@when(u'I retrieve the public key for "kid"')
def step_impl(context):
    context.retrieved_public_key = context.key_directory.get_public_key(context.kid)


@then(u'the retrieved key is byte-for-byte identical to "pk"')
def step_impl(context):
    assert context.retrieved_public_key.dump() == context.pk[0].dump()


@when(u'I compute the primary KeyId of "unregistered_pk" without adding it')
def step_impl(context):
    context.unregistered_kid = KeyId.build(context.unregistered_key[0], digest="sha256")


@when(u'I attempt to retrieve the public key for that KeyId')
def step_impl(context):
    try:
        context.key_directory.get_public_key(context.unregistered_kid)
        context.retrieve_unregistered_public_key_succeeded = True
    except Exception as e:
        context.retrieve_unregistered_public_key_succeeded = False
        context.retrieve_unregistered_public_key_exception = e


@then(u'retrieving the public key fails with KeyNotFound')
def step_impl(context):
    assert context.retrieve_unregistered_public_key_succeeded is False
    assert isinstance(context.retrieve_unregistered_public_key_exception, KeyNotFound)


@when(u'I read the raw bytes of the public key file for "kid" directly from disk')
def step_impl(context):
    kid_hex_id = context.key_directory._hex_of(context.kid)
    path = context.key_directory._public_path(kid_hex_id)
    stored_entry = StoredPublicKeyEntry.load(path.read_bytes())
    context.raw_public_key_bytes = stored_entry["data"]["public_key"].dump()


@then(u'those raw bytes decode as a valid public key entry without needing the passphrase')
def step_impl(context):
    public_key = context.key_directory.get_public_key(context.kid)
    assert context.raw_public_key_bytes == public_key.dump()


@when(u'I request the KeyId for "kid" under digest "sha384"')
def step_impl(context):
    context.sha384_kid = context.key_directory.key_id_for(context.kid, digest="sha384")


@then(u'a KeyId with hash algorithm SHA-384 is returned')
def step_impl(context):
    assert context.sha384_kid["hash_algorithm"]["algorithm"].dotted == "2.16.840.1.101.3.4.2.2"


@then(u'that computation is recorded so it is never repeated')
def step_impl(context):
    # For this to be true, there should be a filed called alt_index.der in the key directory, and it should contain an entry for the SHA-384 KeyId.
    alt_index_path = context.key_directory_path / "alt_index.der"
    # load with AltIndexFile
    alt_index = AltIndexFile.load(alt_index_path.read_bytes())
    entries = alt_index["entries"]
    # check that the SHA-384 KeyId is in the alt_index
    for entry in entries:
        if (
            entry["key_id"]["hash_algorithm"]["algorithm"].dotted == "2.16.840.1.101.3.4.2.2"
            and _key_hash_equal(entry["key_id"]["key_hash"].native, context.sha384_kid["key_hash"].native)
        ):
            return
    assert False, "SHA-384 KeyId not found in alt_index.der"


@given(u'the SHA-384 KeyId for "kid" has already been computed once')
def step_impl(context):
    context.execute_steps(u'When I request the KeyId for "kid" under digest "sha384"')
    context.hash_computations_before = context.key_id_build_mock.call_count


@when(u'I request the KeyId for "kid" under digest "sha384" again')
def step_impl(context):
    context.execute_steps(u'When I request the KeyId for "kid" under digest "sha384"')


@then(u'the same SHA-384 KeyId is returned')
def step_impl(context):
    # KeyId is an asn1crypto Sequence, which has no value equality (`==`
    # is identity-based here) -- and per this module's own policy, KeyId
    # comparisons must go through _key_hash_equal (constant-time) anyway,
    # never `==`.
    other = context.key_directory.key_id_for(context.kid, digest="sha384")
    assert context.sha384_kid["hash_algorithm"]["algorithm"].dotted == other["hash_algorithm"]["algorithm"].dotted
    assert _key_hash_equal(context.sha384_kid["key_hash"].native, other["key_hash"].native)


@then(u'no new hash computation occurs')
def step_impl(context):
    assert context.key_id_build_mock.call_count == context.hash_computations_before, (
        f"Expected no new hash computation (still {context.hash_computations_before}), "
        f"but KeyId.build() was called {context.key_id_build_mock.call_count} times"
    )


@when(u'I retrieve the public key using that SHA-384 KeyId directly')
def step_impl(context):
    context.retrieved_public_key = context.key_directory.get_public_key(context.sha384_kid)


def _der_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    length_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(length_bytes)]) + length_bytes


@given(u'the stored public key file for "kid" has been rewritten with a non-minimal-length BER encoding')
def step_impl(context):
    context.execute_steps(u'When I read the raw bytes of the public key file for "kid" directly from disk')
    # raw_public_key_bytes is the canonical DER of the nested public_key
    # field only (see the step above). Splice its length into a
    # non-minimal long form (valid BER, invalid DER), then rebuild the
    # enclosing `data` and entry SEQUENCE headers so the file still
    # parses -- changing one nested TLV's length changes the byte length
    # of everything that contains it.
    pk_der = context.raw_public_key_bytes
    assert pk_der[1] == 0x82  # 2-octet long-form length, as canonical DER produces for this key size
    non_minimal_pk = pk_der[0:1] + bytes([0x83, 0x00]) + pk_der[2:]  # pad to 3 length octets

    kid_hex_id = context.key_directory._hex_of(context.kid)
    path = context.key_directory._public_path(kid_hex_id)
    stored = StoredPublicKeyEntry.load(path.read_bytes())
    data = stored["data"]

    data_bytes = data.dump()
    assert data_bytes.count(pk_der) == 1
    header_len = len(data_bytes) - len(data.contents)
    data_tag, data_content = data_bytes[:1], data_bytes[header_len:]
    idx = data_content.find(pk_der)
    new_data_content = data_content[:idx] + non_minimal_pk + data_content[idx + len(pk_der):]
    new_data_bytes = data_tag + _der_length(len(new_data_content)) + new_data_content

    # The MAC is recomputed over this same (semantically unchanged) data
    # -- see _mac_public_key_data, which always MACs the canonical
    # re-derived DER of `data`, not whatever bytes happen to be cached on
    # it. So this reproduces the same tag either way; recomputing it
    # explicitly just keeps this step honest about what it's asserting:
    # a legitimately-MAC'd entry whose *encoding* (not its integrity) is
    # non-canonical, isolating the DER check from the MAC check.
    mac_salt = stored["mac_salt"].native
    stored["mac_tag"] = context.key_directory._mac_public_key_data(data, mac_salt, kid_hex_id)

    outer_content = new_data_bytes + stored["mac_salt"].dump() + stored["mac_tag"].dump()
    tampered = path.read_bytes()[:1] + _der_length(len(outer_content)) + outer_content
    path.write_bytes(tampered)


@when(u'I attempt to retrieve the public key for "kid"')
def step_impl(context):
    try:
        context.key_directory.get_public_key(context.kid)
        context.retrieve_public_key_succeeded = True
    except Exception as e:
        context.retrieve_public_key_succeeded = False
        context.retrieve_public_key_exception = e

@then(u'retrieving the public key fails with NonCanonicalEncoding')
def step_impl(context):
    assert not context.retrieve_public_key_succeeded
    assert isinstance(context.retrieve_public_key_exception, NonCanonicalEncoding)
