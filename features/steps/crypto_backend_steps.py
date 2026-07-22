from unittest import mock
from behave import when, then, given
from behave.api.pending_step import StepNotImplementedError

from kem_make.crypto_backend import CryptoBackendUnsupported, check_backend, MLKEM_BACKEND_CLASSES, AEAD_BACKEND_CLASSES

@given(u'a working cryptography backend')
def step_impl(context):
    pass  # This step is just a precondition and does not require implementation


@when(u'I run the crypto backend check')
def step_impl(context):
    try:
        check_backend()
        context.check_result = True
    except Exception as e:
        context.check_result = False
        context.check_exception = e


@then(u'the check passes without raising')
def step_impl(context):
    assert context.check_result, "Crypto backend check did not pass"


@when(u'I generate an ML-KEM-{level:d} key pair')
def step_impl(context, level: int):
    if level not in MLKEM_BACKEND_CLASSES:
        raise ValueError(f"ML-KEM-{level} is not supported by this crypto backend.")
    private_key_cls = MLKEM_BACKEND_CLASSES[level]
    context.private_key = private_key_cls.generate()
    context.public_key = context.private_key.public_key()


@when(u'I encapsulate against its public key')
def step_impl(context):
    context.shared_secret, context.ciphertext = context.public_key.encapsulate()
    

@when(u'I decapsulate the resulting ciphertext with its private key')
def step_impl(context):
    context.decapsulated_shared_secret = context.private_key.decapsulate(context.ciphertext)


@then(u'the decapsulated shared secret equals the encapsulated one')
def step_impl(context):
    assert context.shared_secret == context.decapsulated_shared_secret, (
        "Decapsulated shared secret does not match the encapsulated one."
    )


@then(u'ML-KEM-512 is not among the levels the crypto backend check covers')
def step_impl(context):
    assert 512 not in MLKEM_BACKEND_CLASSES, "ML-KEM-512 should not be supported by this crypto backend."


@then(u'exactly ML-KEM-768 and ML-KEM-1024 are covered')
def step_impl(context):
    assert set(MLKEM_BACKEND_CLASSES.keys()) == {768, 1024}, "Exactly ML-KEM-768 and ML-KEM-1024 should be supported by this crypto backend."


@given(u'ML-KEM-768 key generation is broken on this backend')
def step_impl(context):
    patcher = mock.patch.object(
        MLKEM_BACKEND_CLASSES[768], "generate",
        side_effect=NotImplementedError("simulated missing backend support"),
    )
    patcher.start()
    context.add_cleanup(patcher.stop)


@then(u'the check fails with CryptoBackendUnsupported')
def step_impl(context):
    assert not context.check_result, "Crypto backend check did not fail as expected"
    assert isinstance(context.check_exception, CryptoBackendUnsupported), (
        "Expected CryptoBackendUnsupported, got "
        f"{type(context.check_exception).__name__}"
    )


@then(u'the failure message names "ML-KEM-768"')
def step_impl(context):
    assert "ML-KEM-768" in str(context.check_exception), (
        'Failure message does not mention "ML-KEM-768"'
    )
    

@given(u'ML-KEM-768 decapsulation silently returns the wrong shared secret on this backend')
def step_impl(context):
    # MLKEM768PrivateKey is an abstract interface; .generate() returns a
    # concrete Rust-backed instance whose own decapsulate() is used, not one
    # inherited from the abstract class -- so patching decapsulate() on the
    # class itself has no effect. Wrap a real key instead: delegate
    # public_key() to it (so encapsulate() still works normally) but have
    # decapsulate() exercise the real path and then return garbage anyway.
    real_key = MLKEM_BACKEND_CLASSES[768].generate()

    class BrokenKeyWrapper:
        def public_key(self):
            return real_key.public_key()

        def decapsulate(self, ciphertext):
            real_key.decapsulate(ciphertext)
            return b"\x00" * 32

    patcher = mock.patch.object(
        MLKEM_BACKEND_CLASSES[768], "generate",
        classmethod(lambda cls: BrokenKeyWrapper()),
    )
    patcher.start()
    context.add_cleanup(patcher.stop)


@then(u'the failure message mentions mismatched shared secrets')
def step_impl(context):
    assert "mismatched shared secrets" in str(context.check_exception), (
        'Failure message does not mention "mismatched shared secrets"'
    )


@when(u'I encrypt "capability-check" under {algorithm}')
def step_impl(context, algorithm):
    backend = AEAD_BACKEND_CLASSES.get(algorithm)
    if backend is None:
        raise ValueError(f"AEAD algorithm {algorithm} is not supported by this crypto backend.")
    key_kwargs = {"bit_length": 256} if algorithm == "AES-256-GCM" else {} # ChaCha20-Poly1305 does not take bit_length
    context.aead_key = backend.generate_key(**key_kwargs)
    context.aead = backend(context.aead_key)
    context.nonce = b"\x00" * 12 # Both AEADs use a 12-byte (96-bit) nonce
    context.plaintext = b"capability-check"
    context.ciphertext = context.aead.encrypt(context.nonce, context.plaintext, None)
    

@when(u'I decrypt the resulting ciphertext under the same key')
def step_impl(context):
    context.decrypted_plaintext = context.aead.decrypt(context.nonce, context.ciphertext, None)


@then(u'the decrypted plaintext equals "capability-check"')
def step_impl(context):
    assert context.decrypted_plaintext == b"capability-check", (
        'Decrypted plaintext does not equal "capability-check"'
    )


@given(u'AES-256-GCM encryption is broken on this backend')
def step_impl(context):
    patcher = mock.patch.object(
        AEAD_BACKEND_CLASSES["AES-256-GCM"], "encrypt",
        side_effect=NotImplementedError("simulated broken AEAD"),
    )
    patcher.start()
    context.add_cleanup(patcher.stop)


@then(u'the failure message names "AES-256-GCM"')
def step_impl(context):
    assert "AES-256-GCM" in str(context.check_exception), (
        'Failure message does not mention "AES-256-GCM"'
    )


@then(u'exactly AES-256-GCM and ChaCha20-Poly1305 are the AEAD algorithms the crypto backend check covers')
def step_impl(context):
    # AEAD_BACKEND_CLASSES isn't actually consulted by check_backend() --
    # it hardcodes its own two _check_aead() calls -- so asserting on that
    # dict alone wouldn't prove anything about what the check covers.
    # Patch _check_aead to record which algorithm names check_backend()
    # actually invokes it with.
    covered = []
    with mock.patch(
        "kem_make.crypto_backend._check_aead",
        side_effect=lambda name, cls, key_kwargs: covered.append(name),
    ):
        check_backend()

    assert set(covered) == {"AES-256-GCM", "ChaCha20-Poly1305"}, (
        f"Expected exactly AES-256-GCM and ChaCha20-Poly1305 to be checked, got {covered}"
    )


@when(u'I derive a 32-byte key with {profile}')
def step_impl(context, profile):
    if profile not in ["HKDF-SHA256"]:
        raise ValueError(f"HKDF profile {profile} is not supported by this crypto backend.")
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"capability-check",
    )
    context.derived_key = hkdf.derive(b"\x00" * 32)


@then(u'the derived key is exactly 32 bytes long')
def step_impl(context):
    assert len(context.derived_key) == 32, (
        f"Derived key length is {len(context.derived_key)}, expected 32"
    )
    

@given(u'AES-256-GCM encryption is also broken on this backend')
def step_impl(context):
    context.execute_steps(u'''
        Given AES-256-GCM encryption is broken on this backend
    ''')


@then(u'the failure message names "ML-KEM-768", not "AES-256-GCM"')
def step_impl(context):
    assert "ML-KEM-768" in str(context.check_exception), (
        'Failure message does not mention "ML-KEM-768"'
    )
    assert "AES-256-GCM" not in str(context.check_exception), (
        'Failure message should not mention "AES-256-GCM"'
    )


@when(u'I generate an ML-KEM-{length:d} key pair and encapsulate against it')
def step_impl(context, length: int):
    context.execute_steps(u'''
        When I generate an ML-KEM-{length} key pair
        And I encapsulate against its public key
    '''.format(length=length))


@then(u'the raw public key is {length:d} bytes long')
def step_impl(context, length: int):
    assert len(context.public_key.public_bytes_raw()) == length, (
        f"Raw public key length is {len(context.public_key.public_bytes_raw())}, expected {length}"
    )


@then(u'the ciphertext is {length:d} bytes long')
def step_impl(context, length: int):
    assert len(context.ciphertext) == length, (
        f"Ciphertext length is {len(context.ciphertext)}, expected {length}"
    )
