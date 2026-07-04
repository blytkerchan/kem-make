"""
Tests for crypto_backend.py.

The most important test here is the one that proves check_backend() is not
a silent no-op: it must actually fail when a primitive is broken, not just
succeed because the classes imported. Everything else is a straightforward
functional round trip.

Run with: pytest test_crypto_backend.py -v
"""

from unittest import mock

import pytest

import crypto_backend as cb


def test_check_backend_passes_on_a_working_installation():
    # Must not raise.
    cb.check_backend()


def test_mlkem_512_is_not_offered():
    # Deliberately dropped -- see crypto_backend.py module docstring.
    assert 512 not in cb.MLKEM_BACKEND_CLASSES
    assert set(cb.MLKEM_BACKEND_CLASSES.keys()) == {768, 1024}


@pytest.mark.parametrize("level", [768, 1024])
def test_mlkem_round_trip(level):
    cls = cb.MLKEM_BACKEND_CLASSES[level]
    priv = cls.generate()
    pub = priv.public_key()
    shared_secret, ciphertext = pub.encapsulate()
    assert priv.decapsulate(ciphertext) == shared_secret


def test_check_backend_detects_broken_mlkem_generate():
    # This is the regression test that matters: check_backend() must not
    # silently pass just because the class exists and imports cleanly.
    with mock.patch.object(
        cb.mlkem.MLKEM768PrivateKey, "generate",
        side_effect=NotImplementedError("simulated missing backend support"),
    ):
        with pytest.raises(cb.CryptoBackendUnsupported, match="ML-KEM-768"):
            cb.check_backend()


def test_check_backend_detects_mismatched_shared_secret():
    # Simulate a backend that runs without error but produces wrong output.
    #
    # MLKEM768PrivateKey is an abstract interface; .generate() returns a
    # concrete Rust-backed instance whose own decapsulate() is used, not
    # one inherited from the abstract class. Patching the abstract class's
    # method (as in test_check_backend_detects_broken_mlkem_generate, which
    # patches the classmethod generate() itself and therefore does work)
    # has no effect on decapsulate() here -- so this uses a wrapper object
    # around a real key instead of a class-level patch.
    real_key = cb.mlkem.MLKEM768PrivateKey.generate()

    class BrokenKeyWrapper:
        def public_key(self):
            return real_key.public_key()

        def decapsulate(self, ciphertext):
            real_key.decapsulate(ciphertext)  # exercise the real path
            return b"\x00" * 32  # then return garbage regardless of input

    with mock.patch.object(
        cb.mlkem.MLKEM768PrivateKey, "generate",
        classmethod(lambda cls: BrokenKeyWrapper()),
    ):
        with pytest.raises(cb.CryptoBackendUnsupported, match="mismatched shared secrets"):
            cb.check_backend()


def test_aes_gcm_round_trip():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = b"\x00" * 12
    ct = aesgcm.encrypt(nonce, b"hello", None)
    assert aesgcm.decrypt(nonce, ct, None) == b"hello"


def test_chacha20_poly1305_round_trip():
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    key = ChaCha20Poly1305.generate_key()
    chacha = ChaCha20Poly1305(key)
    nonce = b"\x00" * 12
    ct = chacha.encrypt(nonce, b"hello", None)
    assert chacha.decrypt(nonce, ct, None) == b"hello"


def test_check_backend_detects_broken_aead():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    with mock.patch.object(
        AESGCM, "encrypt", side_effect=NotImplementedError("simulated broken AEAD"),
    ):
        with pytest.raises(cb.CryptoBackendUnsupported, match="AES-128-GCM"):
            cb.check_backend()


def test_hkdf_round_trip():
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"test")
    derived = hkdf.derive(b"\x00" * 32)
    assert len(derived) == 32


def test_mlkem_ciphertext_and_key_sizes_match_fips_203_table_3():
    # Cross-check against the same constants kem_make.py relies on, so a
    # future cryptography release that changes behaviour is caught here
    # rather than only inside a live handshake.
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from kem_make import MLKEM_CT_LEN, MLKEM_PK_LEN

    for level, cls in cb.MLKEM_BACKEND_CLASSES.items():
        priv = cls.generate()
        pub = priv.public_key()
        _, ciphertext = pub.encapsulate()

        pub_bytes = pub.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)

        assert len(ciphertext) == MLKEM_CT_LEN[level], (
            f"ML-KEM-{level} ciphertext length mismatch: "
            f"cryptography gave {len(ciphertext)}, kem_make.py expects {MLKEM_CT_LEN[level]}"
        )
        assert len(pub_bytes) == MLKEM_PK_LEN[level], (
            f"ML-KEM-{level} public key length mismatch: "
            f"cryptography gave {len(pub_bytes)}, kem_make.py expects {MLKEM_PK_LEN[level]}"
        )
