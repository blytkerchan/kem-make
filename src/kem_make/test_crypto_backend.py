"""
Tests for crypto_backend.py.

The most important test here is the one that proves check_backend() is not
a silent no-op: it must actually fail when a primitive is broken, not just
succeed because the classes imported. Everything else is a straightforward
functional round trip.

Run with: pytest test_crypto_backend.py -v
"""
#pylint: disable=missing-function-docstring, missing-class-docstring, redefined-outer-name, too-many-locals, too-many-statements, too-many-lines, duplicate-code
import runpy
from unittest import mock

import pytest

import kem_make.crypto_backend as cb


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
    #pylint: disable=import-outside-toplevel
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = b"\x00" * 12
    ct = aesgcm.encrypt(nonce, b"hello", None)
    assert aesgcm.decrypt(nonce, ct, None) == b"hello"


def test_chacha20_poly1305_round_trip():
    #pylint: disable=import-outside-toplevel
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    key = ChaCha20Poly1305.generate_key()
    chacha = ChaCha20Poly1305(key)
    nonce = b"\x00" * 12
    ct = chacha.encrypt(nonce, b"hello", None)
    assert chacha.decrypt(nonce, ct, None) == b"hello"


@pytest.mark.parametrize(
    "cls, key_kwargs",
    [
        (cb.AESGCM, {"bit_length": 256}),
        (cb.ChaCha20Poly1305, {}),
    ],
)
def test_check_aead_passes_for_real_backends(cls, key_kwargs):
    # Must not raise for either AEAD this layer relies on.
    cb._check_aead(cls.__name__, cls, key_kwargs) #pylint: disable=protected-access


def test_check_aead_wraps_round_trip_exception():
    class BrokenAEAD:
        @classmethod
        def generate_key(cls):
            return b"\x00" * 32

        def __init__(self, key):
            pass

        def encrypt(self, nonce, pt, aad):
            raise NotImplementedError("simulated broken AEAD")

    with pytest.raises(cb.CryptoBackendUnsupported, match="fake-aead"):
        cb._check_aead("fake-aead", BrokenAEAD, {}) #pylint: disable=protected-access


def test_check_aead_detects_mismatched_plaintext():
    # Simulate a backend that runs without error but silently corrupts data
    # -- the same "ran clean but wrong" class of bug the mismatched-
    # shared-secret ML-KEM test guards against.
    class LyingAEAD:
        @classmethod
        def generate_key(cls):
            return b"\x00" * 32

        def __init__(self, key):
            pass

        def encrypt(self, nonce, pt, aad):
            #pylint: disable=unused-argument
            return b"ciphertext"

        def decrypt(self, nonce, ct, aad):
            #pylint: disable=unused-argument
            return b"not-the-plaintext"

    with pytest.raises(cb.CryptoBackendUnsupported, match="mismatched plaintext"):
        cb._check_aead("fake-aead", LyingAEAD, {}) #pylint: disable=protected-access


def test_check_aead_passes_key_kwargs_through_to_generate_key():
    calls = []

    class RecordingAEAD:
        @classmethod
        def generate_key(cls, **kwargs):
            calls.append(kwargs)
            return b"\x00" * 32

        def __init__(self, key):
            pass

        def encrypt(self, nonce, pt, aad):
            #pylint: disable=unused-argument
            return pt

        def decrypt(self, nonce, ct, aad):
            #pylint: disable=unused-argument
            return ct

    cb._check_aead("fake-aead", RecordingAEAD, {"bit_length": 256}) #pylint: disable=protected-access

    assert calls == [{"bit_length": 256}]


def test_check_backend_detects_broken_aead():
    #pylint: disable=import-outside-toplevel
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    with mock.patch.object(
        AESGCM, "encrypt", side_effect=NotImplementedError("simulated broken AEAD"),
    ):
        with pytest.raises(cb.CryptoBackendUnsupported, match="AES-256-GCM"):
            cb.check_backend()


def test_hkdf_round_trip():
    #pylint: disable=import-outside-toplevel
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"test")
    derived = hkdf.derive(b"\x00" * 32)
    assert len(derived) == 32


def test_check_hkdf_wraps_round_trip_exception():
    with mock.patch.object(
        cb.HKDF, "derive",
        side_effect=NotImplementedError("simulated broken HKDF"),
    ):
        with pytest.raises(cb.CryptoBackendUnsupported, match="HKDF-SHA256 failed"):
            cb._check_hkdf() #pylint: disable=protected-access


def test_check_hkdf_detects_wrong_output_length():
    with mock.patch.object(cb.HKDF, "derive", return_value=b"\x00" * 16):
        with pytest.raises(
            cb.CryptoBackendUnsupported,
            match=r"HKDF-SHA256 returned 16 bytes, expected 32",
        ):
            cb._check_hkdf() #pylint: disable=protected-access


def test_mlkem_ciphertext_and_key_sizes_match_fips_203_table_3():
    # Cross-check against the same constants kem_make.py relies on, so a
    # future cryptography release that changes behaviour is caught here
    # rather than only inside a live handshake.
    #pylint: disable=import-outside-toplevel
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from kem_make.bottom import MLKEM_CT_LEN, MLKEM_PK_LEN

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


def test_main_block_runs_check_backend_and_prints_summary(capsys):
    # runpy.run_path re-executes the file's source with __name__ set to
    # "__main__", in-process -- so it actually exercises the `if __name__
    # == "__main__":` block (a real check_backend() call followed by the
    # summary print) and, unlike a subprocess.run() invocation, is visible
    # to coverage.py since it runs under the same interpreter/trace hook
    # as the rest of the test suite.
    runpy.run_path(cb.__file__, run_name="__main__")

    out = capsys.readouterr().out
    assert "Crypto backend check passed" in out
    assert "ML-KEM-768" in out
    assert "ML-KEM-1024" in out
    assert "AES-GCM" in out
    assert "ChaCha20-Poly1305" in out
    assert "HKDF-SHA256" in out
