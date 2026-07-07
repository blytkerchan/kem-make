"""
Runtime capability check for the KEM-MAKE crypto backend.

requirements.txt can pin cryptography's *version*, but it cannot assert
which backend (OpenSSL, AWS-LC, BoringSSL) a given installed wheel was
actually built against, nor guarantee a source build was linked against a
new-enough OpenSSL. ML-KEM support depends on that backend, not just the
version number. Pinning cryptography==49.0.0 in requirements.txt is
necessary (it's the release where the standard PyPI wheels bundle OpenSSL
3.5+, which is what makes ML-KEM available without a custom AWS-LC/
BoringSSL build) but not sufficient on its own -- an unusual platform,
a musl/Alpine build, a vendored older OpenSSL, or a future release that
changes wheel bundling could all silently drop this support.

check_backend() performs an actual functional round trip (generate,
encapsulate/encrypt, decapsulate/decrypt) for every primitive KEM-MAKE
needs, rather than just checking that the classes are importable --
import success alone doesn't guarantee the backend can actually execute
the operation. Call this once at application startup; it's cheap (a few
milliseconds) and turns a silent, hard-to-diagnose failure deep in a
handshake into an immediate, actionable error before any session traffic
flows.

ML-KEM-512 is deliberately not checked or supported here: it's absent
from pyca/cryptography's mlkem module (only MLKEM768PrivateKey and
MLKEM1024PrivateKey exist), consistent with its being dropped from other
recent implementations (e.g. Go's standard library crypto/mlkem) due to
lack of real-world deployment. If kem_make.py's MLKEM_OIDS still lists
512, that level cannot be backed by this crypto layer.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


class CryptoBackendUnsupported(RuntimeError):
    """Raised when the installed cryptography backend can't do something
    KEM-MAKE's crypto layer needs, even though the package imported fine."""
    pass


# Levels actually usable by this crypto layer. 512 is intentionally absent --
# see module docstring.
MLKEM_BACKEND_CLASSES = {
    768: mlkem.MLKEM768PrivateKey,
    1024: mlkem.MLKEM1024PrivateKey,
}


def _check_mlkem(level: int, private_key_cls) -> None:
    try:
        priv = private_key_cls.generate()
        pub = priv.public_key()
        shared_secret, ciphertext = pub.encapsulate()
        recovered = priv.decapsulate(ciphertext)
    except Exception as e:
        raise CryptoBackendUnsupported(
            f"ML-KEM-{level} round trip failed on this backend: {e!r}. "
            f"The cryptography package imported, but its ML-KEM support is "
            f"not functional here -- check that it's built against AWS-LC, "
            f"BoringSSL, or OpenSSL>=3.5 (see cryptography's "
            f"'State of OpenSSL' documentation)."
        ) from e

    if shared_secret != recovered:
        raise CryptoBackendUnsupported(
            f"ML-KEM-{level} encapsulate/decapsulate produced mismatched "
            f"shared secrets. Do not trust this backend for KEM-MAKE."
        )


def _check_aead(name: str, cls, key_kwargs: dict) -> None:
    try:
        key = cls.generate_key(**key_kwargs)
        aead = cls(key)
        nonce = b"\x00" * 12
        pt = b"capability-check"
        ct = aead.encrypt(nonce, pt, None)
        recovered = aead.decrypt(nonce, ct, None)
    except Exception as e:
        raise CryptoBackendUnsupported(
            f"{name} round trip failed on this backend: {e!r}"
        ) from e

    if recovered != pt:
        raise CryptoBackendUnsupported(
            f"{name} encrypt/decrypt produced mismatched plaintext. "
            f"Do not trust this backend for KEM-MAKE."
        )


def _check_hkdf() -> None:
    try:
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"capability-check")
        derived = hkdf.derive(b"\x00" * 32)
    except Exception as e:
        raise CryptoBackendUnsupported(f"HKDF-SHA256 failed on this backend: {e!r}") from e

    if len(derived) != 32:
        raise CryptoBackendUnsupported(
            f"HKDF-SHA256 returned {len(derived)} bytes, expected 32."
        )


def check_backend() -> None:
    """Verify every primitive KEM-MAKE needs actually works on this backend.

    Raises CryptoBackendUnsupported with a specific, actionable message on
    the first failure. Raises nothing (returns None) if everything checked
    out. Intended to be called once at application startup, not on a hot
    path -- each ML-KEM check alone costs real key generation and KEM
    operations.
    """
    for level, cls in MLKEM_BACKEND_CLASSES.items():
        _check_mlkem(level, cls)

    _check_aead("AES-256-GCM", AESGCM, {"bit_length": 256})
    _check_aead("ChaCha20-Poly1305", ChaCha20Poly1305, {})

    _check_hkdf()


if __name__ == "__main__":
    check_backend()
    print("Crypto backend check passed: ML-KEM-768, ML-KEM-1024, "
          "AES-GCM, ChaCha20-Poly1305, and HKDF-SHA256 are all functional.")
