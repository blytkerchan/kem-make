"""
Key directory: on-disk storage for KEM-MAKE public and private keys.

Layout (a real filesystem directory, not one monolithic file -- this is
deliberate: it lets a single key be added/updated with one atomic file
write rather than rewriting the whole store, and matches "key directory"
literally):

    <dir>/
        header.der            -- KeystoreHeader, unencrypted
        public/<hex-sha256>.der    -- StoredPublicKeyEntry, unencrypted
        private/<hex-sha256>.der   -- StoredPrivateKeyEntry, encrypted
        alt_index.der          -- created lazily, see "Avoiding repeat hashing" below

Filenames are the hex-encoded SHA-256 KeyId of the public key, which is
always computed and always present -- this is what "a simple lookup" means
for the default case: an O(1) filesystem path, no scan, no recompute.

Key derivation
--------------
passphrase --PBKDF2-HMAC-SHA256--> master_key (32 bytes)
master_key --HKDF-SHA256(salt=random per-key, info=domain label + key
    identity)--> per-key KEK (32 bytes)
per-key KEK --AES-256 Key Wrap with Padding (RFC 3394 / RFC 5649)-->
    wrapped private key bytes

The master key is DERIVED, NEVER STORED. header.der holds only the
PBKDF2 salt, the iteration count, and a verification tag -- the
ingredients needed to re-derive the same master key from the correct
passphrase, plus a way to confirm that passphrase is correct, but never
the master key itself in any form. This is an explicit design invariant,
not just a description of current behavior: test_keystore.py has a test
that reads every byte of every file this module writes and confirms the
raw master key never appears in any of them, for a range of different
passphrases and iteration counts.

Every private key gets its OWN KEK, derived with its own random salt and
an info field that binds in that key's identity (its primary KeyId's DER
encoding). This means: (a) compromising one private key's KEK reveals
nothing about any other key's KEK, since each derivation is independent
given a fresh salt; (b) the info field's domain-separation label and
per-key identity binding mean this exact same master_key could not be
reused to derive an identical KEK for a different purpose or a different
key by accident. AES Key Wrap (unlike AES-GCM) is deterministic -- there
is no nonce, and wrapping the same key bytes under the same KEK always
produces the same wrapped output. That's fine here specifically because
no two entries ever share a KEK (each private key's KEK comes from its
own random salt), so this determinism never creates a correlation
between different stored entries. If this module is ever changed to
reuse a KEK across more than one wrap operation, that assumption would
need to be revisited.

Public keys are never encrypted -- there is nothing to protect: anyone
who has the public key is supposed to have it. What they DO get is
integrity protection: each StoredPublicKeyEntry is HMAC-SHA256-protected
using a per-entry MAC key derived the same way as private-key KEKs
(HKDF from the master key, fresh random salt, domain-separation label),
with the entry's own filename bound into the derivation info. That last
part specifically catches an attacker swapping two validly-MAC'd entries
between each other's filenames -- both entries individually still verify
under a filename-blind MAC, but not once the filename is part of what's
authenticated. See KeyDirectory._mac_public_key_data /
_verify_and_get_data, and test_keystore.py's swap-attack test.

Avoiding repeat hashing
-----------------------
key_id_for() computes a KeyId under the requested digest algorithm only
if one isn't already cached on that key's StoredPublicKeyEntry. A newly
computed one is persisted back to the entry immediately, so it is never
recomputed on a later call regardless of digest algorithm requested.
alt_index.der maps (non-default) hash algorithm + digest bytes back to
the entry's primary (SHA-256-keyed) filename, so a direct lookup by an
alternate KeyId is also O(1) once that KeyId has been computed at least
once -- not a rescan of every stored key.

Side-channel and hygiene notes
-------------------------------
- The passphrase-verification check (see _derive_check_tag) is compared
  with hmac.compare_digest, not `==`, since CPython's bytes `==` is a
  short-circuiting byte-by-byte comparison and is not constant-time. The
  same applies to KeyId lookups (see _key_hash_equal): a KeyId identifies
  a *public* key and isn't secret the way a password or KEK is, but this
  module treats every digest/hash comparison as constant-time by policy
  regardless of whether a specific instance is provably exploitable --
  it's free, and it removes "is this actually exploitable" from ever
  needing to be re-argued in a future review. Any new comparison of
  digest, hash, or other secret-derived material added to this module
  must use compare_digest (or _key_hash_equal, for KeyId specifically),
  never a plain `==`.
- Integrity verification of wrapped private key material is handled
  inside `cryptography`'s AES Key Wrap implementation (RFC 3394/5649's
  own integrity check value, verified during unwrap), which raises
  InvalidUnwrap on failure -- translated here into
  PrivateKeyUnwrapFailed. We do not re-implement or second-guess that
  check.
- Exceptions in this module never include passphrase, master key, KEK, or
  private key bytes in their message, including in the wrong-passphrase
  case (which reports failure only, not what was wrong or what was
  expected).
- Best-effort zeroization: sensitive intermediate values (the derived
  master key, per-key KEKs, decrypted private key bytes) are held in
  `bytearray`, not `bytes`, and explicitly overwritten with zeros via
  `_zero()` as soon as they're no longer needed. This is genuinely
  best-effort, not a guarantee: CPython's memory allocator, GC, and any
  copies made by libraries this module calls (including `cryptography`
  itself, which may not zero its own internal buffers) are out of this
  module's control. Anyone with ptrace access, a core dump, or a swapped
  page during the window this data is live can still potentially recover
  it. Treat this as raising the bar, not eliminating the risk.
- Every private key file and the header are created with file mode 0600
  (owner read/write only); public key files with 0644; the directory
  itself and its public/private subdirectories with 0700. This is
  enforced with os.chmod after creation, not merely requested via the
  open() umask, since umask alone is not reliable across platforms/callers.
- All writes are atomic: a temp file in the same directory, then
  os.replace(). A crash mid-write cannot leave a half-written key file
  that then parses as valid-but-wrong.
- Salts (the PBKDF2 salt and every per-key KEK salt) are generated with
  os.urandom (OS CSPRNG), never Python's `random` module.

Known limitations (not addressed here; flagging rather than silently
omitting)
--------------------------------------------------------------------
- No key-directory-wide locking: concurrent writers (e.g. two processes
  adding keys at once) can race; atomic writes prevent corruption of any
  single file, but not lost updates to alt_index.der specifically, since
  that file's update is itself read-modify-write.
- No support yet for changing the passphrase (would mean re-deriving
  every private key's KEK-encryption... no, actually the master key
  changes but the per-key salts and KEKs derived from it would need
  fresh derivation and re-encryption of every stored private key, which
  isn't implemented here).
- PBKDF2-HMAC-SHA256 at 600,000 iterations is OWASP's current cited
  PBKDF2 minimum (as of sources available in 2026), chosen here for FIPS
  alignment with the rest of this project. OWASP's overall top
  recommendation as of the same sources is Argon2id, not PBKDF2, for
  contexts that don't need FIPS compliance -- worth reconsidering if FIPS
  isn't actually a requirement here.
"""

from __future__ import annotations

import hmac
import os
import stat
import tempfile
from pathlib import Path
from typing import Optional

from asn1crypto.core import Sequence, SequenceOf, OctetString, Integer, ObjectIdentifier
from asn1crypto.algos import DigestAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import (
    aes_key_wrap_with_padding,
    aes_key_unwrap_with_padding,
    InvalidUnwrap,
)

from .bottom import KemPublicKey, KeyId, _require_der

MASTER_KEY_LEN = 32          # 256-bit master key from PBKDF2
KEK_LEN = 32                 # 256-bit per-key KEK from HKDF, for AES-256 Key Wrap
KDF_SALT_LEN = 16            # 128 bits, NIST's stated minimum
KEK_SALT_LEN = 16
CHECK_TAG_LEN = 32            # HMAC-SHA256 output length
MAC_KEY_LEN = 32              # 256-bit per-entry MAC key from HKDF, for HMAC-SHA256
MAC_SALT_LEN = 16
MAC_TAG_LEN = 32               # HMAC-SHA256 output length

# OWASP's current cited minimum for PBKDF2-HMAC-SHA256 (2026 sources).
# Chosen for FIPS alignment with the rest of this project; Argon2id is
# OWASP's overall top recommendation where FIPS isn't required -- see
# module docstring "Known limitations".
DEFAULT_PBKDF2_ITERATIONS = 600_000

_DOMAIN_KEK = b"kem-make-keystore-kek-v1"
_DOMAIN_CHECK = b"kem-make-keystore-check-v1"
_CHECK_VALUE = b"kem-make-keystore-checkvalue-v1"
_DOMAIN_PUBLIC_KEY_MAC = b"kem-make-keystore-pubkey-mac-v1"

_WRAP_ALGORITHM_OID = "2.16.840.1.101.3.4.1.48"  # id-aes256-wrap-pad, RFC 5649


class KeyDirectoryError(Exception):
    """Base class for all errors this module raises directly."""
    pass


class WrongPassphrase(KeyDirectoryError):
    """Raised when the supplied passphrase does not match the key
    directory's stored verification tag. Deliberately carries no detail
    beyond this -- not the derived key, not the expected tag."""
    pass


class KeyNotFound(KeyDirectoryError):
    pass


class DuplicateKey(KeyDirectoryError):
    pass


class PrivateKeyRequiresPublicKey(KeyDirectoryError):
    """Raised when add_private_key() is called for a public key that was
    never added with add_public_key() -- private keys are always linked
    to a registered public key entry, never stored standalone."""
    pass


class PrivateKeyUnwrapFailed(KeyDirectoryError):
    """Raised when AES-KW unwrap fails integrity verification -- either
    the stored entry was tampered with, or (should not happen once
    open() has already verified the passphrase) the wrong KEK was used."""
    pass


class PublicKeyIntegrityError(KeyDirectoryError):
    """Raised when a stored public key entry's MAC does not verify --
    the entry was edited, replaced, or swapped with a different entry's
    file on disk since it was written."""
    pass


def _zero(buf: bytearray) -> None:
    """Best-effort overwrite of a mutable buffer's contents with zero
    bytes. See module docstring's side-channel notes for what this does
    and does not guarantee."""
    for i in range(len(buf)):
        buf[i] = 0


def _key_hash_equal(a: bytes, b: bytes) -> bool:
    """Constant-time comparison of two KeyId key_hash values.

    A KeyId identifies a *public* key, so neither operand here is secret
    in the way a password or a MAC key is -- but comparing digest/hash
    values with `==` is exactly the pattern this project treats as a
    default-deny policy regardless of whether a specific instance is
    provably exploitable (see module docstring's side-channel notes).
    hmac.compare_digest is used here for that reason: it's free, and it
    removes "is this one actually exploitable" from ever needing to be
    re-litigated in a future review.
    """
    return hmac.compare_digest(a, b)


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    directory = path.parent
    fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".part")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _derive_master_key(passphrase: bytes, salt: bytes, iterations: int) -> bytearray:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=MASTER_KEY_LEN, salt=salt, iterations=iterations)
    return bytearray(kdf.derive(passphrase))


def _derive_kek(master_key: bytes, salt: bytes, key_identity: bytes) -> bytearray:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=KEK_LEN, salt=salt, info=_DOMAIN_KEK + key_identity)
    return bytearray(hkdf.derive(bytes(master_key)))


def _derive_public_key_mac_key(master_key: bytes, salt: bytes, hex_id: str) -> bytearray:
    hkdf = HKDF(
        algorithm=hashes.SHA256(), length=MAC_KEY_LEN, salt=salt,
        info=_DOMAIN_PUBLIC_KEY_MAC + hex_id.encode("ascii"),
    )
    return bytearray(hkdf.derive(bytes(master_key)))


def _derive_check_tag(master_key: bytes, header_salt: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=header_salt, info=_DOMAIN_CHECK)
    check_key = bytearray(hkdf.derive(bytes(master_key)))
    try:
        return hmac.new(bytes(check_key), _CHECK_VALUE, "sha256").digest()
    finally:
        _zero(check_key)


# ---------------------------------------------------------------------------
# On-disk record types
# ---------------------------------------------------------------------------

class KeyIdList(SequenceOf):
    _child_spec = KeyId


class KeystoreHeader(Sequence):
    _fields = [
        ("version", Integer, {"default": 0}),
        ("kdf_salt", OctetString),
        ("kdf_iterations", Integer),
        ("verification_tag", OctetString),
    ]

    @classmethod
    def load(cls, encoded_data, **kwargs):
        obj = super().load(encoded_data, **kwargs)
        _require_der(cls, encoded_data, obj)
        return obj


class PublicKeyEntryData(Sequence):
    _fields = [
        ("public_key", KemPublicKey),
        ("key_ids", KeyIdList),
    ]


class StoredPublicKeyEntry(Sequence):
    # data is HMAC-SHA256-protected (see KeyDirectory._mac_public_key_data)
    # so that swapping, editing, or replacing a public key entry on disk
    # is detected rather than silently trusted. The MAC key is derived
    # per-entry via HKDF from the master key, with a fresh random salt and
    # an info field that binds in the entry's own filename -- the latter
    # specifically so that swapping two validly-MAC'd entries between
    # each other's filenames is also caught, not just editing one in place.
    _fields = [
        ("data", PublicKeyEntryData),
        ("mac_salt", OctetString),
        ("mac_tag", OctetString),
    ]

    @classmethod
    def load(cls, encoded_data, **kwargs):
        obj = super().load(encoded_data, **kwargs)
        _require_der(cls, encoded_data, obj)
        return obj


class StoredPrivateKeyEntry(Sequence):
    _fields = [
        ("key_id", KeyId),               # primary (SHA-256) reference
        ("kek_salt", OctetString),
        ("wrap_algorithm", ObjectIdentifier),
        ("wrapped_key", OctetString),      # RFC 5649 AES-256 key wrap output
    ]

    @classmethod
    def load(cls, encoded_data, **kwargs):
        obj = super().load(encoded_data, **kwargs)
        _require_der(cls, encoded_data, obj)
        return obj


class AltIndexEntry(Sequence):
    _fields = [
        ("key_id", KeyId),                # the alternate-hash KeyId
        ("primary_hex", OctetString),      # ascii hex of the primary sha256 hash, as bytes
    ]

    @classmethod
    def load(cls, encoded_data, **kwargs):
        obj = super().load(encoded_data, **kwargs)
        _require_der(cls, encoded_data, obj)
        return obj


class AltIndex(SequenceOf):
    _child_spec = AltIndexEntry

    @classmethod
    def load(cls, encoded_data, **kwargs):
        obj = super().load(encoded_data, **kwargs)
        _require_der(cls, encoded_data, obj)
        return obj


# ---------------------------------------------------------------------------
# KeyDirectory
# ---------------------------------------------------------------------------

class KeyDirectory:
    def __init__(self, path: Path, master_key: bytearray):
        self._path = path
        self._master_key = master_key  # bytearray; zeroed on close()

    # -- lifecycle -----------------------------------------------------

    @classmethod
    def create(cls, path, passphrase: bytes, iterations: int = DEFAULT_PBKDF2_ITERATIONS) -> "KeyDirectory":
        path = Path(path)
        if path.exists() and any(path.iterdir()):
            raise KeyDirectoryError(f"{path} already exists and is not empty")
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, 0o700)
        (path / "public").mkdir(exist_ok=True)
        os.chmod(path / "public", 0o700)
        (path / "private").mkdir(exist_ok=True)
        os.chmod(path / "private", 0o700)

        kdf_salt = os.urandom(KDF_SALT_LEN)
        master_key = _derive_master_key(passphrase, kdf_salt, iterations)
        check_tag = _derive_check_tag(bytes(master_key), kdf_salt)

        header = KeystoreHeader({
            "version": 0,
            "kdf_salt": kdf_salt,
            "kdf_iterations": iterations,
            "verification_tag": check_tag,
        })
        _atomic_write(path / "header.der", header.dump(), 0o600)

        return cls(path, master_key)

    @classmethod
    def open(cls, path, passphrase: bytes) -> "KeyDirectory":
        path = Path(path)
        header_path = path / "header.der"
        if not header_path.exists():
            raise KeyDirectoryError(f"{path} does not look like a key directory (no header.der)")

        header = KeystoreHeader.load(header_path.read_bytes())
        kdf_salt = header["kdf_salt"].native
        iterations = header["kdf_iterations"].native

        master_key = _derive_master_key(passphrase, kdf_salt, iterations)
        expected_tag = header["verification_tag"].native
        actual_tag = _derive_check_tag(bytes(master_key), kdf_salt)

        if not hmac.compare_digest(actual_tag, expected_tag):
            _zero(master_key)
            raise WrongPassphrase("passphrase does not match this key directory")

        return cls(path, master_key)

    def close(self) -> None:
        _zero(self._master_key)

    def __enter__(self) -> "KeyDirectory":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # -- internal paths --------------------------------------------------

    def _public_path(self, hex_id: str) -> Path:
        return self._path / "public" / f"{hex_id}.der"

    def _private_path(self, hex_id: str) -> Path:
        return self._path / "private" / f"{hex_id}.der"

    def _alt_index_path(self) -> Path:
        return self._path / "alt_index.der"

    @staticmethod
    def _hex_of(key_id: KeyId) -> str:
        return key_id["key_hash"].native.hex()

    def _primary_key_id(self, public_key: KemPublicKey) -> KeyId:
        return KeyId.build(public_key, digest="sha256")

    # -- public key integrity (MAC) -----------------------------------------

    def _mac_public_key_data(self, data: "PublicKeyEntryData", salt: bytes, hex_id: str) -> bytes:
        mac_key = _derive_public_key_mac_key(bytes(self._master_key), salt, hex_id)
        try:
            # force=True: must MAC the canonical re-derived DER, not
            # whatever bytes happen to be cached on `data` -- otherwise a
            # verify computed from a freshly-built PublicKeyEntryData
            # could disagree with one computed after a load() round trip
            # for reasons that have nothing to do with tampering.
            return hmac.new(bytes(mac_key), data.dump(force=True), "sha256").digest()
        finally:
            _zero(mac_key)

    def _build_stored_public_key_entry(self, data: "PublicKeyEntryData", hex_id: str) -> "StoredPublicKeyEntry":
        salt = os.urandom(MAC_SALT_LEN)
        tag = self._mac_public_key_data(data, salt, hex_id)
        return StoredPublicKeyEntry({"data": data, "mac_salt": salt, "mac_tag": tag})

    def _verify_and_get_data(self, stored: "StoredPublicKeyEntry", hex_id: str) -> "PublicKeyEntryData":
        expected_tag = self._mac_public_key_data(stored["data"], stored["mac_salt"].native, hex_id)
        actual_tag = stored["mac_tag"].native
        if not hmac.compare_digest(actual_tag, expected_tag):
            raise PublicKeyIntegrityError(
                f"public key entry {hex_id} failed integrity verification "
                f"(edited, replaced, or swapped with a different entry's "
                f"file since it was written)"
            )
        return stored["data"]

    # -- public keys -------------------------------------------------------

    def add_public_key(self, public_key: KemPublicKey) -> KeyId:
        primary = self._primary_key_id(public_key)
        hex_id = self._hex_of(primary)
        path = self._public_path(hex_id)
        if path.exists():
            raise DuplicateKey(f"public key {hex_id} is already present")

        data = PublicKeyEntryData({
            "public_key": public_key,
            "key_ids": KeyIdList([primary]),
        })
        entry = self._build_stored_public_key_entry(data, hex_id)
        _atomic_write(path, entry.dump(), 0o644)
        return primary

    def get_public_key(self, key_id: KeyId) -> KemPublicKey:
        data = self._load_public_entry_by_key_id(key_id)
        return data["public_key"]

    def _load_public_entry_by_key_id(self, key_id: KeyId) -> "PublicKeyEntryData":
        """Loads, MAC-verifies, and returns the PublicKeyEntryData for the
        given KeyId. Raises PublicKeyIntegrityError if the stored entry's
        MAC does not verify -- callers never see unverified data."""
        hex_id = self._hex_of(key_id)
        digest_oid = key_id["hash_algorithm"]["algorithm"].dotted

        # Fast path: this IS the primary (SHA-256) KeyId -- direct filename hit.
        path = self._public_path(hex_id)
        if path.exists():
            stored = StoredPublicKeyEntry.load(path.read_bytes())
            data = self._verify_and_get_data(stored, hex_id)
            if any(
                kid["hash_algorithm"]["algorithm"].dotted == digest_oid
                and _key_hash_equal(kid["key_hash"].native, key_id["key_hash"].native)
                for kid in data["key_ids"]
            ):
                return data
            # Same filename coincidentally, but not actually a match for a
            # non-default digest -- fall through to the alt index.

        # Alternate-hash path: consult the cached index rather than
        # scanning and rehashing every stored key.
        primary_hex = self._alt_index_lookup(key_id)
        if primary_hex is not None:
            alt_path = self._public_path(primary_hex)
            if alt_path.exists():
                stored = StoredPublicKeyEntry.load(alt_path.read_bytes())
                return self._verify_and_get_data(stored, primary_hex)

        raise KeyNotFound(f"no public key found for the given KeyId ({hex_id})")

    def key_id_for(self, public_key_or_key_id, digest: str = "sha256") -> KeyId:
        """Return a KeyId for the given key under `digest`, computing and
        persisting it only if it isn't already cached on that key's entry.
        Never recomputes a digest that's already been cached for this key."""
        if isinstance(public_key_or_key_id, KeyId):
            data = self._load_public_entry_by_key_id(public_key_or_key_id)
        else:
            data = self._load_public_entry_by_key_id(self._primary_key_id(public_key_or_key_id))

        for kid in data["key_ids"]:
            if kid["hash_algorithm"]["algorithm"].dotted == _digest_oid(digest):
                return kid

        new_kid = KeyId.build(data["public_key"], digest=digest)
        updated_ids = list(data["key_ids"]) + [new_kid]
        data["key_ids"] = KeyIdList(updated_ids)

        primary_hex = self._hex_of(data["key_ids"][0])
        entry = self._build_stored_public_key_entry(data, primary_hex)
        _atomic_write(self._public_path(primary_hex), entry.dump(), 0o644)
        self._alt_index_add(new_kid, primary_hex)
        return new_kid

    # -- alt index ---------------------------------------------------------

    def _alt_index_lookup(self, key_id: KeyId) -> Optional[str]:
        path = self._alt_index_path()
        if not path.exists():
            return None
        index = AltIndex.load(path.read_bytes())
        digest_oid = key_id["hash_algorithm"]["algorithm"].dotted
        for entry in index:
            if (
                entry["key_id"]["hash_algorithm"]["algorithm"].dotted == digest_oid
                and _key_hash_equal(entry["key_id"]["key_hash"].native, key_id["key_hash"].native)
            ):
                return entry["primary_hex"].native.decode("ascii")
        return None

    def _alt_index_add(self, key_id: KeyId, primary_hex: str) -> None:
        path = self._alt_index_path()
        existing = []
        if path.exists():
            existing = list(AltIndex.load(path.read_bytes()))
        existing.append(AltIndexEntry({
            "key_id": key_id,
            "primary_hex": primary_hex.encode("ascii"),
        }))
        _atomic_write(path, AltIndex(existing).dump(), 0o600)

    # -- private keys --------------------------------------------------

    def add_private_key(self, public_key: KemPublicKey, private_key_bytes: bytes) -> KeyId:
        primary = self._primary_key_id(public_key)
        hex_id = self._hex_of(primary)

        if not self._public_path(hex_id).exists():
            raise PrivateKeyRequiresPublicKey(
                f"no registered public key entry for {hex_id}; call "
                f"add_public_key() before add_private_key()"
            )
        if self._private_path(hex_id).exists():
            raise DuplicateKey(f"private key {hex_id} is already present")

        kek_salt = os.urandom(KEK_SALT_LEN)
        kek = _derive_kek(bytes(self._master_key), kek_salt, primary.dump())
        try:
            wrapped_key = aes_key_wrap_with_padding(bytes(kek), private_key_bytes)
        finally:
            _zero(kek)

        entry = StoredPrivateKeyEntry({
            "key_id": primary,
            "kek_salt": kek_salt,
            "wrap_algorithm": _WRAP_ALGORITHM_OID,
            "wrapped_key": wrapped_key,
        })
        _atomic_write(self._private_path(hex_id), entry.dump(), 0o600)
        return primary

    def get_private_key(self, key_id: KeyId) -> bytearray:
        """Returns the decrypted private key bytes as a bytearray. Callers
        are responsible for zeroing it (see _zero()) once done -- this
        module cannot know when that is safe to do on its behalf."""
        # Private key lookups are always by the primary (SHA-256) KeyId --
        # the filename itself. If a caller has an alternate-hash KeyId,
        # resolve it to the public entry first to get the primary hex.
        if key_id["hash_algorithm"]["algorithm"].dotted != _digest_oid("sha256"):
            entry = self._load_public_entry_by_key_id(key_id)
            hex_id = self._hex_of(entry["key_ids"][0])
        else:
            hex_id = self._hex_of(key_id)

        path = self._private_path(hex_id)
        if not path.exists():
            raise KeyNotFound(f"no private key found for {hex_id}")

        stored = StoredPrivateKeyEntry.load(path.read_bytes())

        kek_salt = stored["kek_salt"].native
        wrapped_key = stored["wrapped_key"].native

        kek = _derive_kek(bytes(self._master_key), kek_salt, stored["key_id"].dump())
        try:
            plaintext = aes_key_unwrap_with_padding(bytes(kek), wrapped_key)
        except InvalidUnwrap as e:
            raise PrivateKeyUnwrapFailed(
                f"integrity check failed unwrapping private key {hex_id} "
                f"(tampered entry, or corrupted on disk)"
            ) from e
        finally:
            _zero(kek)

        return bytearray(plaintext)


def _digest_oid(name: str) -> str:
    # DigestAlgorithm resolves common names (sha256, sha384, ...) to their
    # OIDs the same way KeyId.build() does -- reuse that instead of
    # hand-maintaining a second OID table here.
    return DigestAlgorithm({"algorithm": name})["algorithm"].dotted
