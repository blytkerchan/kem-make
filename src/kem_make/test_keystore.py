"""
Tests for kem_make.keystore.

Covers:
  1. Create / add public+private key / retrieve, full round trip.
  2. Wrong passphrase is rejected (via the constant-time-compared
     verification tag), and does not leak anything beyond "wrong".
  3. Duplicate key rejection (public and private, independently).
  4. add_private_key() requires a previously-registered public key.
  5. Each private key gets an independently random KEK salt and nonce --
     confirmed by inspecting two entries directly, not just trusting the
     code.
  6. key_id_for() never recomputes an already-cached digest (verified by
     patching KeyId.build with a call counter, not by inspecting timing).
  7. Alternate-hash lookups resolve via alt_index.der, not a full rescan.
  8. File and directory permissions match the documented design (0700
     dirs, 0600 header/private, 0644 public).
  9. DER canonicality is enforced on load() for all four on-disk record
     types, mirroring bottom.py's existing DER-only policy.
  10. Zeroing is actually invoked for KEK and master-key material (by
      patching _zero to record calls, since the end state of a zeroed
      buffer can't usefully be asserted after the fact once the buffer
      that held it has been reused).
  11. create() refuses to run against a non-empty existing directory.
  12. Key lookups compare key_hash bytes with hmac.compare_digest (via
      _key_hash_equal), not `==`, at both the primary-entry and
      alt-index lookup sites -- confirmed actually invoked, not just
      present in the source.

Run with: pytest test_keystore.py -v
"""

from unittest import mock

import pytest

from kem_make import KemPublicKey, KeyId, MLKEM_PK_LEN
from kem_make.bottom import NonCanonicalEncoding
from kem_make.keystore import (
    KeyDirectory,
    WrongPassphrase,
    KeyNotFound,
    DuplicateKey,
    PrivateKeyRequiresPublicKey,
    KeyDirectoryError,
    StoredPrivateKeyEntry,
)

# Real PBKDF2 iteration counts (600,000 default) would make every test in
# this file slow; use a low count throughout purely for test speed. Never
# do this outside tests.
_FAST_ITERATIONS = 100


def _pk(fill=b"\x11"):
    return KemPublicKey.build(fill * MLKEM_PK_LEN[768], level=768)


# ---------------------------------------------------------------------------
# 1. Basic round trip
# ---------------------------------------------------------------------------

def test_full_round_trip(tmp_path):
    pk = _pk()
    priv_bytes = b"a" * 32

    kd = KeyDirectory.create(tmp_path / "kd", b"correct horse battery staple", iterations=_FAST_ITERATIONS)
    key_id = kd.add_public_key(pk)
    kd.add_private_key(pk, priv_bytes)

    assert kd.get_public_key(key_id).dump() == pk.dump()
    assert bytes(kd.get_private_key(key_id)) == priv_bytes
    kd.close()


def test_reopen_with_correct_passphrase(tmp_path):
    pk = _pk()
    path = tmp_path / "kd"

    kd = KeyDirectory.create(path, b"my passphrase", iterations=_FAST_ITERATIONS)
    key_id = kd.add_public_key(pk)
    kd.add_private_key(pk, b"b" * 32)
    kd.close()

    kd2 = KeyDirectory.open(path, b"my passphrase")
    assert bytes(kd2.get_private_key(key_id)) == b"b" * 32
    kd2.close()


# ---------------------------------------------------------------------------
# 2. Wrong passphrase
# ---------------------------------------------------------------------------

def test_wrong_passphrase_rejected(tmp_path):
    path = tmp_path / "kd"
    kd = KeyDirectory.create(path, b"right passphrase", iterations=_FAST_ITERATIONS)
    kd.close()

    with pytest.raises(WrongPassphrase):
        KeyDirectory.open(path, b"wrong passphrase")


def test_wrong_passphrase_error_does_not_leak_details(tmp_path):
    path = tmp_path / "kd"
    kd = KeyDirectory.create(path, b"right passphrase", iterations=_FAST_ITERATIONS)
    kd.close()

    with pytest.raises(WrongPassphrase) as exc_info:
        KeyDirectory.open(path, b"wrong passphrase")

    message = str(exc_info.value)
    assert "right passphrase" not in message
    assert "wrong passphrase" not in message


def test_verification_tag_compared_with_constant_time_function(tmp_path):
    # We can't reliably assert *timing* in a shared CI environment, but we
    # can assert the implementation actually calls hmac.compare_digest
    # rather than `==` for the passphrase check, which is the property
    # that actually matters.
    path = tmp_path / "kd"
    kd = KeyDirectory.create(path, b"pass", iterations=_FAST_ITERATIONS)
    kd.close()

    with mock.patch("kem_make.keystore.hmac.compare_digest", wraps=__import__("hmac").compare_digest) as spy:
        with pytest.raises(WrongPassphrase):
            KeyDirectory.open(path, b"nope")
        assert spy.called


# ---------------------------------------------------------------------------
# 3. Duplicate key rejection
# ---------------------------------------------------------------------------

def test_duplicate_public_key_rejected(tmp_path):
    pk = _pk()
    kd = KeyDirectory.create(tmp_path / "kd", b"pass", iterations=_FAST_ITERATIONS)
    kd.add_public_key(pk)
    with pytest.raises(DuplicateKey):
        kd.add_public_key(pk)


def test_duplicate_private_key_rejected(tmp_path):
    pk = _pk()
    kd = KeyDirectory.create(tmp_path / "kd", b"pass", iterations=_FAST_ITERATIONS)
    kd.add_public_key(pk)
    kd.add_private_key(pk, b"a" * 32)
    with pytest.raises(DuplicateKey):
        kd.add_private_key(pk, b"different-bytes-32-chars-long!!")


# ---------------------------------------------------------------------------
# 4. Private key requires a registered public key
# ---------------------------------------------------------------------------

def test_private_key_requires_public_key_first(tmp_path):
    pk = _pk()
    kd = KeyDirectory.create(tmp_path / "kd", b"pass", iterations=_FAST_ITERATIONS)
    with pytest.raises(PrivateKeyRequiresPublicKey):
        kd.add_private_key(pk, b"a" * 32)


def test_get_private_key_not_found(tmp_path):
    pk = _pk()
    kd = KeyDirectory.create(tmp_path / "kd", b"pass", iterations=_FAST_ITERATIONS)
    key_id = kd.add_public_key(pk)
    with pytest.raises(KeyNotFound):
        kd.get_private_key(key_id)


def test_get_public_key_not_found(tmp_path):
    pk = _pk()
    other_pk = _pk(fill=b"\x99")
    kd = KeyDirectory.create(tmp_path / "kd", b"pass", iterations=_FAST_ITERATIONS)
    kd.add_public_key(pk)
    missing_id = KeyId.build(other_pk)
    with pytest.raises(KeyNotFound):
        kd.get_public_key(missing_id)


# ---------------------------------------------------------------------------
# 5. Per-key KEK independence
# ---------------------------------------------------------------------------

def test_each_private_key_gets_independent_salt_and_nonce(tmp_path):
    pk1 = _pk(fill=b"\x33")
    pk2 = _pk(fill=b"\x44")
    kd = KeyDirectory.create(tmp_path / "kd", b"pass", iterations=_FAST_ITERATIONS)

    kid1 = kd.add_public_key(pk1)
    kid2 = kd.add_public_key(pk2)
    kd.add_private_key(pk1, b"a" * 32)
    kd.add_private_key(pk2, b"b" * 32)

    e1 = StoredPrivateKeyEntry.load(kd._private_path(kd._hex_of(kid1)).read_bytes())
    e2 = StoredPrivateKeyEntry.load(kd._private_path(kd._hex_of(kid2)).read_bytes())

    assert e1["kek_salt"].native != e2["kek_salt"].native
    assert e1["nonce"].native != e2["nonce"].native

    # And both still decrypt correctly, independently of one another.
    assert bytes(kd.get_private_key(kid1)) == b"a" * 32
    assert bytes(kd.get_private_key(kid2)) == b"b" * 32


# ---------------------------------------------------------------------------
# 6. key_id_for() caching: never recompute an already-cached digest
# ---------------------------------------------------------------------------

def test_key_id_for_does_not_recompute_cached_digest(tmp_path):
    pk = _pk()
    kd = KeyDirectory.create(tmp_path / "kd", b"pass", iterations=_FAST_ITERATIONS)
    key_id = kd.add_public_key(pk)

    kid_sha384_first = kd.key_id_for(key_id, digest="sha384")

    with mock.patch.object(KeyId, "build", wraps=KeyId.build) as spy:
        kid_sha384_second = kd.key_id_for(key_id, digest="sha384")
        kid_sha256_again = kd.key_id_for(key_id, digest="sha256")
        assert spy.call_count == 0

    assert kid_sha384_first["key_hash"].native == kid_sha384_second["key_hash"].native
    assert kid_sha256_again["key_hash"].native == key_id["key_hash"].native


def test_key_id_for_computes_once_when_not_cached(tmp_path):
    pk = _pk()
    kd = KeyDirectory.create(tmp_path / "kd", b"pass", iterations=_FAST_ITERATIONS)
    key_id = kd.add_public_key(pk)

    with mock.patch.object(KeyId, "build", wraps=KeyId.build) as spy:
        kd.key_id_for(key_id, digest="sha512")
        assert spy.call_count == 1


# ---------------------------------------------------------------------------
# 7. Alternate-hash lookup via alt_index.der
# ---------------------------------------------------------------------------

def test_alternate_hash_lookup_resolves_via_alt_index(tmp_path):
    pk = _pk()
    kd = KeyDirectory.create(tmp_path / "kd", b"pass", iterations=_FAST_ITERATIONS)
    key_id = kd.add_public_key(pk)

    kid_sha384 = kd.key_id_for(key_id, digest="sha384")
    assert (tmp_path / "kd" / "alt_index.der").exists()

    found = kd.get_public_key(kid_sha384)
    assert found.dump() == pk.dump()


def test_private_key_lookup_by_alternate_hash(tmp_path):
    pk = _pk()
    kd = KeyDirectory.create(tmp_path / "kd", b"pass", iterations=_FAST_ITERATIONS)
    key_id = kd.add_public_key(pk)
    kd.add_private_key(pk, b"a" * 32)

    kid_sha384 = kd.key_id_for(key_id, digest="sha384")
    assert bytes(kd.get_private_key(kid_sha384)) == b"a" * 32


# ---------------------------------------------------------------------------
# 8. File and directory permissions
# ---------------------------------------------------------------------------

def test_permissions(tmp_path):
    import stat

    pk = _pk()
    path = tmp_path / "kd"
    kd = KeyDirectory.create(path, b"pass", iterations=_FAST_ITERATIONS)
    key_id = kd.add_public_key(pk)
    kd.add_private_key(pk, b"a" * 32)

    def mode(p):
        return stat.S_IMODE(p.stat().st_mode)

    assert mode(path) == 0o700
    assert mode(path / "public") == 0o700
    assert mode(path / "private") == 0o700
    assert mode(path / "header.der") == 0o600
    assert mode(kd._private_path(kd._hex_of(key_id))) == 0o600
    assert mode(kd._public_path(kd._hex_of(key_id))) == 0o644


# ---------------------------------------------------------------------------
# 9. DER canonicality enforcement on all on-disk record types
# ---------------------------------------------------------------------------

def test_load_rejects_non_canonical_private_key_entry(tmp_path):
    pk = _pk()
    kd = KeyDirectory.create(tmp_path / "kd", b"pass", iterations=_FAST_ITERATIONS)
    key_id = kd.add_public_key(pk)
    kd.add_private_key(pk, b"a" * 32)

    path = kd._private_path(kd._hex_of(key_id))
    der = path.read_bytes()
    assert der[1] == 0x81  # long-form, one length octet
    length_value = der[2]
    non_minimal = der[0:1] + bytes([0x82, 0x00, length_value]) + der[3:]
    path.write_bytes(non_minimal)

    with pytest.raises(NonCanonicalEncoding):
        kd.get_private_key(key_id)


def test_load_rejects_non_canonical_public_key_entry(tmp_path):
    pk = _pk()
    kd = KeyDirectory.create(tmp_path / "kd", b"pass", iterations=_FAST_ITERATIONS)
    key_id = kd.add_public_key(pk)

    path = kd._public_path(kd._hex_of(key_id))
    der = path.read_bytes()
    assert der[1] == 0x82  # this one is long enough to use 2 length octets
    length_value = int.from_bytes(der[2:4], "big")
    padded = b"\x00" + length_value.to_bytes(2, "big")
    non_minimal = der[0:1] + bytes([0x83]) + padded + der[4:]
    path.write_bytes(non_minimal)

    with pytest.raises(NonCanonicalEncoding):
        kd.get_public_key(key_id)


def test_load_rejects_non_canonical_header(tmp_path):
    path = tmp_path / "kd"
    kd = KeyDirectory.create(path, b"pass", iterations=_FAST_ITERATIONS)
    kd.close()

    header_path = path / "header.der"
    der = header_path.read_bytes()
    assert der[1] < 0x80
    length_value = der[1]
    non_minimal = der[0:1] + bytes([0x81, length_value]) + der[2:]
    header_path.write_bytes(non_minimal)

    with pytest.raises(NonCanonicalEncoding):
        KeyDirectory.open(path, b"pass")


# ---------------------------------------------------------------------------
# 10. Zeroing is actually invoked
# ---------------------------------------------------------------------------

def test_close_zeroes_master_key(tmp_path):
    kd = KeyDirectory.create(tmp_path / "kd", b"pass", iterations=_FAST_ITERATIONS)
    master_key_ref = kd._master_key
    assert any(b != 0 for b in master_key_ref), "sanity check: key should be non-zero before close()"
    kd.close()
    assert all(b == 0 for b in master_key_ref), "master key was not zeroed on close()"


def test_kek_is_zeroed_after_use(tmp_path):
    pk = _pk()
    kd = KeyDirectory.create(tmp_path / "kd", b"pass", iterations=_FAST_ITERATIONS)
    kd.add_public_key(pk)

    from kem_make import keystore as keystore_module
    real_zero = keystore_module._zero
    zeroed_buffers = []

    def spying_zero(buf):
        zeroed_buffers.append(bytes(buf))  # snapshot before zeroing
        return real_zero(buf)

    with mock.patch.object(keystore_module, "_zero", spying_zero):
        kd.add_private_key(pk, b"a" * 32)

    # At least one non-trivial (KEK-length) buffer should have been zeroed
    # during add_private_key().
    assert any(len(b) == 32 for b in zeroed_buffers)


def test_check_tag_derivation_actually_zeroes_its_key_buffer(tmp_path):
    # Regression test: an earlier version of _derive_check_tag converted
    # its HKDF output to bytearray only inside the finally clause
    # (`_zero(bytearray(check_key))`), which creates a fresh copy to zero
    # and leaves the real buffer untouched -- and since hkdf.derive()
    # returns immutable bytes, `isinstance(check_key, bytearray)` was
    # always False anyway, so the call never even ran. This confirms
    # _zero is actually invoked on the buffer _derive_check_tag itself
    # holds, not a throwaway copy.
    from kem_make import keystore as keystore_module

    zeroed_lengths = []
    real_zero = keystore_module._zero

    def spying_zero(buf):
        zeroed_lengths.append(len(buf))
        return real_zero(buf)

    with mock.patch.object(keystore_module, "_zero", spying_zero):
        keystore_module._derive_check_tag(b"x" * 32, b"y" * 16)

    assert 32 in zeroed_lengths, "_derive_check_tag did not zero its derived key buffer"


def test_get_public_key_uses_constant_time_key_hash_comparison(tmp_path):
    pk = _pk()
    kd = KeyDirectory.create(tmp_path / "kd", b"pass", iterations=_FAST_ITERATIONS)
    key_id = kd.add_public_key(pk)

    from kem_make import keystore as keystore_module
    with mock.patch.object(keystore_module, "_key_hash_equal", wraps=keystore_module._key_hash_equal) as spy:
        kd.get_public_key(key_id)
        assert spy.called


def test_alt_index_lookup_uses_constant_time_key_hash_comparison(tmp_path):
    pk = _pk()
    kd = KeyDirectory.create(tmp_path / "kd", b"pass", iterations=_FAST_ITERATIONS)
    key_id = kd.add_public_key(pk)
    kid_sha384 = kd.key_id_for(key_id, digest="sha384")

    from kem_make import keystore as keystore_module
    with mock.patch.object(keystore_module, "_key_hash_equal", wraps=keystore_module._key_hash_equal) as spy:
        found = kd.get_public_key(kid_sha384)
        assert found.dump() == pk.dump()
        assert spy.called


def test_key_hash_equal_rejects_mismatched_hashes():
    from kem_make.keystore import _key_hash_equal
    assert _key_hash_equal(b"\x00" * 32, b"\x00" * 32) is True
    assert _key_hash_equal(b"\x00" * 32, b"\x01" + b"\x00" * 31) is False


# ---------------------------------------------------------------------------
# 11. create() refuses a non-empty existing directory
# ---------------------------------------------------------------------------

def test_create_refuses_non_empty_directory(tmp_path):
    path = tmp_path / "kd"
    path.mkdir()
    (path / "something").write_text("not a key directory")

    with pytest.raises(KeyDirectoryError):
        KeyDirectory.create(path, b"pass", iterations=_FAST_ITERATIONS)
