#pylint: disable=missing-function-docstring, missing-module-docstring, missing-class-docstring, redefined-outer-name, too-many-locals, too-many-statements, too-many-lines, protected-access, import-outside-toplevel, duplicate-code
import pytest

from cryptography.hazmat.primitives.asymmetric import mlkem

from kem_make import KemPublicKey, KeyId
from kem_make.session import (
    Session,
    Role,
    SessionConfig,
)


class FakeKeyLookup:
    def __init__(self):
        self._pub = {}
        self._priv = {}

    def add(self, key_id, public_key, private_key=None):
        self._pub[bytes(key_id["key_hash"].native)] = public_key
        if private_key is not None:
            self._priv[bytes(key_id["key_hash"].native)] = private_key

    def get_public_key(self, key_id):
        return self._pub[bytes(key_id["key_hash"].native)]

    def get_private_key(self, key_id):
        return self._priv[bytes(key_id["key_hash"].native)]


def _make_identity():
    private = mlkem.MLKEM768PrivateKey.generate()
    public_wire = KemPublicKey.build(private.public_key().public_bytes_raw(), level=768)
    key_id = KeyId.build(public_wire)
    return private, public_wire, key_id


@pytest.fixture
def parties():
    """Alice (initiator) and Bob (responder), each knowing their own
    keypair and the other's public key, with a fast retry/TTL config so
    tests don't need to sleep."""
    alice_priv, alice_pub, alice_kid = _make_identity()
    bob_priv, bob_pub, bob_kid = _make_identity()

    alice_keys = FakeKeyLookup()
    alice_keys.add(alice_kid, alice_pub, alice_priv.private_bytes_raw())
    alice_keys.add(bob_kid, bob_pub)

    bob_keys = FakeKeyLookup()
    bob_keys.add(bob_kid, bob_pub, bob_priv.private_bytes_raw())
    bob_keys.add(alice_kid, alice_pub)

    # Deliberately separate SessionConfig instances, not one shared
    # object -- a test that mutates alice.config expecting it not to
    # affect bob.config (or vice versa) would otherwise silently corrupt
    # itself. See test_no_mutual_aead_is_rejected for exactly this bug,
    # caught while writing these tests.
    alice_config = SessionConfig(max_retries=2, retry_interval_seconds=5.0, ttl_seconds=20.0)
    bob_config = SessionConfig(max_retries=2, retry_interval_seconds=5.0, ttl_seconds=20.0)

    alice = Session(Role.INITIATOR, alice_kid, alice_keys, alice_config)
    bob = Session(Role.RESPONDER, bob_kid, bob_keys, bob_config)

    return {
        "alice": alice, "bob": bob,
        "alice_kid": alice_kid, "bob_kid": bob_kid,
        "alice_pub": alice_pub, "bob_pub": bob_pub,
        "alice_keys": alice_keys, "bob_keys": bob_keys,
        "config": alice_config,
    }
