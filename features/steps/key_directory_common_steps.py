import tempfile
from pathlib import Path
from unittest import mock

from behave import given

from kem_make.bottom import KeyId
from kem_make.crypto_backend import create_mlkem_keypair
from kem_make.keystore import KeyDirectory


@given(u'a key directory created with passphrase "pass"')
def step_impl(context):
    context.temp_dir = tempfile.TemporaryDirectory()
    context.key_directory_path = Path(context.temp_dir.name) / "key_directory"
    context.key_directory = KeyDirectory.create(context.key_directory_path, "pass")

    # KeyId.build() is the sole place a key hash is actually computed --
    # key_id_for() only calls it when a digest isn't already cached
    # (keystore.py), and lookups never call it at all. Wrapping it here
    # lets any step count "did a hash get (re)computed?" via
    # context.key_id_build_mock.call_count.
    patcher = mock.patch.object(KeyId, "build", wraps=KeyId.build)
    context.key_id_build_mock = patcher.start()
    context.add_cleanup(patcher.stop)


@given(u'a second valid ML-KEM-768 KemPublicKey "unregistered_pk" that was never added')
def step_impl(context):
    context.unregistered_key = create_mlkem_keypair(level=768)

    