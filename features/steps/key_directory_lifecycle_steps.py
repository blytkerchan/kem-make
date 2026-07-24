from behave import when
from behave.api.pending_step import StepNotImplementedError

from asn1crypto.core import Sequence, SequenceOf, OctetString, Integer, Choice, ObjectIdentifier
import oschmod

from kem_make.crypto_backend import create_mlkem_keypair
from kem_make.keystore import KeyDirectory, KeyDirectoryError, WrongPassphrase
from kem_make.common import require_der

import tempfile
from pathlib import Path

@given(u'a passphrase "{passphrase}"')
def step_impl(context, passphrase):
    context.passphrase = passphrase


@when(u'I create a key directory at a fresh path with that passphrase')
def step_impl(context):
    context.temp_dir = tempfile.TemporaryDirectory()
    context.key_directory_path = Path(context.temp_dir.name) / "key_directory"
    context.key_directory_path.mkdir(parents=True, exist_ok=False)
    context.key_directory = KeyDirectory.create(context.key_directory_path, context.passphrase)


@then(u'the key directory is created successfully')
def step_impl(context):
    assert context.key_directory_path.exists()
    assert context.key_directory_path.is_dir()
    assert context.key_directory is not None


@then(u'no file anywhere under that path contains the raw master key bytes')
def step_impl(context):
    for file in context.key_directory_path.iterdir():
        if file.is_file():
            with open(file, "rb") as f:
                content = f.read()
                assert b"raw master key bytes" not in content
        if file.is_dir():
            for subfile in file.iterdir():
                if subfile.is_file():
                    with open(subfile, "rb") as f:
                        content = f.read()
                        assert b"raw master key bytes" not in content


@then(u'the header file contains exactly a version, a KDF salt, an iteration count, and a verification tag')
def step_impl(context):
    class StrictKeystoreHeader(Sequence):
        """The unencrypted header.der file at the root of a key directory, containing metadata about
        the keystore."""
        _fields = [
            ("version", Integer, {"default": 0}),
            ("kdf_salt", OctetString),
            ("kdf_iterations", Integer),
            ("verification_tag", OctetString),
        ]

        @classmethod
        def load(cls, encoded_data, **kwargs):
            obj = super().load(encoded_data, strict=True, **kwargs)
            require_der(cls, encoded_data, obj)
            return obj
    with open(context.key_directory_path / "header.der", "rb") as f:
        header_data = f.read()
    header = StrictKeystoreHeader.load(header_data)


@then(u'the header file does not contain the raw master key bytes')
def step_impl(context):
    with open(context.key_directory_path / "header.der", "rb") as f:
        header_data = f.read()
    assert b"raw master key bytes" not in header_data
    

@given(u'a key directory created with passphrase "correct horse battery staple"')
def step_impl(context):
    context.execute_steps(u'''
        Given a passphrase "correct horse battery staple"
        When I create a key directory at a fresh path with that passphrase
    ''')


@when(u'I open that key directory with passphrase "correct horse battery staple"')
def step_impl(context):
    context.key_directory = KeyDirectory.open(context.key_directory_path, "correct horse battery staple")


@then(u'the key directory opens successfully')
def step_impl(context):
    pass # If no exception was raised, the key directory opened successfully.


@when(u'I attempt to open that key directory with passphrase "wrong passphrase"')
def step_impl(context):
    try:
        _ = KeyDirectory.open(context.key_directory_path, "wrong passphrase")
    except WrongPassphrase as e:
        context.open_error = e


@then(u'opening the key directory fails with WrongPassphrase')
def step_impl(context):
    assert isinstance(context.open_error, WrongPassphrase), "Expected WrongPassphrase exception, got: {}".format(type(context.open_error))


@then(u'the resulting error message does not contain "correct horse battery staple"')
def step_impl(context):
    assert "correct horse battery staple" not in str(context.open_error), "Error message contains the passphrase: {}".format(str(context.open_error))


@then(u'the resulting error message does not contain "wrong passphrase"')
def step_impl(context):
    assert "wrong passphrase" not in str(context.open_error), "Error message contains the wrong passphrase: {}".format(str(context.open_error))


@given(u'a directory that already contains an unrelated file')
def step_impl(context):
    context.temp_dir = tempfile.TemporaryDirectory()
    context.key_directory_path = Path(context.temp_dir.name) / "key_directory"
    context.key_directory_path.mkdir(parents=True, exist_ok=False)
    (context.key_directory_path / "unrelated_file.txt").write_text("This is an unrelated file.")


@when(u'I attempt to create a key directory at that same path')
def step_impl(context):
    try:
        context.key_directory = KeyDirectory.create(context.key_directory_path, "some passphrase")
    except KeyDirectoryError as e:
        context.create_error = e


@then(u'creating the key directory fails')
def step_impl(context):
    assert isinstance(context.create_error, KeyDirectoryError), "Expected KeyDirectoryError exception, got: {}".format(type(context.create_error))


@given(u'a key directory created with passphrase "pass"')
def step_impl(context):
    context.temp_dir = tempfile.TemporaryDirectory()
    context.key_directory_path = Path(context.temp_dir.name) / "key_directory"
    context.key_directory = KeyDirectory.create(context.key_directory_path, "pass")


@then(u'the key directory itself is readable and writable only by its owner')
def step_impl(context):
    assert oschmod.get_mode(str(context.key_directory_path)) & 0o777 == 0o700, "Key directory permissions are not 700"


@then(u'the public and private subdirectories are readable and writable only by their owner')
def step_impl(context):
    assert oschmod.get_mode(str(context.key_directory_path / "public")) & 0o777 == 0o700, "Public subdirectory permissions are not 700"
    assert oschmod.get_mode(str(context.key_directory_path / "private")) & 0o777 == 0o700, "Private subdirectory permissions are not 700"


@then(u'the header file is readable and writable only by its owner')
def step_impl(context):
    assert oschmod.get_mode(str(context.key_directory_path / "header.der")) & 0o777 == 0o600, "Header file permissions are not 600"


@when(u'I create a key directory at a fresh path with that passphrase using 100 PBKDF2 iterations')
def step_impl(context):
    context.temp_dir = tempfile.TemporaryDirectory()
    context.key_directory_path = Path(context.temp_dir.name) / "key_directory"
    context.key_directory = KeyDirectory.create(context.key_directory_path, "a", iterations=100)


@when(u'I add a public key and a private key to it')
def step_impl(context):
    context.private_key = create_mlkem_keypair(level=768)    
    context.key_directory.add_public_key(context.private_key[0])
    context.key_directory.add_private_key(*context.private_key)


@when(u'I create a key directory at a fresh path with that passphrase using {iterations:d} PBKDF2 iterations')
def step_impl(context, iterations: int):
    context.temp_dir = tempfile.TemporaryDirectory()
    context.key_directory_path = Path(context.temp_dir.name) / "key_directory"
    context.key_directory_path.mkdir(parents=True, exist_ok=False)
    context.key_directory = KeyDirectory.create(context.key_directory_path, context.passphrase, iterations=iterations)
