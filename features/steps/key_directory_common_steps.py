import tempfile
from pathlib import Path

from behave import given

from kem_make.keystore import KeyDirectory


@given(u'a key directory created with passphrase "pass"')
def step_impl(context):
    context.temp_dir = tempfile.TemporaryDirectory()
    context.key_directory_path = Path(context.temp_dir.name) / "key_directory"
    context.key_directory = KeyDirectory.create(context.key_directory_path, "pass")


