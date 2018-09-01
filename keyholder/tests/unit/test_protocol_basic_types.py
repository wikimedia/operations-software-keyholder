"""SSH basic data types tests."""

from keyholder.protocol.types import SshBytes
from construct.core import ConstructError
import pytest


@pytest.mark.parametrize("value, representation", [
    (b'foo', b'\x00\x00\x00\x03' + b'foo'),
    (b'a' * 0x1000, b'\x00\x00\x10\x00' + b'a' * 0x1000),
    (b'b' * 0x123456, b'\x00\x12\x34\x56' + b'b' * 0x123456),
    (b'', b'\x00\x00\x00\x00'),
])
def test_sshbytes(value, representation):
    """Tests the building and parsing of bytes."""
    built = SshBytes.build(value)
    assert built == representation

    parsed = SshBytes.parse(representation)
    assert parsed == value


def test_sshbytes_fail():
    """Tests that invalid bytes sequences fail parsing."""
    with pytest.raises(ConstructError):
        SshBytes.parse(b'\x00\x00\x00\x04' + b'bar')
