"""SSH basic data types tests."""

import pytest
from construct.core import ConstructError
from keyholder.protocol.types import SshBytes, SshString, SshMPInt


@pytest.mark.parametrize(
    "value, representation",
    [
        (b"foo", b"\x00\x00\x00\x03" + b"foo"),
        (b"a" * 0x1000, b"\x00\x00\x10\x00" + b"a" * 0x1000),
        (b"b" * 0x123456, b"\x00\x12\x34\x56" + b"b" * 0x123456),
        (b"", b"\x00\x00\x00\x00"),
    ],
)
def test_sshbytes(value, representation):
    """Tests the building and parsing of bytes."""
    built = SshBytes.build(value)
    assert built == representation

    parsed = SshBytes.parse(representation)
    assert parsed == value


def test_sshbytes_fail():
    """Tests that invalid bytes sequences fail parsing."""
    with pytest.raises(ConstructError):
        SshBytes.parse(b"\x00\x00\x00\x04" + b"bar")


@pytest.mark.parametrize(
    "value, representation",
    [
        ("foo", b"\x00\x00\x00\x03" + b"foo"),
        ("a" * 0x1000, b"\x00\x00\x10\x00" + b"a" * 0x1000),
        ("b" * 0x123456, b"\x00\x12\x34\x56" + b"b" * 0x123456),
        ("", b"\x00\x00\x00\x00"),
    ],
)
def test_sshstring(value, representation):
    """Tests the building and parsing of strings."""
    built = SshString.build(value)
    assert built == representation

    parsed = SshString.parse(representation)
    assert parsed == value


def test_sshstring_fail():
    """Tests that invalid string sequences fail parsing."""
    with pytest.raises(ConstructError):
        SshString.parse(b"\x00\x00\x00\x04" + b"bar")


@pytest.mark.parametrize(
    "value, representation",
    [
        (0x7F, b"\x00\x00\x00\x01\x7f"),
        (0xFF, b"\x00\x00\x00\x02\x00\xff"),
        (-0x7F, b"\x00\x00\x00\x01\x81"),
        (-0xFF, b"\x00\x00\x00\x02\xff\x01"),
        # RFC 4251's example values and their representation
        (0, b"\x00\x00\x00\x00"),
        (
            0x9A378F9B2E332A7,
            b"\x00\x00\x00\x08\x09\xa3\x78\xf9\xb2\xe3\x32\xa7",
        ),
        (0x80, b"\x00\x00\x00\x02\x00\x80"),
        (-0x1234, b"\x00\x00\x00\x02\xed\xcc"),
        (-0xDEADBEEF, b"\x00\x00\x00\x05\xff\x21\x52\x41\x11"),
        (0x21524111, b"\x00\x00\x00\x04\x21\x52\x41\x11"),
    ],
)
def test_sshmpint(value, representation):
    """Tests the building and parsing of multi-precision integers."""
    built = SshMPInt.build(value)
    assert built == representation

    parsed = SshMPInt.parse(representation)
    assert parsed == value


def test_sshmpint_fail():
    """Tests that invalid string sequences fail parsing."""
    with pytest.raises(ConstructError):
        SshMPInt.parse(b"\x00\x00\x00\x02\xaa")
