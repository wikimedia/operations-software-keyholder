"""Ed25519 tests."""

import pytest
from keyholder.crypto import SshEd25519Key

# pylint: disable=line-too-long


def test_ssh_ed25519_invalid_key():
    """Test loading invalid Ed25519 keys."""
    with pytest.raises(TypeError):
        enc_a = b"invalid-public"
        k = b"invalid-private"
        k_enc_a = k + enc_a
        SshEd25519Key(enc_a, k_enc_a, "comment")

    with pytest.raises(TypeError):
        enc_a = b"invalid-public"
        k = b"Le\xa3S@h\x14u\xbdp\xaa\x03\xfe\xf91\x8cS?\xbe\xdc\x15\xe2\x95\xbf\x8bA\xa0$b\x91\xb8n"
        k_enc_a = k + enc_a
        SshEd25519Key(enc_a, k_enc_a, "comment")


def test_ssh_ed25519_key():
    """Test various operations of SshEd25519Key."""
    enc_a = b'\x85\xcf\xe5\x15?2\xb1\xaa\x03A\xc1d\tB"f\x9a\xe8\x9d\t\xf3\xb3\xf4\xb6\xc8\xfap\xe0\xf1\x89\xe7\xd4'
    k = b"Le\xa3S@h\x14u\xbdp\xaa\x03\xfe\xf91\x8cS?\xbe\xdc\x15\xe2\x95\xbf\x8bA\xa0$b\x91\xb8n"
    k_enc_a = k + enc_a

    key = SshEd25519Key(enc_a, k_enc_a, "comment")

    key_fingerprint = "SHA256:N1isjDPXXD7jxQKvRnhX9h4xtz0TkXbQ+9/Slb6jNMM"
    assert key.fingerprint == key_fingerprint

    assert repr(key) == "<%s: %s>" % ("SshEd25519Key", key_fingerprint)

    key_blob = b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 \x85\xcf\xe5\x15?2\xb1\xaa\x03A\xc1d\tB"f\x9a\xe8\x9d\t\xf3\xb3\xf4\xb6\xc8\xfap\xe0\xf1\x89\xe7\xd4'
    assert key.key_blob == key_blob

    signed = {
        "key_type": "ssh-ed25519",
        "signature": b'\x0c\x04\xcf\x02RQ~\x9c\xb8\x7f\x86\x02\x95zo\xe4p\x02]"\xc5\x89Y\xfcZDg\x07\r\x9a\xd3\xe4\\\x82h\x04\x13\x98u\xe7\x7f\xf1v\x1cv\xec>[\xd5\xc3\xa7\xde\xba\xc7U\xc3\x1bm\x18iNy\x96\x0b',
    }
    assert key.sign(b"test", 0) == signed
