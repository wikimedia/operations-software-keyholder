"""Fingerprint tests."""

import base64
import subprocess
import pytest
from keyholder.crypto import ssh_fingerprint


def test_ssh_fp_unknown():
    """Tests that invalid hash types raise an exception."""
    with pytest.raises(TypeError):
        ssh_fingerprint("example", "invalid-type")


def test_ssh_fp():
    """Test ssh_fingerprint() using fixed data."""
    blob = b"example"
    md5 = "MD5:1a:79:a4:d6:0d:e6:71:8e:8e:5b:32:6e:33:8a:e5:33"
    sha256 = "SHA256:UNhY4JhezH9gQYqvDMWrWH9CwlcKiECVqejMrND2VFw"
    assert ssh_fingerprint(blob, "md5") == md5
    assert ssh_fingerprint(blob, "sha256") == sha256


@pytest.mark.parametrize("hash_type", ["md5", "sha256"])
def test_ssh_fp_with_keygen(hash_type):
    """Test ssh_fingerprint() using ssh-keygen (if found)."""
    key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGwr0W7s7SGF2ZdLR3fHpyjeu6ex8rlCU0jxUq0LNBRs comment"

    _, key_blob64, _ = key.split()
    key_blob = base64.b64decode(key_blob64, validate=True)

    try:
        proc = subprocess.Popen(
            ["ssh-keygen", "-E", hash_type, "-lf", "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
    except FileNotFoundError:
        pytest.skip("ssh-keygen not found")

    try:
        # when moving to Python 3.6, use subprocess' encoding argument instead
        inp = (key + "\n").encode("ascii")
        out, _ = proc.communicate(input=inp, timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
        pytest.fail("ssh-keygen timed out")

    try:
        fingerprint = out.decode("ascii").split()[1]
    except IndexError:
        pytest.fail("Unexpected output from ssh-keygen: %s" % out)

    assert ssh_fingerprint(key_blob, hash_type) == fingerprint
