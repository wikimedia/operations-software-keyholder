"""Test our server implementation using OpenSSH's ssh-add client."""

import gc
import os
import subprocess
import time
from threading import Thread
import pytest
from keyholder import daemon

# pylint:disable=redefined-outer-name


@pytest.fixture
def agent_socket(tmp_path):
    """Returns the location of the agent's socket (a Path)."""
    return tmp_path / "socket"


@pytest.fixture(autouse=True)
def keyholder_instance(agent_socket, shared_datadir, monkeypatch, caplog):
    """Sets ups a keyholder daemon instance.

    The instance runs in debug mode, and in a separate Thread. It listens to a
    socket in a well-known location, and uses the test data for key/auth."""

    # assume we're a superuser and can add/remove keys
    monkeypatch.setattr(daemon.SshAgentHandler, "is_superuser", lambda x: True)

    key_dir = shared_datadir / "key-dir"
    auth_dir = shared_datadir / "auth-dir"
    args = [
        "--bind",
        str(agent_socket),
        "--key-dir",
        str(key_dir),
        "--auth-dir",
        str(auth_dir),
    ]
    keyholder_thread = Thread(target=daemon.main, args=(args,), daemon=True)
    keyholder_thread.start()
    for _ in range(50):
        if "Initialized and serving requests" in caplog.text:
            break
        time.sleep(0.1)

    assert "Initialized and serving requests" in caplog.text
    yield keyholder_thread

    # terrible hack to run a method on the SocketServer instance
    for obj in gc.get_objects():
        if isinstance(obj, daemon.SshAgentServer):
            obj.shutdown()


def ssh_add(agent_socket, args):
    """Executes OpenSSH's ssh-add on a given socket and with the given args."""
    try:
        proc = subprocess.Popen(
            ["ssh-add"] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"LANG": "C", "SSH_AUTH_SOCK": str(agent_socket)},
        )
    except FileNotFoundError:
        pytest.skip("ssh-add not found")

    try:
        out, err = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        assert True

    return out.decode("ascii"), err.decode("ascii")


def test_openssh_basic(agent_socket):
    """Tests whether the agent is responsive."""
    # list keys (nothing to see here)
    out, err = ssh_add(agent_socket, ["-L"])
    assert "The agent has no identities." in out
    assert err == ""


def test_openssh_add_remove(agent_socket, caplog, shared_datadir):
    """Tests whether add/remove/list works."""
    private_key = shared_datadir / "key-dir" / "id_ed25519"
    public_key = shared_datadir / "key-dir" / "id_ed25519.pub"

    # OpenSSH refuses to load a key if it's o+r, so chmod here
    os.chmod(str(private_key), 0o600)

    # add our test key
    out, err = ssh_add(agent_socket, [str(private_key)])
    assert "Identity added" in err
    assert "Successfully added key" in caplog.text

    # list keys, expect to find our key
    out, err = ssh_add(agent_socket, ["-L"])
    assert public_key.read_text() == out
    assert err == ""

    # and delete our key
    out, err = ssh_add(agent_socket, ["-d", str(public_key)])
    assert "Identity removed" in err
    assert "Successfully removed key" in caplog.text

    # list again, and expect to find nothing again
    out, err = ssh_add(agent_socket, ["-L"])
    assert "The agent has no identities." in out
    assert err == ""


def test_openssh_remove_all(agent_socket, caplog, shared_datadir):
    """Tests whether add/remove all keys/list works."""
    private_key = shared_datadir / "key-dir" / "id_ed25519"
    public_key = shared_datadir / "key-dir" / "id_ed25519.pub"

    # OpenSSH refuses to load a key if it's o+r, so chmod here
    os.chmod(str(private_key), 0o600)

    # add our test key
    out, err = ssh_add(agent_socket, [str(private_key)])
    assert "Identity added" in err
    assert "Successfully added key" in caplog.text

    # list keys, expect to find our key
    out, err = ssh_add(agent_socket, ["-L"])
    assert public_key.read_text() == out
    assert err == ""

    # and delete all keys
    out, err = ssh_add(agent_socket, ["-D"])
    assert "All identities removed" in err
    assert "Removed all keys" in caplog.text

    # list again, and expect to find nothing again
    out, err = ssh_add(agent_socket, ["-L"])
    assert "The agent has no identities." in out
    assert err == ""
