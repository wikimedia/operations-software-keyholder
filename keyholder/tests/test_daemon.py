"""SSH daemon main functionality tests."""

import collections
import io
import logging

import nacl.signing
from Crypto.PublicKey import RSA
import pytest

from keyholder import daemon
from keyholder.daemon import AGENT_MAX_LEN, SshAgentProtocolError
from keyholder.protocol.types import SshBytes, SshRequestPublicKeySignature
from keyholder.protocol.agent import (
    SshAgentRequest,
    SshAgentRequestCode,
    SshAgentResponse,
    SshAgentResponseCode,
    SshAgentLock,
    SshAgentSignatureFlags,
)

# pylint: disable=redefined-outer-name


class SshAgentMockConfig:
    """Mock version of SshAgentConfig, just holding state."""

    # pylint: disable=too-few-public-methods
    def __init__(self):
        self.perms = {}


class SshAgentMockServer:
    """Mock version of SshAgentServer, just holding state."""

    # pylint: disable=too-few-public-methods
    def __init__(self):
        self.keys = collections.OrderedDict()
        self.config = SshAgentMockConfig()
        self.lock = daemon.SshLock()


class SshAgentMockHandler(daemon.SshAgentHandler):
    """Mock version of SshAgentHandler, replacing I/O operations."""

    # pylint: disable=super-init-not-called
    def __init__(self):
        self.rfile = io.BytesIO()
        self.wfile = io.BytesIO()
        self.setup()

    def setup(self):
        self.server = SshAgentMockServer()
        self.user, self.groups = "nobody", {"nogroup"}

    def su(self, user, groups=None):  # pylint: disable=invalid-name
        """su to a specified user (and optionally, group."""
        # pylint: disable=attribute-defined-outside-init
        self.user = user
        if groups:
            self.groups = groups

    def write_to_agent(self, msg):
        """mock-specific function: write input to the read buffer."""
        self.rfile.write(msg)
        self.rfile.seek(-len(msg), io.SEEK_END)
        # initialize a new write buffer for the response
        self.wfile = io.BytesIO()

    def read_from_agent(self):
        """mock-specific function: read from the write buffer."""
        # seek to 0 assuming we have a clean buffer
        self.wfile.seek(0)
        read = self.wfile.read()
        response = SshAgentResponse.parse(read)
        return response.code, response.message

    def communicate(self, msg):
        """mock-specific function: write then read."""
        self.write_to_agent(msg)
        self.handle()
        return self.read_from_agent()


@pytest.fixture(scope="function")
def handler():
    """A fixture for holding an instance of SshAgentMockHandler."""
    return SshAgentMockHandler()


@pytest.mark.parametrize(
    "msg, exception",
    [
        (b"", EOFError),
        (b"\x00\x00\x00\x00", SshAgentProtocolError),
        (b"\x00\x00\x00\x04abc", EOFError),
        (b"\x00\x00\x00\x04\x00\x00\x00\x00", SshAgentProtocolError),
        (SshBytes.build(SshBytes.build(b"abc")), SshAgentProtocolError),
        (
            SshBytes.build(SshBytes.build(b"a" * AGENT_MAX_LEN)),
            SshAgentProtocolError,
        ),
    ],
)
def test_recv_request_invalid(handler, msg, exception):
    """Test invalid requests."""
    with pytest.raises(exception):
        handler.write_to_agent(msg)
        handler.recv_request()


def test_recv_request(handler):
    """Test a valid request."""
    handler.write_to_agent(
        SshAgentRequest.build(
            {
                "code": SshAgentRequestCode.LOCK,
                "message": SshAgentLock.build(b"passphrase"),
            }
        )
    )
    code, message = handler.recv_request()
    assert code == SshAgentRequestCode.LOCK
    assert message == SshAgentLock.build(b"passphrase")


@pytest.mark.parametrize(
    "msg",
    [
        b"\x00\x00\x00\x00",
        b"\x00\x00\x00\x04\x00\x00\x00\x00",
        SshBytes.build(SshBytes.build(b"abc")),
        SshBytes.build(SshBytes.build(b"a" * (AGENT_MAX_LEN + 1))),
    ],
)
def test_handle_invalid(handler, caplog, msg):
    """Test invalid requests."""
    caplog.set_level(logging.INFO)
    handler.write_to_agent(msg)
    handler.handle()
    assert "Invalid request received" in caplog.text


def test_send_invalid(handler):
    """Attempt to send invalid messages."""
    with pytest.raises(SshAgentProtocolError):
        handler.send_response(666)


def test_send_ioerror(handler, caplog):
    """Attempt to send to a closed socket."""
    caplog.set_level(logging.INFO)
    handler.wfile.close()
    handler.send_response(SshAgentResponseCode.SUCCESS)
    assert "Response write failed" in caplog.text


def test_permissions(handler):
    """Test the various permissions functions."""
    handler.su("root")
    assert handler.is_superuser()
    assert handler.is_allowed("dummy")

    handler.su("nobody")
    assert not handler.is_superuser()


def test_handle_unimplemented(handler, caplog):
    """Test an unimplemented function."""
    caplog.set_level(logging.DEBUG)
    req_code = SshAgentRequestCode.V1_ADD_RSA_ID_CONSTRAINED
    v1_request = SshAgentRequest.build({"code": req_code, "message": b""})
    code, _ = handler.communicate(v1_request)
    assert code == SshAgentResponseCode.FAILURE
    assert "Request type %s not implemented" % req_code.name in caplog.text


def test_handle_lock_unlock(handler):
    """Test agent locking and unlocking."""
    lock_request = SshAgentRequest.build(
        {
            "code": SshAgentRequestCode.LOCK,
            "message": SshAgentLock.build(b"passphrase"),
        }
    )
    unlock_request = SshAgentRequest.build(
        {
            "code": SshAgentRequestCode.UNLOCK,
            "message": SshAgentLock.build(b"passphrase"),
        }
    )
    unlock_invalid_request = SshAgentRequest.build(
        {
            "code": SshAgentRequestCode.UNLOCK,
            "message": SshAgentLock.build(b"invalid"),
        }
    )

    # start with an unlocked state
    assert not handler.server.lock.is_locked()

    # try once with no privileges
    handler.su("nobody")
    code, _ = handler.communicate(lock_request)
    assert code == SshAgentResponseCode.FAILURE

    # then try again with the right privileges
    handler.su("root")
    code, _ = handler.communicate(lock_request)
    assert code == SshAgentResponseCode.SUCCESS
    assert handler.server.lock.is_locked()

    # then attempt to lock twice
    handler.su("root")
    code, _ = handler.communicate(lock_request)
    assert code == SshAgentResponseCode.FAILURE

    # ensure that no operations are allowed, even for root
    handler.su("nobody")
    assert not handler.is_allowed("dummy")
    handler.su("root")
    assert not handler.is_allowed("dummy")

    handler.su("nobody")
    # try unlocking as a non-superuser
    code, _ = handler.communicate(unlock_request)
    assert code == SshAgentResponseCode.FAILURE
    assert handler.server.lock.is_locked()

    handler.su("root")
    # try first with an invalid passphrase
    code, _ = handler.communicate(unlock_invalid_request)
    assert code == SshAgentResponseCode.FAILURE
    assert handler.server.lock.is_locked()

    # then try again with the right passphrase + user, i.e. actually unlock
    code, _ = handler.communicate(unlock_request)
    assert code == SshAgentResponseCode.SUCCESS
    assert not handler.server.lock.is_locked()

    # try unlocking the unlocked agent again
    code, _ = handler.communicate(unlock_request)
    assert code == SshAgentResponseCode.FAILURE
    assert not handler.server.lock.is_locked()


def test_add_identity_invalid(handler):
    """Test adding invalid identities."""
    # first try to add an invalid key type
    ssh_add_identity_invalid = SshAgentRequest.build(
        {
            "code": SshAgentRequestCode.ADD_IDENTITY,
            "message": {"key_type": "ssh-invalid", "key": b"invalid"},
        }
    )

    handler.su("root")
    code, _ = handler.communicate(ssh_add_identity_invalid)
    assert code == SshAgentResponseCode.FAILURE

    # then an invalid ed25519 key
    ssh_add_identity_invalid = SshAgentRequest.build(
        {
            "code": SshAgentRequestCode.ADD_IDENTITY,
            "message": {
                "key_type": "ssh-ed25519",
                "key": {
                    "enc_a": b"invalid",
                    "k_enc_a": b"invalid",
                    "comment": "comment-invalid",
                },
            },
        }
    )
    handler.su("root")
    code, _ = handler.communicate(ssh_add_identity_invalid)
    assert code == SshAgentResponseCode.FAILURE


def test_add_identity_rsa(handler):
    """Test adding an RSA identity."""
    # generate an RSA key
    rsa_key = RSA.generate(2048)

    # then add the key to the agent
    ssh_add_identity = SshAgentRequest.build(
        {
            "code": SshAgentRequestCode.ADD_IDENTITY,
            "message": {
                "key_type": "ssh-rsa",
                "key": {
                    "n": rsa_key.n,
                    "e": rsa_key.e,
                    "d": rsa_key.d,
                    "iqmp": rsa_key.u,
                    "p": rsa_key.p,
                    "q": rsa_key.q,
                    "comment": "comment",
                },
            },
        }
    )
    # first try as a non-privileged user (and fail)
    handler.su("nobody")
    code, _ = handler.communicate(ssh_add_identity)
    assert code == SshAgentResponseCode.FAILURE

    # then actually add them to the agent
    handler.su("root")
    code, _ = handler.communicate(ssh_add_identity)
    assert code == SshAgentResponseCode.SUCCESS


def test_add_identity_ed25519(handler):
    """Test adding an Ed25519 identity."""
    # generate an Ed25519 key
    private_key = nacl.signing.SigningKey.generate()
    k = private_key.encode()
    enc_a = private_key.verify_key.encode()
    k_enc_a = k + enc_a

    # then add the key to the agent
    ssh_add_identity = SshAgentRequest.build(
        {
            "code": SshAgentRequestCode.ADD_IDENTITY,
            "message": {
                "key_type": "ssh-ed25519",
                "key": {
                    "enc_a": enc_a,
                    "k_enc_a": k_enc_a,
                    "comment": "comment",
                },
            },
        }
    )
    # first try as a non-privileged user (and fail)
    handler.su("nobody")
    code, _ = handler.communicate(ssh_add_identity)
    assert code == SshAgentResponseCode.FAILURE

    # then actually add them to the agent
    handler.su("root")
    code, _ = handler.communicate(ssh_add_identity)
    assert code == SshAgentResponseCode.SUCCESS


def test_add_remove_identities(handler):
    """Test adding, listing and removing identities."""
    ssh_request_identities = SshAgentRequest.build(
        {"code": SshAgentRequestCode.REQUEST_IDENTITIES, "message": b""}
    )

    handler.su("root")
    code, message = handler.communicate(ssh_request_identities)
    assert code == SshAgentResponseCode.IDENTITIES_ANSWER
    assert len(message) == 0  # pylint: disable=len-as-condition

    # now add a few keys to the agent
    n_keys = 3
    for key_id in range(n_keys):
        # generate an Ed25519 key
        private_key = nacl.signing.SigningKey.generate()
        k = private_key.encode()
        enc_a = private_key.verify_key.encode()
        k_enc_a = k + enc_a

        # then add this key to the agent
        ssh_add_identity = SshAgentRequest.build(
            {
                "code": SshAgentRequestCode.ADD_IDENTITY,
                "message": {
                    "key_type": "ssh-ed25519",
                    "key": {
                        "enc_a": enc_a,
                        "k_enc_a": k_enc_a,
                        "comment": "comment%d" % key_id,
                    },
                },
            }
        )
        # first try as a non-privileged user (and fail)
        handler.su("nobody")
        code, _ = handler.communicate(ssh_add_identity)
        assert code == SshAgentResponseCode.FAILURE

        # then actually add them to the agent
        handler.su("root")
        code, _ = handler.communicate(ssh_add_identity)
        assert code == SshAgentResponseCode.SUCCESS

    # re-add the last added key -- this, combined with the n_keys check below,
    # makes sure that duplicates are suppressed
    handler.su("root")
    code, _ = handler.communicate(ssh_add_identity)
    assert code == SshAgentResponseCode.SUCCESS

    # list identities, but with no permissions (i.e. should get empty list)
    handler.su("nobody")
    code, _ = handler.communicate(ssh_request_identities)
    assert code == SshAgentResponseCode.IDENTITIES_ANSWER
    assert len(message) == 0  # pylint: disable=len-as-condition

    # list identities, but with superuser permissions
    handler.su("root")
    code, message = handler.communicate(ssh_request_identities)
    assert code == SshAgentResponseCode.IDENTITIES_ANSWER
    assert len(message) == n_keys
    assert message[0].comment == "comment0"

    # now, try to remove the first identity from the agent
    key_blob_to_delete = message[0].key_blob
    ssh_remove_identity = SshAgentRequest.build(
        {
            "code": SshAgentRequestCode.REMOVE_IDENTITY,
            "message": {"key_blob": key_blob_to_delete},
        }
    )
    handler.su("nobody")
    code, _ = handler.communicate(ssh_remove_identity)
    assert code == SshAgentResponseCode.FAILURE

    handler.su("root")
    code, _ = handler.communicate(ssh_remove_identity)
    assert code == SshAgentResponseCode.SUCCESS

    # ...and verify that it was deleted
    handler.su("root")
    code, message = handler.communicate(ssh_request_identities)
    assert code == SshAgentResponseCode.IDENTITIES_ANSWER
    assert len(message) == n_keys - 1
    assert message[0].comment == "comment1"

    # try removing the same key again (should fail)
    handler.su("root")
    code, _ = handler.communicate(ssh_remove_identity)
    assert code == SshAgentResponseCode.FAILURE


def test_remove_all_identities(handler):
    """Verify that removing all identities works."""
    # add a key or two
    test_add_identity_rsa(handler)
    test_add_identity_ed25519(handler)

    # then try to remove all identities from the agent
    ssh_remove_all_identities = SshAgentRequest.build(
        {"code": SshAgentRequestCode.REMOVE_ALL_IDENTITIES, "message": b""}
    )
    handler.su("nobody")
    code, _ = handler.communicate(ssh_remove_all_identities)
    assert code == SshAgentResponseCode.FAILURE

    handler.su("root")
    code, _ = handler.communicate(ssh_remove_all_identities)
    assert code == SshAgentResponseCode.SUCCESS

    # and verify that they're all gone
    handler.su("root")
    ssh_request_identities = SshAgentRequest.build(
        {"code": SshAgentRequestCode.REQUEST_IDENTITIES, "message": b""}
    )
    code, message = handler.communicate(ssh_request_identities)
    assert code == SshAgentResponseCode.IDENTITIES_ANSWER
    assert len(message) == 0  # pylint: disable=len-as-condition


def test_sign_request(handler):
    """Test that signature requests work."""
    test_add_identity_ed25519(handler)
    test_add_identity_rsa(handler)

    handler.su("root")
    ssh_request_identities = SshAgentRequest.build(
        {"code": SshAgentRequestCode.REQUEST_IDENTITIES, "message": b""}
    )
    code, message = handler.communicate(ssh_request_identities)
    assert code == SshAgentResponseCode.IDENTITIES_ANSWER
    assert len(message) == 2

    for identity in message:
        key_blob = identity.key_blob
        ssh_signature = SshRequestPublicKeySignature.build(
            {
                "session": b"dummy-session",
                "username": "dummy-username",
                "servicename": "dummy-servicename",
                "algo": "ssh-ed25519",
                "key_blob": key_blob,
            }
        )
        ssh_sign_request = SshAgentRequest.build(
            {
                "code": SshAgentRequestCode.SIGN_REQUEST,
                "message": {
                    "key_blob": key_blob,
                    "data": ssh_signature,
                    "flags": SshAgentSignatureFlags.AGENT_NO_FLAGS,
                },
            }
        )
        # ask for a sign request (but with a key that we don't have perms for)
        handler.su("nobody")
        code, _ = handler.communicate(ssh_sign_request)
        assert code == SshAgentResponseCode.FAILURE

        # now do the same, but with superuser perms
        handler.su("root")
        code, _ = handler.communicate(ssh_sign_request)
        assert code == SshAgentResponseCode.SIGN_RESPONSE

        # ask with an invalid signature request (OpenSSH accepts this!)
        ssh_invalid_sign_request = SshAgentRequest.build(
            {
                "code": SshAgentRequestCode.SIGN_REQUEST,
                "message": {
                    "key_blob": key_blob,
                    "data": b"invalid",
                    "flags": SshAgentSignatureFlags.AGENT_NO_FLAGS,
                },
            }
        )
        handler.su("root")
        code, _ = handler.communicate(ssh_invalid_sign_request)
        assert code == SshAgentResponseCode.FAILURE

    # try with a non-existing key
    ssh_signature = SshRequestPublicKeySignature.build(
        {
            "session": b"dummy-session",
            "username": "dummy-username",
            "servicename": "dummy-servicename",
            "algo": "ssh-ed25519",
            "key_blob": b"random-garbage",
        }
    )
    ssh_sign_request = SshAgentRequest.build(
        {
            "code": SshAgentRequestCode.SIGN_REQUEST,
            "message": {
                "key_blob": b"random-garbage",
                "data": ssh_signature,
                "flags": SshAgentSignatureFlags.AGENT_NO_FLAGS,
            },
        }
    )
    handler.su("root")
    code, _ = handler.communicate(ssh_sign_request)
    assert code == SshAgentResponseCode.FAILURE


@pytest.mark.skip(reason="Takes too long")
def test_agent_max_len(handler):
    """Add a lot of keys then lists them, to trigger AGENT_MAX_LEN."""
    n_keys = 4000
    for key_id in range(n_keys):
        k = key_id.to_bytes(32, "big")
        private_key = nacl.signing.SigningKey(k)
        enc_a = private_key.verify_key.encode()
        k_enc_a = k + enc_a

        # then add this key to the agent
        ssh_add_identity = SshAgentRequest.build(
            {
                "code": SshAgentRequestCode.ADD_IDENTITY,
                "message": {
                    "key_type": "ssh-ed25519",
                    "key": {
                        "enc_a": enc_a,
                        "k_enc_a": k_enc_a,
                        "comment": "comment%d" % key_id,
                    },
                },
            }
        )
        # then actually do it
        handler.su("root")
        code, _ = handler.communicate(ssh_add_identity)
        assert code == SshAgentResponseCode.SUCCESS

    ssh_request_identities = SshAgentRequest.build(
        {"code": SshAgentRequestCode.REQUEST_IDENTITIES, "message": b""}
    )

    code, _ = handler.communicate(ssh_request_identities)
    assert code == SshAgentResponseCode.FAILURE
