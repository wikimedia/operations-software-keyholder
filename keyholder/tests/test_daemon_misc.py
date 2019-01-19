"""SSH daemon misc tests."""

import ctypes
import logging
import os
import signal
import pytest
from keyholder import daemon


def test_config(caplog, shared_datadir):
    """Test the configuration handling and loading."""
    caplog.set_level(logging.INFO)

    # load with a non-existing directory
    not_a_dir = "/nonexistent"
    args = daemon.parse_args(["--auth-dir", not_a_dir, "--key-dir", not_a_dir])
    config = daemon.SshAgentConfig(args.auth_dir, args.key_dir)
    assert "/nonexistent is not a directory" in caplog.text

    # load with test data
    auth_dir = shared_datadir / "auth-dir"
    key_dir = shared_datadir / "key-dir"
    config = daemon.SshAgentConfig(auth_dir, key_dir)
    assert "Successfully loaded" in caplog.text
    assert "Could not parse key " + str(key_dir / "invalid.pub") in caplog.text
    assert "Fingerprint not found for key nonexistingkey" in caplog.text
    assert "Unable to parse " + str(auth_dir / "invalid.yaml") in caplog.text

    # try making a key and config inaccesible
    os.chmod(str(key_dir / "invalid.pub"), 0)
    os.chmod(str(auth_dir / "invalid.yaml"), 0)

    # reload and test for the error reading the above
    config.sighandle(signal.SIGHUP, None)
    assert "reloading" in caplog.text
    assert "Unable to read" in caplog.text


def test_parse_args():
    """Test the parsing of arguments (good and bad)."""
    args = daemon.parse_args("")
    assert not args.debug

    args = daemon.parse_args(["--debug"])
    assert args.debug

    with pytest.raises(SystemExit) as exc:
        daemon.parse_args(["--help"])
    assert exc.type == SystemExit
    assert exc.value.code == 0

    with pytest.raises(SystemExit) as exc:
        daemon.parse_args(["--unknown"])
    assert exc.type == SystemExit
    assert exc.value.code == 2


@pytest.mark.parametrize("debug", [False, True])
def test_setup_logging(debug):
    """Test logging setup (mostly stub for now)."""
    daemon.setup_logging(debug)


def test_mlockall(monkeypatch):
    """Test mlockall (sort of, that's really impossible)."""

    # pylint: disable=unused-argument, invalid-name,too-few-public-methods
    def mock_strerror_exc(errno):
        raise ValueError("strerror raises ValueError on certain platforms")

    def mock_CDLL_exc(name, use_errno=False):
        raise OSError("CDLL raises OSError sometimes")

    def mock_CDLL_dummy(name, use_errno=False):
        class libc:
            """Mock (a subset of) libc6."""

            @staticmethod
            def mlockall(flags):
                """Mock mlockall()"""
                return 0

        return libc()

    with monkeypatch.context() as mpatch:
        mpatch.setattr(ctypes, "CDLL", mock_CDLL_exc)
        daemon.mlockall()

    with monkeypatch.context() as mpatch:
        mpatch.setattr(ctypes, "CDLL", mock_CDLL_dummy)
        daemon.mlockall()

    with monkeypatch.context() as mpatch:
        mpatch.setattr(os, "strerror", mock_strerror_exc)
        daemon.mlockall()
