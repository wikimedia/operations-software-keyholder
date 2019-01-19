"""Lock class tests."""

from keyholder.crypto import SshLock


def test_ssh_lock():
    """Test various operations around an SshLock instance."""
    lock = SshLock()

    # pylint: disable=singleton-comparison

    # start with it being unlocked
    assert lock.is_locked() == False
    assert repr(lock) == "<SshLock: False>"

    # lock and test if locked
    assert lock.lock(b"passphrase") == True
    assert lock.is_locked() == True

    # wrong passphrase
    assert lock.unlock(b"wrong") == False
    assert lock.is_locked() == True

    # unlock and test if unlocked
    assert lock.unlock(b"passphrase") == True
    assert lock.is_locked() == False

    # unlock while unlocked
    assert lock.unlock(b"wrong") == False
    assert lock.is_locked() == False

    # lock while locked
    assert lock.lock(b"passphrase") == True
    assert lock.is_locked() == True
    assert lock.lock(b"again") == False
    assert lock.is_locked() == True
