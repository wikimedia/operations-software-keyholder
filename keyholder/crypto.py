"""
SSH public/private keys crypto implementation.

Copyright 2018 Wikimedia Foundation, Inc.
Copyright 2018 Faidon Liambotis <faidon@wikimedia.org>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY CODE, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import base64
import binascii
import hashlib
import os
from keyholder.protocol.agent import SshAgentSignatureFlags
from keyholder.protocol.types import SshRSAKeyBlob, SshEd25519KeyBlob

# for RSA
from Crypto.Hash import SHA, SHA256, SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

# for ed25519
import nacl.signing


def ssh_fingerprint(blob, hash_type='sha256'):
    """Returns the fingerprint of a key blob, in OpenSSH format."""
    if hash_type == 'md5':
        digest = hashlib.md5(blob).digest()
        hexdigest = b':'.join([binascii.hexlify(bytes([b])) for b in digest])
        return 'MD5:' + hexdigest.decode('ascii')
    elif hash_type == 'sha256':
        digest = hashlib.sha256(blob).digest()
        b64 = base64.b64encode(digest)
        return 'SHA256:' + b64.rstrip(b'=').decode('ascii')
    else:
        raise TypeError('Unrecognized fingerprint type %s' % hash_type)


class SshLock:
    """An instance of a lock, with lock() and unlock() operations."""
    def __init__(self):
        self.salt = os.urandom(16)
        self.iter = 100 * 1000
        self.locked = None

    def _pbkdf2(self, passphrase):
        """Helper function to return the PBKDF2 of a passphrase."""
        return hashlib.pbkdf2_hmac('sha256', passphrase, self.salt, self.iter)

    def is_locked(self):
        """Returns True if object is locked, False otherwise."""
        return self.locked is not None

    def lock(self, passphrase):
        """Lock the object with passphrase.

        Returns True if object was successfully locked.
        Returns False if object was already locked.
        """
        if not self.is_locked():
            self.locked = self._pbkdf2(passphrase)
            return True
        else:
            return False

    def unlock(self, passphrase):
        """Unlock the object with passphrase.

        Returns False if object was not already locked.
        Returns False if passphrase did not match.
        Returns True if object was successfully unlocked.
        """
        if not self.is_locked():
            return False

        attempted = self._pbkdf2(passphrase)
        if attempted == self.locked:
            self.locked = None
            return True
        else:
            return False

    def __repr__(self):
        return '<%s: %s>' % (self.__class__.__name__, self.is_locked())


class SshBaseKey:
    """Base class to represents an SSH key."""
    @property
    def fingerprint(self, hash_type='sha256'):
        """Returns the fingerprint of the current public key."""
        return ssh_fingerprint(self.key_blob, hash_type)

    def __repr__(self):
        return '<%s: %s>' % (self.__class__.__name__, self.fingerprint)

    @property
    def key_blob(self):
        """Returns the key blob of the public key, in OpenSSH format."""
        raise NotImplementedError

    def sign(self, data, flags):
        """Signs `data` with the private key."""
        raise NotImplementedError


class SshRSAKey(SshBaseKey):
    """SSH RSA key."""
    def __init__(self, tup, comment):
        super().__init__()
        self.private_key = RSA.construct(tup)
        self.comment = comment

    @property
    def key_blob(self):
        return SshRSAKeyBlob.build({
            'e': self.private_key.e,
            'n': self.private_key.n,
        })

    def sign(self, data, flags):
        # pylint: disable=redefined-variable-type
        if flags == SshAgentSignatureFlags.AGENT_RSA_SHA2_256:
            hsh = SHA256.new(data)
        elif flags == SshAgentSignatureFlags.AGENT_RSA_SHA2_512:
            hsh = SHA512.new(data)
        else:
            hsh = SHA.new(data)

        signer = PKCS1_v1_5.new(self.private_key)
        signature = signer.sign(hsh)

        return {
            'key_type': 'ssh-rsa',
            'signature': signature,
        }


class SshEd25519Key(SshBaseKey):
    """SSH Ed25519 key."""
    def __init__(self, enc_a, k_enc_a, comment):
        super().__init__()
        k = k_enc_a[:32]
        if k + enc_a != k_enc_a:
            raise TypeError('Invalid key: ENC(A) does not match k || ENC(A)')

        self.private_key = nacl.signing.SigningKey(k)
        self.public_key = self.private_key.verify_key
        self.comment = comment

        if self.public_key.encode() != enc_a:
            raise TypeError('Invalid key: ENC(A) does not match k')

    @property
    def key_blob(self):
        return SshEd25519KeyBlob.build({
            'public_key': self.public_key.encode(),
        })

    def sign(self, data, flags):
        signature = self.private_key.sign(data).signature
        return {
            'key_type': 'ssh-ed25519',
            'signature': signature,
        }
