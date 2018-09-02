"""
SSH Agent Protocol

This is based on the draft RFC about the SSH Agent protocol
I-D.ietf-miller-ssh-agent (as of September 2018).

Earlier SSHv1 commands are listed for reference, but not intended to be used
anymore. They can be found here: <http://api.libssh.org/rfc/PROTOCOL.agent>

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

# pylint: disable=invalid-name

import enum
from keyholder.protocol.types import PyEnum, SshBytes, SshString, SshMPInt
from keyholder.protocol.types import SshSignature
from construct import Byte, Int32ub
from construct import GreedyBytes
from construct import Struct, FocusedSeq
from construct import Prefixed, Switch, Rebuild, Terminated
from construct import this, len_


@enum.unique
class SshAgentRequestCode(enum.IntEnum):
    """SSH Agent request codes."""
    V1_REQUEST_RSA_IDENTITIES = 1
    V1_RSA_CHALLENGE = 3
    V1_ADD_RSA_IDENTITY = 7
    V1_REMOVE_RSA_IDENTITY = 8
    V1_REMOVE_ALL_RSA_IDENTITIES = 9
    REQUEST_IDENTITIES = 11
    SIGN_REQUEST = 13
    ADD_IDENTITY = 17
    REMOVE_IDENTITY = 18
    REMOVE_ALL_IDENTITIES = 19
    ADD_SMARTCARD_KEY = 20
    REMOVE_SMARTCARD_KEY = 21
    LOCK = 22
    UNLOCK = 23
    V1_ADD_RSA_ID_CONSTRAINED = 24
    ADD_ID_CONSTRAINED = 25
    ADD_SMARTCARD_KEY_CONSTRAINED = 26
    EXTENSION = 27


@enum.unique
class SshAgentResponseCode(enum.IntEnum):
    """SSH Agent response codes."""
    V1_RSA_IDENTITIES_ANSWER = 2
    V1_RSA_RESPONSE = 4
    FAILURE = 5
    SUCCESS = 6
    IDENTITIES_ANSWER = 12
    SIGN_RESPONSE = 14
    EXTENSION_FAILURE = 28


@enum.unique
class SshAgentSignatureFlags(enum.Enum):
    """AGENTC_SIGN_REQUEST flags.

    These are flags that can, in theory, be combined, but in practice they all
    conflict with each other, hence they are listed as an Enum here.
    """
    AGENT_NO_FLAGS = 0
    V1_AGENT_OLD_SIGNATURE = 1
    AGENT_RSA_SHA2_256 = 2
    AGENT_RSA_SHA2_512 = 4


SshAgentIdentities = FocusedSeq(
    'keys',
    'nkeys' / Rebuild(Int32ub, len_(this.keys)),
    'keys' / Struct(
        'key_blob' / SshBytes,
        'comment' / SshString,
    )[this.nkeys],
    Terminated,
)

SshAddRSAKey = Struct(
    'n' / SshMPInt,
    'e' / SshMPInt,
    'd' / SshMPInt,
    'iqmp' / SshMPInt,
    'p' / SshMPInt,
    'q' / SshMPInt,
    'comment' / SshString,
)

SshAddEd25519Key = Struct(
    'enc_a' / SshBytes,
    'k_enc_a' / SshBytes,
    'comment' / SshString,
)

SshAddIdentity = Struct(
    'key_type' / SshString,
    'key' / Switch(
        this.key_type, {
            'ssh-ed25519': SshAddEd25519Key,
            'ssh-rsa': SshAddRSAKey,
        },
        default=GreedyBytes,
    ),
    Terminated,
)

SshRemoveIdentity = Struct(
    'key_blob' / SshBytes,
    Terminated
)

SshAgentSignRequest = Struct(
    'key_blob' / SshBytes,
    'data' / SshBytes,
    'flags' / PyEnum(Int32ub, SshAgentSignatureFlags),
    Terminated
)

SshAgentLock = SshAgentUnlock = FocusedSeq(
    'passphrase',
    'passphrase' / SshBytes,
    Terminated
)

# define and parse the size field separately in order to have a way to know how
# many bytes to expect to read on the socket.
SshAgentRequestHeader = Int32ub
SshAgentRequest = FocusedSeq(
    'request',
    'request' / Prefixed(Int32ub, Struct(
        'code' / PyEnum(Byte, SshAgentRequestCode),
        'message' / Switch(
            this.code, {
                SshAgentRequestCode.REQUEST_IDENTITIES: Terminated,
                SshAgentRequestCode.ADD_IDENTITY: SshAddIdentity,
                SshAgentRequestCode.REMOVE_IDENTITY: SshRemoveIdentity,
                SshAgentRequestCode.REMOVE_ALL_IDENTITIES: Terminated,
                SshAgentRequestCode.SIGN_REQUEST: SshAgentSignRequest,
                SshAgentRequestCode.LOCK: SshAgentLock,
                SshAgentRequestCode.UNLOCK: SshAgentUnlock,
            },
            default=GreedyBytes
        ),
        Terminated
    )),
    Terminated
)

SshAgentResponse = FocusedSeq(
    'response',
    'response' / Prefixed(Int32ub, Struct(
        'code' / PyEnum(Byte, SshAgentResponseCode),
        'message' / Switch(
            this.code, {
                SshAgentResponseCode.FAILURE: Terminated,
                SshAgentResponseCode.SUCCESS: Terminated,
                SshAgentResponseCode.IDENTITIES_ANSWER: SshAgentIdentities,
                SshAgentResponseCode.SIGN_RESPONSE: SshSignature,
                SshAgentResponseCode.EXTENSION_FAILURE: Terminated,
            },
            default=GreedyBytes
        ),
        Terminated
    )),
    Terminated
)
