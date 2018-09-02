"""
Basic SSH protocol data types

As defined in RFCs 4251, 4252, 4253 etc.

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

from construct import Byte, Flag, Int32ub, PascalString, BytesInteger
from construct import GreedyBytes
from construct import Struct, FocusedSeq
from construct import Prefixed, Select, Rebuild, Terminated
from construct import this
from .compat import Const

# RFC 4251 section 5
SshBytes = Prefixed(Int32ub, GreedyBytes)
SshString = PascalString(Int32ub, 'utf8')
SshMPInt = Select(
    Const(0, Int32ub),  # zero stored as zero bytes of data
    FocusedSeq(
        'num',
        'len' / Rebuild(Int32ub,
                        lambda ctx: int(ctx.num.bit_length() // 8 + 1)),
        'num' / BytesInteger(this.len, signed=True),
    ),
)

# RFC 4253 section 6.6
SshRSAKeyBlob = Struct(
    'algo' / Const('ssh-rsa', SshString),
    'e' / SshMPInt,
    'n' / SshMPInt,
    Terminated
)

# I-D.ietf-curdle-ssh-ed25519, section 4
SshEd25519KeyBlob = Struct(
    'algo' / Const('ssh-ed25519', SshString),
    'public_key' / SshBytes,
    Terminated
)

# RFC 4253 section 6.6
SshSignature = FocusedSeq(
    'signature',
    'signature' / Prefixed(Int32ub, Struct(
        'key_type' / SshString,
        'signature' / SshBytes,
        Terminated
    )),
    Terminated
)

# RFC 4252, section 7
SSH_MSG_USERAUTH_REQUEST = 50
SshRequestPublicKeySignature = Struct(
    'session' / SshBytes,
    'type' / Const(SSH_MSG_USERAUTH_REQUEST, Byte),
    'username' / SshString,
    'servicename' / SshString,
    'method' / Const('publickey', SshString),
    'has_signature' / Const(True, Flag),
    'algo' / SshString,
    'key_blob' / SshBytes,
    Terminated,
)
