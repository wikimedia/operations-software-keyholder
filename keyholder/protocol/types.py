"""
Basic SSH protocol data types

As defined in RFC 4251, section 5.

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
from construct.core import AdaptationError, MappingError
from construct import Adapter
from construct import Int32ub, PascalString, BytesInteger
from construct import Struct, FocusedSeq, Const
from construct import Prefixed, Select, Rebuild, Terminated
from construct import this

SshBytes = PascalString(Int32ub)
SshString = PascalString(Int32ub, 'utf8')
SshMPInt = Select(
    Const(Int32ub, 0),  # zero stored as zero bytes of data
    FocusedSeq(
        'num',
        'len' / Rebuild(Int32ub,
                        lambda ctx: int(ctx.num.bit_length() // 8 + 1)),
        'num' / BytesInteger(this.len, signed=True),
    ),
)

SshRSAKeyBlob = Struct(
    'algo' / Const(SshString, 'ssh-rsa'),
    'e' / SshMPInt,
    'n' / SshMPInt,
    Terminated
)

SshEd25519KeyBlob = Struct(
    'algo' / Const(SshString, 'ssh-ed25519'),
    'public_key' / SshBytes,
    Terminated
)

SshSignature = FocusedSeq(
    'signature',
    'signature' / Prefixed(Int32ub, Struct(
        'key_type' / SshString,
        'signature' / SshBytes,
        Terminated
    )),
    Terminated
)


class PyEnum(Adapter):
    """Adapt Python's Enum to its value.

    Construct << 2.9 doesn't support mapping Python's Enums to Construct's
    Enums, so add our own support for it.
    """
    def __init__(self, subcon, enum_class):
        super().__init__(subcon)
        if not issubclass(enum_class, enum.Enum):
            raise AdaptationError('%r is not an enum.Enum' % enum_class)
        self.enum_class = enum_class

    def _decode(self, obj, context):
        try:
            return self.enum_class(obj)
        except ValueError as exc:
            raise MappingError(exc) from None

    def _encode(self, obj, context):
        try:
            return obj.value
        except AttributeError as exc:
            raise MappingError(exc) from None
