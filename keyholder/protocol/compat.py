"""
Multi-version Construct compatibility overrides

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

import enum

from construct import (
    Adapter,
    MappingError,
    AdaptationError,
    Const as ConstructConst
)
from construct.version import version as CONSTRUCT_VERSION


class PyEnum(Adapter):
    """Adapt Python's Enum to its value and vice-versa.

    Construct << 2.9 doesn't support mapping Python's Enums to Construct's
    Enums at all. Construct 2.9 does, but maps them into the internal
    EnumIntegerString which behaves like a string, not a Python Enum.
    """
    def __init__(self, subcon, enum_class):
        super().__init__(subcon)
        if not issubclass(enum_class, enum.Enum):
            raise AdaptationError('%r is not an enum.Enum' % enum_class)
        self.enum_class = enum_class

    # pylint: disable=arguments-differ,unused-argument
    #
    # path is an argument in Construct 2.9, but didn't exist in 2.8
    # get away with it by defining it with a default argument
    def _decode(self, obj, context, path=None):
        try:
            return self.enum_class(obj)
        except ValueError as exc:
            raise MappingError(exc) from None

    def _encode(self, obj, context, path=None):
        try:
            return obj.value
        except AttributeError as exc:
            raise MappingError(exc) from None


class OurConst(ConstructConst):
    """A post-Construct 2.8.22 compatible version of Const."""
    def __init__(self, value, subcon=None):
        super().__init__(subcon, value)


if CONSTRUCT_VERSION >= (2, 8, 22):
    Const = ConstructConst
else:
    Const = OurConst
