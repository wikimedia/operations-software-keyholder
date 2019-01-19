"""Construct compatibility tests."""

import pytest
from construct import AdaptationError, GreedyBytes, Int32ub
from keyholder.protocol.compat import PyEnum


def test_construct_pyenum():
    """Test our own version of Enum."""
    with pytest.raises(TypeError):
        PyEnum(Int32ub, GreedyBytes)

    with pytest.raises(AdaptationError):
        PyEnum(Int32ub, object)
