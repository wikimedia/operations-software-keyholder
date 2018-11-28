"""Argument parse tests."""

import pytest
import keyholder.daemon


def test_parse_args_help(capsys):
    """Test whether --help returns usage and exits"""
    with pytest.raises(SystemExit) as exc:
        keyholder.daemon.parse_args(['--help'])

    out, _ = capsys.readouterr()
    assert exc.value.code == 0
    assert 'usage: ' in out
