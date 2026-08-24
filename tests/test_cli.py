import argparse

import pytest

from mnemocode.cli import build_parser, parse_key


def test_parses_hex_with_and_without_prefix():
    assert parse_key("00" * 16) == bytes(16)
    assert parse_key("0x" + "00" * 32) == bytes(32)


@pytest.mark.parametrize("bad", ["zz" * 16, "00" * 15, "00" * 33, ""])
def test_rejects_bad_keys(bad):
    with pytest.raises(argparse.ArgumentTypeError):
        parse_key(bad)


def test_help_exits_cleanly(capsys):
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["--help"])
    assert exc.value.code == 0
    assert "BIP-39" in capsys.readouterr().out
