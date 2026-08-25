import argparse

import pytest

from mnemocode.cli import build_parser, main, parse_key

ZEROS_12 = "abandon " * 11 + "about"


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


def test_requires_a_subcommand(capsys):
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args([])
    assert exc.value.code == 2


def test_encode(capsys):
    assert main(["encode", "00" * 16]) == 0
    assert capsys.readouterr().out.strip() == ZEROS_12


def test_decode_accepts_separate_words_and_one_phrase(capsys):
    assert main(["decode", *ZEROS_12.split()]) == 0
    assert capsys.readouterr().out.strip() == "00" * 16

    assert main(["decode", ZEROS_12]) == 0
    assert capsys.readouterr().out.strip() == "00" * 16


def test_decode_reports_bad_checksum_without_traceback(capsys):
    assert main(["decode", "abandon " * 12]) == 2
    assert "checksum" in capsys.readouterr().err
