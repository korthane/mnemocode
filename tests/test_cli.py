import io
import os
import stat
import subprocess
import sys

import pytest

from mnemocode import __version__, secretio
from mnemocode.bech32 import bech32_encode
from mnemocode.bip39 import entropy_to_mnemonic
from mnemocode.cli import (
    FORMATS,
    KEY_FORMATTERS,
    KEY_PARSERS,
    build_parser,
    main,
    parse_hex_key,
)

ZEROS_12 = "abandon " * 11 + "about"
ZEROS_24 = "abandon " * 23 + "art"


def test_parses_hex_with_and_without_prefix():
    assert parse_hex_key("00" * 16) == bytes(16)
    assert parse_hex_key("0x" + "00" * 32) == bytes(32)
    assert parse_hex_key("0X" + "00" * 32) == bytes(32)


# Pin the cause too: bad digits and a bad length are separate checks, and a
# bare ValueError would pass if one started reporting the other's message.
@pytest.mark.parametrize(
    "bad,message",
    [
        ("zz" * 16, "not valid hex"),
        ("00" * 15, "120 bits"),
        ("00" * 33, "264 bits"),
        ("", "0 bits"),
    ],
)
def test_rejects_bad_keys(bad, message):
    with pytest.raises(ValueError, match=message):
        parse_hex_key(bad)


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
    captured = capsys.readouterr()
    assert captured.out.strip() == ZEROS_12
    assert captured.err == ""


def test_decode_accepts_separate_words_and_one_phrase(capsys):
    assert main(["decode", *ZEROS_12.split()]) == 0
    assert capsys.readouterr().out.strip() == "00" * 16

    assert main(["decode", ZEROS_12]) == 0
    assert capsys.readouterr().out.strip() == "00" * 16


@pytest.mark.parametrize("words", ["", "   "])
def test_decode_reports_an_empty_mnemonic(words, capsys):
    """Re-splitting on whitespace must yield no words, not one empty word."""
    assert main(["decode", words]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "mnemocode: error: mnemonic has 0 words; must be 12, 15, 18, 21 or 24\n"
    )


def test_decode_reports_bad_checksum_without_traceback(capsys):
    # A distinctive phrase, not "abandon" * 12: an all-one-word mnemonic cannot
    # tell "the count was reported" from "the phrase was echoed".
    words = VECTOR_WORDS.split()[:11] + ["zebra"]
    assert main(["decode", " ".join(words)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    # Exact, not a word scan: a scan reports a false leak whenever a vector
    # word also occurs in the message, and misses a single echoed character.
    assert captured.err == (
        "mnemocode: error: checksum mismatch; the mnemonic contains a typo "
        "or wrong word order\n"
    )


def test_decode_does_not_echo_a_phrase_of_the_wrong_length(capsys):
    """The word-count message must report the count, never the words."""
    words = VECTOR_WORDS.split()[:13]
    assert main(["decode", " ".join(words)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "mnemocode: error: mnemonic has 13 words; must be 12, 15, 18, 21 or 24\n"
    )


# The same synthetic identity as tests/test_agekey.py, kept here so this file
# stands alone. Its key is bytes(range(32)).
IDENTITY = "AGE-SECRET-KEY-1QQQSYQCYQ5RQWZQFPG9SCRGWPUGPZYSNZS23V9CCRYDPK8QARC0SWRYDWG"


def test_encode_age_produces_twenty_four_words(capsys):
    assert main(["encode", "--format", "age", IDENTITY]) == 0
    assert len(capsys.readouterr().out.split()) == 24


def test_age_round_trip(capsys):
    assert main(["encode", "--format", "age", IDENTITY]) == 0
    encoded = capsys.readouterr()
    assert encoded.err == ""

    assert main(["decode", "--format", "age", encoded.out.strip()]) == 0
    decoded = capsys.readouterr()
    assert decoded.out.strip() == IDENTITY
    assert decoded.err == ""


def test_lowercase_identity_encodes_the_same(capsys):
    assert main(["encode", "--format", "age", IDENTITY]) == 0
    upper = capsys.readouterr().out
    assert main(["encode", "--format", "age", IDENTITY.lower()]) == 0
    assert capsys.readouterr().out == upper


def test_explicit_hex_matches_the_default(capsys):
    assert main(["encode", "00" * 16]) == 0
    default = capsys.readouterr().out
    assert main(["encode", "--format", "hex", "00" * 16]) == 0
    assert capsys.readouterr().out == default


def test_decode_defaults_to_hex(capsys):
    assert main(["decode", ZEROS_12]) == 0
    assert capsys.readouterr().out.strip() == "00" * 16


# An all-zero key hides letter case, so pin it with a BIP-39 vector whose hex
# spans a-f. The spec requires lowercase hex with no 0x prefix.
VECTOR_WORDS = (
    "void come effort suffer camp survey warrior heavy shoot primary clutch "
    "crush open amazing screen patrol group space point ten exist slush "
    "involve unfold"
)
VECTOR_HEX = "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f"


@pytest.mark.parametrize("args", [["decode"], ["decode", "--format", "hex"]])
def test_decode_prints_lowercase_hex_without_a_prefix(args, capsys):
    assert main([*args, VECTOR_WORDS]) == 0
    assert capsys.readouterr().out.strip() == VECTOR_HEX


@pytest.mark.parametrize("command", ["encode", "decode"])
def test_rejects_an_unknown_format(command, capsys):
    with pytest.raises(SystemExit) as exc:
        main([command, "--format", "base64", "whatever"])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "hex" in captured.err and "age" in captured.err


@pytest.mark.parametrize("n_bytes, n_words", [(16, 12), (20, 15), (24, 18), (28, 21)])
def test_decode_age_requires_twenty_four_words(n_bytes, n_words, capsys):
    # Distinctive entropy, not bytes(n): an all-"abandon" phrase cannot tell
    # "the count was reported" from "the phrase was echoed".
    words = entropy_to_mnemonic(bytes(range(1, n_bytes + 1)))
    assert main(["decode", "--format", "age", " ".join(words)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    # A literal count, not len(words): deriving it from the code under test
    # would let a wrong word count assert itself.
    assert captured.err == (
        "mnemocode: error: an age key is always 24 words; this mnemonic "
        f"has {n_words}\n"
    )


@pytest.mark.parametrize("n_words", [0, 1, 25, 48])
def test_decode_age_rejects_any_other_word_count(n_words, capsys):
    """The gate must bracket 24, not just catch phrases shorter than it."""
    assert main(["decode", "--format", "age", " ".join(["abandon"] * n_words)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        f"mnemocode: error: an age key is always 24 words; this mnemonic has "
        f"{n_words}\n"
    )


def test_decode_age_reports_a_whitespace_only_phrase_as_zero_words(capsys):
    """The word-count gate runs on the re-split words, not the raw argument."""
    assert main(["decode", "--format", "age", "   "]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "mnemocode: error: an age key is always 24 words; this mnemonic has 0\n"
    )


# The spec gives each of these its own scenario, requiring the message to name
# the cause, so pin the fragment rather than only the "mnemocode: error:" prefix.
@pytest.mark.parametrize(
    "key,message",
    [
        (IDENTITY[:-1] + "P", "bech32 checksum does not match"),
        (
            IDENTITY[:-1] + IDENTITY[-1].lower(),
            "bech32 string mixes upper and lower case",
        ),
        (
            "age13aqvttdk3ujkyjh9kg2w5an6dmy5mq5a84a4uxk3hfhnugfc9p0sy5p2wh",
            "not an age secret key: expected the 'age-secret-key-' prefix, "
            "got a different one",
        ),
        ("00" * 32, "bech32 string has no '1' separator"),
        (
            bech32_encode("age-secret-key-", bytes(31)).upper(),
            "age secret key is 31 bytes; must be 32 bytes",
        ),
        # Both positions count from the start of the string as given, so the
        # 1-based index of the character each case substitutes.
        (
            IDENTITY[:20] + "B" + IDENTITY[21:],
            "not a bech32 data character at position 21",
        ),
        (
            IDENTITY.replace("K", "\u212a", 1),
            "bech32 string has a character out of range at position 12",
        ),
    ],
)
def test_encode_age_reports_a_bad_key_without_traceback(key, message, capsys):
    assert main(["encode", "--format", "age", key]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    # Exact, not "key not in err": a message widened to quote the offending
    # character or the data part around it would still pass a containment
    # check, and that character is the key.
    assert captured.err == f"mnemocode: error: {message}\n"


# A hex key holds a '1', so it splits as a bech32 HRP and a data part. The
# second case puts that '1' far enough left that the data part clears the
# length and charset checks and the split is only caught by the checksum.
@pytest.mark.parametrize(
    "secret,message",
    [
        (
            bytes(range(32)).hex(),
            "bech32 data part is 1 characters; needs at least 6 for the "
            "checksum",
        ),
        ("01" + "22" * 31, "bech32 checksum does not match"),
    ],
)
def test_encode_age_does_not_echo_a_hex_key_given_by_mistake(
    secret, message, capsys
):
    assert main(["encode", "--format", "age", secret]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == f"mnemocode: error: {message}\n"


# "zzzz" rather than a word like "mnemocode", which the error prefix contains.
@pytest.mark.parametrize(
    "args,n_words", [(["decode"], 12), (["decode", "--format", "age"], 24)]
)
def test_decode_does_not_echo_a_word_outside_the_wordlist(args, n_words, capsys):
    """The word is secret material; only its position may be reported."""
    words = ["abandon"] * (n_words - 1) + ["zzzz"]
    assert main([*args, " ".join(words)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        f"mnemocode: error: word {n_words} is not in the BIP-39 English "
        "wordlist\n"
    )


# argparse fails before main()'s try block, and its own messages quote the
# offending argv value. These pin the redaction; if a future argparse rewords
# either message the regex stops matching and these fail rather than leaking.
def test_a_mistyped_subcommand_does_not_echo_the_key(capsys):
    """Omitting "encode" makes argparse report the key as a bad subcommand."""
    with pytest.raises(SystemExit) as exc:
        main([IDENTITY])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert IDENTITY not in captured.err
    # Redaction must leave a diagnostic behind, not blank the message out.
    assert "invalid choice" in captured.err
    assert "encode" in captured.err and "decode" in captured.err


def test_an_unquoted_mnemonic_does_not_echo_its_words(capsys):
    """`encode word word ...` sends the tail of the phrase through argparse."""
    words = VECTOR_WORDS.split()
    with pytest.raises(SystemExit) as exc:
        main(["encode", *words])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    # Exact, not a word scan: "code", "must", "one" and "age" are all BIP-39
    # words that occur in the usage line or the message, so a scan would
    # report a false leak for some vectors and miss a single echoed character.
    # Pinning both parts covers every word, not just the tail: the first is
    # consumed as the key positional and must not be echoed either.
    assert captured.err.startswith("usage: mnemocode ")
    assert captured.err.endswith(
        "mnemocode: error: unrecognized arguments (withheld); check for a "
        "misspelled option, or pass a key or mnemonic as a single argument\n"
    )


@pytest.mark.parametrize("command", ["encode", "decode"])
def test_a_key_given_as_the_format_value_is_not_echoed(command, capsys):
    """`--format KEY` makes the subparser report the key as a bad choice.

    Redaction reaches the subparsers only through add_subparsers' default
    parser_class, so this also pins that inheritance.
    """
    with pytest.raises(SystemExit) as exc:
        main([command, "--format", IDENTITY])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert IDENTITY not in captured.err
    assert "hex" in captured.err and "age" in captured.err


def test_a_format_value_that_mimics_the_message_is_fully_redacted(capsys):
    """The greedy match must run past a " (choose from" inside the value.

    A lazy `.+?` stops at the planted fragment and leaves the tail of the
    value standing, so this is what makes the greediness load-bearing.
    """
    with pytest.raises(SystemExit) as exc:
        main(["encode", "--format", f"{IDENTITY} (choose from {IDENTITY}"])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert IDENTITY not in captured.err
    assert "hex" in captured.err and "age" in captured.err


def test_a_multiline_argument_is_fully_redacted(capsys):
    """argparse joins raw argv, so a pasted newline survives into the message.

    Without re.DOTALL the pattern stops at the newline and everything after
    it reaches stderr verbatim.
    """
    with pytest.raises(SystemExit) as exc:
        main(["encode", "somekey", f"{IDENTITY}\n{IDENTITY}"])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert IDENTITY not in captured.err
    # Redaction must leave a diagnostic behind, not blank the message out.
    assert "unrecognized arguments" in captured.err


@pytest.mark.parametrize("argv", [["--version"], ["encode", "--help"]])
def test_an_explicit_argument_to_a_flag_does_not_echo_the_key(argv, capsys):
    """`--version=KEY` makes argparse quote the key back as "ignored"."""
    with pytest.raises(SystemExit) as exc:
        main([*argv[:-1], f"{argv[-1]}={IDENTITY}"])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert IDENTITY not in captured.err
    # Redaction must leave a diagnostic behind, not blank the message out.
    assert "ignored explicit argument" in captured.err


@pytest.mark.parametrize("argv", [[], ["encode"], ["decode"]])
def test_an_ambiguous_option_does_not_echo_the_key(argv, capsys):
    """`--=KEY` is an empty abbreviation, so argparse quotes the whole token.

    The empty prefix matches every long option the parser has, which is what
    makes this reachable on the top-level parser and both subparsers.
    """
    with pytest.raises(SystemExit) as exc:
        main([*argv, f"--={IDENTITY}"])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert IDENTITY not in captured.err
    # Redaction must leave a diagnostic behind, not blank the message out.
    assert "ambiguous option" in captured.err
    assert "--help" in captured.err


def test_an_ambiguous_option_that_mimics_the_message_is_fully_redacted(capsys):
    """Pins the greedy match and re.DOTALL on the ambiguous-option pattern.

    argparse interpolates this token raw, so a planted " could match " stops a
    lazy pattern and a pasted newline stops one without DOTALL, in both cases
    leaving the tail of the key on stderr.
    """
    with pytest.raises(SystemExit) as exc:
        main(["encode", f"--={IDENTITY} could match {IDENTITY}\n{IDENTITY}"])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert IDENTITY not in captured.err
    assert "ambiguous option" in captured.err


@pytest.mark.parametrize(
    "planted", [" ignored explicit argument x", " unrecognized arguments: x"]
)
@pytest.mark.parametrize("argv", [[], ["encode"], ["decode"]])
def test_one_message_planted_in_another_is_still_redacted(
    argv, planted, capsys
):
    """A value may carry the text of a different argparse message.

    The patterns that consume to end of string must not run first: they eat
    the trailing " could match " the ambiguous-option pattern needs, and the
    whole token then survives on stderr.
    """
    with pytest.raises(SystemExit) as exc:
        main([*argv, f"--={IDENTITY}{planted}"])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert IDENTITY not in captured.err
    assert "ambiguous option" in captured.err


def _key_fragments():
    """Every 12-character window of the identity's Bech32 data part.

    A pattern that fires but matches too little leaves a fragment of the key
    standing, which a whole-string `IDENTITY not in err` check would miss.
    """
    data = IDENTITY.split("1", 1)[1]
    return [data[i : i + 12] for i in range(len(data) - 11)]


# The four redactions are a denylist over argparse's own message text, so the
# per-message tests above cannot say anything about a shape that starts
# leaking later. This sweeps malformed argv instead and asserts the property
# the change exists for: no key material on either stream, whatever argparse
# decides the problem is.
@pytest.mark.parametrize("command", [[], ["encode"], ["decode"]])
@pytest.mark.parametrize(
    "shape",
    [
        "{key}",
        "--={key}",
        "--help={key}",
        "--format={key}",
        "--nope={key}",
        "-{key}",
        "--{key}",
        "={key}",
    ],
)
def test_no_argv_shape_puts_key_material_on_a_stream(shape, command, capsys):
    try:
        main([*command, shape.format(key=IDENTITY)])
    except SystemExit:
        pass
    captured = capsys.readouterr()
    streams = captured.out + captured.err
    assert IDENTITY not in streams
    assert not [f for f in _key_fragments() if f in streams]


@pytest.mark.parametrize(
    "argv",
    [
        ["encode", "{key}", "extra"],
        ["decode", "--format", "{key}"],
        ["encode", "--format", "{key}"],
        ["--version", "{key}"],
        ["--version={key}"],
        ["encode", "somekey", "{key}"],
        ["decode", "abandon", "{key}"],
    ],
    ids=lambda argv: "-".join(argv),
)
def test_no_multi_token_argv_puts_key_material_on_a_stream(argv, capsys):
    try:
        main([token.format(key=IDENTITY) for token in argv])
    except SystemExit:
        pass
    captured = capsys.readouterr()
    streams = captured.out + captured.err
    assert IDENTITY not in streams
    assert not [f for f in _key_fragments() if f in streams]


def test_version_still_prints_on_the_redacting_parser(capsys):
    """--version exits through the same subclass that rewrites error()."""
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert captured.out == f"mnemocode {__version__}\n"
    assert captured.err == ""


def test_both_directions_support_the_same_formats():
    """A format encode accepts but decode cannot render would break round trips."""
    assert KEY_PARSERS.keys() == KEY_FORMATTERS.keys()
    assert set(FORMATS) == KEY_PARSERS.keys()


def test_decode_age_still_checks_the_bip39_checksum(capsys):
    """The 24-word gate runs first; it must not bypass the checksum check."""
    words = ["abandon"] * 23 + ["about"]
    assert main(["decode", "--format", "age", " ".join(words)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "checksum" in captured.err


@pytest.mark.parametrize(
    "args,expected_prefix",
    [(["encode", IDENTITY], "abandon"), (["decode", ZEROS_24], "AGE-SECRET-KEY-1")],
)
def test_format_option_may_follow_the_positionals(args, expected_prefix, capsys):
    """decode's nargs="*" makes this the ordering most likely to break."""
    assert main([*args, "--format", "age"]) == 0
    assert capsys.readouterr().out.strip().startswith(expected_prefix)


def test_encode_hex_rejects_an_identity(capsys):
    assert main(["encode", "--format", "hex", IDENTITY]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    # Exact, not a fragment: a widened message is how the key gets back onto
    # stderr, and it must not reach logs or scrollback.
    assert captured.err == "mnemocode: error: key is not valid hex\n"
    assert IDENTITY not in captured.err


def test_age_and_hex_encode_the_same_key_identically(capsys):
    assert main(["encode", "--format", "age", IDENTITY]) == 0
    from_age = capsys.readouterr().out
    assert main(["encode", "--format", "hex", bytes(range(32)).hex()]) == 0
    assert capsys.readouterr().out == from_age


# Distinctive digits, not "00" * n: a repeated-zero key is indistinguishable
# from noise in stderr even if the message echoes it in full.
@pytest.mark.parametrize(
    "bad,message",
    [
        ("zz" * 16, "key is not valid hex"),
        ("ab" * 15, "key is 120 bits; must be one of 128, 160, 192, 224, 256"),
        ("cd" * 33, "key is 264 bits; must be one of 128, 160, 192, 224, 256"),
    ],
)
def test_encode_hex_reports_a_bad_key_without_traceback(bad, message, capsys):
    assert main(["encode", bad]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == f"mnemocode: error: {message}\n"


def test_encode_hex_reports_an_empty_key(capsys):
    assert main(["encode", ""]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "mnemocode: error: key is 0 bits; must be one of "
        "128, 160, 192, 224, 256\n"
    )


HEX_KEY = "0c1e24e5917779d297e14d45f14e1a1a"


def _encode_out(argv, capsys):
    assert main(argv) == 0
    return capsys.readouterr().out


def test_every_input_source_yields_the_same_mnemonic(tmp_path, monkeypatch, capsys):
    baseline = _encode_out(["encode", HEX_KEY], capsys)

    assert _encode_out(["encode", "--input", f"pass:{HEX_KEY}"], capsys) == baseline

    monkeypatch.setenv("MNEMOCODE_KEY", HEX_KEY)
    assert _encode_out(["encode", "--input", "env:MNEMOCODE_KEY"], capsys) == baseline

    path = tmp_path / "key.txt"
    path.write_text(f"{HEX_KEY}\n")
    assert _encode_out(["encode", "--input", f"file:{path}"], capsys) == baseline

    fd = os.open(path, os.O_RDONLY)
    try:
        assert _encode_out(["encode", "--input", f"fd:{fd}"], capsys) == baseline
    finally:
        os.close(fd)

    monkeypatch.setattr(sys, "stdin", io.StringIO(HEX_KEY))
    assert _encode_out(["encode", "--input", "stdin"], capsys) == baseline


def test_encode_reads_an_age_key_file_with_comments(tmp_path, capsys):
    path = tmp_path / "keys.txt"
    path.write_text(
        "# created: 2026-08-31T00:00:00Z\n"
        "# public key: age1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qar\n"
        "AGE-SECRET-KEY-1QQQSYQCYQ5RQWZQFPG9SCRGWPUGPZYSNZS23V9CCRYDPK8QARC0SWRYDWG\n"
    )
    out = _encode_out(["encode", "--format", "age", "--input", f"file:{path}"], capsys)
    assert len(out.split()) == 24


def test_encode_rejects_a_key_file_holding_two_identities(tmp_path, capsys):
    path = tmp_path / "keys.txt"
    key = "AGE-SECRET-KEY-1QQQSYQCYQ5RQWZQFPG9SCRGWPUGPZYSNZS23V9CCRYDPK8QARC0SWRYDWG"
    path.write_text(f"# created\n{key}\n{key}\n")
    assert main(["encode", "--format", "age", "--input", f"file:{path}"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "2 keys" in captured.err
    assert key not in captured.err


def test_decode_reads_a_phrase_wrapped_across_lines(tmp_path, capsys):
    words = ZEROS_24.split()
    path = tmp_path / "phrase.txt"
    path.write_text("\n".join(" ".join(words[i : i + 6]) for i in range(0, 24, 6)))
    assert main(["decode", "--input", f"file:{path}"]) == 0
    assert capsys.readouterr().out == "00" * 32 + "\n"


def test_a_positional_and_input_together_are_rejected(capsys):
    assert main(["encode", HEX_KEY, "--input", f"pass:{HEX_KEY}"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("mnemocode: error: ")
    assert "not both" in captured.err
    assert HEX_KEY not in captured.err


def test_output_file_receives_the_result_and_stdout_stays_empty(tmp_path, capsys):
    path = tmp_path / "phrase.txt"
    assert main(["encode", HEX_KEY, "--output", f"file:{path}"]) == 0
    assert capsys.readouterr().out == ""
    assert len(path.read_text().split()) == 12


def test_output_file_is_created_private(tmp_path):
    path = tmp_path / "key.txt"
    previous = os.umask(0o022)
    try:
        assert main(["decode", "--output", f"file:{path}", *ZEROS_12.split()]) == 0
    finally:
        os.umask(previous)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_output_refuses_to_overwrite_an_existing_file(tmp_path, capsys):
    path = tmp_path / "key.txt"
    path.write_text("existing")
    assert main(["encode", HEX_KEY, "--output", f"file:{path}"]) == 2
    assert path.read_text() == "existing"
    assert capsys.readouterr().err.startswith("mnemocode: error: ")


def test_output_fd_receives_the_result(tmp_path, capsys):
    path = tmp_path / "out.txt"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        assert main(["encode", HEX_KEY, "--output", f"fd:{fd}"]) == 0
    finally:
        os.close(fd)
    assert capsys.readouterr().out == ""
    assert len(path.read_text().split()) == 12


def test_encode_prompts_when_no_key_is_given(prompt_terminal, capsys):
    prompt_terminal.answer(HEX_KEY)
    assert main(["encode"]) == 0
    captured = capsys.readouterr()
    assert len(captured.out.split()) == 12
    assert "key:" not in captured.out


def test_decode_prompts_when_no_mnemonic_is_given(prompt_terminal, capsys):
    prompt_terminal.answer(ZEROS_12)
    assert main(["decode"]) == 0
    assert capsys.readouterr().out == "00" * 16 + "\n"


def test_abandoning_the_prompt_is_an_exit_code_not_a_traceback(
    prompt_terminal, monkeypatch, capsys
):
    """Ctrl-C is the ordinary way to leave a prompt, and this branch adds the
    tool's first one; main catches only ValueError, so the interrupt would
    otherwise reach the user as a traceback."""

    def interrupted_read(fd):
        raise KeyboardInterrupt

    monkeypatch.setattr(secretio, "_read_line", interrupted_read)
    # A responder still drains the prompt: the TCSAFLUSH restore in the finally
    # blocks until that output has gone.
    prompt_terminal.answer("unread")
    assert main(["encode"]) == 130
    captured = capsys.readouterr()
    assert captured.out == ""
    # The newline moves the cursor off the prompt line, and is the whole of it:
    # a traceback would land on this same stream.
    assert captured.err == "\n"


def test_prompting_without_a_terminal_exits_two(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(secretio, "_TTY_PATH", str(tmp_path / "no-such-tty"))
    assert main(["encode"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "terminal" in captured.err


def test_an_unknown_input_source_exits_two_without_echoing_it(capsys):
    assert main(["encode", "--input", f"bogus:{HEX_KEY}"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert HEX_KEY not in captured.err


def test_an_unreadable_input_file_names_only_the_path(tmp_path, capsys):
    missing = tmp_path / "absent.txt"
    assert main(["encode", "--input", f"file:{missing}"]) == 2
    assert str(missing) in capsys.readouterr().err


def test_an_unset_environment_source_names_the_variable(monkeypatch, capsys):
    monkeypatch.delenv("MNEMOCODE_ABSENT", raising=False)
    assert main(["encode", "--input", "env:MNEMOCODE_ABSENT"]) == 2
    assert "MNEMOCODE_ABSENT" in capsys.readouterr().err


def test_an_unusable_descriptor_source_names_the_number(capsys):
    assert main(["encode", "--input", "fd:9999"]) == 2
    assert "9999" in capsys.readouterr().err


def test_an_unknown_output_sink_exits_two_without_echoing_it(capsys):
    assert main(["encode", HEX_KEY, "--output", f"bogus:{HEX_KEY}"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert HEX_KEY not in captured.err


# The same property the argv sweep pins, extended over the options this change
# adds: whatever the tool decides is wrong with a source or a sink, no part of
# the key may reach either stream. Shapes that deliberately name the key as a
# variable or a path are excluded - the spec allows a message to name its
# source, and a caller who types the key as a name has already leaked it.
@pytest.mark.parametrize("command", [["encode"], ["decode"]])
@pytest.mark.parametrize(
    "shape",
    [
        "--input={key}",
        "--input=pass:{key}",
        "--input=fd:{key}",
    ],
)
def test_no_input_option_shape_puts_key_material_on_a_stream(shape, command, capsys):
    try:
        main([*command, shape.format(key=IDENTITY)])
    except SystemExit:
        pass
    captured = capsys.readouterr()
    streams = captured.out + captured.err
    assert IDENTITY not in streams
    assert not [f for f in _key_fragments() if f in streams]


# The sink shapes need a secret of their own: with none supplied the run dies
# at the prompt before write_sink is ever reached, and the sweep asserts
# nothing about sinks at all.
@pytest.mark.parametrize(
    "command", [["encode", HEX_KEY], ["decode", *ZEROS_12.split()]]
)
@pytest.mark.parametrize("shape", ["--output={key}", "--output=fd:{key}"])
def test_no_output_option_shape_puts_key_material_on_a_stream(shape, command, capsys):
    try:
        main([*command, shape.format(key=IDENTITY)])
    except SystemExit:
        pass
    captured = capsys.readouterr()
    streams = captured.out + captured.err
    assert IDENTITY not in streams
    assert not [f for f in _key_fragments() if f in streams]


def test_dev_stdout_follows_what_standard_output_is_attached_to(tmp_path):
    """The path is a device down a pipe and a regular file under a redirect.

    Run out of process: the distinction is about the real descriptor 1, which
    capsys replaces at the Python level and so cannot express.
    """
    argv = [
        sys.executable,
        "-m",
        "mnemocode",
        "encode",
        HEX_KEY,
        "--output",
        "file:/dev/stdout",
    ]

    piped = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    assert piped.returncode == 0
    assert len(piped.stdout.split()) == 12

    redirected = tmp_path / "out.txt"
    with open(redirected, "w") as handle:
        to_file = subprocess.run(
            argv, stdout=handle, stderr=subprocess.PIPE, text=True, timeout=30
        )
    assert to_file.returncode == 2
    assert "refusing to overwrite" in to_file.stderr
    assert redirected.read_text() == ""


@pytest.mark.parametrize("content", ["", "\n\n", "# only a comment\n"])
def test_decode_reports_a_source_holding_no_mnemonic(tmp_path, capsys, content):
    path = tmp_path / "phrase.txt"
    path.write_text(content)
    assert main(["decode", "--input", f"file:{path}"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "no mnemonic" in captured.err


@pytest.mark.parametrize("content", ["", "\n\n", "# only a comment\n"])
def test_encode_reports_a_source_holding_no_key(tmp_path, capsys, content):
    path = tmp_path / "key.txt"
    path.write_text(content)
    assert main(["encode", "--input", f"file:{path}"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "no key" in captured.err


def test_output_refuses_a_directory(tmp_path, capsys):
    assert main(["encode", HEX_KEY, "--output", f"file:{tmp_path}"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert str(tmp_path) in captured.err


def test_an_unusable_descriptor_sink_names_the_number(capsys):
    assert main(["encode", HEX_KEY, "--output", "fd:9999"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "9999" in captured.err
    assert HEX_KEY not in captured.err


def test_a_non_numeric_descriptor_sink_is_reported_in_our_own_wording(capsys):
    assert main(["encode", HEX_KEY, "--output", "fd:x"]) == 2
    assert "descriptor number" in capsys.readouterr().err


def test_an_unwritable_output_path_names_only_the_path(tmp_path, capsys):
    missing = tmp_path / "no-such-dir" / "key.txt"
    assert main(["encode", HEX_KEY, "--output", f"file:{missing}"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert str(missing) in captured.err
    assert HEX_KEY not in captured.err


def test_a_binary_source_names_the_path_and_shows_no_byte_of_it(tmp_path, capsys):
    """The default UnicodeDecodeError text quotes an offending byte and its
    offset, and those bytes are the key."""
    path = tmp_path / "key.bin"
    path.write_bytes(bytes(range(256)))
    assert main(["encode", "--input", f"file:{path}"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert str(path) in captured.err
    assert "not UTF-8 text" in captured.err
    assert "0x" not in captured.err


@pytest.mark.parametrize(
    "command", [["encode", ""], ["decode", ""]]
)
def test_an_empty_positional_still_conflicts_with_input(command, capsys):
    """An empty argument is one the caller supplied, so it is a conflict, not
    a value that lets --input win by default."""
    assert main([*command, "--input", f"pass:{HEX_KEY}"]) == 2
    assert "not both" in capsys.readouterr().err


def test_every_input_source_yields_the_same_key_for_decode(
    tmp_path, monkeypatch, capsys
):
    def out(argv):
        assert main(argv) == 0
        return capsys.readouterr().out

    baseline = out(["decode", *ZEROS_12.split()])
    assert out(["decode", "--input", f"pass:{ZEROS_12}"]) == baseline

    monkeypatch.setenv("MNEMOCODE_PHRASE", ZEROS_12)
    assert out(["decode", "--input", "env:MNEMOCODE_PHRASE"]) == baseline

    path = tmp_path / "phrase.txt"
    path.write_text(f"{ZEROS_12}\n")
    assert out(["decode", "--input", f"file:{path}"]) == baseline

    fd = os.open(path, os.O_RDONLY)
    try:
        assert out(["decode", "--input", f"fd:{fd}"]) == baseline
    finally:
        os.close(fd)

    monkeypatch.setattr(sys, "stdin", io.StringIO(ZEROS_12))
    assert out(["decode", "--input", "stdin"]) == baseline


def test_a_diagnostic_never_lands_on_standard_output(tmp_path):
    """CPython leaves sys.stderr None when fd 2 was closed at startup, and
    print(file=None) then falls back to standard output — putting the
    diagnostic on the very stream a redirect or a pipe collects.

    The relay closes fd 2 and execs, so the tool starts with it already gone;
    closing it from inside would leave sys.stderr bound to a dead descriptor
    instead, which is a different case.
    """
    missing = tmp_path / "nope.txt"
    relay = (
        "import os, sys; os.close(2); os.execv(sys.executable, [sys.executable,"
        f" '-m', 'mnemocode', 'encode', '--input', 'file:{missing}'])"
    )
    result = subprocess.run(
        [sys.executable, "-c", relay], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 2
    assert result.stdout == ""


def test_a_piped_key_is_ignored_without_input():
    """The README promises stdin is read only when asked for. Routing the
    no-argument case through stdin would satisfy every other test here.
    """
    result = subprocess.run(
        [sys.executable, "-m", "mnemocode", "encode"],
        input=f"{HEX_KEY}\n",
        capture_output=True,
        text=True,
        # start_new_session detaches the child from the terminal pytest was
        # launched from; without it the prompt opens /dev/tty and blocks
        # forever, stealing the developer's keystrokes.
        start_new_session=True,
        timeout=30,
    )
    assert result.returncode == 2
    assert "--input" in result.stderr
    assert result.stdout == ""
    assert HEX_KEY not in result.stderr


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["encode", "--output", "bogus:path"], "unknown output sink"),
        (["decode", "--output", "fd:not-a-number"], "needs a descriptor number"),
    ],
)
def test_a_bad_sink_is_reported_before_the_secret_is_asked_for(argv, expected, capsys):
    """Otherwise a typo in --output costs a blind entry at the prompt first.
    With no terminal attached the prompt is what fails, so the message names
    which of the two ran.
    """
    assert main(argv) == 2
    err = capsys.readouterr().err
    assert "no terminal is available" not in err
    assert expected in err


@pytest.mark.parametrize(
    "args",
    [
        ["encode", "--input", "fd:2147483648"],
        ["encode", HEX_KEY, "--output", "fd:2147483648"],
    ],
)
def test_an_out_of_range_descriptor_is_an_error_not_a_traceback(args, capsys):
    """open() hands an int this large to the path lookup and raises
    TypeError, which main does not catch."""
    assert main(args) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "descriptor number" in captured.err


def test_a_prompted_mnemonic_starting_with_a_hash_is_not_a_comment(
    prompt_terminal, capsys
):
    """The prompt reads one line, so the source stream rules do not apply to
    it: a bad word must be reported as a word, not as an empty source."""
    prompt_terminal.answer("# not a word")
    assert main(["decode"]) == 2
    err = capsys.readouterr().err
    assert "no mnemonic" not in err
    assert "mnemonic has 4 words" in err
