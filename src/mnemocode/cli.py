"""Command-line interface for mnemocode."""

import argparse
import re
import sys
from typing import NoReturn

from . import __version__
from .agekey import format_age_secret_key, parse_age_secret_key
from .bip39 import VALID_ENTROPY_BYTES, entropy_to_mnemonic, mnemonic_to_entropy

AGE_WORD_COUNT = 24


def parse_hex_key(text: str) -> bytes:
    """Parse a hex-encoded key of a BIP-39 entropy size.

    Args:
        text: hex digits, with or without a leading 0x.

    Raises:
        ValueError: on non-hex input or an unsupported length.
    """
    cleaned = text.removeprefix("0x").removeprefix("0X")
    try:
        key = bytes.fromhex(cleaned)
    except ValueError:
        raise ValueError("key is not valid hex") from None
    if len(key) not in VALID_ENTROPY_BYTES:
        allowed = ", ".join(str(n * 8) for n in VALID_ENTROPY_BYTES)
        raise ValueError(f"key is {len(key) * 8} bits; must be one of {allowed}")
    return key


KEY_PARSERS = {"hex": parse_hex_key, "age": parse_age_secret_key}
KEY_FORMATTERS = {"hex": bytes.hex, "age": format_age_secret_key}

# encode parses and decode renders, so both subcommands must offer the same set
# or a mnemonic could not round trip through the format it came from.
FORMATS = tuple(KEY_PARSERS)


def run_encode(args: argparse.Namespace) -> int:
    # Parsed here rather than in an argparse type= hook, which argparse applies
    # while parsing, before --format is known.
    key = KEY_PARSERS[args.format](args.key)
    print(" ".join(entropy_to_mnemonic(key)))
    return 0


def run_decode(args: argparse.Namespace) -> int:
    # Re-split so a single quoted phrase and separate word arguments both work.
    words = " ".join(args.words).split()
    if args.format == "age" and len(words) != AGE_WORD_COUNT:
        raise ValueError(
            f"an age key is always {AGE_WORD_COUNT} words; this mnemonic has "
            f"{len(words)}"
        )
    print(KEY_FORMATTERS[args.format](mnemonic_to_entropy(words)))
    return 0


def add_format_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=FORMATS,
        default="hex",
        # Neutral wording: the option names the input on encode and the output
        # on decode.
        help="text encoding of the key: hex (the default), or age for an "
        "AGE-SECRET-KEY-1... identity",
    )


# argparse quotes the offending argv value into these three messages, and here
# that value is the key itself: a mistyped subcommand prints the whole
# identity, an unquoted mnemonic prints all but its first word, and
# `--version=KEY` prints the key as an "ignored explicit argument".
# Greedy and DOTALL on purpose: a lazy match would stop at a " (choose
# from" embedded in the value itself and leave the rest of it standing.
_INVALID_CHOICE = re.compile(r"invalid choice: .+ \(choose from", re.DOTALL)
_UNRECOGNIZED = re.compile(r"unrecognized arguments: .+", re.DOTALL)
_IGNORED_EXPLICIT = re.compile(r"ignored explicit argument .+", re.DOTALL)


def _redact_argv(message: str) -> str:
    message = _INVALID_CHOICE.sub("invalid choice (choose from", message)
    # Conditional, not a rule: decode takes loose words, so "a mnemonic must
    # be one argument" would be false, and the cause is as often a misspelled
    # option as an unquoted phrase.
    message = _UNRECOGNIZED.sub(
        "unrecognized arguments (withheld); check for a misspelled option, or "
        "pass a key or mnemonic as a single argument",
        message,
    )
    return _IGNORED_EXPLICIT.sub("ignored explicit argument", message)


class _RedactingParser(argparse.ArgumentParser):
    """Parser that keeps key material out of argparse's own diagnostics.

    argparse fails before main() can catch anything, so redaction has to
    happen here for the no-leak rule to hold on every exit path. The
    subparsers inherit this class through add_subparsers' parser_class default.
    """

    def error(self, message: str) -> NoReturn:
        super().error(_redact_argv(message))


def build_parser() -> argparse.ArgumentParser:
    parser = _RedactingParser(
        prog="mnemocode",
        description="Convert between a key and a BIP-39 mnemonic phrase.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    encode = subcommands.add_parser(
        "encode", help="encode a key into a mnemonic phrase"
    )
    add_format_option(encode)
    encode.add_argument(
        "key",
        help="the key to encode, in the --format encoding; hex is "
        "128 to 256 bits (32 to 64 hex chars)",
    )
    encode.set_defaults(run=run_encode)

    decode = subcommands.add_parser(
        "decode", help="recover the key from a mnemonic phrase"
    )
    add_format_option(decode)
    decode.add_argument(
        "words",
        nargs="+",
        metavar="WORD",
        help="the mnemonic, as separate words or one quoted phrase",
    )
    decode.set_defaults(run=run_decode)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.run(args)
    except ValueError as exc:
        print(f"mnemocode: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
