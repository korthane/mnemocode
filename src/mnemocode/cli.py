"""Command-line interface for mnemocode."""

import argparse
import re
import sys
from typing import NoReturn

from . import __version__
from .agekey import format_age_secret_key, parse_age_secret_key
from .bip39 import VALID_ENTROPY_BYTES, entropy_to_mnemonic, mnemonic_to_entropy
from .secretio import (
    one_secret,
    prompt_secret,
    read_source,
    secret_words,
    write_sink,
)

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


def reject_double_input(given: bool, source: str | None, label: str) -> None:
    """Refuse a secret supplied twice.

    Checked here rather than with a mutually exclusive argparse group: such a
    group accepts a positional only when its nargs permits zero, and the
    message it generates for that case reads poorly. Raising keeps the wording
    consistent with every other key error.

    Encode passes presence, not truthiness: an empty positional is still one
    the caller supplied, and `encode ""` alone already reports an empty key.
    Decode's nargs="*" cannot express that difference, so it passes a bool.
    """
    if given and source is not None:
        raise ValueError(f"give the {label} as an argument or with --input, not both")


def run_encode(args: argparse.Namespace) -> int:
    reject_double_input(args.key is not None, args.input_source, "key")
    if args.input_source is not None:
        text = one_secret(read_source(args.input_source))
    elif args.key is not None:
        # A positional argument keeps its existing handling: the stream rules
        # describe a source, and applying them here would reword its errors.
        text = args.key
    else:
        text = prompt_secret("key")
    # Parsed here rather than in an argparse type= hook, which argparse applies
    # while parsing, before --format is known.
    key = KEY_PARSERS[args.format](text)
    write_sink(args.output_sink, " ".join(entropy_to_mnemonic(key)))
    return 0


def run_decode(args: argparse.Namespace) -> int:
    reject_double_input(bool(args.words), args.input_source, "mnemonic")
    if args.input_source is not None:
        words = secret_words(read_source(args.input_source))
    elif args.words:
        # Re-split so a single quoted phrase and separate word arguments both work.
        words = " ".join(args.words).split()
    else:
        # Split, not secret_words: the stream rules describe a source, and a
        # phrase typed at the prompt is a single line the prompt already
        # stripped and refused to accept empty.
        words = prompt_secret("mnemonic").split()
    if args.format == "age" and len(words) != AGE_WORD_COUNT:
        raise ValueError(
            f"an age key is always {AGE_WORD_COUNT} words; this mnemonic has "
            f"{len(words)}"
        )
    write_sink(args.output_sink, KEY_FORMATTERS[args.format](mnemonic_to_entropy(words)))
    return 0


def add_io_options(parser: argparse.ArgumentParser, *, what: str) -> None:
    parser.add_argument(
        "--input",
        dest="input_source",
        metavar="SOURCE",
        help=f"where to read the {what} from: pass:VALUE, env:VAR, file:PATH, "
        "fd:N or stdin; with neither this nor the argument, you are prompted",
    )
    parser.add_argument(
        "--output",
        dest="output_sink",
        metavar="SINK",
        default="stdout",
        help="where to write the result: file:PATH (created private, and never "
        "overwriting an existing regular file), fd:N, or stdout (the default)",
    )


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


# argparse quotes the offending argv value into these four messages, and here
# that value is the key itself: a mistyped subcommand prints the whole
# identity, an unquoted mnemonic prints all but its first word, `--version=KEY`
# prints the key as an "ignored explicit argument", and `--=KEY` is an empty
# abbreviation that matches every long option, so argparse calls it ambiguous
# and prints the token whole.
# Greedy and DOTALL on purpose: a lazy match would stop at a " (choose
# from" embedded in the value itself and leave the rest of it standing, and
# the two messages that interpolate raw argv carry a pasted newline through.
# One alternation rather than four passes: argparse always puts the message
# text before the value, so the leftmost match is the real message, and
# re.sub never rescans a replacement. A value with another of these messages
# planted inside it therefore cannot survive by eating the text a second
# pattern anchors on.
_ARGV_QUOTED = re.compile(
    r"(?P<choice>invalid choice: .+ \(choose from)"
    r"|(?P<ambiguous>ambiguous option: .+ could match )"
    r"|(?P<unrecognized>unrecognized arguments: .+)"
    r"|(?P<ignored>ignored explicit argument .+)",
    re.DOTALL,
)

_REDACTED = {
    "choice": "invalid choice (choose from",
    # The match list argparse appends is registered option names, not input.
    "ambiguous": "ambiguous option (withheld) could match ",
    # Conditional, not a rule: decode takes loose words, so "a mnemonic must
    # be one argument" would be false, and the cause is as often a misspelled
    # option as an unquoted phrase.
    "unrecognized": (
        "unrecognized arguments (withheld); check for a misspelled option, or "
        "pass a key or mnemonic as a single argument"
    ),
    "ignored": "ignored explicit argument",
}


def _redact_argv(message: str) -> str:
    return _ARGV_QUOTED.sub(lambda m: _REDACTED[m.lastgroup], message)


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
    add_io_options(encode, what="key")
    encode.add_argument(
        "key",
        nargs="?",
        help="the key to encode, in the --format encoding; hex is "
        "128 to 256 bits (32 to 64 hex chars)",
    )
    encode.set_defaults(run=run_encode)

    decode = subcommands.add_parser(
        "decode", help="recover the key from a mnemonic phrase"
    )
    add_format_option(decode)
    add_io_options(decode, what="mnemonic")
    decode.add_argument(
        "words",
        nargs="*",
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
