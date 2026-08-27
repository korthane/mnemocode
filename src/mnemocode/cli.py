"""Command-line interface for mnemocode."""

import argparse
import sys

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


def add_format_option(
    parser: argparse.ArgumentParser, formats: dict[str, object]
) -> None:
    parser.add_argument(
        "--format",
        choices=tuple(formats),
        default="hex",
        help="key encoding: hex (the default), or age for an "
        "AGE-SECRET-KEY-1... identity",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
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
    add_format_option(encode, KEY_PARSERS)
    encode.add_argument(
        "key",
        help="the key to encode, in the --format encoding; hex is "
        "128 to 256 bits (32 to 64 hex chars)",
    )
    encode.set_defaults(run=run_encode)

    decode = subcommands.add_parser(
        "decode", help="recover the key from a mnemonic phrase"
    )
    add_format_option(decode, KEY_FORMATTERS)
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
