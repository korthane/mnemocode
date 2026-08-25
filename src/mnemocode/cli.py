"""Command-line interface for mnemocode."""

import argparse
import sys

from . import __version__
from .bip39 import VALID_ENTROPY_BYTES, entropy_to_mnemonic, mnemonic_to_entropy


def parse_key(text: str) -> bytes:
    """Parse a hex-encoded key of a BIP-39 entropy size.

    Raises:
        argparse.ArgumentTypeError: on non-hex input or an unsupported length.
    """
    cleaned = text.removeprefix("0x").removeprefix("0X")
    try:
        key = bytes.fromhex(cleaned)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not valid hex: {text!r}") from None
    if len(key) not in VALID_ENTROPY_BYTES:
        allowed = ", ".join(str(n * 8) for n in VALID_ENTROPY_BYTES)
        raise argparse.ArgumentTypeError(
            f"key is {len(key) * 8} bits; must be one of {allowed}"
        )
    return key


def run_encode(args: argparse.Namespace) -> int:
    print(" ".join(entropy_to_mnemonic(args.key)))
    return 0


def run_decode(args: argparse.Namespace) -> int:
    # Re-split so a single quoted phrase and separate word arguments both work.
    words = " ".join(args.words).split()
    print(mnemonic_to_entropy(words).hex())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mnemocode",
        description="Convert between a hex-encoded key and a BIP-39 mnemonic phrase.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    encode = subcommands.add_parser(
        "encode", help="encode a hex key into a mnemonic phrase"
    )
    encode.add_argument(
        "key",
        type=parse_key,
        help="hex-encoded key, 128 to 256 bits (32 to 64 hex chars)",
    )
    encode.set_defaults(run=run_encode)

    decode = subcommands.add_parser(
        "decode", help="recover the hex key from a mnemonic phrase"
    )
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
