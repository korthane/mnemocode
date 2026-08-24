"""Command-line interface for mnemocode."""

import argparse
import sys

from . import __version__
from .bip39 import VALID_ENTROPY_BYTES, entropy_to_mnemonic


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mnemocode",
        description="Encode a hex-encoded key into a BIP-39 mnemonic phrase.",
    )
    parser.add_argument(
        "key",
        type=parse_key,
        help="hex-encoded key, 128 to 256 bits (32 to 64 hex chars)",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    print(" ".join(entropy_to_mnemonic(args.key)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
