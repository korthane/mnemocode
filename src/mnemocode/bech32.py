"""Bech32 encoding, as defined by BIP-173.

Vendored rather than taken as a dependency so the package installs with no
runtime dependencies; see openspec design notes for the trade-off.

Spec: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
"""

from collections.abc import Iterable

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
CHECKSUM_LENGTH = 6
MAX_LENGTH = 90
_GENERATOR = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _polymod(values: Iterable[int]) -> int:
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = (checksum & 0x1FFFFFF) << 5 ^ value
        for bit in range(5):
            checksum ^= _GENERATOR[bit] if (top >> bit) & 1 else 0
    return checksum


def _expand_hrp(hrp: str) -> list[int]:
    """Split the human-readable part into the high and low bits BIP-173 mixes in."""
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _validate_hrp(hrp: str) -> None:
    if not hrp:
        raise ValueError("bech32 string has an empty human-readable part")
    for position, char in enumerate(hrp, start=1):
        if not 33 <= ord(char) <= 126:
            raise ValueError(
                f"human-readable part has a character out of range at "
                f"position {position}"
            )


def convertbits(
    data: Iterable[int], from_bits: int, to_bits: int, pad: bool = True
) -> list[int]:
    """Regroup a sequence of integers from one bit width to another.

    Args:
        data: values, each below ``2 ** from_bits``.
        from_bits: width of each input value.
        to_bits: width of each output value.
        pad: the tail rarely lands on a boundary in either direction. True
            pads it with zero bits, which is what encoding needs; False
            requires the tail to be zero bits alone, which decoding demands.

    Raises:
        ValueError: on a value too wide for from_bits, or, when pad is False,
            on more than ``from_bits - 1`` leftover bits or a non-zero one.
    """
    accumulator = 0
    bits = 0
    result = []
    max_value = (1 << to_bits) - 1
    # Bound the accumulator as BIP-173's reference does: unmasked it grows as
    # wide as the whole input, making every shift O(n) and the loop O(n**2).
    # from_bits + to_bits - 1 is the most bits any single read below needs.
    max_accumulator = (1 << (from_bits + to_bits - 1)) - 1
    for value in data:
        if value < 0 or value >> from_bits:
            raise ValueError(f"value {value} does not fit in {from_bits} bits")
        accumulator = ((accumulator << from_bits) | value) & max_accumulator
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            result.append((accumulator >> bits) & max_value)
    if pad:
        if bits:
            result.append((accumulator << (to_bits - bits)) & max_value)
    elif bits >= from_bits:
        raise ValueError(f"{bits} bits of padding; at most {from_bits - 1} allowed")
    elif accumulator & ((1 << bits) - 1):
        raise ValueError("padding bits are not zero")
    return result


def bech32_encode(hrp: str, payload: bytes) -> str:
    """Encode a payload as a lowercase Bech32 string under the given HRP.

    Args:
        hrp: human-readable part, lowercase; each character in [33, 126].
        payload: the bytes to encode.

    Returns:
        ``<hrp>1<data><checksum>``, all lowercase.

    Raises:
        ValueError: on an empty or out-of-range HRP, an HRP that is not
            lowercase, or a result longer than 90 characters.
    """
    _validate_hrp(hrp)
    if hrp != hrp.lower():
        raise ValueError(f"human-readable part must be lowercase: {hrp!r}")

    data = convertbits(payload, 8, 5, pad=True)
    checksum = _polymod(_expand_hrp(hrp) + data + [0] * CHECKSUM_LENGTH) ^ 1
    data += [
        (checksum >> 5 * (CHECKSUM_LENGTH - 1 - i)) & 31 for i in range(CHECKSUM_LENGTH)
    ]

    text = hrp + "1" + "".join(CHARSET[value] for value in data)
    if len(text) > MAX_LENGTH:
        raise ValueError(
            f"bech32 string is {len(text)} characters; max is {MAX_LENGTH}"
        )
    return text


def bech32_decode(text: str) -> tuple[str, bytes]:
    """Decode a Bech32 string, verifying its checksum.

    Args:
        text: a Bech32 string, entirely upper or entirely lower case.

    Returns:
        The lowercased human-readable part and the decoded payload.

    Raises:
        ValueError: on a non-ASCII or out-of-range character, mixed case, an
            over-long string, a missing separator, an empty HRP, an invalid
            data character, a payload whose padding is wrong, or a checksum
            that does not match.
    """
    # Check the raw text: U+212A lowercases to "k" and uppercases to itself,
    # so a homoglyph would survive the case and charset checks below.
    for position, char in enumerate(text, start=1):
        if not 33 <= ord(char) <= 126:
            raise ValueError(
                f"bech32 string has a character out of range at position {position}"
            )
    if len(text) > MAX_LENGTH:
        raise ValueError(
            f"bech32 string is {len(text)} characters; max is {MAX_LENGTH}"
        )
    if text != text.lower() and text != text.upper():
        raise ValueError("bech32 string mixes upper and lower case")

    # Fold before splitting: BIP-173 defines the checksum over the lowercase
    # form, which is why an uppercase string checksums the same as its lower.
    folded = text.lower()
    separator = folded.rfind("1")
    if separator < 0:
        raise ValueError("bech32 string has no '1' separator")

    hrp, encoded = folded[:separator], folded[separator + 1 :]
    _validate_hrp(hrp)
    if len(encoded) < CHECKSUM_LENGTH:
        raise ValueError(
            f"bech32 data part is {len(encoded)} characters; "
            f"needs at least {CHECKSUM_LENGTH} for the checksum"
        )

    data = []
    for position, char in enumerate(encoded, start=1):
        value = CHARSET.find(char)
        if value < 0:
            # By position, never the character: this text is the secret, and
            # the diagnostics are meant to be safe to paste into a bug report.
            raise ValueError(f"not a bech32 data character at position {position}")
        data.append(value)

    if _polymod(_expand_hrp(hrp) + data) != 1:
        raise ValueError("bech32 checksum does not match")

    return hrp, bytes(convertbits(data[:-CHECKSUM_LENGTH], 5, 8, pad=False))
