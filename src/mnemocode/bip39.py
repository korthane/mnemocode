"""BIP-39 entropy-to-mnemonic encoding.

Spec: https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039.mediawiki
"""

import hashlib
from .wordlist import load_words


VALID_ENTROPY_BYTES = (16, 20, 24, 28, 32)
BITS_PER_WORD = 11  # 2**11 == len(wordlist)


def entropy_to_mnemonic(entropy: bytes) -> list[str]:
    """Encode entropy as a BIP-39 mnemonic.

    Args:
        entropy: 16, 20, 24, 28 or 32 bytes (128-256 bits, multiples of 32).

    Returns:
        12, 15, 18, 21 or 24 words from the English wordlist.

    Raises:
        ValueError: if the entropy length is not a supported size.
    """
    # Other sizes leave total_bits indivisible by 11, silently dropping the
    # trailing bits instead of failing.
    if len(entropy) not in VALID_ENTROPY_BYTES:
        raise ValueError(
            f"entropy is {len(entropy) * 8} bits; must be 128, 160, 192, 224 or 256"
        )

    entropy_bits = len(entropy) * 8
    checksum_bits = entropy_bits // 32
    total_bits = entropy_bits + checksum_bits

    digest = hashlib.sha256(entropy).digest()
    checksum = int.from_bytes(digest) >> (len(digest) * 8 - checksum_bits)
    payload = (int.from_bytes(entropy) << checksum_bits) | checksum

    words = load_words()
    mnemonic = []
    for shift in range(total_bits - BITS_PER_WORD, -1, -BITS_PER_WORD):
        index = (payload >> shift) & ((1 << BITS_PER_WORD) - 1)
        mnemonic.append(words[index])
    return mnemonic
