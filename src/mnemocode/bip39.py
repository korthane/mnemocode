"""BIP-39 entropy-to-mnemonic encoding.

Spec: https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039.mediawiki
"""

import hashlib
from collections.abc import Sequence

from .wordlist import load_words, word_index


VALID_ENTROPY_BYTES = (16, 20, 24, 28, 32)
VALID_WORD_COUNTS = (12, 15, 18, 21, 24)
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


def mnemonic_to_entropy(mnemonic: Sequence[str]) -> bytes:
    """Recover the entropy a BIP-39 mnemonic encodes, verifying its checksum.

    Args:
        mnemonic: 12, 15, 18, 21 or 24 English wordlist words, any case.

    Returns:
        The 16, 20, 24, 28 or 32 bytes of entropy.

    Raises:
        ValueError: on an unsupported word count, a word outside the wordlist,
            or a checksum that does not match the entropy.
    """
    if len(mnemonic) not in VALID_WORD_COUNTS:
        raise ValueError(
            f"mnemonic has {len(mnemonic)} words; must be 12, 15, 18, 21 or 24"
        )

    indexes = word_index()
    payload = 0
    for position, word in enumerate(mnemonic, start=1):
        try:
            index = indexes[word.lower()]
        except KeyError:
            # The word is secret material; the position is enough to locate it.
            raise ValueError(
                f"word {position} is not in the BIP-39 English wordlist"
            ) from None
        payload = (payload << BITS_PER_WORD) | index

    # A mnemonic is 33 bits per 32 bits of entropy, so the checksum is 1/33rd.
    total_bits = len(mnemonic) * BITS_PER_WORD
    checksum_bits = total_bits // 33
    entropy_bits = total_bits - checksum_bits

    entropy = (payload >> checksum_bits).to_bytes(entropy_bits // 8)
    digest = hashlib.sha256(entropy).digest()
    expected = int.from_bytes(digest) >> (len(digest) * 8 - checksum_bits)
    actual = payload & ((1 << checksum_bits) - 1)
    if actual != expected:
        raise ValueError(
            "checksum mismatch; the mnemonic contains a typo or wrong word order"
        )
    return entropy
