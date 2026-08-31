"""age X25519 identities, the AGE-SECRET-KEY-1... strings sops consumes.

Spec: https://github.com/C2SP/C2SP/blob/main/age.md
"""

from .bech32 import bech32_decode, bech32_encode

AGE_SECRET_KEY_HRP = "age-secret-key-"
AGE_SECRET_KEY_BYTES = 32


def parse_age_secret_key(text: str) -> bytes:
    """Recover the key an age identity string carries, verifying its checksum.

    Args:
        text: an AGE-SECRET-KEY-1... string, entirely upper or lower case.

    Returns:
        The 32-byte X25519 secret key.

    Raises:
        ValueError: if the text is not valid Bech32, carries a different
            human-readable part, or holds something other than 32 bytes.
    """
    hrp, key = bech32_decode(text.strip())
    if hrp != AGE_SECRET_KEY_HRP:
        # The prefix we wanted is a constant, but the one we got came from
        # the input, so it is not quoted back.
        raise ValueError(
            f"not an age secret key: expected the {AGE_SECRET_KEY_HRP!r} prefix, "
            "got a different one"
        )
    if len(key) != AGE_SECRET_KEY_BYTES:
        raise ValueError(
            f"age secret key is {len(key)} bytes; must be {AGE_SECRET_KEY_BYTES} bytes"
        )
    return key


def format_age_secret_key(key: bytes) -> str:
    """Render a 32-byte key as an age identity string.

    Uppercase, matching what age-keygen writes, so the result can be pasted
    into a key file unchanged.

    Raises:
        ValueError: if the key is not exactly 32 bytes.
    """
    if len(key) != AGE_SECRET_KEY_BYTES:
        raise ValueError(
            f"age secret key is {len(key)} bytes; must be {AGE_SECRET_KEY_BYTES} bytes"
        )
    return bech32_encode(AGE_SECRET_KEY_HRP, key).upper()
