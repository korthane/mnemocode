import pytest

from mnemocode.agekey import (
    AGE_SECRET_KEY_BYTES,
    format_age_secret_key,
    parse_age_secret_key,
)
from mnemocode.bech32 import bech32_encode

# A synthetic key, not one from age-keygen: a real private key in the tree
# would trip secret scanners. Verified against age itself -- age-keygen -y
# accepts this identity and derives PUBLIC_KEY from it.
KEY = bytes(range(32))
IDENTITY = "AGE-SECRET-KEY-1QQQSYQCYQ5RQWZQFPG9SCRGWPUGPZYSNZS23V9CCRYDPK8QARC0SWRYDWG"
PUBLIC_KEY = "age13aqvttdk3ujkyjh9kg2w5an6dmy5mq5a84a4uxk3hfhnugfc9p0sy5p2wh"


def test_parses_the_fixture():
    assert parse_age_secret_key(IDENTITY) == KEY


def test_formats_the_fixture():
    assert format_age_secret_key(KEY) == IDENTITY


def test_round_trips():
    assert parse_age_secret_key(format_age_secret_key(KEY)) == KEY


def test_output_is_uppercase():
    assert format_age_secret_key(KEY).isupper()


def test_accepts_lowercase_input():
    assert parse_age_secret_key(IDENTITY.lower()) == KEY


def test_rejects_mixed_case():
    mixed = IDENTITY[:-1] + IDENTITY[-1].lower()
    with pytest.raises(ValueError, match="case"):
        parse_age_secret_key(mixed)


def test_rejects_a_public_key():
    with pytest.raises(ValueError, match="not an age secret key"):
        parse_age_secret_key(PUBLIC_KEY)


def test_rejects_a_bad_checksum():
    typo = IDENTITY[:-1] + ("P" if IDENTITY[-1] != "P" else "Z")
    with pytest.raises(ValueError, match="checksum"):
        parse_age_secret_key(typo)


@pytest.mark.parametrize("size", [0, 16, 31, 33])
def test_rejects_a_payload_that_is_not_32_bytes(size):
    text = bech32_encode("age-secret-key-", bytes(size)).upper()
    with pytest.raises(ValueError, match="32 bytes"):
        parse_age_secret_key(text)


@pytest.mark.parametrize("size", [0, 16, 31, 33])
def test_refuses_to_format_a_key_that_is_not_32_bytes(size):
    with pytest.raises(ValueError, match="32 bytes"):
        format_age_secret_key(bytes(size))


def test_rejects_text_that_is_not_bech32_at_all():
    with pytest.raises(ValueError):
        parse_age_secret_key("not a key")


def test_exports_the_key_size():
    assert AGE_SECRET_KEY_BYTES == 32
