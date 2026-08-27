import pytest

from mnemocode.bech32 import bech32_decode, bech32_encode, convertbits

# Test vectors from BIP-173, "Test vectors".
# https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
VALID = [
    "A12UEL5L",
    "a12uel5l",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
    "?1ezyfcl",
]

INVALID = [
    ("\x201nwldj5", "HRP character out of range"),
    ("\x7f1axkwrx", "HRP character out of range"),
    ("\x801eym55h", "HRP character out of range"),
    (
        "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
        "overall max length exceeded",
    ),
    ("pzry9x0s0muk", "no separator character"),
    ("1pzry9x0s0muk", "empty HRP"),
    ("x1b4n0q5v", "invalid data character"),
    ("li1dgmt3", "too short checksum"),
    ("de1lg7wt\xff", "invalid character in checksum"),
    ("A1G7SGD8", "checksum calculated with uppercase form of HRP"),
    ("10a06t8", "empty HRP"),
    ("1qzzfhee", "empty HRP"),
    ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", "invalid checksum"),
    (
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
        "mixed case",
    ),
    # The two below are listed in BIP-173 as invalid segwit addresses. Their
    # padding is what makes them invalid at the plain Bech32 layer too: the
    # first leaves 7 bits over, the second leaves a non-zero bit.
    ("bc1rw5uspcuh", "more than 4 bits of padding"),
    (
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
        "non-zero padding in the 8-to-5 conversion",
    ),
]


@pytest.mark.parametrize("text", VALID)
def test_accepts_the_spec_vectors(text):
    hrp, payload = bech32_decode(text)
    assert hrp == text[: text.rfind("1")].lower()
    assert isinstance(payload, bytes)


@pytest.mark.parametrize("text", VALID)
def test_spec_vectors_round_trip(text):
    hrp, payload = bech32_decode(text)
    assert bech32_encode(hrp, payload) == text.lower()


@pytest.mark.parametrize("text,reason", INVALID, ids=[r for _, r in INVALID])
def test_rejects_the_spec_vectors(text, reason):
    with pytest.raises(ValueError):
        bech32_decode(text)


def test_case_is_folded_but_not_mixed():
    assert bech32_decode("A12UEL5L") == bech32_decode("a12uel5l")
    with pytest.raises(ValueError):
        bech32_decode("A12uel5l")


def test_checksum_uses_the_lowercased_hrp():
    """The property age relies on: an upper-case string checksums as lower.

    BIP-173's A1G7SGD8 vector is the counter-example, whose checksum was
    computed over the upper-case HRP; a1g7sgd8 is invalid for the same reason.
    """
    assert bech32_encode("a", b"") == "a12uel5l"
    with pytest.raises(ValueError):
        bech32_decode("A1G7SGD8")


def test_encode_rejects_an_out_of_range_hrp():
    with pytest.raises(ValueError):
        bech32_encode("\x7f", b"")


def test_encode_rejects_an_empty_hrp():
    with pytest.raises(ValueError):
        bech32_encode("", b"")


def test_encode_rejects_a_string_over_the_length_limit():
    with pytest.raises(ValueError):
        bech32_encode("hrp", bytes(64))


@pytest.mark.parametrize(
    "data,expected",
    [([], []), ([0x00], [0, 0]), ([0xFF], [31, 28]), ([0xFF, 0xFF], [31, 31, 31, 16])],
)
def test_convertbits_pads_the_trailing_group_with_zeros(data, expected):
    assert convertbits(data, 8, 5, pad=True) == expected


def test_convertbits_rejects_more_than_four_leftover_bits():
    # 8 groups of 5 bits is exactly 5 bytes; 3 groups is 15 bits, which is
    # one byte and 7 bits left over -- more padding than a byte can have.
    assert convertbits([0] * 8, 5, 8, pad=False) == [0] * 5
    with pytest.raises(ValueError):
        convertbits([0] * 3, 5, 8, pad=False)


def test_convertbits_rejects_non_zero_padding():
    with pytest.raises(ValueError):
        convertbits([0, 0, 0, 0, 1], 5, 8, pad=False)


# The 90-character limit caps a one-character HRP at 51 payload bytes. That
# still covers every 8-to-5 bit alignment six times over, since the alignment
# repeats every 8 bytes.
MAX_PAYLOAD_BYTES = 51


@pytest.mark.parametrize("size", range(MAX_PAYLOAD_BYTES + 1))
def test_round_trips_every_payload_length_that_fits(size):
    payload = bytes(range(1, size + 1))
    assert bech32_decode(bech32_encode("a", payload)) == ("a", payload)


@pytest.mark.parametrize("size", [MAX_PAYLOAD_BYTES + 1, 64])
def test_rejects_a_payload_too_long_for_the_length_limit(size):
    with pytest.raises(ValueError):
        bech32_encode("a", bytes(size))
