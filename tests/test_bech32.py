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

# Each entry pairs a vector with the message fragment it must be rejected by,
# so a vector caught for an unrelated reason fails the test.
INVALID = [
    ("\x201nwldj5", "HRP character out of range", "out of range"),
    ("\x7f1axkwrx", "HRP character out of range", "out of range"),
    ("\x801eym55h", "HRP character out of range", "out of range"),
    (
        "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
        "overall max length exceeded",
        "max is 90",
    ),
    ("pzry9x0s0muk", "no separator character", "no '1' separator"),
    ("1pzry9x0s0muk", "empty HRP", "empty human-readable part"),
    ("x1b4n0q5v", "invalid data character", "not a bech32 data character"),
    ("li1dgmt3", "too short checksum", "needs at least 6 for the checksum"),
    ("de1lg7wt\xff", "invalid character in checksum", "out of range"),
    (
        "A1G7SGD8",
        "checksum calculated with uppercase form of HRP",
        "checksum does not match",
    ),
    ("10a06t8", "empty HRP", "empty human-readable part"),
    ("1qzzfhee", "empty HRP", "empty human-readable part"),
    (
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
        "invalid checksum",
        "checksum does not match",
    ),
    (
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
        "mixed case",
        "mixes upper and lower case",
    ),
    # The two below are listed in BIP-173 as invalid segwit addresses. Their
    # padding is what makes them invalid at the plain Bech32 layer too: the
    # first leaves 7 bits over, the second leaves a non-zero bit.
    ("bc1rw5uspcuh", "more than 4 bits of padding", "bits of padding"),
    (
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
        "non-zero padding in the 8-to-5 conversion",
        "padding bits are not zero",
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


@pytest.mark.parametrize(
    "text,message", [(t, m) for t, _, m in INVALID], ids=[r for _, r, _ in INVALID]
)
def test_rejects_the_spec_vectors(text, message):
    with pytest.raises(ValueError, match=message):
        bech32_decode(text)


def test_rejects_a_non_ascii_character_that_folds_onto_the_charset():
    """U+212A lowercases to "k" and uppercases to itself, passing both folds."""
    with pytest.raises(ValueError, match="out of range"):
        bech32_decode("\u212a18DUSE0")


def test_case_is_folded_but_not_mixed():
    assert bech32_decode("A12UEL5L") == bech32_decode("a12uel5l")
    with pytest.raises(ValueError, match="mixes upper and lower case"):
        bech32_decode("A12uel5l")


def test_checksum_uses_the_lowercased_hrp():
    """The property age relies on: an upper-case string checksums as lower.

    BIP-173's A1G7SGD8 vector is the counter-example, whose checksum was
    computed over the upper-case HRP; a1g7sgd8 is invalid for the same reason.
    """
    assert bech32_encode("a", b"") == "a12uel5l"
    with pytest.raises(ValueError, match="checksum does not match"):
        bech32_decode("A1G7SGD8")


def test_encode_rejects_an_out_of_range_hrp():
    with pytest.raises(ValueError, match="character out of range"):
        bech32_encode("\x7f", b"")


def test_encode_rejects_an_empty_hrp():
    with pytest.raises(ValueError, match="empty human-readable part"):
        bech32_encode("", b"")


def test_encode_rejects_an_uppercase_hrp():
    # The checksum is defined over the lowercase HRP, so encoding under an
    # uppercase one would emit a string bech32_decode rejects.
    with pytest.raises(ValueError, match="lowercase"):
        bech32_encode("A", b"")


def test_encode_rejects_a_string_over_the_length_limit():
    with pytest.raises(ValueError, match="max is 90"):
        bech32_encode("hrp", bytes(64))


@pytest.mark.parametrize(
    "data,expected",
    [([], []), ([0x00], [0, 0]), ([0xFF], [31, 28]), ([0xFF, 0xFF], [31, 31, 31, 16])],
)
def test_convertbits_pads_the_trailing_group_with_zeros(data, expected):
    assert convertbits(data, 8, 5, pad=True) == expected


# n groups of 5 bits leave (5 * n) % 8 over: 4 at n=4, 5 at n=1, 7 at n=3.
# The reject/accept boundary sits between 4 and 5, so both sides are pinned.
@pytest.mark.parametrize("groups,expected", [(8, [0] * 5), (4, [0, 0])])
def test_convertbits_accepts_up_to_four_leftover_bits(groups, expected):
    assert convertbits([0] * groups, 5, 8, pad=False) == expected


@pytest.mark.parametrize("groups", [1, 3])
def test_convertbits_rejects_more_than_four_leftover_bits(groups):
    with pytest.raises(ValueError, match="bits of padding; at most 4 allowed"):
        convertbits([0] * groups, 5, 8, pad=False)


@pytest.mark.parametrize("value", [-1, 32])
def test_convertbits_rejects_a_value_too_wide_for_from_bits(value):
    with pytest.raises(ValueError, match="does not fit"):
        convertbits([value], 5, 8, pad=False)


# convertbits documents a general width contract but the codec only ever uses
# 8<->5, so the accumulator mask is otherwise pinned at a single width pair.
@pytest.mark.parametrize("from_bits,to_bits", [(8, 5), (5, 8), (8, 6), (6, 8), (4, 11)])
def test_convertbits_round_trips_at_other_widths(from_bits, to_bits):
    values = [i % (1 << from_bits) for i in range(64)]
    widened = convertbits(values, from_bits, to_bits, pad=True)
    assert all(0 <= v < (1 << to_bits) for v in widened)
    restored = convertbits(widened, to_bits, from_bits, pad=True)
    assert restored[: len(values)] == values


def test_convertbits_rejects_non_zero_padding():
    with pytest.raises(ValueError, match="padding bits are not zero"):
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
    with pytest.raises(ValueError, match="max is 90"):
        bech32_encode("a", bytes(size))
