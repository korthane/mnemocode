import pytest

from mnemocode.bip39 import entropy_to_mnemonic, mnemonic_to_entropy

# Official BIP-39 English vectors from trezor/python-mnemonic vectors.json.
# The set covers 128/192/256 bits only; 160 and 224 have no official vectors.
VECTORS = [
    ('00000000000000000000000000000000', 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'),
    ('7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f', 'legal winner thank year wave sausage worth useful legal winner thank yellow'),
    ('ffffffffffffffffffffffffffffffff', 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong'),
    ('000000000000000000000000000000000000000000000000', 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent'),
    ('0000000000000000000000000000000000000000000000000000000000000000', 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art'),
    ('f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f', 'void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold'),
]


@pytest.mark.parametrize("entropy_hex,expected", VECTORS)
def test_official_vectors(entropy_hex, expected):
    assert entropy_to_mnemonic(bytes.fromhex(entropy_hex)) == expected.split()


@pytest.mark.parametrize("n_bytes,n_words", [(16, 12), (20, 15), (24, 18), (28, 21), (32, 24)])
def test_word_count_per_entropy_size(n_bytes, n_words):
    assert len(entropy_to_mnemonic(bytes(n_bytes))) == n_words


@pytest.mark.parametrize("n_bytes", [0, 15, 17, 31, 33, 64])
def test_rejects_unsupported_entropy_size(n_bytes):
    with pytest.raises(ValueError):
        entropy_to_mnemonic(bytes(n_bytes))


@pytest.mark.parametrize("entropy_hex,mnemonic", VECTORS)
def test_official_vectors_decode(entropy_hex, mnemonic):
    assert mnemonic_to_entropy(mnemonic.split()) == bytes.fromhex(entropy_hex)


@pytest.mark.parametrize("n_bytes", [16, 20, 24, 28, 32])
def test_round_trip(n_bytes):
    entropy = bytes(range(1, n_bytes + 1))
    assert mnemonic_to_entropy(entropy_to_mnemonic(entropy)) == entropy


def test_leading_zero_bytes_survive_round_trip():
    entropy = bytes(15) + b"\x01"
    assert mnemonic_to_entropy(entropy_to_mnemonic(entropy)) == entropy


def test_accepts_mixed_case():
    words = "Abandon ABANDON abandon abandon abandon abandon abandon abandon abandon abandon abandon About"
    assert mnemonic_to_entropy(words.split()) == bytes(16)


def test_rejects_bad_checksum():
    # Valid words, but all-zero entropy checksums to "about", not "abandon".
    with pytest.raises(ValueError, match="checksum"):
        mnemonic_to_entropy(["abandon"] * 12)


def test_rejects_unknown_word():
    words = ["abandon"] * 11 + ["mnemocode"]
    with pytest.raises(ValueError, match="word 12"):
        mnemonic_to_entropy(words)


@pytest.mark.parametrize("n_words", [0, 11, 13, 23, 25])
def test_rejects_unsupported_word_count(n_words):
    with pytest.raises(ValueError, match="must be 12"):
        mnemonic_to_entropy(["abandon"] * n_words)
