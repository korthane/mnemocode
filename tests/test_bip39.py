import pytest

from mnemocode.bip39 import entropy_to_mnemonic

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
