import hashlib
from importlib.resources import files

from mnemocode.wordlist import WORDLIST_SIZE, load_words

# sha256 of bitcoin/bips master bip-0039/english.txt; guards the vendored copy
# against accidental edits, which would silently change every mnemonic.
OFFICIAL_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"


def test_vendored_file_matches_official_wordlist():
    raw = files("mnemocode").joinpath("english.txt").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == OFFICIAL_SHA256


def test_load_words_returns_sorted_index_order():
    words = load_words()
    assert len(words) == WORDLIST_SIZE
    assert words[0] == "abandon"
    assert words[-1] == "zoo"
    assert list(words) == sorted(words)
