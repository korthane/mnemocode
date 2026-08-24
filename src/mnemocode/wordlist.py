"""Access to the vendored BIP-39 English wordlist."""

from functools import cache
from importlib.resources import files

WORDLIST_SIZE = 2048


@cache
def load_words() -> tuple[str, ...]:
    """Return the 2048 BIP-39 English words, in index order.

    Read through importlib.resources so it resolves whether the package is an
    installed wheel or a source checkout. The result is cached and shared
    between callers, hence a tuple.

    Raises:
        ValueError: if the vendored file is not exactly 2048 words.
    """
    text = files(__package__).joinpath("english.txt").read_text("utf-8")
    words = tuple(text.split())
    if len(words) != WORDLIST_SIZE:
        raise ValueError(
            f"corrupt wordlist: expected {WORDLIST_SIZE} words, got {len(words)}"
        )
    return words
