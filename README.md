# mnemocode

Converts a binary key (128 to 256 bits) to and from a word mnemonic according
to [BIP-39][bip39], using the official English wordlist. The key can be hex or
an [age][age] secret key — the `AGE-SECRET-KEY-1…` identity [sops][sops] uses.

```
$ mnemocode encode 0c1e24e5917779d297e14d45f14e1a1a
army van defense carry jealous true garbage claim echo media make crunch

$ mnemocode decode army van defense carry jealous true garbage claim echo media make crunch
0c1e24e5917779d297e14d45f14e1a1a
```

`decode` takes the words as separate arguments or as one quoted phrase, in
any case. It verifies the BIP-39 checksum and exits non-zero on a mismatch,
so a mistyped word is reported rather than silently decoded to the wrong key.

## Key sizes

BIP-39 accepts entropy in multiples of 32 bits, between 128 and 256:

| Key size | Hex chars | Words |
|---------:|----------:|------:|
|      128 |        32 |    12 |
|      160 |        40 |    15 |
|      192 |        48 |    18 |
|      224 |        56 |    21 |
|      256 |        64 |    24 |

An optional `0x` prefix is accepted on input; `decode` prints lowercase hex
without one. Any other length is rejected, in either direction.

An age secret key is always 256 bits, so it is always 24 words.

## age and sops keys

Pass `--format age` to read or write an age identity instead of hex:

```
$ mnemocode encode --format age AGE-SECRET-KEY-1QQQSYQCYQ5RQWZQFPG9SCRGWPUGPZYSNZS23V9CCRYDPK8QARC0SWRYDWG
abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch range attend journey unaware

$ mnemocode decode --format age abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch range attend journey unaware
AGE-SECRET-KEY-1QQQSYQCYQ5RQWZQFPG9SCRGWPUGPZYSNZS23V9CCRYDPK8QARC0SWRYDWG
```

(That is a throwaway demo key, built from the bytes `00 01 02 … 1f`.)

The identity may be given in upper or lower case, but not a mix of the two —
Bech32 forbids it, and a mixed-case string usually means a transcription error.
`decode` always prints upper case, matching what `age-keygen` writes, so the
output can go straight into a key file.

The Bech32 checksum is verified on the way in, just as the BIP-39 checksum is,
so a mistyped key is reported rather than silently converted to the wrong
mnemonic.

Note that a mnemonic does not record which format it came from. A phrase made
from an age key decodes as hex just as readily, so `decode` needs to be told
`--format age`; it will not guess.

## Running it

Local checkout:

```sh
uv run mnemocode encode <key>
```

From GitHub, without cloning:

```sh
uvx --from git+https://github.com/korthane/mnemocode mnemocode encode <key>
uv run https://raw.githubusercontent.com/korthane/mnemocode/main/main.py encode <key>
```

Both install the package into a temporary environment, so the bundled
wordlist comes with them. The second form works because `main.py` is a
[PEP 723][pep723] script whose only dependency is this package.

Install it permanently:

```sh
uv tool install git+https://github.com/korthane/mnemocode
```

## Development

No runtime dependencies; the tool is pure standard library. `bech32.py` is a
vendored implementation of [BIP-173][bip173], kept in-tree for that reason;
`tests/test_bech32.py` runs it against the spec's own test vectors.

```sh
uv sync          # create the venv, install dev dependencies
uv run pytest    # run the tests
```

`src/mnemocode/english.txt` is a verbatim copy of [the official BIP-39 English
wordlist][wordlist]. `tests/test_wordlist.py` pins its SHA-256, since an edit
there would silently change every mnemonic the tool produces.

[age]: https://age-encryption.org
[bip39]: https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039.mediawiki
[bip173]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
[wordlist]: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
[pep723]: https://peps.python.org/pep-0723/
[sops]: https://github.com/getsops/sops
