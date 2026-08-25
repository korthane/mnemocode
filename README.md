# mnemocode

Converts a hex-encoded binary key (128 to 256 bits) to and from a word
mnemonic according to [BIP-39][bip39], using the official English wordlist.

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

No runtime dependencies; the tool is pure standard library.

```sh
uv sync          # create the venv, install dev dependencies
uv run pytest    # run the tests
```

`src/mnemocode/english.txt` is a verbatim copy of [the official BIP-39 English
wordlist][wordlist]. `tests/test_wordlist.py` pins its SHA-256, since an edit
there would silently change every mnemonic the tool produces.

[bip39]: https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039.mediawiki
[wordlist]: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
[pep723]: https://peps.python.org/pep-0723/
