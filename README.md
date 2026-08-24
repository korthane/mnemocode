# mnemocode

Encodes a hex-encoded binary key (128 to 256 bits) into a word mnemonic
according to [BIP-39][bip39], using the official English wordlist.

```
$ mnemocode 0c1e24e5917779d297e14d45f14e1a1a
army van defense carry jealous true garbage claim echo media make crunch
```

## Key sizes

BIP-39 accepts entropy in multiples of 32 bits, between 128 and 256:

| Key size | Hex chars | Words |
|---------:|----------:|------:|
|      128 |        32 |    12 |
|      160 |        40 |    15 |
|      192 |        48 |    18 |
|      224 |        56 |    21 |
|      256 |        64 |    24 |

An optional `0x` prefix is accepted. Any other length is rejected.

## Running it

Local checkout:

```sh
uv run mnemocode <key>
```

From GitHub, without cloning:

```sh
uvx --from git+https://github.com/korthane/mnemocode mnemocode <key>
uv run https://raw.githubusercontent.com/korthane/mnemocode/main/main.py <key>
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
