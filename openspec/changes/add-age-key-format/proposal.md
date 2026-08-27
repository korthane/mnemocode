## Why

`mnemocode` only reads and writes hex, but the keys most worth backing up as a
spoken/written phrase are age X25519 identities — the `AGE-SECRET-KEY-1…` string
that sops uses to decrypt a repository's secrets. Today that means converting to
hex by hand before encoding and back again after decoding, which is exactly the
error-prone step the tool exists to remove.

## What Changes

- Add a `--format {hex,age}` option to both `encode` and `decode`, defaulting to
  `hex`. No existing invocation changes behaviour.
- `encode --format age` accepts an `AGE-SECRET-KEY-1…` Bech32 string, verifies its
  checksum, and emits the 24-word BIP-39 mnemonic for its 32-byte payload.
- `decode --format age` reverses it, printing a canonical uppercase
  `AGE-SECRET-KEY-1…` string.
- Add a Bech32 (BIP-173) implementation. It is written in-tree rather than pulled
  in as a dependency so the package keeps `dependencies = []` and the
  `uv run <raw-url>/main.py` entry point keeps working with no install step.
- Not a breaking change: `bip39.py` is untouched, and 32 bytes is already a
  supported entropy size.

## Capabilities

### New Capabilities

- `key-formats`: how a key is parsed from and rendered to text at the CLI
  boundary — which encodings are supported, how one is selected, and what makes
  an input valid in each.

### Modified Capabilities

<!-- None: openspec/specs/ is empty, so the mnemonic behaviour this builds on has
     no spec to amend yet. This change specs only the format boundary it adds. -->

## Impact

- **New**: `src/mnemocode/bech32.py`, `src/mnemocode/agekey.py`, and their tests.
- **Changed**: `src/mnemocode/cli.py`. Key validation moves out of the argparse
  `type=` hook into the subcommand handlers, because argparse applies `type=`
  before `--format` is known. Invalid keys keep exit code 2 but are reported as
  `mnemocode: error: …` rather than an argparse usage block.
- **Unchanged**: `bip39.py`, `wordlist.py`, `english.txt`, and the package's
  zero-dependency install story.
- **Docs**: README gains an age/sops section and the key-size table gains a note
  that an age identity is always 256 bits / 24 words.
