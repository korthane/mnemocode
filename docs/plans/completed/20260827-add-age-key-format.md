# Add age key format to encode and decode

## Overview

`mnemocode` only reads and writes hex, but the keys most worth backing up as a
spoken or written phrase are age X25519 identities — the `AGE-SECRET-KEY-1…`
string that sops uses to decrypt a repository's secrets. Today that means
converting to hex by hand before encoding and back again after decoding, which is
exactly the error-prone step the tool exists to remove.

This change adds a `--format {hex,age}` option to both `encode` and `decode`,
defaulting to `hex` so no existing invocation changes behaviour. With
`--format age`, `encode` accepts an `AGE-SECRET-KEY-1…` Bech32 string, verifies
its checksum, and emits the 24-word BIP-39 mnemonic for its 32-byte payload;
`decode` reverses it and prints a canonical uppercase identity string.

## Context

- Adopted from OpenSpec change `add-age-key-format`
  (`openspec/changes/add-age-key-format/`), which carries the full proposal,
  design rationale, and the `key-formats` capability spec.
- **New**: `src/mnemocode/bech32.py`, `src/mnemocode/agekey.py`, and their tests.
- **Changed**: `src/mnemocode/cli.py`. Key validation moves out of the argparse
  `type=` hook into the subcommand handlers, because argparse applies `type=`
  before `--format` is known. Invalid keys keep exit code 2 but are reported as
  `mnemocode: error: …` rather than an argparse usage block.
- **Unchanged**: `bip39.py`, `wordlist.py`, `english.txt`. `bip39.py` already
  accepts 32 bytes (256 bits, 24 words), which is exactly the size of an age
  identity, so it needs no change.
- Bech32 (BIP-173) is implemented in-tree rather than pulled in as a dependency,
  so the package keeps `dependencies = []` and the `uv run <raw-url>/main.py`
  entry point keeps working with no install step.
- Not a breaking change.

## Development Approach

- Testing approach: TDD — write the tests first, confirm they fail for want of
  the module, then implement until they pass
- Complete each task fully before moving to the next
- Update this plan when scope changes during implementation

## Testing Strategy

- Unit tests required for every code-changing Task
- Bech32 is tested against the published BIP-173 vectors, including the invalid
  ones (bad checksum, mixed case, non-zero padding bits, out-of-range length,
  invalid characters, missing separator)
- Age fixtures are built from a synthetic deterministic 32-byte pattern rather
  than `age-keygen` output, so no real-looking secret is committed
- Run project tests after each Task before proceeding

## Progress Tracking

- Mark completed items with `[x]` immediately when done
- Update plan if implementation deviates from original scope

## Technical Details

### Module split

`bech32.py` implements BIP-173 and knows nothing about age. `agekey.py` owns the
`age-secret-key-` human-readable part, the 32-byte length rule, and the
upper-case display convention. The split is what lets `bech32.py` be tested
against the spec's own vectors, including its invalid ones; folding age's rules
into the codec would leave those vectors untestable and the length check buried
in a general-purpose function.

An age identity's Bech32 checksum is computed over the *lower-case*
human-readable part `age-secret-key-`, and the whole string is then upper-cased
for display. This is plain BIP-173 with no age-specific quirk, so a stock codec
is sufficient.

### `--format` over boolean flags

The format is a single choice from a closed set, which is what a `choices=`
option models. `age` rather than `sops` names what the string actually is — sops
is a consumer of age identities, not the definer of the format. The flag appears
on both subcommands rather than being sniffed on `encode`, so the two subcommands
take the same option for the same concept and the format is recorded in shell
history and scripts.

### Validation moves out of the argparse `type=` hook

argparse applies a positional argument's `type=` callable during parsing, without
regard to whether `--format` appeared before or after it on the command line. A
`type=` hook therefore cannot know which format to validate against. Validation
moves into `run_encode()`, which raises `ValueError` for the handler already
present in `main()`.

### Word count is checked before rendering

`decode --format age` rejects anything other than 24 words up front. Letting
`agekey.py`'s length check fail instead would produce a message about byte counts
for a user who supplied words.

### Required behaviour (from the `key-formats` spec)

- **Format selection**: `--format` accepts `hex` and `age`, defaults to `hex`. On
  `encode` it describes the key given on the command line; on `decode` it
  describes the key printed to stdout. A mnemonic carries no record of its
  format, so `decode` does not infer one. An unsupported value exits non-zero and
  names the accepted values.
- **Hex unchanged**: an optional `0x` prefix is accepted, any BIP-39 entropy size
  from 128 to 256 bits is accepted, and `decode` prints lowercase hex with no
  prefix. Explicit `--format hex` produces the same mnemonic as the default.
- **Encoding an age key**: the Bech32 checksum is verified before the key is
  used. A failed checksum, an `age1…` public key, or a payload that is not 32
  bytes each exit 2 with a message naming that specific problem.
- **Decoding to an age key**: the BIP-39 checksum is verified as before, then the
  key is printed as an identity string. A valid mnemonic of 12, 15, 18 or 21
  words exits 2 with a message naming the 24-word requirement.
- **Letter case**: an identity written entirely in upper case or entirely in
  lower case is accepted; a mixed-case one is rejected. Output is always upper
  case, matching what `age-keygen` writes.
- **Error reporting**: a key rejected for any reason exits 2 and writes a
  diagnostic to stderr, leaving stdout empty.

### Out of scope

Deriving or printing the `age1…` public key; reading or writing sops files, age
recipient files, or key files; a general format registry.

## Implementation Steps

### Task 1: Bech32 codec

- [x] write `tests/test_bech32.py` from the BIP-173 test vectors — the valid
      strings, and the invalid ones (bad checksum, mixed case, non-zero padding
      bits, out-of-range length, invalid characters, missing separator); verify
      the file collects and every test fails for want of the module
- [x] implement `src/mnemocode/bech32.py` with `bech32_encode(hrp, payload)` and
      `bech32_decode(text) -> (hrp, payload)`, computing the checksum over the
      lower-cased human-readable part per BIP-173, free of any age knowledge
- [x] add a round-trip property test over every payload length that fits
      (1–51 bytes for a one-character HRP; Bech32's 90-character limit makes 64
      unreachable), covering the 8-to-5-bit conversion padding
- [x] run project tests - must pass before next task

### Task 2: Age identity module

- [x] choose a synthetic deterministic 32-byte fixture rather than `age-keygen`
      output, and confirm the expected identity string by round-tripping it
      through the real `age` tool locally; record the string in the test file and
      commit no generated key file
- [x] write `tests/test_agekey.py`: round trip for the fixture, lower-case input
      accepted, mixed-case rejected, `age1…` public key rejected as not a secret
      key, wrong payload length rejected, bad checksum rejected; verify the tests
      fail for want of the module
- [x] implement `src/mnemocode/agekey.py` with `parse_age_secret_key(text)` and
      `format_age_secret_key(key)`, owning the `age-secret-key-` human-readable
      part, the 32-byte rule, and upper-case output, raising `ValueError` with a
      message naming the specific problem in each case
- [x] run project tests - must pass before next task

### Task 3: CLI wiring

- [x] extend `tests/test_cli.py` for the new surface: `--format age` encode and
      decode round trip, the default and explicit `--format hex` producing
      identical output, an unknown `--format` value rejected, `decode --format
      age` on a 12-word mnemonic erroring with a message naming the 24-word
      requirement, and each failure exiting 2 with empty stdout; verify they fail
      first
- [x] add `--format` with `choices=("hex", "age")` and `default="hex"` to both
      subcommands in `build_parser()`, and verify `mnemocode encode --help` shows
      it
- [x] move key validation out of the argparse `type=` hook: take the key as a
      plain string and dispatch on `args.format` inside `run_encode()`, raising
      `ValueError` for the existing handler in `main()`; verify the pre-existing
      hex tests still pass unchanged apart from the expected message wording
- [x] dispatch the output format in `run_decode()`, rejecting a non-24-word
      mnemonic before rendering when the format is `age`
- [x] run project tests - must pass before next task

### Task 4: Documentation

- [x] add an age/sops section to `README.md` showing both directions with a real
      command, and note in the key-size table that an age identity is always
      256 bits and 24 words
- [x] verify the commands shown in the README produce the output shown
- [x] confirm the zero-dependency claim still holds: `pyproject.toml` still has
      `dependencies = []` and the PEP 723 shim works — `main.py` pins its
      dependency to GitHub `main` so it cannot exercise unpushed code, so verify
      instead with `uvx --from .` and by running the shim against a local path
- [x] run project tests - must pass before next task

### Task 5: Verify acceptance criteria

- [x] round-trip a freshly generated `age-keygen` key through `encode --format
      age` and `decode --format age` and verify the result is
      character-for-character identical to the original; delete the generated key
      afterwards and commit nothing
- [x] verify every scenario in the `key-formats` spec has a corresponding test
- [x] verify all requirements from Overview are implemented
- [x] run full project test suite - must pass with no skips
- [x] run project linter - all issues must be fixed

## Post-Completion

*Items requiring manual intervention - no checkboxes, informational only*

- The source OpenSpec change at `openspec/changes/add-age-key-format/` is still
  unarchived; archive it once the work is committed.
- `main.py` pins its dependency to GitHub `main`, so the hosted
  `uv run <raw-url>/main.py` entry point only exercises `--format age` after the
  change is pushed.
