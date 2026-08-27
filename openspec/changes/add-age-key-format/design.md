## Context

See `proposal.md` — Why. The relevant current state:

- `cli.py` holds all format knowledge in two places: `parse_key()`, wired in as
  an argparse `type=` hook, and the `.hex()` call in `run_decode()`.
- `bip39.py` already accepts 32 bytes (256 bits, 24 words), which is exactly the
  size of an age X25519 identity. No change is needed there.
- The package declares `dependencies = []`, and the README advertises that. It
  is load-bearing: `uv run https://…/main.py` works because the PEP 723 script's
  only dependency is this package.

**Verified during design** — an age identity's Bech32 checksum is computed over
the *lower-case* human-readable part `age-secret-key-`, and the whole string is
then upper-cased for display. This is plain BIP-173 with no age-specific quirk,
confirmed by decoding a real `age-keygen` output and re-encoding it byte-for-byte
with a reference implementation. A stock BIP-173 codec is therefore sufficient.

## Goals / Non-Goals

**Goals:**

- Keep `dependencies = []` and the no-install entry point intact.
- Keep Bech32 generic and free of age knowledge, so it is testable against the
  published BIP-173 vectors rather than only against age keys.
- Leave `bip39.py` untouched.

**Non-Goals:**

- Deriving or printing the `age1…` public key. It is public and recomputable
  from the secret; nothing about it needs a mnemonic backup.
- Reading or writing sops files, age recipient files, or key files. This change
  converts one key on the command line, nothing more.
- A general format registry. Two formats do not justify a plugin seam.

## Decisions

### `--format {hex,age}` over `--sops` / `--hex` boolean flags

The format is a single choice from a closed set, which is what a `choices=`
option models. Two mutually exclusive booleans encode the same thing less
directly and grow an exclusive group if a third format ever appears.

`age` rather than `sops` names what the string actually is. sops is a consumer of
age identities, not the definer of the format; a `--sops` flag would be wrong the
first time someone uses an age key outside sops.

**Alternative considered:** sniffing the `AGE-SECRET-KEY-` prefix on `encode` and
requiring the flag only on `decode`. Rejected for asymmetry — the two subcommands
would take different options for the same concept, and an explicit flag on both
also documents the format in shell history and scripts.

### Two new modules, split at the age boundary

`bech32.py` implements BIP-173 and knows nothing about age. `agekey.py` owns the
`age-secret-key-` human-readable part, the 32-byte length rule, and the
upper-case display convention.

The split is what lets `bech32.py` be tested against the spec's own vectors,
including its invalid ones. Folding age's rules into the codec would leave those
vectors untestable and the length check buried in a general-purpose function.

### Vendor Bech32 rather than depend on it

Roughly fifty lines of well-specified, frozen algorithm against the loss of the
zero-dependency property and the `uv run <url>` entry point. The BIP-173
reference implementation is public domain and has not changed since 2017; the
spec's test vectors pin correctness precisely.

**Alternative considered:** the `bech32` package on PyPI. Rejected on the
dependency cost above, not on quality.

### Key validation moves out of the argparse `type=` hook

argparse applies a positional argument's `type=` callable during parsing,
without regard to whether `--format` appeared before or after it on the command
line. A `type=` hook therefore cannot know which format to validate against.

Validation moves into `run_encode()`, which raises `ValueError` for the handler
already present in `main()`. `parse_key()` shrinks to the hex-specific parser it
already is, alongside a new age parser, with the handler selecting between them.

This is an observable change: an invalid key still exits 2, but is now reported
as `mnemocode: error: …` rather than an argparse usage block. That is a small
improvement in consistency — a bad key and a failed BIP-39 checksum are the same
class of error and now read the same way.

### Word count is checked before rendering, not after

`decode --format age` rejects anything other than 24 words up front. The
alternative — let `agekey.py`'s length check fail — produces a message about
byte counts for a user who supplied words. The spec's scenario calls for a
message naming the 24-word requirement.

## Risks / Trade-offs

- **A hand-written Bech32 codec is a place to get the checksum subtly wrong.**
  → Test against the BIP-173 vectors including the invalid ones (bad checksum,
  mixed case, non-zero padding bits, wrong length), plus a round trip through a
  known age identity. The failure mode this guards against — a bad checksum
  accepted — is the one the invalid vectors specifically cover.

- **A real-looking `AGE-SECRET-KEY-…` string committed as a test fixture trips
  secret scanners**, and looks alarming in a public repository even when
  throwaway. → Build fixtures from a synthetic deterministic 32-byte pattern
  rather than `age-keygen` output, and verify the expected string against the
  real `age` tool once, during implementation, without committing its output.

- **Owning vendored crypto-adjacent code is a maintenance cost.** → Accepted.
  BIP-173 is frozen, the module is small and fully covered by published vectors,
  and the alternative costs the property the README sells.

- **A `--format age` mnemonic and a `--format hex` mnemonic are
  indistinguishable.** A 24-word phrase from an age key decodes as hex just as
  happily. → Inherent to BIP-39, which carries no format tag; out of scope to
  fix. The spec makes it explicit that `decode` does not infer a format.
