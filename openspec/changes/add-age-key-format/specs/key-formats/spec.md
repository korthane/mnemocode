## Purpose

Defines the text encodings `mnemocode` accepts for a key and renders a key back
into at the CLI boundary, how the caller selects one, and what makes an input
valid in each — so the same key survives a round trip through a mnemonic in the
form its owning tool expects.

## ADDED Requirements

### Requirement: Key format selection

The `encode` and `decode` subcommands SHALL each accept a `--format` option
choosing the text encoding of the key. The supported values SHALL be `hex` and
`age`, and the default SHALL be `hex`.

On `encode`, `--format` describes the key given on the command line. On
`decode`, it describes the key printed to standard output. A mnemonic carries no
record of the format it was produced from, so `decode` SHALL NOT infer one.

#### Scenario: Format defaults to hex

- **WHEN** `encode` or `decode` is invoked without `--format`
- **THEN** the key is read or written as hex, exactly as before this change

#### Scenario: Unsupported format value

- **WHEN** `--format` is given a value other than `hex` or `age`
- **THEN** the command exits non-zero and names the accepted values

### Requirement: Hex format behaviour is unchanged

With `--format hex`, whether given explicitly or by default, the tool SHALL
behave exactly as it did before this change: an optional `0x` prefix is accepted
on input, any BIP-39 entropy size from 128 to 256 bits is accepted, and `decode`
prints lowercase hex without a prefix.

#### Scenario: Explicit hex matches the default

- **WHEN** a key is encoded with `--format hex` and the same key is encoded with
  no `--format` option
- **THEN** both produce the same mnemonic

### Requirement: Encoding an age secret key

With `--format age`, `encode` SHALL accept an age X25519 identity — a Bech32
string with the human-readable part `age-secret-key-`, as written by
`age-keygen` and consumed by sops — and print the BIP-39 mnemonic for the
32-byte key it carries.

The Bech32 checksum SHALL be verified before the key is used, so that a
mistyped identity is reported rather than silently encoded to the wrong
mnemonic.

#### Scenario: Valid age identity is encoded

- **WHEN** `encode --format age AGE-SECRET-KEY-1…` is given a well-formed identity
- **THEN** the 24-word mnemonic for its 32-byte payload is printed and the
  command exits zero

#### Scenario: Bech32 checksum does not match

- **WHEN** the identity's characters are valid Bech32 but its checksum fails
- **THEN** the command exits with status 2 and reports the checksum failure,
  printing no mnemonic

#### Scenario: Input is an age public key

- **WHEN** the input is an `age1…` public key rather than a secret key
- **THEN** the command exits with status 2 and reports that the key is not an
  age secret key

#### Scenario: Payload is not 32 bytes

- **WHEN** the input is a well-formed Bech32 string with the
  `age-secret-key-` human-readable part but a payload of some other length
- **THEN** the command exits with status 2 and reports the unexpected key size

### Requirement: Decoding to an age secret key

With `--format age`, `decode` SHALL verify the mnemonic's BIP-39 checksum as it
already does, then print the recovered key as an age identity string.

An age identity always carries 32 bytes, which BIP-39 encodes as 24 words. The
command SHALL therefore reject any other word count with an error naming the
requirement, rather than printing a key that age would refuse.

#### Scenario: Twenty-four words decode to an identity

- **WHEN** `decode --format age` is given a valid 24-word mnemonic
- **THEN** an `AGE-SECRET-KEY-1…` string is printed and the command exits zero

#### Scenario: Round trip preserves the identity

- **WHEN** an age identity is encoded to a mnemonic and that mnemonic is decoded
  with `--format age`
- **THEN** the printed identity is character-for-character the original

#### Scenario: Mnemonic is the wrong length for an age key

- **WHEN** `decode --format age` is given a valid mnemonic of 12, 15, 18 or 21
  words
- **THEN** the command exits with status 2 and reports that an age key requires
  24 words, printing no key

### Requirement: Age identity letter case

Bech32 forbids mixing letter cases within one string. The tool SHALL accept an
age identity written entirely in upper case or entirely in lower case, and SHALL
reject a mixed-case one.

Output SHALL always be upper case, matching what `age-keygen` writes, so a
decoded key can be pasted into a key file without further editing.

#### Scenario: Lower-case input is accepted

- **WHEN** an identity is given entirely in lower case
- **THEN** it encodes to the same mnemonic as the same identity in upper case

#### Scenario: Mixed-case input is rejected

- **WHEN** an identity mixes upper- and lower-case letters
- **THEN** the command exits with status 2 and reports the mixed case

#### Scenario: Output is upper case

- **WHEN** `decode --format age` prints an identity
- **THEN** every letter in it is upper case

### Requirement: Key errors are reported consistently

A key rejected for any reason — bad hex, bad Bech32, an unsupported size, a
failed checksum — SHALL cause the command to exit with status 2 and write a
diagnostic to standard error, leaving standard output empty.

#### Scenario: Nothing is written to standard output on failure

- **WHEN** any key or mnemonic is rejected
- **THEN** standard output is empty, standard error names the problem, and the
  exit status is 2

### Requirement: Diagnostics never echo key material

A diagnostic is the one part of a failed run a user is likely to paste into a
bug report, so no message the tool writes to standard error SHALL contain the
key, the mnemonic, or any word of one. A rejected word SHALL be identified by
its 1-based position instead. This holds on every exit path, including the
errors the argument parser emits before a subcommand handler runs.

#### Scenario: A rejected word is named by its position

- **WHEN** a mnemonic carries a word outside the BIP-39 English wordlist
- **THEN** standard error names the word's position and does not contain the
  word

#### Scenario: A rejected key is not quoted back

- **WHEN** a key is rejected for bad hex, bad Bech32, mixed case, a failed
  checksum, or an unsupported size
- **THEN** standard error names the cause and does not contain the key

#### Scenario: Argument-parsing failures do not quote the command line

- **WHEN** a key is given where a subcommand or a `--format` value was
  expected, a key is attached to an option that takes no value
  (`--version=KEY`), or a mnemonic is passed unquoted so its words become
  unrecognized arguments
- **THEN** the command exits with status 2 and standard error reports the
  problem without repeating any of the offending arguments
