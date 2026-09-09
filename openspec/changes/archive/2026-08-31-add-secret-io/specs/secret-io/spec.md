## Purpose

Defines where secret material enters and leaves `mnemocode` — the sources a key
or mnemonic may be read from, the sinks a result may be written to, and the file
modes and terminal handling that keep the secret from reaching a channel its
owner did not choose. Format decides what the text is; this decides where it
travels.

## ADDED Requirements

### Requirement: Selecting where the secret is read from

`encode` and `decode` SHALL each accept an `--input` option naming the source of
the secret. The supported forms SHALL be `pass:VALUE`, `env:VAR`, `file:PATH`,
`fd:N` and `stdin`.

The existing positional argument SHALL remain supported and unchanged. It names
the same channel as `pass:`, so supplying both a positional and `--input` SHALL
be an error rather than a precedence rule.

A `file:` source SHALL accept a regular file, a character device or a named
pipe, so that `/dev/stdin` and a process substitution work without further
syntax.

#### Scenario: Every source form yields the same result

- **WHEN** the same key is supplied through the positional argument, `pass:`,
  `env:`, `file:`, `fd:` and `stdin` in turn
- **THEN** each run prints the same mnemonic and exits zero

#### Scenario: A positional and --input together are rejected

- **WHEN** a secret is given both as a positional argument and through `--input`
- **THEN** the command exits with status 2 and reports that the two name the
  same input

#### Scenario: An unknown source scheme is rejected

- **WHEN** `--input` is given a value whose scheme is none of the supported forms
- **THEN** the command exits with status 2 and names the accepted forms

### Requirement: Reading a key from a source

When `encode` reads a key, blank lines and lines beginning with `#` SHALL be
ignored, and surrounding whitespace SHALL be stripped, so that an `age-keygen`
key file can be named directly.

Exactly one secret SHALL remain after that filtering. If more than one remains,
the command SHALL exit with status 2 and report how many were found, rather than
choosing one — silently encoding an identity the caller did not mean produces a
wrong answer that looks like a right one.

#### Scenario: An age key file with comment lines is read

- **WHEN** `encode --format age --input file:PATH` names a file whose first
  lines are `#` comments followed by one identity
- **THEN** the identity is encoded and the comment lines are ignored

#### Scenario: A key file holding two identities is rejected

- **WHEN** the named file contains two identities after comments are ignored
- **THEN** the command exits with status 2, reports that more than one key was
  found, and prints no mnemonic

#### Scenario: A trailing newline is not part of the key

- **WHEN** the source ends with a newline
- **THEN** the key is read as though the newline were absent

### Requirement: Reading a mnemonic from a source

When `decode` reads a mnemonic, the whole source SHALL be consumed and split
into words on any whitespace, including line breaks, so that a phrase written
across several lines is read as one mnemonic. Blank lines and `#` comment lines
SHALL be ignored as they are for a key.

Reading only the first line would silently truncate a wrapped phrase into a
shorter one, which the BIP-39 checksum would then reject as though the user had
mistyped it.

#### Scenario: A phrase wrapped across lines is one mnemonic

- **WHEN** `decode --input file:PATH` names a file holding a 24-word phrase
  split across several lines
- **THEN** the phrase is decoded as 24 words and the key is printed

#### Scenario: A source holding no words is rejected

- **WHEN** the named source is empty or holds only comments and blank lines
- **THEN** the command exits with status 2 and reports that no mnemonic was
  supplied

### Requirement: Selecting where the result is written

`encode` and `decode` SHALL each accept an `--output` option naming the sink for
the result. The supported forms SHALL be `file:PATH`, `fd:N` and `stdout`, and
the default SHALL be `stdout`.

With `--output` omitted, the command SHALL behave exactly as it did before this
change.

#### Scenario: The default sink is standard output

- **WHEN** a command is invoked without `--output`
- **THEN** the result is written to standard output, exactly as before this
  change

#### Scenario: A file descriptor receives the result

- **WHEN** `--output fd:N` names an open, writable descriptor
- **THEN** the result is written to that descriptor and standard output is empty

### Requirement: Writing a secret to a file

A `file:` sink SHALL create a new file with mode `0600`, not the mode the
caller's umask would produce, because the file holds key material.

If the path already exists, the outcome SHALL depend on what it is: a regular
file SHALL be refused with status 2 and left byte-for-byte unchanged, while a
named pipe or a character device SHALL be written to. Any other kind of path
SHALL be refused.

A refused regular file SHALL NOT be truncated. The check SHALL apply to the
object actually opened rather than to a separate look at the path, so that a
path swapped between the check and the write cannot redirect the secret.

#### Scenario: A new file is created private

- **WHEN** `--output file:PATH` names a path that does not exist, under a umask
  that would otherwise produce a world-readable file
- **THEN** the file is created with mode `0600` and holds the result

#### Scenario: An existing regular file is refused intact

- **WHEN** `--output file:PATH` names an existing regular file
- **THEN** the command exits with status 2, writes no result, and the file's
  contents and modification time are unchanged

#### Scenario: An existing named pipe is written to

- **WHEN** `--output file:PATH` names an existing FIFO with a reader attached
- **THEN** the result is written to the pipe and the command exits zero

#### Scenario: A character device is written to

- **WHEN** `--output file:/dev/null` is given
- **THEN** the result is written and the command exits zero

#### Scenario: /dev/stdout follows what standard output is attached to

- **WHEN** `--output file:/dev/stdout` is given while standard output is a
  terminal or a pipe
- **THEN** the result appears on standard output and the command exits zero
- **WHEN** the same is given while standard output is redirected to a regular
  file
- **THEN** the write is refused, since the path then names a regular file and
  the guard that protects an existing key file applies

#### Scenario: A directory is refused

- **WHEN** `--output file:PATH` names an existing directory
- **THEN** the command exits with status 2 and writes no result

### Requirement: Prompting on the terminal

When neither a positional argument nor `--input` is given, the command SHALL
prompt for the secret on the controlling terminal with echo disabled, so that a
key or a phrase read off paper never appears on the command line.

The prompt SHALL be written to the terminal rather than to standard output, so
that a redirected result is unpolluted. If no controlling terminal is available,
the command SHALL exit with status 2 rather than wait on a terminal that will
never answer.

#### Scenario: A missing secret is prompted for

- **WHEN** `encode --format age` is invoked with no positional argument and no
  `--input`, with a terminal attached
- **THEN** the secret is read from the terminal and the mnemonic is printed

#### Scenario: The typed secret is not echoed

- **WHEN** a secret is typed at the prompt
- **THEN** the characters are not echoed to the terminal

#### Scenario: The prompt does not reach the result stream

- **WHEN** a command prompts for a secret and its result is redirected
- **THEN** the redirected result holds the result alone, with no prompt text

#### Scenario: No terminal is available

- **WHEN** no secret is supplied and no controlling terminal is available
- **THEN** the command exits with status 2 reporting that it cannot prompt,
  rather than blocking

### Requirement: A secret reaches no channel the caller did not choose

No diagnostic arising from a source or a sink SHALL contain the secret. A
message MAY name the source or sink itself — a path, a descriptor number, an
environment variable name — since those are not secret, and SHALL identify the
problem by that name.

When `--output` names a sink other than standard output, standard output SHALL
remain empty, so that a redirect or a terminal never receives a copy.

#### Scenario: An unreadable source names only the path

- **WHEN** `--input file:PATH` names a file that cannot be read
- **THEN** standard error names the path and the reason, and the command exits
  with status 2

#### Scenario: A malformed secret is not quoted back

- **WHEN** a secret read from any source fails to parse in the selected format
- **THEN** standard error names the cause and contains no part of the secret

#### Scenario: A named sink keeps the result off standard output

- **WHEN** a command succeeds with `--output` naming a file or descriptor
- **THEN** standard output is empty and the result is in the named sink alone
