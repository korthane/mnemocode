## Why

Both subcommands take their secret as a command-line argument, and that is the
one place a secret should never be. On Linux `/proc/PID/cmdline` is
world-readable; on any platform the shell records the command in history, where
it outlives the process by months. The tool exists to move key material between
two forms safely, and today the only way to feed it that material leaks it. The
README teaches the leaky form in every example.

## What Changes

- `encode` and `decode` gain `--input <source>`, naming where the secret is read
  from: `pass:VALUE`, `env:VAR`, `file:PATH`, `fd:N`, or `stdin`. The grammar is
  OpenSSL's `-passin`/`-passout` syntax, chosen because it is established, its
  security caveats are already documented for users, and `file:` accepting a
  device or named pipe makes process substitution work without extra syntax.
- Both gain `--output <sink>`: `file:PATH`, `fd:N`, or `stdout` (the default).
  `file:` creates a new file with mode `0600` rather than letting the umask
  decide, matching what OpenSSL does for private-key output. It refuses to
  overwrite an existing regular file, but writes to an existing FIFO or
  character device, so `file:/dev/stdout` and a named pipe both work.
- Omitting the secret entirely prompts for it on the controlling terminal with
  echo off, as OpenSSL does when no passphrase source is given. This makes
  `mnemocode decode --format age` a safe way to type a phrase off paper.
- The existing positional argument stays supported and unchanged. It is the same
  leaky channel as `pass:`, and both are documented as such rather than removed.
- Giving both a positional and `--input` is an error; the two name the same
  thing.
- **Docs**: the README stops using real-looking secrets on the command line in
  its examples, and gains a note that a `>` redirect creates the file with the
  shell's umask — typically world-readable — with `--output file:` as the
  alternative that does not.

## Capabilities

### New Capabilities

- `secret-io`: where secret material enters and leaves the tool — the source and
  sink grammar, the stream rules for reading a key versus a mnemonic, the
  terminal prompt, and the file modes and overwrite rules that apply when a
  secret is written to disk.

### Modified Capabilities

None. `key-formats` governs what the text of a key *is* — its encoding, letter
case, and checksums — while this change governs where that text travels. Its
existing scenarios describe invocations with no `--input` or `--output`, and
they remain true unchanged on that default path. Its "Diagnostics never echo key
material" requirement is already written to hold on every exit path, so it
governs the new sources without rewording.

## Impact

- `src/mnemocode/cli.py`: two new options per subcommand, the positional becomes
  optional, and the resolved secret reaches the existing handlers as a string, so
  `parse_hex_key`, `parse_age_secret_key` and the BIP-39 code are untouched.
- A new module for source and sink resolution, keeping the file-descriptor and
  terminal handling out of the argument-parsing layer.
- `tests/`: new coverage per source and sink, including that no source puts a
  secret on a stream a third party can read, extending the existing no-leak
  property tests.
- No new dependencies; `os`, `stat` and `termios` are standard library.
- Not addressed: a `>` redirect's file mode is the shell's to choose, so it is
  documented rather than fixed.
