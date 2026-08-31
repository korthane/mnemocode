## 1. Source grammar

- [x] 1.1 Add the secret-I/O module with a source parser for `pass:`, `env:`,
      `file:`, `fd:` and `stdin`, and verify unit tests cover each form plus an
      unknown scheme, which must raise rather than be treated as a literal
      secret.
- [x] 1.2 Implement reading from each source to a raw string, and verify a test
      supplies the same key through all five forms and gets identical bytes.
- [x] 1.3 Read an `fd:` source without taking ownership of the caller's
      descriptor, and verify a test reads from a descriptor it opened and finds
      it still open afterwards.

## 2. Stream rules

- [x] 2.1 Filter blank lines and `#` comment lines, and strip surrounding
      whitespace, and verify a test reads an `age-keygen` key file whose first
      two lines are comments.
- [x] 2.2 Reduce a key source to exactly one secret, erroring with a count when
      more than one remains, and verify a test on a two-identity `keys.txt`
      exits 2, names the count, and prints no mnemonic.
- [x] 2.3 Read a mnemonic source to EOF and split on any whitespace, and verify
      a test decodes a 24-word phrase written across four lines.
- [x] 2.4 Reject a source that yields no words, and verify a test on an empty
      file and on a comments-only file both exit 2.

## 3. Sinks

- [x] 3.1 Add the sink parser for `file:`, `fd:` and `stdout` with `stdout` as
      the default, and verify a test asserts an omitted `--output` writes to
      standard output exactly as today.
- [x] 3.2 Implement the create path as `O_WRONLY|O_CREAT|O_EXCL` with mode
      `0600`, and verify a test run under umask `022` produces a file whose mode
      is `0600`.
- [x] 3.3 Implement the `EEXIST` branch as a second open without `O_TRUNC`
      followed by `fstat` on the descriptor, refusing a regular file and any
      non-pipe non-device path, and verify a test finds an existing regular
      file's contents and mtime unchanged after a refused run.
- [x] 3.4 Allow an existing FIFO and character device, and verify tests write to
      a named pipe with a reader attached and to `file:/dev/stdout`.
- [x] 3.5 Refuse an existing directory, and verify a test exits 2 with no result
      written.

## 4. Terminal prompt

- [x] 4.1 Prompt on the controlling terminal with echo disabled when neither a
      positional nor `--input` is given, writing the prompt to the terminal
      rather than standard output, and verify a `pty`-driven test reads a key and
      prints the mnemonic.
- [x] 4.2 Verify through the same `pty` harness that the typed secret is not
      echoed and that a redirected result contains the result alone with no
      prompt text.
- [x] 4.3 Exit 2 with a message when no controlling terminal is available rather
      than blocking, and verify a test with the terminal closed fails fast.

## 5. CLI wiring

- [x] 5.1 Add `--input` and `--output` to both subcommands and make the
      positional optional, and verify existing tests still pass unchanged, since
      they exercise the default path.
- [x] 5.2 Reject a positional and `--input` given together, checked in the
      handler so the message uses the existing `mnemocode: error: …` form, and
      verify a test asserts exit 2 and that wording.
- [x] 5.3 Route the resolved secret into the existing handlers and the result
      into the selected sink, leaving `parse_hex_key`, `parse_age_secret_key` and
      the BIP-39 code untouched, and verify `git diff` shows no change to those
      functions.

## 6. Diagnostics carry no secret

- [x] 6.1 Ensure source and sink errors name only the path, descriptor number or
      variable name, and verify tests on an unreadable file, a bad descriptor and
      an unset variable each name the source and contain no secret.
- [x] 6.2 Extend the existing no-leak property test to cover every new source and
      sink, and verify no fragment of a real key reaches standard output or
      standard error on any failing path.
- [x] 6.3 Verify a successful run with `--output` naming a file or descriptor
      leaves standard output empty.

## 7. Documentation

- [x] 7.1 Rewrite the README examples so no real-looking secret appears on a
      command line, and verify every example in the file uses a source other than
      the positional.
- [x] 7.2 Document the source and sink grammar, that `pass:`/`env:`/the
      positional are the insecure forms and why, that `fd:` is POSIX-only, and
      that writing to a FIFO blocks until a reader attaches.
- [x] 7.3 Add the note that a `>` redirect creates its file with the shell's
      umask — typically world-readable — with `--output file:` as the
      alternative, and verify the note sits next to the `decode` example that
      would otherwise teach the redirect.

## 8. Acceptance

- [x] 8.1 Verify every scenario in `specs/secret-io/spec.md` has a corresponding
      test, and that `uv run pytest` passes with no skips.
