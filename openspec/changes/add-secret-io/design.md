## Context

See `proposal.md` — Why. The constraints that shape the approach: the package has
no runtime dependencies and targets Python 3.14, `cli.py` already carries a
`_RedactingParser` whose job is to keep argv values out of argparse's own
messages, and `key-formats` already requires that no diagnostic echo key
material. Whatever this change adds inherits that requirement rather than
renegotiating it.

## Goals / Non-Goals

**Goals:**

- One grammar for both directions, so a caller learns the source forms once.
- Every new path is testable without a real terminal or a real world-writable
  directory.
- The parsing layer keeps handling text; descriptors, terminals and file modes
  stay out of it.

**Non-Goals:**

- Changing how a key or a mnemonic is parsed or rendered once read — that is
  `key-formats`, untouched here.
- Making `pass:`, `env:` or the positional argument secure. They are retained
  for compatibility and scripting, labelled, and left as they are.
- Fixing what a `>` redirect does. The shell chose that mode; the design's answer
  is `--output file:`, and the README's answer is a warning.

## Decisions

### Borrow OpenSSL's source grammar verbatim

`pass:` `env:` `file:` `fd:` `stdin` is OpenSSL's `-passin`/`-passout` syntax.
Taking it as-is means the caveats are already written down in a man page users
may know, `file:` is already specified to accept a device or named pipe, and
`fd:` already carries the "not on Windows" caveat we would otherwise have to
discover. It also gives `pass:` an established, honest description — OpenSSL's
own wording is that it "should only be used where security is not important."

**Alternative considered:** separate flags (`--key-file`, `--key-env`,
`--key-stdin`). Rejected — more surface, no extensibility, and a flag per source
multiplies as sinks are added.

### Extend the grammar to the output sink, knowingly diverging

OpenSSL applies the same grammar to `-passin` and `-passout`, but both are
*reads*: `-passout` reads the passphrase used to encrypt output. For the output
data stream OpenSSL uses `-out filename`, a plain path with no scheme —
`openssl genpkey -out fd:3` creates a file literally named `fd:3`.

We diverge deliberately, because unlike OpenSSL's `-out` — usually a certificate
or ciphertext — our output *is* the secret. The precedent we do keep is the file
mode: OpenSSL writes private keys with `0600` regardless of umask, so `0600` here
is the established behavior for key material rather than an invention.

### Decide the sink by opening it, not by looking at it

`O_CREAT|O_EXCL` cannot express the rule the spec states, because it fails on any
existing path — a FIFO included. Checking with `stat` first and opening second is
a time-of-check/time-of-use race. The sequence is therefore:

```
  os.open(path, O_WRONLY|O_CREAT|O_EXCL, 0o600)
      |
      +-- ok ------> new file, 0600, write
      |
      +-- EEXIST --> os.open(path, O_WRONLY)      <-- no O_TRUNC
                         |
                     os.fstat(fd).st_mode
                         |
             +-----------+-----------+-------------+
             |           |           |             |
          S_ISREG    S_ISFIFO     S_ISCHR       other
             |           |           |             |
          refuse       write       write        refuse
```

Two properties this ordering buys, both of which the spec asserts:

- **No `O_TRUNC` on the second open.** Truncating before inspecting would destroy
  the very file we are about to refuse to overwrite.
- **`fstat` on the descriptor, not `stat` on the path.** The decision applies to
  the object actually held, so a path swapped in between cannot redirect the
  secret.

A useful POSIX guarantee falls out of step one: `O_CREAT|O_EXCL` fails with
`EEXIST` when the path is a symbolic link, whatever it points at. So a dangling
symlink planted in a shared directory cannot steer the newly created key file to
an attacker's path.

**Alternative considered:** always refuse an existing path. Rejected — it breaks
`file:/dev/stdout` and named pipes, which are the cases that make `file:` useful
beyond a plain path.

### Different stream rules for a key and a mnemonic

OpenSSL reads only the first line of a `file:` source. That rule does not
transfer, in either direction:

```
  encode input                        decode input
  --------------------------------    --------------------------------
  # created: 2026-08-31T...           abandon amount liar amount
  # public key: age1...               expire adjust cage candy
  AGE-SECRET-KEY-1...                 ... 24 words over several lines

  first line is a COMMENT             first line is a THIRD of the phrase
  -> skip #/blank, take the one       -> read to EOF, split on whitespace
```

So a key is one token after comments are filtered, and a mnemonic is the whole
stream split on whitespace. First-line-only would read a comment in the first
case and silently truncate the phrase in the second, where the BIP-39 checksum
would then blame the user for a mistyped word.

**Alternative considered:** one shared rule plus a `--multiline` flag. Rejected —
the correct rule is a property of the subcommand, which is already known.

### Enforce "positional or --input, not both" after parsing

argparse supports a positional in a mutually exclusive group only when its
`nargs` permits zero, and its generated message for that case is awkward.
Checking it in the subcommand handler and raising `ValueError` reuses `main()`'s
existing `mnemocode: error: …` path, so the message matches every other
key error and the exit status stays 2 without a second convention.

### Keep source and sink resolution in its own module

`cli.py` stays argument parsing plus two handlers. A new module owns the grammar,
the descriptor and terminal handling, and the open sequence above, and hands back
a string on the way in and takes one on the way out. That keeps `os`, `stat`,
`termios` and `getpass` out of the parsing layer and lets the resolution logic be
tested without building a parser.

### Prompt on the controlling terminal, not on stdin

Reading the prompt from `/dev/tty` rather than stdin means a prompt still works
when stdin is a pipe, and the prompt text goes to the terminal rather than into a
redirected result. Echo stays off for a mnemonic as well as a key: the tool's
standing rule is that secret material does not go onto a stream unless it must,
and the BIP-39 checksum already catches the typo that echo would have caught.

## Risks / Trade-offs

- **Opening a FIFO for writing blocks until a reader attaches.** A user pointing
  `--output file:` at a pipe with nothing reading sees a hang, not an error.
  → Document it in the README next to the FIFO example. Not fixed with
  `O_NONBLOCK`: that would turn a legitimate wait into a spurious failure.
- **`fd:` is POSIX-only,** as OpenSSL documents for the same feature.
  → State the limitation rather than emulate it on Windows.
- **A no-echo prompt for 24 words is unforgiving.** A typo is invisible until the
  checksum rejects the phrase, with no indication of which word.
  → Accepted: the existing error already names the offending word by position,
  which is the strongest hint that can be given without echoing the word.
- **`--input` and `--output` take a descriptor, but a confused caller will type
  `--input AGE-SECRET-KEY-1…` sooner or later.** argparse succeeds, so the
  redaction never fires and the secret is in argv and history.
  → Unavoidable in principle. Mitigated by rejecting an unknown scheme rather
  than treating a bare value as a literal secret, so the mistake fails loudly
  instead of silently working.
- **Terminal tests are the flaky kind.** → Drive the prompt through a `pty` pair
  in the tests rather than monkeypatching the prompt away, so the no-echo
  property is actually exercised; keep those tests separable from the rest.

## Migration Plan

Additive. The positional argument keeps working, no default changes, and a run
with neither new option behaves exactly as it does today — which is what the
`key-formats` scenarios assert, so they serve as the regression check. Rollback
is removing the two options; nothing persists between runs.

## Open Questions

- Whether `--input`/`--output` deserve short aliases (`-i`/`-o`). Deferrable: it
  adds no behavior and can be decided once the long forms have been used.
- Whether `env:` and `pass:` should print a warning to stderr when used. Also
  deferrable, and it interacts with nothing else here.
