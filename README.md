# mnemocode

Converts a binary key (128 to 256 bits) to and from a word mnemonic according
to [BIP-39][bip39], using the official English wordlist. The key can be hex or
an [age][age] secret key — the `AGE-SECRET-KEY-1…` identity [sops][sops] uses.

```
$ cat key.txt
0c1e24e5917779d297e14d45f14e1a1a

$ mnemocode encode --input file:key.txt
army van defense carry jealous true garbage claim echo media make crunch

$ mnemocode decode --input file:phrase.txt
0c1e24e5917779d297e14d45f14e1a1a
```

With neither `--input` nor an argument, the key or phrase is read from the
terminal without echoing. The prompt is written to the terminal, not to
standard output, so a redirected or piped result holds the result alone:

```
$ mnemocode encode
key:
army van defense carry jealous true garbage claim echo media make crunch
```

`decode` verifies the BIP-39 checksum and exits non-zero on a mismatch, so a
mistyped word is reported rather than silently decoded to the wrong key. It
reads a phrase written across several lines as one mnemonic, so a phrase
copied out of a text file needs no reflowing. Words may be given in any case,
and as separate arguments or one quoted phrase — though, like a bare key
argument, that puts the phrase on the command line.

That applies to a phrase read from a source, not to one typed at the prompt:
there Enter submits, so a phrase pasted with its line breaks is read only as
far as the first one. Use `--input file:` for a wrapped phrase.

Errors name a bad word or character by its position rather than quoting it,
counting from the start of the key itself, with surrounding whitespace
trimmed. No message echoes the key or the phrase, so the diagnostics are safe
to paste into a bug report. The one thing a message does repeat is the source
you named — a path, a descriptor number, a variable name — so `--input env:`
given the key itself in place of a variable name will show it.

## Where the key comes from

A key passed as a command-line argument is visible to other processes — on
Linux any of them can read `/proc/PID/cmdline` — and your shell records it in
its history, where it outlives the command by months. `--input` names a source
instead, using the same grammar as OpenSSL's `-passin`:

| Source | Reads from | |
|---|---|---|
| `--input file:PATH` | a file, device, or named pipe | safe |
| `--input fd:N` | an open file descriptor | safe |
| `--input stdin` | standard input | safe |
| `--input env:VAR` | an environment variable | inherited by children |
| `--input pass:VALUE` | the command line itself | leaks, as an argument does |
| *(a bare argument)* | the command line itself | leaks |
| *(omitted)* | the terminal, without echo | safe |

`pass:` and a bare key argument are the same leaky channel; both are kept for
compatibility and for scripts where it does not matter. Because they are the
same channel, giving both a bare argument and `--input` is an error — exit 2,
not a rule about which one wins. `env:` is better than either — on Linux
`/proc/PID/environ` is readable only by its owner — but the variable is still
inherited by every child process.

Because `file:` accepts a device or a named pipe, a process substitution needs
no extra syntax:

```sh
mnemocode encode --format age --input file:<(age-keygen)
```

`fd:` is POSIX-only, as it is in OpenSSL. A path is used exactly as given, so
write `$HOME` rather than `~`: no shell expands a tilde in the middle of a
word, and `file:~/keys.txt` would look for a directory actually named `~`.

Standard input is read only when you ask for it, with `--input stdin` or
`--input file:/dev/stdin`. With no `--input` and no argument, mnemocode always
prompts on the terminal, so a piped key is ignored rather than read. Where
there is no terminal at all — a cron job, a CI runner, a container — it exits
with an error naming `--input` instead of waiting for an answer that will
never come.

A source may hold `#` comment lines and blank lines, both of which are ignored,
so an `age-keygen` key file can be named directly. Exactly one key must remain
after that: a `keys.txt` holding several identities is an error rather than a
silent pick, since encoding the wrong one produces a wrong answer that looks
like a right one.

A source holds the key as text in the `--format` encoding, not as raw bytes:
`--input file:key.bin` pointed at 32 binary bytes is rejected as not UTF-8
rather than encoded.

## Where the result goes

`--output` names a sink: `file:PATH`, `fd:N`, or `stdout` (the default).

```sh
mnemocode decode --format age --input file:phrase.txt --output file:keys.txt
```

**A shell redirect creates its file with your umask** — typically `0644`, which
is world-readable — so `mnemocode decode ... > keys.txt` leaves an age identity
readable by every user on the machine. `--output file:` creates the file with
mode `0600` instead, and refuses to overwrite an existing regular file rather
than destroying a key you still have.

If the write fails part-way — a full disk, a reader that went away — the file
this run created is removed rather than left holding half a mnemonic, which
would look like a whole one until the day you restored from it. A pipe or
device that already existed is written to but never removed.

Writing to a named pipe is allowed, and blocks until a reader opens the other
end, as writing to a pipe always does. `file:/dev/stdout` works while standard
output is a terminal or a pipe; if standard output is redirected to a regular
file, that path *is* a regular file, and the same refusal applies.

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

An age secret key is always 256 bits, so it is always 24 words.

## age and sops keys

Pass `--format age` to read or write an age identity instead of hex:

```
$ mnemocode encode --format age --input file:"$HOME/.config/sops/age/keys.txt"
abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch range attend journey unaware

$ mnemocode decode --format age --input file:phrase.txt
AGE-SECRET-KEY-1QQQSYQCYQ5RQWZQFPG9SCRGWPUGPZYSNZS23V9CCRYDPK8QARC0SWRYDWG
```

The key file `age-keygen` writes starts with two comment lines; they are
ignored, so it can be named as it stands.

(That is a throwaway demo key, built from the bytes `00 01 02 … 1f`.)

The identity may be given in upper or lower case, but not a mix of the two —
Bech32 forbids it, and a mixed-case string usually means a transcription error.
`decode` always prints upper case, matching what `age-keygen` writes, so the
output can go straight into a key file.

The Bech32 checksum is verified on the way in, just as the BIP-39 checksum is,
so a mistyped key is reported rather than silently converted to the wrong
mnemonic. `decode --format age` likewise refuses a mnemonic that is not 24
words, since a shorter phrase carries fewer than the 32 bytes an age identity
needs.

Note that a mnemonic does not record which format it came from. A phrase made
from an age key decodes as hex just as readily, so `decode` needs to be told
`--format age`; it will not guess.

## Running it

Local checkout:

```sh
uv run mnemocode encode --input file:key.txt
```

From GitHub, without cloning:

```sh
uvx --from git+https://github.com/korthane/mnemocode mnemocode encode --input file:key.txt
uv run https://raw.githubusercontent.com/korthane/mnemocode/main/main.py encode --input file:key.txt
```

Both install the package into a temporary environment, so the bundled
wordlist comes with them. The second form works because `main.py` is a
[PEP 723][pep723] script whose only dependency is this package.

Install it permanently:

```sh
uv tool install git+https://github.com/korthane/mnemocode
```

## Development

No runtime dependencies; the tool is pure standard library. `bech32.py` is a
vendored implementation of [BIP-173][bip173], kept in-tree for that reason;
`tests/test_bech32.py` runs it against the spec's own test vectors.

```sh
uv sync          # create the venv, install dev dependencies
uv run pytest    # run the tests
```

`src/mnemocode/english.txt` is a verbatim copy of [the official BIP-39 English
wordlist][wordlist]. `tests/test_wordlist.py` pins its SHA-256, since an edit
there would silently change every mnemonic the tool produces.

[age]: https://age-encryption.org
[bip39]: https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039.mediawiki
[bip173]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
[wordlist]: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
[pep723]: https://peps.python.org/pep-0723/
[sops]: https://github.com/getsops/sops
