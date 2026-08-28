## 1. Bech32 codec

- [x] 1.1 Write `tests/test_bech32.py` from the BIP-173 test vectors — the valid
      strings, and the invalid ones (bad checksum, mixed case, non-zero padding
      bits, out-of-range length, invalid characters, missing separator). Verify
      the file collects and every test fails for want of the module.
- [x] 1.2 Implement `src/mnemocode/bech32.py` with `bech32_encode(hrp, payload)`
      and `bech32_decode(text) -> (hrp, payload)`, computing the checksum over
      the lower-cased human-readable part per BIP-173. Keep it free of any age
      knowledge. Verify `uv run pytest tests/test_bech32.py` passes.
- [x] 1.3 Add a round-trip property test over every payload length that fits
      (1–51 bytes for a one-character HRP; Bech32's 90-character limit makes 64
      unreachable, so the original range was impossible) and verify it passes,
      covering the 8-to-5-bit conversion padding.

## 2. Age identity module

- [x] 2.1 Choose a synthetic deterministic 32-byte fixture (not `age-keygen`
      output — see design.md, Risks) and confirm the expected identity string by
      round-tripping it through the real `age` tool locally. Record the string in
      the test file; do not commit any generated key file.
- [x] 2.2 Write `tests/test_agekey.py`: round trip for the fixture, lower-case
      input accepted, mixed-case rejected, `age1…` public key rejected as not a
      secret key, wrong payload length rejected, bad checksum rejected. Verify
      the tests fail for want of the module.
- [x] 2.3 Implement `src/mnemocode/agekey.py` with `parse_age_secret_key(text)`
      and `format_age_secret_key(key)`, owning the `age-secret-key-`
      human-readable part, the 32-byte rule, and upper-case output. Raise
      `ValueError` with a message naming the specific problem in each case.
      Verify `uv run pytest tests/test_agekey.py` passes.

## 3. CLI wiring

- [x] 3.1 Extend `tests/test_cli.py` for the new surface: `--format age` encode
      and decode round trip, the default and explicit `--format hex` producing
      identical output, an unknown `--format` value rejected, `decode --format
      age` on a 12-word mnemonic erroring with a message naming the 24-word
      requirement, and each failure exiting 2 with empty stdout. Verify they fail
      first.
- [x] 3.2 Add `--format` with `choices=("hex", "age")` and `default="hex"` to
      both subcommands in `build_parser()`. Verify `mnemocode encode --help`
      shows it.
- [x] 3.3 Move key validation out of the argparse `type=` hook: take the key as a
      plain string and dispatch on `args.format` inside `run_encode()`, raising
      `ValueError` for the existing handler in `main()`. Verify the pre-existing
      hex tests still pass unchanged apart from the expected message wording.
- [x] 3.4 Dispatch the output format in `run_decode()`, rejecting a non-24-word
      mnemonic before rendering when the format is `age`. Verify the full
      `uv run pytest` suite passes.

## 4. Documentation

- [x] 4.1 Add an age/sops section to `README.md` showing both directions with a
      real command, and note in the key-size table that an age identity is always
      256 bits and 24 words. Verify the commands shown produce the output shown.
- [x] 4.2 Confirm the README's zero-dependency claim still holds: verify
      `pyproject.toml` still has `dependencies = []` and that the PEP 723 shim
      works. Note: `main.py` pins its dependency to GitHub `main`, so it cannot
      exercise unpushed code — verified instead with `uvx --from .` (installs 1
      package, no dependencies) and by running the shim against a local path.

## 5. Verification

- [x] 5.1 Round-trip a freshly generated `age-keygen` key through
      `encode --format age` and `decode --format age` and verify the result is
      character-for-character identical to the original. Delete the generated key
      afterwards; do not commit it.
- [x] 5.2 Verify every scenario in `specs/key-formats/spec.md` has a
      corresponding test, and that `uv run pytest` passes with no skips.

## 6. Diagnostics carry no key material

- [x] 6.1 Report a mnemonic word rejected by `bip39.py` by its 1-based position
      rather than echoing it, and assert in `tests/test_bip39.py` and
      `tests/test_cli.py` that the word never reaches stderr.
- [x] 6.2 Keep key material out of argparse's own diagnostics, which are
      emitted before `main()` can catch anything: redact the argv value from
      `invalid choice`, `unrecognized arguments`, `ignored explicit
      argument` and `ambiguous option`. Verify a key given as a subcommand, as
      a `--format` value, as `--flag=KEY`, as `--=KEY`, and an unquoted
      mnemonic all exit 2 without echoing.
- [x] 6.3 Pin the redaction with tests that fail rather than leak if argparse
      rewords a message, and that assert the substituted text still names the
      problem.
