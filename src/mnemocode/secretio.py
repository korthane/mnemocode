"""Reading secret material from a source and writing it to a sink.

The source grammar is OpenSSL's, as used by its -passin and -passout options,
so the security caveats attached to each form are already documented for users.
"""

import contextlib
import os
import stat
import sys

SOURCE_FORMS = ("pass:", "env:", "file:", "fd:", "stdin")

# A descriptor is a C int. open() hands anything larger to the path lookup
# instead, raising TypeError, which no caller here is prepared to catch.
_MAX_DESCRIPTOR = 2**31 - 1


def _descriptor(number: str, what: str) -> int:
    # isascii guards the isdigit check: "\u00b2".isdigit() is true but int()
    # rejects it, which would surface a raw Python message instead of ours.
    if not (number.isascii() and number.isdigit()):
        raise ValueError(f"an fd: {what} needs a descriptor number")
    value = int(number)
    if value > _MAX_DESCRIPTOR:
        raise ValueError(f"an fd: {what} needs a descriptor number")
    return value


def _read_fd(number: str) -> str:
    fd = _descriptor(number, "source")
    try:
        # closefd=False: the descriptor is the caller's, not ours to close.
        with open(fd, encoding="utf-8", closefd=False) as stream:
            return stream.read()
    except UnicodeDecodeError:
        # The default message quotes an offending byte and its offset, and
        # those bytes are the secret.
        raise ValueError(
            f"cannot read file descriptor {fd}: not UTF-8 text"
        ) from None
    except OSError as exc:
        raise ValueError(
            f"cannot read file descriptor {fd}: {exc.strerror}"
        ) from None


def _read_file(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as stream:
            return stream.read()
    except UnicodeDecodeError:
        raise ValueError(f"cannot read {path}: not UTF-8 text") from None
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc.strerror}") from None


def _read_env(name: str) -> str:
    try:
        return os.environ[name]
    except KeyError:
        raise ValueError(f"environment variable {name} is not set") from None


def read_source(source: str) -> str:
    """Return the raw text a source holds.

    Args:
        source: one of pass:VALUE, env:VAR, file:PATH, fd:N, or stdin.

    Raises:
        ValueError: on an unknown form or an unreadable source. The message
            names the source but never its contents.
    """
    if source == "stdin":
        try:
            return sys.stdin.read()
        except UnicodeDecodeError:
            raise ValueError("cannot read standard input: not UTF-8 text") from None
        except OSError as exc:
            raise ValueError(
                f"cannot read standard input: {exc.strerror}"
            ) from None
    if source.startswith("pass:"):
        return source.removeprefix("pass:")
    if source.startswith("env:"):
        return _read_env(source.removeprefix("env:"))
    if source.startswith("file:"):
        return _read_file(source.removeprefix("file:"))
    if source.startswith("fd:"):
        return _read_fd(source.removeprefix("fd:"))
    # The value may itself be a secret typed into the wrong option, so name the
    # accepted forms without quoting what was given.
    raise ValueError(f"unknown input source; use one of {', '.join(SOURCE_FORMS)}")


def _content_lines(text: str) -> list[str]:
    """Return the lines that carry secret material.

    Comments are stripped so that an age-keygen key file, whose first lines
    describe the key, can be named as a source directly.
    """
    lines = (line.strip() for line in text.splitlines())
    return [line for line in lines if line and not line.startswith("#")]


def one_secret(text: str) -> str:
    """Return the single secret a source holds.

    Raises:
        ValueError: when the source holds none, or more than one. A key file
            may list several identities, and encoding whichever came first
            would be a wrong answer that looks like a right one.
    """
    lines = _content_lines(text)
    if not lines:
        raise ValueError("the input source holds no key")
    if len(lines) > 1:
        raise ValueError(f"the input source holds {len(lines)} keys; expected 1")
    return lines[0]


def secret_words(text: str) -> list[str]:
    """Return the words of a mnemonic held in a source.

    The whole source is consumed and split on any whitespace: reading one line
    would truncate a phrase written across several, and the BIP-39 checksum
    would then report it as a mistyped word.
    """
    words = " ".join(_content_lines(text)).split()
    if not words:
        raise ValueError("the input source holds no mnemonic")
    return words


SINK_FORMS = ("file:", "fd:", "stdout")


def _open_existing_sink(path: str) -> int:
    """Open a path that already exists, refusing anything but a pipe or device.

    Opened without O_TRUNC so that a regular file we are about to refuse is
    still intact when we refuse it, and judged by fstat on the descriptor
    rather than by a second look at the path, so a swap in between cannot
    redirect the secret.

    Symlinks are followed on purpose: `/dev/stdout` is one, so O_NOFOLLOW here
    would refuse the very path the spec requires us to write to.
    """
    try:
        fd = os.open(path, os.O_WRONLY)
    except OSError as exc:
        raise ValueError(f"cannot write {path}: {exc.strerror}") from None
    mode = os.fstat(fd).st_mode
    if not (stat.S_ISFIFO(mode) or stat.S_ISCHR(mode)):
        os.close(fd)
        raise ValueError(f"refusing to overwrite {path}")
    return fd


def _open_file_sink(path: str) -> tuple[int, bool]:
    """Open a sink path, reporting whether this call created it."""
    try:
        # O_EXCL fails on an existing symlink whatever it points at, so a
        # planted link cannot make us *create* a key file elsewhere. It says
        # nothing about the existing-path branch below, which does follow one.
        return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), True
    except FileExistsError:
        return _open_existing_sink(path), False
    except OSError as exc:
        raise ValueError(f"cannot write {path}: {exc.strerror}") from None


def _write_fd(fd: int, text: str, *, closefd: bool) -> None:
    with open(fd, "w", encoding="utf-8", closefd=closefd) as stream:
        stream.write(f"{text}\n")


def write_sink(sink: str, text: str) -> None:
    """Write a result to a sink.

    Args:
        sink: one of file:PATH, fd:N, or stdout.
        text: the result; a newline is appended, as print would.

    Raises:
        ValueError: on an unknown form, an unwritable sink, or an existing
            regular file. The message names the sink but never the text.
    """
    if sink == "stdout":
        try:
            print(text)
            # print only fills the buffer. Without this flush a broken pipe
            # surfaces at interpreter shutdown, long after we reported success.
            sys.stdout.flush()
        except OSError as exc:
            # The buffer still holds the text and the interpreter would retry
            # it while shutting down; send that retry to /dev/null so the
            # failure is reported once, here.
            with contextlib.suppress(OSError, ValueError):
                os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
            raise ValueError(
                f"cannot write standard output: {exc.strerror}"
            ) from None
        return
    if sink.startswith("fd:"):
        fd = _descriptor(sink.removeprefix("fd:"), "sink")
        try:
            _write_fd(fd, text, closefd=False)
        except OSError as exc:
            raise ValueError(
                f"cannot write file descriptor {fd}: {exc.strerror}"
            ) from None
        return
    if sink.startswith("file:"):
        path = sink.removeprefix("file:")
        fd, created = _open_file_sink(path)
        try:
            _write_fd(fd, text, closefd=True)
        except OSError as exc:
            # A part-written key file looks like a whole one, and the caller
            # would find out only on restoring from it. Only a file this call
            # created is ours to remove; a pre-existing pipe or device is not.
            if created:
                with contextlib.suppress(OSError):
                    os.unlink(path)
            raise ValueError(f"cannot write {path}: {exc.strerror}") from None
        return
    raise ValueError(f"unknown output sink; use one of {', '.join(SINK_FORMS)}")


# Overridden in tests to point the prompt at a pty pair. Opening the terminal
# by path rather than relying on getpass keeps the echo handling here, where
# the module's other descriptor work already lives.
_TTY_PATH = "/dev/tty"


def _read_line(fd: int) -> str:
    """Read the entry a user submits at the prompt.

    Enter ends the entry, so this stops at the first newline rather than
    reading to EOF. It loops because a single os.read need not return the
    whole line: an entry ended with Ctrl-D arrives without a newline, and
    taking only the first chunk would silently shorten the secret.
    """
    chunks: list[bytes] = []
    while (chunk := os.read(fd, 4096)) and not chunk.endswith(b"\n"):
        chunks.append(chunk)
    return b"".join([*chunks, chunk]).decode(errors="replace")


def prompt_secret(label: str) -> str:
    """Read a secret from the controlling terminal without echoing it.

    The prompt goes to the terminal rather than to standard output, so a
    redirected result stays free of it.

    Raises:
        ValueError: when no terminal is available, or nothing was entered.
    """
    # Imported here so that a platform without termios still runs every path
    # that does not prompt, rather than failing at import.
    try:
        import termios
    except ImportError:
        raise ValueError(
            f"no terminal is available to read the {label} from; use --input"
        ) from None
    # TCSAFLUSH discards anything typed before the prompt: those keystrokes
    # were echoed, so accepting them as the secret would defeat the point.
    # TCSASOFT is the BSD companion getpass adds where it exists.
    when = termios.TCSAFLUSH | getattr(termios, "TCSASOFT", 0)
    try:
        # O_NOCTTY so prompting never makes this terminal the controlling one.
        # Raw descriptor I/O because a tty is not seekable, which rules out the
        # read/write text wrapper that "r+" would build.
        fd = os.open(_TTY_PATH, os.O_RDWR | os.O_NOCTTY)
    except OSError:
        raise ValueError(
            f"no terminal is available to read the {label} from; use --input"
        ) from None
    try:
        restore = termios.tcgetattr(fd)
    except termios.error:
        os.close(fd)
        raise ValueError(f"{_TTY_PATH} is not a terminal; use --input") from None
    silenced = termios.tcgetattr(fd)
    silenced[3] &= ~termios.ECHO
    try:
        termios.tcsetattr(fd, when, silenced)
        os.write(fd, f"{label}: ".encode())
        entered = _read_line(fd)
    finally:
        termios.tcsetattr(fd, when, restore)
        # The newline the user typed was swallowed along with the echo.
        os.write(fd, b"\n")
        os.close(fd)
    secret = entered.strip()
    if not secret:
        raise ValueError(f"no {label} was entered")
    return secret
