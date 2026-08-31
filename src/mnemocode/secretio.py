"""Reading secret material from a source and writing it to a sink.

The source grammar is OpenSSL's, as used by its -passin and -passout options,
so the security caveats attached to each form are already documented for users.
"""

import os
import stat
import termios
import sys

SOURCE_FORMS = ("pass:", "env:", "file:", "fd:", "stdin")


def _read_fd(number: str) -> str:
    if not number.isdigit():
        raise ValueError("an fd: source needs a descriptor number")
    fd = int(number)
    try:
        # closefd=False: the descriptor is the caller's, not ours to close.
        with open(fd, encoding="utf-8", closefd=False) as stream:
            return stream.read()
    except OSError as exc:
        raise ValueError(
            f"cannot read file descriptor {fd}: {exc.strerror}"
        ) from None


def _read_file(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as stream:
            return stream.read()
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
        return sys.stdin.read()
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

_WRITABLE_EXISTING = (stat.S_ISFIFO, stat.S_ISCHR)


def _open_existing_sink(path: str) -> int:
    """Open a path that already exists, refusing anything but a pipe or device.

    Opened without O_TRUNC so that a regular file we are about to refuse is
    still intact when we refuse it, and judged by fstat on the descriptor
    rather than by a second look at the path, so a swap in between cannot
    redirect the secret.
    """
    try:
        fd = os.open(path, os.O_WRONLY)
    except OSError as exc:
        raise ValueError(f"cannot write {path}: {exc.strerror}") from None
    mode = os.fstat(fd).st_mode
    if not any(is_writable(mode) for is_writable in _WRITABLE_EXISTING):
        os.close(fd)
        raise ValueError(f"refusing to overwrite {path}")
    return fd


def _open_file_sink(path: str) -> int:
    try:
        # O_EXCL also fails on a symlink, whatever it points at, so a planted
        # link cannot steer a new key file elsewhere.
        return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return _open_existing_sink(path)
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
        print(text)
        return
    if sink.startswith("fd:"):
        number = sink.removeprefix("fd:")
        if not number.isdigit():
            raise ValueError("an fd: sink needs a descriptor number")
        try:
            _write_fd(int(number), text, closefd=False)
        except OSError as exc:
            raise ValueError(
                f"cannot write file descriptor {number}: {exc.strerror}"
            ) from None
        return
    if sink.startswith("file:"):
        path = sink.removeprefix("file:")
        fd = _open_file_sink(path)
        try:
            _write_fd(fd, text, closefd=True)
        except OSError as exc:
            raise ValueError(f"cannot write {path}: {exc.strerror}") from None
        return
    raise ValueError(f"unknown output sink; use one of {', '.join(SINK_FORMS)}")


# Overridden in tests to point the prompt at a pty pair. Opening the terminal
# by path rather than relying on getpass keeps the echo handling here, where
# the module's other descriptor work already lives.
_TTY_PATH = "/dev/tty"

# TCSAFLUSH, as getpass uses, discards anything typed before the prompt: those
# keystrokes were echoed, so accepting them as the secret would defeat the
# point. TCSASOFT is the BSD companion getpass adds where it exists.
_TCSETATTR = termios.TCSAFLUSH | getattr(termios, "TCSASOFT", 0)


def prompt_secret(label: str) -> str:
    """Read a secret from the controlling terminal without echoing it.

    The prompt goes to the terminal rather than to standard output, so a
    redirected result stays free of it.

    Raises:
        ValueError: when no terminal is available, or nothing was entered.
    """
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
        termios.tcsetattr(fd, _TCSETATTR, silenced)
        os.write(fd, f"{label}: ".encode())
        entered = os.read(fd, 4096).decode()
    finally:
        termios.tcsetattr(fd, _TCSETATTR, restore)
        # The newline the user typed was swallowed along with the echo.
        os.write(fd, b"\n")
        os.close(fd)
    secret = entered.strip()
    if not secret:
        raise ValueError(f"no {label} was entered")
    return secret
