import errno
import io
import os
import pathlib
import stat
import subprocess
import sys
import termios
import threading

import pytest

from mnemocode import secretio
from mnemocode.secretio import (
    SOURCE_FORMS,
    check_sink,
    one_secret,
    prompt_secret,
    read_source,
    secret_words,
    write_sink,
)

KEY = "0c1e24e5917779d297e14d45f14e1a1a"


def test_pass_source_returns_the_literal_value():
    assert read_source(f"pass:{KEY}") == KEY


def test_env_source_reads_the_named_variable(monkeypatch):
    monkeypatch.setenv("MNEMOCODE_TEST_KEY", KEY)
    assert read_source("env:MNEMOCODE_TEST_KEY") == KEY


def test_env_source_reports_an_unset_variable_by_name(monkeypatch):
    monkeypatch.delenv("MNEMOCODE_TEST_KEY", raising=False)
    with pytest.raises(ValueError, match="MNEMOCODE_TEST_KEY"):
        read_source("env:MNEMOCODE_TEST_KEY")


def test_file_source_reads_the_file(tmp_path):
    path = tmp_path / "key.txt"
    path.write_text(KEY)
    assert read_source(f"file:{path}") == KEY


def test_file_source_reports_a_missing_file_by_path(tmp_path):
    missing = tmp_path / "nope.txt"
    with pytest.raises(ValueError, match=str(missing)):
        read_source(f"file:{missing}")


def test_fd_source_reads_the_descriptor(tmp_path):
    path = tmp_path / "key.txt"
    path.write_text(KEY)
    fd = os.open(path, os.O_RDONLY)
    try:
        assert read_source(f"fd:{fd}") == KEY
    finally:
        os.close(fd)


def test_fd_source_leaves_the_caller_descriptor_open(tmp_path):
    path = tmp_path / "key.txt"
    path.write_text(KEY)
    fd = os.open(path, os.O_RDONLY)
    try:
        read_source(f"fd:{fd}")
        # Raises OSError(EBADF) if read_source closed a descriptor it borrowed.
        os.lseek(fd, 0, os.SEEK_SET)
    finally:
        os.close(fd)


def test_stdin_source_reads_standard_input(monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO(KEY))
    assert read_source("stdin") == KEY


@pytest.mark.parametrize("bad", ["http:x", KEY, "", "file", "fd:eleven"])
def test_an_unknown_source_is_rejected(bad):
    with pytest.raises(ValueError):
        read_source(bad)


def test_the_rejection_names_every_accepted_form():
    with pytest.raises(ValueError) as exc:
        read_source("http://example.com")
    assert all(form in str(exc.value) for form in SOURCE_FORMS)


def test_an_unknown_source_does_not_echo_its_value():
    with pytest.raises(ValueError) as exc:
        read_source(f"bogus:{KEY}")
    assert KEY not in str(exc.value)


AGE_KEY = "AGE-SECRET-KEY-1QQQSYQCYQ5RQWZQFPG9SCRGWPUGPZYSNZS23V9CCRYDPK8QARC0SWRYDWG"
AGE_KEYFILE = (
    "# created: 2026-08-31T00:00:00Z\n"
    "# public key: age1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s\n"
    f"{AGE_KEY}\n"
)
WORDS_24 = ["abandon"] * 23 + ["art"]
WRAPPED_24 = "\n".join(" ".join(WORDS_24[i : i + 6]) for i in range(0, 24, 6))


def test_one_secret_ignores_comment_lines():
    assert one_secret(AGE_KEYFILE) == AGE_KEY


def test_one_secret_strips_surrounding_whitespace():
    assert one_secret(f"  {KEY}\n") == KEY


def test_one_secret_rejects_a_file_holding_two_keys():
    with pytest.raises(ValueError, match="2"):
        one_secret(f"# comment\n{KEY}\n{KEY}\n")


def test_one_secret_rejection_does_not_echo_the_keys():
    with pytest.raises(ValueError) as exc:
        one_secret(f"{KEY}\n{KEY}\n")
    assert KEY not in str(exc.value)


@pytest.mark.parametrize("empty", ["", "\n\n", "# only a comment\n"])
def test_one_secret_rejects_a_source_holding_no_key(empty):
    with pytest.raises(ValueError):
        one_secret(empty)


def test_secret_words_reads_a_phrase_wrapped_across_lines():
    assert secret_words(WRAPPED_24) == WORDS_24


def test_secret_words_reads_a_single_line_phrase():
    assert secret_words(" ".join(WORDS_24)) == WORDS_24


def test_secret_words_ignores_comment_lines():
    assert secret_words(f"# a note\n{WRAPPED_24}\n") == WORDS_24


@pytest.mark.parametrize("empty", ["", "\n\n", "# only a comment\n"])
def test_secret_words_rejects_a_source_holding_no_words(empty):
    with pytest.raises(ValueError):
        secret_words(empty)


def test_secret_words_rejection_does_not_echo_the_phrase():
    with pytest.raises(ValueError) as exc:
        secret_words("# nothing here\n")
    assert "nothing here" not in str(exc.value)


def test_stdout_sink_writes_to_standard_output(capsys):
    write_sink("stdout", "result")
    assert capsys.readouterr().out == "result\n"


def test_fd_sink_writes_to_the_descriptor(tmp_path):
    path = tmp_path / "out.txt"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        write_sink(f"fd:{fd}", "result")
    finally:
        os.close(fd)
    assert path.read_text() == "result\n"


def test_fd_sink_leaves_the_caller_descriptor_open(tmp_path):
    path = tmp_path / "out.txt"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        write_sink(f"fd:{fd}", "result")
        os.lseek(fd, 0, os.SEEK_SET)
    finally:
        os.close(fd)


def test_file_sink_creates_a_private_file(tmp_path):
    path = tmp_path / "key.txt"
    previous = os.umask(0o022)
    try:
        write_sink(f"file:{path}", "result")
    finally:
        os.umask(previous)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_text() == "result\n"


def test_file_sink_refuses_an_existing_regular_file(tmp_path):
    path = tmp_path / "key.txt"
    path.write_text("original")
    before = path.stat().st_mtime_ns
    with pytest.raises(ValueError, match=str(path)):
        write_sink(f"file:{path}", "result")
    assert path.read_text() == "original"
    assert path.stat().st_mtime_ns == before


def test_file_sink_refusal_does_not_echo_the_secret(tmp_path):
    path = tmp_path / "key.txt"
    path.write_text("original")
    with pytest.raises(ValueError) as exc:
        write_sink(f"file:{path}", KEY)
    assert KEY not in str(exc.value)


def test_file_sink_refuses_a_directory(tmp_path):
    with pytest.raises(ValueError, match=str(tmp_path)):
        write_sink(f"file:{tmp_path}", "result")


def test_file_sink_writes_to_a_named_pipe(tmp_path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    received: list[str] = []

    def read_pipe() -> None:
        with open(fifo, encoding="utf-8") as stream:
            received.append(stream.read())

    # daemon so a regression that never writes leaves a failed test rather
    # than a reader blocked in open() that hangs the whole run at shutdown.
    reader = threading.Thread(target=read_pipe, daemon=True)
    reader.start()
    write_sink(f"file:{fifo}", "result")
    reader.join(timeout=5)
    assert received == ["result\n"]


def test_file_sink_writes_to_a_character_device():
    # /dev/null is a character device on every platform this runs on, so it
    # exercises the S_ISCHR branch without depending on how stdout is attached.
    write_sink("file:/dev/null", "result")


def test_prompt_reads_the_secret_from_the_terminal(prompt_terminal):
    prompt_terminal.answer(KEY)
    assert prompt_secret("key") == KEY


def test_prompt_writes_its_label_to_the_terminal(prompt_terminal):
    thread = prompt_terminal.answer(KEY)
    prompt_secret("key")
    thread.join(timeout=5)
    assert "key" in prompt_terminal.prompts[0]


def test_prompt_does_not_echo_the_typed_secret(prompt_terminal):
    thread = prompt_terminal.answer(KEY)
    prompt_secret("key")
    thread.join(timeout=5)
    assert KEY not in prompt_terminal.drain()


def test_prompt_restores_the_terminal_echo_setting(prompt_terminal):
    watcher = os.open(secretio._TTY_PATH, os.O_RDWR | os.O_NOCTTY)
    try:
        before = termios.tcgetattr(watcher)[3]
        prompt_terminal.answer(KEY)
        prompt_secret("key")
        assert termios.tcgetattr(watcher)[3] == before
    finally:
        os.close(watcher)


def test_prompt_does_not_reach_standard_output(prompt_terminal, capsys):
    prompt_terminal.answer(KEY)
    prompt_secret("key")
    assert capsys.readouterr().out == ""


def test_prompt_accepts_an_entry_ended_with_eof(prompt_terminal):
    """Ctrl-D submits the line without a newline, so the read must not stop
    at the first chunk and discard it."""
    prompt_terminal.answer_with_eof(KEY)
    assert prompt_secret("key") == KEY


def test_prompt_without_a_terminal_is_an_error(monkeypatch, tmp_path):
    monkeypatch.setattr(secretio, "_TTY_PATH", str(tmp_path / "no-such-tty"))
    with pytest.raises(ValueError, match="terminal"):
        prompt_secret("key")


def test_prompt_on_something_that_is_not_a_terminal_is_an_error(
    monkeypatch, tmp_path
):
    plain = tmp_path / "plain.txt"
    plain.write_text("not a tty")
    monkeypatch.setattr(secretio, "_TTY_PATH", str(plain))
    with pytest.raises(ValueError, match="not a terminal"):
        prompt_secret("key")


def test_prompt_rejects_an_empty_entry(prompt_terminal):
    prompt_terminal.answer("")
    with pytest.raises(ValueError):
        prompt_secret("key")


def test_file_sink_refuses_a_symlink_to_a_regular_file(tmp_path):
    """O_EXCL stops a planted link creating a key file elsewhere, but the
    existing-path branch follows one; what protects the target here is the
    fstat refusal, not the link check."""
    target = tmp_path / "target.txt"
    target.write_text("original")
    link = tmp_path / "key.txt"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="refusing to overwrite"):
        write_sink(f"file:{link}", "result")
    assert target.read_text() == "original"


def test_file_sink_refuses_a_dangling_symlink(tmp_path):
    link = tmp_path / "key.txt"
    link.symlink_to(tmp_path / "absent.txt")
    with pytest.raises(ValueError, match=str(link)):
        write_sink(f"file:{link}", "result")


def test_file_sink_follows_a_symlink_to_a_character_device(tmp_path):
    # Following is deliberate: /dev/stdout is itself a symlink, so refusing
    # links here would refuse the path the spec requires us to write to.
    link = tmp_path / "out"
    link.symlink_to("/dev/null")
    write_sink(f"file:{link}", "result")


def test_prompt_reads_an_entry_that_arrives_in_two_reads(prompt_terminal):
    """Pinned separately from the Ctrl-D case: there the whole entry still
    fits one os.read, so a reader that took only the first chunk would pass
    that test while silently shortening a longer secret."""
    prompt_terminal.answer_in_two_reads(KEY[:16], KEY[16:])
    assert prompt_secret("key") == KEY


def test_prompt_replaces_bytes_that_are_not_utf8(prompt_terminal):
    """Strict decoding would raise UnicodeDecodeError, a ValueError that main
    prints — quoting a byte of the secret and its offset."""
    prompt_terminal.answer_bytes(b"\xff\xfe deadbeef\n")
    assert prompt_secret("key").endswith("deadbeef")


def test_prompt_without_termios_is_an_error(monkeypatch):
    # A platform with no termios must still reach our message rather than an
    # ImportError traceback.
    monkeypatch.setitem(sys.modules, "termios", None)
    with pytest.raises(ValueError, match="--input"):
        prompt_secret("key")


def test_an_fd_source_too_large_for_a_descriptor_is_an_error():
    # open() hands an int this large to the path lookup, raising TypeError,
    # which no caller catches.
    with pytest.raises(ValueError, match="descriptor number"):
        read_source(f"fd:{2**31}")


def test_an_fd_sink_too_large_for_a_descriptor_is_an_error():
    with pytest.raises(ValueError, match="descriptor number"):
        write_sink(f"fd:{2**31}", "result")


def test_a_non_ascii_digit_is_not_a_descriptor():
    # "²".isdigit() is true, so isdigit alone would let int() raise and quote
    # the value back.
    with pytest.raises(ValueError, match="an fd: source needs a descriptor number"):
        read_source("fd:²")


def test_an_fd_source_of_non_utf8_bytes_names_the_descriptor(tmp_path):
    path = tmp_path / "binary"
    path.write_bytes(b"\xff\xfe\x00")
    fd = os.open(path, os.O_RDONLY)
    try:
        with pytest.raises(ValueError, match="not UTF-8 text") as caught:
            read_source(f"fd:{fd}")
    finally:
        os.close(fd)
    assert "�" not in str(caught.value)


def test_a_stdin_source_of_non_utf8_bytes_names_the_source(monkeypatch):
    monkeypatch.setattr(
        sys, "stdin", io.TextIOWrapper(io.BytesIO(b"\xff\xfe\x00"), encoding="utf-8")
    )
    with pytest.raises(ValueError, match="cannot read standard input: not UTF-8 text"):
        read_source("stdin")


def test_an_unreadable_stdin_names_the_source(monkeypatch):
    class Unreadable:
        def read(self):
            raise OSError(errno.EBADF, os.strerror(errno.EBADF))

    monkeypatch.setattr(sys, "stdin", Unreadable())
    with pytest.raises(ValueError, match="cannot read standard input: Bad file"):
        read_source("stdin")


def _failing_write(written: bytes, error: int):
    """A _write_fd that lands part of the text, then fails as ENOSPC would."""

    def failing(fd: int, text: str, *, closefd: bool) -> None:
        os.write(fd, written)
        os.close(fd)
        raise OSError(error, os.strerror(error))

    return failing


def test_a_failed_file_sink_write_leaves_no_partial_key_file(tmp_path, monkeypatch):
    """A part-written mnemonic looks like a whole one, and the caller would
    find out only on restoring from it."""
    path = tmp_path / "keys.txt"
    monkeypatch.setattr(
        secretio, "_write_fd", _failing_write(b"word word ", errno.ENOSPC)
    )
    with pytest.raises(ValueError, match=str(path)):
        write_sink(f"file:{path}", "result")
    assert not path.exists()


def test_a_failed_write_to_an_existing_pipe_leaves_the_pipe(tmp_path, monkeypatch):
    """Only a file this call created is ours to remove."""
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
    monkeypatch.setattr(secretio, "_write_fd", _failing_write(b"", errno.EPIPE))
    try:
        with pytest.raises(ValueError, match=str(fifo)):
            write_sink(f"file:{fifo}", "result")
    finally:
        os.close(reader)
    assert stat.S_ISFIFO(os.stat(fifo).st_mode)


def test_a_broken_stdout_is_reported_rather_than_reported_as_success(monkeypatch):
    """The other two sinks fail loudly; stdout buffered the failure until
    after main had already returned zero."""

    class BrokenStdout(io.StringIO):
        def flush(self):
            raise BrokenPipeError(errno.EPIPE, "Broken pipe")

    monkeypatch.setattr(sys, "stdout", BrokenStdout())
    with pytest.raises(ValueError, match="cannot write standard output: Broken pipe"):
        write_sink("stdout", "result")


def test_a_closed_stdout_is_an_error_not_an_attribute_error(monkeypatch):
    """CPython leaves sys.stdout None when fd 1 is closed. print() then
    discards the mnemonic silently and flush() raises AttributeError."""
    monkeypatch.setattr(sys, "stdout", None)
    with pytest.raises(ValueError, match="cannot write standard output: it is closed"):
        write_sink("stdout", "result")


def test_a_closed_stdin_is_an_error_not_an_attribute_error(monkeypatch):
    """sys.stdin is None, not a stream raising OSError, so the OSError guard
    beside this one never sees it."""
    monkeypatch.setattr(sys, "stdin", None)
    with pytest.raises(ValueError, match="cannot read standard input: it is closed"):
        read_source("stdin")


def test_a_broken_stdout_is_redirected_so_shutdown_does_not_retry_it(tmp_path):
    """The salvage is unreachable through a StringIO: its fileno() raises
    io.UnsupportedOperation, which is both OSError and ValueError, so the
    suppress swallows it and the dup2 never runs. Only a real descriptor
    reaches it, and only out of process can the shutdown retry be observed.
    """
    argv = [sys.executable, "-m", "mnemocode", "encode", "0" * 32]
    process = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    process.stdout.close()
    _, err = process.communicate(timeout=30)
    assert process.returncode == 2
    assert err.strip() == "mnemocode: error: cannot write standard output: Broken pipe"
    # Without the dup2 the interpreter retries the buffered mnemonic while
    # shutting down and prints this after our own message.
    assert "Exception ignored" not in err


def test_file_source_reads_a_named_pipe(tmp_path):
    """The spec admits a device or a pipe so that a process substitution and
    /dev/stdin work; every other file: test uses a regular file."""
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    writer = threading.Thread(
        target=lambda: pathlib.Path(fifo).write_text(f"{KEY}\n"), daemon=True
    )
    writer.start()
    try:
        assert read_source(f"file:{fifo}") == f"{KEY}\n"
    finally:
        writer.join(timeout=15)
        assert not writer.is_alive()


def test_check_sink_rejects_a_bad_form_before_the_secret_is_read():
    """A typo in --output otherwise costs a blind 24-word entry at the prompt
    before anything looks at the sink."""
    with pytest.raises(ValueError, match="unknown output sink"):
        check_sink("bogus:path")
    with pytest.raises(ValueError, match="needs a descriptor number"):
        check_sink("fd:not-a-number")


def test_check_sink_accepts_the_three_forms_without_opening_anything(tmp_path):
    """A file: FIFO must not be opened here: the open blocks until a reader
    arrives, which would hang ahead of the prompt this precedes.

    Run off the main thread so that a regression which does open it fails this
    test on the join instead of blocking the run with nothing to report.
    """
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)

    def check_all() -> None:
        check_sink("stdout")
        check_sink("fd:1")
        check_sink(f"file:{fifo}")
        checked.append(True)

    checked: list[bool] = []
    thread = threading.Thread(target=check_all, daemon=True)
    thread.start()
    thread.join(timeout=5)
    assert checked == [True]


def test_a_terminal_that_fails_mid_prompt_is_an_error_not_a_traceback(
    prompt_terminal, monkeypatch
):
    """main catches only ValueError, so an EIO on a hung-up terminal would
    reach the user as a traceback. _read_line is the seam: patching os.read
    itself would also break the pty responder that answers the prompt.
    """

    def failing_read(fd):
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(secretio, "_read_line", failing_read)
    # A responder is still needed: it drains the prompt from the pty, and the
    # TCSAFLUSH restore in the finally blocks until that output has gone.
    prompt_terminal.answer("unread")
    with pytest.raises(ValueError, match="cannot read the key from"):
        prompt_secret("key")


def test_a_terminal_that_fails_at_the_echo_off_is_an_error_not_a_traceback(
    prompt_terminal, monkeypatch
):
    """termios.error is not an OSError and carries no strerror, so the guard
    around the read has to name it too; tcsetattr is the call that raises it
    on a terminal that hung up between the open and the prompt.
    """
    real_tcsetattr = termios.tcsetattr
    calls: list[int] = []

    def failing_tcsetattr(fd, when, attributes):
        calls.append(fd)
        # Only the echo-off; the restore in the finally must still run.
        if len(calls) == 1:
            raise termios.error(errno.EIO, "Input/output error")
        return real_tcsetattr(fd, when, attributes)

    monkeypatch.setattr(termios, "tcsetattr", failing_tcsetattr)
    with pytest.raises(ValueError, match="cannot read the key from"):
        prompt_secret("key")


def test_a_restore_that_fails_leaves_the_read_error_standing(
    prompt_terminal, monkeypatch
):
    """The read error is the one worth reporting, so the finally suppresses a
    restore failure on the same dead terminal rather than replacing it."""
    real_tcsetattr = termios.tcsetattr
    calls: list[int] = []

    def failing_restore(fd, when, attributes):
        calls.append(fd)
        if len(calls) == 2:
            raise termios.error(errno.EIO, "Input/output error")
        return real_tcsetattr(fd, when, attributes)

    def failing_read(fd):
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(termios, "tcsetattr", failing_restore)
    monkeypatch.setattr(secretio, "_read_line", failing_read)
    prompt_terminal.answer("unread")
    with pytest.raises(ValueError, match="cannot read the key from"):
        prompt_secret("key")


def test_write_sink_rejects_an_unknown_form():
    """The CLI now checks the form ahead of the prompt, so this guard is
    reachable only through a direct call — and must still hold."""
    with pytest.raises(ValueError, match="unknown output sink"):
        write_sink("bogus:path", "result")


def test_the_broken_pipe_salvage_leaves_no_descriptor_open(monkeypatch):
    """The salvage opens /dev/null to redirect the doomed retry; leaving it
    open would leak a descriptor on every broken-pipe run."""

    class BrokenStream(io.StringIO):
        def flush(self):
            raise OSError(errno.EPIPE, "Broken pipe")

        def fileno(self):
            return devnull_probe

    devnull_probe = os.open(os.devnull, os.O_WRONLY)
    try:
        before = len(os.listdir("/dev/fd"))
        monkeypatch.setattr(sys, "stdout", BrokenStream())
        with pytest.raises(ValueError, match="cannot write standard output"):
            write_sink("stdout", "result")
        assert len(os.listdir("/dev/fd")) == before
    finally:
        os.close(devnull_probe)
