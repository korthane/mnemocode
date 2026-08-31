import io
import os
import stat
import sys
import termios
import threading

import pytest

from mnemocode import secretio
from mnemocode.secretio import (
    SOURCE_FORMS,
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

    reader = threading.Thread(target=read_pipe)
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
