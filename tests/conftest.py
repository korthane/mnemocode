import os
import pty
import select
import threading
import time

import pytest

from mnemocode import secretio


@pytest.fixture(autouse=True)
def no_controlling_terminal(monkeypatch, tmp_path_factory):
    """Keep the suite off the real terminal.

    A test that reaches the prompt would otherwise block on /dev/tty wherever
    one happens to be attached. Tests that exercise the prompt point this at a
    pty of their own.
    """
    absent = tmp_path_factory.mktemp("tty") / "absent"
    monkeypatch.setattr(secretio, "_TTY_PATH", str(absent))


class PromptTerminal:
    """A pty the prompt reads from, with a responder that cannot deadlock."""

    def __init__(self, master: int) -> None:
        self.master = master
        self.prompts: list[str] = []
        self.threads: list[threading.Thread] = []

    def _once_prompted(self, type_it) -> threading.Thread:
        """Run `type_it` after the prompt appears, as a user would.

        Typing before the prompt appears would be discarded: the prompt
        disables echo with TCSAFLUSH, which drops anything already queued. The
        wait is bounded so that a prompt which never arrives fails the test
        rather than hanging the suite with no diagnostic.
        """

        def respond() -> None:
            if select.select([self.master], [], [], 10)[0]:
                self.prompts.append(os.read(self.master, 4096).decode())
            # Answer even if the prompt never came, so the reader unblocks and
            # the test reports what it saw instead of timing out.
            type_it()

        thread = threading.Thread(target=respond, daemon=True)
        self.threads.append(thread)
        thread.start()
        return thread

    def answer(self, text: str) -> threading.Thread:
        return self.answer_bytes(f"{text}\n".encode())

    def answer_bytes(self, payload: bytes) -> threading.Thread:
        """Type raw bytes, for entries that are not valid UTF-8."""
        return self._once_prompted(lambda: os.write(self.master, payload))

    def answer_with_eof(self, text: str) -> threading.Thread:
        # Two EOFs: the first delivers the pending line without a newline, the
        # second reads as end of input.
        return self.answer_bytes(text.encode() + b"\x04\x04")

    def answer_in_two_reads(self, first: str, rest: str) -> threading.Thread:
        """Type an entry the reader cannot take in one os.read.

        Ctrl-D delivers what is pending without a newline, so the reader sees
        `first` alone and must loop for `rest`. The pause is what forces the
        two into separate reads rather than one.
        """

        def type_it() -> None:
            os.write(self.master, first.encode() + b"\x04")
            time.sleep(0.2)
            os.write(self.master, f"{rest}\n".encode())

        return self._once_prompted(type_it)

    def drain(self) -> str:
        os.set_blocking(self.master, False)
        try:
            return os.read(self.master, 4096).decode()
        except BlockingIOError:
            return ""
        finally:
            os.set_blocking(self.master, True)


@pytest.fixture
def prompt_terminal(monkeypatch):
    """Point prompt_secret at a fresh pty and close both ends afterwards."""
    master, slave = pty.openpty()
    monkeypatch.setattr(secretio, "_TTY_PATH", os.ttyname(slave))
    terminal = PromptTerminal(master)
    try:
        yield terminal
    finally:
        # Join first: a responder still in select would otherwise write to a
        # descriptor number the OS may have handed to another test's file.
        for thread in terminal.threads:
            thread.join(timeout=15)
        # Master first: closing the slave while the master is still open leaves
        # macOS waiting on the line discipline for about half a second.
        os.close(master)
        os.close(slave)
