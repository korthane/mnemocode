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
