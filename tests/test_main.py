"""Coverage for ``python -m pocketshell`` (the ``__main__`` shim)."""

from __future__ import annotations

import runpy
import sys

import pytest


def test_python_dash_m_pocketshell_invokes_the_cli(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["pocketshell", "--help"])

    with pytest.raises(SystemExit) as excinfo:
        runpy.run_module("pocketshell", run_name="__main__")

    assert excinfo.value.code == 0
    assert "Usage" in capsys.readouterr().out


def _add_command(monkeypatch, exc):
    import click

    from pocketshell.cli import cli

    def boom():
        raise exc

    monkeypatch.setitem(cli.commands, "boom-test", click.Command("boom-test", callback=boom))


def test_main_unexpected_exception_prints_only_class_name(monkeypatch, capsys) -> None:
    from pocketshell.cli import main

    monkeypatch.delenv("POCKETSHELL_DEBUG", raising=False)
    _add_command(monkeypatch, RuntimeError("\x1b]52;c;ZXZpbA==\x07 raw gateway bytes"))
    assert main(["boom-test"]) == 1
    out = capsys.readouterr()
    assert out.err == "pocketshell: internal error (RuntimeError)\n"
    assert out.out == ""


def test_main_debug_reraises(monkeypatch) -> None:
    from pocketshell.cli import main

    monkeypatch.setenv("POCKETSHELL_DEBUG", "1")
    _add_command(monkeypatch, RuntimeError("x"))
    with pytest.raises(RuntimeError):
        main(["boom-test"])


@pytest.mark.parametrize("exc", [KeyboardInterrupt(), __import__("click").Abort()])
def test_main_interrupt_exits_130_quietly(monkeypatch, capsys, exc) -> None:
    from pocketshell.cli import main

    _add_command(monkeypatch, exc)
    assert main(["boom-test"]) == 130
    err = capsys.readouterr().err
    assert "Traceback" not in err and "internal error" not in err


def test_main_usage_errors_keep_click_exit_code(capsys) -> None:
    from pocketshell.cli import main

    assert main(["no-such-command-xyz"]) == 2
    assert "No such command" in capsys.readouterr().err
    assert main(["--version"]) == 0
