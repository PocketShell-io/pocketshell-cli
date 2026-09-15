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
