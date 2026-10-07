"""Shared fixtures for the `pocketshell gateway` CLI tests.

The gateway tests must never depend on the developer box actually having a
`pocketshell-link` installed, and must never inherit a real
``POCKETSHELL_GATEWAY_HELPER`` pin, so the environment is isolated here.
"""

from __future__ import annotations

import pytest

from pocketshell.gateway import helper as gateway_helper


@pytest.fixture(autouse=True)
def _isolate_helper_env(monkeypatch):
    """Keep tests away from any operator-set helper pin on this box."""
    monkeypatch.delenv("POCKETSHELL_GATEWAY_HELPER", raising=False)


@pytest.fixture
def pin_helper(tmp_path, monkeypatch):
    """Write a fake helper executable and pin it via POCKETSHELL_GATEWAY_HELPER."""

    def _install(script: str, name: str = "pocketshell-link") -> str:
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir(exist_ok=True)
        path = bin_dir / name
        path.write_text(script)
        path.chmod(0o755)
        monkeypatch.setenv("POCKETSHELL_GATEWAY_HELPER", str(path))
        return str(path)

    return _install


@pytest.fixture
def exec_calls(monkeypatch):
    """Replace the exec boundary with a recorder.

    Each recorded call is a ``(helper, argv)`` tuple. Raising SystemExit(0)
    stops Click cleanly after the boundary, so tests observe both the exit
    path and the exact call. The real os.execv boundary is covered by the
    subprocess suites (test_gateway_exec_passthrough.py).
    """
    calls: list[tuple[str, list[str]]] = []

    def _capture(helper: str, argv: list[str]) -> None:
        calls.append((helper, argv))
        raise SystemExit(0)

    monkeypatch.setattr(gateway_helper, "exec_helper", _capture)
    return calls


@pytest.fixture
def forbid_helper_launch(monkeypatch):
    """Poison helper resolution for negative preflight tests.

    ``exec_calls == []`` proves nothing was exec'd; this additionally
    proves the wrapper never even *resolved* the helper on a rejected
    invocation — the strongest local form of "refused before any helper
    launch, hence zero helper network". If a regression lets the preflight
    pass, resolution blows up the test loudly instead of the test silently
    passing on an empty recorder.
    """
    def _refuse(*args, **kwargs):
        raise AssertionError(
            "helper resolution started despite a preflight refusal"
        )

    monkeypatch.setattr(gateway_helper, "resolve_helper", _refuse)
