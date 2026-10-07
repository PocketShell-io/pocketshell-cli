"""Shared fixtures for the `pocketshell gateway` CLI tests.

The gateway tests must never depend on the developer box actually having a
`pocketshell-link` installed — on PATH, pinned via
``POCKETSHELL_GATEWAY_HELPER``, or as an installed
``pocketshell-gateway-link`` wheel — and must never inherit a real
operator-set pin, so the environment is isolated here.
"""

from __future__ import annotations

import pytest

from pocketshell.gateway import helper as gateway_helper

# The helper's `version --json` metadata contract (frozen one-line JSON),
# as the test doubles must answer it for the wrapper's protocol gate.
VALID_METADATA = (
    '{"version":"devel","protocol":"pocketshell-tunnel-v1","commit":"unknown"}'
)

# sh shebang + the metadata branch: the wrapper probes `version --json`
# BEFORE the real subcommand, so every sh test double gets a valid default
# answer unless a test overrides it via pin_helper(version_json=...).
_VERSION_BRANCH = (
    '#!/bin/sh\n'
    'if [ "$1" = version ]; then\n'
    "  printf '%s\\n' '{version_json}'\n"
    "  exit {version_exit}\n"
    "fi\n"
)


@pytest.fixture(autouse=True)
def _isolate_helper_env(monkeypatch):
    """Keep tests away from any operator-set helper pin on this box."""
    monkeypatch.delenv("POCKETSHELL_GATEWAY_HELPER", raising=False)


@pytest.fixture(autouse=True)
def _no_installed_wheel(monkeypatch):
    """Treat ``pocketshell-gateway-link`` as not installed by default.

    Whether this box happens to have the helper wheel installed must not
    change what the wrapper-level tests observe; the wheel-specific suites
    install controlled fakes, and the fresh-venv integration run proves
    the real installed-wheel route end to end.
    """
    monkeypatch.setattr(
        gateway_helper, "_installed_wheel_distribution", lambda: None
    )


@pytest.fixture
def pin_helper(tmp_path, monkeypatch):
    """Write a fake helper executable and pin it via POCKETSHELL_GATEWAY_HELPER.

    sh scripts get a ``version --json`` branch prepended that answers with
    ``version_json`` (default: the valid devel contract) and exits
    ``version_exit`` — that is what the wrapper's protocol gate sees. The
    script body itself is what ``enroll``/``run``/``show`` reach after
    verification. Scripts with another shebang are installed verbatim and
    must handle ``version --json`` themselves.
    """

    def _install(
        script: str,
        name: str = "pocketshell-link",
        version_json: str = VALID_METADATA,
        version_exit: int = 0,
    ) -> str:
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir(exist_ok=True)
        path = bin_dir / name
        if script.startswith("#!/bin/sh"):
            script = _VERSION_BRANCH.format(
                version_json=version_json, version_exit=version_exit
            ) + script[len("#!/bin/sh\n"):]
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
