"""Unit tests for Go-helper resolution (`pocketshell.gateway.helper`).

The `pocketshell gateway` commands have no transport logic of their own;
their entire usefulness depends on finding the right `pocketshell-link`
binary: an explicit trusted pin first, then PATH, and a loud actionable
error otherwise — never a download, never a bundled copy.
"""

from __future__ import annotations

import os

import pytest

from pocketshell.gateway.helper import (
    HELPER_ENV_VAR,
    HELPER_NAME,
    HelperNotFoundError,
    build_helper_argv,
    resolve_helper,
)


def _write_exec(path, contents="#!/bin/sh\nexit 0\n"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents)
    path.chmod(0o755)
    return path


# ---------------------------------------------------------------------------
# resolution order
# ---------------------------------------------------------------------------


def test_env_pin_wins_over_path(tmp_path, monkeypatch):
    pinned = _write_exec(tmp_path / "pinned" / HELPER_NAME)
    on_path = _write_exec(tmp_path / "bin" / HELPER_NAME)
    monkeypatch.setenv("PATH", str(on_path.parent))
    monkeypatch.setenv(HELPER_ENV_VAR, str(pinned))
    assert resolve_helper() == str(pinned)


def test_path_fallback_when_unpinned(tmp_path, monkeypatch):
    on_path = _write_exec(tmp_path / "bin" / HELPER_NAME)
    monkeypatch.setenv("PATH", str(on_path.parent))
    assert resolve_helper() == str(on_path)


# ---------------------------------------------------------------------------
# failure modes are loud and actionable
# ---------------------------------------------------------------------------


def test_missing_helper_error_names_the_build_path(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "nothing-here"))
    with pytest.raises(HelperNotFoundError) as excinfo:
        resolve_helper()
    message = str(excinfo.value)
    assert HELPER_NAME in message
    assert "go build" in message
    # The real private repository and its authoritative URL — never the
    # -tunnel spelling (that is a local worker worktree, not a repo).
    assert "PocketShell-io/pocketshell-gateway" in message
    assert "cd /path/to/pocketshell-gateway" in message
    assert "pocketshell-gateway-tunnel" not in message
    assert HELPER_ENV_VAR in message


@pytest.mark.parametrize(
    "contents",
    [
        None,  # file does not exist at all
        "#!/bin/sh\nexit 0\n",  # exists but not executable
    ],
)
def test_broken_env_pin_does_not_fall_back_to_path(
    tmp_path, monkeypatch, contents
):
    on_path = _write_exec(tmp_path / "bin" / HELPER_NAME)
    monkeypatch.setenv("PATH", str(on_path.parent))
    pinned = tmp_path / "pinned" / HELPER_NAME
    if contents is not None:
        pinned.parent.mkdir(parents=True, exist_ok=True)
        pinned.write_text(contents)
        pinned.chmod(0o644)
    monkeypatch.setenv(HELPER_ENV_VAR, str(pinned))
    with pytest.raises(HelperNotFoundError) as excinfo:
        resolve_helper()
    assert HELPER_ENV_VAR in str(excinfo.value)


# ---------------------------------------------------------------------------
# argv builder invariants
# ---------------------------------------------------------------------------


def test_builder_rejects_unknown_subcommands():
    with pytest.raises(ValueError):
        build_helper_argv("daemon")


def test_builder_omits_unset_options_and_never_defaults_insecure_dev():
    assert build_helper_argv("enroll", token_stdin=True) == ["enroll", "--token-stdin"]
    assert build_helper_argv("run") == ["run"]
    assert build_helper_argv("show", config_dir="/d") == ["show", "--config-dir", "/d"]
    assert "--insecure-dev" not in build_helper_argv("run", insecure_dev=False)


def test_builder_forwards_falsy_but_set_values():
    # A value of "0" or "" that the user actually typed must still be
    # forwarded: only None means "not passed".
    assert build_helper_argv("enroll", token_stdin=True, device_id="0") == [
        "enroll",
        "--token-stdin",
        "--device-id",
        "0",
    ]
    assert build_helper_argv("show", config_dir="") == ["show", "--config-dir", ""]


def test_env_pin_helper_is_never_resolved_from_cwd_relative_fallback(
    tmp_path, monkeypatch
):
    # A bare name like "pocketshell-link" in the env pin must not resolve
    # against the working directory implicitly via isfile/which confusion:
    # relative pins are honored (relative to cwd), but a pin naming a file
    # that only exists on PATH is an error, not a silent PATH lookup.
    on_path = _write_exec(tmp_path / "bin" / HELPER_NAME)
    monkeypatch.setenv("PATH", str(on_path.parent))
    monkeypatch.setenv(HELPER_ENV_VAR, HELPER_NAME)
    monkeypatch.chdir(tmp_path)
    if os.path.isfile(HELPER_NAME):
        pytest.skip("a real pocketshell-link exists in this cwd")
    with pytest.raises(HelperNotFoundError):
        resolve_helper()
