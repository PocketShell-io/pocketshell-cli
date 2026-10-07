"""Installed-wheel route of the helper resolver (`pocketshell gateway`).

Priority: operator pin → installed ``pocketshell-gateway-link`` wheel →
PATH. The wheel step is a selection, not a hint: a broken install (binary
missing, not executable, built for another platform, unreadable metadata)
must fail closed — never a silent fallback to a different binary on PATH.
Resolution unit tests fake the distribution object; the real installed
wheel is proven end to end in the fresh-venv integration run (see the
progress ledger).
"""

from __future__ import annotations

import sys

import pytest

from pocketshell.gateway import helper as gateway_helper
from pocketshell.gateway.helper import (
    HELPER_NAME,
    HELPER_ENV_VAR,
    HelperNotFoundError,
    resolve_helper,
)


class FakeWheelDist:
    """Stand-in for importlib.metadata's Distribution of the helper wheel."""

    def __init__(self, binary, wheel_text):
        self._binary = binary
        self._wheel_text = wheel_text

    def read_text(self, name):
        return self._wheel_text if name == "WHEEL" else None

    def locate_file(self, relative):
        return self._binary


def _write_exec(path, contents="#!/bin/sh\nexit 0\n"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents)
    path.chmod(0o755)
    return path


def _install_dist(monkeypatch, dist):
    monkeypatch.setattr(
        gateway_helper, "_installed_wheel_distribution", lambda: dist
    )


def _fake_host(monkeypatch, system, machine):
    monkeypatch.setattr(gateway_helper.platform, "system", lambda: system)
    monkeypatch.setattr(gateway_helper.platform, "machine", lambda: machine)


def _path_decoy(tmp_path, monkeypatch):
    """A good-looking helper on PATH that must be ignored once a wheel is
    selected — and used when no wheel is installed."""
    on_path = _write_exec(tmp_path / "bin" / HELPER_NAME)
    monkeypatch.setenv("PATH", str(on_path.parent))
    return on_path


LINUX_X86_64_WHEEL = "Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-manylinux_2_28_x86_64\n"

# Captured before any fixture can swap the module attribute: the autouse
# `_no_installed_wheel` isolation replaces `_installed_wheel_distribution`;
# this test deliberately puts the real one back.
_REAL_WHEEL_LOOKUP = gateway_helper._installed_wheel_distribution


# ---------------------------------------------------------------------------
# priority
# ---------------------------------------------------------------------------


def test_installed_wheel_is_preferred_over_path(tmp_path, monkeypatch):
    decoy = _path_decoy(tmp_path, monkeypatch)
    wheel_binary = _write_exec(tmp_path / "wheel" / HELPER_NAME)
    _install_dist(
        monkeypatch, FakeWheelDist(wheel_binary, LINUX_X86_64_WHEEL)
    )
    assert resolve_helper() == str(wheel_binary)
    assert resolve_helper() != str(decoy)


def test_operator_pin_still_wins_over_installed_wheel(tmp_path, monkeypatch):
    wheel_binary = _write_exec(tmp_path / "wheel" / HELPER_NAME)
    _install_dist(
        monkeypatch, FakeWheelDist(wheel_binary, LINUX_X86_64_WHEEL)
    )
    pinned = _write_exec(tmp_path / "pinned" / HELPER_NAME)
    monkeypatch.setenv(HELPER_ENV_VAR, str(pinned))
    assert resolve_helper() == str(pinned)


def test_no_wheel_installed_falls_back_to_path(tmp_path, monkeypatch):
    decoy = _path_decoy(tmp_path, monkeypatch)
    _install_dist(monkeypatch, None)  # PackageNotFoundError territory
    assert resolve_helper() == str(decoy)


# ---------------------------------------------------------------------------
# a selected-but-broken wheel never falls back
# ---------------------------------------------------------------------------


def test_wheel_binary_missing_fails_without_path_fallback(
    tmp_path, monkeypatch
):
    decoy = _path_decoy(tmp_path, monkeypatch)
    _install_dist(
        monkeypatch,
        FakeWheelDist(tmp_path / "wheel" / "absent" / HELPER_NAME, LINUX_X86_64_WHEEL),
    )
    with pytest.raises(HelperNotFoundError) as excinfo:
        resolve_helper()
    assert "does not contain an executable" in str(excinfo.value)
    assert str(decoy) not in str(excinfo.value)


def test_wheel_binary_not_executable_fails_without_path_fallback(
    tmp_path, monkeypatch
):
    _path_decoy(tmp_path, monkeypatch)
    wheel_binary = tmp_path / "wheel" / HELPER_NAME
    wheel_binary.parent.mkdir(parents=True, exist_ok=True)
    wheel_binary.write_text("#!/bin/sh\nexit 0\n")
    wheel_binary.chmod(0o644)
    _install_dist(monkeypatch, FakeWheelDist(wheel_binary, LINUX_X86_64_WHEEL))
    with pytest.raises(HelperNotFoundError, match="not executable"):
        resolve_helper()


def test_foreign_platform_wheel_fails_without_path_fallback(
    tmp_path, monkeypatch
):
    # A wheel whose tags name another platform must never be exec'd (it
    # would be an architecture mismatch at best); it is a broken selection.
    decoy = _path_decoy(tmp_path, monkeypatch)
    wheel_binary = _write_exec(tmp_path / "wheel" / HELPER_NAME)
    _install_dist(
        monkeypatch,
        FakeWheelDist(
            wheel_binary, "Tag: py3-none-macosx_11_0_arm64\n"
        ),
    )
    with pytest.raises(HelperNotFoundError) as excinfo:
        resolve_helper()
    message = str(excinfo.value)
    assert "do not match this host" in message
    assert "macosx_11_0_arm64" in message
    assert str(decoy) not in message


def test_multiple_tags_with_one_matching_host_are_accepted(
    tmp_path, monkeypatch
):
    _path_decoy(tmp_path, monkeypatch)
    wheel_binary = _write_exec(tmp_path / "wheel" / HELPER_NAME)
    _install_dist(
        monkeypatch,
        FakeWheelDist(
            wheel_binary,
            "Tag: py3-none-manylinux_2_28_aarch64\n"
            "Tag: py3-none-manylinux_2_28_x86_64\n",
        ),
    )
    assert resolve_helper() == str(wheel_binary)


def test_wheel_metadata_tag_comparison_is_exact(tmp_path, monkeypatch):
    # A tag that merely CONTAINS the expected fragment (macosx_11_0_x86_64
    # contains x86_64) must not satisfy a manylinux host: compare the tag's
    # platform component, not a substring.
    _path_decoy(tmp_path, monkeypatch)
    wheel_binary = _write_exec(tmp_path / "wheel" / HELPER_NAME)
    _install_dist(
        monkeypatch,
        FakeWheelDist(wheel_binary, "Tag: py3-none-macosx_11_0_x86_64\n"),
    )
    with pytest.raises(HelperNotFoundError, match="do not match this host"):
        resolve_helper()


def test_unreadable_wheel_metadata_fails_without_path_fallback(
    tmp_path, monkeypatch
):
    _path_decoy(tmp_path, monkeypatch)
    wheel_binary = _write_exec(tmp_path / "wheel" / HELPER_NAME)
    _install_dist(monkeypatch, FakeWheelDist(wheel_binary, None))
    with pytest.raises(HelperNotFoundError, match="no readable"):
        resolve_helper()


def test_corrupt_distribution_fails_without_path_fallback(
    tmp_path, monkeypatch
):
    def _corrupt(name):
        raise RuntimeError("metadata directory is mangled")

    # Patch the underlying lookup so the resolver's real try/except (the
    # fail-closed branch for unreadable distributions) is what runs.
    monkeypatch.setattr(
        gateway_helper,
        "_installed_wheel_distribution",
        _REAL_WHEEL_LOOKUP,
    )
    monkeypatch.setattr(gateway_helper.metadata, "distribution", _corrupt)
    _path_decoy(tmp_path, monkeypatch)
    with pytest.raises(HelperNotFoundError, match="could not be read"):
        resolve_helper()


# ---------------------------------------------------------------------------
# platform honesty
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("system", "machine", "expected"),
    [
        ("Linux", "x86_64", "manylinux_2_28_x86_64"),
        ("Linux", "amd64", "manylinux_2_28_x86_64"),  # Debian spelling
        ("Linux", "aarch64", "manylinux_2_28_aarch64"),
        ("Linux", "arm64", "manylinux_2_28_aarch64"),  # macOS spelling
        ("Darwin", "x86_64", "macosx_11_0_x86_64"),
        ("Darwin", "amd64", "macosx_11_0_x86_64"),
        ("Darwin", "arm64", "macosx_11_0_arm64"),
        ("Darwin", "aarch64", "macosx_11_0_arm64"),
    ],
)
def test_host_wheel_tag_mapping(monkeypatch, system, machine, expected):
    _fake_host(monkeypatch, system, machine)
    assert gateway_helper._host_wheel_tag() == expected


@pytest.mark.parametrize(
    ("system", "machine"),
    [
        ("Linux", "riscv64"),
        ("Linux", "i686"),
        ("FreeBSD", "amd64"),
    ],
)
def test_platform_without_wheels_names_itself_honestly(
    tmp_path, monkeypatch, system, machine
):
    # Without an installed wheel these hosts still have the PATH route;
    # but a FORCED wheel install must be refused with the platform named,
    # not exec'd blindly.
    wheel_binary = _write_exec(tmp_path / "wheel" / HELPER_NAME)
    _install_dist(
        monkeypatch, FakeWheelDist(wheel_binary, LINUX_X86_64_WHEEL)
    )
    _fake_host(monkeypatch, system, machine)
    with pytest.raises(HelperNotFoundError) as excinfo:
        resolve_helper()
    message = str(excinfo.value)
    assert f"({system.lower()} {machine})" in message
    assert "linux amd64/arm64 and darwin amd64/arm64" in message


def test_windows_is_refused_upfront(tmp_path, monkeypatch):
    # POSIX exec boundary: Windows was never supported; say so before any
    # lookup instead of failing inside os.execv.
    monkeypatch.setattr(sys, "platform", "win32")
    with pytest.raises(HelperNotFoundError, match="Windows"):
        resolve_helper()


def test_missing_helper_message_names_wheel_and_build_routes(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("PATH", str(tmp_path / "empty-path"))
    with pytest.raises(HelperNotFoundError) as excinfo:
        resolve_helper()
    message = str(excinfo.value)
    # The wheel install route (checksum-verified, --no-index) and the
    # build-from-source route are both actionable in the error itself.
    assert "--no-index --no-deps" in message
    assert "go build" in message
    assert "PocketShell-io/pocketshell-gateway" in message
    assert HELPER_ENV_VAR in message
