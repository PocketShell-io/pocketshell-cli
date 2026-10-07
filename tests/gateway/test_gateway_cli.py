"""Click-surface tests for `pocketshell gateway enroll|run|show`.

These cover the wrapper layer through the top-level CLI registration:
exact helper argv construction (flag values with spaces stay single argv
elements — nothing is ever interpolated through a shell), delegation of
defaults to the Go helper, the stdin-only token contract, and the
coexistence with the legacy `link`/`relay` commands. The exec itself is
replaced by a recorder here; the real exec boundary (stdin, signals, exit
codes) is proven end-to-end in test_gateway_exec_passthrough.py.
"""

from __future__ import annotations

import re

import pytest
from click.testing import CliRunner

from pocketshell.cli import cli

pytestmark = pytest.mark.usefixtures("exec_calls")


def _argv(exec_calls, result) -> list[str]:
    assert result.exit_code == 0, (result.output, result.exception)
    return exec_calls[-1][1]


# ---------------------------------------------------------------------------
# Registration / help
# ---------------------------------------------------------------------------


def test_gateway_group_is_registered_in_top_level_help():
    result = CliRunner().invoke(cli, ["--help"])
    assert result.exit_code == 0, result.output
    assert "gateway" in result.output


def test_gateway_help_lists_the_three_wrappers():
    result = CliRunner().invoke(cli, ["gateway", "--help"])
    assert result.exit_code == 0, result.output
    for name in ("enroll", "run", "show"):
        assert name in result.output
    assert "pocketshell-link" in result.output


def test_legacy_link_and_relay_commands_are_preserved():
    runner = CliRunner()
    top = runner.invoke(cli, ["--help"])
    assert top.exit_code == 0, top.output
    assert "link" in top.output
    assert "relay" in top.output
    # The legacy surface is untouched: the shared-token flags still exist.
    link_run = runner.invoke(cli, ["link", "run", "--help"])
    assert link_run.exit_code == 0, link_run.output
    assert "--relay" in link_run.output
    assert "--token" in link_run.output
    relay_serve = runner.invoke(cli, ["relay", "serve", "--help"])
    assert relay_serve.exit_code == 0, relay_serve.output
    assert "--listen" in relay_serve.output


def test_enroll_help_documents_stdin_only_token():
    result = CliRunner().invoke(cli, ["gateway", "enroll", "--help"])
    assert result.exit_code == 0, result.output
    assert "--token-stdin" in result.output
    # There is deliberately no value-taking token flag.
    assert re.search(r"--token(?!-stdin)\b", result.output) is None


# ---------------------------------------------------------------------------
# argv construction
# ---------------------------------------------------------------------------


def test_enroll_forwards_flags_verbatim_including_values_with_spaces(
    pin_helper, exec_calls
):
    pin_helper("#!/bin/sh\nexit 0\n")
    # Host-key lines, device ids and paths legitimately contain spaces and
    # shell metacharacters; every one of them must arrive at the helper as
    # ONE argv element, byte-identical.
    host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBox-with spaces; $(rm -rf /)"
    result = CliRunner().invoke(
        cli,
        [
            "gateway", "enroll",
            "--token-stdin",
            "--server", "wss://gateway.example",
            "--config-dir", "/tmp/dir with spaces",
            "--device-id", "my device; id `whoami`",
            "--ssh-host", "127.0.0.1:2222",
            "--expect-host-key", host_key,
            "--insecure-dev",
            "--verbose",
        ],
    )
    assert _argv(exec_calls, result) == [
        "enroll",
        "--token-stdin",
        "--server", "wss://gateway.example",
        "--config-dir", "/tmp/dir with spaces",
        "--device-id", "my device; id `whoami`",
        "--ssh-host", "127.0.0.1:2222",
        "--expect-host-key", host_key,
        "--insecure-dev",
        "--verbose",
    ]


def test_enroll_with_no_options_forwards_only_token_stdin(pin_helper, exec_calls):
    pin_helper("#!/bin/sh\nexit 0\n")
    result = CliRunner().invoke(cli, ["gateway", "enroll", "--token-stdin"])
    # Defaults are delegated: the wrapper neither knows nor forwards a
    # default --server/--config-dir/--ssh-host; the Go helper applies its
    # own. --insecure-dev is never defaulted on.
    assert _argv(exec_calls, result) == ["enroll", "--token-stdin"]


def test_run_forwards_only_passed_flags(pin_helper, exec_calls):
    pin_helper("#!/bin/sh\nexit 0\n")
    bare = CliRunner().invoke(cli, ["gateway", "run"])
    assert _argv(exec_calls, bare) == ["run"]

    full = CliRunner().invoke(
        cli,
        [
            "gateway", "run",
            "--server", "ws://gateway:8080",
            "--config-dir", "/tmp/agent state",
            "--insecure-dev",
            "--verbose",
        ],
    )
    assert _argv(exec_calls, full) == [
        "run",
        "--server", "ws://gateway:8080",
        "--config-dir", "/tmp/agent state",
        "--insecure-dev",
        "--verbose",
    ]


def test_show_accepts_config_dir_only(pin_helper, exec_calls):
    pin_helper("#!/bin/sh\nexit 0\n")
    bare = CliRunner().invoke(cli, ["gateway", "show"])
    assert _argv(exec_calls, bare) == ["show"]

    custom = CliRunner().invoke(cli, ["gateway", "show", "--config-dir", "/tmp/state dir"])
    assert _argv(exec_calls, custom) == ["show", "--config-dir", "/tmp/state dir"]


def test_helper_pin_reaches_the_exec_boundary(pin_helper, exec_calls):
    helper_path = pin_helper("#!/bin/sh\nexit 0\n")
    result = CliRunner().invoke(cli, ["gateway", "show"])
    assert result.exit_code == 0, result.output
    assert exec_calls[-1][0] == helper_path


# ---------------------------------------------------------------------------
# token-stdin enforcement
# ---------------------------------------------------------------------------


def test_enroll_without_token_stdin_is_rejected_before_exec(exec_calls):
    result = CliRunner().invoke(cli, ["gateway", "enroll"])
    assert result.exit_code != 0
    assert "--token-stdin" in result.output
    assert "stdin" in result.output.lower()
    # The failure happens at the wrapper: nothing was exec'd.
    assert exec_calls == []


# ---------------------------------------------------------------------------
# missing helper
# ---------------------------------------------------------------------------


def test_missing_helper_exits_127_with_build_instructions(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path / "empty-path"))
    result = CliRunner().invoke(cli, ["gateway", "show"])
    assert result.exit_code == 127
    assert "pocketshell-link" in result.stderr
    assert "go build" in result.stderr
    assert "pocketshell-gateway-tunnel" in result.stderr


def test_broken_helper_pin_errors_instead_of_falling_back(monkeypatch, tmp_path):
    missing = tmp_path / "not-a-helper"
    monkeypatch.setenv("POCKETSHELL_GATEWAY_HELPER", str(missing))
    monkeypatch.setenv("PATH", str(tmp_path / "empty-path"))
    result = CliRunner().invoke(cli, ["gateway", "run"])
    assert result.exit_code == 127
    assert "POCKETSHELL_GATEWAY_HELPER" in result.stderr
