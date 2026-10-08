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
    # The C2 scoped-credential correction: stdin carries a short-lived
    # gateway-scoped ENROLLMENT token, not an account credential.
    assert "enrollment token" in result.output
    assert "5 minutes" in result.output
    assert "Google" not in result.output
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


def test_enroll_without_token_stdin_or_login_is_rejected_before_exec(
    exec_calls, pin_helper, no_account
):
    pin_helper("#!/bin/sh\nexit 0\n")
    result = CliRunner().invoke(cli, ["gateway", "enroll"])
    assert result.exit_code == 3
    assert "--token-stdin" in result.output
    assert "enrollment token" in result.output
    assert "pocketshell" in result.output
    assert "Google" not in result.output
    # The failure happens at the wrapper: nothing was exec'd.
    assert exec_calls == []


# ---------------------------------------------------------------------------
# protocol metadata gate at the CLI surface
# ---------------------------------------------------------------------------


def test_incompatible_helper_exits_126_with_concise_error(
    pin_helper, exec_calls
):
    pin_helper(
        "#!/bin/sh\nexit 0\n",
        version_json=(
            '{"version":"1.0.0","protocol":"pocketshell-tunnel-v2",'
            '"commit":"abc"}'
        ),
    )
    result = CliRunner().invoke(cli, ["gateway", "show"])
    assert result.exit_code == 126
    stderr = result.stderr
    assert "not compatible" in stderr
    assert "pocketshell-tunnel-v1" in stderr
    assert "Traceback" not in stderr
    # Nothing exec'd: the real subcommand never ran against a stale helper.
    assert exec_calls == []


def test_helper_with_unusable_metadata_is_refused_before_exec(
    pin_helper, exec_calls
):
    pin_helper(
        "#!/bin/sh\nexit 0\n",
        # commit missing entirely: not the frozen contract, refuse.
        version_json='{"version":"devel","protocol":"pocketshell-tunnel-v1"}',
    )
    result = CliRunner().invoke(cli, ["gateway", "run"])
    assert result.exit_code == 126
    assert "'commit' is missing" in result.stderr
    assert exec_calls == []


def test_uninjected_devel_metadata_passes_the_gate(pin_helper, exec_calls):
    # The default test double answers exactly what an un-injected source
    # build answers (devel/unknown, pocketshell-tunnel-v1): protocol-
    # compatible, so the command proceeds — acceptance proves the protocol,
    # never release provenance.
    pin_helper("#!/bin/sh\nexit 0\n")
    result = CliRunner().invoke(cli, ["gateway", "show"])
    assert result.exit_code == 0, result.output
    assert exec_calls[-1][1] == ["show"]


def test_every_gateway_subcommand_verifies_before_exec(pin_helper, exec_calls):
    pin_helper(
        "#!/bin/sh\nexit 0\n",
        version_json='{"version":"1.0.0","protocol":"stale","commit":"x"}',
    )
    runner = CliRunner()
    for command in ("enroll", "run", "show"):
        args = ["gateway", command] + (
            ["--token-stdin"] if command == "enroll" else []
        )
        result = runner.invoke(cli, args)
        assert result.exit_code == 126, command
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
    # The wheel install route is actionable in the same error (checksum
    # verification is a docs matter; the wrapper never downloads).
    assert "--no-index --no-deps" in result.stderr
    # The build source is the REAL private repository (authoritative URL);
    # the -tunnel spelling is only a local worker worktree, never a repo.
    assert "PocketShell-io/pocketshell-gateway" in result.stderr
    assert "pocketshell-gateway-tunnel" not in result.stderr


def test_broken_helper_pin_errors_instead_of_falling_back(monkeypatch, tmp_path):
    missing = tmp_path / "not-a-helper"
    monkeypatch.setenv("POCKETSHELL_GATEWAY_HELPER", str(missing))
    monkeypatch.setenv("PATH", str(tmp_path / "empty-path"))
    result = CliRunner().invoke(cli, ["gateway", "run"])
    assert result.exit_code == 127
    assert "POCKETSHELL_GATEWAY_HELPER" in result.stderr


# ---------------------------------------------------------------------------
# guarded --dev-broker-issuer forwarding (mirrors the Go brokerPolicy guard)
# ---------------------------------------------------------------------------


def test_dev_broker_issuer_forwarded_when_guarded(pin_helper, exec_calls):
    pin_helper("#!/bin/sh\nexit 0\n")
    result = CliRunner().invoke(
        cli,
        [
            "gateway", "enroll",
            "--token-stdin",
            "--server", "ws://[::1]:8080",
            "--insecure-dev",
            "--dev-broker-issuer", "https://lab-broker.example",
        ],
    )
    # Guarded forwarding: DEV issuer override only ever travels with
    # --insecure-dev AND an explicit non-production --server; both the
    # IPv6 literal server URL and the issuer stay single argv elements.
    assert _argv(exec_calls, result) == [
        "enroll",
        "--token-stdin",
        "--server", "ws://[::1]:8080",
        "--dev-broker-issuer", "https://lab-broker.example",
        "--insecure-dev",
    ]


@pytest.mark.parametrize(
    "server",
    [
        "ws://127.0.0.1:8080",  # explicit loopback IPv4
        "ws://gateway:8080",  # docker-compose service hostname
        "ws://gateway:8080/tunnel",  # docker hostname with a path
    ],
)
def test_dev_broker_issuer_forwards_lab_servers_verbatim(
    pin_helper, exec_calls, server
):
    # The guard's flip side: legitimate lab targets — loopback IPv4,
    # docker hostnames, paths — are none of the wrapper's business beyond
    # the production-host check; they reach the helper byte-identical.
    pin_helper("#!/bin/sh\nexit 0\n")
    result = CliRunner().invoke(
        cli,
        [
            "gateway", "enroll",
            "--token-stdin",
            "--server", server,
            "--insecure-dev",
            "--dev-broker-issuer", "https://lab-broker.example",
        ],
    )
    assert _argv(exec_calls, result) == [
        "enroll",
        "--token-stdin",
        "--server", server,
        "--dev-broker-issuer", "https://lab-broker.example",
        "--insecure-dev",
    ]


def test_dev_broker_issuer_without_insecure_dev_is_refused_before_exec(
    exec_calls,
):
    result = CliRunner().invoke(
        cli,
        [
            "gateway", "enroll",
            "--token-stdin",
            "--dev-broker-issuer", "https://lab-broker.example",
        ],
    )
    assert result.exit_code != 0
    assert "--insecure-dev" in result.output
    # Nothing reached the helper: the refusal is local to the wrapper, and
    # without --insecure-dev the helper itself would refuse too (its
    # brokerPolicy guard) — the wrapper just fails earlier and clearer.
    assert exec_calls == []


def test_dev_broker_issuer_without_explicit_server_is_refused(exec_calls):
    # Insecure-dev alone is not enough: with no --server the helper would
    # target its built-in production gateway while trusting a lab issuer —
    # exactly the disclosure the wrapper must prevent.
    result = CliRunner().invoke(
        cli,
        [
            "gateway", "enroll",
            "--token-stdin",
            "--insecure-dev",
            "--dev-broker-issuer", "https://lab-broker.example",
        ],
    )
    assert result.exit_code != 0
    assert "--server" in result.output
    assert "production" in result.output
    assert exec_calls == []


@pytest.mark.parametrize("server", ["", "   ", "\t"])
def test_dev_broker_issuer_with_blank_server_is_refused(
    exec_calls, forbid_helper_launch, server
):
    # A blank explicit --server is NOT an explicit one: the Go helper's
    # ResolveServer("") falls back to its built-in production default, so
    # forwarding `--server ''` would aim a lab issuer at production while
    # the guard believed the target was lab. Refuse before any launch.
    result = CliRunner().invoke(
        cli,
        [
            "gateway", "enroll",
            "--token-stdin",
            "--server", server,
            "--insecure-dev",
            "--dev-broker-issuer", "https://lab-broker.example",
        ],
    )
    assert result.exit_code != 0, repr(server)
    assert "--server" in result.output
    assert "production" in result.output
    assert exec_calls == []


@pytest.mark.parametrize(
    "server",
    [
        "ws://[::1",  # unbalanced bracket (malformed IPv6 literal)
        "ws://[gateway.pocketshell.io]",  # bracketed non-IP
    ],
)
def test_dev_broker_issuer_with_unparseable_server_is_a_clear_usage_error(
    exec_calls, forbid_helper_launch, server
):
    # urlsplit raises ValueError on these; that must surface as a clean
    # usage error naming the flag — never a raw traceback, and never a
    # forward of a --server the wrapper could not check.
    result = CliRunner().invoke(
        cli,
        [
            "gateway", "enroll",
            "--token-stdin",
            "--server", server,
            "--insecure-dev",
            "--dev-broker-issuer", "https://lab-broker.example",
        ],
    )
    assert result.exit_code == 2, (server, result.output, result.exception)
    assert "--server" in result.output
    assert "not a valid URL" in result.output
    # No stack trace leaked to the operator.
    assert "Traceback" not in result.output
    assert not isinstance(result.exception, ValueError)
    assert exec_calls == []


@pytest.mark.parametrize(
    "server",
    [
        "wss://gateway.pocketshell.io",
        "https://gateway.pocketshell.io",
        "ws://GATEWAY.POCKETSHELL.IO:8080",
        "wss://gateway.pocketshell.io/some/path",
        # DNS-canonicalization regressions: the same host spelled with a
        # trailing FQDN dot or in other cases still resolves to production.
        "wss://gateway.pocketshell.io.",
        "WSS://GATEWAY.POCKETSHELL.IO",
        "wss://Gateway.Pocketshell.Io",
        # relay.pocketshell.io is the production gateway's legacy alias
        # (LegacyServerURL in the Go hostagent; still served there), so
        # every spelling of it must refuse too.
        "ws://relay.pocketshell.io",
        "wss://relay.pocketshell.io.",
        "ws://RELAY.POCKETSHELL.IO:8080",
        "wss://relay.pocketshell.io:8443/lab",
        # Ports and userinfo change nothing about the target host.
        "wss://gateway.pocketshell.io:8443",
        "wss://user@gateway.pocketshell.io",
    ],
)
def test_dev_broker_issuer_never_targets_the_production_gateway(
    pin_helper, exec_calls, forbid_helper_launch, server
):
    pin_helper("#!/bin/sh\nexit 0\n")
    result = CliRunner().invoke(
        cli,
        [
            "gateway", "enroll",
            "--token-stdin",
            "--server", server,
            "--insecure-dev",
            "--dev-broker-issuer", "https://lab-broker.example",
        ],
    )
    assert result.exit_code != 0, server
    assert "production" in result.output, server
    # Refused before any helper launch: nothing exec'd — and resolution
    # (the step before exec, where any network could begin) never ran,
    # because forbid_helper_launch would blow up if it did.
    assert exec_calls == []


def test_enroll_without_dev_broker_issuer_is_unaffected(pin_helper, exec_calls):
    # The production contract is untouched: no dev flags, no dev guard.
    pin_helper("#!/bin/sh\nexit 0\n")
    result = CliRunner().invoke(cli, ["gateway", "enroll", "--token-stdin"])
    assert _argv(exec_calls, result) == ["enroll", "--token-stdin"]


# ---------------------------------------------------------------------------
# --re-enroll forwarding
# ---------------------------------------------------------------------------


def test_re_enroll_forwarded_only_when_passed(pin_helper, exec_calls):
    pin_helper("#!/bin/sh\nexit 0\n")
    plain = CliRunner().invoke(cli, ["gateway", "enroll", "--token-stdin"])
    assert _argv(exec_calls, plain) == ["enroll", "--token-stdin"]

    again = CliRunner().invoke(
        cli, ["gateway", "enroll", "--token-stdin", "--re-enroll"]
    )
    assert _argv(exec_calls, again) == ["enroll", "--token-stdin", "--re-enroll"]


def test_re_enroll_and_dev_broker_issuer_are_enroll_only(pin_helper, exec_calls):
    # run/show must not grow enroll-only flags: Click rejects the option and
    # the builder rejects the kwarg, so nothing is ever exec'd with them.
    pin_helper("#!/bin/sh\nexit 0\n")
    runner = CliRunner()
    for command in ("run", "show"):
        result = runner.invoke(cli, ["gateway", command, "--re-enroll"])
        assert result.exit_code != 0, command
        assert exec_calls == []


def test_enroll_help_documents_the_dev_issuer_guard():
    result = CliRunner().invoke(cli, ["gateway", "enroll", "--help"])
    assert result.exit_code == 0, result.output
    assert "--re-enroll" in result.output
    assert "--dev-broker-issuer" in result.output
    # The guard contract is visible in help, not buried in a man page.
    assert "--insecure-dev" in result.output


# ---------------------------------------------------------------------------
# server URL shapes the helper actually supports (forwarded verbatim)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "server",
    [
        "wss://gateway.example/api/v1",  # base URL with a path
        "ws://[2001:db8::1]:8080",  # IPv6 literal (docker/lab networks)
        "wss://[::1]:8443/tunnel",  # IPv6 loopback with path
    ],
)
def test_server_urls_with_ipv6_and_paths_forward_verbatim(
    pin_helper, exec_calls, server
):
    # The wrapper does not parse or rewrite --server: whatever the operator
    # typed — IPv6 literals, paths, ports — arrives at the helper as ONE
    # argv element for the helper's own NormalizeServerURL to judge.
    pin_helper("#!/bin/sh\nexit 0\n")
    result = CliRunner().invoke(
        cli, ["gateway", "run", "--server", server, "--insecure-dev"]
    )
    assert _argv(exec_calls, result) == [
        "run",
        "--server", server,
        "--insecure-dev",
    ]
