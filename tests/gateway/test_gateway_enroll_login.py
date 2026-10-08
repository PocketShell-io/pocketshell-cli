"""`gateway enroll` without --token-stdin: token minted from `pocketshell login`
and delivered to the helper ONLY on a private stdin pipe."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from click.testing import CliRunner

from conftest import FAKE_JWT
from pocketshell.cli import cli
from pocketshell.gateway import helper as gateway_helper


@pytest.fixture
def pipe_exec(monkeypatch):
    calls = []

    def fake(helper, argv, token):
        calls.append((helper, argv, token))
        raise SystemExit(0)

    monkeypatch.setattr(gateway_helper, "exec_helper_with_stdin_token", fake)
    return calls


def test_logged_in_enroll_mints_and_pipes(pin_helper, fake_account, pipe_exec, exec_calls):
    helper = pin_helper("#!/bin/sh\nexit 0\n")
    result = CliRunner().invoke(cli, ["gateway", "enroll", "--device-id", "home-lab"])
    assert result.exit_code == 0, result.output
    assert pipe_exec == [(helper, ["enroll", "--token-stdin", "--device-id", "home-lab"], FAKE_JWT)]
    assert exec_calls == []
    assert FAKE_JWT not in result.output


def test_token_stdin_path_is_unchanged(pin_helper, fake_account, pipe_exec, exec_calls):
    pin_helper("#!/bin/sh\nexit 0\n")
    result = CliRunner().invoke(cli, ["gateway", "enroll", "--token-stdin"])
    assert result.exit_code == 0, result.output
    assert exec_calls[-1][1] == ["enroll", "--token-stdin"]
    assert pipe_exec == []
    assert fake_account.calls == 0


def test_not_logged_in(pin_helper, fake_account, pipe_exec):
    pin_helper("#!/bin/sh\nexit 0\n")
    fake_account.error = fake_account.module.NotLoggedIn("no session")
    result = CliRunner().invoke(cli, ["gateway", "enroll"])
    assert result.exit_code == 3
    assert "pocketshell login" in result.output
    assert "--token-stdin" in result.output
    assert pipe_exec == []


def test_helper_is_verified_before_minting(fake_account, pipe_exec):
    result = CliRunner().invoke(cli, ["gateway", "enroll"])
    assert result.exit_code == 127
    assert fake_account.calls == 0


def test_incompatible_helper_refused_before_minting(pin_helper, fake_account, pipe_exec):
    pin_helper("#!/bin/sh\nexit 0\n", version_json='{"version":"x","protocol":"old","commit":"c"}')
    result = CliRunner().invoke(cli, ["gateway", "enroll"])
    assert result.exit_code == 126
    assert fake_account.calls == 0


@pytest.mark.parametrize(
    "args",
    [
        ["--server", "wss://lab.example"],  # non-production, not vouched for
        ["--server", "wss://lab.example", "--trust-gateway", "other.example"],
        ["--server", "ws://lab.example", "--insecure-dev", "--trust-gateway", "lab.example"],
        ["--server", "ws://127.0.0.1:8080"],  # cleartext without --insecure-dev
        [
            "--server", "ws://127.0.0.1:8080", "--insecure-dev",
            "--trust-gateway", "127.0.0.1", "--dev-broker-issuer", "https://lab",
        ],
    ],
)
def test_auto_mint_target_refusals(pin_helper, fake_account, pipe_exec, args):
    pin_helper("#!/bin/sh\nexit 0\n")
    result = CliRunner().invoke(cli, ["gateway", "enroll", *args])
    assert result.exit_code == 2, result.output
    assert fake_account.calls == 0
    assert pipe_exec == []


def test_trusted_lab_server_is_forwarded_verbatim(pin_helper, fake_account, pipe_exec):
    pin_helper("#!/bin/sh\nexit 0\n")
    result = CliRunner().invoke(
        cli,
        ["gateway", "enroll", "--server", "ws://127.0.0.1:8080", "--insecure-dev",
         "--trust-gateway", "127.0.0.1"],
    )
    assert result.exit_code == 0, result.output
    assert pipe_exec[0][1] == [
        "enroll", "--token-stdin", "--server", "ws://127.0.0.1:8080", "--insecure-dev",
    ]


# --- the real exec boundary ----------------------------------------------------

RECORDER = """#!{python}
import json, os, sys
if sys.argv[1:2] == ["version"]:
    print(json.dumps({{"version": "devel", "protocol": "pocketshell-tunnel-v1", "commit": "x"}}))
    sys.exit(0)
data = sys.stdin.buffer.read()
json.dump({{
    "argv": sys.argv[1:],
    "stdin": data.decode("latin-1"),
    "env": dict(os.environ),
    "fds": sorted(int(f) for f in os.listdir("/proc/self/fd")) if os.path.isdir("/proc/self/fd") else None,
}}, open(os.environ["RECORD_FILE"], "w"))
"""

DRIVER = textwrap.dedent(
    """
    import dataclasses, sys, types
    m = types.ModuleType("pocketshell.account")
    class AccountError(Exception): pass
    class NotLoggedIn(AccountError): pass
    @dataclasses.dataclass(frozen=True)
    class GatewayToken:
        token: str
        expires_at: int
    m.AccountError, m.NotLoggedIn, m.GatewayToken = AccountError, NotLoggedIn, GatewayToken
    m.mint_gateway_token = lambda *, broker_url=None: GatewayToken({token!r}, 2000000000)
    sys.modules["pocketshell.account"] = m
    from pocketshell.cli import main
    sys.argv = ["pocketshell", "gateway", "enroll", "--device-id", "home-lab"]
    sys.exit(main())
    """
)


def test_token_reaches_helper_only_on_stdin(tmp_path):
    record = tmp_path / "record.json"
    helper = tmp_path / "pocketshell-link"
    helper.write_text(RECORDER.format(python=sys.executable))
    helper.chmod(0o755)
    token = FAKE_JWT
    env = {
        **os.environ,
        "POCKETSHELL_GATEWAY_HELPER": str(helper),
        "RECORD_FILE": str(record),
    }
    proc = subprocess.run(
        [sys.executable, "-c", DRIVER.format(token=token)],
        input=b"PARENT-STDIN-MUST-NOT-LEAK",
        capture_output=True, env=env, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    rec = json.loads(Path(record).read_text())
    assert rec["stdin"] == token + "\n"
    assert rec["argv"] == ["enroll", "--token-stdin", "--device-id", "home-lab"]
    assert all(token not in v for v in rec["env"].values())
    assert token.encode() not in proc.stdout + proc.stderr
    if rec["fds"] is not None:
        # no stray inherited pipe ends beyond stdio (+ the listing's own fd)
        assert [f for f in rec["fds"] if f > 2] in ([], [3])
