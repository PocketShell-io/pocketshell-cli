"""`gateway enroll` without --token-stdin: token minted from `pocketshell login`
and delivered to the helper ONLY on a private stdin pipe.

Uses the real account module against the local fake broker
(tests/fake_broker.py); nothing inside pocketshell.account is replaced.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from pocketshell.account import credentials
from pocketshell.cli import cli
from pocketshell.gateway import helper as gateway_helper
from tests.fake_broker import DEVICE_CODE, SESSION_TOKEN

MINT_PATH = "/cli/gateway/token"


@pytest.fixture
def pipe_exec(monkeypatch):
    calls = []

    def fake(helper, argv, token):
        calls.append((helper, argv, token))
        raise SystemExit(0)

    monkeypatch.setattr(gateway_helper, "exec_helper_with_stdin_token", fake)
    return calls


@pytest.fixture
def logged_in(fake_broker):
    """A stored session for the fake broker, as `pocketshell login` leaves it
    (the full device flow runs in test_token_reaches_helper_only_on_stdin)."""
    credentials.save(
        credentials.Credentials(
            broker_url=fake_broker.url,
            access_token=SESSION_TOKEN,
            token_id="tok_123",
            email="me@example.com",
            expires_at=int(time.time()) + 3600,
            label="me@laptop",
        )
    )
    return fake_broker


def _mints(broker) -> int:
    return len(broker.requests_to(MINT_PATH))


def test_logged_in_enroll_mints_and_pipes(pin_helper, logged_in, pipe_exec, exec_calls):
    helper = pin_helper("#!/bin/sh\nexit 0\n")
    result = CliRunner().invoke(cli, ["gateway", "enroll", "--device-id", "home-lab"])
    assert result.exit_code == 0, result.output
    assert pipe_exec == [
        (helper, ["enroll", "--token-stdin", "--device-id", "home-lab"], logged_in.gateway_jwt)
    ]
    assert exec_calls == []
    [mint] = logged_in.requests_to(MINT_PATH)
    assert mint["headers"]["Authorization"] == f"Bearer {SESSION_TOKEN}"
    assert logged_in.gateway_jwt not in result.output
    assert SESSION_TOKEN not in result.output


def test_token_stdin_path_is_unchanged(pin_helper, logged_in, pipe_exec, exec_calls):
    pin_helper("#!/bin/sh\nexit 0\n")
    result = CliRunner().invoke(cli, ["gateway", "enroll", "--token-stdin"])
    assert result.exit_code == 0, result.output
    assert exec_calls[-1][1] == ["enroll", "--token-stdin"]
    assert pipe_exec == []
    assert logged_in.requests == []


def test_not_logged_in(pin_helper, fake_broker, pipe_exec):
    pin_helper("#!/bin/sh\nexit 0\n")
    result = CliRunner().invoke(cli, ["gateway", "enroll"])
    assert result.exit_code == 3
    assert "pocketshell login" in result.output
    assert "--token-stdin" in result.output
    assert ".." not in result.output
    assert pipe_exec == []
    assert fake_broker.requests == []


def test_session_revoked_on_the_broker_is_not_logged_in(pin_helper, logged_in, pipe_exec):
    pin_helper("#!/bin/sh\nexit 0\n")
    logged_in.logged_out = True  # the broker answers 401
    result = CliRunner().invoke(cli, ["gateway", "enroll"])
    assert result.exit_code == 3, result.output
    assert "no longer valid" in result.output
    assert pipe_exec == []
    assert SESSION_TOKEN not in result.output


def test_broker_refusal_is_a_plain_error(pin_helper, logged_in, pipe_exec):
    pin_helper("#!/bin/sh\nexit 0\n")
    logged_in.overrides[("POST", MINT_PATH)] = (403, {"error": "account_not_allowed"})
    result = CliRunner().invoke(cli, ["gateway", "enroll"])
    assert result.exit_code == 1, result.output
    assert "could not get a gateway token" in result.output
    assert "HTTP 403" in result.output
    assert pipe_exec == []


def test_helper_is_verified_before_minting(logged_in, pipe_exec, monkeypatch, tmp_path):
    # No helper anywhere: an empty PATH, no pin, no wheel — so a real
    # pocketshell-link installed on the test machine cannot satisfy discovery.
    monkeypatch.delenv("POCKETSHELL_GATEWAY_HELPER", raising=False)
    monkeypatch.setenv("PATH", str(tmp_path))
    result = CliRunner().invoke(cli, ["gateway", "enroll"])
    assert result.exit_code == 127
    assert _mints(logged_in) == 0


def test_incompatible_helper_refused_before_minting(pin_helper, logged_in, pipe_exec):
    pin_helper("#!/bin/sh\nexit 0\n", version_json='{"version":"x","protocol":"old","commit":"c"}')
    result = CliRunner().invoke(cli, ["gateway", "enroll"])
    assert result.exit_code == 126
    assert _mints(logged_in) == 0


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
def test_auto_mint_target_refusals(pin_helper, logged_in, pipe_exec, args):
    pin_helper("#!/bin/sh\nexit 0\n")
    result = CliRunner().invoke(cli, ["gateway", "enroll", *args])
    assert result.exit_code == 2, result.output
    assert logged_in.requests == []
    assert pipe_exec == []


def test_trusted_lab_server_is_forwarded_verbatim(pin_helper, logged_in, pipe_exec):
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
    # The gateway's --insecure-dev never redirects the session: it still
    # went only to the broker stored at login.
    assert [r["path"] for r in logged_in.requests] == [MINT_PATH]


# --- the real exec boundary, after a real `pocketshell login` -------------------

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



def _pocketshell(env, *args, stdin: bytes = b""):
    return subprocess.run(
        [sys.executable, "-m", "pocketshell", *args],
        input=stdin, capture_output=True, env=env, timeout=60,
    )


def test_token_reaches_helper_only_on_stdin(tmp_path, fake_broker):
    record = tmp_path / "record.json"
    helper = tmp_path / "pocketshell-link"
    helper.write_text(RECORDER.format(python=sys.executable))
    helper.chmod(0o755)
    env = {**os.environ}  # isolated HOME/XDG + the fake broker URL/insecure-dev flag

    fake_broker.start_response["interval"] = 1  # pending once, then approved
    login = _pocketshell(env, "login", "--no-open")
    assert login.returncode == 0, login.stderr
    assert b"Logged in as me@example.com." in login.stdout

    env.update({"POCKETSHELL_GATEWAY_HELPER": str(helper), "RECORD_FILE": str(record)})
    proc = _pocketshell(
        env, "gateway", "enroll", "--device-id", "home-lab",
        stdin=b"PARENT-STDIN-MUST-NOT-LEAK",
    )
    assert proc.returncode == 0, proc.stderr
    token = fake_broker.gateway_jwt
    [mint] = fake_broker.requests_to(MINT_PATH)
    assert mint["headers"]["Authorization"] == f"Bearer {SESSION_TOKEN}"
    rec = json.loads(Path(record).read_text())
    assert rec["stdin"] == token + "\n"
    assert rec["argv"] == ["enroll", "--token-stdin", "--device-id", "home-lab"]
    for secret in (token, SESSION_TOKEN):
        assert all(secret not in v for v in rec["env"].values())
        assert all(secret not in a for a in rec["argv"])
    for out in (login.stdout + login.stderr, proc.stdout + proc.stderr):
        for secret in (token, SESSION_TOKEN, DEVICE_CODE):
            assert secret.encode() not in out
    if rec["fds"] is not None:
        # no stray inherited pipe ends beyond stdio (+ the listing's own fd)
        assert [f for f in rec["fds"] if f > 2] in ([], [3])
