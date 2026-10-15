"""`pocketshell gateway auth show|set`: passthrough to `pocketshell-link gateway-auth`.

The Click layer builds the exact helper argv and leaves validation of the
policy and keys to the helper; the subprocess test proves public keys on
stdin reach the helper byte-identically through the real exec boundary.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest
from click.testing import CliRunner

from pocketshell.cli import cli
from pocketshell.gateway.cli import build_gateway_auth_argv

pytestmark = pytest.mark.usefixtures("exec_calls")


def _argv(exec_calls, result) -> list[str]:
    assert result.exit_code == 0, (result.output, result.exception)
    return exec_calls[-1][1]


def test_auth_is_listed_in_gateway_help():
    result = CliRunner().invoke(cli, ["gateway", "--help"])
    assert result.exit_code == 0
    assert "auth" in result.output


def test_show_forwards_only_passed_flags(pin_helper, exec_calls):
    pin_helper("#!/bin/sh\nexit 0\n")
    assert _argv(exec_calls, CliRunner().invoke(cli, ["gateway", "auth", "show"])) == ["gateway-auth", "show"]
    full = CliRunner().invoke(cli, ["gateway", "auth", "show", "--json", "--config-dir", "/tmp/state dir"])
    assert _argv(exec_calls, full) == ["gateway-auth", "show", "--json", "--config-dir", "/tmp/state dir"]


@pytest.mark.parametrize("policy", ["host", "managed", "both"])
def test_set_forwards_policy_and_keys_stdin(pin_helper, exec_calls, policy):
    pin_helper("#!/bin/sh\nexit 0\n")
    result = CliRunner().invoke(cli, ["gateway", "auth", "set", "--policy", policy, "--keys-stdin", "--json"])
    assert _argv(exec_calls, result) == ["gateway-auth", "set", "--policy", policy, "--keys-stdin", "--json"]


def test_set_keys_only(pin_helper, exec_calls):
    pin_helper("#!/bin/sh\nexit 0\n")
    result = CliRunner().invoke(cli, ["gateway", "auth", "set", "--keys-stdin"])
    assert _argv(exec_calls, result) == ["gateway-auth", "set", "--keys-stdin"]


def test_set_refuses_bad_usage_before_exec(pin_helper, exec_calls):
    pin_helper("#!/bin/sh\nexit 0\n")
    nothing = CliRunner().invoke(cli, ["gateway", "auth", "set"])
    assert nothing.exit_code == 2 and not exec_calls
    bad = CliRunner().invoke(cli, ["gateway", "auth", "set", "--policy", "everything"])
    assert bad.exit_code == 2 and not exec_calls


def test_incompatible_helper_is_refused(pin_helper, exec_calls):
    pin_helper("#!/bin/sh\nexit 0\n", version_json='{"version":"x","protocol":"pocketshell-tunnel-v0","commit":"y"}')
    result = CliRunner().invoke(cli, ["gateway", "auth", "show"])
    assert result.exit_code == 126 and not exec_calls


def test_argv_builder_rejects_set_only_flags_for_show():
    with pytest.raises(ValueError):
        build_gateway_auth_argv("show", policy="host")
    with pytest.raises(ValueError):
        build_gateway_auth_argv("list")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX exec boundary")
def test_public_keys_reach_helper_stdin_through_exec(tmp_path):
    record = tmp_path / "record"
    helper = tmp_path / "pocketshell-link"
    helper.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = version ]; then\n"
        "  printf '{\"version\":\"devel\",\"protocol\":\"pocketshell-tunnel-v1\",\"commit\":\"unknown\"}\\n'; exit 0\n"
        "fi\n"
        "printf '%s\\n' \"$*\" > \"$RECORD\"\n"
        "cat >> \"$RECORD\"\n"
        "exit 3\n"
    )
    helper.chmod(0o755)
    keys = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleOnlyNotARealKeyForTests00000 vault:k1\n"
    proc = subprocess.run(
        [sys.executable, "-m", "pocketshell", "gateway", "auth", "set", "--policy", "managed", "--keys-stdin"],
        input=keys,
        capture_output=True,
        env={**os.environ, "POCKETSHELL_GATEWAY_HELPER": str(helper), "RECORD": str(record)},
        timeout=30,
        check=False,
    )
    assert proc.returncode == 3, proc.stderr
    assert record.read_bytes() == b"gateway-auth set --policy managed --keys-stdin\n" + keys


# --- `gateway enroll --gateway-auth-policy` -----------------------------------

_AUTH_STUB = """#!/bin/sh
if [ "$1" = "gateway-auth" ]; then
  echo "$@" >> "$AUTH_LOG"
  if [ "$2" = "show" ]; then
    echo '{"policy":"host","source":"default","endpoint":"","managed_keys":'"$MANAGED"'}'
    exit 0
  fi
  [ -n "$REFUSE" ] && { echo "$REFUSE" >&2; exit 1; }
  echo '{"policy":"both","source":"configured","endpoint":"","managed_keys":[]}'
  exit 0
fi
echo "$1 $2 $3" >> "$AUTH_LOG"
exit "${ENROLL_EXIT:-0}"
"""


@pytest.fixture
def auth_stub(pin_helper, tmp_path, monkeypatch):
    log = tmp_path / "auth.log"
    monkeypatch.setenv("AUTH_LOG", str(log))
    monkeypatch.setenv("MANAGED", "[]")
    monkeypatch.delenv("REFUSE", raising=False)
    monkeypatch.delenv("ENROLL_EXIT", raising=False)
    pin_helper(_AUTH_STUB)
    from pocketshell.gateway import private_endpoint
    monkeypatch.setattr(private_endpoint, "init", lambda: ["sshd", "-i", "-f", "/cfg"])
    return log


def _enroll(*extra):
    return CliRunner().invoke(cli, ["gateway", "enroll", "--token-stdin", "--config-dir", "/tmp/cfg", *extra])


def test_enroll_without_policy_never_touches_gateway_auth(auth_stub, exec_calls):
    result = _enroll()
    assert result.exit_code == 0 and exec_calls[-1][1][0] == "enroll"
    assert not auth_stub.exists()


def test_enroll_with_policy_enrolls_first_then_sets_it(auth_stub, exec_calls):
    result = _enroll("--gateway-auth-policy", "both")
    assert result.exit_code == 0, result.output
    # enroll ran as a child (not exec), then the policy was set
    assert not exec_calls
    assert auth_stub.read_text().splitlines() == [
        "enroll --token-stdin --config-dir",
        "gateway-auth set --policy both --json --config-dir /tmp/cfg",
    ]
    assert "gateway auth policy: both" in result.output


def test_enroll_failure_skips_policy(auth_stub, exec_calls, monkeypatch):
    monkeypatch.setenv("ENROLL_EXIT", "5")
    result = _enroll("--gateway-auth-policy", "both")
    assert result.exit_code == 5
    assert "gateway-auth" not in auth_stub.read_text()


def test_enroll_refuses_managed_without_keys(auth_stub, exec_calls):
    result = _enroll("--gateway-auth-policy", "managed")
    assert result.exit_code == 1 and "vault public keys first" in result.output
    assert not exec_calls
    assert auth_stub.read_text().splitlines() == ["gateway-auth show --json --config-dir /tmp/cfg"]


def test_enroll_managed_with_keys(auth_stub, exec_calls, monkeypatch):
    monkeypatch.setenv("MANAGED", '[{"type":"ssh-ed25519","fingerprint":"SHA256:x","comment":"vault:k"}]')
    result = _enroll("--gateway-auth-policy", "managed")
    assert result.exit_code == 0, result.output
    assert auth_stub.read_text().splitlines()[-1].startswith("gateway-auth set --policy managed")


def test_enroll_refuses_vault_policy_on_loopback_before_helper(auth_stub, exec_calls):
    result = _enroll("--ssh-host", "127.0.0.1:2222", "--gateway-auth-policy", "both")
    assert result.exit_code == 2 and "loopback" in result.output
    assert not exec_calls and not auth_stub.exists()


def test_enroll_reports_helper_refusal_after_enrolling(auth_stub, exec_calls, monkeypatch):
    monkeypatch.setenv("REFUSE", "sshd config sets AuthorizedKeysFile")
    result = _enroll("--gateway-auth-policy", "both")
    assert result.exit_code == 1
    assert "enrolled, but" in result.output and "AuthorizedKeysFile" in result.output
    assert "pocketshell gateway auth set --policy both" in result.output
