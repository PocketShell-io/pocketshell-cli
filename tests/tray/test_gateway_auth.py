"""Tray gateway key policy (key vault): parsing, refusals, menu, actions."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from pocketshell.tray import gateway_auth as ga
from pocketshell.tray.app import TrayApp
from pocketshell.tray.model import TrayModel

ED = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJw6s36jWdJ+ZQ8yW7FK2n7Aj/ENs1GpBxm/h40D+cEs"
KEY = ga.ManagedKey("ssh-ed25519", "SHA256:Jw6s36jWdJ+ZQ8yW7FK2n7Aj/ENs1GpBxm/h40D+cEs", "vault:k1")


def state(policy="host", endpoint="exec", keys=(), source="configured"):
    return ga.GatewayAuthState(policy=policy, source=source, endpoint=endpoint, managed_keys=tuple(keys))


@pytest.fixture(autouse=True)
def posix_platform(monkeypatch):
    monkeypatch.setattr(ga.sys, "platform", "linux")


# --- parsing ---------------------------------------------------------------


def test_parse_show_output_reads_contract_fields():
    line = json.dumps({"policy": "both", "source": "configured", "endpoint": "exec",
                       "managed_keys": [{"type": KEY.type, "fingerprint": KEY.fingerprint, "comment": "vault:k1"}]})
    parsed = ga.parse_show_output("warning: something\n" + line + "\n")
    assert parsed == state("both", keys=[KEY])
    assert parsed.summary == "Key policy: both"
    assert KEY.fingerprint in parsed.managed_keys[0].display_line


def test_parse_show_output_default_policy_summary():
    parsed = ga.parse_show_output('{"policy":"host","source":"default","endpoint":"","managed_keys":[]}')
    assert parsed.summary == "Key policy: host, default"


@pytest.mark.parametrize("text", ["", "not json", '["host"]', '{"policy":"everything"}',
                                  '{"policy":"host","managed_keys":"x"}', '{"policy":"host","managed_keys":[1]}'])
def test_parse_show_output_refuses_unexpected(text):
    with pytest.raises(ga.GatewayAuthError):
        ga.parse_show_output(text)


# --- refusals --------------------------------------------------------------


def test_host_is_always_allowed_when_readable():
    assert ga.policy_refusal(state("managed", "loopback"), "host") is None


@pytest.mark.parametrize("policy", ["managed", "both"])
def test_loopback_endpoint_refuses_vault_policies(policy):
    assert ga.policy_refusal(state(endpoint="loopback", keys=[KEY]), policy) == ga.WINDOWS_HOST_ONLY


@pytest.mark.parametrize("policy", ["managed", "both"])
def test_windows_refuses_vault_policies_even_if_endpoint_unknown(monkeypatch, policy):
    monkeypatch.setattr(ga.sys, "platform", "win32")
    assert ga.policy_refusal(state(endpoint="exec", keys=[KEY]), policy) == ga.WINDOWS_HOST_ONLY


def test_managed_without_keys_is_refused_to_avoid_lockout():
    assert "No vault public keys" in ga.policy_refusal(state(endpoint="exec"), "managed")
    assert ga.policy_refusal(state(endpoint="exec"), "both") is None
    assert ga.policy_refusal(state(endpoint="exec", keys=[KEY]), "managed") is None


def test_unenrolled_and_unreadable_states_refuse():
    assert "Enroll" in ga.policy_refusal(state(endpoint=""), "both")
    assert "could not be read" in ga.policy_refusal(ga.GatewayAuthState.unavailable("boom"), "host")


# --- public key prefilter --------------------------------------------------


def test_prefilter_accepts_public_lines_and_skips_comments():
    text = f"# vault keys\n\n{ED} vault:k1\n  ssh-rsa AAAAB3Nza other  \n"
    assert ga.prefilter_public_keys(text) == [f"{ED} vault:k1", "ssh-rsa AAAAB3Nza other"]


def test_prefilter_refuses_private_key_without_echoing_it():
    secret = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA-SECRET\n-----END OPENSSH PRIVATE KEY-----"
    with pytest.raises(ga.GatewayAuthError) as exc:
        ga.prefilter_public_keys(secret)
    assert "PRIVATE" in str(exc.value) and "SECRET" not in str(exc.value)


@pytest.mark.parametrize("line,needle", [
    (f'command="id" {ED}', "options"),
    ("ssh-ed25519-cert-v01@openssh.com AAAA", "certificates"),
    ("ssh-ed25519", "missing"),
])
def test_prefilter_refuses_options_certs_and_bare_types(line, needle):
    with pytest.raises(ga.GatewayAuthError, match=needle):
        ga.prefilter_public_keys(line)


def test_prefilter_limits():
    with pytest.raises(ga.GatewayAuthError, match="Too many"):
        ga.prefilter_public_keys("\n".join(f"{ED} k{i}" for i in range(65)))
    with pytest.raises(ga.GatewayAuthError, match="KiB"):
        ga.prefilter_public_keys("#" * (64 * 1024 + 1))


# --- menu ------------------------------------------------------------------


def flatten(spec):
    yield spec
    for child in spec.children:
        yield from flatten(child)


def test_menu_shows_policy_choices_and_fingerprints_only():
    spec = ga.menu_spec(state("both", keys=[KEY]))
    assert spec.text == "Key policy: both"
    checked = [s.action_id for s in flatten(spec) if s.checked]
    assert checked == ["gateway_auth_policy:both"]
    texts = [s.text for s in flatten(spec)]
    assert any(KEY.fingerprint in t for t in texts)
    assert not any("AAAA" in t for t in texts)
    actions = {s.action_id for s in flatten(spec)}
    assert {"gateway_auth_import_clipboard", "gateway_auth_import_file", "gateway_auth_clear"} <= actions


def test_menu_on_loopback_explains_and_hides_import():
    spec = ga.menu_spec(state("host", "loopback"))
    actions = {s.action_id for s in flatten(spec)}
    assert "gateway_auth_explain" in actions
    assert "gateway_auth_import_clipboard" not in actions


def test_menu_unavailable_and_pending():
    assert ga.menu_spec(None).enabled is False
    spec = ga.menu_spec(ga.GatewayAuthState.unavailable("helper predates gateway-auth"))
    assert spec.text == "Key policy: unknown"
    assert any("predates" in s.text for s in flatten(spec))


# --- client ----------------------------------------------------------------


def fake_run(stdout="", stderr="", rc=0, calls=None):
    def run(cmd, **kwargs):
        if calls is not None:
            calls.append((cmd, kwargs.get("input")))
        return subprocess.CompletedProcess(cmd, rc, stdout.encode(), stderr.encode())
    return run


def test_client_set_policy_prechecks_before_running(monkeypatch):
    calls = []
    monkeypatch.setattr(ga.subprocess, "run", fake_run(calls=calls))
    client = ga.GatewayAuthClient(command=["link", "gateway-auth"])
    with pytest.raises(ga.GatewayAuthError, match="loopback"):
        client.set_policy(state(endpoint="loopback"), "managed")
    assert calls == []


def test_client_keys_go_on_stdin_never_argv(monkeypatch):
    calls = []
    out = '{"policy":"both","source":"configured","endpoint":"exec","managed_keys":[]}'
    monkeypatch.setattr(ga.subprocess, "run", fake_run(stdout=out, calls=calls))
    client = ga.GatewayAuthClient(command=["link", "gateway-auth"], config_dir="/cfg")
    client.replace_managed_keys(state("both"), [f"{ED} vault:k1"])
    cmd, stdin = calls[0]
    assert cmd == ["link", "gateway-auth", "set", "--keys-stdin", "--json", "--config-dir", "/cfg"]
    assert stdin == f"{ED} vault:k1\n".encode()
    assert not any("AAAA" in part for part in cmd)


def test_client_refuses_clearing_keys_under_managed(monkeypatch):
    monkeypatch.setattr(ga.subprocess, "run", fake_run())
    with pytest.raises(ga.GatewayAuthError, match="vault-only"):
        ga.GatewayAuthClient().replace_managed_keys(state("managed", keys=[KEY]), [])


def test_client_show_reports_helper_errors_as_unavailable(monkeypatch):
    monkeypatch.setattr(ga.subprocess, "run", fake_run(stderr="flag provided but not defined\nusage", rc=2))
    shown = ga.GatewayAuthClient().show()
    assert not shown.available and shown.error == "usage"


def test_client_set_failure_raises_last_stderr_line(monkeypatch):
    monkeypatch.setattr(ga.subprocess, "run", fake_run(stderr="managed keys: line 1: key options are not allowed",
                                                       rc=1))
    with pytest.raises(ga.GatewayAuthError, match="key options"):
        ga.GatewayAuthClient().set_policy(state("host"), "both")


# --- tray actions ----------------------------------------------------------


class FakeDialogs:
    def __init__(self, confirm=True, clipboard=None, file_text=None):
        self.answer = confirm
        self.clipboard = clipboard
        self.file_text = file_text
        self.infos: list[str] = []
        self.questions: list[str] = []

    def info(self, text):
        self.infos.append(text)

    def confirm(self, text):
        self.questions.append(text)
        return self.answer

    def read_clipboard(self):
        return self.clipboard

    def choose_file(self, title):
        return self.file_text


def make_app(current, dialogs, result=None):
    client = MagicMock()
    client.show.return_value = current
    client.set_policy.return_value = result or current
    client.replace_managed_keys.return_value = result or current
    app = TrayApp(status_client=MagicMock(), autostart_checker=lambda: False,
                  gateway_auth_client=client, dialogs=dialogs, initial_model=TrayModel(state="online"))
    app.notify = MagicMock()
    return app, client


def test_set_policy_confirms_then_applies():
    dialogs = FakeDialogs()
    app, client = make_app(state("host", keys=[KEY]), dialogs, result=state("both", keys=[KEY]))
    assert app.do_set_gateway_auth_policy("both") is True
    client.set_policy.assert_called_once()
    assert app.gateway_auth.policy == "both"
    assert "Host keys and vault keys" in dialogs.questions[0]


def test_set_policy_cancelled_does_nothing():
    app, client = make_app(state("host"), FakeDialogs(confirm=False))
    assert app.do_set_gateway_auth_policy("both") is False
    client.set_policy.assert_not_called()


def test_set_policy_refused_on_windows_with_explanation(monkeypatch):
    monkeypatch.setattr(ga.sys, "platform", "win32")
    dialogs = FakeDialogs()
    app, client = make_app(state("host", "loopback"), dialogs)
    assert app.do_set_gateway_auth_policy("managed") is False
    client.set_policy.assert_not_called()
    assert dialogs.questions == [] and ga.WINDOWS_HOST_ONLY in dialogs.infos[0]


def test_helper_refusal_is_shown_and_state_refreshed():
    dialogs = FakeDialogs()
    app, client = make_app(state("host"), dialogs)
    client.set_policy.side_effect = ga.GatewayAuthError("sshd config conflicts")
    assert app.do_set_gateway_auth_policy("both") is False
    assert "sshd config conflicts" in dialogs.infos[0]


def test_import_from_clipboard_replaces_managed_set():
    dialogs = FakeDialogs(clipboard=f"{ED} vault:k1\n")
    app, client = make_app(state("both"), dialogs, result=state("both", keys=[KEY]))
    assert app.do_import_managed_keys("clipboard") is True
    _current, lines = client.replace_managed_keys.call_args.args
    assert lines == [f"{ED} vault:k1"]
    assert "PUBLIC" in dialogs.questions[0] and "AAAA" not in dialogs.questions[0]


def test_import_refuses_private_key_before_confirming():
    dialogs = FakeDialogs(file_text="-----BEGIN OPENSSH PRIVATE KEY-----\nxx\n")
    app, client = make_app(state("both"), dialogs)
    assert app.do_import_managed_keys("file") is False
    client.replace_managed_keys.assert_not_called()
    assert dialogs.questions == []


def test_import_refused_on_loopback():
    dialogs = FakeDialogs(clipboard=f"{ED} k")
    app, client = make_app(state("host", "loopback"), dialogs)
    assert app.do_import_managed_keys("clipboard") is False
    assert dialogs.infos == [ga.WINDOWS_HOST_ONLY]


def test_menu_specs_insert_policy_submenu_after_sessions():
    app, _ = make_app(state("host"), FakeDialogs())
    app.refresh_gateway_auth()
    texts = [s.text for s in app.menu_specs()]
    assert texts[2].startswith("Sessions") and texts[3] == "Key policy: host"


def test_not_installed_skips_helper():
    app, client = make_app(state("host"), FakeDialogs())
    app.model = TrayModel(state="not_installed")
    assert app.refresh_gateway_auth().available is False
    client.show.assert_not_called()


# --- real helper (pocketshell-gateway >= 70f5a4b) ---------------------------

REAL_HELPER = os.environ.get("POCKETSHELL_TEST_GATEWAY_AUTH_HELPER")


@pytest.mark.skipif(not REAL_HELPER, reason="set POCKETSHELL_TEST_GATEWAY_AUTH_HELPER to a pocketshell-link build")
def test_real_helper_round_trip(tmp_path: Path):
    if not shutil.which("ssh-keygen"):
        pytest.skip("ssh-keygen unavailable")
    key = tmp_path / "k"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "vault:t", "-f", str(key)], check=True)
    client = ga.GatewayAuthClient(command=[REAL_HELPER, "gateway-auth"], config_dir=str(tmp_path / "cfg"))
    first = client.show()
    assert first.available and first.policy == "host" and first.source == "default"
    lines = ga.prefilter_public_keys(key.with_suffix(".pub").read_text())
    after = client.replace_managed_keys(first, lines)
    assert [k.comment for k in after.managed_keys] == ["vault:t"]
    assert after.managed_keys[0].fingerprint.startswith("SHA256:")
    # Unenrolled config dir: endpoint is "", so the tray refuses vault policies.
    assert ga.policy_refusal(after, "both") is not None


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX quoting")
def test_module_imports_without_gui():
    subprocess.run([sys.executable, "-c", "import pocketshell.tray.gateway_auth, pocketshell.tray.dialogs"],
                   check=True)


def test_policy_refresh_failure_never_breaks_status_polling():
    app, client = make_app(state("host"), FakeDialogs())
    client.show.side_effect = RuntimeError("binding unreadable")
    app.status_client.fetch_status.return_value = TrayModel(state="online", summary="ok")
    assert app.poll_once().state == "online"
    assert app.gateway_auth.error == "refresh failed"
