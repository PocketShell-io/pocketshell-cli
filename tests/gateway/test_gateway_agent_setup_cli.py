"""Setup ABI v3 CLI wiring (revision B, f41c5f01…): install FIRST with
--config-dir/--endpoint-inputs, then bind --manifest … --authority. The
generation/trust logic itself is covered with non-production fixtures in
test_gateway_endpoint_setup.py; here the agent commands must route to it."""

from __future__ import annotations

import json


import pytest

from pocketshell.gateway import service_agent_endpoint as eps
from pocketshell.gateway import service_agent_install as inst
from pocketshell.gateway import service_endpoint as ep
from pocketshell.gateway import service_user_agent as agent_mod

from test_gateway_service import QUALIFIED, WIN_CONFIG, WIN_HELPER, fake_windows  # noqa: F401
from test_gateway_service_endpoint import MANIFEST
from test_gateway_user_agent import agent, run  # noqa: F401

AUTHORITY = "C:\\Users\\owner\\AppData\\Roaming\\PocketShell\\managed-runtime\\authority.json"
ROWS = {"c:\\x": "1" * 64}


def bind_authority(manifest=MANIFEST):
    return run("bind", "--manifest", manifest, "--config-dir", WIN_CONFIG, "--helper", WIN_HELPER,
               "--authority", AUTHORITY, "--json")


@pytest.fixture
def authority(agent, monkeypatch):  # noqa: F811
    monkeypatch.setattr(ep, "ALLOWED_ENDPOINT_MANIFEST_SHA256", frozenset())  # the legacy path stays closed
    state = {"sha": "a" * 64, "calls": [], "receipt": {"version": 3, "endpoint": {"manifest": MANIFEST}}}

    def load(path, owner_sid, paths):
        assert path == AUTHORITY
        return state["receipt"], state["sha"], ROWS

    def trust(m, receipt, *, file_sha256, release_pins=None):
        state["calls"].append((m.path, receipt, release_pins))

    monkeypatch.setattr(eps, "load_authority", load)
    monkeypatch.setattr(ep, "check_trust_authority", trust)
    monkeypatch.setattr(agent_mod, "_native_paths", lambda api: object())
    return state


def test_bind_with_authority_trusts_the_recorded_manifest_and_records_the_authority(authority):
    result, data = bind_authority()
    assert result.exit_code == 0, result.output
    assert sorted(data["binding"]) == ["configDir", "deviceId", "manifest", "manifestSHA256", "port"]  # JSON v1
    stored = json.loads(agent_mod._read_private(agent_mod._path("binding.json")))
    assert stored["authority"] == AUTHORITY and stored["authoritySHA256"] == "a" * 64
    assert authority["calls"] and authority["calls"][0][2] == ROWS


def test_bind_without_authority_still_refuses_an_unreviewed_manifest(authority):
    result, data = run("bind", "--manifest", MANIFEST, "--config-dir", WIN_CONFIG, "--helper", WIN_HELPER, "--json")
    assert result.exit_code == 1 and data["error"]["code"] == "binding-refused"


def test_bind_refuses_a_manifest_that_is_not_the_authority_endpoint(authority):
    authority["receipt"] = {"version": 3, "endpoint": {"manifest": MANIFEST.replace("endpoint-manifest", "other")}}
    result, data = bind_authority()
    assert result.exit_code == 1 and data["error"]["code"] == "authority-invalid"
    assert not authority["calls"]


def test_bind_refuses_an_unusable_authority(authority, monkeypatch):
    def refuse(path, owner_sid, paths):
        raise inst.InstallError("authority-invalid", "the installed authority is unusable: test")

    monkeypatch.setattr(eps, "load_authority", refuse)
    result, data = bind_authority()
    assert result.exit_code == 1 and data["error"]["code"] == "authority-invalid"


def test_start_and_status_revalidate_the_authority(authority):
    assert bind_authority()[0].exit_code == 0
    calls = len(authority["calls"])
    result, data = run("status", "--json")
    assert result.exit_code == 4, result.output  # stopped, trusted through the authority
    authority["sha"] = "b" * 64  # authority.json replaced after bind
    result, data = run("start", "--json")
    assert result.exit_code == 1 and data["error"]["code"] == "binding-invalid"
    assert "authority" in data["error"]["message"]
    assert len(authority["calls"]) >= calls


def test_install_needs_both_endpoint_flags():
    result = run("install", "--user-data", "C:\\u", "--catalog", "C:\\c.json", "--staged", "C:\\s",
                 "--config-dir", WIN_CONFIG, "--json")[0]
    assert result.exit_code == 2


def test_install_first_routes_to_the_endpoint_installer_without_a_binding(agent, monkeypatch, tmp_path):  # noqa: F811
    inputs = tmp_path / "endpoint-inputs.json"
    inputs.write_bytes(b'{"version":1}')
    seen = {}

    def fake_install(**kw):
        seen.update(kw)
        return {"version": 3}

    monkeypatch.setattr(eps, "install_endpoint_runtime", fake_install)
    monkeypatch.setattr(eps, "local_account", lambda sid: "owner")
    from pocketshell.gateway import service_windows as win

    real = win.validate_path
    monkeypatch.setattr(win, "validate_path", lambda p, what: p if p == str(inputs) else real(p, what))
    doc, code = agent_mod.install_command(user_data="C:\\u", catalog="C:\\c.json", staged="C:\\s", dry_run=False,
                                          api=agent["api"], runner=None, paths=object(), folders={"x": 1},
                                          config_dir=WIN_CONFIG, endpoint_inputs=str(inputs))
    assert code == 0 and doc["ok"] and doc["receipt"] == {"version": 3}, doc
    assert seen["config_dir"] == WIN_CONFIG and seen["endpoint_inputs"] == b'{"version":1}'
    assert seen["account"] == "owner" and seen["owner_sid"] == agent["api"].current_sid()
    text, digest = seen["show"](WIN_HELPER)  # the reviewed helper's show of the enrollment
    assert "pinned ssh host key" in text and digest == QUALIFIED
