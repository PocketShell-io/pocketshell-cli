import hashlib
import json
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from pocketshell import tray_bundle, tray_repair
from pocketshell.gateway import service_agent_endpoint as eps
from pocketshell.gateway import service_agent_install as inst
from pocketshell.gateway import service_user_agent as agent
from pocketshell.gateway import service_windows as win


@pytest.mark.parametrize("interrupted", [False, True])
def test_upgrade_preserves_keys_and_enrollment_and_resumes(tmp_path, monkeypatch, interrupted):
    root = tmp_path / "runtime"
    root.mkdir()
    (tmp_path / "host-runtime-catalog.json").write_text("{}")
    authority = str(tmp_path / "managed-runtime/authority.json")
    binding = {"authority": authority, "authoritySHA256": "old-sha", "enrolled": True,
               "deviceId": "same-device", "manifestSHA256": "old-manifest", "configDir": "enrollment"}
    keys = {"mode": "generated", "hostKey": "private-key-path", "authorizedKeys": "allowed-path",
            "hostKeyPublic": "same-public-key", "hostKeyFingerprint": "same-fingerprint"}
    receipt = {"keys": keys}
    store = {}
    events = []
    monkeypatch.setattr(tray_bundle, "home", lambda: tmp_path)
    monkeypatch.setattr(agent, "_path", lambda name: str(tmp_path / name))
    monkeypatch.setattr(agent, "_OperationLock", nullcontext)
    monkeypatch.setattr(agent, "_read_private", lambda path: store.get(path))
    monkeypatch.setattr(agent, "_write_private", lambda path, data: (store.__setitem__(path, data),
                                                                 __import__("pathlib").Path(path).write_bytes(data)))
    monkeypatch.setattr(agent, "load_binding", lambda **kw: (binding, None, None))
    monkeypatch.setattr(agent, "_binding_sha256", lambda: "expected-binding")
    monkeypatch.setattr(agent, "_expect_prior", lambda expect: events.append("compare-binding"))
    monkeypatch.setattr(agent, "_replacement_guard", lambda *a: events.append("prove-stopped"))
    monkeypatch.setattr(agent, "stop", lambda **kw: (events.append("stop") or {}, 0))
    monkeypatch.setattr(win, "WindowsApi", lambda: SimpleNamespace(current_sid=lambda: "same-sid"))
    monkeypatch.setattr(inst, "NativePaths", lambda api: SimpleNamespace(write=lambda *a: events.append("authority")))
    monkeypatch.setattr(inst, "known_folders", lambda: {})
    monkeypatch.setattr(inst, "parse_catalog", lambda data: {})
    monkeypatch.setattr(eps, "load_authority", lambda *a: (receipt, "old-sha", {}))
    monkeypatch.setattr(eps, "local_account", lambda sid: "same-user")
    monkeypatch.setattr(eps, "measure_system_roles", lambda *a: {})
    monkeypatch.setattr(eps, "role_file", lambda *a: {"path": "bin/link.exe"})
    attempts = []
    def install(**kw):
        assert json.loads(kw["endpoint_inputs"]) == {
            "version": 1, "hostKey": keys["hostKey"], "authorizedKeys": keys["authorizedKeys"]}
        assert kw["config_dir"] == binding["configDir"] and kw["keys_mode"] == "migrated"
        attempts.append(True)
        if interrupted and len(attempts) == 1:
            raise OSError("interrupted copy")
        return {"keys": dict(keys, mode="migrated"), "location": {"root": "managed-runtime"},
                "release": "new-release", "endpoint": {"manifest": "new-manifest"}}
    monkeypatch.setattr(eps, "install_endpoint_runtime", install)
    def bind(manifest, config, helper, **kw):
        assert manifest == "new-manifest" and config == "enrollment"
        assert kw["expect"] == "expected-binding" and kw["authority"] == authority
        events.append("bind")
    monkeypatch.setattr(agent, "bind", bind)
    if interrupted:
        with pytest.raises(OSError, match="interrupted"):
            tray_repair.repair(root)
        assert (tmp_path / "tray-upgrade.json").exists()
    result = tray_repair.repair(root)
    assert result["keys"] == keys
    assert events.count("stop") == 1 and events.index("stop") < events.index("authority")
    assert events[-1] == "bind"
    assert not (tmp_path / "tray-upgrade.json").exists()


def test_servicing_guardian_matches_the_compiled_release_anchor():
    from pathlib import Path
    from pocketshell.gateway import service_endpoint as ep
    root = Path(__file__).parents[2] / "release/inputs/guardian-servicing"
    hashes = tuple(hashlib.sha256((root / name).read_bytes()).hexdigest() for name in ep.SOURCE_NAMES)
    assert hashes in ep.ALLOWED_GUARDIAN_SOURCES
    assert hashes[0] == ep.SERVICING_GUARDIAN_SHA256
