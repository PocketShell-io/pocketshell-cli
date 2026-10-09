"""ordinary-v2 producer on a real Windows host (disposable CI runner):
`install_runtime` + the handle-based NativePaths verifier, no activation
(nothing is started; no enrollment; synthetic release bytes)."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="native Windows verifier")

from pocketshell import __version__  # noqa: E402
from pocketshell.gateway import service_agent_install as inst  # noqa: E402
from pocketshell.gateway import service_windows as win  # noqa: E402

SOURCE = "a" * 40


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


FILES = {
    "pocketshell.exe": (b"cli-trampoline", "cli"),
    "python/python.exe": (b"python", "interpreter"),
    "native/guardian.py": (b"guardian", "guardian"),
    "native/native_api.py": (b"native-api", "native-api"),
    "native/policy.py": (b"policy", "policy"),
    "bin/pocketshell-link.exe": (b"helper", "helper"),
    "python/Lib/site-packages/pocketshell/__init__.py": (b"module", "module"),
}


def catalog():
    by = {role: sha(d) for _p, (d, role) in FILES.items() if role != "module"}
    return {"version": 2, "release": "ci-native-1", "source": SOURCE, "platform": "win32-x64", "api": "ordinary-v2",
            "lineage": {"cliVersion": __version__, "cliCommit": SOURCE, "agentApi": 1,
                        "guardian": {"abi": "6cf7ae85", "sourceSHA256": by["guardian"]},
                        "nativeApi": {"sourceSHA256": by["native-api"]},
                        "policy": {"version": 1, "sourceSHA256": by["policy"]},
                        "interpreter": {"distribution": "python-build-standalone", "version": "3.12.7",
                                        "sha256": by["interpreter"]},
                        "helper": {"version": "0.9.0", "sha256": by["helper"]}, "lockSHA256": "b" * 64},
            "files": [{"path": p, "sha256": sha(d), "role": r} for p, (d, r) in FILES.items()]}


@pytest.fixture
def layout(tmp_path):
    staged = tmp_path / "Programs" / "resources" / "runtime"
    for rel, (data, _role) in FILES.items():
        target = staged / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    cat = tmp_path / "Programs" / "resources" / "host-runtime-catalog.json"
    cat.write_bytes(json.dumps(catalog()).encode())
    user_data = tmp_path / "Roaming" / "PocketShell"
    user_data.mkdir(parents=True)
    return {"staged": str(staged), "catalog": str(cat), "userData": str(user_data)}


def test_install_and_verify_paths_on_real_acls(layout):
    api = win.WindowsApi()
    sid = api.current_sid()
    paths = inst.NativePaths(api)
    binding = {"deviceId": "win-service-e2e", "manifest": "C:\\x\\endpoint-manifest.json", "manifestSHA256": "d" * 64,
               "configDir": "C:\\x\\keys", "port": 22024, "helperSHA256": sha(b"helper"), "ownerSID": sid,
               "hostKeyFingerprint": "SHA256:" + "A" * 43}
    folders = inst.known_folders()
    print("known folders:", folders)
    assert folders["SystemRoot"].lower() == os.environ["SystemRoot"].lower()
    receipt = inst.install_runtime(user_data=layout["userData"], catalog_path=layout["catalog"],
                                   staged=layout["staged"], binding=binding, server="wss://gateway.invalid",
                                   owner_sid=sid, paths=paths, folders=folders, cli_version=__version__)
    root = os.path.join(layout["userData"], "managed-runtime")
    release = os.path.join(root, "releases", "ci-native-1")
    authority = os.path.join(root, "authority.json")

    reply, code = inst.verify_paths(owner_sid=sid, files=[authority], directories=[root, release],
                                    inventories=[release], anchored=[layout["catalog"]], paths=paths,
                                    current_sid=sid)
    print(json.dumps({**reply, "results": [{k: v for k, v in r.items() if k != "bytesBase64"}
                                           for r in reply["results"]]}, indent=1))
    assert code == 0 and reply["ok"], reply
    assert json.loads(base64.b64decode(reply["results"][0]["bytesBase64"])) == receipt
    inventory = next(r for r in reply["results"] if r["kind"] == "inventory")
    assert sorted(inventory["files"]) == sorted(FILES)
    cat = next(r for r in reply["results"] if r["path"] == layout["catalog"])
    assert cat["sha256"] == receipt["catalogSHA256"]

    # the staged (inherited-DACL) tree is NOT private: refused as --file, fine as anchored
    staged_file = os.path.join(layout["staged"], "pocketshell.exe")
    reply, code = inst.verify_paths(owner_sid=sid, files=[staged_file], paths=paths, current_sid=sid)
    assert code == 1, reply
    print("staged as private:", reply["results"][0]["problem"])
    reply, code = inst.verify_paths(owner_sid=sid, anchored=[staged_file], paths=paths, current_sid=sid)
    assert code == 0

    # a foreign grant on the receipt is refused (test-only icacls on the disposable runner)
    subprocess.run(["icacls", authority, "/grant", "*S-1-1-0:R"], check=True, capture_output=True)
    reply, code = inst.verify_paths(owner_sid=sid, files=[authority], paths=paths, current_sid=sid)
    assert code == 1 and "outside your account" in reply["results"][0]["problem"], reply

    # a junction inside the private tree is refused by the inventory
    junction = os.path.join(release, "python", "evil")
    subprocess.run(["cmd", "/c", "mklink", "/J", junction, os.environ["SystemRoot"]], check=True,
                   capture_output=True)
    reply, code = inst.verify_paths(owner_sid=sid, inventories=[release], paths=paths, current_sid=sid)
    assert code == 1 and "reparse" in reply["results"][0]["problem"], reply

    # another owner SID is refused outright
    reply, code = inst.verify_paths(owner_sid="S-1-5-21-1-2-3-4", files=[authority], paths=paths,
                                    current_sid=sid)
    assert code == 1


def test_install_refuses_a_tampered_staged_file(layout):
    api = win.WindowsApi()
    sid = api.current_sid()
    with open(os.path.join(layout["staged"], "native", "guardian.py"), "ab") as handle:
        handle.write(b"#")
    binding = {"deviceId": "win-service-e2e", "manifest": "C:\\x\\m.json", "manifestSHA256": "d" * 64,
               "configDir": "C:\\x\\keys", "port": 22024, "helperSHA256": sha(b"helper"), "ownerSID": sid,
               "hostKeyFingerprint": "SHA256:" + "A" * 43}
    with pytest.raises(inst.InstallError, match="does not match"):
        inst.install_runtime(user_data=layout["userData"], catalog_path=layout["catalog"], staged=layout["staged"],
                             binding=binding, server="wss://gateway.invalid", owner_sid=sid,
                             paths=inst.NativePaths(api), folders=inst.known_folders(), cli_version=__version__)
    assert not os.path.exists(os.path.join(layout["userData"], "managed-runtime"))
