"""The ordinary-v2 release closure (agreement §14) on windows-latest: the
closure built by scripts/release/build_closure.py (CI helper stand-in) RUNS
from its own directory with the closed environment, the verifier measures it
against its catalog, and the normal installer maps it into
<userData>\\managed-runtime. Nothing is started as a host; no enrollment."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="native Windows release closure")

OUT = os.environ.get("POCKETSHELL_TEST_RELEASE_OUT", "")
VERIFY = os.environ.get("POCKETSHELL_TEST_VERIFY_EXE", "")


@pytest.fixture(scope="module")
def release():
    if not OUT or not os.path.isdir(OUT):
        pytest.skip("POCKETSHELL_TEST_RELEASE_OUT not built")
    root = Path(OUT) / "root-a" / "releases" / "staged"
    catalog = json.loads((Path(OUT) / "host-runtime-catalog.json").read_text())
    receipt = json.loads((Path(OUT) / "build-receipt.json").read_text())
    print("build receipt:", json.dumps(receipt["outputs"] | receipt["bounds"]))
    assert receipt["outputs"]["reproducibleAcrossRoots"] is True
    return {"root": root, "catalog": catalog, "catalogPath": Path(OUT) / "host-runtime-catalog.json"}


def closed_env(tmp_path):
    from pocketshell.gateway import service_agent_install as inst

    folders = inst.known_folders()
    tmp = tmp_path / "tmp"
    tmp.mkdir(exist_ok=True)
    profile = tmp_path / "profile"
    profile.mkdir(exist_ok=True)
    env = {k: folders[k] for k in ("SystemDrive", "SystemRoot", "ProgramData", "LOCALAPPDATA")}
    env.update(USERPROFILE=str(profile), TEMP=str(tmp), TMP=str(tmp))
    return env


def cli(release, tmp_path, *args):
    p = subprocess.run([str(release["root"] / "pocketshell.exe"), *args], env=closed_env(tmp_path),
                       capture_output=True, timeout=120, creationflags=0x08000000)
    print("$ pocketshell", *args, "->", p.returncode, p.stdout.decode(errors="replace")[:1500],
          p.stderr.decode(errors="replace")[-1500:])
    return p


def test_closure_runs_from_its_own_directory(release, tmp_path):
    p = cli(release, tmp_path, "--version")
    assert p.returncode == 0 and release["catalog"]["lineage"]["cliVersion"] in p.stdout.decode()
    p = cli(release, tmp_path, "gateway", "agent", "status", "--json", "--operation-id", "rel-1")
    doc = json.loads(p.stdout)
    assert p.returncode == 1 and doc["error"]["code"] == "not-bound" and doc["operationId"] == "rel-1"


def test_closure_imports_its_native_and_guardian_dependencies(release, tmp_path):
    py = release["root"] / "python" / "python.exe"
    code = ("import sys, ctypes, ssl\n"
            "import cryptography.hazmat.primitives.ciphers.aead, yaml, click, google.auth\n"
            "import native_api, policy\n"
            "assert 'site' not in sys.modules, 'site must not be imported'\n"
            "print(sorted(p for p in sys.path))")
    p = subprocess.run([str(py), "-I", "-S", "-B", "-c", code], env=closed_env(tmp_path), capture_output=True,
                       timeout=120, creationflags=0x08000000)
    print(p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")[-2000:])
    assert p.returncode == 0


def test_closure_writes_nothing_while_running(release, tmp_path):
    before = sorted(str(p) for p in release["root"].rglob("*"))
    cli(release, tmp_path, "gateway", "agent", "status", "--json")
    assert sorted(str(p) for p in release["root"].rglob("*")) == before  # no __pycache__, no new files


def test_verifier_measures_the_whole_closure_against_its_catalog(release):
    if not VERIFY:
        pytest.skip("verifier not built")
    from pocketshell.gateway import service_windows as win

    sid = win.WindowsApi().current_sid()
    root = release["root"]
    reqs = ["--request", f"inventory={root}"]
    files = release["catalog"]["files"]
    for f in files:
        reqs += ["--request", "binary=" + str(root / f["path"].replace("/", "\\"))]
    reqs += ["--request", f"document={release['catalogPath']}"]
    p = subprocess.run([VERIFY, "verify", "--operation-id", "rel-2", "--owner-sid", sid,
                        "--resources-root", str(Path(OUT)), *reqs], capture_output=True, timeout=300,
                       creationflags=0x08000000)
    reply = json.loads(p.stdout.decode().splitlines()[0])
    assert p.returncode == 0 and reply["ok"], [r for r in reply["results"] if not r["ok"]][:5]
    inventory = reply["results"][0]["files"]
    assert sorted(inventory) == sorted(f["path"] for f in files)
    for f, r in zip(files, reply["results"][1:-1]):
        assert r["sha256"] == f["sha256"] and r["bytesBase64"] is None, f
    print(f"verified {len(files)} catalogued files; reply {len(p.stdout)} bytes")


def test_normal_installer_maps_the_real_closure(release, tmp_path):
    from pocketshell import __version__
    from pocketshell.gateway import service_agent_install as inst
    from pocketshell.gateway import service_windows as win

    api = win.WindowsApi()
    sid = api.current_sid()
    catalog = release["catalog"]
    helper = next(f for f in catalog["files"] if f["role"] == "helper")
    user_data = tmp_path / "Roaming" / "PocketShell"
    user_data.mkdir(parents=True)
    config_dir, manifest, manifest_sha = private_binding_roots(tmp_path)
    binding = {"deviceId": "win-service-e2e", "manifest": manifest, "manifestSHA256": manifest_sha,
               "configDir": config_dir, "port": 22024, "helperSHA256": helper["sha256"], "ownerSID": sid,
               "hostKeyFingerprint": "SHA256:" + "A" * 43}
    if catalog["lineage"]["cliVersion"] != __version__:
        pytest.skip("catalog built for another CLI version")
    receipt = inst.install_runtime(user_data=str(user_data), catalog_path=str(release["catalogPath"]),
                                   staged=str(release["root"]), binding=binding, server="wss://gateway.pocketshell.io",
                                   owner_sid=sid, paths=inst.NativePaths(api), folders=inst.known_folders(),
                                   cli_version=__version__)
    print("receipt:", json.dumps(receipt)[:600])
    installed = Path(receipt["location"]["root"]) / "releases" / catalog["release"]
    p = subprocess.run([str(installed / "pocketshell.exe"), "--version"], env=closed_env(tmp_path),
                       capture_output=True, timeout=120, creationflags=0x08000000)
    assert p.returncode == 0  # the installed (relocated) copy runs too


def private_binding_roots(base):
    """A private (owner-only, protected) enrollment config dir and guardian
    manifest directory, as the installer requires them (agreement §16)."""
    import hashlib as _h
    from pathlib import Path as _P

    from pocketshell import windows_security as ws

    config = _P(base) / "enrollment" / "keys"
    manifest = _P(base) / "guardian-root" / "endpoint-manifest.json"
    ws.write_private(config / "placeholder", b"public placeholder")
    data = b'{"version": 1}'
    ws.write_private(manifest, data)
    return str(config), str(manifest), _h.sha256(data).hexdigest()


def test_verifier_spawns_the_held_release_entry(release, tmp_path):
    """The final bootstrap bridge on the real closure: the verifier verifies the
    full closure, holds it, creates pocketshell.exe from the held file and
    returns the CLI's JSON (not-bound here) — Desktop spawns nothing by path."""
    import base64

    if not VERIFY:
        pytest.skip("verifier not built")
    from pocketshell.gateway import service_windows as win

    sid = win.WindowsApi().current_sid()
    root = release["root"]
    entry = str(root / "pocketshell.exe")
    reqs = ["--request", f"inventory={root}"]
    for f in release["catalog"]["files"]:
        reqs += ["--request", "binary=" + str(root / f["path"].replace("/", "\\"))]
    args = ["gateway", "agent", "status", "--json", "--operation-id", "bridge-1"]
    # stdin stays OPEN for the whole command (its EOF means "controller gone")
    proc = subprocess.Popen([VERIFY, "verify", "--operation-id", "bridge-1", "--owner-sid", sid,
                             "--resources-root", str(Path(OUT)), *reqs, "--hold", "--entry", entry, "--spawn-entry",
                             *[x for a in args for x in ("--entry-arg", a)], "--entry-timeout", "120"],
                            env=closed_env(tmp_path), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            creationflags=0x00000008)  # DETACHED, as a GUI parent
    lines = [json.loads(x) for x in proc.stdout]
    code = proc.wait(timeout=60)
    proc.stdin.close()
    events = lines[1:]
    print(code, [e.get("event") for e in events])
    assert code == 0 and lines[0]["ok"]
    assert [e["event"] for e in events] == ["launched", "exited", "released"]
    exited = events[1]
    doc = json.loads(base64.b64decode(exited["stdoutBase64"]))
    assert exited["exitCode"] == 1 and doc["error"]["code"] == "not-bound" and doc["operationId"] == "bridge-1"
