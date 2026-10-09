"""ordinary-v2 producer (agreement v3 §10, PROPOSED): catalog v2, the
authority receipt, `agent install` and `agent verify-paths` — unit level,
with an in-memory stand-in for the native handle-based verifier."""

from __future__ import annotations

import base64
import hashlib
import json
import ntpath
from pathlib import Path

import pytest

from pocketshell import __version__
from pocketshell.gateway import service_agent_install as inst
from pocketshell.gateway import service_user_agent as agent_mod

from test_gateway_service import QUALIFIED, USER_SID, WIN_CONFIG, WIN_HELPER, fake_windows  # noqa: F401
from test_gateway_user_agent import agent, bind  # noqa: F401
from test_gateway_service_endpoint import MANIFEST

SCHEMA = json.loads((Path(__file__).parent / "fixtures" / "ordinary-v2-authority.schema.json").read_text())
SOURCE = "a" * 40
USER_DATA = "C:\\Users\\owner\\AppData\\Roaming\\PocketShell"
STAGED = "C:\\Users\\owner\\AppData\\Local\\Programs\\PocketShell\\resources\\runtime"
CATALOG = "C:\\Users\\owner\\AppData\\Local\\Programs\\PocketShell\\resources\\host-runtime-catalog.json"
FOLDERS = {"SystemDrive": "C:", "SystemRoot": "C:\\Windows", "ProgramData": "C:\\ProgramData",
           "USERPROFILE": "C:\\Users\\owner", "LOCALAPPDATA": "C:\\Users\\owner\\AppData\\Local"}


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class Paths:
    """In-memory stand-in for NativePaths: case-insensitive Windows paths,
    explicit 'unprotected' / 'reparse' markers that the verifier refuses."""

    def __init__(self):
        self.files, self.dirs = {}, set()
        self.unprotected, self.reparse = set(), set()
        self.writes = []

    @staticmethod
    def key(p):
        return ntpath.normcase(ntpath.normpath(p))

    def put(self, path, data):
        self.files[self.key(path)] = (path, data)

    def _refuse(self, path, private):
        k = self.key(path)
        for r in self.reparse:
            if k == r or k.startswith(r + "\\"):
                raise inst.ServiceError(f"{path} is a reparse point")
        if private and k in self.unprotected:
            raise inst.ServiceError(f"{path} is not owner-only")

    def file(self, path, owner_sid, *, private, max_bytes):
        self._refuse(path, private)
        if self.key(path) not in self.files:
            raise FileNotFoundError(path)
        _orig, data = self.files[self.key(path)]
        return {"canonicalPath": path, "size": len(data), "sha256": sha(data),
                "bytes": data if len(data) <= max_bytes else None}

    def directory(self, path, owner_sid):
        self._refuse(path, True)
        if self.key(path) not in self.dirs:
            raise FileNotFoundError(path)
        return path

    def inventory(self, path, owner_sid, *, private=True):
        self._refuse(path, private)
        prefix = self.key(path) + "\\"
        out = []
        for k, (orig, _data) in self.files.items():
            if k.startswith(prefix):
                self._refuse(orig, private)
                out.append(orig[len(path) + 1:].replace("\\", "/"))
        return sorted(out)

    def write(self, path, data):
        self.writes.append(path)
        self.put(path, data)

    def mkdir(self, path):
        self.dirs.add(self.key(path))


def release_files():
    return {
        "pocketshell.exe": (b"cli-trampoline", "cli"),
        "python/python.exe": (b"python", "interpreter"),
        "native/guardian.py": (b"guardian", "guardian"),
        "native/native_api.py": (b"native-api", "native-api"),
        "native/policy.py": (b"policy", "policy"),
        "bin/pocketshell-link.exe": (b"helper", "helper"),
        "python/Lib/site-packages/pocketshell/__init__.py": (b"module", "module"),
    }


def make_catalog(files=None, **over):
    files = files or release_files()
    by = {role: sha(data) for _p, (data, role) in files.items() if role != "module"}
    c = {"version": 2, "release": "r2026-10-09-1", "source": SOURCE, "platform": "win32-x64", "api": "ordinary-v2",
         "lineage": {"cliVersion": __version__, "cliCommit": SOURCE, "agentApi": 1,
                     "guardian": {"abi": "6cf7ae85", "sourceSHA256": by["guardian"]},
                     "nativeApi": {"sourceSHA256": by["native-api"]},
                     "policy": {"version": 1, "sourceSHA256": by["policy"]},
                     "interpreter": {"distribution": "python-build-standalone", "version": "3.12.7",
                                     "sha256": by["interpreter"]},
                     "helper": {"version": "0.9.0", "sha256": by["helper"]},
                     "lockSHA256": "b" * 64},
         "files": [{"path": p, "sha256": sha(d), "role": r} for p, (d, r) in files.items()]}
    c.update(over)
    return c


def staged_paths(catalog=None, files=None):
    files = files or release_files()
    paths = Paths()
    for p, (data, _role) in files.items():
        paths.put(STAGED + "\\" + p.replace("/", "\\"), data)
    paths.put(CATALOG, json.dumps(catalog or make_catalog(files)).encode())
    return paths


# --- catalog v2 ------------------------------------------------------------------------


def test_catalog_v2_accepts_the_schema_shape():
    assert inst.parse_catalog(json.dumps(make_catalog()).encode())["api"] == "ordinary-v2"


@pytest.mark.parametrize("mutate,why", [
    (lambda c: c.update(version=1), "version"),
    (lambda c: c.update(extra=1), "keys"),
    (lambda c: c["lineage"].update(cliCommit="c" * 40), "cliCommit"),
    (lambda c: c["lineage"]["helper"].update(sha256="0" * 64), "helper pin"),
    (lambda c: c["files"].append({"path": "POCKETSHELL.EXE", "sha256": "0" * 64, "role": "module"}), "case"),
    (lambda c: c["files"].append({"path": "../escape.dll", "sha256": "0" * 64, "role": "module"}), "traversal"),
    (lambda c: c["files"].append({"path": "x/cli2.exe", "sha256": "0" * 64, "role": "cli"}), "two cli"),
    (lambda c: c.update(files=[f for f in c["files"] if f["role"] != "policy"]), "no policy"),
    (lambda c: c["lineage"]["guardian"].update(abi="74a0"), "abi"),
])
def test_catalog_v2_refuses(mutate, why):
    c = make_catalog()
    mutate(c)
    with pytest.raises(inst.InstallError):
        inst.parse_catalog(json.dumps(c).encode())


# --- install (pure) ----------------------------------------------------------------------


def public_binding():
    return {"deviceId": "host-laptop-pha6tcnc-75fu", "manifest": MANIFEST, "manifestSHA256": "d" * 64,
            "configDir": WIN_CONFIG, "port": 22024, "helperSHA256": sha(b"helper"), "ownerSID": USER_SID,
            "hostKeyFingerprint": "SHA256:" + "A" * 43}


def install(paths, **over):
    kw = dict(user_data=USER_DATA, catalog_path=CATALOG, staged=STAGED, binding=public_binding(),
              server="wss://gateway.pocketshell.io", owner_sid=USER_SID, paths=paths, folders=FOLDERS,
              cli_version=__version__, now=0)
    kw.update(over)
    return inst.install_runtime(**kw)


def _closed(obj, schema):
    """The receipt matches the schema's closed key sets (no jsonschema dep)."""
    assert sorted(obj) == sorted(schema["required"]) == sorted(schema["properties"])
    for key, sub in schema["properties"].items():
        if sub.get("type") == "object" and "properties" in sub:
            _closed(obj[key], sub)


def test_install_copies_the_closure_and_writes_the_receipt():
    paths = staged_paths()
    receipt = install(paths)
    root = USER_DATA + "\\managed-runtime"
    rel = root + "\\releases\\r2026-10-09-1"
    for p, (data, _r) in release_files().items():
        assert paths.files[paths.key(rel + "\\" + p.replace("/", "\\"))][1] == data
    stored = json.loads(paths.files[paths.key(root + "\\authority.json")][1])
    assert stored == receipt
    _closed(receipt, SCHEMA["$defs"]["receipt"])
    assert receipt["catalogSHA256"] == sha(paths.files[paths.key(CATALOG)][1])
    assert receipt["environment"]["TEMP"] == receipt["environment"]["TMP"] == root + "\\tmp"
    assert receipt["environment"]["SystemRoot"] == "C:\\Windows"
    assert receipt["location"] == {"root": root, "ownerSid": USER_SID, "protectedDACL": True,
                                   "allowTrustees": [USER_SID], "reparseFree": True, "verifier": inst.VERIFIER}
    assert receipt["binding"]["server"] == "wss://gateway.pocketshell.io"
    assert receipt["installer"] == {"cliVersion": __version__, "cliCommit": SOURCE,
                                    "installedAt": "1970-01-01T00:00:00Z"}
    flat = json.dumps(receipt).lower()
    assert "token" not in flat and "private" not in flat  # public-only


def test_install_dry_run_writes_nothing():
    paths = staged_paths()
    install(paths, dry_run=True)
    assert paths.writes == [] and paths.dirs == set()


def test_install_refuses_an_extra_staged_file():
    paths = staged_paths()
    paths.put(STAGED + "\\python\\Lib\\sitecustomize.py", b"import evil")
    with pytest.raises(inst.InstallError, match="differs from the catalog"):
        install(paths)
    assert paths.writes == []


def test_install_refuses_a_hash_mismatch():
    paths = staged_paths()
    paths.put(STAGED + "\\native\\guardian.py", b"tampered")
    with pytest.raises(inst.InstallError, match="native/guardian.py does not match"):
        install(paths)


def test_install_refuses_a_staged_reparse_point():
    paths = staged_paths()
    paths.reparse.add(paths.key(STAGED + "\\python"))
    with pytest.raises(inst.InstallError, match="cannot be enumerated safely"):
        install(paths)


def test_install_refuses_a_foreign_helper_binding():
    paths = staged_paths()
    with pytest.raises(inst.InstallError, match="not this release's helper"):
        install(paths, binding={**public_binding(), "helperSHA256": "e" * 64})


def test_install_refuses_another_cli_release():
    paths = staged_paths(make_catalog())
    with pytest.raises(inst.InstallError, match="install with that release's own CLI"):
        install(paths, cli_version="0.0.1")


def test_install_refuses_a_dirty_release_dir():
    paths = staged_paths()
    paths.put(USER_DATA + "\\managed-runtime\\releases\\r2026-10-09-1\\stray.dll", b"x")
    with pytest.raises(inst.InstallError, match="outside the catalog"):
        install(paths)


def test_install_refuses_a_missing_server():
    with pytest.raises(inst.InstallError, match="no public wss:// server"):
        install(staged_paths(), server="")


# --- verify-paths (pure) -------------------------------------------------------------------


def test_verify_paths_returns_handle_bytes_and_digest():
    paths = Paths()
    paths.put("C:\\x\\managed-runtime\\authority.json", b"{}")
    paths.mkdir("C:\\x\\managed-runtime")
    reply, code = inst.verify_paths(owner_sid=USER_SID, files=["C:\\x\\managed-runtime\\authority.json"],
                                    directories=["C:\\x\\managed-runtime"], paths=paths, current_sid=USER_SID)
    assert code == 0 and reply["ok"]
    f = reply["results"][0]
    assert f["sha256"] == sha(b"{}") and base64.b64decode(f["bytesBase64"]) == b"{}"
    assert sorted(f) == sorted(SCHEMA["$defs"]["verifyPathsReply"]["properties"]["results"]["items"]["oneOf"][0]
                               ["required"])


def test_verify_paths_refuses_another_owner_and_unprotected_objects():
    paths = Paths()
    paths.put("C:\\x\\a.json", b"{}")
    reply, code = inst.verify_paths(owner_sid=USER_SID, files=["C:\\x\\a.json"], paths=paths,
                                    current_sid="S-1-5-21-1-2-3-4")
    assert code == 1 and not reply["ok"]
    paths.unprotected.add(paths.key("C:\\x\\a.json"))
    reply, code = inst.verify_paths(owner_sid=USER_SID, files=["C:\\x\\a.json"], paths=paths, current_sid=USER_SID)
    assert code == 1 and "owner-only" in reply["results"][0]["problem"]
    reply, code = inst.verify_paths(owner_sid=USER_SID, anchored=["C:\\x\\a.json"], paths=paths,
                                    current_sid=USER_SID)
    assert code == 0  # digest-anchored: no ACL shape required


def test_verify_paths_refuses_relative_and_nothing():
    reply, code = inst.verify_paths(owner_sid=USER_SID, files=["a.json"], paths=Paths(), current_sid=USER_SID)
    assert code == 1
    reply, code = inst.verify_paths(owner_sid=USER_SID, paths=Paths(), current_sid=USER_SID)
    assert code == 1 and reply["results"] == []


# --- CLI glue (agent fixture) ---------------------------------------------------------------


def test_cli_install_uses_the_existing_binding_and_the_enrolled_server(agent, monkeypatch):  # noqa: F811
    bind()
    files = release_files()
    files["bin/pocketshell-link.exe"] = (b"helper", "helper")
    catalog = make_catalog(files)
    # the bound helper's digest (fixture) is QUALIFIED: build a release whose helper pin matches it
    catalog["files"] = [dict(f, sha256=QUALIFIED) if f["role"] == "helper" else f for f in catalog["files"]]
    catalog["lineage"]["helper"]["sha256"] = QUALIFIED
    paths = staged_paths(catalog)
    paths.put(STAGED + "\\bin\\pocketshell-link.exe", b"helper")
    real_file = paths.file

    def file(path, owner_sid, *, private, max_bytes):  # the helper's staged bytes hash to QUALIFIED here
        got = real_file(path, owner_sid, private=private, max_bytes=max_bytes)
        if path.lower().endswith("pocketshell-link.exe"):
            got = dict(got, sha256=QUALIFIED)
        return got

    paths.file = file
    doc, code = agent_mod.install_command(user_data=USER_DATA, catalog=CATALOG, staged=STAGED, dry_run=False,
                                          api=agent["api"], runner=None, paths=paths, folders=FOLDERS)
    assert code == 0, doc
    r = doc["receipt"]
    assert r["binding"]["deviceId"] == "host-laptop-pha6tcnc-75fu" and r["binding"]["port"] == 22024
    assert r["binding"]["server"] == "wss://gateway.pocketshell.io"
    assert r["binding"]["hostKeyFingerprint"].startswith("SHA256:")
    assert r["ownerSid"] == agent["api"].current_sid()


def test_cli_install_requires_a_binding(agent):  # noqa: F811
    doc, code = agent_mod.install_command(user_data=USER_DATA, catalog=CATALOG, staged=STAGED, dry_run=False,
                                          api=agent["api"], runner=None, paths=staged_paths(), folders=FOLDERS)
    assert code == 1 and doc["error"]["code"] == "not-bound" and doc["receipt"] is None
