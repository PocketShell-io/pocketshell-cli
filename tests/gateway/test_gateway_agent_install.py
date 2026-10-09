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

    def file(self, path, owner_sid, *, private, max_bytes, private_root=None):
        self._refuse(path, private)
        if self.key(path) not in self.files:
            raise FileNotFoundError(path)
        _orig, data = self.files[self.key(path)]
        return {"canonicalPath": path, "size": len(data), "sha256": sha(data),
                "bytes": data if len(data) <= max_bytes else None}

    def directory(self, path, owner_sid, private_root=None):
        self._refuse(path, True)
        if self.key(path) not in self.dirs:
            raise FileNotFoundError(path)
        return path

    def directory_anchored(self, path, owner_sid):
        self._refuse(path, False)
        return path

    def inventory(self, path, owner_sid, *, private=True, private_root=None):
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


# --- verify-paths protocol v2 (pure) ------------------------------------------------------

PRIV = "C:\\x\\managed-runtime"
RES = "C:\\Program Files\\PocketShell\\resources"


def vp(paths, requests, **kw):
    args = dict(owner_sid=USER_SID, operation_id="op-1", private_roots=[PRIV], resources_roots=[RES],
                requests=requests, paths=paths, current_sid=USER_SID)
    args.update(kw)
    return inst.verify_paths(**args)


def verify_fixture():
    paths = Paths()
    paths.put(PRIV + "\\authority.json", b"{}")
    paths.put(PRIV + "\\releases\\r\\pocketshell.exe", b"MZ" * 40000)
    paths.put(RES + "\\host-runtime-catalog.json", b"[]")
    paths.mkdir(PRIV)
    return paths


def test_verify_v2_correlated_documents_and_hash_only_binaries():
    paths = verify_fixture()
    reqs = [("document", PRIV + "\\authority.json"), ("binary", PRIV + "\\releases\\r\\pocketshell.exe"),
            ("document", RES + "\\host-runtime-catalog.json"), ("directory", PRIV)]
    reply, code = vp(paths, reqs)
    assert code == 0 and reply["ok"] and reply["operationId"] == "op-1"
    assert [(r["index"], r["kind"], r["path"]) for r in reply["results"]] == [(i, k, p) for i, (k, p) in
                                                                               enumerate(reqs)]
    doc, binary, cat, _d = reply["results"]
    assert base64.b64decode(doc["bytesBase64"]) == b"{}" and doc["root"] == PRIV
    assert binary["bytesBase64"] is None and binary["sha256"] == sha(b"MZ" * 40000) and binary["size"] == 80000
    assert cat["root"] == RES
    item_schema = SCHEMA["$defs"]["verifyReply"]["properties"]["results"]["items"]
    for r in reply["results"]:
        assert sorted(r) == sorted(item_schema["required"])


def test_verify_v2_private_vs_resources_policy():
    paths = verify_fixture()
    paths.unprotected.add(paths.key(PRIV + "\\authority.json"))
    paths.unprotected.add(paths.key(RES + "\\host-runtime-catalog.json"))
    reply, code = vp(paths, [("document", PRIV + "\\authority.json"),
                             ("document", RES + "\\host-runtime-catalog.json")])
    assert code == 1
    assert "owner-only" in reply["results"][0]["problem"] and reply["results"][1]["ok"]


@pytest.mark.parametrize("requests,code", [
    ([("document", "C:\\Users\\owner\\.ssh\\id_ed25519")], 1),          # outside every root
    ([("document", PRIV + "\\releases\\r\\pocketshell.exe")], 1),      # bytes only for .json
    ([("document", PRIV + "\\authority.json")] * 2, 2),                   # duplicate
    ([("binary", PRIV + "\\..\\secret.json")], 1),                       # traversal
    ([("binary", PRIV + "\\authority.json:evil")], 1),                     # ADS
    ([("frobnicate", PRIV)], 2),                                         # unknown kind
    ([], 2),                                                             # nothing requested
])
def test_verify_v2_refusals(requests, code):
    reply, got = vp(verify_fixture(), requests)
    assert got == code and not reply["ok"]


def test_verify_v2_refuses_large_documents_owner_and_root_problems():
    paths = verify_fixture()
    paths.put(PRIV + "\\big.json", b"x" * (64 * 1024 + 1))
    reply, code = vp(paths, [("document", PRIV + "\\big.json")])
    assert code == 1 and "64 KiB" in reply["results"][0]["problem"]
    assert vp(paths, [("directory", PRIV)], current_sid="S-1-5-21-1-2-3-4")[1] == 1
    assert vp(paths, [("directory", PRIV)], operation_id="")[1] == 2
    assert vp(paths, [("directory", PRIV)], resources_roots=[PRIV + "\\releases"])[1] == 2  # overlap
    assert vp(paths, [("directory", PRIV)], private_roots=["relative"])[1] == 2


# --- path syntax guards (code AND schema, the same expressions) ----------------------------

BAD_ABS = ["C:\\", "C:/", "C:\\a\\..\\b", "C:\\a\\.\\b", "C:\\a:stream", "C:\\a\\b.", "C:\\a\\b ", "\\\\server\\share\\x",
           "\\\\?\\C:\\x", "C:\\a\\CON", "C:\\a\\nul.txt", "C:\\a\\\\b", "a\\b", "C:a\\b", "C:\\a\\b*"]
GOOD_ABS = ["C:\\Users\\owner\\AppData\\Roaming\\PocketShell", "D:/a/b.json", "C:\\a\\con2\\x.json"]
BAD_REL = ["../x", "a/../b", "./a", "a/./b", "a/CON", "a/nul.txt", "a.", "a/b.", "a:b", "a//b", "/a", "a\\b"]
GOOD_REL = ["pocketshell.exe", "python/Lib/site-packages/a.py", "a/con2/b"]


def test_path_guards_code_and_schema_agree():
    import re

    schema_abs = re.compile(SCHEMA["$defs"]["absPath"]["pattern"])
    schema_rel = re.compile(SCHEMA["$defs"]["relPath"]["pattern"])
    for p in BAD_ABS:
        assert not inst._abs(p) and not schema_abs.match(p), p
    for p in GOOD_ABS:
        assert inst._abs(p) and schema_abs.match(p), p
    for p in BAD_REL:
        assert not inst.REL_RE.match(p) and not schema_rel.match(p), p
    for p in GOOD_REL:
        assert inst.REL_RE.match(p) and schema_rel.match(p), p


@pytest.mark.parametrize("bad", ["../escape.dll", "python/../x.py", "a/CON.dll", "a:stream", "trail.", "x/./y"])
def test_catalog_refuses_unsafe_relative_paths(bad):
    c = make_catalog()
    c["files"].append({"path": bad, "sha256": "0" * 64, "role": "module"})
    with pytest.raises(inst.InstallError):
        inst.parse_catalog(json.dumps(c).encode())


@pytest.mark.parametrize("field,value", [("manifest", "C:\\x\\..\\m.json"), ("configDir", "C:\\keys:ads"),
                                         ("manifest", "\\\\host\\share\\m.json")])
def test_install_refuses_unsafe_binding_paths(field, value):
    with pytest.raises(inst.InstallError, match="plain drive-absolute"):
        install(staged_paths(), binding={**public_binding(), field: value})


def test_schema_accepts_the_canonical_public_server():
    """consumer review: the real provisioning receipt carries wss://gateway.pocketshell.io."""
    import re

    pattern = re.compile(SCHEMA["$defs"]["receipt"]["properties"]["binding"]["properties"]["server"]["pattern"])
    assert pattern.match("wss://gateway.pocketshell.io")
    assert inst.SERVER_RE.match("wss://gateway.pocketshell.io")
    for bad in ("https://gateway.pocketshell.io", "ws://gateway.pocketshell.io", "wss://user@gw", "wss://gw/x?y"):
        assert not pattern.match(bad) and not inst.SERVER_RE.match(bad), bad


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

    def file(path, owner_sid, *, private, max_bytes, private_root=None):  # the helper's staged bytes: QUALIFIED
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


def test_cli_verify_paths_keeps_interleaved_request_order(monkeypatch):
    """Fleet ManagedVerifierReply requires results 1:1 in the REQUEST order."""
    from click.testing import CliRunner

    from pocketshell.cli import cli

    seen = {}

    def fake(**kw):
        seen.update(kw)
        return {"version": 2}, 0

    monkeypatch.setattr(agent_mod, "verify_paths_command", fake)
    result = CliRunner().invoke(cli, ["gateway", "agent", "verify-paths", "--operation-id", "o", "--owner-sid", USER_SID,
                                      "--private-root", PRIV, "--request", "binary=" + PRIV + "\\a.exe",
                                      "--request", "document=" + PRIV + "\\b.json",
                                      "--request", "binary=" + PRIV + "\\c.exe", "--json"])
    assert result.exit_code == 0, result.output
    assert [k for k, _p in seen["requests"]] == ["binary", "document", "binary"]


def test_schema_launch_matches_the_producer_launch_keys():
    from pocketshell.gateway import service_user_agent as ua

    launch = SCHEMA["$defs"]["launch"]
    assert sorted(launch["required"]) == sorted(launch["properties"]) == sorted(ua.LAUNCH_KEYS)


# --- S1: the schema launch predicate = "target measured outside every job" --------------


def _schema_accepts(schema, value):
    """Minimal checker for the launch fragment (const/type/required/closed)."""
    if sorted(value) != sorted(schema["required"]) or set(value) - set(schema["properties"]):
        return False
    for key, rule in schema["properties"].items():
        v = value[key]
        if "const" in rule and v != rule["const"]:
            return False
        if rule.get("type") == "boolean" and not isinstance(v, bool):
            return False
        if rule.get("type") == "integer" and (not isinstance(v, int) or isinstance(v, bool) or v < rule.get("minimum", v)):
            return False
    return True


@pytest.mark.parametrize("broke_away,child_in_job,accepted", [
    (True, False, True),    # breakaway applied, target measured job-free
    (False, False, True),   # breakaway not applied (caller in no job / flag not needed), target measured job-free
    (True, True, False),    # an ancestor job forbids breakaway: refused
    (False, True, False),   # breakaway refused: refused
])
def test_s1_launch_tuples_production_and_schema_agree(broke_away, child_in_job, accepted):
    from pocketshell.gateway import service_windows as win

    try:
        verdict = win.job_verdict(caller_in_job=False,
                                  broke_away=broke_away, child_in_job=child_in_job, nearest_kill=False)
    except win.TargetJobError:
        verdict = None
    assert (verdict is not None) == accepted
    if verdict is not None:
        launch = {**verdict, "elevated": False, "session": 1}
        assert _schema_accepts(SCHEMA["$defs"]["launch"], launch), launch
    # the schema itself refuses every in-job tuple, whatever brokeAway says
    in_job = {"inJob": True, "brokeAway": broke_away, "callerInJob": True, "callerJobKillOnClose": False,
              "elevated": False, "session": 1}
    assert not _schema_accepts(SCHEMA["$defs"]["launch"], in_job)
