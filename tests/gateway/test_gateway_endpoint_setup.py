"""Generic per-host endpoint setup (setup ABI v3, revision B; Option B).

NON-PRODUCTION FIXTURES: the endpoint "binaries" below (sshd.exe, sftp-server,
bash, msys DLL, companions) are synthetic stand-in bytes. They exercise the
catalog role selection, manifest generation and authority trust. Real endpoint
binary custody is resolved separately and is never inferred from these tests.
"""

from __future__ import annotations

import hashlib
import json
import ntpath

import pytest

from pocketshell import __version__
from pocketshell.gateway import service_agent_endpoint as eps
from pocketshell.gateway import service_agent_install as inst
from pocketshell.gateway import service_endpoint as ep

from test_gateway_agent_install import Paths as _Paths, SOURCE, release_files


class Paths(_Paths):
    """+ metadata-only measurement (the key files) and a record of every read."""

    def __init__(self):
        super().__init__()
        self.reads, self.meta, self.measured = [], {}, set()

    def file(self, path, owner_sid, **kw):
        self.reads.append(path)
        return super().file(path, owner_sid, **kw)

    def metadata(self, path, owner_sid):
        self.measured.add(self.key(path))
        m = self.meta.get(self.key(path))
        if m is None:
            raise FileNotFoundError(path)
        if not m["regular"]:
            raise inst.ServiceError(f"{path} is not a regular file")
        if not m["private"]:
            raise inst.ServiceError(f"{path} is not owner-protected")
        return {"regular": True}

TRIO = ("e862645ddc374801f1ae921be3bf66afeb0ccff03d82adb909ad1b4ec0bdd877",
        "cab601e27e9814ee8c4e3cd72e0dfd55fd2808682d302655725885b4a4812231",
        "e92bbe02c497c959702b35cfd2d4444a073eafe6e17d5e3872449c3bd4f6b1ce")
# natively measured System32 servicing roles (here: synthetic digests)
SYSTEM_ROLES = {"C:\\WINDOWS\\System32\\cmd.exe": "c" * 64, "C:\\WINDOWS\\System32\\conhost.exe": "d" * 64}
KEY_LINE = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK8B0Ctl2bl8wdg50ZKPY7t9WuU170cplZpzuMckYrSU"


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class Host:
    """One synthetic Windows user (a second instance proves genericity)."""

    def __init__(self, user="owner", sid="S-1-5-21-1846869698-1433458354-420588588-1001", port=22024):
        self.user, self.sid, self.port = user, sid, port
        home = f"C:\\Users\\{user}"
        self.folders = {"SystemDrive": "C:", "SystemRoot": "C:\\WINDOWS", "ProgramData": "C:\\ProgramData",
                        "USERPROFILE": home, "LOCALAPPDATA": home + "\\AppData\\Local"}
        self.user_data = home + "\\AppData\\Roaming\\PocketShell"
        self.resources = home + "\\AppData\\Local\\Programs\\PocketShell\\resources"
        self.staged = self.resources + "\\runtime"
        self.catalog_path = self.resources + "\\host-runtime-catalog.json"
        self.config_dir = home + "\\PocketShellFleet\\enrollment\\keys"
        self.host_key = home + "\\PocketShellFleet\\endpoint-keys\\ssh_host_ed25519_key"
        self.authorized = home + "\\PocketShellFleet\\endpoint-keys\\authorized_keys"
        self.show = (f"server:          wss://gateway.pocketshell.io\ndevice id:       host-{user.replace('.', '-')}-1\n"
                     f"local ssh:       127.0.0.1:{port} (loopback only)\npinned ssh host key: {KEY_LINE}\n")


def endpoint_files():
    """v2 release files + the NON-PRODUCTION endpoint stand-ins (catalog v3)."""
    files = {p: v for p, v in release_files().items() if not p.startswith("native/")}
    files["guardian/guardian.py"] = (b"guardian-6cf", "guardian")
    files["guardian/native_api.py"] = (b"native-api-cab", "native-api")
    files["guardian/policy.py"] = (b"policy-e92", "policy")
    files.update({
        "endpoint/bin/sshd.exe": (b"FIXTURE sshd", "sshd"),
        "endpoint/bin/sshd-session.exe": (b"FIXTURE sshd-session", "module"),
        "endpoint/bin/sshd-auth.exe": (b"FIXTURE sshd-auth", "module"),
        "endpoint/bin/ssh-shellhost.exe": (b"FIXTURE shellhost", "module"),
        "endpoint/bin/libcrypto.dll": (b"FIXTURE libcrypto", "module"),
        "endpoint/sftp/sftp-server.exe": (b"FIXTURE sftp", "sftp"),
        "endpoint/sftp/libcrypto.dll": (b"FIXTURE sftp libcrypto", "module"),
        "endpoint/shell/usr/bin/bash.exe": (b"FIXTURE bash", "backend-shell"),
        "endpoint/shell/usr/bin/msys-2.0.dll": (b"FIXTURE msys", "backend-dll"),
    })
    return files


def catalog_v3(files=None):
    files = files or endpoint_files()
    by = {role: sha(d) for _p, (d, role) in files.items() if role != "module"}
    return {"version": 3, "release": "r2026-10-10-3", "source": SOURCE, "platform": "win32-x64", "api": "ordinary-v2",
            "lineage": {"cliVersion": __version__, "cliCommit": SOURCE, "agentApi": 1,
                        "guardian": {"abi": "e862645d", "sourceSHA256": by["guardian"]},
                        "nativeApi": {"sourceSHA256": by["native-api"]},
                        "policy": {"version": 1, "sourceSHA256": by["policy"]},
                        "interpreter": {"distribution": "python-build-standalone", "version": "3.12.13",
                                        "sha256": by["interpreter"]},
                        "helper": {"version": "cd7c6f6a0c7b", "sha256": by["helper"]},
                        "lockSHA256": "b" * 64,
                        "endpoint": {"openssh": {"version": "OpenSSH_for_Windows_10.3p1", "sourceCommit": "e" * 40,
                                                 "buildReceiptSHA256": "c" * 64},
                                     "sftp": {"version": "9.5.6.2", "sha256": by.get("sftp", "0" * 64)},
                                     "backendShell": {"distribution": "fixture", "version": "0",
                                                      "sha256": by.get("backend-shell", "0" * 64)}}},
            "files": [{"path": p, "sha256": sha(d), "role": r} for p, (d, r) in files.items()]}


def trio_of(files):
    return tuple(sha(files[f"guardian/{n}"][0]) for n in ("guardian.py", "native_api.py", "policy.py"))


def staged(host, files=None, catalog=None):
    files = files or endpoint_files()
    paths = Paths()
    for p, (data, _r) in files.items():
        paths.put(host.staged + "\\" + p.replace("/", "\\"), data)
    paths.put(host.catalog_path, json.dumps(catalog or catalog_v3(files)).encode())
    paths.mkdir(host.config_dir)
    paths.meta[paths.key(host.host_key)] = {"regular": True, "private": True}
    paths.meta[paths.key(host.authorized)] = {"regular": True, "private": True}
    return paths


def inputs(host, **over):
    d = {"version": 1, "hostKey": host.host_key, "authorizedKeys": host.authorized}
    d.update(over)
    return json.dumps(d).encode()


def install(host, paths, **over):
    kw = dict(user_data=host.user_data, catalog_path=host.catalog_path, staged=host.staged,
              config_dir=host.config_dir, endpoint_inputs=inputs(host), owner_sid=host.sid, account=host.user,
              show=lambda helper: (host.show, sha(b"helper")), system_roles=dict(SYSTEM_ROLES), paths=paths, folders=host.folders,
              cli_version=__version__, now=0)
    kw.update(over)
    return eps.install_endpoint_runtime(**kw)


@pytest.fixture(autouse=True)
def generic_trio(monkeypatch):
    # the compiled GENERIC trio, here the fixture stand-ins' digests (production: TRIO)
    monkeypatch.setattr(ep, "ALLOWED_GUARDIAN_SOURCES", frozenset({trio_of(endpoint_files())}))


# --- catalog v3 ---------------------------------------------------------------------------


def test_catalog_v3_selects_exactly_one_of_each_endpoint_role():
    assert inst.parse_catalog(json.dumps(catalog_v3()).encode())["version"] == 3
    for role in ("sshd", "sftp", "backend-shell", "backend-dll"):
        files = {p: v for p, v in endpoint_files().items() if v[1] != role}
        with pytest.raises(inst.InstallError):
            inst.parse_catalog(json.dumps(catalog_v3(files)).encode())
    files = endpoint_files()
    files["endpoint/bin/other-sshd.exe"] = (b"x", "sshd")
    with pytest.raises(inst.InstallError):
        inst.parse_catalog(json.dumps(catalog_v3(files)).encode())


def test_the_production_trio_is_compiled_generically():
    import importlib

    fresh = importlib.reload(importlib.import_module("pocketshell.gateway.service_endpoint"))
    assert fresh.ALLOWED_GUARDIAN_SOURCES == frozenset({TRIO})
    assert fresh.ALLOWED_ENDPOINT_MANIFEST_SHA256 == frozenset()  # NO per-host compiled digest


# --- install (first) -----------------------------------------------------------------------


def test_install_generates_the_manifest_and_anchors_it_in_authority_v3():
    host = Host()
    paths = staged(host)
    receipt = install(host, paths)
    root = host.user_data + "\\managed-runtime"
    e = receipt["endpoint"]
    assert sorted(e) == ["config", "manifest", "manifestSHA256", "root", "state", "systemReferences"]
    assert e["systemReferences"] == [
        {"role": "system-reference", "name": "cmd.exe", "path": "C:\\WINDOWS\\System32\\cmd.exe", "sha256": "c" * 64},
        {"role": "system-reference", "name": "conhost.exe", "path": "C:\\WINDOWS\\System32\\conhost.exe",
         "sha256": "d" * 64}]
    assert e["root"] == root and e["manifest"] == root + "\\endpoint\\endpoint-manifest.json"
    assert e["config"] == root + "\\endpoint\\sshd.conf" and e["state"] == root + "\\endpoint\\state"
    data = paths.files[paths.key(e["manifest"])][1]
    assert sha(data) == e["manifestSHA256"]
    assert receipt["version"] == 3 and receipt["binding"]["manifest"] == e["manifest"]
    assert receipt["binding"]["manifestSHA256"] == e["manifestSHA256"] and receipt["binding"]["port"] == host.port
    m = ep.parse_manifest(data, e["manifest"])
    assert m.root.casefold() == root.casefold() and m.port == host.port
    assert m.guardian.casefold().endswith("\\releases\\r2026-10-10-3\\guardian\\guardian.py")
    assert m.daemon.casefold().endswith("\\releases\\r2026-10-10-3\\endpoint\\bin\\sshd.exe")
    ep.config_guard(paths.files[paths.key(e["config"])][1].decode(), m)
    assert sorted(json.loads(paths.files[paths.key(root + "\\authority.json")][1])) == sorted(receipt)


def test_the_host_key_and_authorized_keys_are_never_read():
    host = Host()
    paths = staged(host)
    install(host, paths)
    read = {paths.key(p) for p in paths.reads}
    assert paths.key(host.host_key) not in read and paths.key(host.authorized) not in read
    assert paths.key(host.host_key) in paths.measured and paths.key(host.authorized) in paths.measured


@pytest.mark.parametrize("bad", [
    {"extra": 1}, {"version": 2}, {"hostKey": "relative\\key"}, {"authorizedKeys": "C:\\x\\..\\y"},
])
def test_endpoint_inputs_are_closed(bad):
    host = Host()
    with pytest.raises(inst.InstallError, match="endpoint-inputs|endpoint inputs"):
        install(host, staged(host), endpoint_inputs=inputs(host, **bad))


def test_unprotected_key_files_refuse():
    host = Host()
    paths = staged(host)
    paths.meta[paths.key(host.host_key)] = {"regular": True, "private": False}
    with pytest.raises(inst.InstallError, match="endpoint-inputs|owner-protected"):
        install(host, paths)


def test_a_shipped_endpoint_binary_is_verified_against_the_catalog():
    host = Host()
    paths = staged(host)
    paths.put(host.staged + "\\endpoint\\bin\\sshd.exe", b"tampered sshd")
    with pytest.raises(inst.InstallError, match="does not match"):
        install(host, paths)
    assert not paths.writes


def test_show_must_be_the_enrolled_loopback_port_and_key():
    host = Host()
    with pytest.raises(inst.InstallError):
        install(host, staged(host), show=lambda h: (host.show.replace("pinned ssh host key", "pinned x"), sha(b"helper")))


# --- trust from the installed authority --------------------------------------------------


def _installed(host):
    paths = staged(host)
    receipt = install(host, paths)
    e = receipt["endpoint"]
    data = paths.files[paths.key(e["manifest"])][1]
    disk = {k: sha(v[1]) for k, v in paths.files.items()}
    disk.update({paths.key(k): v for k, v in SYSTEM_ROLES.items()})
    return paths, receipt, e, data, (lambda p: disk.get(paths.key(p)))


def test_trust_accepts_the_recorded_manifest():
    host = Host()
    _paths, receipt, e, data, digest = _installed(host)
    m = ep.parse_manifest(data, e["manifest"])
    ep.check_trust_authority(m, receipt, file_sha256=digest, closure=_closure(host))


def test_trust_refuses_a_tampered_manifest():
    host = Host()
    _paths, receipt, e, data, digest = _installed(host)
    tampered = data.replace(b'"port":%d' % host.port, b'"port":%d' % (host.port + 1))
    assert tampered != data
    m = ep.parse_manifest(tampered, e["manifest"])
    with pytest.raises(ep.ServiceError, match="recorded"):
        ep.check_trust_authority(m, receipt, file_sha256=digest, closure=_closure(host))


def test_trust_refuses_an_unrecorded_structurally_valid_manifest():
    host = Host()
    _paths, receipt, e, data, digest = _installed(host)
    m = ep.parse_manifest(data, e["manifest"])
    with pytest.raises(ep.ServiceError):
        ep.check_trust_authority(m, None, file_sha256=digest, closure=_closure(host))
    other = dict(receipt, endpoint=dict(e, manifestSHA256="0" * 64))
    with pytest.raises(ep.ServiceError, match="recorded"):
        ep.check_trust_authority(m, other, file_sha256=digest, closure=_closure(host))


def test_trust_refuses_a_manifest_outside_the_authority_root():
    host = Host()
    _paths, receipt, e, data, digest = _installed(host)
    moved = "C:\\Users\\owner\\elsewhere\\managed-runtime\\endpoint\\endpoint-manifest.json"
    m = ep.parse_manifest(data, e["manifest"])
    other = dict(receipt, endpoint=dict(e, manifest=moved))
    with pytest.raises(ep.ServiceError):
        ep.check_trust_authority(m, other, file_sha256=digest, closure=_closure(host))


def test_trust_refuses_a_wrong_guardian_trio(monkeypatch):
    host = Host()
    _paths, receipt, e, data, digest = _installed(host)
    monkeypatch.setattr(ep, "ALLOWED_GUARDIAN_SOURCES", frozenset({TRIO}))  # not the fixture trio
    m = ep.parse_manifest(data, e["manifest"])
    with pytest.raises(ep.ServiceError, match="source triple|trio"):
        ep.check_trust_authority(m, receipt, file_sha256=digest, closure=_closure(host))


def test_trust_refuses_a_pin_that_no_longer_matches_on_disk():
    host = Host()
    paths, receipt, e, data, digest = _installed(host)
    m = ep.parse_manifest(data, e["manifest"])
    daemon = m.daemon

    def changed(p):
        return "f" * 64 if paths.key(p) == paths.key(daemon) else digest(p)

    with pytest.raises(ep.ServiceError, match="does not match"):
        ep.check_trust_authority(m, receipt, file_sha256=changed, closure=_closure(host))


def test_a_second_synthetic_host_needs_no_rebuild():
    """Generic: another account, SID, profile and port; same source."""
    a, b = Host(), Host(user="jane.doe", sid="S-1-5-21-111-222-333-2001", port=31337)
    ra = install(a, staged(a))
    paths_b = staged(b)
    rb = install(b, paths_b)
    assert ra["endpoint"]["manifestSHA256"] != rb["endpoint"]["manifestSHA256"]
    e = rb["endpoint"]
    data = paths_b.files[paths_b.key(e["manifest"])][1]
    m = ep.parse_manifest(data, e["manifest"])
    assert m.owner_sid == b.sid and m.port == 31337 and m.config_bindings["allowUser"] == "jane.doe"
    disk = {k: sha(v[1]) for k, v in paths_b.files.items()}
    disk.update({paths_b.key(k): v for k, v in SYSTEM_ROLES.items()})
    ep.check_trust_authority(m, rb, file_sha256=lambda p: disk.get(paths_b.key(p)), closure=_closure(b))
    ep.config_guard(paths_b.files[paths_b.key(e["config"])][1].decode(), m)


def test_trust_refuses_a_role_pin_that_is_not_the_catalog_row():
    """Even a recorded manifest cannot pin a release role file to another hash
    than the catalog's row (wrong-role-file-hash)."""
    host = Host()
    _paths, receipt, e, data, digest = _installed(host)
    m = ep.parse_manifest(data, e["manifest"])
    rel = host.user_data + "\\managed-runtime\\releases\\r2026-10-10-3"
    closure = _closure(host)
    ep.check_trust_authority(m, receipt, file_sha256=digest, closure=closure)
    sftp = ntpath.normcase(rel + "\\endpoint\\sftp\\sftp-server.exe")
    with pytest.raises(ep.ServiceError, match="catalog row"):
        ep.check_trust_authority(m, receipt, file_sha256=digest,
                                 closure=dict(closure, pins=dict(closure["pins"], **{sftp: "0" * 64})))


# --- the installed authority (bind/start input) -----------------------------------------


def test_load_authority_returns_the_receipt_and_catalog_rows():
    host = Host()
    paths, receipt, e, data, digest = _installed(host)
    authority = host.user_data + "\\managed-runtime\\authority.json"
    r, asha, closure = eps.load_authority(authority, host.sid, paths)
    assert closure == _closure(host)
    assert r == receipt and asha == sha(paths.files[paths.key(authority)][1])
    m = ep.parse_manifest(data, e["manifest"])
    ep.check_trust_authority(m, r, file_sha256=digest, closure=closure)


@pytest.mark.parametrize("mutate", ["sid", "catalog-copy", "unprotected", "not-managed-runtime", "v2"])
def test_load_authority_refuses(mutate):
    host = Host()
    paths, receipt, e, _data, _digest = _installed(host)
    authority = host.user_data + "\\managed-runtime\\authority.json"
    sid = host.sid
    if mutate == "sid":
        sid = "S-1-5-21-9-9-9-1001"
    elif mutate == "catalog-copy":
        copy = eps.catalog_copy(host.user_data + "\\managed-runtime", receipt["catalogSHA256"])
        paths.put(copy, paths.files[paths.key(copy)][1] + b" ")
    elif mutate == "unprotected":
        paths.unprotected.add(paths.key(authority))
    elif mutate == "not-managed-runtime":
        authority = host.user_data + "\\elsewhere\\authority.json"
        paths.put(authority, paths.files[paths.key(host.user_data + "\\managed-runtime\\authority.json")][1])
    elif mutate == "v2":
        paths.put(authority, json.dumps(dict(receipt, version=2)).encode())
    with pytest.raises(inst.InstallError) as err:
        eps.load_authority(authority, sid, paths)
    assert err.value.code == "authority-invalid"


# --- ALL guardian-required pins (review finding 2 on 91ed08b) ----------------------------


def _closure(host):
    return eps.catalog_closure(host.user_data + "\\managed-runtime", catalog_v3())


def _rows(host):
    rel = host.user_data + "\\managed-runtime\\releases\\r2026-10-10-3"
    return {ntpath.normcase(rel + "\\" + f["path"].replace("/", "\\")): f["sha256"] for f in catalog_v3()["files"]}


def _rewritten(host, receipt, e, data, mutate):
    """A manifest variant re-recorded in the authority (the authority is the
    only anchor, so the controls must hold even for a recorded manifest)."""
    doc = json.loads(data)
    mutate(doc)
    new = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    r = json.loads(json.dumps(receipt))
    r["endpoint"]["manifestSHA256"] = r["binding"]["manifestSHA256"] = sha(new)
    return ep.parse_manifest(new, e["manifest"]), r


def test_the_generated_manifest_pins_the_whole_catalog_closure_and_the_system_roles():
    host = Host()
    _paths, receipt, e, data, digest = _installed(host)
    pins = {ntpath.normcase(k): v for k, v in json.loads(data)["pins"].items()}
    rows = _rows(host)
    assert all(pins.get(k) == v for k, v in rows.items())
    assert _closure(host)["pins"] == rows  # every catalog row, python modules included
    for k, v in SYSTEM_ROLES.items():
        assert pins[ntpath.normcase(k)] == v
    ep.check_trust_authority(ep.parse_manifest(data, e["manifest"]), receipt, file_sha256=digest, closure=_closure(host))


@pytest.mark.parametrize("drop", ["python/Lib/site-packages/pocketshell/__init__.py", "endpoint/bin/libcrypto.dll",
                                  "cmd.exe", "conhost.exe"])
def test_a_manifest_missing_any_startup_member_refuses(drop):
    host = Host()
    _paths, receipt, e, data, digest = _installed(host)

    def mutate(doc):
        victim = [k for k in doc["pins"] if k.replace("\\", "/").casefold().endswith(drop.casefold())]
        assert len(victim) == 1
        del doc["pins"][victim[0]]

    m, r = _rewritten(host, receipt, e, data, mutate)
    with pytest.raises(ep.ServiceError, match="lacks|missing"):
        ep.check_trust_authority(m, r, file_sha256=digest, closure=_closure(host))


def test_a_wrong_system_role_hash_refuses():
    host = Host()
    _paths, receipt, e, data, digest = _installed(host)
    conhost = ntpath.normcase("C:\\Windows\\System32\\conhost.exe")

    def changed(p):
        return "e" * 64 if ntpath.normcase(p) == conhost else digest(p)

    with pytest.raises(ep.ServiceError, match="does not match"):
        ep.check_trust_authority(ep.parse_manifest(data, e["manifest"]), receipt, file_sha256=changed,
                                 closure=_closure(host))


def test_a_non_system_dir_conhost_refuses():
    host = Host()
    _paths, receipt, e, data, digest = _installed(host)

    def mutate(doc):
        doc["pins"]["C:\\Users\\owner\\Downloads\\conhost.exe"] = "d" * 64

    m, r = _rewritten(host, receipt, e, data, mutate)
    with pytest.raises(ep.ServiceError, match="outside"):
        ep.check_trust_authority(m, r, file_sha256=lambda p: "d" * 64 if "Downloads" in p else digest(p),
                                 closure=_closure(host))


@pytest.mark.parametrize("bad", [
    {}, {"C:\\Windows\\System32\\cmd.exe": "c" * 64},
    {"C:\\Windows\\System32\\cmd.exe": "c" * 64, "C:\\Temp\\conhost.exe": "d" * 64},
    {"C:\\Windows\\System32\\cmd.exe": "c" * 64, "C:\\Windows\\System32\\conhost.exe": "XYZ"},
])
def test_install_requires_exactly_the_measured_system_roles(bad):
    host = Host()
    with pytest.raises(inst.InstallError, match="system"):
        install(host, staged(host), system_roles=bad)


def test_a_closure_over_the_guardian_manifest_bound_refuses_with_its_measurement(monkeypatch):
    """The production generate+bound path; the bound is lowered so a small
    synthetic closure crosses it (the real bound is pinned by
    test_agreed_bounds_are_identical_across_installer_trust_and_oracle)."""
    monkeypatch.setattr(ep, "MAX_MANIFEST_BYTES", 64 * 1024)
    host = Host()
    files = endpoint_files()
    for i in range(400):
        files[f"endpoint/shell/usr/share/f{i:04d}.txt"] = (b"x%d" % i, "module")
    with pytest.raises(inst.InstallError, match="manifest bound"):
        install(host, staged(host, files=files, catalog=catalog_v3(files)))


# --- c1: the narrow measured system-reference role (§16.13) -----------------------------


def _with_refs(receipt, refs):
    r = json.loads(json.dumps(receipt))
    r["endpoint"]["systemReferences"] = refs
    return r


@pytest.mark.parametrize("case", ["missing", "extra-path", "wrong-hash", "syswow64", "case-other-dir",
                                  "short-name", "unc", "not-system-role", "outside-root-pin"])
def test_system_references_are_exact_and_narrow(case):
    host = Host()
    _paths, receipt, e, data, digest = _installed(host)
    m = ep.parse_manifest(data, e["manifest"])
    refs = receipt["endpoint"]["systemReferences"]
    ep.check_trust_authority(m, receipt, file_sha256=digest, closure=_closure(host))  # the exact pair: accepted
    r = receipt
    if case == "missing":
        r = _with_refs(receipt, refs[:1])
    elif case == "extra-path":
        r = _with_refs(receipt, refs + [dict(refs[0], name="cmd.exe", path="C:\\Temp\\cmd.exe")])
    elif case == "wrong-hash":
        r = _with_refs(receipt, [refs[0], dict(refs[1], sha256="e" * 64)])
    elif case == "syswow64":
        r = _with_refs(receipt, [dict(refs[0], path="C:\\WINDOWS\\SysWOW64\\cmd.exe"), refs[1]])
    elif case == "case-other-dir":
        r = _with_refs(receipt, [dict(refs[0], path="C:\\windows\\system\\cmd.exe"), refs[1]])
    elif case == "short-name":
        r = _with_refs(receipt, [dict(refs[0], path="C:\\WINDOW~1\\System32\\cmd.exe"), refs[1]])
    elif case == "unc":
        r = _with_refs(receipt, [dict(refs[0], path="\\\\?\\C:\\WINDOWS\\System32\\cmd.exe"), refs[1]])
    elif case == "not-system-role":
        r = _with_refs(receipt, [dict(refs[0], role="sftp"), refs[1]])
    elif case == "outside-root-pin":
        m, r = _rewritten(host, receipt, e, data,
                          lambda doc: doc["pins"].__setitem__("C:\\WINDOWS\\System32\\whoami.exe", "f" * 64))
    with pytest.raises(ep.ServiceError):
        ep.check_trust_authority(m, r, file_sha256=digest, closure=_closure(host))


def test_system_references_follow_the_measured_system_root():
    host = Host()
    host.folders["SystemRoot"] = "C:\\Windows"
    receipt = install(host, staged(host), system_roles={"C:\\Windows\\System32\\cmd.exe": "c" * 64,
                                                       "C:\\Windows\\System32\\conhost.exe": "d" * 64})
    assert [x["path"] for x in receipt["endpoint"]["systemReferences"]] == [
        "C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\conhost.exe"]
    with pytest.raises(inst.InstallError, match="system"):
        install(Host(), staged(Host()), system_roles={"C:\\Windows\\System32\\cmd.exe": "c" * 64,
                                                     "D:\\Windows\\System32\\conhost.exe": "d" * 64})


@pytest.mark.parametrize("role", ["sftp", "backendExecutable", "backendDLL", "python"])
def test_a_system_reference_cannot_serve_a_non_system_role(role):
    host = Host()
    _paths, receipt, e, data, digest = _installed(host)
    cmd = "C:/WINDOWS/System32/cmd.exe"

    def mutate(doc):
        if role == "python":
            doc["python"] = cmd.replace("/", "\\")
        else:
            doc["configBindings"][role] = cmd

    m, r = _rewritten(host, receipt, e, data, mutate)
    with pytest.raises(ep.ServiceError, match="system reference|managed-runtime"):
        ep.check_trust_authority(m, r, file_sha256=digest, closure=_closure(host))



# --- exact catalog role -> path parity (review 065692d2 on a096a07) -----------------------


@pytest.mark.parametrize("case", ["daemon", "python", "sftp", "backendExecutable", "backendDLL", "extra-pin",
                                  "member-wrong-path", "guardian"])
def test_roles_cannot_leave_their_catalog_paths(case):
    host = Host()
    _paths, receipt, e, data, digest = _installed(host)
    root = host.user_data + "\\managed-runtime"
    other = root + "\\other\\thing.exe"

    def mutate(doc):
        if case in ("daemon", "python"):
            doc[case] = other
        elif case in ("sftp", "backendExecutable", "backendDLL"):
            doc["configBindings"][case] = other.replace("\\", "/")
        elif case == "guardian":
            pass
        if case == "member-wrong-path":
            key = next(k for k in doc["pins"] if k.endswith("sshd-auth.exe"))
            doc["pins"][key.replace("endpoint\\bin", "endpoint\\elsewhere")] = doc["pins"].pop(key)
        elif case == "guardian":
            for name in ("guardian.py", "native_api.py", "policy.py"):
                key = next(k for k in doc["pins"] if k.endswith("guardian\\" + name))
                doc["pins"][root + "\\other\\" + name] = doc["pins"][key]
        else:
            doc["pins"][other] = "f" * 64

    try:
        m, r = _rewritten(host, receipt, e, data, mutate)
    except ep.ServiceError:
        return  # the guardian schema itself already refuses this shape
    with pytest.raises(ep.ServiceError):
        ep.check_trust_authority(m, r, file_sha256=lambda p: "f" * 64 if "other" in p else digest(p),
                                 closure=_closure(host))


# --- agreed full-closure bounds (§16.14) ---------------------------------------------------


def test_agreed_bounds_are_identical_across_installer_trust_and_oracle():
    assert inst.CATALOG3_MAX_FILES == 16384 and inst.CATALOG3_MAX_BYTES == 8 << 20
    assert inst.MAX_FILES == 4096 and inst.MAX_DOC == 1024 * 1024  # catalog v2 keeps its bounds
    assert inst.MAX_REQUESTS == 32768 and inst.MAX_DOCUMENT == 8 << 20 and inst.MAX_REPLY == 32 << 20
    assert ep.MAX_MANIFEST_BYTES == 8 << 20


def _catalog_rows(n):
    files = endpoint_files()
    i = 0
    while len(files) < n:
        files[f"endpoint/shell/usr/share/f{i:05d}"] = (b"%d" % i, "module")
        i += 1
    return files


def test_catalog_v3_row_bound_exact_and_plus_one():
    at = catalog_v3(_catalog_rows(16384))
    assert len(at["files"]) == 16384 and inst.parse_catalog(json.dumps(at).encode())["version"] == 3
    over = catalog_v3(_catalog_rows(16385))
    with pytest.raises(inst.InstallError, match="files"):
        inst.parse_catalog(json.dumps(over).encode())


def test_catalog_v3_byte_bound_exact_and_plus_one():
    body = json.dumps(catalog_v3()).encode()
    assert inst.parse_catalog(body + b" " * ((8 << 20) - len(body)))["version"] == 3
    with pytest.raises(inst.InstallError, match="larger"):
        inst.parse_catalog(body + b" " * ((8 << 20) - len(body) + 1))


def test_catalog_v2_keeps_its_old_bounds():
    from test_gateway_agent_install import make_catalog

    body = json.dumps(make_catalog()).encode()
    with pytest.raises(inst.InstallError, match="larger"):
        inst.parse_catalog(body + b" " * ((1 << 20) - len(body) + 1))


@pytest.mark.parametrize("dup", ["exact", "casefold"])
def test_catalog_v3_duplicate_paths_refuse(dup):
    c = catalog_v3()
    row = dict(c["files"][-1])
    if dup == "casefold":
        row["path"] = row["path"].upper()
    c["files"].append(row)
    with pytest.raises(inst.InstallError):
        inst.parse_catalog(json.dumps(c).encode())


def test_manifest_byte_bound_exact_and_plus_one():
    host = Host()
    _paths, _receipt, e, data, _digest = _installed(host)
    assert ep.parse_manifest(data + b" " * ((8 << 20) - len(data)), e["manifest"])
    with pytest.raises(ep.ServiceError, match="larger"):
        ep.parse_manifest(data + b" " * ((8 << 20) - len(data) + 1), e["manifest"])


def test_the_whole_portablegit_scale_closure_installs_and_is_measured():
    """9 622 backend members (the historical PortableGit cardinality, synthetic
    bytes): the whole closure installs and the receipt records its measurement."""
    host = Host()
    files = endpoint_files()
    for i in range(9622 - 2):
        files[f"endpoint/shell/usr/lib/m{i:05d}"] = (b"m%d" % i, "module")
    receipt = install(host, staged(host, files=files, catalog=catalog_v3(files)))
    measured = receipt["installer"]["closure"]
    assert measured["rows"] == len(files) and measured["catalogBytes"] > 1_000_000
    assert measured["manifestBytes"] > 1_000_000 and measured["pins"] == len(files) + 4


def test_oracle_request_bound_exact_and_plus_one():
    reqs = [("binary", f"C:\\r\\f{i:05d}") for i in range(32769)]

    class P:
        def file(self, path, owner_sid, **kw):
            return {"canonicalPath": path, "size": 1, "sha256": "a" * 64, "bytes": None}

    kw = dict(owner_sid=Host().sid, operation_id="op", private_roots=["C:\\r"], paths=P(), current_sid=Host().sid)
    doc, code = inst.verify_paths(requests=reqs[:32768], **kw)
    assert code == 0, doc.get("problem")
    doc, code = inst.verify_paths(requests=reqs, **kw)
    assert code == 2 and not doc["ok"]



# --- the successor guardian e862645d (agreed 8 MiB manifest bound) --------------------------


def test_the_vendored_successor_guardian_is_the_compiled_trio_and_differs_by_the_bound_only():
    from pathlib import Path

    base = Path(__file__).resolve().parents[2] / "release" / "inputs"
    new, old = base / "guardian-e862645d", base / "guardian-6cf7ae85"
    assert tuple(sha((new / n).read_bytes()) for n in ("guardian.py", "native_api.py", "policy.py")) == TRIO
    a, b = (old / "guardian.py").read_bytes().split(b"\n"), (new / "guardian.py").read_bytes().split(b"\n")
    changed = [(x, y) for x, y in zip(a, b) if x != y]
    assert len(a) == len(b) and len(changed) == 1
    assert b"st_size>65536:" in changed[0][0] and b"st_size>%d:" % ep.MAX_MANIFEST_BYTES in changed[0][1]
    for n in ("native_api.py", "policy.py"):
        assert (new / n).read_bytes() == (old / n).read_bytes()


def test_catalog_guardian_abi_follows_the_catalog_version():
    c = catalog_v3()
    c["lineage"]["guardian"]["abi"] = "6cf7ae85"
    with pytest.raises(inst.InstallError, match="lineage"):
        inst.parse_catalog(json.dumps(c).encode())
    from test_gateway_agent_install import make_catalog

    assert inst.parse_catalog(json.dumps(make_catalog()).encode())["lineage"]["guardian"]["abi"] == "6cf7ae85"


@pytest.mark.parametrize("version,bound", [(3, 16384), (2, 4096)])
def test_the_staged_and_installed_inventories_use_the_catalog_version_bound(version, bound):
    """The production installer passes the agreed bound to EVERY inventory
    (staged, release-dirty check, re-measure); catalog v2 keeps 4 096."""
    host = Host()
    paths = staged(host)
    seen = []
    real = paths.inventory

    def inventory(path, owner_sid, **kw):
        seen.append(kw.get("max_files"))
        return real(path, owner_sid, **{k: v for k, v in kw.items() if k != "max_files"})

    paths.inventory = inventory
    cat = catalog_v3() if version == 3 else dict(catalog_v3(), version=2)
    blobs, want = inst._verify_staged(host.staged, cat, host.sid, paths)
    inst._copy_release(host.user_data + "\\\\mr", host.user_data + "\\\\mr\\\\releases\\\\r", host.user_data + "\\\\mr\\\\tmp",
                       blobs, want, cat, host.sid, paths)
    assert seen and set(seen) == {bound}
