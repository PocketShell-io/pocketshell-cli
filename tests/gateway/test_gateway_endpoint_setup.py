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

TRIO = ("6cf7ae85ad21b23496e7187da7e3bb4f171adef5f63edd2fd01f6ce6435bd047",
        "cab601e27e9814ee8c4e3cd72e0dfd55fd2808682d302655725885b4a4812231",
        "e92bbe02c497c959702b35cfd2d4444a073eafe6e17d5e3872449c3bd4f6b1ce")
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
        self.show = (f"server:          wss://gateway.pocketshell.io\ndevice id:       host-{user.replace(".", "-")}-1\n"
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
                        "guardian": {"abi": "6cf7ae85", "sourceSHA256": by["guardian"]},
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
              show_text=host.show, helper_sha256=sha(b"helper"), paths=paths, folders=host.folders,
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
    assert sorted(e) == ["config", "manifest", "manifestSHA256", "root", "state"]
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
        install(host, staged(host), show_text=host.show.replace("pinned ssh host key", "pinned something"))


# --- trust from the installed authority --------------------------------------------------


def _installed(host):
    paths = staged(host)
    receipt = install(host, paths)
    e = receipt["endpoint"]
    data = paths.files[paths.key(e["manifest"])][1]
    disk = {k: sha(v[1]) for k, v in paths.files.items()}
    return paths, receipt, e, data, (lambda p: disk.get(paths.key(p)))


def test_trust_accepts_the_recorded_manifest():
    host = Host()
    _paths, receipt, e, data, digest = _installed(host)
    m = ep.parse_manifest(data, e["manifest"])
    ep.check_trust_authority(m, receipt, file_sha256=digest)


def test_trust_refuses_a_tampered_manifest():
    host = Host()
    _paths, receipt, e, data, digest = _installed(host)
    tampered = data.replace(b'"port": %d' % host.port, b'"port": %d' % (host.port + 1))
    assert tampered != data
    m = ep.parse_manifest(tampered, e["manifest"])
    with pytest.raises(ep.ServiceError, match="recorded"):
        ep.check_trust_authority(m, receipt, file_sha256=digest)


def test_trust_refuses_an_unrecorded_structurally_valid_manifest():
    host = Host()
    _paths, receipt, e, data, digest = _installed(host)
    m = ep.parse_manifest(data, e["manifest"])
    with pytest.raises(ep.ServiceError):
        ep.check_trust_authority(m, None, file_sha256=digest)
    other = dict(receipt, endpoint=dict(e, manifestSHA256="0" * 64))
    with pytest.raises(ep.ServiceError, match="recorded"):
        ep.check_trust_authority(m, other, file_sha256=digest)


def test_trust_refuses_a_manifest_outside_the_authority_root():
    host = Host()
    _paths, receipt, e, data, digest = _installed(host)
    moved = "C:\\Users\\owner\\elsewhere\\managed-runtime\\endpoint\\endpoint-manifest.json"
    m = ep.parse_manifest(data, e["manifest"])
    other = dict(receipt, endpoint=dict(e, manifest=moved))
    with pytest.raises(ep.ServiceError):
        ep.check_trust_authority(m, other, file_sha256=digest)


def test_trust_refuses_a_wrong_guardian_trio(monkeypatch):
    host = Host()
    _paths, receipt, e, data, digest = _installed(host)
    monkeypatch.setattr(ep, "ALLOWED_GUARDIAN_SOURCES", frozenset({TRIO}))  # not the fixture trio
    m = ep.parse_manifest(data, e["manifest"])
    with pytest.raises(ep.ServiceError, match="source triple|trio"):
        ep.check_trust_authority(m, receipt, file_sha256=digest)


def test_trust_refuses_a_pin_that_no_longer_matches_on_disk():
    host = Host()
    paths, receipt, e, data, digest = _installed(host)
    m = ep.parse_manifest(data, e["manifest"])
    daemon = m.daemon

    def changed(p):
        return "f" * 64 if paths.key(p) == paths.key(daemon) else digest(p)

    with pytest.raises(ep.ServiceError, match="does not match"):
        ep.check_trust_authority(m, receipt, file_sha256=changed)


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
    ep.check_trust_authority(m, rb, file_sha256=lambda p: disk.get(paths_b.key(p)))
    ep.config_guard(paths_b.files[paths_b.key(e["config"])][1].decode(), m)


def test_trust_refuses_a_role_pin_that_is_not_the_catalog_row():
    """Even a recorded manifest cannot pin a release role file to another hash
    than the catalog's row (wrong-role-file-hash)."""
    host = Host()
    _paths, receipt, e, data, digest = _installed(host)
    m = ep.parse_manifest(data, e["manifest"])
    rel = host.user_data + "\\managed-runtime\\releases\\r2026-10-10-3"
    rows = {ntpath.normcase(rel + "\\" + f["path"].replace("/", "\\")): f["sha256"] for f in catalog_v3()["files"]}
    ep.check_trust_authority(m, receipt, file_sha256=digest, release_pins=rows)
    sftp = ntpath.normcase(rel + "\\endpoint\\sftp\\sftp-server.exe")
    with pytest.raises(ep.ServiceError, match="catalog row"):
        ep.check_trust_authority(m, receipt, file_sha256=digest, release_pins=dict(rows, **{sftp: "0" * 64}))


def test_show_must_come_from_the_catalog_helper():
    host = Host()
    with pytest.raises(inst.InstallError, match="catalog's own helper"):
        install(host, staged(host), helper_sha256="0" * 64)
