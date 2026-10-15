import hashlib
import importlib.util
import json
import os
import stat
import struct
import sys
import zipfile
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("tray_installer", Path(__file__).parents[2] / "scripts/release/build_tray_installer.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def inventory(root):
    return [{"path": p.relative_to(root).as_posix(), "sha256": builder.digest(p)}
            for p in root.rglob("*") if p.is_file()]


def test_private_backend_refuses_changed_build_files_before_replacing_any(tmp_path):
    source = tmp_path / "build"
    source.mkdir()
    root = tmp_path / "runtime"
    (root / "endpoint/bin").mkdir(parents=True)
    names = ("sshd.exe", "sshd-auth.exe", "sshd-session.exe", "ssh-shellhost.exe",
             "sftp-server.exe", "libcrypto.dll", "LICENSE.txt", "NOTICE.txt")
    for name in names:
        (source / name).write_bytes(name.encode())
    receipt = source / "receipt.json"
    receipt.write_text(json.dumps({"sourceArchiveSHA256": "8545e33b809f7ec6eb8363cbbbd2d4d68982d8ab7a8b7e6bb63506d82ae62223",
                                  "files": {n: builder.digest(source / n) for n in names},
                                  "source": {}, "processes": [{"naturalExit": 0}]}))
    sha = builder.digest(receipt)
    (source / "NOTICE.txt").write_bytes(b"changed")
    with pytest.raises(ValueError, match="file digest"):
        builder.stage_private_backend(source, sha, root, {})
    assert not list((root / "endpoint/bin").iterdir())
    with pytest.raises(ValueError, match="receipt SHA256"):
        builder.stage_private_backend(source, "0" * 64, root, {})


def test_offline_client_is_pinned_and_does_not_ship_a_server(tmp_path, monkeypatch):
    archive = tmp_path / "OpenSSH.zip"
    with zipfile.ZipFile(archive, "w") as z:
        for name in ("ssh.exe", "LICENSE.txt", "NOTICE.txt", "sshd.exe", "install-sshd.ps1"):
            z.writestr("OpenSSH-Win64/" + name, name.encode())
    monkeypatch.setattr(builder.sys, "platform", "linux")
    with pytest.raises(ValueError, match="SHA256"):
        builder.stage_ssh_client(archive, "0" * 64, tmp_path / "bad")
    result = builder.stage_ssh_client(archive, builder.digest(archive), tmp_path / "client")
    assert {p.name for p in (tmp_path / "client").iterdir()} == {"ssh.exe", "LICENSE.txt", "NOTICE.txt"}
    assert result["sshSHA256"] == builder.digest(tmp_path / "client/ssh.exe")


UPSTREAM_PSC_INSTALL = b"# stand-in for the reviewed upstream install.ps1\n"


@pytest.fixture
def upstream_pin(monkeypatch):
    monkeypatch.setattr(builder, "UPSTREAM_PSC_INSTALL_SHA256", hashlib.sha256(UPSTREAM_PSC_INSTALL).hexdigest())


def test_offline_psc_installs_the_tray_installer_and_recatalogs_it(tmp_path, upstream_pin):
    script = tmp_path / "install.ps1"
    script.write_bytes(UPSTREAM_PSC_INSTALL)
    manifest = tmp_path / "package-manifest.json"
    manifest.write_text(json.dumps({"files": {"install.ps1": "before"}}))
    content_id = builder.configure_offline_psc(tmp_path, "ab" * 32)
    text = script.read_text()
    assert f"$ContentId = '{content_id}'" in text and "@CONTENT_ID@" not in text
    assert text == builder.PSC_INSTALL_TEMPLATE.read_text().replace("@CONTENT_ID@", content_id)
    assert json.loads(manifest.read_text())["files"]["install.ps1"] == builder.digest(script)
    # A second adaptation sees a changed upstream script and refuses.
    with pytest.raises(ValueError, match="review"):
        builder.configure_offline_psc(tmp_path, "ab" * 32)


def test_upstream_psc_install_pin_is_the_reviewed_client_script():
    assert builder.UPSTREAM_PSC_INSTALL_SHA256 == "f22200ddc623459c1a6bb522438ee241aa3367459020a774c8fd6b1abf8542e3"


def test_psc_installer_template_keeps_the_upgrade_contract():
    text = builder.PSC_INSTALL_TEMPLATE.read_text()
    assert text.isascii()  # PowerShell 5 reads BOM-less scripts as ANSI
    # content-addressed tree, staged then published by rename, shim switched last
    assert '$name = "$($manifest.version)-$InstallVariant-$ContentId"' in text
    assert "Rename-Item -LiteralPath $stage" in text and "[IO.File]::Replace($next, $shim, $null)" in text
    assert text.index("Set-Shim $tree") > text.index('cli.js" hosts')
    # recoverable: the previous PSC stays active -> exit 3, never a failure
    assert "exit 3" in text and "Existing PSC version differs" not in text
    # OS folders, not the caller's environment (SSH sessions lack SystemRoot)
    assert "[Environment]::GetFolderPath('Windows')" in text and "$env:SystemRoot" not in text


def test_nsis_treats_a_kept_previous_psc_as_a_warning():
    nsi = (builder.REPO / "scripts/release/tray-installer.nsi").read_text()
    assert "StrCmp $2 3 0 psc_failed" in nsi and "StrCmp $2 3 psc_shortcut" in nsi
    warning = nsi[nsi.index("StrCmp $2 3 0 psc_failed"):nsi.index("psc_failed:")]
    assert "MessageBox" not in warning


def adapted_tree(tmp_path, name, files, ssh="ab" * 32):
    root = tmp_path / name
    root.mkdir()
    (root / "install.ps1").write_bytes(UPSTREAM_PSC_INSTALL)
    (root / "package-manifest.json").write_text(json.dumps({"version": "0.6.2", "files": files}))
    return builder.configure_offline_psc(root, ssh)


def test_psc_same_version_with_different_content_gets_a_fresh_version_tree(tmp_path, upstream_pin):
    # Regression: v0.5.10 over v0.5.9 on a laptop. Both shipped PSC 0.6.2 with
    # a rebuilt previewStyle.js, the shared `<version>-gateway-ssh10` tree
    # failed install.ps1's identical-reinstall check, and PSC was not upgraded.
    old = {"install.ps1": "x", "psc/dist/cli.js": "1" * 64,
           "psc/node_modules/@pocketshell/core/dist/esm/preview/previewStyle.js": "2" * 64}
    rebuilt = dict(old, **{"psc/node_modules/@pocketshell/core/dist/esm/preview/previewStyle.js": "3" * 64})
    assert adapted_tree(tmp_path, "a", old) != adapted_tree(tmp_path, "b", rebuilt)


def test_psc_identical_package_reinstalls_into_its_existing_tree(tmp_path, upstream_pin):
    files = {"install.ps1": "x", "psc/dist/cli.js": "1" * 64}
    # A changed adapter script alone does not move the tree: install.ps1 is never installed.
    assert adapted_tree(tmp_path, "a", files) == adapted_tree(tmp_path, "b", dict(files, **{"install.ps1": "y"}))


def test_psc_changed_ssh_client_gets_a_fresh_version_tree(tmp_path, upstream_pin):
    # ssh.exe is copied into the tree and its digest is bound, so it must move the tree too.
    files = {"install.ps1": "x", "psc/dist/cli.js": "1" * 64}
    assert adapted_tree(tmp_path, "a", files, "ab" * 32) != adapted_tree(tmp_path, "b", files, "cd" * 32)


def test_catalog_rejects_tampered_or_extra_payload(tmp_path):
    (tmp_path / "python").mkdir()
    for name in ("a.exe", "aplexer.exe"):
        (tmp_path / "python" / name).write_bytes(b"matching Windows aplexer worker")
    rows = inventory(tmp_path)
    builder.verify_inventory(tmp_path, rows)
    (tmp_path / "python/a.exe").write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="differs"):
        builder.verify_inventory(tmp_path, rows)
    (tmp_path / "python/a.exe").write_bytes(b"matching Windows aplexer worker")
    (tmp_path / "unexpected.exe").write_bytes(b"extra")
    with pytest.raises(ValueError, match="differs"):
        builder.verify_inventory(tmp_path, rows)


def test_catalog_requires_complete_aplexer(tmp_path):
    (tmp_path / "python").mkdir()
    (tmp_path / "python/a.exe").write_bytes(b"CLI without worker")
    with pytest.raises(ValueError, match="worker"):
        builder.verify_inventory(tmp_path, inventory(tmp_path))


def test_zip_preserves_namespace_packages_and_reproducibility(tmp_path):
    import zipfile
    a, b = tmp_path / "a.zip", tmp_path / "b.zip"
    builder.write_zip(a, {"google/auth/__init__.py": b"# namespace", "six.py": b"# module"})
    builder.write_zip(b, {"six.py": b"# module", "google/auth/__init__.py": b"# namespace"})
    assert a.read_bytes() == b.read_bytes()
    with zipfile.ZipFile(a) as archive:
        assert "google/" in archive.namelist()


def psc_archive(tmp_path, extra=None):
    import hashlib
    import json
    import zipfile
    files = {name: b"fixture" for name in (
        "node.exe", "psc-security.exe", "psc.cmd", "install.ps1", "psc/dist/cli.js")}
    manifest = {"version": "0.3.1", "clientCommit": "a" * 40, "coreCommit": "b" * 40,
                "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
    archive = tmp_path / "psc.zip"
    with zipfile.ZipFile(archive, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
        z.writestr("package-manifest.json", json.dumps(manifest))
        if extra:
            z.writestr(*extra)
    return archive


def test_psc_stages_complete_pinned_package(tmp_path):
    archive = psc_archive(tmp_path)
    receipt = builder.stage_psc(archive, builder.digest(archive), tmp_path / "payload")
    assert receipt["version"] == "0.3.1"
    assert (tmp_path / "payload/psc/dist/cli.js").read_bytes() == b"fixture"
    with pytest.raises(ValueError, match="SHA256"):
        builder.stage_psc(archive, "0" * 64, tmp_path / "bad")


@pytest.mark.parametrize("extra", [("../escape.exe", b"bad"), ("extra.exe", b"bad"),
                                 ("psc/dist/cli.js", b"tampered")])
def test_psc_rejects_traversal_unknown_and_duplicate_members(tmp_path, extra):
    archive = psc_archive(tmp_path, extra)
    with pytest.raises(ValueError):
        builder.stage_psc(archive, builder.digest(archive), tmp_path / "payload")
    assert not (tmp_path / "payload").exists()


def aplexer_wheels(tmp_path, monkeypatch):
    import hashlib
    paths = []
    for kind, files in (("cli", {"aplexer_cli/bin/aplexer.exe": b"RPC CLI and worker"}),
                        ("client", {"aplexer/_native.pyd": b"native client", "aplexer/__init__.py": b"new client"})):
        path = tmp_path / builder.APLEXER_WHEELS[kind][0]
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        monkeypatch.setitem(builder.APLEXER_WHEELS, kind, (path.name, hashlib.sha256(path.read_bytes()).hexdigest()))
        paths.append(path)
    return paths


def test_aplexer_replaces_both_executables_and_old_native_client(tmp_path, monkeypatch):
    wheels = aplexer_wheels(tmp_path, monkeypatch)
    root = tmp_path / "runtime"
    old = root / "python/site-native/aplexer"
    old.mkdir(parents=True)
    (old / "client.pyc").write_bytes(b"obsolete sourceless client")
    receipt = builder.stage_aplexer(*wheels, root)
    assert receipt["version"] == "0.1.13"
    assert (root / "python/a.exe").read_bytes() == (root / "python/aplexer.exe").read_bytes() == b"RPC CLI and worker"
    assert not (old / "client.pyc").exists()
    assert (old / "_native.pyd").read_bytes() == b"native client"
    assert receipt["exeSHA256"] == builder.digest(root / "python/a.exe")


def test_aplexer_rejects_changed_wheel_before_touching_runtime(tmp_path, monkeypatch):
    wheels = aplexer_wheels(tmp_path, monkeypatch)
    wheels[1].write_bytes(b"changed")
    root = tmp_path / "runtime"
    with pytest.raises(ValueError, match="pinned"):
        builder.stage_aplexer(*wheels, root)
    assert not root.exists()


def frame(payload):
    return struct.pack(">I", len(payload)) + payload


class FakeHelper:
    """Stand-in for subprocess.Popen capturing the request frame."""

    def __init__(self, reply, returncode=0, timeout_error=False):
        self.reply = reply
        self.returncode = returncode
        self.timeout_error = timeout_error
        self.request = None
        self.killed = False

    def __call__(self, argv, **kwargs):
        assert argv[1:] == ["rpc", "--stdio", "--protocol", "1"]
        assert kwargs["stdin"] == builder.subprocess.PIPE
        fake = self

        class Process:
            returncode = fake.returncode

            def communicate(self, frame_bytes, timeout=None):
                fake.request = frame_bytes
                if fake.timeout_error:
                    raise builder.subprocess.TimeoutExpired(argv, timeout)
                return (fake.reply, b"")

            def poll(self):
                return fake.returncode

            def kill(self):
                fake.killed = True

        return Process()


def ping_reply(**result):
    return frame(json.dumps({"protocol": 1, "id": "tray-rpc-check",
                             "result": result}).encode())


def test_rpc_stdio_ping_drives_a_framed_round_trip(monkeypatch):
    fake = FakeHelper(ping_reply(ok=True, generation="gen-1"))
    monkeypatch.setattr(builder.subprocess, "Popen", fake)
    assert builder.rpc_stdio_ping("a.exe") == "gen-1"
    size = struct.unpack(">I", fake.request[:4])[0]
    assert len(fake.request) == 4 + size
    assert json.loads(fake.request[4:]) == {"protocol": 1, "id": "tray-rpc-check",
                                            "method": "ping", "params": {}}


@pytest.mark.parametrize("reply,returncode", [
    (b"", 0),  # no framed response
    (frame(b"{"), 0),  # not JSON
    (frame(b"\x00"), 0),  # invalid frame handling downstream
    (ping_reply(ok=False, generation="gen-1"), 0),  # ping not ok
    (frame(json.dumps({"protocol": 1, "id": "other",
                       "result": {"ok": True}}).encode()), 0),  # wrong id
    (ping_reply(ok=True, generation="gen-1"), 3),  # nonzero exit
])
def test_rpc_stdio_ping_rejects_broken_helpers(monkeypatch, reply, returncode):
    monkeypatch.setattr(builder.subprocess, "Popen", FakeHelper(reply, returncode))
    with pytest.raises(ValueError):
        builder.rpc_stdio_ping("a.exe")


def test_rpc_stdio_ping_rejects_a_hanging_helper(monkeypatch):
    monkeypatch.setattr(builder.subprocess, "Popen",
                        FakeHelper(b"", timeout_error=True))
    with pytest.raises(ValueError, match="in time"):
        builder.rpc_stdio_ping("a.exe")


def test_rpc_stdio_ping_rejects_an_unlaunchable_helper(monkeypatch):
    def missing(argv, **kwargs):
        raise OSError("no such file")

    monkeypatch.setattr(builder.subprocess, "Popen", missing)
    with pytest.raises(ValueError, match="Cannot launch"):
        builder.rpc_stdio_ping("a.exe")


@pytest.mark.skipif(sys.platform == "win32", reason="shebang helpers are not directly executable on Windows")
def test_rpc_stdio_ping_serves_a_real_helper_process(tmp_path):
    script = tmp_path / "fake-a"
    script.write_text("#!/usr/bin/env python3\n"
                      "import json, struct, sys\n"
                      "stdin, stdout = sys.stdin.buffer, sys.stdout.buffer\n"
                      "header = stdin.read(4)\n"
                      "(size,) = struct.unpack('>I', header)\n"
                      "request = json.loads(stdin.read(size))\n"
                      "reply = json.dumps({'protocol': 1, 'id': request['id'],\n"
                      "                    'result': {'ok': True, 'generation': 'fake-gen'}}).encode()\n"
                      "stdout.write(struct.pack('>I', len(reply)) + reply)\n"
                      "stdout.flush()\n"
                      "assert not stdin.read()\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    assert builder.rpc_stdio_ping(str(script)) == "fake-gen"


HELPER_INPUT = Path(__file__).parents[2] / "release/inputs/pocketshell-link-70f5a4b/pocketshell-link-windows-amd64.exe"
HELPER_SHA = "5672354b647d2ffddf7e69f753b90f1a031d9af7e57ca6d0c3ab002db28cedd8"


def helper_catalog(root):
    (root / "bin").mkdir(parents=True)
    (root / "bin/pocketshell-link.exe").write_bytes(b"old cd7 helper")
    return {"files": [{"path": "bin/pocketshell-link.exe", "sha256": "0" * 64, "role": "helper"}],
            "lineage": {"helper": {"version": "cd7c6f6a0c7b", "sha256": "0" * 64}}}


def test_helper_replaces_base_helper_and_lineage(tmp_path):
    root = tmp_path / "runtime"
    catalog = helper_catalog(root)
    receipt = builder.stage_helper(HELPER_INPUT, HELPER_SHA, "git-70f5a4b9e8ee", root, catalog)
    assert builder.digest(root / "bin/pocketshell-link.exe") == HELPER_SHA
    assert catalog["lineage"]["helper"] == {"version": "git-70f5a4b9e8ee", "sha256": HELPER_SHA}
    assert receipt["path"] == "bin/pocketshell-link.exe"


def test_helper_refuses_wrong_digest_or_unpinned_build(tmp_path):
    root = tmp_path / "runtime"
    catalog = helper_catalog(root)
    with pytest.raises(ValueError, match="expected SHA256"):
        builder.stage_helper(HELPER_INPUT, "1" * 64, "v", root, catalog)
    other = tmp_path / "other.exe"
    other.write_bytes(b"unreviewed")
    with pytest.raises(ValueError, match="reviewed Windows build"):
        builder.stage_helper(other, builder.digest(other), "v", root, catalog)
    assert (root / "bin/pocketshell-link.exe").read_bytes() == b"old cd7 helper"


@pytest.mark.skipif(not os.environ.get("POCKETSHELL_TEST_GATEWAY_AUTH_HELPER"),
                    reason="set POCKETSHELL_TEST_GATEWAY_AUTH_HELPER to a host pocketshell-link build")
def test_gateway_auth_probe_against_real_helper():
    assert builder.gateway_auth_probe(os.environ["POCKETSHELL_TEST_GATEWAY_AUTH_HELPER"])["endpoint"] == ""


def test_gateway_auth_probe_refuses_helper_without_command(tmp_path):
    if sys.platform == "win32":
        pytest.skip("POSIX shell stub")
    stub = tmp_path / "old-link"
    stub.write_text("#!/bin/sh\necho 'unknown command' >&2\nexit 2\n")
    stub.chmod(0o755)
    with pytest.raises(ValueError, match="gateway-auth"):
        builder.gateway_auth_probe(stub)
