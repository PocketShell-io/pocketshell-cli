import importlib.util
import json
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


def test_offline_psc_preserves_previous_version_and_recatalogs_installer(tmp_path):
    script = tmp_path / "install.ps1"
    script.write_text('param([string]$SshPath = "$env:SystemRoot\\System32\\OpenSSH\\ssh.exe")\n'
                      '$dest = "$base\\$($manifest.version)"\nSet-Acl -LiteralPath $Path -AclObject $acl\n')
    manifest = tmp_path / "package-manifest.json"
    manifest.write_text(json.dumps({"files": {"install.ps1": "before"}}))
    builder.configure_offline_psc(tmp_path)
    assert "$($manifest.version)-$InstallVariant" in script.read_text()
    assert "System32\\OpenSSH" not in script.read_text()
    assert '$item.SetAccessControl($acl)' in script.read_text()
    assert json.loads(manifest.read_text())["files"]["install.ps1"] == builder.digest(script)
    with pytest.raises(ValueError, match="review"):
        builder.configure_offline_psc(tmp_path)


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
    assert receipt["version"] == "0.1.12"
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
