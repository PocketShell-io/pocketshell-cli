"""Assemble a Windows tray installer from a verified catalog-v3 closure.

No downloads occur on the end user's machine. The base closure supplies Python,
the reviewed gateway helper, aplexer and its native client, SSH and Git Bash.
The current CLI and frozen tray dependencies replace its Python application.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from pathlib import PurePosixPath
import shutil
import subprocess
import sys
import tempfile
import zipfile

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
from pocketshell.gateway.service_agent_install import parse_catalog  # noqa: E402


def digest(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_inventory(root, rows):
    wanted = {row["path"]: row["sha256"] for row in rows}
    actual = {p.relative_to(root).as_posix(): digest(p) for p in root.rglob("*") if p.is_file()}
    if actual != wanted:
        raise ValueError("The base closure differs from its verified catalog")
    # Windows uses one executable for both names; shipping only a.exe is incomplete.
    if wanted.get("python/a.exe") != wanted.get("python/aplexer.exe") or "python/a.exe" not in wanted:
        raise ValueError("The closure must contain the matching aplexer CLI and worker")


def write_zip(path, entries):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        dirs = {name.rsplit("/", i)[0] + "/" for name in entries for i in range(1, name.count("/") + 1)}
        for name in sorted(dirs):
            archive.writestr(zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0)), b"")
        for name, data in sorted(entries.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)


def stage_psc(archive_path, expected_sha256, destination):
    """Accept only the complete, pinned standalone PSC package; no target downloads."""
    archive_path = Path(archive_path)
    if digest(archive_path) != expected_sha256:
        raise ValueError("PSC zip SHA256 differs from the selected input")
    with zipfile.ZipFile(archive_path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("Duplicate PSC archive member")
        for member in archive.infolist():
            path = PurePosixPath(member.filename)
            if (path.is_absolute() or ".." in path.parts or "\\" in member.filename
                    or ":" in member.filename or member.is_dir()
                    or (member.external_attr >> 16) & 0o170000 == 0o120000):
                raise ValueError("Unsafe PSC archive member")
        manifest = json.loads(archive.read("package-manifest.json"))
        rows = manifest["files"]
        required = {"node.exe", "psc-security.exe", "psc.cmd", "install.ps1", "psc/dist/cli.js"}
        if not required.issubset(rows) or set(names) != set(rows) | {"package-manifest.json"}:
            raise ValueError("Incomplete PSC package inventory")
        for name, sha256 in rows.items():
            if hashlib.sha256(archive.read(name)).hexdigest() != sha256:
                raise ValueError("PSC package inventory digest differs")
        for name in names:
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(name))
    return {"version": manifest["version"], "zipSHA256": expected_sha256,
            "clientCommit": manifest["clientCommit"], "coreCommit": manifest["coreCommit"]}


def stage_ssh_client(archive_path, expected_sha256, destination):
    """Ship only Microsoft's portable client and notices, never its service installer."""
    if digest(archive_path) != expected_sha256:
        raise ValueError("OpenSSH zip SHA256 differs from the selected input")
    names = ("ssh.exe", "LICENSE.txt", "NOTICE.txt")
    destination.mkdir(parents=True)
    with zipfile.ZipFile(archive_path) as archive:
        for name in names:
            member = "OpenSSH-Win64/" + name
            if archive.namelist().count(member) != 1:
                raise ValueError("Missing or duplicate portable SSH client member")
            (destination / name).write_bytes(archive.read(member))
    if sys.platform == "win32":
        command = ("param([string]$Client)\n$s=Get-AuthenticodeSignature -LiteralPath $Client; "
                   "if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch "
                   "'O=Microsoft Corporation(?:,|$)') {exit 1}")
        with tempfile.TemporaryDirectory() as scratch:
            gate = Path(scratch) / "signature.ps1"
            gate.write_text(command)
            subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                            "-File", str(gate), str(destination / "ssh.exe")], check=True)
    return {"zipSHA256": expected_sha256, "sshSHA256": digest(destination / "ssh.exe")}


def configure_offline_psc(destination):
    """Use a separate version tree so a former inbox-SSH binding stays intact."""
    script = destination / "install.ps1"
    text = script.read_text(encoding="utf-8")
    old = 'param([string]$SshPath = "$env:SystemRoot\\System32\\OpenSSH\\ssh.exe")'
    new = ('param([string]$SshPath, [ValidatePattern("^gateway-ssh[0-9]+$")]'
           '[string]$InstallVariant = "gateway-ssh10")')
    prefix = '$dest = "$base\\$($manifest.version)"'
    if text.count(old) != 1 or text.count(prefix) != 1:
        raise ValueError("PSC installer changed; review the offline adaptation")
    # PowerShell 5 Set-Acl tries to write auditing on an existing protected
    # object and can require SeSecurityPrivilege. The .NET object method writes
    # only the owner/DACL sections changed above, with identical private ACEs.
    text = text.replace('Set-Acl -LiteralPath $Path -AclObject $acl', '$item.SetAccessControl($acl)')
    script.write_text(text.replace(old, new).replace(prefix,
                      '$dest = "$base\\$($manifest.version)-$InstallVariant"'), encoding="utf-8")
    manifest_path = destination / "package-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["files"]["install.ps1"] = digest(script)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def build(args):
    source = Path(args.resources).resolve()
    cat_path = source / "host-runtime-catalog.json"
    if digest(cat_path) != args.catalog_sha256:
        raise ValueError("The base catalog is not the selected build input")
    catalog = parse_catalog(cat_path.read_bytes())
    if catalog["version"] != 3:
        raise ValueError("The installer requires the complete catalog-v3 endpoint")
    verify_inventory(source / "runtime", catalog["files"])
    if not (REPO / "src/pocketshell/gateway/status.py").is_file():
        raise ValueError("Merge gateway status and lifecycle support before building")
    out = Path(args.out).resolve()
    if out.exists():
        raise ValueError("Use a fresh output directory")
    root = out / "payload" / "runtime"
    psc_receipt = stage_psc(args.psc_zip, args.psc_sha256, out / "payload" / "psc-package")
    psc_receipt["sshClient"] = stage_ssh_client(args.ssh_zip, args.ssh_sha256, out / "payload" / "psc-ssh")
    configure_offline_psc(out / "payload" / "psc-package")
    psc_receipt["installVariant"] = "gateway-ssh10"
    psc_receipt["adaptedInstallerSHA256"] = digest(out / "payload" / "psc-package/install.ps1")
    shutil.copytree(source / "runtime", root)
    shutil.copyfile(args.tray_launcher, root / "GatewayTray.exe")
    with tempfile.TemporaryDirectory() as scratch:
        work = Path(scratch)
        requirements = work / "requirements.txt"
        requirements.write_bytes(subprocess.check_output([
            "uv", "export", "--frozen", "--extra", "tray", "--no-dev", "--no-emit-project",
            "--format", "requirements-txt"], cwd=REPO))
        site = work / "site"
        subprocess.run(["uv", "pip", "install", "--target", str(site), "--python-platform",
                        "x86_64-pc-windows-msvc", "--python-version", "3.12", "--only-binary", ":all:",
                        "--no-deps", "--require-hashes", "--no-cache", "--link-mode", "copy",
                        "-r", str(requirements)], check=True)
        subprocess.run(["uv", "build", "--wheel", "--out-dir", str(work / "wheel")], cwd=REPO, check=True)
        wheel = next((work / "wheel").glob("pocketshell-*.whl"))
        subprocess.run(["uv", "pip", "install", "--target", str(site), "--python-platform",
                        "x86_64-pc-windows-msvc", "--python-version", "3.12", "--no-deps", str(wheel)], check=True)
        for name in ("bin", "Scripts"):
            shutil.rmtree(site / name, ignore_errors=True)
        native = {p.relative_to(site).parts[0] for p in site.rglob("*") if p.suffix.lower() in (".pyd", ".dll")}
        entries = {}
        for p in sorted(site.rglob("*")):
            if not p.is_file() or "__pycache__" in p.parts or p.name in ("direct_url.json", "uv_cache.json"):
                continue
            rel = p.relative_to(site)
            if rel.parts[0] in native:
                target = root / "python/site-native" / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(p, target)
            else:
                entries[rel.as_posix()] = p.read_bytes()
        write_zip(root / "python/app.zip", entries)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    catalog = copy.deepcopy(catalog)
    catalog["source"] = catalog["lineage"]["cliCommit"] = commit
    catalog["lineage"]["lockSHA256"] = digest(REPO / "uv.lock")
    catalog["release"] = "tray-" + commit[:12]
    roles = {row["path"]: row["role"] for row in catalog["files"]}
    catalog["files"] = [{"path": p.relative_to(root).as_posix(), "sha256": digest(p),
                         "role": roles.get(p.relative_to(root).as_posix(), "module")}
                        for p in sorted(root.rglob("*")) if p.is_file()]
    data = json.dumps(catalog, indent=1, sort_keys=True).encode()
    parse_catalog(data)
    (out / "payload/host-runtime-catalog.json").write_bytes(data)
    if sys.platform == "win32":
        # Catch missing metadata / native wheels before producing a broken EXE.
        subprocess.run([str(root / "python/python.exe"), "-I", "-B", "-c",
                        "import PIL.Image, pystray, pocketshell.tray_bundle, aplexer; print('Bundled imports OK')"], check=True)
    script = REPO / "scripts/release/tray-installer.nsi"
    exe = out / "PocketShellGateway-Setup-x64.exe"
    subprocess.run([args.makensis, f"/DPAYLOAD={out / 'payload'}", f"/DOUTPUT={exe}",
                    f"/DVERSION={catalog['lineage']['cliVersion']}", str(script)], check=True)
    receipt = {"source": commit, "sourceDirty": bool(subprocess.check_output(
        ["git", "status", "--porcelain"], cwd=REPO)), "baseCatalogSHA256": args.catalog_sha256,
        "catalogSHA256": hashlib.sha256(data).hexdigest(), "installerSHA256": digest(exe),
        "installerBytes": exe.stat().st_size, "files": len(catalog["files"]),
        "aplexerSHA256": digest(root / "python/a.exe"), "launcherSHA256": digest(root / "GatewayTray.exe")}
    receipt["psc"] = psc_receipt
    (out / "installer-receipt.json").write_text(json.dumps(receipt, indent=2))
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resources", required=True, help="Extracted resources.tar.gz")
    parser.add_argument("--catalog-sha256", required=True)
    parser.add_argument("--tray-launcher", required=True, help="native/launcher built with -X main.module=pocketshell.tray_bundle")
    parser.add_argument("--psc-zip", required=True, help="Reviewed standalone psc-windows-x64 zip")
    parser.add_argument("--psc-sha256", required=True, help="Expected SHA256 of the PSC zip")
    parser.add_argument("--ssh-zip", required=True, help="Microsoft's portable OpenSSH-Win64.zip")
    parser.add_argument("--ssh-sha256", required=True, help="Expected SHA256 of the OpenSSH zip")
    parser.add_argument("--makensis", required=True)
    parser.add_argument("--out", required=True)
    build(parser.parse_args())
