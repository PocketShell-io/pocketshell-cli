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
import struct
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


APLEXER_VERSION = "0.1.13"
APLEXER_WHEELS = {
    "cli": ("aplexer-0.1.13-py3-none-win_amd64.whl", "14364c4a1c7c3bc50a49811820d34b379f3cec64c88e92cf458ce77d8b562374"),
    "client": ("aplexer_client-0.1.13-cp311-abi3-win_amd64.whl", "fb787aa5fb93865c7797b328da4ae76b0dae78bcaefe0ab1ae430a0a455d6dd5"),
}


def stage_aplexer(cli_wheel, client_wheel, root):
    """Replace the old closure pair with the pinned Windows RPC release.

    Validate both archives completely before replacing any runtime files.
    Inputs are obtained at build time; the installer remains offline.
    """
    packages = {}
    for kind, path in (("cli", Path(cli_wheel)), ("client", Path(client_wheel))):
        filename, expected = APLEXER_WHEELS[kind]
        if path.name != filename or digest(path) != expected:
            raise ValueError("Aplexer wheel differs from the pinned 0.1.13 Windows release")
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise ValueError("Duplicate aplexer wheel member")
            for member in names:
                rel = PurePosixPath(member)
                if rel.is_absolute() or ".." in rel.parts or "\\" in member or ":" in member:
                    raise ValueError("Unsafe aplexer wheel member")
            packages[kind] = {n: archive.read(n) for n in names if not n.endswith("/")}
    executable = packages["cli"]["aplexer_cli/bin/aplexer.exe"]
    packages["client"]["aplexer/_native.pyd"]  # require the complete matching client
    site = root / "python/site-native"
    for pattern in ("aplexer", "aplexer_cli", "aplexer*.dist-info"):
        for old in site.glob(pattern):
            shutil.rmtree(old)
    for files in packages.values():
        for name, data in files.items():
            target = site / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    for name in ("a.exe", "aplexer.exe"):
        (root / "python" / name).write_bytes(executable)
    return {"version": APLEXER_VERSION, "cliWheelSHA256": digest(Path(cli_wheel)),
            "clientWheelSHA256": digest(Path(client_wheel)),
            "exeSHA256": hashlib.sha256(executable).hexdigest(),
            "pydSHA256": digest(site / "aplexer/_native.pyd")}


def rpc_stdio_ping(a_exe, timeout=60):
    """Prove the bundled helper serves PSC-RPC-1 over framed stdio.

    A `--help` stub could pass while the resident helper is missing (exactly
    what the pinned 0.1.11 wheel did: no `rpc` subcommand at all), so drive
    one real framed ping round trip: u32 big-endian length prefix plus UTF-8
    JSON, requiring `{"protocol":1,"id":...,"result":{"ok":true}}` back.
    Returns the helper generation string.
    """
    request = json.dumps({"protocol": 1, "id": "tray-rpc-check",
                          "method": "ping", "params": {}}).encode()
    frame = struct.pack(">I", len(request)) + request
    popen = {"stdin": subprocess.PIPE, "stdout": subprocess.PIPE,
             "stderr": subprocess.DEVNULL}
    if sys.platform == "win32":
        popen["creationflags"] = 0x08000000
    try:
        child = subprocess.Popen([str(a_exe), "rpc", "--stdio", "--protocol", "1"], **popen)
    except OSError as exc:
        raise ValueError(f"Cannot launch the bundled rpc helper: {exc}")
    try:
        # Closing stdin after the request makes the helper answer, see EOF and
        # exit, so communicate() collects the single framed response.
        try:
            out = child.communicate(frame, timeout=timeout)[0]
        except subprocess.TimeoutExpired:
            child.kill()
            raise ValueError("The bundled rpc helper did not answer the ping in time")
        if child.returncode != 0:
            raise ValueError("The bundled rpc helper exited without serving the ping")
        if len(out) < 4:
            raise ValueError("The bundled rpc helper produced no framed response")
        (size,) = struct.unpack(">I", out[:4])
        if size == 0 or size > 16 * 1024 * 1024 or len(out[4:]) != size:
            raise ValueError("The bundled rpc helper produced an invalid frame")
        try:
            reply = json.loads(out[4:])
        except ValueError:
            raise ValueError("The bundled rpc helper did not answer JSON")
        result = reply.get("result") if isinstance(reply, dict) else None
        if (not isinstance(reply, dict) or reply.get("protocol") != 1
                or reply.get("id") != "tray-rpc-check"
                or not isinstance(result, dict) or not result.get("ok")):
            raise ValueError(f"The bundled rpc helper ping failed: {out[4:204]!r}")
        return result.get("generation")
    finally:
        if child.poll() is None:
            child.kill()


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
        command = ('param([string]$Client)\nImport-Module '
                   '"$PSHOME\\Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1" -Force\n'
                   "$s=Get-AuthenticodeSignature -LiteralPath $Client; "
                   "if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch "
                   "'O=Microsoft Corporation(?:,|$)') {exit 1}")
        with tempfile.TemporaryDirectory() as scratch:
            gate = Path(scratch) / "signature.ps1"
            gate.write_text(command)
            subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                            "-File", str(gate), str(destination / "ssh.exe")], check=True)
    return {"zipSHA256": expected_sha256, "sshSHA256": digest(destination / "ssh.exe")}


def psc_content_id(manifest, ssh_sha256):
    """Short identity of what install.ps1 writes into a version tree.

    The upstream installer treats an existing `<version>` tree as the same
    package and refuses any byte difference ("Existing PSC version differs;
    use a fresh version"). Rebuilt packages keep their version string, so
    the tree name carries this digest of every installed file plus the
    bundled ssh.exe: changed content installs side by side into a fresh
    tree and the bin shim switches to it, while an identical reinstall
    still maps onto its existing tree.
    """
    rows = sorted((name, sha) for name, sha in manifest["files"].items() if name != "install.ps1")
    material = json.dumps({"files": rows, "ssh": ssh_sha256}, separators=(",", ":")).encode()
    return hashlib.sha256(material).hexdigest()[:12]


# The standalone package's own install.ps1 (pocketshell-tui-client
# scripts/windows/install.ps1 at the workflow's CLIENT_REF). It is replaced by
# scripts/release/psc-install.ps1; a different upstream script must be reviewed
# for changes the replacement has to carry over before this pin moves.
UPSTREAM_PSC_INSTALL_SHA256 = "f22200ddc623459c1a6bb522438ee241aa3367459020a774c8fd6b1abf8542e3"
PSC_INSTALL_TEMPLATE = REPO / "scripts/release/psc-install.ps1"


def configure_offline_psc(destination, ssh_sha256):
    """Install PSC with the tray's own content-addressed, atomic installer.

    Re-running any installer over any existing PSC install must succeed: the
    tree is named by content, a verified tree is reused, anything else is
    rebuilt in staging and published by rename, and the shim switches last.
    """
    script = destination / "install.ps1"
    if digest(script) != UPSTREAM_PSC_INSTALL_SHA256:
        raise ValueError("PSC installer changed; review the offline adaptation")
    manifest_path = destination / "package-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    content_id = psc_content_id(manifest, ssh_sha256)
    template = PSC_INSTALL_TEMPLATE.read_text(encoding="utf-8")
    if template.count("'@CONTENT_ID@'") != 1:
        raise ValueError("PSC installer template has no content id placeholder")
    script.write_bytes(template.replace("@CONTENT_ID@", content_id).encode("utf-8"))
    manifest["files"]["install.ps1"] = digest(script)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return content_id


def stage_private_backend(source, receipt_sha256, root, catalog):
    """Accept a complete, measured private-shell rebuild, never arbitrary sshd.exe."""
    source = Path(source)
    receipt = source / "receipt.json"
    if digest(receipt) != receipt_sha256:
        raise ValueError("Endpoint build receipt SHA256 differs")
    doc = json.loads(receipt.read_text())
    required = {"sshd.exe", "sshd-auth.exe", "sshd-session.exe", "ssh-shellhost.exe",
                "sftp-server.exe", "libcrypto.dll", "LICENSE.txt", "NOTICE.txt"}
    if (set(doc["files"]) != required or set(p.name for p in source.iterdir()) != required | {"receipt.json"}
            or doc["sourceArchiveSHA256"] != "8545e33b809f7ec6eb8363cbbbd2d4d68982d8ab7a8b7e6bb63506d82ae62223"
            or not doc.get("processes") or any(p["naturalExit"] != 0 for p in doc["processes"])):
        raise ValueError("Incomplete private endpoint build")
    for name, sha256 in doc["files"].items():
        if digest(source / name) != sha256:
            raise ValueError("Private endpoint build file digest differs")
    for name in doc["files"]:
        shutil.copyfile(source / name, root / "endpoint/bin" / name)
    catalog["lineage"]["endpoint"]["openssh"]["buildReceiptSHA256"] = receipt_sha256
    catalog["lineage"]["endpoint"]["sftp"]["sha256"] = doc["files"]["sftp-server.exe"]
    return {"receiptSHA256": receipt_sha256, "files": doc["files"], "source": doc["source"]}


def stage_helper(helper, expected_sha256, version, root, catalog):
    """Replace the BASE closure's pocketshell-link with a reviewed newer build.

    The digest must be on the Windows allow-list, so the installed guardian
    and wrapper will accept what this installer ships.
    """
    from pocketshell.gateway.helper import WINDOWS_HELPER_SHA256
    from pocketshell.gateway.service_windows import ALLOWED_HELPER_SHA256

    helper = Path(helper)
    if digest(helper) != expected_sha256:
        raise ValueError("The helper differs from its expected SHA256")
    if expected_sha256 not in ALLOWED_HELPER_SHA256 or expected_sha256 != WINDOWS_HELPER_SHA256:
        raise ValueError("The helper is not the reviewed Windows build pinned by this CLI")
    rows = [row for row in catalog["files"] if row["role"] == "helper"]
    if len(rows) != 1:
        raise ValueError("The base catalog has no single helper")
    target = root / rows[0]["path"]
    if not target.is_file():
        raise ValueError("The base closure has no helper file")
    shutil.copyfile(helper, target)
    catalog["lineage"]["helper"] = {"version": version, "sha256": expected_sha256}
    return {"path": rows[0]["path"], "sha256": expected_sha256, "version": version}


def gateway_auth_probe(helper, timeout=30):
    """Prove the bundled helper answers `gateway-auth show --json`."""
    with tempfile.TemporaryDirectory() as scratch:
        proc = subprocess.run([str(helper), "gateway-auth", "show", "--json", "--config-dir", scratch],
                              capture_output=True, timeout=timeout)
    if proc.returncode != 0:
        raise ValueError("The bundled helper does not support gateway-auth")
    doc = json.loads(proc.stdout)
    if doc.get("policy") != "host" or doc.get("source") != "default":
        raise ValueError("The bundled helper reported an unexpected gateway-auth default")
    return doc


def stage_guardian(root, catalog):
    from pocketshell.gateway import service_endpoint as ep
    source = REPO / "release/inputs/guardian-servicing"
    expected = (ep.SERVICING_GUARDIAN_SHA256,
                "cab601e27e9814ee8c4e3cd72e0dfd55fd2808682d302655725885b4a4812231",
                "e92bbe02c497c959702b35cfd2d4444a073eafe6e17d5e3872449c3bd4f6b1ce")
    for name, sha in zip(ep.SOURCE_NAMES, expected):
        if digest(source / name) != sha:
            raise ValueError("Servicing guardian differs from its reviewed source")
    for name in ep.SOURCE_NAMES:
        shutil.copyfile(source / name, root / "guardian" / name)
    catalog["lineage"]["guardian"]["sourceSHA256"] = expected[0]


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
    psc_receipt["contentId"] = configure_offline_psc(out / "payload" / "psc-package",
                                                     psc_receipt["sshClient"]["sshSHA256"])
    psc_receipt["installVariant"] = "gateway-ssh10"
    psc_receipt["adaptedInstallerSHA256"] = digest(out / "payload" / "psc-package/install.ps1")
    shutil.copytree(source / "runtime", root)
    # Readiness and gateway ssh must work before PSC is installed, with no
    # optional inbox OpenSSH feature. Keep the signed client in the measured
    # closure as well as PSC's separate per-user package.
    shutil.copytree(out / "payload" / "psc-ssh", root / "psc-ssh")
    backend_receipt = stage_private_backend(args.endpoint_backend, args.endpoint_backend_receipt_sha256, root, catalog)
    shutil.copyfile(Path(args.endpoint_backend) / "receipt.json", out / "payload/private-endpoint-build-receipt.json")
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
    stage_guardian(root, catalog)
    helper_receipt = stage_helper(args.helper, args.helper_sha256, args.helper_version, root, catalog)
    if sys.platform == "win32":
        gateway_auth_probe(root / helper_receipt["path"])
    aplexer_receipt = stage_aplexer(args.aplexer_cli_wheel, args.aplexer_client_wheel, root)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    catalog = copy.deepcopy(catalog)
    catalog["source"] = catalog["lineage"]["cliCommit"] = commit
    from pocketshell import __version__
    catalog["lineage"]["cliVersion"] = __version__
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
        version = subprocess.check_output([str(root / "python/a.exe"), "--version"], text=True).strip()
        if version != "a " + APLEXER_VERSION:
            raise ValueError("Bundled aplexer executable version differs")
        subprocess.run([str(root / "python/a.exe"), "list", "--help"], check=True)
        subprocess.run([str(root / "python/a.exe"), "rpc", "--help"], check=True)
        rpc_stdio_ping(root / "python/a.exe")
    script = REPO / "scripts/release/tray-installer.nsi"
    exe = out / "PocketShellGateway-Setup-x64.exe"
    subprocess.run([args.makensis, f"/DPAYLOAD={out / 'payload'}", f"/DOUTPUT={exe}",
                    f"/DVERSION={catalog['lineage']['cliVersion']}", str(script)], check=True)
    receipt = {"source": commit, "sourceDirty": bool(subprocess.check_output(
        ["git", "status", "--porcelain"], cwd=REPO)), "baseCatalogSHA256": args.catalog_sha256,
        "catalogSHA256": hashlib.sha256(data).hexdigest(), "installerSHA256": digest(exe),
        "installerBytes": exe.stat().st_size, "files": len(catalog["files"]),
        "aplexerSHA256": digest(root / "python/a.exe"), "launcherSHA256": digest(root / "GatewayTray.exe")}
    receipt["aplexer"] = aplexer_receipt
    receipt["helper"] = helper_receipt
    receipt["psc"] = psc_receipt
    receipt["privateEndpoint"] = backend_receipt
    (out / "installer-receipt.json").write_text(json.dumps(receipt, indent=2))
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resources", required=True, help="Extracted resources.tar.gz")
    parser.add_argument("--catalog-sha256", required=True)
    parser.add_argument("--aplexer-cli-wheel", required=True, help="Pinned aplexer 0.1.13 Windows CLI wheel")
    parser.add_argument("--aplexer-client-wheel", required=True, help="Pinned aplexer-client 0.1.13 Windows wheel")
    parser.add_argument("--tray-launcher", required=True, help="native/launcher built with -X main.module=pocketshell.tray_bundle")
    parser.add_argument("--psc-zip", required=True, help="Reviewed standalone psc-windows-x64 zip")
    parser.add_argument("--psc-sha256", required=True, help="Expected SHA256 of the PSC zip")
    parser.add_argument("--ssh-zip", required=True, help="Microsoft's portable OpenSSH-Win64.zip")
    parser.add_argument("--ssh-sha256", required=True, help="Expected SHA256 of the OpenSSH zip")
    parser.add_argument("--endpoint-backend", required=True, help="Complete owned private-shell OpenSSH rebuild")
    parser.add_argument("--endpoint-backend-receipt-sha256", required=True)
    parser.add_argument("--helper", required=True, help="Reviewed pocketshell-link Windows build (release/inputs)")
    parser.add_argument("--helper-sha256", required=True, help="Expected SHA256 of the helper")
    parser.add_argument("--helper-version", required=True, help="Helper version for the catalog lineage")
    parser.add_argument("--makensis", required=True)
    parser.add_argument("--out", required=True)
    build(parser.parse_args())
