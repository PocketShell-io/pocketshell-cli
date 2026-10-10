#!/usr/bin/env python3
"""Owned rebuild of the generic Windows endpoint backend (root decision, Option B2).

Runs on a normal GitHub-hosted Windows runner. Every input is PUBLIC and pinned
by sha256; every build process is recorded (argv, pid, start/end, natural exit,
stdout/stderr log sha256). Nothing that is built is executed here.

Parts (``--part``):

openssh  OpenSSH_for_Windows_10.3p1, PowerShell/openssh-portable e302fe1 (archive
         8545e33b…) + the reviewed quiet overlay (w32fd.c baeb8d3f…, shell-host.c
         f0e0a17e…; release/inputs/openssh-quiet-e302fe1), dependencies from the
         source's own vcpkg manifest (builtin-baseline a345bbdc; zlib 1.3.2,
         libressl 4.2.0, libfido2 1.16.0, libcbor 0.14.0, overlay ports/triplets),
         MSBuild per project as OWNED-BUILD-V26A (config, win32iocompat,
         openbsd_compat, libssh, sshd, sshd-auth, sshd-session, ssh-shellhost) plus
         sftp-server from the same source.
msys     git-for-windows/msys2-runtime 5a1665c8 (archive ce1a003f…) with the
         reviewed console.cc (717e49fe…; ec3092a1… before), built in the pinned
         git-sdk-64 de64efda (archive a904e472…) by the upstream recipe
         (winsup/autogen.sh, configure --with-msys2-runtime-commit, make).

Usage: build_backend_windows.py --part openssh|msys --work DIR --out DIR
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
INPUTS = REPO / "release" / "inputs"

OPENSSH = {
    "url": "https://github.com/PowerShell/openssh-portable/archive/e302fe1ed190e408573cf0139252e5db26eeba2f.zip",
    "commit": "e302fe1ed190e408573cf0139252e5db26eeba2f",
    "sha256": "8545e33b809f7ec6eb8363cbbbd2d4d68982d8ab7a8b7e6bb63506d82ae62223",
    "overlay": {  # path in the source tree: (upstream sha256, reviewed sha256)
        "contrib/win32/win32compat/w32fd.c": (
            "a964fb8994b4b778fe51db359fa72ba04e4c0cead122156c21f110958f899186",
            "baeb8d3fcf8a24e71b242e890a97771c23c32c0914c2f4f7e763048d409eaf7a"),
        "contrib/win32/win32compat/shell-host.c": (
            "82d580093f4c6587c4a2dd3e888b4c8c38122556bd1396cdcbbd396bab0b5b10",
            "f0e0a17ec66079ee16201abf92041034af2c502973e5a886fc14da2e2ac02c0d"),
    },
}
# The registry checkout must CONTAIN the manifest's override versions (zlib 1.3.2,
# libcbor 0.14.0); the manifest's builtin-baseline a345bbdc is older than them. Pinned
# master commit; the four dependency SOURCE archives are checked against the dossier.
VCPKG = {"repo": "https://github.com/microsoft/vcpkg", "commit": "e456309491fd875487bf02b8a0dca76c1b1b00cc",
         "manifestBaseline": "a345bbdc68cdfda65603e24413b21afb28f110fb"}
DEPENDENCY_SOURCES = {  # dependency-source-downloads.json (reviewed dossier)
    "zlib": "b99a0b86c0ba9360ec7e78c4f1e43b1cbdf1e6936c8fa0f6835c0cd694a495a1",
    "libcbor": "a8c1516e741562cf95aa4479c64916c3d4d2623e24fdc35e414e2320e7300aae",
    "libfido2": "7d86088ef4a48f9faad4ff6f41343328157849153a8dc94d88f4b5461cb29474",
    "libressl": "0f7dba44d7cb8df8d53f2cfbf1955254bc128e0089595f1aba2facfaee8408b2",
}
PROJECTS = ("config", "win32iocompat", "openbsd_compat", "libssh", "sshd", "sshd-auth", "sshd-session",
            "ssh-shellhost", "sftp-server")
OPENSSH_OUTPUTS = ("sshd.exe", "sshd-session.exe", "sshd-auth.exe", "ssh-shellhost.exe", "sftp-server.exe",
                   "LICENSE.txt", "NOTICE.txt")
SDK = "10.0.26100.0"

MSYS = {
    "url": "https://github.com/git-for-windows/msys2-runtime/archive/5a1665c8a0fb24930e55f1621441dfd98a798c15.tar.gz",
    "commit": "5a1665c8a0fb24930e55f1621441dfd98a798c15",
    "sha256": "ce1a003f647119738875010630a25c032c161b5c72cceb8416c5b551781391a9",
    "console": "winsup/cygwin/fhandler/console.cc",
    "consoleBefore": "ec3092a13fc7237d7136cc86401a83549b39cf718136f38bf2f902e236b89e03",
    "consoleAfter": "717e49fe10e8a31df0a21035b8b1f74987460a61b4a2bf34a498ee9ff4710e46",
}
GIT_SDK = {
    "url": "https://github.com/git-for-windows/git-sdk-64/archive/de64efdafd991b2ddf8d9fccd7f549286d039328.tar.gz",
    "commit": "de64efdafd991b2ddf8d9fccd7f549286d039328",
    "sha256": "a904e4721c599aa36e01ff1660ffa4619b022f0d289f0aafe29e6ae7079c6d85",
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Recorder:
    """Owned build processes: argv, pid, times, natural exit, log digests."""

    def __init__(self, logs: Path):
        self.logs = logs
        logs.mkdir(parents=True, exist_ok=True)
        self.processes = []

    def run(self, label: str, argv: list, *, cwd=None, env=None, check=True) -> int:
        out, err = self.logs / f"{label}.stdout.log", self.logs / f"{label}.stderr.log"
        started = time.time()
        with open(out, "wb") as so, open(err, "wb") as se:
            p = subprocess.Popen([str(a) for a in argv], cwd=cwd, env=env, stdout=so, stderr=se,
                                 stdin=subprocess.DEVNULL)
            pid = p.pid
            code = p.wait()
        rec = {"label": label, "pid": pid, "argv": [str(a) for a in argv], "cwd": str(cwd) if cwd else None,
               "started": started, "ended": time.time(), "naturalExit": code,
               "stdout": {"path": out.name, "sha256": sha256(out), "bytes": out.stat().st_size},
               "stderr": {"path": err.name, "sha256": sha256(err), "bytes": err.stat().st_size}}
        self.processes.append(rec)
        print(f"[{label}] exit {code}", flush=True)
        if check and code != 0:
            sys.stdout.write(out.read_text(errors="replace")[-6000:])
            sys.stdout.write(err.read_text(errors="replace")[-3000:])
            raise SystemExit(f"{label} failed with natural exit {code}")
        return code


def fetch(url: str, dest: Path, want: str) -> dict:
    if not dest.exists():
        urllib.request.urlretrieve(url, dest)
    got = sha256(dest)
    if got != want:
        raise SystemExit(f"{url}: sha256 {got} is not the pinned {want}")
    return {"url": url, "sha256": got, "bytes": dest.stat().st_size}


def tool(path) -> dict:
    p = Path(path)
    return {"path": str(p), "sha256": sha256(p)} if p.is_file() else {"path": str(p), "sha256": None}


def vswhere(*args) -> str:
    exe = Path(os.environ["ProgramFiles(x86)"]) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    return subprocess.run([str(exe), *args], capture_output=True, text=True, check=True).stdout.strip()


def build_openssh(work: Path, out: Path, rec: Recorder) -> dict:
    inputs = {"source": fetch(OPENSSH["url"], work / "openssh-e302fe1.zip", OPENSSH["sha256"])}
    src = work / "s"
    with zipfile.ZipFile(work / "openssh-e302fe1.zip") as z:
        z.extractall(work / "unz")
    (work / "unz" / f"openssh-portable-{OPENSSH['commit']}").rename(src)
    overlay = {}
    for rel, (upstream, reviewed) in OPENSSH["overlay"].items():
        target = src / rel
        if sha256(target) != upstream:
            raise SystemExit(f"{rel} is not the upstream file the overlay was reviewed against")
        repl = INPUTS / "openssh-quiet-e302fe1" / Path(rel).name
        if sha256(repl) != reviewed:
            raise SystemExit(f"{repl} is not the reviewed overlay")
        shutil.copyfile(repl, target)
        overlay[rel] = {"upstream": upstream, "reviewed": reviewed}
    inputs["overlay"] = overlay

    vsroot = vswhere("-latest", "-version", "[17.0,18.0)", "-requires", "Microsoft.Component.MSBuild",
                     "-property", "installationPath")
    msbuild = Path(vsroot) / "MSBuild" / "Current" / "Bin" / "amd64" / "MSBuild.exe"
    sln = src / "contrib" / "win32" / "openssh"

    # dependencies: the source's own vcpkg manifest, pinned baseline, overlay ports/triplets
    vcpkg = work / "vcpkg"
    rec.run("vcpkg-clone", ["git", "clone", "--quiet", VCPKG["repo"], vcpkg])  # full history: baseline lookups
    rec.run("vcpkg-checkout", ["git", "-C", vcpkg, "checkout", "--quiet", VCPKG["commit"]])
    rec.run("vcpkg-bootstrap", [vcpkg / "bootstrap-vcpkg.bat", "-disableMetrics"], cwd=vcpkg)
    downloads = work / "vcpkg-downloads"
    downloads.mkdir()
    env = dict(os.environ, VCPKG_ROOT=str(vcpkg), VCPKG_DOWNLOADS=str(downloads), VCPKG_DISABLE_METRICS="1",
               VCPKG_VISUAL_STUDIO_PATH=vsroot, VCPKG_PLATFORM_TOOLSET="v143", VCPKG_BINARY_SOURCES="clear",
               VCPKG_MAX_CONCURRENCY="4")
    installed = sln / "vcpkg_installed" / "x64-custom"
    rec.run("vcpkg-install", [vcpkg / "vcpkg.exe", "install", "--triplet", "x64-custom",
                              f"--overlay-triplets={sln / 'vcpkg_triplets'}",
                              f"--overlay-ports={sln / 'vcpkg_overlay_ports'}",
                              f"--x-manifest-root={sln}", f"--x-install-root={installed}"],
            cwd=sln, env=env)
    dl = {p.name: sha256(p) for p in sorted(downloads.iterdir()) if p.is_file()}
    for name, want in DEPENDENCY_SOURCES.items():
        if want not in dl.values():
            raise SystemExit(f"the {name} source archive is not the reviewed {want[:12]}…: {dl}")
    inputs["vcpkg"] = {**VCPKG, "downloads": dl}
    triplet = installed / "x64-custom"
    props = work / "dependency-append.props"
    props.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">\n  <PropertyGroup>\n'
        f'    <IncludePath>$(IncludePath);{triplet / "include"}</IncludePath>\n'
        f'    <LibraryPath>$(LibraryPath);{triplet / "lib"}</LibraryPath>\n'
        '  </PropertyGroup>\n</Project>\n', encoding="utf-8")
    userprops = work / "user-props"
    userprops.mkdir()
    for project in PROJECTS:
        rec.run(f"msbuild-{project}", [
            msbuild, sln / f"{project}.vcxproj", "/t:Build", "/m:1", "/nr:false", "/nologo", "/v:minimal",
            "/p:Configuration=Release", "/p:Platform=x64", "/p:BuildInParallel=false",
            f"/p:SolutionDir={sln}\\", f"/p:UserRootDir={userprops}\\", f"/p:ForceImportAfterCppTargets={props}",
            "/p:VcpkgEnabled=false", f"/p:WindowsSDKVersion={SDK}", f"/p:WindowsTargetPlatformVersion={SDK}",
            "/p:SpectreMitigation=Spectre"], cwd=sln, env=dict(os.environ, MSBUILDDISABLENODEREUSE="1"))
    built = src / "bin" / "x64" / "Release"
    out.mkdir(parents=True, exist_ok=True)
    files = {}
    for name in OPENSSH_OUTPUTS:
        shutil.copyfile(built / name, out / name)
        files[name] = sha256(out / name)
    shutil.copyfile(triplet / "bin" / "libcrypto.dll", out / "libcrypto.dll")
    files["libcrypto.dll"] = sha256(out / "libcrypto.dll")
    tools = {"msbuild": tool(msbuild), "vsInstall": vsroot,
             "vsVersion": vswhere("-latest", "-version", "[17.0,18.0)", "-property", "catalog_productDisplayVersion"),
             "windowsSdk": SDK, "vcpkgExe": tool(vcpkg / "vcpkg.exe")}
    for p in sorted(Path(vsroot, "VC", "Tools", "MSVC").glob("*/bin/Hostx64/x64/cl.exe")):
        tools.setdefault("cl", []).append(tool(p))
    return {"inputs": inputs, "tools": tools, "outputs": files, "version": "OpenSSH_for_Windows_10.3p1"}


def build_msys(work: Path, out: Path, rec: Recorder) -> dict:
    inputs = {"source": fetch(MSYS["url"], work / "msys2-runtime.tar.gz", MSYS["sha256"]),
              "sdk": fetch(GIT_SDK["url"], work / "git-sdk-64.tar.gz", GIT_SDK["sha256"])}
    sdk = work / "sdk"
    sdk.mkdir()
    # the Windows tar (bsdtar): the SDK snapshot is a checkout made for Windows
    rec.run("sdk-extract", ["tar", "-xzf", work / "git-sdk-64.tar.gz", "-C", sdk, "--strip-components=1"])
    src = work / "src"
    src.mkdir()
    with tarfile.open(work / "msys2-runtime.tar.gz") as t:
        t.extractall(src, filter="tar")
    src = next(src.iterdir())
    console = src / MSYS["console"]
    if sha256(console) != MSYS["consoleBefore"]:
        raise SystemExit("console.cc is not the file the overlay was reviewed against")
    overlay = INPUTS / "msys2-runtime-5a1665c8" / "console.cc"
    if sha256(overlay) != MSYS["consoleAfter"]:
        raise SystemExit("the console.cc overlay is not the reviewed 717e49fe")
    shutil.copyfile(overlay, console)
    inputs["overlay"] = {MSYS["console"]: {"upstream": MSYS["consoleBefore"], "reviewed": MSYS["consoleAfter"]}}
    bash = sdk / "usr" / "bin" / "bash.exe"
    env = dict(os.environ, MSYSTEM="MSYS", CHERE_INVOKING="1", MSYS="winsymlinks:lnk")
    posix = "/" + str(src).replace("\\", "/").replace(":", "", 1)
    script = (f"set -e; cd '{posix}'; (cd winsup && ./autogen.sh); "
              f"./configure --disable-dependency-tracking --with-msys2-runtime-commit={MSYS['commit']}; "
              "make -j4")
    rec.run("msys-build", [bash, "-lc", script], cwd=src, env=env)
    dll = src / "x86_64-pc-msys" / "winsup" / "cygwin" / "new-msys-2.0.dll"
    out.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(dll, out / "msys-2.0.dll")
    tools = {"bash": tool(bash), "gcc": tool(sdk / "usr" / "bin" / "gcc.exe"),
             "make": tool(sdk / "usr" / "bin" / "make.exe")}
    return {"inputs": inputs, "tools": tools, "outputs": {"msys-2.0.dll": sha256(out / "msys-2.0.dll")}}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--part", choices=("openssh", "msys"), required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    work, out = Path(args.work).resolve(), Path(args.out).resolve()
    work.mkdir(parents=True, exist_ok=True)
    rec = Recorder(out / "logs")
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True).stdout.strip()
    tree = subprocess.run(["git", "rev-parse", "HEAD^{tree}"], cwd=REPO, capture_output=True, text=True).stdout.strip()
    started = time.time()
    try:
        result = (build_openssh if args.part == "openssh" else build_msys)(work, out / args.part, rec)
        ok = True
    except SystemExit as exc:
        result, ok = {"error": str(exc)}, False
    receipt = {"schema": "pocketshell-backend-build/v1", "part": args.part, "accepted": ok,
               "checkout": {"commit": commit, "tree": tree, "githubSha": os.environ.get("GITHUB_SHA"),
                            "githubRef": os.environ.get("GITHUB_REF"), "run": os.environ.get("GITHUB_RUN_ID"),
                            "runner": os.environ.get("ImageOS"), "imageVersion": os.environ.get("ImageVersion")},
               "started": started, "ended": time.time(), "processes": rec.processes, **result,
               "executedOutputs": False}
    (out / f"{args.part}-build-receipt.json").write_text(json.dumps(receipt, indent=1))
    print(json.dumps({k: receipt.get(k) for k in ("part", "accepted", "outputs", "error")}, indent=1))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
