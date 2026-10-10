#!/usr/bin/env python3
"""Build the ordinary-v2 Windows release closure and its catalog (agreement §14).

The closure is assembled cross-platform from PINNED inputs only, so its bytes
are the same on every build host and at every install location:

    <release>/pocketshell.exe            role cli         (native/launcher, Go, reproducible)
    <release>/python/python.exe          role interpreter (python-build-standalone, pinned archive)
    <release>/python/python312._pth      fixes sys.path to the closure (no site, no PATH)
    <release>/python/python312.zip       the stdlib (py + unchecked-hash .pyc), minus tests/GUI/tooling
    <release>/python/app.zip             pure-Python packages from uv.lock + pocketshell (py + .pyc)
    <release>/python/site-native/...     packages with native extensions (sourceless unchecked .pyc + .pyd)
    <release>/python/DLLs/...            the needed extension modules / DLLs only
    <release>/guardian/guardian.py       role guardian    (6cf7ae85…)
    <release>/guardian/native_api.py     role native-api  (cab601e2…)
    <release>/guardian/policy.py         role policy      (e92bbe02…)
    <release>/bin/pocketshell-link.exe   role helper      (the reviewed helper; f9582de6… for cd7)

Usage:
    build_closure.py --out DIR --helper EXE --helper-sha256 HEX --helper-version V \
        [--guardian-dir DIR (default: release/inputs/guardian-6cf7ae85)] [--pbs-archive FILE] [--twice]

`--twice` builds into two different directories and requires byte-identical
inventories (the relocation/reproducibility proof). Requires uv and go.
Nothing is installed or run on Windows by this script.
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
import tempfile
import urllib.request
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from pocketshell.gateway import service_agent_install as inst  # noqa: E402

PBS_VERSION = "3.12.13"
PBS_URL = ("https://github.com/astral-sh/python-build-standalone/releases/download/20260310/"
           "cpython-3.12.13%2B20260310-x86_64-pc-windows-msvc-install_only_stripped.tar.gz")
PBS_SHA256 = "a814e8406b698ad491e1073717d644479e86abf34a3d5897b4d581381b4b8164"
GUARDIAN_PINS = {  # the reviewed 6cf7ae85 guardian source triple
    "guardian.py": "6cf7ae85ad21b23496e7187da7e3bb4f171adef5f63edd2fd01f6ce6435bd047",
    "native_api.py": "cab601e27e9814ee8c4e3cd72e0dfd55fd2808682d302655725885b4a4812231",
    "policy.py": "e92bbe02c497c959702b35cfd2d4444a073eafe6e17d5e3872449c3bd4f6b1ce",
}
GUARDIAN3_PINS = {  # the e862645d successor (agreement §16.14): the generic catalog v3 trio
    "guardian.py": "e862645ddc374801f1ae921be3bf66afeb0ccff03d82adb909ad1b4ec0bdd877",
    "native_api.py": "cab601e27e9814ee8c4e3cd72e0dfd55fd2808682d302655725885b4a4812231",
    "policy.py": "e92bbe02c497c959702b35cfd2d4444a073eafe6e17d5e3872449c3bd4f6b1ce",
}
# --- catalog v3: the generic endpoint backend (root decision B2 + owned CI rebuild) ----------
GIT_URL = "https://github.com/git-for-windows/git/releases/download/v2.56.0.windows.2/Git-2.56.0.2-64-bit.tar.bz2"
GIT_SHA256 = "16ca394bdb94b372267d79e1e10b68763674f73e03e0648202a7971a8a730a84"
GIT_VERSION = "2.56.0.2"
GIT_MEMBERS = 9622                     # 9525 regular + 92 hard links + 5 symlinks, all materialized
MSYS_ORIGINAL = "2a89b7c31b323c42e2fb37900af087aeb27417694e630a210bc75b0369410bc7"
APLEXER_ZIP_SHA256 = "676d516b71568070e7925f40aba66be538fc6c4cd308432b846febdbd15fbfa6"  # root-accepted fc396 artifact 11660695501
APLEXER = {"exe": "e3c741789e6306d037c883294c0e2b9d61702b7994fd844bc761bb5f56389b13",
           "pyd": "4a70877e4fccb4a81e971a7fe3f051586e574f3cbf7dceddec3ec2dfaf7700db",
           "cliWheel": "7bf0f8197a4999b678b699c0f798a8185c839943aa8b54b7acc1f4e50c757747", "clientWheel": "28b4586e9ee57d40b7a402d60158dac18db3ac56a2e4caa8abb83158757af91d", "head": "fc396eb0"}
OPENSSH_FILES = ("sshd.exe", "sshd-session.exe", "sshd-auth.exe", "ssh-shellhost.exe", "sftp-server.exe",
                 "libcrypto.dll", "LICENSE.txt", "NOTICE.txt")
POLICY_VERSION = 1
GO_TOOLCHAIN = "go1.26.8"
TOP_FILES = {"python.exe", "python312.dll", "python3.dll", "vcruntime140.dll", "vcruntime140_1.dll", "LICENSE.txt"}
DLLS = {"_asyncio.pyd", "_bz2.pyd", "_ctypes.pyd", "_decimal.pyd", "_elementtree.pyd", "_hashlib.pyd", "_lzma.pyd",
        "_multiprocessing.pyd", "_overlapped.pyd", "_queue.pyd", "_socket.pyd", "_ssl.pyd", "_uuid.pyd", "_wmi.pyd",
        "_zoneinfo.pyd", "pyexpat.pyd", "select.pyd", "unicodedata.pyd", "libcrypto-3-x64.dll", "libssl-3-x64.dll",
        "libffi-8.dll"}
STDLIB_EXCLUDE = {"site-packages", "test", "idlelib", "tkinter", "turtledemo", "ensurepip", "lib2to3", "pydoc_data",
                  "venv", "__pycache__", "sqlite3", "dbm", "curses"}
NATIVE_TOP = ("cryptography", "cffi", "_cffi_backend")  # extension modules cannot load from a zip
ZIP_TIME = (1980, 1, 1, 0, 0, 0)
PTH = "python312.zip\nDLLs\napp.zip\nsite-native\n..\\guardian\n"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(*argv, **kw) -> str:
    return subprocess.run([str(a) for a in argv], check=True, capture_output=True, text=True, **kw).stdout


def compiler() -> str:
    """A CPython 3.12.13 to produce bytecode identical to the shipped interpreter's."""
    run("uv", "python", "install", PBS_VERSION)
    return run("uv", "python", "find", PBS_VERSION).strip()


COMPILE = r"""
import importlib.util, py_compile, sys, json
for src, dst, name in json.load(sys.stdin):
    py_compile.compile(src, cfile=dst, dfile=name, doraise=True,
                       invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
"""


def compile_many(py: str, jobs: list) -> None:
    """jobs = [(source path, legacy .pyc path, name recorded in the code object)]"""
    subprocess.run([py, "-I", "-c", COMPILE], input=json.dumps(jobs), text=True, check=True)


def deterministic_zip(dest: Path, entries: dict) -> None:
    """entries: archive name -> bytes; sorted, fixed time/permissions."""
    # explicit directory entries: zipimport (3.12) resolves implicit namespace
    # packages (e.g. `google`) only through a directory entry in the archive
    dirs = {name.rsplit("/", i)[0] + "/" for name in entries for i in range(1, name.count("/") + 1)}
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name in sorted(dirs):
            info = zipfile.ZipInfo(name, ZIP_TIME)
            info.external_attr = (0o40755 << 16) | 0x10
            info.create_system = 0
            z.writestr(info, b"")
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            info.create_system = 0
            z.writestr(info, entries[name])


def tree_with_pyc(root: Path, py: str, scratch: Path, keep_source: bool) -> dict:
    """Relative name -> bytes for every file under root, with a legacy
    unchecked-hash .pyc next to each .py (sourceless when not keep_source)."""
    files = sorted(p for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts)
    jobs, out = [], {}
    for p in files:
        rel = p.relative_to(root).as_posix()
        if p.suffix == ".py":
            dst = scratch / (rel + "c")
            dst.parent.mkdir(parents=True, exist_ok=True)
            jobs.append((str(p), str(dst), rel))
            if keep_source:
                out[rel] = p.read_bytes()
        elif p.suffix in (".pyi",) or p.name == "py.typed":
            continue
        else:
            out[rel] = p.read_bytes()
    compile_many(py, jobs)
    for _src, dst, rel in jobs:
        out[rel + "c"] = Path(dst).read_bytes()
    return out


def normalize_dist_info(site: Path) -> None:
    """Drop installer bookkeeping that records build-host paths or times
    (direct_url.json, uv_cache.json) and RECORD rows for files not shipped."""
    for info in site.glob("*.dist-info"):
        for name in ("direct_url.json", "uv_cache.json"):
            (info / name).unlink(missing_ok=True)
        record = info / "RECORD"
        if record.exists():
            rows = [r for r in record.read_text().splitlines()
                    if r and (r.split(",")[0].endswith("RECORD") or (site / r.split(",")[0]).is_file())]
            record.write_text("\n".join(rows) + "\n")


def build(out: Path, args, py: str, work: Path) -> dict:
    release = out
    if release.exists():
        raise SystemExit(f"{release} exists; use a fresh directory")
    pyd = release / "python"
    (pyd / "DLLs").mkdir(parents=True)

    # 1. interpreter (pinned archive)
    stdlib = work / "Lib"
    with tarfile.open(args.pbs_archive) as tar:
        for m in tar.getmembers():
            if not m.isfile():
                continue
            parts = Path(m.name).parts  # python/...
            if len(parts) == 2 and parts[1] in TOP_FILES:
                (pyd / parts[1]).write_bytes(tar.extractfile(m).read())
            elif len(parts) == 3 and parts[1] == "DLLs" and parts[2] in DLLS:
                (pyd / "DLLs" / parts[2]).write_bytes(tar.extractfile(m).read())
            elif len(parts) > 2 and parts[1] == "Lib" and parts[2] not in STDLIB_EXCLUDE \
                    and "__pycache__" not in parts and not stdlib.joinpath(*parts[2:]).exists():
                target = stdlib.joinpath(*parts[2:])
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(tar.extractfile(m).read())
    missing = (TOP_FILES - {p.name for p in pyd.iterdir()}) | (DLLS - {p.name for p in (pyd / "DLLs").iterdir()})
    if missing:
        raise SystemExit(f"the interpreter archive lacks {sorted(missing)}")
    deterministic_zip(pyd / "python312.zip", tree_with_pyc(stdlib, py, work / "pyc-stdlib", keep_source=True))
    (pyd / "python312._pth").write_bytes(PTH.replace("\n", "\r\n").encode())

    # 2. packages from uv.lock (hash-pinned) + this project's wheel
    site = work / "site"
    reqs = work / "requirements.txt"
    reqs.write_text(run("uv", "export", "--frozen", "--no-dev", "--no-emit-project", "--format",
                        "requirements-txt", cwd=REPO))
    common = ["--target", str(site), "--python-platform", "x86_64-pc-windows-msvc", "--python-version", "3.12",
              "--only-binary", ":all:", "--no-deps", "--no-cache", "--link-mode", "copy"]
    run("uv", "pip", "install", *common, "--require-hashes", "-r", str(reqs))
    env = dict(os.environ, SOURCE_DATE_EPOCH=args.source_date_epoch)
    run("uv", "build", "--wheel", "--out-dir", str(work / "wheel"), cwd=REPO, env=env)
    wheel = next((work / "wheel").glob("pocketshell-*.whl"))
    run("uv", "pip", "install", *common, str(wheel))
    for junk in ("bin", "Scripts"):
        shutil.rmtree(site / junk, ignore_errors=True)
    normalize_dist_info(site)
    native = work / "native"
    native.mkdir()
    for p in sorted(site.iterdir()):
        top = p.name.split("-")[0].split(".")[0]
        if top in NATIVE_TOP:
            shutil.move(str(p), native / p.name)
    for p in site.rglob("_yaml*.pyd"):
        p.unlink()  # PyYAML falls back to its pure loader; a .pyd cannot load from a zip
    if any(site.rglob("*.pyd")):
        raise SystemExit(f"extension modules left for the zip: {list(site.rglob('*.pyd'))}")
    deterministic_zip(pyd / "app.zip", tree_with_pyc(site, py, work / "pyc-site", keep_source=True))
    if args.v3:
        meta3 = add_aplexer_client(native, args)
    for rel, data in tree_with_pyc(native, py, work / "pyc-native", keep_source=False).items():
        target = pyd / "site-native" / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    # 3. guardian triple, helper, launcher
    (release / "guardian").mkdir()
    for name, pin in (GUARDIAN3_PINS if args.v3 else GUARDIAN_PINS).items():
        src = Path(args.guardian_dir) / name
        if sha256(src) != pin:
            raise SystemExit(f"{src} is not the reviewed {name} ({pin[:12]}…)")
        shutil.copyfile(src, release / "guardian" / name)
    (release / "bin").mkdir()
    shutil.copyfile(args.helper, release / "bin" / "pocketshell-link.exe")
    # pinned toolchain: the launcher bytes are the same on every build host
    benv = dict(os.environ, GOOS="windows", GOARCH="amd64", CGO_ENABLED="0", GOTOOLCHAIN=GO_TOOLCHAIN,
                GOFLAGS="-mod=readonly")
    # -H=windowsgui: a GUI-subsystem launcher, so no console window is ever allocated for it
    run("go", "-C", REPO / "native" / "launcher", "build", "-trimpath", "-buildvcs=false",
        "-ldflags=-s -w -buildid= -H=windowsgui",
        "-o", release / "pocketshell.exe", ".", env=benv)
    meta = {"wheel": wheel.name, "wheelSHA256": sha256(wheel), "requirementsSHA256": sha256(reqs)}
    if args.v3:
        meta.update(meta3)
        meta.update(add_backend(release, args))
    return meta


def _verified_receipt(directory: Path, part: str) -> dict:
    receipt = json.loads((directory / f"{part}-build-receipt.json").read_text())
    if receipt.get("accepted") is not True or receipt.get("executedOutputs") is not False:
        raise SystemExit(f"the {part} backend build receipt is not an accepted build")
    for name, digest in receipt["outputs"].items():
        if sha256(directory / part / name) != digest:
            raise SystemExit(f"{part}/{name} is not the bytes its build receipt records")
    return receipt


def add_aplexer_client(native: Path, args) -> dict:
    """The accepted fresh aplexer fc396 pair: the client package (with
    _native.pyd 4a70877e) into site-native; the exe pair is placed by
    add_backend next to python.exe."""
    z = Path(args.aplexer_zip)
    if sha256(z) != APLEXER_ZIP_SHA256:
        raise SystemExit("the aplexer artifact is not the accepted fc396 ZIP")
    with zipfile.ZipFile(z) as outer:
        exe, pyd = outer.read("native/aplexer.exe"), outer.read("native/_native.pyd")
        cli = next(n for n in outer.namelist() if n.startswith("cli-dist/") and n.endswith(".whl"))
        client = next(n for n in outer.namelist() if n.startswith("client-dist/") and n.endswith(".whl"))
        cli_bytes, client_bytes = outer.read(cli), outer.read(client)
    if hashlib.sha256(exe).hexdigest() != APLEXER["exe"] or hashlib.sha256(pyd).hexdigest() != APLEXER["pyd"]:
        raise SystemExit("the aplexer native pair is not the accepted e3c74178/4a70877e")
    for data, pin in ((cli_bytes, APLEXER["cliWheel"]), (client_bytes, APLEXER["clientWheel"])):
        if hashlib.sha256(data).hexdigest() != pin:
            raise SystemExit("an aplexer wheel is not the accepted one")
    import io

    with zipfile.ZipFile(io.BytesIO(cli_bytes)) as w:
        if w.read("aplexer_cli/bin/aplexer.exe") != exe:
            raise SystemExit("the CLI wheel's aplexer.exe is not the native exe")
    with zipfile.ZipFile(io.BytesIO(client_bytes)) as w:
        if w.read("aplexer/_native.pyd") != pyd:
            raise SystemExit("the client wheel's _native.pyd is not the native pyd")
        for name in w.namelist():
            if name.startswith("aplexer/") and not name.endswith("/"):
                target = native / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(w.read(name))
    args.aplexer_exe = exe
    return {"aplexer": {"zipSHA256": sha256(z), "exeSHA256": APLEXER["exe"], "pydSHA256": APLEXER["pyd"],
                        "cliWheelSHA256": hashlib.sha256(cli_bytes).hexdigest(),
                        "clientWheelSHA256": hashlib.sha256(client_bytes).hexdigest(), "head": APLEXER["head"]}}


SYMLINK_COOKIE = b"!<symlink>\xff\xfe"


def add_backend(release: Path, args) -> dict:
    """endpoint/bin: the owned OpenSSH 10.3p1 build; endpoint/shell: the
    Git-for-Windows 2.56.0.2 tree (every member; hard links materialized as
    copies of their target, symlinks as Cygwin symlink-cookie files), with
    usr/bin/msys-2.0.dll replaced by the owned 717e49fe MSYS build; python/
    a.exe + aplexer.exe: the accepted fc396 exe."""
    ossh = _verified_receipt(Path(args.backend_openssh), "openssh")
    msys = _verified_receipt(Path(args.backend_msys), "msys")
    bin_dir = release / "endpoint" / "bin"
    bin_dir.mkdir(parents=True)
    for name in OPENSSH_FILES:
        shutil.copyfile(Path(args.backend_openssh) / "openssh" / name, bin_dir / name)
    shell = release / "endpoint" / "shell"
    shell.mkdir(parents=True)
    members = 0
    with tarfile.open(args.git_archive) as tar:
        for m in tar.getmembers():
            if m.isdir():
                continue
            name = m.name.lstrip("./")
            target = shell.joinpath(*name.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            if m.issym():
                data = SYMLINK_COOKIE + (m.linkname.encode("utf-16-le")) + b"\0\0"
            elif m.islnk():
                data = tar.extractfile(tar.getmember(m.linkname)).read()
            elif m.isfile():
                data = tar.extractfile(m).read()
            else:
                raise SystemExit(f"unexpected member type in the Git archive: {name}")
            target.write_bytes(data)
            members += 1
    if members != GIT_MEMBERS:
        raise SystemExit(f"the Git archive has {members} file members, not {GIT_MEMBERS}")
    dll = shell / "usr" / "bin" / "msys-2.0.dll"
    if sha256(dll) != MSYS_ORIGINAL:
        raise SystemExit("the archive's msys-2.0.dll is not the reviewed original 2a89b7c3")
    shutil.copyfile(Path(args.backend_msys) / "msys" / "msys-2.0.dll", dll)
    for name in ("a.exe", "aplexer.exe"):
        (release / "python" / name).write_bytes(args.aplexer_exe)
    return {"backend": {"openssh": {"receiptSHA256": sha256(Path(args.backend_openssh) / "openssh-build-receipt.json"),
                                    "checkout": ossh["checkout"], "outputs": ossh["outputs"]},
                        "msys": {"receiptSHA256": sha256(Path(args.backend_msys) / "msys-build-receipt.json"),
                                 "checkout": msys["checkout"], "outputs": msys["outputs"]},
                        "git": {"url": GIT_URL, "sha256": GIT_SHA256, "version": GIT_VERSION, "members": members,
                                "replaced": {"usr/bin/msys-2.0.dll": {"before": MSYS_ORIGINAL,
                                                                     "after": msys["outputs"]["msys-2.0.dll"]}}}}}


def catalog_for(release: Path, args, commit: str) -> dict:
    roles = {"pocketshell.exe": "cli", "python/python.exe": "interpreter", "guardian/guardian.py": "guardian",
             "guardian/native_api.py": "native-api", "guardian/policy.py": "policy",
             "bin/pocketshell-link.exe": "helper"}
    if args.v3:
        roles.update({"endpoint/bin/sshd.exe": "sshd", "endpoint/bin/sftp-server.exe": "sftp",
                      "endpoint/shell/usr/bin/bash.exe": "backend-shell",
                      "endpoint/shell/usr/bin/msys-2.0.dll": "backend-dll"})
    files = []
    for p in sorted(release.rglob("*")):
        if p.is_file():
            rel = p.relative_to(release).as_posix()
            files.append({"path": rel, "sha256": sha256(p), "role": roles.get(rel, "module")})
    by = {f["role"]: f["sha256"] for f in files if f["role"] != "module"}
    project = run("uv", "version", "--short", cwd=REPO).strip()
    c = {"version": 3 if args.v3 else 2, "release": f"cli-{project.replace('.', '-')}-{commit[:12]}",
         "source": commit,
         "platform": "win32-x64", "api": "ordinary-v2",
         "lineage": {"cliVersion": project, "cliCommit": commit, "agentApi": 1,
                     "guardian": {"abi": "e862645d" if args.v3 else "6cf7ae85", "sourceSHA256": by["guardian"]},
                     "nativeApi": {"sourceSHA256": by["native-api"]},
                     "policy": {"version": POLICY_VERSION, "sourceSHA256": by["policy"]},
                     "interpreter": {"distribution": "python-build-standalone", "version": PBS_VERSION,
                                     "sha256": by["interpreter"]},
                     "helper": {"version": args.helper_version, "sha256": by["helper"]},
                     "lockSHA256": sha256(REPO / "uv.lock")},
         "files": files}
    if args.v3:
        c["lineage"]["endpoint"] = {
            "openssh": {"version": "OpenSSH_for_Windows_10.3p1", "sourceCommit": "e302fe1ed190e408573cf0139252e5db26eeba2f",
                        "buildReceiptSHA256": sha256(Path(args.backend_openssh) / "openssh-build-receipt.json")},
            "sftp": {"version": "OpenSSH_for_Windows_10.3p1", "sha256": by["sftp"]},
            "backendShell": {"distribution": "git-for-windows", "version": GIT_VERSION, "sha256": by["backend-shell"]}}
    data = json.dumps(c, indent=1, sort_keys=True).encode()
    inst.parse_catalog(data)  # the producer's own closed validator (roles, pins, path guards)
    return c


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--helper", required=True)
    ap.add_argument("--helper-sha256", required=True)
    ap.add_argument("--helper-version", required=True)
    ap.add_argument("--guardian-dir", default=None)
    ap.add_argument("--backend-openssh", help="catalog v3: the owned OpenSSH build artifact dir")
    ap.add_argument("--backend-msys", help="catalog v3: the owned MSYS build artifact dir")
    ap.add_argument("--git-archive", help="catalog v3: Git-2.56.0.2-64-bit.tar.bz2 (16ca394b; fetched if absent)")
    ap.add_argument("--aplexer-zip", help="catalog v3: the accepted fc396 windows-native ZIP")
    ap.add_argument("--pbs-archive")
    ap.add_argument("--twice", action="store_true")
    args = ap.parse_args()
    args.v3 = bool(args.backend_openssh)
    if args.v3 and not (args.backend_msys and args.aplexer_zip):
        raise SystemExit("catalog v3 needs --backend-openssh, --backend-msys and --aplexer-zip")
    args.guardian_dir = args.guardian_dir or str(REPO / "release" / "inputs" /
                                                 ("guardian-e862645d" if args.v3 else "guardian-6cf7ae85"))
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    if sha256(Path(args.helper)) != args.helper_sha256:
        raise SystemExit("the helper does not match --helper-sha256")
    if not args.pbs_archive:
        args.pbs_archive = str(out / "pbs.tar.gz")
        urllib.request.urlretrieve(PBS_URL, args.pbs_archive)
    if sha256(Path(args.pbs_archive)) != PBS_SHA256:
        raise SystemExit("the interpreter archive does not match the pinned sha256")
    if args.v3:
        if not args.git_archive:
            args.git_archive = str(out / "git.tar.bz2")
            if not Path(args.git_archive).exists():
                urllib.request.urlretrieve(GIT_URL, args.git_archive)
        if sha256(Path(args.git_archive)) != GIT_SHA256:
            raise SystemExit("the Git archive does not match the pinned sha256")
    commit = run("git", "rev-parse", "HEAD", cwd=REPO).strip()
    dirty = run("git", "status", "--porcelain", cwd=REPO).strip()
    args.source_date_epoch = run("git", "log", "-1", "--format=%ct", cwd=REPO).strip()
    py = compiler()
    builds = []
    for name in ("a", "b") if args.twice else ("a",):
        with tempfile.TemporaryDirectory() as tmp:
            target = out / f"root-{name}" / "releases" / "staged"
            meta = build(target, args, py, Path(tmp))
            builds.append((target, meta))
    catalogs = [catalog_for(t, args, commit) for t, _m in builds]
    if args.twice and catalogs[0]["files"] != catalogs[1]["files"]:
        diff = [a["path"] for a, b in zip(catalogs[0]["files"], catalogs[1]["files"]) if a != b]
        raise SystemExit(f"NOT reproducible across install roots: {diff[:10]}")
    data = json.dumps(catalogs[0], indent=1, sort_keys=True).encode()
    (out / "host-runtime-catalog.json").write_bytes(data)
    receipt = {
        "schema": "pocketshell-ordinary-v2-release-build/v1",
        "source": commit, "sourceDirty": bool(dirty),
        "inputs": {"pbs": {"url": PBS_URL, "sha256": PBS_SHA256, "version": PBS_VERSION},
                   "guardian": GUARDIAN3_PINS if args.v3 else GUARDIAN_PINS, "helper": {"sha256": args.helper_sha256, "version": args.helper_version},
                   "uvLockSHA256": sha256(REPO / "uv.lock"), **builds[0][1]},
        "tools": {"uv": run("uv", "--version").strip(),
                  "go": run("go", "env", "GOVERSION", env=dict(os.environ, GOTOOLCHAIN=GO_TOOLCHAIN)).strip(),
                  "compiler": run(py, "-c", "import sys;print(sys.version)").strip()},
        "outputs": {"catalogSHA256": hashlib.sha256(data).hexdigest(), "catalogBytes": len(data),
                    "files": len(catalogs[0]["files"]), "release": catalogs[0]["release"],
                    "roots": [str(t) for t, _m in builds],
                    "reproducibleAcrossRoots": bool(args.twice)},
        "bounds": {"catalogFitsVerifierDocument": len(data) <= inst.MAX_DOCUMENT,
                   "filesWithinVerifierRequests": len(catalogs[0]["files"]) + 3 <= inst.MAX_REQUESTS,
                   "inventoryWithinBound": len(catalogs[0]["files"]) <= (inst.CATALOG3_MAX_FILES if args.v3
                                                                           else inst.MAX_FILES)},
    }
    (out / "build-receipt.json").write_text(json.dumps(receipt, indent=1))
    print(json.dumps(receipt["outputs"] | receipt["bounds"], indent=1))
    return 0 if all(receipt["bounds"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
