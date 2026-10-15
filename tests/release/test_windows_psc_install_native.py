"""Windows-native: the tray's PSC installer over any existing PSC install.

Fast CI gate for scripts/release/psc-install.ps1, without building an
installer. It extracts the previous release's installer (pinned digest), takes
its PSC package and portable ssh.exe, and runs the install scripts directly as
an ordinary (unelevated) user:

- the previous release's own install.ps1 (what users have today)
- the new installer: exit 0, PSC active from its content tree
- the same package again: the verified tree is reused
- the reported bug: same PSC version, one rebuilt file
- a partly broken active tree
- the previous installer over the new one, then the new one again
- a package whose checks fail: exit 3, the previous PSC stays active

Runs when POCKETSHELL_TEST_PREVIOUS_INSTALLER names the previous installer.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

PREVIOUS = os.environ.get("POCKETSHELL_TEST_PREVIOUS_INSTALLER")

pytestmark = [
    pytest.mark.skipif(sys.platform != "win32", reason="Windows PSC installer"),
    pytest.mark.skipif(not PREVIOUS, reason="set POCKETSHELL_TEST_PREVIOUS_INSTALLER"),
]

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests" / "gateway"))
spec = importlib.util.spec_from_file_location("tray_installer", REPO / "scripts/release/build_tray_installer.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

SYSTEM_ROOT = os.environ.get("SystemRoot", r"C:\Windows")
POWERSHELL = str(Path(SYSTEM_ROOT) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")
CMD = str(Path(SYSTEM_ROOT) / "System32" / "cmd.exe")
LOCAL = Path(os.environ.get("LOCALAPPDATA", r"C:\missing"))
PSC = LOCAL / "PocketShell" / "psc"
SHIM = PSC / "bin" / "psc.cmd"


def user_env():
    # A real Windows user has no XDG_* overrides; CI runners may.
    return {k: v for k, v in os.environ.items() if not k.upper().startswith("XDG_")}


def run(argv, timeout=900):
    from unelevated import run_unelevated

    code, out = run_unelevated([str(a) for a in argv], env=user_env(), cwd=str(LOCAL), timeout=timeout)
    text = out.decode("utf-8", "replace")
    print(f"$ (unelevated) {subprocess.list2cmdline([str(a) for a in argv])} -> exit {code}\n{text[-4000:]}")
    return code, text


@pytest.fixture(scope="module")
def previous(tmp_path_factory):
    """The previous installer's PSC package and ssh.exe, extracted with 7z."""
    out = tmp_path_factory.mktemp("previous")
    subprocess.run(["7z", "x", "-y", f"-o{out}", PREVIOUS], check=True, capture_output=True)
    manifest = next(out.rglob("psc-package/package-manifest.json"))
    package = manifest.parent
    ssh = next(out.rglob("psc-ssh/ssh.exe"))
    print("previous package", package, "ssh", ssh)
    print({k: v for k, v in os.environ.items() if k.upper().startswith(("XDG_", "TEMP", "TMP", "LOCALAPPDATA",
                                                                            "USERPROFILE", "APPDATA"))})
    return package, ssh


def new_package(previous_package, ssh, dest, mutate=None):
    """A copy of the package with the tray's installer (and an optional change)."""
    shutil.copytree(previous_package, dest)
    manifest_path = dest / "package-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if mutate:
        for name in mutate(dest):
            manifest["files"][name] = builder.digest(dest / name)
    content_id = builder.psc_content_id(manifest, builder.digest(ssh))
    template = builder.PSC_INSTALL_TEMPLATE.read_text(encoding="utf-8")
    (dest / "install.ps1").write_bytes(template.replace("@CONTENT_ID@", content_id).encode("utf-8"))
    manifest["files"]["install.ps1"] = builder.digest(dest / "install.ps1")
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return content_id, manifest["version"]


def install(package, ssh):
    return run([POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-File", package / "install.ps1", "-SshPath", ssh, "-InstallVariant", "gateway-ssh10"])


def active_tree():
    match = re.search(r'call "([^"]+)\\psc\.cmd"', SHIM.read_text(encoding="utf-8"))
    assert match, SHIM.read_text(encoding="utf-8")
    return Path(match.group(1))


def psc_works():
    code, text = run([CMD, "/d", "/c", SHIM, "--version"], timeout=120)
    if code != 0:
        # Diagnostics: the same entry point directly, and the user state roots.
        tree = active_tree()
        run([tree / "node.exe", tree / "psc" / "dist" / "cli.js", "hosts"], timeout=120)
        for root in ("pocketshell-client", "pocketshell-client-account", "pocketshell-client-runtime"):
            print(root, (LOCAL / "PocketShell" / root).exists())
    assert code == 0, text


def rebuilt(dest):
    """The reported case: same PSC version, one rebuilt JS file."""
    target = next(p for p in sorted((dest / "psc").rglob("*.js")) if "node_modules" in p.parts)
    target.write_bytes(target.read_bytes() + b"\n// rebuilt\n")
    return [target.relative_to(dest).as_posix()]


def broken_cli(dest):
    """A package that passes inventory but fails its own `--version` check."""
    target = dest / "psc" / "dist" / "cli.js"
    target.write_text("process.exit(7);\n", encoding="utf-8")
    return ["psc/dist/cli.js"]


def test_psc_install_over_any_existing_install(previous, tmp_path):
    package, ssh = previous

    # 1. the previous release's own installer
    code, text = install(package, ssh)
    assert code == 0, text
    psc_works()
    old_tree = active_tree()

    # 2. new over previous
    content_id, version = new_package(package, ssh, tmp_path / "new")
    code, text = install(tmp_path / "new", ssh)
    assert code == 0, text
    assert active_tree().name == f"{version}-gateway-ssh10-{content_id}"
    psc_works()

    # 3. the same package again reuses its verified tree
    code, text = install(tmp_path / "new", ssh)
    assert code == 0 and "Reusing verified PSC tree" in text, text
    assert active_tree().name == f"{version}-gateway-ssh10-{content_id}"

    # 4. the reported bug: same version, rebuilt bytes
    rebuilt_id, _ = new_package(package, ssh, tmp_path / "rebuilt", rebuilt)
    assert rebuilt_id != content_id
    code, text = install(tmp_path / "rebuilt", ssh)
    assert code == 0, text
    assert "Existing PSC version differs" not in text
    assert active_tree().name == f"{version}-gateway-ssh10-{rebuilt_id}"
    psc_works()

    # 5. a partly broken active tree is rebuilt
    (active_tree() / "psc" / "dist" / "cli.js").unlink()
    code, text = install(tmp_path / "rebuilt", ssh)
    assert code == 0 and "Installed PSC tree" in text, text
    psc_works()

    # 6. the previous installer over the new one, then the new one again
    code, text = install(package, ssh)
    assert code == 0, text
    assert active_tree() == old_tree
    psc_works()
    code, text = install(tmp_path / "new", ssh)
    assert code == 0, text
    assert active_tree().name == f"{version}-gateway-ssh10-{content_id}"
    psc_works()

    # 7. a package that cannot be activated keeps the previous PSC: exit 3
    before = active_tree()
    new_package(package, ssh, tmp_path / "failing", broken_cli)
    code, text = install(tmp_path / "failing", ssh)
    assert code == 3, text
    assert "previous PSC stays active" in text
    assert active_tree() == before
    psc_works()

    leftovers = [p.name for p in PSC.iterdir() if p.name.startswith((".stage-", ".trash-"))]
    assert not leftovers, leftovers
    assert hashlib.sha256(SHIM.read_bytes()).hexdigest()
