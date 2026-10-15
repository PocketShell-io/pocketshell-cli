"""Windows-native: re-running tray installers over existing PSC installs.

The regression: v0.5.10 over v0.5.9 on a laptop failed the PSC step with
"Existing PSC version differs", because both carried the same PSC version
with rebuilt bytes. This runs real installers silently as an ordinary
(unelevated) user, in the order users hit them:

previous -> new -> new again -> new over a broken tree -> previous over new
-> new again.

Every new-installer run must leave PSC active from the new content tree with
exit code 0 and a working `psc --version`. The previous installer may keep
its own tree; PSC must stay usable after it.

Runs only when the release workflow provides both installers.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest

NEW = os.environ.get("POCKETSHELL_TEST_NEW_INSTALLER")
NEW_RECEIPT = os.environ.get("POCKETSHELL_TEST_NEW_INSTALLER_RECEIPT")
PREVIOUS = os.environ.get("POCKETSHELL_TEST_PREVIOUS_INSTALLER")

pytestmark = [
    pytest.mark.skipif(sys.platform != "win32", reason="Windows installer"),
    pytest.mark.skipif(not (NEW and NEW_RECEIPT and PREVIOUS), reason="set the POCKETSHELL_TEST_*_INSTALLER inputs"),
]

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "gateway"))

LOCAL = Path(os.environ.get("LOCALAPPDATA", "C:/missing"))
INSTDIR = LOCAL / "Programs" / "PocketShellGateway"
PSC = LOCAL / "PocketShell" / "psc"
SHIM = PSC / "bin" / "psc.cmd"
CMD = str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "cmd.exe")


def run(argv, timeout=1800):
    from unelevated import run_unelevated

    # A real Windows user has no XDG_* overrides; CI runners may.
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("XDG_")}
    code, out = run_unelevated(argv, env=env, cwd=str(LOCAL), timeout=timeout)
    text = out.decode("utf-8", "replace")
    print(f"$ (unelevated) {' '.join(map(str, argv))} -> exit {code}\n{text[-3000:]}")
    return code, text


def install(installer):
    code, _ = run([installer, "/S"])
    log = (INSTDIR / "psc-install.log").read_text(encoding="utf-8", errors="replace")
    print(f"--- psc-install.log ---\n{log[-4000:]}")
    match = re.search(r"PSC installer exit code: (-?\d+)", log)
    return code, (int(match.group(1)) if match else None), log


def active_tree():
    match = re.search(r'call "([^"]+)\\psc\.cmd"', SHIM.read_text(encoding="utf-8"))
    assert match, SHIM.read_text(encoding="utf-8")
    return Path(match.group(1))


def psc_works():
    code, text = run([CMD, "/d", "/c", str(SHIM), "--version"], timeout=120)
    assert code == 0, text
    assert text.strip()


def expected_tree_prefix():
    receipt = json.loads(Path(NEW_RECEIPT).read_text())
    manifest = json.loads((INSTDIR / "psc-package" / "package-manifest.json").read_text())
    return f"{manifest['version']}-{receipt['psc']['installVariant']}-{receipt['psc']['contentId']}"


def assert_new_active(log, psc_code):
    assert psc_code == 0, log
    assert "Existing PSC version differs" not in log
    assert active_tree().name.startswith(expected_tree_prefix()), active_tree()
    psc_works()


def test_reinstalling_over_any_existing_psc_install_succeeds():
    # previous release: what users have today
    code, psc_code, log = install(PREVIOUS)
    assert code == 0, log
    psc_works()
    before = active_tree()

    # new over previous: the reported upgrade
    code, psc_code, log = install(NEW)
    assert code == 0
    assert_new_active(log, psc_code)
    assert active_tree() != before
    upgraded = active_tree()

    # the same version twice: reuses the verified tree
    code, psc_code, log = install(NEW)
    assert code == 0
    assert_new_active(log, psc_code)
    assert active_tree() == upgraded and "Reusing verified PSC tree" in log

    # partly broken: a file of the active tree is gone
    (upgraded / "psc" / "dist" / "cli.js").unlink()
    code, psc_code, log = install(NEW)
    assert code == 0
    assert_new_active(log, psc_code)
    assert "Installed PSC tree" in log

    # older over newer, then newer again
    code, _, log = install(PREVIOUS)
    assert code == 0, log
    psc_works()
    code, psc_code, log = install(NEW)
    assert code == 0
    assert_new_active(log, psc_code)

    # no leftovers from staging or replaced trees
    leftovers = [p.name for p in PSC.iterdir() if p.name.startswith((".stage-", ".trash-"))]
    assert not leftovers, leftovers
