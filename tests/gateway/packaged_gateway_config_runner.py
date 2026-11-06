"""Copied test-only runner: actual isolated embedded Python, no source imports."""
from __future__ import annotations

import ctypes as c
from ctypes import wintypes as w
import json
from pathlib import Path
import sys

PREFIX = "POCKETSHELL_PACKAGED_CONFIG_PROOF="


def elevated():
    kernel = c.WinDLL("kernel32", use_last_error=True)
    adv = c.WinDLL("advapi32", use_last_error=True)
    kernel.GetCurrentProcess.restype = w.HANDLE
    adv.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
    adv.GetTokenInformation.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)]
    kernel.CloseHandle.argtypes = [w.HANDLE]
    token = w.HANDLE()
    assert adv.OpenProcessToken(kernel.GetCurrentProcess(), 8, c.byref(token))
    try:
        value, size = w.DWORD(), w.DWORD()
        assert adv.GetTokenInformation(token, 20, c.byref(value), 4, c.byref(size))
        return bool(value.value)
    finally:
        kernel.CloseHandle(token)


def main(root, work, version):
    root, work = Path(root).resolve(), Path(work).resolve()
    assert sys.flags.isolated and sys.flags.no_site and sys.flags.ignore_environment
    assert "site" not in sys.modules and not elevated(), "must run as an ordinary user"
    assert Path(sys.executable).resolve() == root / "python/python.exe"
    expected = json.loads((work / "expected.json").read_text())
    assert expected["version"] == 1 and len(set(expected["cases"])) == 12
    import pocketshell
    import pocketshell.gateway.vault_enrollment  # noqa: F401
    import pocketshell.gateway.service_windows  # noqa: F401
    import pocketshell.windows_security  # noqa: F401

    assert pocketshell.__version__ == version
    archive = str(root / "python/app.zip").replace("\\", "/").casefold() + "/"

    def provenance():
        files = {name: str(module.__file__) for name, module in sys.modules.copy().items()
                 if name == "pocketshell" or name.startswith("pocketshell.")}
        assert files and all(path.replace("\\", "/").casefold().startswith(archive)
                             for path in files.values()), files
        return files

    provenance()  # before adding isolated test tooling, then before every case
    sys.path.append(str(work / "pytest-support.zip"))
    import os
    os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    import pytest

    class Inventory:
        def __init__(self):
            self.collected, self.passed, self.rejected = [], [], []

        def pytest_collection_finish(self, session):
            self.collected = [item.nodeid.rsplit("::", 1)[-1] for item in session.items]
            assert sorted(self.collected) == sorted(expected["cases"])

        def pytest_runtest_setup(self, item):
            provenance()

        def pytest_runtest_logreport(self, report):
            if report.failed or report.skipped:
                self.rejected.append({"case": report.nodeid, "when": report.when, "outcome": report.outcome})
            if report.when == "call" and report.passed:
                self.passed.append(report.nodeid.rsplit("::", 1)[-1])

    inventory = Inventory()
    status = pytest.main([str(work / expected["suite"]), "-v", "-rs", "--noconftest",
                          "--rootdir", str(work), "--basetemp", str(work / "tmp"),
                          "--import-mode=importlib", "-p", "no:cacheprovider"], plugins=[inventory])
    assert status == 0 and not inventory.rejected, inventory.rejected
    assert sorted(inventory.passed) == sorted(expected["cases"])
    print(PREFIX + json.dumps({"version": version, "elevated": elevated(),
                              "executable": sys.executable, "cases": inventory.passed,
                              "passed": len(inventory.passed), "skipped": 0,
                              "moduleFiles": provenance()}), flush=True)


if __name__ == "__main__":
    main(*sys.argv[1:])
