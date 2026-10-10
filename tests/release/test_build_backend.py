"""Source controls for the owned backend build driver (review 094ef92c):
the MSYS configure triplet and its emitted DLL path, and an accepted:false
receipt (with the accumulated process records) for EVERY failure class."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "release" / "build_backend_windows.py"


@pytest.fixture
def bb():
    spec = importlib.util.spec_from_file_location("build_backend_windows", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_msys_configure_declares_the_cygwin_build_triplet_and_the_matching_dll_path(bb, tmp_path):
    script = bb.msys_build_script("/C/bw/src")
    assert "--build=x86_64-pc-cygwin" in script and "--with-msys2-runtime-commit=" + bb.MSYS["commit"] in script
    assert "x86_64-w64-mingw32-gcc" in script and "--with-cross-bootstrap" in script and "--disable-dumper" in script  # the winsup cross compiler is checked, never assumed
    assert bb.msys_dll(tmp_path) == tmp_path / "x86_64-pc-cygwin" / "winsup" / "cygwin" / "new-msys-2.0.dll"
    assert "x86_64-pc-msys" not in str(bb.msys_dll(tmp_path))


def _run_main(bb, monkeypatch, tmp_path, fail):
    def build(work, out, rec):
        rec.run("first-step", [sys.executable, "-c", "print('ok')"])
        fail()

    monkeypatch.setattr(bb, "build_msys", build)
    monkeypatch.setattr(sys, "argv", ["x", "--part", "msys", "--work", str(tmp_path / "w"), "--out",
                                      str(tmp_path / "o")])
    code = bb.main()
    receipt = json.loads((tmp_path / "o" / "msys-build-receipt.json").read_text())
    return code, receipt


def _missing_dll():
    raise FileNotFoundError(2, "No such file", "new-msys-2.0.dll")


def _popen():
    raise subprocess.SubprocessError("cannot start")


def _oserror():
    raise PermissionError(13, "Access is denied", "copy")


def _exit():
    raise SystemExit("make failed with natural exit 2")


@pytest.mark.parametrize("fail", [_missing_dll, _popen, _oserror, _exit],
                         ids=["missing-output", "process-creation", "copy-error", "natural-failure"])
def test_every_failure_class_writes_a_refused_receipt_with_the_processes(bb, monkeypatch, tmp_path, fail):
    code, receipt = _run_main(bb, monkeypatch, tmp_path, fail)
    assert code == 1 and receipt["accepted"] is False and "outputs" not in receipt
    assert [p["label"] for p in receipt["processes"]] == ["first-step"]
    assert receipt["processes"][0]["naturalExit"] == 0
    assert receipt["error"]["type"] and len(receipt["error"]["message"]) <= 2000
