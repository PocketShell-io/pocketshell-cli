"""All twelve config cases against catalogued packaged code as an ordinary user."""
from __future__ import annotations

import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="native packaged Windows runtime")
REPO = Path(__file__).resolve().parents[2]
MANIFEST = REPO / "tests/account/fixtures/windows-gateway-config-native-v1.json"


def run_packaged(root, work, version):
    """Stage only tests/tooling outside the immutable release; no project code."""
    from packaged_gateway_config_runner import PREFIX, elevated
    from pocketshell import windows_security as ws
    assert not work.exists()
    # The CI parent is elevated; name the actual user as owner explicitly so
    # the filtered child can read its test-only workspace without admin rights.
    ws.write_private(work / "workspace.json", b'{"testOnly":true}')
    expected = json.loads(MANIFEST.read_text())
    shutil.copyfile(MANIFEST, work / "expected.json")
    shutil.copyfile(REPO / "tests/account" / expected["suite"], work / expected["suite"])
    shutil.copyfile(Path(__file__).with_name("packaged_gateway_config_runner.py"), work / "runner.py")
    with zipfile.ZipFile(work / "pytest-support.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for name in ("pytest", "pluggy", "iniconfig", "packaging", "pygments", "colorama"):
            distribution = importlib.metadata.distribution(name)
            for entry in distribution.files:
                path = Path(str(entry))
                if ".." in path.parts or "__pycache__" in path.parts or path.suffix == ".pyc":
                    continue
                assert path.parts[0] not in {"pocketshell", "src"}
                source = distribution.locate_file(entry)
                if source.is_file():
                    archive.write(source, path.as_posix())
    env = {key: os.environ[key] for key in ("SystemRoot", "SystemDrive", "ProgramData")}
    env.update(USERPROFILE=str(work), LOCALAPPDATA=str(work), TEMP=str(work), TMP=str(work))
    # No repo, editable/site packages, PYTHONPATH or inherited test plugins.
    argv = [str(root / "python/python.exe"), "-I", "-S", "-B", str(work / "runner.py"),
            str(root), str(work), version]
    if elevated():
        from unelevated import run_unelevated
        code, output = run_unelevated(argv, env=env, cwd=str(work), timeout=180)
    else:
        result = subprocess.run(argv, env=env, cwd=work, capture_output=True, timeout=180,
                                creationflags=0x08000000)
        code, output = result.returncode, result.stdout + result.stderr
    text = output.decode("utf8", errors="replace")
    print(text)
    assert code == 0, text
    receipts = [line.removeprefix(PREFIX) for line in text.splitlines() if line.startswith(PREFIX)]
    assert len(receipts) == 1
    proof = json.loads(receipts[0])
    assert proof["passed"] == 12 and proof["skipped"] == 0 and proof["elevated"] is False
    assert sorted(proof["cases"]) == sorted(expected["cases"])
    assert proof["version"] == version
    assert Path(proof["executable"]).resolve() == root / "python/python.exe"
    prefix = str(root / "python/app.zip").replace("\\", "/").casefold() + "/"
    assert proof["moduleFiles"] and all(path.replace("\\", "/").casefold().startswith(prefix)
                                         for path in proof["moduleFiles"].values())
    return proof


def test_all_config_cases_use_actual_packaged_modules_without_source_fallback(tmp_path):
    output = os.environ.get("POCKETSHELL_TEST_RELEASE_OUT")
    assert output, "mandatory packaged lane must build its own release"
    base = Path(output)
    catalog = json.loads((base / "host-runtime-catalog.json").read_text())
    root = base / "root-a/releases/staged"
    assert root.is_dir()
    # Check the exact packaged code against the CI producer's catalog first.
    import hashlib
    rows = {row["path"]: row["sha256"] for row in catalog["files"]}
    assert hashlib.sha256((root / "python/app.zip").read_bytes()).hexdigest() == rows["python/app.zip"]
    run_packaged(root, tmp_path / "config-proof", catalog["lineage"]["cliVersion"])
