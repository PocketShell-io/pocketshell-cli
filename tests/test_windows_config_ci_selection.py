"""Dropping either the direct or actual-packaged security lane is a CI failure."""
import json
from pathlib import Path

import yaml


def test_direct_and_packaged_gateway_config_security_are_both_selected():
    repo = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((repo / ".github/workflows/ci.yml").read_text())
    steps = workflow["jobs"]["windows-gateway"]["steps"]
    direct = next(step["run"] for step in steps if step.get("name") == "Windows unit tests")
    native = next(step["run"] for step in steps if step.get("name") == "Ordinary-user agent, installer and pocketshell-verify.exe (native)")
    assert "tests/account/test_windows_gateway_config_native.py" in direct.split()
    assert "tests/gateway/test_windows_packaged_gateway_config_native.py" in native.split()
    manifest = json.loads((repo / "tests/account/fixtures/windows-gateway-config-native-v1.json").read_text())
    assert manifest["suite"] == "test_windows_gateway_config_native.py"
    assert len(manifest["cases"]) == len(set(manifest["cases"])) == 12
