"""Opt-in real private endpoint check; never enrolls or contacts the gateway."""
import json
import os
from pathlib import Path
import sys

import pytest

BASE = os.environ.get("POCKETSHELL_TRAY_TEST_USERDATA")
pytestmark = pytest.mark.skipif(sys.platform != "win32" or not BASE,
                               reason="requires an endpoint-only smoke installation")


def test_owned_endpoint_ready_then_stopped(monkeypatch):
    from pocketshell.gateway import service_common, service_user_agent
    from pocketshell.tray_supervisor import TrayWindowsApi
    base = Path(BASE).resolve()
    receipt = json.loads((base / "managed-runtime/authority.json").read_text())
    assert receipt["keys"]["mode"] == "generated"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(base / "isolated-config"))
    api = TrayWindowsApi()
    try:
        doc, code = service_user_agent.start(api=api, runner=service_common.run_child,
                                             timeout=300, operation_id="tray-native-start")
        assert code == 0, doc
        assert doc["state"] == "pre-enrollment"
        assert doc["endpoint"]["state"] == "ready"
        assert doc["endpoint"]["hostKey"]["proven"] is True
        record = service_user_agent._guardian_launch()
        assert record["supervision"]["kind"] == "tray-owned" and record["inJob"] is True
    finally:
        stopped, code = service_user_agent.stop(api=api, runner=service_common.run_child,
                                               timeout=120, operation_id="tray-native-stop")
        api.close()
        assert code in (0, 4) and stopped["state"] == "stopped", stopped
