"""Exercise the packaged Windows runtime without logging in or starting a gateway."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", required=True)
    parser.add_argument("--install-check", help="Fresh userData directory for an endpoint-only installation")
    parser.add_argument("--endpoint-check", help="Existing smoke userData: bind/start/stop in an isolated XDG directory")
    args = parser.parse_args()
    payload = Path(args.payload).resolve()
    root = payload / "runtime"
    def run(argv, timeout=180, env=None):
        result = subprocess.run(argv, capture_output=True, timeout=timeout, creationflags=0x08000000, env=env)
        if result.returncode:
            raise RuntimeError(result.stderr.decode("utf-8", "replace")[-2000:] or result.stdout.decode("utf-8", "replace")[-2000:])
        return result.stdout.decode("utf-8", "replace")
    version = run([str(root / "pocketshell.exe"), "--version"]).strip()
    helper = json.loads(run([str(root / "bin/pocketshell-link.exe"), "version", "--json"]))
    assert helper["protocol"] == "pocketshell-tunnel-v1"
    rpc_help = run([str(root / "python/a.exe"), "rpc", "--stdio", "--help"])
    assert "--stdio" in rpc_help
    sessions = json.loads(run([str(root / "python/a.exe"), "--json", "list"]))
    assert isinstance(sessions, list)
    code = """
import json, threading
from pocketshell.tray.app import TrayApp
from pocketshell.tray.model import TrayModel
class OfflineClient:
    def fetch_status(self):
        return TrayModel(state='offline', summary='Installer smoke test; no gateway started')
app = TrayApp(status_client=OfflineClient(), autostart_checker=lambda:False)
observed = []
def finish():
    observed.append(bool(app._icon and app._icon.visible))
    app.quit()
threading.Timer(3, finish).start()
app.run()
assert observed == [True], observed
print(json.dumps({'tray_visible': True}))
"""
    tray = json.loads(run([str(root / "python/python.exe"), "-I", "-B", "-c", code], timeout=30))
    result = {"version": version, "helper": helper, "visibleTray": tray["tray_visible"], "activeSessions": len(sessions)}
    if args.install_check:
        target = Path(args.install_check).resolve()
        if target.exists():
            raise RuntimeError("The installation check must use a fresh directory")
        target.mkdir(parents=True)
        install = json.loads(run([str(root / "python/python.exe"), "-I", "-B", "-m", "pocketshell", "gateway", "agent", "install",
                                  "--user-data", str(target), "--catalog", str(payload / "host-runtime-catalog.json"),
                                  "--staged", str(root), "--endpoint-keys", "generate", "--port", "22236",
                                  "--json", "--operation-id", "installer-smoke"], timeout=1800))
        assert install["ok"] and install["receipt"]["keys"]["mode"] == "generated"
        result["installedClosure"] = install["receipt"]["installer"]["closure"]
    if args.endpoint_check:
        base = Path(args.endpoint_check).resolve()
        receipt = json.loads((base / "managed-runtime/authority.json").read_text())
        env = dict(os.environ, XDG_CONFIG_HOME=str(base / "isolated-config"))
        entry = [str(root / "python/python.exe"), "-I", "-B", "-m", "pocketshell", "gateway", "agent"]
        def action(verb, *flags):
            return json.loads(run([*entry, verb, *flags, "--json", "--operation-id", "smoke-" + verb],
                                  timeout=900, env=env))
        binding = base / "isolated-config/pocketshell/agent/binding.json"
        expected = hashlib.sha256(binding.read_bytes()).hexdigest() if binding.exists() else "none"
        bound = action("bind", "--manifest", receipt["endpoint"]["manifest"], "--authority",
                       str(base / "managed-runtime/authority.json"), "--expect-binding-sha256", expected)
        assert bound["state"] == "stopped"
        try:
            started = action("start", "--timeout", "300")
            assert started["endpoint"]["state"] == "ready" and started["state"] == "pre-enrollment"
            result["endpointHostKeyProven"] = started["endpoint"]["hostKey"]["proven"]
        finally:
            # Stop has the documented exit 4 for a measured stopped generation.
            stopped = subprocess.run([*entry, "stop", "--json", "--operation-id", "smoke-stop"],
                                     env=env, capture_output=True, timeout=180, creationflags=0x08000000)
            doc = json.loads(stopped.stdout)
            assert stopped.returncode in (0, 4) and doc["state"] == "stopped", doc
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    if sys.platform != "win32":
        raise SystemExit("Run the native smoke check on Windows")
    main()
