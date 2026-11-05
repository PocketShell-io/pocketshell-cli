"""Real kernel oracle; runs only in an owned disposable bounded container."""
import json
import os
from pathlib import Path
import subprocess
import sys

from pocketshell.runtime import inherited_cgroup

workspace = Path("/tmp/inherited-work")
workspace.mkdir()
state = Path("/tmp/inherited-state")
os.environ.update(APLEXER_STATE_DIR=str(state), APLEXER_RUNTIME_DIR="/tmp/inherited-runtime",
                  APLEXER_CONFIG="/tmp/inherited-config.toml")
mode = sys.argv[1]
extra = ["--mem", "128M"] if mode == "too-small" else []
command = [sys.executable, "-m", "pocketshell", "sessions", "create", "first-shell",
           "--cwd", str(workspace), "--json", *extra]
result = subprocess.run(command, capture_output=True, text=True, timeout=30)
created = {}
try:
    if mode != "bounded":
        assert result.returncode != 0, result.stdout
        assert not list(state.glob("sessions/*/session.json")), "refused launch left a worker/session"
        print(json.dumps({"case": mode, "refused": True}))
    else:
        assert result.returncode == 0, result.stderr + result.stdout
        created = json.loads(result.stdout)
        assert created["created"] is True
        proof = inherited_cgroup.discover(12 * 1024**3)
        assert created["memory_enforcement"] == proof.public()
        assert proof.memory_max_bytes == 384 * 1024**2
        records = list(state.glob("sessions/*/session.json"))
        assert len(records) == 1
        record = json.loads(records[0].read_text())
        assert not record.get("limits", {}).get("memory_bytes"), "must not claim an independent 12G scope"
        current = Path("/proc/self/cgroup").read_text()
        for field in ("worker_pid", "workload_pid"):
            pid = record[field]
            assert type(pid) is int and pid > 0
            assert Path(f"/proc/{pid}/cgroup").read_text() == current, f"{field} escaped inherited domain"
        try:
            with open("/sys/fs/cgroup/cgroup.procs", "w"):
                pass
        except OSError:
            pass
        else:
            raise AssertionError("the workload could modify cgroup membership")
        print(json.dumps({"case": mode, "created": True, "enforcement": proof.public(),
                          "worker_and_workload_same_cgroup": True}))
finally:
    if created.get("id"):
        stopped = subprocess.run([sys.executable, "-m", "pocketshell", "sessions", "kill",
                                  created["id"], "--json"], capture_output=True, text=True, timeout=20)
        assert stopped.returncode == 0, stopped.stderr + stopped.stdout
