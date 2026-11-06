"""Fail closed unless every real packaged Windows lifecycle case executes."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

CASES = {
    "test_fresh_create_pty_reconnect_and_owned_kill",
    "test_project_cap_is_kernel_enforced_not_only_reported",
    "test_invalid_caps_and_mutable_selectors_fail_closed",
    "test_private_pty_encoder_preserves_one_exact_windows_operand",
    "test_private_profile_preserves_complete_scripts_and_interactive_shell",
    "test_packaged_launchers_preserve_console_and_quiet_stdio",
}


class Inventory:
    def __init__(self):
        self.collected, self.passed, self.rejected = [], [], []

    def pytest_collection_finish(self, session):
        self.collected = [item.name for item in session.items]

    def pytest_runtest_logreport(self, report):
        if report.skipped or report.failed:
            self.rejected.append(report.nodeid)
        if report.when == "call" and report.passed:
            self.passed.append(report.nodeid.rsplit("::", 1)[-1])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--payload", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    assert sys.platform == "win32", "native gate cannot be qualified on another platform"
    args.out.mkdir(parents=True, exist_ok=False)
    proof_path = args.out / "native-proof.json"
    os.environ["POCKETSHELL_TRAY_TERMINAL_PAYLOAD"] = str(args.payload.resolve())
    os.environ["POCKETSHELL_TRAY_TERMINAL_PROOF"] = str(proof_path.resolve())
    inventory = Inventory()
    test = Path(__file__).resolve().parents[2] / "tests/release/test_windows_tray_terminal_native.py"
    encoder = test.with_name("test_private_pty_argv_native.py")
    code = pytest.main([str(test), str(encoder), "-v", "-rA", "-s",
                        "--junitxml=" + str(args.out / "junit.xml")], plugins=[inventory])
    result = {"expected": sorted(CASES), "collected": inventory.collected,
              "passed": inventory.passed, "rejected": inventory.rejected, "pytestCode": int(code)}
    (args.out / "result.json").write_text(json.dumps(result, indent=2))
    assert code == 0 and len(inventory.collected) == len(CASES) and set(inventory.collected) == CASES
    assert len(inventory.passed) == len(CASES) and set(inventory.passed) == CASES and not inventory.rejected
    proof = json.loads(proof_path.read_text())
    assert proof["qualification"] == "clean-exact-head-artifact"
    assert proof["provenance"]["elevated"] is False and proof["provenance"]["isolated"] is True
    assert len(proof["proofs"]) == 12 and all(row["independentFileOracle"] for row in proof["proofs"])
    assert any(row.get("interruptVerified") is True for row in proof["proofs"])
    assert len(proof["killProofs"]) == 5 and all(len(row["ownedProcessesGone"]) == 2 for row in proof["killProofs"])
    observations = proof["memoryObservations"]
    assert len(observations) == 2
    python_sha = hashlib.sha256((args.payload / "runtime/python/python.exe").read_bytes()).hexdigest()
    interpreter = proof["provenance"]["module"].replace("\\", "/").casefold().split("/app.zip/", 1)[0] + "/python.exe"
    assert all(row["isolated"] is True and row["childJobMember"] is True and row["imageVerified"] is True
               and row["imageSHA256"] == python_sha
               and row["imagePath"].replace("\\", "/").casefold() == interpreter for row in observations)
    assert all(row["kernelFlags"] & 0x200 and row["kernelFlags"] & 0x2000
               and not row["kernelFlags"] & (0x800 | 0x1000)
               and row["before"]["memory_limit_bytes"] == row["after"]["memory_limit_bytes"] == row["kernelLimitBytes"]
               for row in observations)
    control, bounded = observations
    assert control["kernelLimitBytes"] == 12 * 1024**3 and control["nativeExit"] == 0
    assert control["allocation"]["value"]["allocated"] is True
    assert control["before"]["oom_kill_count"] == control["after"]["oom_kill_count"]
    assert bounded["kernelLimitBytes"] == 64 * 1024**2 and bounded["nativeExit"] == 0xC000012D
    assert bounded["after"]["oom_kill_count"] == bounded["before"]["oom_kill_count"] + 1
    assert len(proof["oomPreservations"]) == 1
    preserved = proof["oomPreservations"][0]
    assert preserved["preservedBeforeExplicitCleanup"] is True and len(preserved["preservationSHA256"]) == 64
    ended = preserved["nativeEndedRecord"]
    assert ended["exit"]["oom_killed"] is True and ended["phase"] == ended["state"] == "exited"
    assert ended["worker_alive"] is False and ended["containment_empty"] is True
    assert bounded["before"]["job"] == bounded["after"]["job"] == "aplexer-" + preserved["id"]
    assert preserved["firstKill"]["uncertain"] is False and "not confirmed" in preserved["firstKill"]["error"]
    assert preserved["absence"]["namedJobAbsent"] is True
    explicit = [row for row in proof["killProofs"] if row["explicitEndedCleanup"]]
    assert len(explicit) == 1 and explicit[0]["id"] == preserved["id"]
    assert explicit[0]["ownedProcessesGone"] == preserved["absence"]["ownedPIDsUnallocated"]


if __name__ == "__main__":
    main()
