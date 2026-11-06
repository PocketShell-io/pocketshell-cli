"""Mandatory normal-tray artifact gate: actual private SSH and native PTYs."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows native terminal")


@pytest.fixture(scope="module")
def endpoint():
    sys.path[:0] = [str(Path(__file__).parents[1] / "gateway"), str(Path(__file__).parent)]
    from tray_terminal_fixture import Endpoint
    payload = os.environ["POCKETSHELL_TRAY_TERMINAL_PAYLOAD"]  # missing input is a failure, never a skip
    host = Endpoint(payload)
    host.proofs = []
    try:
        host.start()
        yield host
    finally:
        host.close()
        proof = {"qualification": host.qualification, "source": host.catalog["source"],
                 "provenance": getattr(host, "provenance", None), "proofs": host.proofs,
                 "killProofs": host.kill_proofs, "memoryObservations": host.memory_observations,
                 "oomPreservations": host.oom_preservations}
        Path(os.environ["POCKETSHELL_TRAY_TERMINAL_PROOF"]).write_text(json.dumps(proof, indent=2))


def test_fresh_create_pty_reconnect_and_owned_kill(endpoint):
    host = endpoint
    control = host.create("control-" + host.nonce[:8])
    target = host.create("fresh-" + host.nonce[:8])
    assert target["id"] != control["id"] and target["created"] is True
    proof = host.kernel_oracle(target["id"])
    assert proof["bytes"] == 12 * 1024**3
    assert target["memory_enforcement"]["memory_limit_bytes"] == proof["bytes"]
    host.proofs += [host.attach_io(target["id"], "first", interrupt_probe=True), host.attach_io(target["id"], "reconnect")]
    host.kill(target["id"])
    assert control["id"] in {row["id"] for row in host.rows()}
    host.proofs.append(host.attach_io(control["id"], "unrelated-preserved"))
    host.kill(control["id"])


def test_project_cap_is_kernel_enforced_not_only_reported(endpoint):
    host = endpoint
    control = host.create("allocation-control-" + host.nonce[:8])
    host.proofs.append(host.attach_io(control["id"], "kernel-allows-128m", allocation_probe="allow"))
    config = host.workspace / "cgroups.toml"
    assert not config.exists()
    config.write_text('mem = "64M"\n')
    try:
        target = host.create("bounded-" + host.nonce[:8])
        proof = host.kernel_oracle(target["id"])
        assert proof["bytes"] == 64 * 1024**2
        host.proofs.append({"kernelBound": proof, **host.attach_io(
            target["id"], "kernel-refused-128m", allocation_probe="deny")})
        host.kill(target["id"], after_oom=True)
        assert control["id"] in {row["id"] for row in host.rows()}
        host.kill(control["id"])
    finally:
        config.unlink()


def test_invalid_caps_and_mutable_selectors_fail_closed(endpoint):
    host = endpoint
    control = host.create("preserved-" + host.nonce[:8])
    before = {row["id"] for row in host.rows()}
    cwd = shlex.quote(host.sftp_workspace())
    for cap in ("none", "invalid", "1M"):
        code, output = host.exec(f"pocketshell sessions create --json --cwd {cwd} --mem {cap} -- denied")
        assert code != 0 and "error" in json.loads(output)
        assert {row["id"] for row in host.rows()} == before
    config = host.workspace / "cgroups.toml"
    config.write_text('mem = "none"\n')
    try:
        code, output = host.exec(f"pocketshell sessions create --json --cwd {cwd} -- denied-project")
        assert code != 0 and "error" in json.loads(output)
    finally:
        config.unlink()
    for command in ("attach", "kill --json"):
        code, _ = host.exec(f"pocketshell sessions {command} -- " + shlex.quote(control["name"]))
        assert code != 0
    assert {row["id"] for row in host.rows()} == before
    host.proofs.append(host.attach_io(control["id"], "negative-preserved"))
    host.kill(control["id"])


def test_private_profile_preserves_complete_scripts_and_interactive_shell(endpoint):
    host = endpoint
    values = ["space arg", "single' and double\" quote", "C:\\tail dir\\", r"C:\\paired\\slashes", "Ω 日本 😀",
              "$(printf NOT_AN_EXPANSION)", "; printf ALSO_DATA", "line one\nline two"]
    oracle = host.workspace / "argv-boundary.json"
    code = "import json,pathlib,sys;pathlib.Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:]),encoding='utf8');print('ARGV44_OK')"
    command = host.python_command(code) + " " + shlex.quote(str(oracle)) + " " + " ".join(map(shlex.quote, values))
    for pty in (False, True):
        assert not oracle.exists()
        answer = host.exec_pty(command) if pty else host.exec(command)
        assert answer[0] == 0 and "ARGV44_OK" in answer[1], answer
        assert json.loads(oracle.read_text(encoding="utf8")) == values
        oracle.unlink()
        # Actual Python SOURCE, not encoded data: the Windows literals must
        # arrive unchanged through both Bash command-line boundaries.
        embedded = ("import json,pathlib\npathlib.Path(" + repr(str(oracle)) + ").write_text(json.dumps("
                    + repr(values) + "),encoding='utf8')\nprint('SOURCE44_OK')\n")
        script = host.python_command(embedded)
        answer = host.exec_pty(script) if pty else host.exec(script)
        assert answer[0] == 0 and "SOURCE44_OK" in answer[1], answer
        assert json.loads(oracle.read_text(encoding="utf8")) == values
        oracle.unlink()
        expansion = host.workspace / "expansion.txt"
        script = "printf '%s' \"$((44+8))\" > " + shlex.quote(expansion.as_posix())
        answer = host.exec_pty(script) if pty else host.exec(script)
        assert answer[0] == 0 and expansion.read_text() == "52", answer
        expansion.unlink()
        host.proofs.append({"privateProfilePTY": pty, "independentFileOracle": True,
                            "argvDataPreserved": True, "shellExpansionPreserved": True,
                            "embeddedSourcePreserved": True})
    host.proofs.append(host.attach_io(None, "no-command-interactive"))


def test_packaged_launchers_preserve_console_and_quiet_stdio(endpoint):
    from tray_launcher_probe import background_controls, build_layout
    host = endpoint
    root = build_layout(host.installed, host.top / "launcher-probe")
    host.proofs.append(background_controls(root))
    for name, console in (("pocketshell.exe", True), ("GatewayTray.exe", False)):
        oracle = root / (name + ".json")
        # The actual binaries are unchanged; only the throwaway Python module
        # writes console metadata. No real tray/setup/native owner prompt runs.
        command = shlex.quote((root / name).as_posix()) + " proof " + shlex.quote(str(oracle))
        answer = host.exec_pty(command)
        assert answer[0] == 0 and oracle.exists(), answer
        proof = json.loads(oracle.read_text(encoding="utf8"))
        assert proof["stdinConsole"] is console and proof["stdoutConsole"] is console
        if not console:
            assert proof["consoleWindow"] == 0
        host.proofs.append({"independentFileOracle": True, "entry": name, "console": console,
                            "validParentConsoleOnly": True})
