"""End-to-end exec-boundary tests for `pocketshell gateway …`.

The CliRunner suites stop at the exec seam; these drive the real thing:
`python -m pocketshell gateway …` as a subprocess whose process image is
replaced by a fake `pocketshell-link`. That is what proves the wrapper
contract:

- the piped token reaches the helper's stdin byte-identically and never
  appears in the wrapper's own stdout/stderr;
- flag values with spaces/shell metacharacters arrive as exact argv
  elements (no shell in between);
- the helper's exit code IS the command's exit code;
- SIGTERM reaches the helper (same PID, replaced image).
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from pathlib import Path

# Arbitrary opaque bytes with awkward whitespace: the wrapper must pass
# stdin through untouched whatever the token contains (and the name must not
# imply any account credential — it is a gateway-scoped enrollment token).
TOKEN = b"enrollment-token scoped-0123456789 \t trailing-newline\n"

RECORDING_HELPER = """\
#!/bin/sh
# Test double for the Go pocketshell-link helper.
printf '%s\\0' "$@" > "$FAKE_ARGV_FILE"
cat > "$FAKE_STDIN_FILE"
if [ -n "${FAKE_STDERR:-}" ]; then
  printf '%s\\n' "$FAKE_STDERR" >&2
fi
exit "${FAKE_EXIT:-0}"
"""

SIGNAL_HELPER = """\
#!/usr/bin/env python3
import signal, sys, time

def on_term(_sig, _frame):
    print("helper-got-sigterm", flush=True)
    sys.exit(70)

signal.signal(signal.SIGTERM, on_term)
print("helper-ready", flush=True)
time.sleep(30)
"""


def _run_gateway(args: list[str], helper: Path, **env_extra) -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        "POCKETSHELL_GATEWAY_HELPER": str(helper),
        **env_extra,
    }
    return subprocess.run(
        [sys.executable, "-m", "pocketshell", "gateway", *args],
        input=TOKEN,
        capture_output=True,
        env=env,
        timeout=30,
        check=False,
    )


def _recording_helper(tmp_path: Path) -> tuple[Path, Path, Path]:
    argv_file = tmp_path / "argv.bin"
    stdin_file = tmp_path / "stdin.bin"
    helper = tmp_path / "bin" / "pocketshell-link"
    helper.parent.mkdir(parents=True, exist_ok=True)
    helper.write_text(RECORDING_HELPER)
    helper.chmod(0o755)
    return helper, argv_file, stdin_file


def test_token_flows_to_helper_stdin_and_is_never_logged(tmp_path):
    helper, argv_file, stdin_file = _recording_helper(tmp_path)
    proc = _run_gateway(
        ["enroll", "--token-stdin"],
        helper,
        FAKE_ARGV_FILE=str(argv_file),
        FAKE_STDIN_FILE=str(stdin_file),
    )
    assert proc.returncode == 0, proc.stderr
    # The token was preserved byte-identically: Python passed stdin through
    # without reading or rewriting it.
    assert stdin_file.read_bytes() == TOKEN
    # …and it stayed out of everything the wrapper itself emitted.
    assert TOKEN not in proc.stdout
    assert TOKEN not in proc.stderr
    assert b"enrollment-token" not in proc.stdout + proc.stderr


def test_enroll_flags_reach_the_helper_as_exact_argv_elements(tmp_path):
    helper, argv_file, stdin_file = _recording_helper(tmp_path)
    host_key = "ssh-ed25519 AAAAcomment; $(rm -rf /) with spaces"
    proc = _run_gateway(
        [
            "enroll", "--token-stdin",
            "--expect-host-key", host_key,
            "--device-id", "device `id` $(whoami) 42",
            "--config-dir", str(tmp_path / "state dir"),
        ],
        helper,
        FAKE_ARGV_FILE=str(argv_file),
        FAKE_STDIN_FILE=str(stdin_file),
    )
    assert proc.returncode == 0, proc.stderr
    # The wrapper emits the helper's flags in one canonical order regardless
    # of how the operator spelled them; the Go flag package accepts any.
    argv = argv_file.read_bytes().split(b"\0")[:-1]
    assert argv == [
        b"enroll",
        b"--token-stdin",
        b"--config-dir", str(tmp_path / "state dir").encode(),
        b"--device-id", b"device `id` $(whoami) 42",
        b"--expect-host-key", host_key.encode(),
    ]


def test_helper_exit_code_is_propagated_verbatim(tmp_path):
    helper, argv_file, stdin_file = _recording_helper(tmp_path)
    proc = _run_gateway(
        ["run"],
        helper,
        FAKE_EXIT="42",
        FAKE_ARGV_FILE=str(argv_file),
        FAKE_STDIN_FILE=str(stdin_file),
    )
    assert proc.returncode == 42


def test_helper_stderr_is_forwarded_untouched(tmp_path):
    helper, argv_file, stdin_file = _recording_helper(tmp_path)
    proc = _run_gateway(
        ["run"],
        helper,
        FAKE_STDERR="helper diagnostic line",
        FAKE_ARGV_FILE=str(argv_file),
        FAKE_STDIN_FILE=str(stdin_file),
    )
    assert proc.returncode == 0
    assert b"helper diagnostic line" in proc.stderr


def test_sigterm_reaches_the_replaced_process(tmp_path):
    # With os.execv the wrapper PID becomes the helper, so a signal sent to
    # `pocketshell gateway run` must be handled by the helper itself.
    helper = tmp_path / "bin" / "pocketshell-link"
    helper.parent.mkdir(parents=True, exist_ok=True)
    helper.write_text(SIGNAL_HELPER)
    helper.chmod(0o755)
    env = {**os.environ, "POCKETSHELL_GATEWAY_HELPER": str(helper)}
    proc = subprocess.Popen(
        [sys.executable, "-m", "pocketshell", "gateway", "run", "--verbose"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
    )
    try:
        assert proc.stdout is not None
        ready = proc.stdout.readline().strip()
        assert ready == "helper-ready", ready
        proc.send_signal(signal.SIGTERM)
        returncode = proc.wait(timeout=15)
    finally:
        if proc.poll() is None:  # pragma: no cover - only on failure paths
            proc.kill()
            proc.wait(timeout=10)
    assert returncode == 70
    assert "helper-got-sigterm" in proc.stdout.read()
    assert proc.stderr is not None and proc.stderr.read() == ""


def test_missing_helper_command_fails_with_127(tmp_path):
    env = {
        **os.environ,
        "PATH": str(tmp_path / "no-bin-here"),
    }
    env.pop("POCKETSHELL_GATEWAY_HELPER", None)
    proc = subprocess.run(
        [sys.executable, "-m", "pocketshell", "gateway", "show"],
        capture_output=True,
        env=env,
        timeout=30,
        check=False,
    )
    assert proc.returncode == 127
    stderr = proc.stderr.decode()
    assert "pocketshell-link" in stderr
    assert "go build" in stderr


def test_run_preserves_stdin_descriptor_for_the_helper(tmp_path):
    # `run` does not consume stdin: an open pipe must survive the exec, not
    # be closed or drained by the wrapper. The fake reads one line.
    helper, argv_file, stdin_file = _recording_helper(tmp_path)
    proc = _run_gateway(
        ["run"],
        helper,
        FAKE_ARGV_FILE=str(argv_file),
        FAKE_STDIN_FILE=str(stdin_file),
    )
    assert proc.returncode == 0, proc.stderr
    assert stdin_file.read_bytes() == TOKEN
    argv = argv_file.read_bytes().split(b"\0")[:-1]
    assert argv == [b"run"]
