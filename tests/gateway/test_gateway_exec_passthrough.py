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

import pytest

# Arbitrary opaque bytes with awkward whitespace: the wrapper must pass
# stdin through untouched whatever the token contains (and the name must not
# imply any account credential — it is a gateway-scoped enrollment token).
TOKEN = b"enrollment-token scoped-0123456789 \t trailing-newline\n"

RECORDING_HELPER = """\
#!/bin/sh
# Test double for the Go pocketshell-link helper. The wrapper probes
# `version --json` before the real subcommand; that branch stays
# side-effect-free with respect to the argv/stdin recordings — its only
# optional side effects are the dedicated probe proofs below.
if [ "$1" = version ]; then
  if [ -n "${FAKE_ORDER_FILE:-}" ]; then
    printf 'probe\\n' >> "$FAKE_ORDER_FILE"
  fi
  if [ -n "${FAKE_METADATA_STDIN_FILE:-}" ]; then
    # If the probe ever inherited the piped stdin, this would swallow the
    # enrollment token before the real command could read it.
    cat > "$FAKE_METADATA_STDIN_FILE"
  fi
  if [ -n "${FAKE_METADATA:-}" ]; then
    printf '%s\\n' "$FAKE_METADATA"
  else
    printf '{"version":"devel","protocol":"pocketshell-tunnel-v1","commit":"unknown"}\\n'
  fi
  exit "${FAKE_METADATA_EXIT:-0}"
fi
if [ -n "${FAKE_ORDER_FILE:-}" ]; then
  printf 'exec\\n' >> "$FAKE_ORDER_FILE"
fi
printf '%s\\0' "$@" > "$FAKE_ARGV_FILE"
cat > "$FAKE_STDIN_FILE"
if [ -n "${FAKE_STDERR:-}" ]; then
  printf '%s\\n' "$FAKE_STDERR" >&2
fi
exit "${FAKE_EXIT:-0}"
"""

SIGNAL_HELPER = """\
#!/usr/bin/env python3
import json, signal, sys, time

# SIGTERM is blocked until the handler is installed and the ready line is
# out: a signal arriving mid-print used to run the handler re-entrantly
# inside BufferedWriter (RuntimeError, exit 1) — a defect of this test
# double's stdio, not of the exec boundary under test. After the ready
# line, the test may signal at any moment; delivery happens either here
# (handler runs) or as a pending signal at unblock (handler then runs).
signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})

if len(sys.argv) > 1 and sys.argv[1] == "version":
    # The wrapper's protocol probe must get an answer instead of a timeout.
    print(json.dumps(
        {"version": "devel", "protocol": "pocketshell-tunnel-v1",
         "commit": "unknown"}))
    sys.exit(0)

def on_term(_sig, _frame):
    print("helper-got-sigterm", flush=True)
    sys.exit(70)

signal.signal(signal.SIGTERM, on_term)
print("helper-ready", flush=True)
signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM})
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


def _wheel_installed() -> bool:
    from importlib import metadata as importlib_metadata

    try:
        importlib_metadata.distribution("pocketshell-gateway-link")
        return True
    except importlib_metadata.PackageNotFoundError:  # pragma: no cover
        return False


def test_metadata_probe_runs_before_the_real_command(tmp_path):
    # The protocol gate is a BEFORE-exec step: the helper sees the
    # `version --json` probe first and only then the real subcommand, in
    # one exec chain (same process after os.execv). This always runs, even
    # with a helper wheel installed: the explicit pin below wins
    # resolution, so discovery cannot change what this test observes.
    helper, argv_file, stdin_file = _recording_helper(tmp_path)
    order_file = tmp_path / "order.txt"
    proc = _run_gateway(
        ["enroll", "--token-stdin"],
        helper,
        FAKE_ORDER_FILE=str(order_file),
        FAKE_ARGV_FILE=str(argv_file),
        FAKE_STDIN_FILE=str(stdin_file),
    )
    assert proc.returncode == 0, proc.stderr
    assert order_file.read_text().splitlines() == ["probe", "exec"]


CWD_SELECTED_HELPER = """\
#!/bin/sh
# Identity-tagged double: order entries name WHICH file ran, so a probe
# answered by one binary and a command executed by another is visible.
if [ "$1" = version ]; then
  printf 'cwd-probe\\n' >> "$FAKE_ORDER_FILE"
  printf '%s\\n' '{"version":"devel","protocol":"pocketshell-tunnel-v1","commit":"unknown"}'
  exit "${FAKE_CWD_PROBE_EXIT:-0}"
fi
printf 'cwd-exec\\n' >> "$FAKE_ORDER_FILE"
exit 0
"""

PATH_DECOY_HELPER = """\
#!/bin/sh
# The PATH look-alike: fully compatible, so only the resolution identity
# (not compatibility) can decide which binary is probed and exec'd.
if [ "$1" = version ]; then
  printf 'decoy-probe\\n' >> "$FAKE_ORDER_FILE"
  printf '%s\\n' '{"version":"devel","protocol":"pocketshell-tunnel-v1","commit":"unknown"}'
  exit 0
fi
printf 'decoy-exec\\n' >> "$FAKE_ORDER_FILE"
exit 0
"""


def _write_exec_at(path: Path, script: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(script)
    path.chmod(0o755)
    return path


def _run_gateway_from_cwd(
    args: list[str], *, cwd: Path, pin: str | None, **env_extra
) -> subprocess.CompletedProcess:
    """Like _run_gateway, but with a controlled cwd and an optional BARE pin."""
    env = {**os.environ}
    env.pop("POCKETSHELL_GATEWAY_HELPER", None)
    if pin is not None:
        env["POCKETSHELL_GATEWAY_HELPER"] = pin
    env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "pocketshell", "gateway", *args],
        input=TOKEN,
        capture_output=True,
        env=env,
        cwd=str(cwd),
        timeout=30,
        check=False,
    )


def test_bare_relative_pin_probes_and_execs_the_same_file(tmp_path):
    # A bare `POCKETSHELL_GATEWAY_HELPER=pocketshell-link` pin with the
    # named file present in cwd: the selected binary must be ONE absolute
    # file used for BOTH the metadata probe and the final exec. Before the
    # normalization fix, Popen searched PATH (decoy answered the probe)
    # while os.execv took the cwd file (executing an unverified binary).
    order_file = tmp_path / "order.txt"
    _write_exec_at(tmp_path / "pocketshell-link", CWD_SELECTED_HELPER)
    _write_exec_at(tmp_path / "decoy-bin" / "pocketshell-link", PATH_DECOY_HELPER)
    proc = _run_gateway_from_cwd(
        ["show"],
        cwd=tmp_path,
        pin="pocketshell-link",
        PATH=str(tmp_path / "decoy-bin"),
        FAKE_ORDER_FILE=str(order_file),
    )
    assert proc.returncode == 0, proc.stderr
    # Only the SELECTED (cwd) binary supplies metadata and executes; the
    # compatible PATH decoy never runs at all.
    assert order_file.read_text().splitlines() == ["cwd-probe", "cwd-exec"]


def test_incompatible_selected_pin_refuses_despite_good_decoy(tmp_path):
    # The inverse identity failure: the cwd-selected binary speaks the
    # WRONG protocol while a perfect helper sits on PATH. The gate must
    # probe the selected file and refuse — never pass on the decoy's
    # answer and then exec the unverified selected binary.
    exec_marker = tmp_path / "cwd-exec-marker"
    bad_cwd_helper = (
        "#!/bin/sh\n"
        'if [ "$1" = version ]; then\n'
        "  printf '%s\\n' "
        "'{\"version\":\"9.9.9\",\"protocol\":\"pocketshell-tunnel-v2\",\"commit\":\"x\"}'\n"
        "  exit 0\n"
        "fi\n"
        f"touch '{exec_marker}'\n"
        "exit 0\n"
    )
    _write_exec_at(tmp_path / "pocketshell-link", bad_cwd_helper)
    _write_exec_at(tmp_path / "decoy-bin" / "pocketshell-link", PATH_DECOY_HELPER)
    proc = _run_gateway_from_cwd(
        ["show"],
        cwd=tmp_path,
        pin="pocketshell-link",
        PATH=str(tmp_path / "decoy-bin"),
        FAKE_ORDER_FILE=str(tmp_path / "decoy-order.txt"),
    )
    assert proc.returncode == 126, proc.stderr
    stderr = proc.stderr.decode()
    assert "not compatible" in stderr
    assert "Traceback" not in stderr
    # Neither binary executed a real subcommand: the selected one was
    # refused at the gate, the decoy was never even probed.
    assert not exec_marker.exists()
    assert not (tmp_path / "decoy-order.txt").exists()


def test_metadata_probe_cannot_consume_the_piped_enrollment_token(tmp_path):
    # The probe would love to `cat` the piped token away if it inherited
    # stdin; it must read zero bytes (stdin detached) so the token is
    # still there for the real command after the exec.
    helper, argv_file, stdin_file = _recording_helper(tmp_path)
    probe_stdin_file = tmp_path / "probe-stdin.bin"
    proc = _run_gateway(
        ["enroll", "--token-stdin"],
        helper,
        FAKE_METADATA_STDIN_FILE=str(probe_stdin_file),
        FAKE_ARGV_FILE=str(argv_file),
        FAKE_STDIN_FILE=str(stdin_file),
    )
    assert proc.returncode == 0, proc.stderr
    assert probe_stdin_file.read_bytes() == b""
    assert stdin_file.read_bytes() == TOKEN


def test_stale_protocol_helper_is_refused_in_subprocess(tmp_path):
    # At the real process boundary: a helper answering the wrong protocol
    # tag is refused with exit 126, a concise stderr line, no traceback —
    # and the real subcommand (and its stdin recording) never happens.
    helper, argv_file, stdin_file = _recording_helper(tmp_path)
    proc = _run_gateway(
        ["show"],
        helper,
        FAKE_METADATA=(
            '{"version":"1.0.0","protocol":"pocketshell-tunnel-v2",'
            '"commit":"abc"}'
        ),
        FAKE_ARGV_FILE=str(argv_file),
        FAKE_STDIN_FILE=str(stdin_file),
    )
    assert proc.returncode == 126, proc.stderr
    stderr = proc.stderr.decode()
    assert "not compatible" in stderr
    assert "pocketshell-tunnel-v1" in stderr
    assert "Traceback" not in stderr
    assert not argv_file.exists()
    assert not stdin_file.exists()


def test_helper_with_failing_version_subcommand_is_refused_in_subprocess(
    tmp_path,
):
    # Right JSON shape is not enough: a helper whose `version --json`
    # exits nonzero is broken, and the gate refuses before any exec.
    helper, argv_file, stdin_file = _recording_helper(tmp_path)
    proc = _run_gateway(
        ["run"],
        helper,
        FAKE_METADATA_EXIT="3",
        FAKE_ARGV_FILE=str(argv_file),
        FAKE_STDIN_FILE=str(stdin_file),
    )
    assert proc.returncode == 126
    stderr = proc.stderr.decode()
    assert "status 3" in stderr
    assert "Traceback" not in stderr
    assert not argv_file.exists()


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_non_json_additive_values_are_refused_in_subprocess(tmp_path, constant):
    # NaN/Infinity/-Infinity parse via Python's legacy float extension but
    # are NOT JSON: an additive field carrying one must fail the gate at
    # the real process boundary (exit 126, concise line, no traceback) and
    # the real subcommand must never run. These are explicit-pin tests —
    # the pin wins resolution, so they run unchanged even with a helper
    # wheel installed.
    helper, argv_file, stdin_file = _recording_helper(tmp_path)
    payload = (
        '{"version":"1.0.0","protocol":"pocketshell-tunnel-v1",'
        f'"commit":"abc","ratio":{constant}}}'
    )
    proc = _run_gateway(
        ["show"],
        helper,
        FAKE_METADATA=payload,
        FAKE_ARGV_FILE=str(argv_file),
        FAKE_STDIN_FILE=str(stdin_file),
    )
    assert proc.returncode == 126, proc.stderr
    stderr = proc.stderr.decode()
    assert "not compatible" in stderr
    assert "Traceback" not in stderr
    assert not argv_file.exists()
    assert not stdin_file.exists()


def test_nested_additive_json_is_accepted_in_subprocess(tmp_path):
    # Ordinary additive JSON — nested objects/arrays — must keep passing
    # the gate (the contract is additive), and the real subcommand runs.
    helper, argv_file, stdin_file = _recording_helper(tmp_path)
    payload = (
        '{"version":"1.0.0","protocol":"pocketshell-tunnel-v1",'
        '"commit":"abc","buildInfo":{"go":"1.27","flags":["a","b"]}}'
    )
    proc = _run_gateway(
        ["show"],
        helper,
        FAKE_METADATA=payload,
        FAKE_ARGV_FILE=str(argv_file),
        FAKE_STDIN_FILE=str(stdin_file),
    )
    assert proc.returncode == 0, proc.stderr
    assert argv_file.read_bytes().split(b"\0")[:-1] == [b"show"]


@pytest.mark.skipif(
    _wheel_installed(),
    reason=(
        "with a pocketshell-gateway-link wheel installed in THIS venv (or "
        "on PYTHONPATH), the wheel is selected BEFORE the emptied PATH, so "
        "helper absence cannot be simulated in this process tree and the "
        "asserted not-found route is unreachable; the fresh-venv "
        "integration run covers the installed-wheel environment, and this "
        "test runs wherever no wheel is installed"
    ),
)
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


def test_guarded_dev_flags_reach_the_helper_as_exact_argv(tmp_path):
    # Subprocess proof of the guarded forwarding: --dev-broker-issuer and
    # --re-enroll pass the wrapper preflight (insecure-dev + explicit
    # non-production server) and arrive as exact single argv elements, with
    # the IPv6 literal server URL intact.
    helper, argv_file, stdin_file = _recording_helper(tmp_path)
    proc = _run_gateway(
        [
            "enroll",
            "--token-stdin",
            "--server", "ws://[::1]:8080",
            "--insecure-dev",
            "--dev-broker-issuer", "https://lab-broker.example",
            "--re-enroll",
        ],
        helper,
        FAKE_ARGV_FILE=str(argv_file),
        FAKE_STDIN_FILE=str(stdin_file),
    )
    assert proc.returncode == 0, proc.stderr
    argv = argv_file.read_bytes().split(b"\0")[:-1]
    assert argv == [
        b"enroll",
        b"--token-stdin",
        b"--server", b"ws://[::1]:8080",
        b"--re-enroll",
        b"--dev-broker-issuer", b"https://lab-broker.example",
        b"--insecure-dev",
    ]


def test_dev_broker_issuer_preflight_rejection_happens_in_subprocess(tmp_path):
    # The negative half at the real process boundary: an unguarded
    # --dev-broker-issuer is refused with usage exit code 2 and the helper
    # is never exec'd (its argv file is never created).
    helper, argv_file, stdin_file = _recording_helper(tmp_path)
    proc = _run_gateway(
        [
            "enroll",
            "--token-stdin",
            "--dev-broker-issuer", "https://lab-broker.example",
        ],
        helper,
        FAKE_ARGV_FILE=str(argv_file),
        FAKE_STDIN_FILE=str(stdin_file),
    )
    assert proc.returncode == 2
    stderr = proc.stderr.decode()
    assert "--insecure-dev" in stderr
    assert not argv_file.exists(), "helper must not be exec'd on preflight refusal"
    assert not stdin_file.exists()


def test_blank_server_preflight_rejection_happens_in_subprocess(tmp_path):
    # The audit's escape hatch at the real process boundary: `--server ''`
    # used to pass the "explicit server" check (only a None check) and the
    # helper's ResolveServer("") then defaulted to PRODUCTION with a lab
    # issuer attached. It must refuse with usage exit code 2 before the
    # helper is ever exec'd.
    helper, argv_file, stdin_file = _recording_helper(tmp_path)
    proc = _run_gateway(
        [
            "enroll",
            "--token-stdin",
            "--server", "",
            "--insecure-dev",
            "--dev-broker-issuer", "https://lab-broker.example",
        ],
        helper,
        FAKE_ARGV_FILE=str(argv_file),
        FAKE_STDIN_FILE=str(stdin_file),
    )
    assert proc.returncode == 2
    stderr = proc.stderr.decode()
    assert "--server" in stderr
    assert "production" in stderr
    assert "Traceback" not in stderr
    assert not argv_file.exists(), "helper must not be exec'd on preflight refusal"
    assert not stdin_file.exists()


@pytest.mark.parametrize(
    "server",
    [
        "wss://gateway.pocketshell.io.",  # trailing FQDN dot, same host
        "ws://relay.pocketshell.io:8080",  # legacy production alias + port
        "ws://RELAY.POCKETSHELL.IO.",  # alias, uppercased, trailing dot
    ],
)
def test_production_server_spellings_refused_in_subprocess(tmp_path, server):
    # Canonicalization regressions at the real process boundary: trailing
    # dots and case must not rename the production gateway, and neither
    # its canonical name nor its relay alias may carry a lab issuer.
    helper, argv_file, stdin_file = _recording_helper(tmp_path)
    proc = _run_gateway(
        [
            "enroll",
            "--token-stdin",
            "--server", server,
            "--insecure-dev",
            "--dev-broker-issuer", "https://lab-broker.example",
        ],
        helper,
        FAKE_ARGV_FILE=str(argv_file),
        FAKE_STDIN_FILE=str(stdin_file),
    )
    assert proc.returncode == 2, (server, proc.stderr)
    stderr = proc.stderr.decode()
    assert "production" in stderr
    assert "Traceback" not in stderr
    assert not argv_file.exists(), "helper must not be exec'd on preflight refusal"


def test_malformed_server_url_is_a_clean_usage_error_in_subprocess(tmp_path):
    # A malformed IPv6 literal makes urlsplit raise ValueError; the
    # operator must see a one-line usage error naming --server, never a
    # Python traceback, and nothing may be exec'd.
    helper, argv_file, stdin_file = _recording_helper(tmp_path)
    proc = _run_gateway(
        [
            "enroll",
            "--token-stdin",
            "--server", "ws://[::1",
            "--insecure-dev",
            "--dev-broker-issuer", "https://lab-broker.example",
        ],
        helper,
        FAKE_ARGV_FILE=str(argv_file),
        FAKE_STDIN_FILE=str(stdin_file),
    )
    assert proc.returncode == 2
    stderr = proc.stderr.decode()
    assert "--server" in stderr
    assert "not a valid URL" in stderr
    assert "Traceback" not in stderr
    assert not argv_file.exists(), "helper must not be exec'd on preflight refusal"
    assert not stdin_file.exists()


def test_docker_lab_server_reaches_the_helper_in_subprocess(tmp_path):
    # The guard's flip side at the real process boundary: an ordinary
    # docker-compose lab hostname passes the preflight and is forwarded
    # byte-identically together with the guarded dev flags.
    helper, argv_file, stdin_file = _recording_helper(tmp_path)
    proc = _run_gateway(
        [
            "enroll",
            "--token-stdin",
            "--server", "ws://gateway:8080",
            "--insecure-dev",
            "--dev-broker-issuer", "https://lab-broker.example",
        ],
        helper,
        FAKE_ARGV_FILE=str(argv_file),
        FAKE_STDIN_FILE=str(stdin_file),
    )
    assert proc.returncode == 0, proc.stderr
    argv = argv_file.read_bytes().split(b"\0")[:-1]
    assert argv == [
        b"enroll",
        b"--token-stdin",
        b"--server", b"ws://gateway:8080",
        b"--dev-broker-issuer", b"https://lab-broker.example",
        b"--insecure-dev",
    ]
