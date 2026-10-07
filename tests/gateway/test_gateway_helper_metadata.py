"""Strictness matrix for the `version --json` protocol gate.

`verify_helper` runs before every exec of every chosen helper (pin, wheel,
or PATH): the answer must be exactly one JSON object on one line with
nonempty string `version`/`commit` and `protocol` equal to
`pocketshell-tunnel-v1` — else the helper is refused with a concise
compatibility error before the real subcommand can run. These tests drive
real child processes (sh doubles) so the bounds (timeout, output cap,
stdin detachment, reaping) are exercised, not mocked.
"""

from __future__ import annotations

import json
import os
import shlex
import signal
import subprocess
import sys
import time

import pytest

from pocketshell.gateway import helper as gateway_helper
from pocketshell.gateway.helper import (
    EXPECTED_PROTOCOL,
    METADATA_MAX_OUTPUT_BYTES,
    METADATA_TIMEOUT_SECONDS,
    HelperIncompatibleError,
    verify_helper,
)

VALID_DEVEL = (
    '{"version":"devel","protocol":"pocketshell-tunnel-v1","commit":"unknown"}'
)


def _sh_helper(tmp_path, version_body: str, **extra_scripts) -> str:
    """A sh test double: `version` runs version_body; named scripts run extra.

    Bodies must NOT include the `case` terminator — this helper adds `;;`.
    """
    lines = ["#!/bin/sh", 'case "$1" in']
    lines.append("  version)")
    lines.extend("    " + line for line in version_body.splitlines())
    lines.append("    ;;")
    for name, body in extra_scripts.items():
        lines.append(f"  {name})")
        lines.extend("    " + line for line in body.splitlines())
        lines.append("    ;;")
    lines.append('  *) echo "unknown subcommand $1" >&2; exit 2 ;;')
    lines.append("esac")
    path = tmp_path / "pocketshell-link"
    path.write_text("\n".join(lines) + "\n")
    path.chmod(0o755)
    return str(path)


def _emit(line: str) -> str:
    """sh snippet printing one line (payload stays a single argv element)."""
    return f"printf '%s\\n' {shlex.quote(line)} ; exit 0"


# ---------------------------------------------------------------------------
# the honest answers that must pass
# ---------------------------------------------------------------------------


def test_uninjected_source_build_devel_unknown_is_accepted(tmp_path):
    # A source build without release injection honestly reports
    # devel/unknown; it is protocol-compatible and passes the gate. It is
    # NOT treated as a release anywhere — acceptance proves the protocol,
    # never the provenance.
    helper = _sh_helper(tmp_path, _emit(VALID_DEVEL))
    verify_helper(helper)  # must not raise


def test_release_style_metadata_is_accepted(tmp_path):
    helper = _sh_helper(
        tmp_path,
        _emit(
            '{"version":"1.2.3","protocol":"pocketshell-tunnel-v1",'
            '"commit":"1d2248e168710c070d156ac720194bd6fe63dbee"}'
        ),
    )
    verify_helper(helper)


def test_additive_extra_json_fields_are_accepted(tmp_path):
    # The helper's contract is frozen-ADDITIVE: appended fields keep the
    # protocol tag unchanged, so a strict-but-forward-compatible parser
    # must ignore unknown top-level fields.
    payload = json.dumps(
        {
            "version": "1.2.3",
            "protocol": EXPECTED_PROTOCOL,
            "commit": "abc",
            "buildInfo": "go1.27.1",
        }
    )
    verify_helper(_sh_helper(tmp_path, _emit(payload)))


def test_nested_additive_json_structures_are_accepted(tmp_path):
    # Additive means ordinary JSON structures too: nested objects and
    # arrays that the parser must simply accept and ignore.
    payload = json.dumps(
        {
            "version": "1.2.3",
            "protocol": EXPECTED_PROTOCOL,
            "commit": "abc",
            "buildInfo": {"go": "1.27", "flags": ["a", "b"], "meta": {"x": 1}},
        }
    )
    verify_helper(_sh_helper(tmp_path, _emit(payload)))  # must not raise


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_non_json_constants_are_refused(tmp_path, constant):
    # Python's json accepts NaN/Infinity by default, but they are not
    # JSON: the frozen contract speaks JSON, so an additive field carrying
    # one fails the gate instead of sliding through the lenient parser.
    payload = (
        '{"version":"1.0.0","protocol":"pocketshell-tunnel-v1",'
        f'"commit":"abc","ratio":{constant}}}'
    )
    with pytest.raises(HelperIncompatibleError):
        verify_helper(_sh_helper(tmp_path, _emit(payload)))


def test_deeply_nested_additive_json_is_contained_as_a_refusal():
    # A deep additive array can exhaust the JSON parser's recursion before
    # (or instead of) parsing; the gate must contain that as the documented
    # concise refusal, never leak a RecursionError traceback through the
    # CLI's 126 contract. Driven at the real parse seam — no mocks. The
    # depth is sized beyond any supported interpreter's parse recursion:
    # on CPython ≤3.12 such a trigger fit below the 4096-byte capture
    # budget; 3.14's parser only recurses out around 10⁵ levels.
    depth = 300_000
    payload = (
        '{"version":"1.0.0","protocol":"pocketshell-tunnel-v1",'
        '"commit":"abc","deep":' + "[" * depth + "]" * depth + "}"
    )
    with pytest.raises(HelperIncompatibleError, match="deep") as excinfo:
        gateway_helper._parse_version_metadata(payload.encode())
    assert "\n" not in str(excinfo.value)


def test_json_without_trailing_newline_is_accepted(tmp_path):
    # The Go encoder appends exactly one newline; a bare line without one
    # is the same answer and must not be rejected on punctuation.
    helper = _sh_helper(
        tmp_path,
        f"printf '%s' {shlex.quote(VALID_DEVEL)} ; exit 0",
    )
    verify_helper(helper)


# ---------------------------------------------------------------------------
# every deviation must fail closed
# ---------------------------------------------------------------------------


def test_stale_protocol_tag_is_refused(tmp_path):
    helper = _sh_helper(
        tmp_path,
        _emit(VALID_DEVEL.replace("tunnel-v1", "tunnel-v2")),
    )
    with pytest.raises(HelperIncompatibleError) as excinfo:
        verify_helper(helper)
    message = str(excinfo.value)
    assert "pocketshell-tunnel-v1" in message
    assert "not compatible" in message
    assert helper in message


def test_future_or_foreign_protocol_spelling_is_refused(tmp_path):
    for protocol in (
        "pocketshell-tunnel-v0",
        "pocketshell-tunnel-v11",
        "pocketshell-tunnel",
        "",
        "ssh",
    ):
        payload = json.dumps(
            {"version": "1.0.0", "protocol": protocol, "commit": "abc"}
        )
        with pytest.raises(HelperIncompatibleError):
            verify_helper(_sh_helper(tmp_path, _emit(payload)))


@pytest.mark.parametrize("field", ["version", "protocol", "commit"])
def test_missing_field_is_refused(tmp_path, field):
    payload = {
        "version": "1.0.0",
        "protocol": EXPECTED_PROTOCOL,
        "commit": "abc",
    }
    del payload[field]
    with pytest.raises(HelperIncompatibleError, match="missing"):
        verify_helper(_sh_helper(tmp_path, _emit(json.dumps(payload))))


@pytest.mark.parametrize("field", ["version", "protocol", "commit"])
@pytest.mark.parametrize("bad", [1, None, True, ["x"], {"a": 1}])
def test_non_string_field_is_refused(tmp_path, field, bad):
    payload = {
        "version": "1.0.0",
        "protocol": EXPECTED_PROTOCOL,
        "commit": "abc",
    }
    payload[field] = bad
    with pytest.raises(HelperIncompatibleError, match="not a string"):
        verify_helper(_sh_helper(tmp_path, _emit(json.dumps(payload))))


@pytest.mark.parametrize("field", ["version", "protocol", "commit"])
@pytest.mark.parametrize("bad", ["", "   ", "\t"])
def test_empty_or_blank_field_is_refused(tmp_path, field, bad):
    payload = {
        "version": "1.0.0",
        "protocol": EXPECTED_PROTOCOL,
        "commit": "abc",
    }
    payload[field] = bad
    with pytest.raises(HelperIncompatibleError, match="empty"):
        verify_helper(_sh_helper(tmp_path, _emit(json.dumps(payload))))


@pytest.mark.parametrize(
    "raw",
    [
        "",  # silent exit 0
        "   \n",  # blank line only
        "pocketshell-link 1.2.3 (protocol pocketshell-tunnel-v1)",  # human line
        "not json at all",
        '{"version":"1.0.0","protocol":"pocketshell-tunnel-v1","commit":"abc"}\n'
        '{"version":"1.0.0","protocol":"pocketshell-tunnel-v1","commit":"abc"}\n',  # two objects
        '{"version":"1.0.0","protocol":"pocketshell-tunnel-v1","commit":"abc"} trailing\n',
        '{"version":"1.0.0","protocol":"pocketshell-tunnel-v1","commit":"abc"}\n\n',  # blank second line
        '{"version":"1.0.0","protocol":"pocketshell-tunnel-v1","commit":"abc"}\n'
        'log noise\n',  # JSON followed by chatter
        '["version","protocol"]',  # JSON but not an object
        '"pocketshell-tunnel-v1"',  # JSON string
        'null',
        '{"version":"1.0.0","protocol":"pocketshell-tunnel-v1","commit":"a","commit":"b"}',  # conflicting duplicate
    ],
)
def test_malformed_or_ambiguous_output_is_refused(tmp_path, raw):
    with pytest.raises(HelperIncompatibleError):
        verify_helper(_sh_helper(tmp_path, _emit(raw)))


def test_nonzero_exit_is_refused_even_with_wellformed_output(tmp_path):
    # A helper that prints the right line but exits nonzero is broken (or
    # lying); the exit status alone fails the gate.
    helper = _sh_helper(
        tmp_path,
        _emit(VALID_DEVEL).replace("exit 0", "exit 3"),
    )
    with pytest.raises(HelperIncompatibleError) as excinfo:
        verify_helper(helper)
    assert "status 3" in str(excinfo.value)


def test_missing_version_subcommand_is_refused(tmp_path):
    # An old or alien binary without `version --json` answers "unknown
    # subcommand" on stderr, exits 2, prints nothing on stdout.
    helper = _sh_helper(tmp_path, 'echo "refusing" >&2 ; exit 2')
    with pytest.raises(HelperIncompatibleError) as excinfo:
        verify_helper(helper)
    message = str(excinfo.value)
    assert "status 2" in message
    assert "refusing" not in message  # stderr is never echoed either


def test_nul_bytes_are_refused(tmp_path):
    helper = _sh_helper(tmp_path, "printf 'a\\0b' ; exit 0")
    with pytest.raises(HelperIncompatibleError, match="NUL"):
        verify_helper(helper)


def test_non_utf8_output_is_refused(tmp_path):
    helper = _sh_helper(tmp_path, "printf '\\377\\376' ; exit 0")
    with pytest.raises(HelperIncompatibleError, match="UTF-8"):
        verify_helper(helper)


def test_unexecutable_helper_is_reported_clearly(tmp_path):
    path = tmp_path / "pocketshell-link"
    path.write_text("#!/bin/sh\n")
    path.chmod(0o644)
    with pytest.raises(HelperIncompatibleError, match="cannot be executed"):
        verify_helper(str(path))


# ---------------------------------------------------------------------------
# the probe is bounded
# ---------------------------------------------------------------------------


def _recording_popen(monkeypatch) -> list[subprocess.Popen]:
    """Record every child the helper module spawns, without mocking it.

    The real Popen runs; only a bookkeeping subclass is installed so a test
    can assert the lifetime of the EXACT probe child it caused — never by
    scanning machine-wide process tables, which observe other suites' or
    workers' processes too.
    """
    created: list[subprocess.Popen] = []
    real_popen = subprocess.Popen

    class RecordingPopen(real_popen):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            created.append(self)

    monkeypatch.setattr(gateway_helper.subprocess, "Popen", RecordingPopen)
    return created


def test_hanging_helper_times_out_quickly_and_is_reaped(tmp_path, monkeypatch):
    monkeypatch.setattr(gateway_helper, "METADATA_TIMEOUT_SECONDS", 0.5)
    # `exec` so the kill hits the sleeper itself, not a shell wrapping it —
    # an orphaned grandchild would be exactly the leak this test guards.
    helper = _sh_helper(tmp_path, "exec sleep 30")
    created = _recording_popen(monkeypatch)
    start = time.monotonic()
    with pytest.raises(HelperIncompatibleError) as excinfo:
        verify_helper(helper)
    elapsed = time.monotonic() - start
    assert elapsed < 5, "the gate must honor its deadline, not the child's"
    assert "version --json" in str(excinfo.value)
    assert "0.5" in str(excinfo.value)
    # Killed AND reaped, proven on the exact probe child this test caused:
    # a negative returncode is the SIGKILL exit status and is only set by
    # wait(), so it cannot hold for an unreaped zombie.
    assert len(created) == 1
    probe = created[0]
    assert probe.returncode == -signal.SIGKILL
    with pytest.raises(ProcessLookupError):
        os.kill(probe.pid, 0)  # gone from the process table, not a zombie


def test_timeout_cleanup_spares_unrelated_owned_sleepers(tmp_path, monkeypatch):
    # Negative calibration for the reaping proof: with an unrelated,
    # test-owned `sleep 30` alive, the old machine-wide
    # `pgrep -f "sleep 30"` predicate reported a leak that did not exist
    # (it saw THIS process). The exact-PID proof must pass, and cleanup
    # must leave the unrelated process strictly alone.
    monkeypatch.setattr(gateway_helper, "METADATA_TIMEOUT_SECONDS", 0.5)
    unrelated = subprocess.Popen(["sleep", "30"])
    try:
        helper = _sh_helper(tmp_path, "exec sleep 30")
        created = _recording_popen(monkeypatch)
        with pytest.raises(HelperIncompatibleError):
            verify_helper(helper)
        assert created[0].returncode == -signal.SIGKILL
        assert unrelated.poll() is None, (
            "probe cleanup must not kill unrelated processes"
        )
    finally:
        if unrelated.poll() is None:
            unrelated.kill()
        unrelated.wait()


def test_post_eof_lingering_helper_is_refused_at_the_deadline(
    tmp_path, monkeypatch
):
    # Prints a fully valid answer, CLOSES stdout (the reader sees EOF),
    # then stays alive past the configured budget — inside the removed
    # +0.5s acceptance grace. The monotonic deadline governs acceptance;
    # only kill/reap cleanup may outlive it.
    monkeypatch.setattr(gateway_helper, "METADATA_TIMEOUT_SECONDS", 0.5)
    helper = _sh_helper(
        tmp_path,
        f"printf '%s\\n' {shlex.quote(VALID_DEVEL)} ; exec 1>&- ; sleep 0.7",
    )
    start = time.monotonic()
    with pytest.raises(HelperIncompatibleError) as excinfo:
        verify_helper(helper)
    elapsed = time.monotonic() - start
    assert "version --json" in str(excinfo.value)
    assert "0.5" in str(excinfo.value)
    assert elapsed < 5


# ---------------------------------------------------------------------------
# the acceptance deadline has no post-EOF/post-wait hole
# ---------------------------------------------------------------------------


class _SeamClock:
    """Controlled monotonic clock for the wrapper module only.

    Each ``time.monotonic()`` read inside :mod:`gateway_helper` consumes
    the next scripted value (the tail repeats once the script runs out);
    the module's ``time`` binding is swapped, so the real clock still
    governs the subprocess and selector machinery. The script models a
    scheduler delay of the WRAPPER itself — reads while the answer is
    expected, then a jump past the deadline at the exact EOF→wait seam.
    """

    def __init__(self, script, tail):
        self._script = list(script)
        self._tail = tail
        self.reads: list[float] = []

    def monotonic(self) -> float:
        value = self._script.pop(0) if self._script else self._tail
        self.reads.append(value)
        return value


# For a one-chunk valid answer the wrapper reads its clock exactly: once
# for the deadline, once per selector loop turn (data turn, then EOF
# turn), once at the acceptance wait seam, and — since the repair — once
# more to recheck the deadline across the successful wait. The scripted
# reads assert that layout, so a structural change recalibrates these
# tests loudly instead of silently jumping the wrong read.
_SEAM_READS_BEFORE_WAIT = 4


def test_wait_seam_resumed_after_deadline_refuses_finished_child(
    tmp_path, monkeypatch
):
    # Scheduler-delay hole at the EOF→wait seam: the helper printed fully
    # valid metadata and EXITED — a real, completed Popen child — but the
    # wrapper only reaches the acceptance wait after the original
    # deadline. An already-exited child makes even wait(timeout=0) return
    # instantly, so the old max(deadline - now, 0) wait accepted the late
    # answer. The exhausted budget must be refused explicitly; cleanup
    # still reaps the finished child itself (the kill is for running
    # children only).
    clock = _SeamClock(
        [1000.0] * (_SEAM_READS_BEFORE_WAIT - 1) + [1020.0], tail=1020.0
    )
    monkeypatch.setattr(gateway_helper, "time", clock)
    created = _recording_popen(monkeypatch)
    helper = _sh_helper(tmp_path, _emit(VALID_DEVEL))
    with pytest.raises(HelperIncompatibleError) as excinfo:
        verify_helper(helper)
    assert "within 10s" in str(excinfo.value)
    # Calibration: the jump landed on the wait-seam read, not inside the
    # read loop — that is the seam a scheduler delay would hit.
    assert clock.reads == [1000.0, 1000.0, 1000.0, 1020.0]
    # The refusal happened despite a successfully finished child: cleanup
    # reaped its real exit status, it was never killed.
    assert len(created) == 1
    assert created[0].returncode == 0


def test_deadline_is_rechecked_after_a_successful_wait(tmp_path, monkeypatch):
    # The inverse seam: the budget still looks alive when wait() is
    # entered and the wait itself succeeds instantly on the finished
    # child — but the wrapper is descheduled ACROSS it, and the monotonic
    # deadline has passed by the time wait() returns. A successful reap is
    # not an answer: the deadline must be rechecked BEFORE the output is
    # accepted.
    clock = _SeamClock(
        [1000.0] * _SEAM_READS_BEFORE_WAIT + [1020.0], tail=1020.0
    )
    monkeypatch.setattr(gateway_helper, "time", clock)
    created = _recording_popen(monkeypatch)
    helper = _sh_helper(tmp_path, _emit(VALID_DEVEL))
    with pytest.raises(HelperIncompatibleError) as excinfo:
        verify_helper(helper)
    assert "within 10s" in str(excinfo.value)
    # Calibration: the jump landed on the post-wait recheck — the read
    # the old code never made.
    assert clock.reads == [1000.0, 1000.0, 1000.0, 1000.0, 1020.0]
    assert len(created) == 1
    assert created[0].returncode == 0


def test_timely_eof_and_exit_still_accepted_on_the_controlled_clock(
    tmp_path, monkeypatch
):
    # Stay-green guard for the two seam refusals: a child that answers and
    # finishes INSIDE the budget is accepted on the same controlled clock
    # (whatever the read count — the pre-repair layout made one read
    # fewer), so the explicit refusals above are not over-broad refusals
    # of the ordinary fast path.
    clock = _SeamClock([], tail=1000.0)
    monkeypatch.setattr(gateway_helper, "time", clock)
    created = _recording_popen(monkeypatch)
    helper = _sh_helper(tmp_path, _emit(VALID_DEVEL))
    verify_helper(helper)  # must not raise
    assert len(created) == 1
    assert created[0].returncode == 0
    assert clock.reads and all(read == 1000.0 for read in clock.reads)


def test_oversize_output_is_refused_without_unbounded_capture(tmp_path):
    # 200 KB of one-line-ish output is far over the 4 KB budget; the gate
    # must refuse (and kill the writer) instead of slurping it all.
    helper = _sh_helper(
        tmp_path,
        "yes 'x' | head -c 200000 ; exit 0",
    )
    start = time.monotonic()
    with pytest.raises(HelperIncompatibleError) as excinfo:
        verify_helper(helper)
    assert time.monotonic() - start < METADATA_TIMEOUT_SECONDS
    assert "byte" in str(excinfo.value)


def test_output_budget_constant_is_tight(tmp_path):
    # The budget exists to bound capture: it must stay small even if the
    # contract grows — one JSON line, not a dump.
    assert METADATA_MAX_OUTPUT_BYTES < 64 * 1024
    assert 0 < METADATA_TIMEOUT_SECONDS <= 30


# ---------------------------------------------------------------------------
# the error is safe to show
# ---------------------------------------------------------------------------


def test_error_is_concise_and_never_echoes_helper_output(tmp_path):
    marker = "TOPSECRET-PLAYLOAD-7f3a"
    hostile_line = (
        '{"version":"' + marker + '","protocol":"pocketshell-tunnel-v2"}\n'
    )
    helper = _sh_helper(tmp_path, _emit(hostile_line))
    with pytest.raises(HelperIncompatibleError) as excinfo:
        verify_helper(helper)
    message = str(excinfo.value)
    assert marker not in message, "helper output must never be echoed"
    assert "\n" not in message, "compatibility error must stay one line"


def test_hostile_multiline_version_cannot_forge_error_lines(tmp_path):
    # A version field full of newlines must not be able to inject fake
    # error lines into the (type-invalid) report.
    payload = (
        '{"version":"1\\nFAKE ERROR LINE\\n","protocol":"pocketshell-tunnel-v2",'
        '"commit":"x"}'
    )
    helper = _sh_helper(tmp_path, _emit(payload))
    with pytest.raises(HelperIncompatibleError) as excinfo:
        verify_helper(helper)
    message = str(excinfo.value)
    assert "FAKE ERROR LINE" not in message
    assert "\n" not in message


def test_protocol_value_in_error_is_ascii_escaped_and_truncated(tmp_path):
    protocol = "pocketshell-tunnel-v1" + "x" * 500
    payload = json.dumps(
        {"version": "1.0.0", "protocol": protocol, "commit": "abc"}
    )
    helper = _sh_helper(tmp_path, _emit(payload))
    with pytest.raises(HelperIncompatibleError) as excinfo:
        verify_helper(helper)
    message = str(excinfo.value)
    assert "\n" not in message
    assert len(message) < 500, "compatibility error must stay concise"


def test_posix_only_probe_constants_are_importable():
    # Guard the documented surface used by the CLI error mapping.
    assert EXPECTED_PROTOCOL == "pocketshell-tunnel-v1"
    assert sys.platform != "win32", "these doubles are POSIX sh scripts"
