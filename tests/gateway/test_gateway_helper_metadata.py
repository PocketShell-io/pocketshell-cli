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
import shlex
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


def test_hanging_helper_times_out_quickly_and_is_reaped(tmp_path, monkeypatch):
    monkeypatch.setattr(gateway_helper, "METADATA_TIMEOUT_SECONDS", 0.5)
    # `exec` so the kill hits the sleeper itself, not a shell wrapping it —
    # an orphaned grandchild would be exactly the leak this test guards.
    helper = _sh_helper(tmp_path, "exec sleep 30")
    start = time.monotonic()
    with pytest.raises(HelperIncompatibleError) as excinfo:
        verify_helper(helper)
    elapsed = time.monotonic() - start
    assert elapsed < 10, "the gate must honor its deadline, not the child's"
    assert "version --json" in str(excinfo.value)
    assert "0.5" in str(excinfo.value)
    # The probe child was reaped, not left behind.
    leftovers = subprocess.run(
        ["pgrep", "-f", "sleep 30"], capture_output=True, text=True
    )
    assert leftovers.stdout.strip() == "", "probe child leaked"


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
