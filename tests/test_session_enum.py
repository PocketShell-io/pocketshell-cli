"""Contract tests for the aplexer-only session list."""

from __future__ import annotations

from pocketshell.runtime import sessions as session_enum


NOW_MS = 1_700_000_000_000


def live_record(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "id": "b3feff71-4a78-4055-a2d3-6c99187ecffb",
        "workspace": "/work/pocketshell",
        "tag": "shell",
        "engine": "shell",
        "phase": "running",
        "worker_pid": 1234,
        "worker_alive": True,
        "created_at_ms": NOW_MS - 10_000,
        "last_activity_ms": NOW_MS - 1_000,
        "agent": "codex",
    }
    record.update(overrides)
    return record


def test_schema_three_has_no_backend_discriminator() -> None:
    rows, errors = session_enum.enumerate_live_sessions(
        aplexer_payload=[live_record()], now_ms=NOW_MS
    )
    payload = session_enum.json_payload(rows, errors)

    assert payload["schema"] == 3
    assert set(payload) == {"schema", "sessions", "errors"}
    assert errors == []
    assert payload["sessions"][0]["name"] == "pocketshell:shell"
    assert "manager" not in payload["sessions"][0]


def test_empty_success_is_healthy() -> None:
    rows, errors = session_enum.enumerate_live_sessions(aplexer_payload=[])
    assert rows == []
    assert errors == []


def test_missing_aplexer_is_visible_as_an_enumeration_error(monkeypatch) -> None:
    monkeypatch.setattr(session_enum.aplexer, "enabled", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        session_enum.aplexer,
        "resolve_a",
        lambda *args, **kwargs: session_enum.aplexer.AplexerResolution(
            tried=("APLEXER_BIN (unset)", "/gone/bin/a (bundled, missing)")
        ),
    )

    rows, errors = session_enum.enumerate_live_sessions()

    assert rows == []
    assert len(errors) == 1
    message = errors[0]["message"]
    assert "the bundled `a` executable was not found" in message
    assert "/gone/bin/a (bundled, missing)" in message, (
        "the unresolved error must name the candidates it tried (issue #2543)"
    )


def test_failed_probe_is_not_silently_returned_as_empty(monkeypatch) -> None:
    monkeypatch.setattr(session_enum.aplexer, "enabled", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        session_enum.aplexer,
        "resolve_a",
        lambda *args, **kwargs: session_enum.aplexer.AplexerResolution(path="/opt/a"),
    )
    monkeypatch.setattr(
        session_enum.aplexer,
        "run_json_reported",
        lambda *args, **kwargs: (
            None,
            session_enum.aplexer.AplexerFailure("exit", "exit 1: boom"),
        ),
    )

    rows, errors = session_enum.enumerate_live_sessions()

    assert rows == []
    assert len(errors) == 1
    message = errors[0]["message"]
    assert "failed or returned unreadable JSON" in message
    assert "exit 1: boom" in message, (
        "aplexer's stderr must reach the error entry, not be discarded (issue #2)"
    )


# ---------------------------------------------------------------------------
# Issue #2: the failure taxonomy is visible in the enumeration error
# ---------------------------------------------------------------------------

_PROBE_ENV = {"POCKETSHELL_APLEXER": "1"}


def test_probe_timeout_is_distinguished_from_a_non_zero_exit(install_fake_a) -> None:
    install_fake_a(sleep=3)  # outlives both 2s probes

    rows, errors = session_enum.enumerate_live_sessions(env=_PROBE_ENV)

    assert rows == []
    assert len(errors) == 1
    message = errors[0]["message"]
    assert "timeout: no output within 2s" in message, message
    assert "exit 1" not in message, (
        "a hung probe must not be reported as a non-zero exit (issue #2)"
    )


def test_probe_non_zero_exit_carries_aplexer_stderr(install_fake_a) -> None:
    install_fake_a(exit_code=1)

    rows, errors = session_enum.enumerate_live_sessions(env=_PROBE_ENV)

    assert rows == []
    assert len(errors) == 1
    message = errors[0]["message"]
    assert "exit 1: fail" in message, message
    assert "timeout" not in message, message


def test_probe_decode_failure_is_distinguished_from_an_exit(install_fake_a) -> None:
    install_fake_a(stdout="this is not json")

    rows, errors = session_enum.enumerate_live_sessions(env=_PROBE_ENV)

    assert rows == []
    assert len(errors) == 1
    message = errors[0]["message"]
    assert "decode" in message, message
    assert "this is not json" in message, message
    assert "exit 1" not in message, message


def test_dead_records_are_filtered_but_remain_available_for_diagnostics() -> None:
    dead = live_record(phase="exited", worker_alive=False, worker_pid=1234)

    rows, errors = session_enum.enumerate_live_sessions(
        aplexer_payload=[dead], now_ms=NOW_MS
    )

    assert rows == []
    assert errors == []
    diagnostic = session_enum.dead_sessions_from_aplexer_snapshot(
        [dead], now_ms=NOW_MS
    )
    assert diagnostic[0].phase == "exited"
    assert diagnostic[0].alive is False


def test_agent_state_prefers_a_recent_report() -> None:
    record = live_record(
        reported_state="idle",
        reported_state_at_ms=NOW_MS - 100,
        last_activity_ms=NOW_MS - 20_000,
    )
    assert session_enum.aplexer_agent_state(record, NOW_MS) == ("idle", "reported")
