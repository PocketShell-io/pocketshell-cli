"""Crash/OOM warning surfacing: `sessions warnings` / `sessions ack` (issue #18)."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from pocketshell import sessions
from pocketshell.runtime import sessions as session_enum
from pocketshell.runtime.aplexer import AplexerFailure
from pocketshell.sessions import listing as listing_mod
from pocketshell.sessions import warnings as warnings_mod


def _warning_row(**overrides):
    # HOME is isolated to a tmp dir by conftest; building the workspace from
    # it lets _display_selector shorten it back to `~/git/aplexer`.
    row = {
        "session": "b3feff71-4a78-4055-a2d3-6c99187ecffb",
        "workspace": str(Path.home() / "git" / "aplexer"),
        "tag": "shell",
        "engine": "codex",
        "kind": "oom",
        "detail": "workload was OOM-killed (exit status 137)",
        "created_at_ms": 1_768_000_000_000,
    }
    row.update(overrides)
    return row


def _stub_reported(monkeypatch, payload, failure=None):
    calls = []

    def run(args, **kwargs):
        calls.append((list(args), kwargs))
        return payload, failure

    monkeypatch.setattr(warnings_mod, "run_json_reported", run)
    return calls


def _stub_listing(monkeypatch, warnings):
    row = session_enum.LiveSession(name="project:shell", aplexer_id="id-1")
    monkeypatch.setattr(listing_mod, "_try_daemon_sessions_list", lambda **_: None)
    monkeypatch.setattr(
        sessions._session_enum, "enumerate_live_sessions", lambda: ([row], [])
    )
    monkeypatch.setattr(listing_mod, "fetch_warnings", lambda: warnings)


def test_help_exposes_the_warning_commands() -> None:
    result = CliRunner().invoke(sessions.sessions_group, ["--help"])
    assert result.exit_code == 0, result.output
    for command in ("warnings", "ack"):
        assert command in result.output


def test_warnings_json_is_the_aplexer_array(monkeypatch) -> None:
    row = _warning_row()
    calls = _stub_reported(monkeypatch, [row])

    result = CliRunner().invoke(sessions.sessions_group, ["warnings", "--json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == [row]
    assert calls == [(["warnings"], {"env": None, "feature": "sessions"})]


def test_warnings_human_output_uses_banner_lines(monkeypatch) -> None:
    _stub_reported(monkeypatch, [_warning_row()])

    result = CliRunner().invoke(sessions.sessions_group, ["warnings"])

    assert result.exit_code == 0, result.output
    assert "1 unacknowledged crash warning" in result.output
    assert "oom ~/git/aplexer:shell — workload was OOM-killed" in result.output
    assert "pocketshell sessions ack" in result.output


def test_warnings_pluralizes_the_banner_header(monkeypatch) -> None:
    _stub_reported(
        monkeypatch,
        [_warning_row(tag="shell"), _warning_row(tag="shell-2", kind="crash")],
    )

    result = CliRunner().invoke(sessions.sessions_group, ["warnings"])

    assert result.exit_code == 0, result.output
    assert "2 unacknowledged crash warnings" in result.output
    assert "crashed ~/git/aplexer:shell-2" in result.output


def test_warnings_reports_an_empty_store(monkeypatch) -> None:
    _stub_reported(monkeypatch, [])

    result = CliRunner().invoke(sessions.sessions_group, ["warnings"])

    assert result.exit_code == 0, result.output
    assert "no unacknowledged warnings" in result.output


def test_warnings_fails_loud_when_the_probe_fails(monkeypatch) -> None:
    # A silent "no warnings" could hide a crash, so the standalone command
    # must not degrade an aplexer failure into empty output.
    _stub_reported(monkeypatch, None, AplexerFailure("exit", "a: unknown command"))

    result = CliRunner().invoke(sessions.sessions_group, ["warnings"])

    assert result.exit_code == 1
    assert "could not list crash warnings" in result.output
    assert "a: unknown command" in result.output


def test_ack_bare_acknowledges_everything(monkeypatch) -> None:
    row = _warning_row()
    calls = _stub_reported(monkeypatch, {"acknowledged": [row]})

    result = CliRunner().invoke(sessions.sessions_group, ["ack", "--json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "schema": warnings_mod.WARNINGS_SCHEMA_VERSION,
        "acknowledged": [row],
    }
    assert calls == [(["ack"], {"env": None, "feature": "sessions"})]


def test_ack_passes_the_selector_through(monkeypatch) -> None:
    calls = _stub_reported(monkeypatch, {"acknowledged": [_warning_row()]})

    result = CliRunner().invoke(sessions.sessions_group, ["ack", "~/git/aplexer:shell"])

    assert result.exit_code == 0, result.output
    assert calls[0][0] == ["ack", "~/git/aplexer:shell"]
    assert "acknowledged ~/git/aplexer:shell (oom)" in result.output
    assert "acknowledged 1 warning(s)" in result.output


def test_ack_reports_a_targeted_miss(monkeypatch) -> None:
    _stub_reported(monkeypatch, {"acknowledged": []})

    result = CliRunner().invoke(sessions.sessions_group, ["ack", "nope:gone"])

    assert result.exit_code == 0, result.output
    assert "no matching unacknowledged warning" in result.output


def test_ack_fails_loud_when_the_probe_fails(monkeypatch) -> None:
    _stub_reported(monkeypatch, None, AplexerFailure("unresolved", ""))

    result = CliRunner().invoke(sessions.sessions_group, ["ack"])

    assert result.exit_code == 1
    assert "could not acknowledge crash warnings" in result.output


def test_list_banner_rides_only_the_human_listing(monkeypatch) -> None:
    _stub_listing(monkeypatch, [_warning_row()])

    human = CliRunner().invoke(sessions.sessions_group, ["list"])

    assert human.exit_code == 0, human.output
    assert "unacknowledged crash warning" in human.output
    assert "oom ~/git/aplexer:shell" in human.output


def test_list_json_stays_warning_free(monkeypatch) -> None:
    _stub_listing(monkeypatch, [_warning_row()])

    result = CliRunner().invoke(sessions.sessions_group, ["list", "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema"] == 3
    assert "warning" not in result.output


def test_list_banner_degrades_quietly_on_probe_failure(monkeypatch) -> None:
    # A listing must not fail over warnings it cannot fetch (an older
    # bundled aplexer without the subcommand, kill switches, ...).
    _stub_listing(monkeypatch, None)

    result = CliRunner().invoke(sessions.sessions_group, ["list"])

    assert result.exit_code == 0, result.output
    assert "unacknowledged" not in result.output


def test_human_age_phrase_matches_the_aplexer_banner() -> None:
    now = 1_768_000_000_000
    phrase = warnings_mod.human_age_phrase
    assert phrase(now - 30_000, now_ms=now) == "just now"
    assert phrase(now - 5 * 60_000, now_ms=now) == "5m ago"
    assert phrase(now - 3 * 3_600_000, now_ms=now) == "3h ago"
    assert phrase(now - 2 * 86_400_000, now_ms=now) == "2d ago"
