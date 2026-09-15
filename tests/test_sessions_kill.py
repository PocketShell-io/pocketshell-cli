"""Aplexer-only kill and record-reaping contract tests."""

from __future__ import annotations

import json
import subprocess

from click.testing import CliRunner

from pocketshell import sessions
from pocketshell.runtime import aplexer, sessions as session_enum
from pocketshell.sessions import kill as kill_mod


def _resolution() -> aplexer.AplexerResolution:
    return aplexer.AplexerResolution(path="/fake/a", tried=("/fake/a",))


def _row() -> session_enum.LiveSession:
    return session_enum.LiveSession(
        name="project:shell", aplexer_id="b3feff71-4a78-4055-a2d3-6c99187ecffb"
    )


def test_kill_uses_aplexer_record_removal_result(monkeypatch) -> None:
    calls: list[list[str]] = []

    monkeypatch.setattr(kill_mod, "_attach_live_rows", lambda: ([_row()], []))
    monkeypatch.setattr(kill_mod, "_resolve_aplexer", _resolution)

    def run(argv):
        calls.append(list(argv))
        return subprocess.CompletedProcess(
            argv, 0, stdout='{"record_removed": true}', stderr=""
        )

    # sessions_kill resolves _run_session_command through its own module
    # namespace; no second force-forget command should be issued.
    monkeypatch.setattr(kill_mod, "_run_session_command", run)
    result = CliRunner().invoke(
        sessions.sessions_group, ["kill", "project:shell", "--json"]
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload == {
        "schema": 3,
        "name": "project:shell",
        "id": "b3feff71-4a78-4055-a2d3-6c99187ecffb",
        "killed": True,
        "reaped": True,
    }
    assert calls == [
        ["/fake/a", "--json", "kill", "b3feff71-4a78-4055-a2d3-6c99187ecffb"],
    ]


def test_kill_reports_a_missing_session(monkeypatch) -> None:
    monkeypatch.setattr(kill_mod, "_attach_live_rows", lambda: ([], []))
    result = CliRunner().invoke(sessions.sessions_group, ["kill", "missing"])
    assert result.exit_code == sessions.ATTACH_EXIT_NOT_FOUND
    assert "no session named" in result.output
