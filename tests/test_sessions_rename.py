"""Aplexer-only rename contract tests (issue #9)."""

from __future__ import annotations

import json
import subprocess

from click.testing import CliRunner

from pocketshell import sessions
from pocketshell.runtime import aplexer, sessions as session_enum
from pocketshell.sessions import rename as rename_mod


def _resolution() -> aplexer.AplexerResolution:
    return aplexer.AplexerResolution(path="/fake/a", tried=("/fake/a",))


def _row(**overrides: object) -> session_enum.LiveSession:
    fields: dict[str, object] = {
        "name": "project:shell",
        "aplexer_id": "b3feff71-4a78-4055-a2d3-6c99187ecffb",
        "workspace": "/work/project",
        "tag": "shell",
    }
    fields.update(overrides)
    return session_enum.LiveSession(**fields)


def _completed(argv: list[str], *, code: int = 0, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess(argv, code, stdout=stdout, stderr=stderr)


def test_rename_invokes_a_rename_with_the_resolved_id_and_new_tag(monkeypatch) -> None:
    """AC: the argv pins the delegation — resolved id, never the display name."""
    calls: list[list[str]] = []
    monkeypatch.setattr(rename_mod, "_attach_live_rows", lambda: ([_row()], []))
    monkeypatch.setattr(rename_mod, "_resolve_aplexer", _resolution)
    monkeypatch.setattr(
        rename_mod,
        "_run_session_command",
        lambda argv: (calls.append(list(argv)), _completed(argv, stdout="{}"))[1],
    )

    result = CliRunner().invoke(
        sessions.sessions_group, ["rename", "project:shell", "review", "--json"]
    )

    assert result.exit_code == 0, result.output
    assert calls == [
        [
            "/fake/a", "--json", "rename",
            "b3feff71-4a78-4055-a2d3-6c99187ecffb", "--tag", "review",
        ]
    ]
    payload = json.loads(result.output)
    assert payload == {
        "schema": 3,
        "name": "project:review",
        "id": "b3feff71-4a78-4055-a2d3-6c99187ecffb",
        "renamed": True,
        "tag": "review",
    }


def test_rename_reports_a_missing_session(monkeypatch) -> None:
    monkeypatch.setattr(rename_mod, "_attach_live_rows", lambda: ([], []))
    result = CliRunner().invoke(sessions.sessions_group, ["rename", "missing", "x"])
    assert result.exit_code == sessions.ATTACH_EXIT_NOT_FOUND
    assert "no session named" in result.output


def test_rename_reports_an_ambiguous_session(monkeypatch) -> None:
    monkeypatch.setattr(
        rename_mod,
        "_attach_live_rows",
        # Same display name from two different workspaces — the only way
        # exact matching is ambiguous.
        lambda: ([_row(), _row(aplexer_id="aaaaaaaa-4a78-4055-a2d3-6c99187ecffb")], []),
    )
    result = CliRunner().invoke(sessions.sessions_group, ["rename", "project:shell", "x"])
    assert result.exit_code == sessions.ATTACH_EXIT_AMBIGUOUS
    assert "ambiguous session name" in result.output


def test_rename_fails_clearly_for_a_row_without_an_aplexer_id(monkeypatch) -> None:
    """The no-id row analogue of issue #9's tmux clause: loud, never silent."""
    monkeypatch.setattr(rename_mod, "_attach_live_rows", lambda: ([_row(aplexer_id=None)], []))
    monkeypatch.setattr(rename_mod, "_resolve_aplexer", _resolution)
    result = CliRunner().invoke(
        sessions.sessions_group, ["rename", "project:shell", "review", "--json"]
    )
    assert result.exit_code == sessions.ATTACH_EXIT_NOT_FOUND, result.output
    assert "cannot be renamed" in json.loads(result.output)["error"]


def test_rename_fails_loudly_when_aplexer_cannot_resolve(monkeypatch) -> None:
    monkeypatch.setattr(rename_mod, "_attach_live_rows", lambda: ([_row()], []))
    monkeypatch.setattr(
        rename_mod,
        "_resolve_aplexer",
        lambda: aplexer.AplexerResolution(tried=("APLEXER_BIN (unset)",)),
    )
    result = CliRunner().invoke(sessions.sessions_group, ["rename", "project:shell", "review"])
    assert result.exit_code == sessions.ATTACH_EXIT_NO_BINARY
    assert "could not resolve" in result.output


def test_rename_surfaces_aplexer_rejection_verbatim(monkeypatch) -> None:
    """A bad tag (or the aplexer#13 dead-claim gap) surfaces aplexer's text."""
    monkeypatch.setattr(rename_mod, "_attach_live_rows", lambda: ([_row()], []))
    monkeypatch.setattr(rename_mod, "_resolve_aplexer", _resolution)
    monkeypatch.setattr(
        rename_mod,
        "_run_session_command",
        lambda argv: _completed(
            argv, code=1,
            stderr="a: workspace+tag already belongs to session 6f0e2e2f-0000\n",
        ),
    )
    result = CliRunner().invoke(
        sessions.sessions_group, ["rename", "project:shell", "bad tag!", "--json"]
    )
    assert result.exit_code == 1
    error = json.loads(result.output)["error"]
    assert "already belongs to session 6f0e2e2f-0000" in error, (
        "aplexer's own diagnosis must reach the user verbatim (issue #9); "
        f"got: {error}"
    )


def test_rename_to_the_current_tag_is_a_no_op_success(monkeypatch) -> None:
    """AC: same-name rename succeeds without invoking aplexer at all.

    aplexer's claim check rejects a workspace+tag its own target record
    already holds (aplexer#13), so the short-circuit is what makes the
    no-op succeed instead of erroring.
    """
    calls: list[list[str]] = []
    monkeypatch.setattr(rename_mod, "_attach_live_rows", lambda: ([_row()], []))
    monkeypatch.setattr(
        rename_mod,
        "_run_session_command",
        lambda argv: (calls.append(list(argv)), _completed(argv))[1],
    )

    result = CliRunner().invoke(
        sessions.sessions_group, ["rename", "project:shell", "shell", "--json"]
    )

    assert result.exit_code == 0, result.output
    assert calls == [], "a self-rename must never reach aplexer"
    payload = json.loads(result.output)
    assert payload["renamed"] is False
    assert payload["tag"] == "shell"
    assert payload["name"] == "project:shell"


def test_rename_names_the_enumeration_error_instead_of_degrading(monkeypatch) -> None:
    """A probe failure is visible (exit 127), matching kill's contract."""
    monkeypatch.setattr(
        rename_mod,
        "_attach_live_rows",
        lambda: ([], [{"message": "boom from the probe"}]),
    )
    result = CliRunner().invoke(sessions.sessions_group, ["rename", "x", "y"])
    assert result.exit_code == sessions.ATTACH_EXIT_NO_BINARY
    assert "boom from the probe" in result.output
