"""Aplexer-only lifecycle contract tests for ``pocketshell sessions``."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from click.testing import CliRunner

from pocketshell import aplexer, sessions


def _resolution(path: str | None) -> aplexer.AplexerResolution:
    return aplexer.AplexerResolution(
        path=path,
        source="test" if path else None,
        worker="/fake/aplexer" if path else None,
        tried=(path or "missing",),
    )


def _record() -> dict[str, object]:
    return {
        "id": "b3feff71-4a78-4055-a2d3-6c99187ecffb",
        "workspace": "/work/project",
        "tag": "shell",
        "phase": "running",
        "worker_alive": True,
        "worker_pid": 1234,
    }


def test_create_uses_only_aplexer_and_emits_schema_three(monkeypatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(sessions, "_resolve_aplexer", lambda: _resolution("/fake/a"))
    monkeypatch.setattr(sessions, "_aplexer_snapshot", lambda: [])
    monkeypatch.setattr(sessions._memcap, "resolve_session_mem_bytes", lambda **_: 123)
    monkeypatch.setattr(sessions, "uuid4", lambda: SimpleNamespace(hex="deadbeefcafe"))

    def start(argv):
        calls.append(list(argv))
        return 0, json.dumps(_record()), ""

    monkeypatch.setattr(sessions, "_run_aplexer", start)
    result = CliRunner().invoke(
        sessions.sessions_group,
        ["create", "shell", "--cwd", str(tmp_path), "--engine", "codex", "--json"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload == {
        "schema": 3,
        "name": "project:shell",
        "id": _record()["id"],
        "created": True,
    }
    assert calls == [[
        "systemd-run", "--user", "--scope",
        "--unit", "aplexer-launch-deadbeefcafe", "--collect", "--",
        "/fake/a", "--json", "start", "--workspace", str(tmp_path),
        "--tag", "shell", "--engine", "codex", "--memory", "123",
    ]]
    assert "backend" not in result.output.lower()


def test_capped_start_wraps_the_worker_in_a_unique_user_scope() -> None:
    first = sessions.aplexer_start_argv(
        aplexer_path="/fake/a", workspace="/work/project", tag="shell",
        engine=None, profile=None, memory_bytes=123,
    )
    second = sessions.aplexer_start_argv(
        aplexer_path="/fake/a", workspace="/work/project", tag="shell",
        engine=None, profile=None, memory_bytes=123,
    )
    for argv in (first, second):
        assert argv[:7] == [
            "systemd-run", "--user", "--scope", "--unit", argv[4], "--collect", "--",
        ]
        assert argv[4].startswith("aplexer-launch-")
        assert "--memory" in argv[7:]
    assert first[4] != second[4]


def test_uncapped_start_is_not_wrapped() -> None:
    argv = sessions.aplexer_start_argv(
        aplexer_path="/fake/a", workspace="/work/project", tag="shell",
        engine=None, profile=None, memory_bytes=None,
    )
    assert argv == ["/fake/a", "--json", "start", "--workspace", "/work/project", "--tag", "shell"]
    assert not any("systemd-run" in part for part in argv)


def test_create_reuses_a_live_record_without_starting_again(monkeypatch, tmp_path: Path) -> None:
    starts: list[list[str]] = []
    monkeypatch.setattr(sessions, "_resolve_aplexer", lambda: _resolution("/fake/a"))
    monkeypatch.setattr(
        sessions,
        "_aplexer_snapshot",
        lambda: [{**_record(), "workspace": str(tmp_path)}],
    )
    monkeypatch.setattr(sessions._memcap, "resolve_session_mem_bytes", lambda **_: 123)
    monkeypatch.setattr(sessions, "_run_aplexer", lambda argv: starts.append(list(argv)))

    result = CliRunner().invoke(
        sessions.sessions_group,
        ["create", "shell", "--cwd", str(tmp_path), "--json"],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["created"] is False
    assert starts == []


def test_create_fails_loudly_when_aplexer_cannot_resolve(monkeypatch) -> None:
    monkeypatch.setattr(sessions, "_resolve_aplexer", lambda: _resolution(None))
    result = CliRunner().invoke(sessions.sessions_group, ["create", "shell", "--json"])

    assert result.exit_code == 127
    assert "could not resolve" in result.output


def _start_recording(calls: list[list[str]]):
    def start(argv: list[str]):
        calls.append(list(argv))
        return 0, json.dumps(_record()), ""

    return start


def test_create_translates_a_profile_display_name_onto_the_aplexer_id(
    monkeypatch, tmp_path: Path
) -> None:
    """#2661: the picker sends display names; aplexer wants dir-stem ids."""
    calls: list[list[str]] = []
    monkeypatch.setattr(sessions, "_resolve_aplexer", lambda: _resolution("/fake/a"))
    monkeypatch.setattr(sessions, "_aplexer_snapshot", lambda: [])
    monkeypatch.setattr(sessions._memcap, "resolve_session_mem_bytes", lambda **_: 123)
    monkeypatch.setattr(sessions, "_run_aplexer", _start_recording(calls))
    monkeypatch.setattr(
        sessions._profiles,
        "resolve_aplexer_profile_arg",
        lambda name, engine=None: {"Zcodex": "zcodex"}.get(name, name),
    )

    result = CliRunner().invoke(
        sessions.sessions_group,
        [
            "create", "shell", "--cwd", str(tmp_path),
            "--engine", "codex", "--profile", "Zcodex", "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls[0][calls[0].index("--profile") + 1] == "zcodex"


def test_create_drops_the_profile_flag_for_the_engine_default_display_name(
    monkeypatch, tmp_path: Path
) -> None:
    """#2661: aplexer omits default dirs, so `--profile Codex` must go away."""
    calls: list[list[str]] = []
    monkeypatch.setattr(sessions, "_resolve_aplexer", lambda: _resolution("/fake/a"))
    monkeypatch.setattr(sessions, "_aplexer_snapshot", lambda: [])
    monkeypatch.setattr(sessions._memcap, "resolve_session_mem_bytes", lambda **_: 123)
    monkeypatch.setattr(sessions, "_run_aplexer", _start_recording(calls))
    monkeypatch.setattr(
        sessions._profiles,
        "resolve_aplexer_profile_arg",
        lambda name, engine=None: None if name == "Codex" else name,
    )

    result = CliRunner().invoke(
        sessions.sessions_group,
        [
            "create", "shell", "--cwd", str(tmp_path),
            "--engine", "codex", "--profile", "Codex", "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "--profile" not in calls[0]
