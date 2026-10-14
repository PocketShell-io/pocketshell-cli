import json
from click.testing import CliRunner
from pocketshell import windows_sessions as commands


def test_windows_listing_has_the_standard_session_contract(monkeypatch):
    row = commands.runtime.LiveSession(name="repo:tray", aplexer_id="test-id", tag="tray",
                                       workspace="C:/work/repo", phase="running")
    monkeypatch.setattr(commands.runtime, "enumerate_live_sessions", lambda: ([row], []))
    result = CliRunner().invoke(commands.sessions_group, ["list", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["schema"] == 3
    assert payload["sessions"][0]["id"] == "test-id"
    assert payload["sessions"][0]["name"] == "repo:tray"
    assert payload["errors"] == []


def test_probe_failure_is_not_reported_as_a_healthy_empty_list(monkeypatch):
    monkeypatch.setattr(commands.runtime, "enumerate_live_sessions", lambda: ([], [{"message":"worker probe failed"}]))
    result = CliRunner().invoke(commands.sessions_group, ["ls", "--json"])
    assert result.exit_code == 1
    assert json.loads(result.output)["errors"] == [{"message":"worker probe failed"}]
