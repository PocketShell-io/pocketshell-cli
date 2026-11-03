from __future__ import annotations

import tomllib
from pathlib import Path

from click.testing import CliRunner

from pocketshell import __version__
from pocketshell.cli import cli


def _pyproject_version() -> str:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    with pyproject.open("rb") as handle:
        return tomllib.load(handle)["project"]["version"]


def test_internal_version_matches_pyproject_metadata() -> None:
    assert __version__ == _pyproject_version()


def test_top_level_version_matches_pyproject_metadata() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])

    assert result.exit_code == 0, result.output
    assert result.output == f"pocketshell, version {_pyproject_version()}\n"


def test_hub_owned_commands_are_not_registered() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0, result.output
    assert "push" not in cli.commands

    for args in (["push", "--help"], ["agent-log", "handoff"]):
        result = runner.invoke(cli, args)
        assert result.exit_code != 0
        assert (
            "No such command" in result.output
            or "unexpected extra argument" in result.output
        )

    usage_help = runner.invoke(cli, ["usage", "--help"])
    assert usage_help.exit_code == 0, usage_help.output
    for removed_option in ("--capture", "--cached", "--reset-events"):
        assert removed_option not in usage_help.output
