"""Tests for the `pocketshell tray` CLI interface."""

from __future__ import annotations

import pytest

from unittest.mock import patch

from click.testing import CliRunner

from pocketshell.cli import cli


def test_tray_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["tray", "--help"])
    assert result.exit_code == 0
    assert "PocketShell background system tray application" in result.output
    assert "--install-autostart" in result.output
    assert "--remove-autostart" in result.output
    assert "--poll-interval" in result.output


def test_tray_autostart_flags_mutual_exclusion():
    runner = CliRunner()
    result = runner.invoke(cli, ["tray", "--install-autostart", "--remove-autostart"])
    assert result.exit_code == 2
    assert "Cannot specify both" in result.output


def test_tray_install_autostart():
    runner = CliRunner()
    with patch("pocketshell.tray.autostart.install_autostart", return_value=(True, "Autostart configured")):
        result = runner.invoke(cli, ["tray", "--install-autostart"])
        assert result.exit_code == 0
        assert "Autostart configured" in result.output

    with patch("pocketshell.tray.autostart.install_autostart", return_value=(False, "Permission denied")):
        result = runner.invoke(cli, ["tray", "--install-autostart"])
        assert result.exit_code == 1
        assert "Permission denied" in result.output


def test_tray_remove_autostart():
    runner = CliRunner()
    with patch("pocketshell.tray.autostart.remove_autostart", return_value=(True, "Autostart removed")):
        result = runner.invoke(cli, ["tray", "--remove-autostart"])
        assert result.exit_code == 0
        assert "Autostart removed" in result.output


def test_tray_missing_dependencies_error():
    runner = CliRunner()
    with patch.dict("sys.modules", {"PIL": None}):
        result = runner.invoke(cli, ["tray"])
        assert result.exit_code == 1
        assert "pocketshell[tray]" in result.output


def test_tray_linux_missing_display():
    # The display check runs after the optional-dependency check.
    pytest.importorskip("PIL")
    pytest.importorskip("pystray")
    runner = CliRunner()
    with patch.dict("os.environ", {}, clear=True):
        with patch("sys.platform", "linux"):
            result = runner.invoke(cli, ["tray"])
            assert result.exit_code == 1
            assert "graphical display" in result.output


def test_tray_single_instance_already_running():
    runner = CliRunner()
    with patch("pocketshell.tray.cli._check_dependencies"):
        with patch("pocketshell.tray.single_instance.SingleInstance.acquire", return_value=False):
            result = runner.invoke(cli, ["tray"])
            assert result.exit_code == 0
            assert "already running" in result.output
