"""Tests for GatewayStatusClient and system interaction utilities."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from pocketshell.tray.status_client import (
    GatewayStatusClient,
    copy_to_clipboard,
    open_logs_folder,
    resolve_logs_dir,
)

SAMPLE_JSON = json.dumps(
    {
        "v": 1,
        "checked_at": "2026-10-13T20:00:00Z",
        "device_id": "host-1",
        "state": "online",
        "summary": "Gateway online",
        "clients": [],
        "sessions": [],
        "errors": [],
    }
)


def test_fetch_status_success():
    client = GatewayStatusClient(status_command=["fake-status"])
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=SAMPLE_JSON.encode("utf-8"),
            stderr=b"",
        )
        model = client.fetch_status()

    assert model.state == "online"
    assert model.device_id == "host-1"
    assert model.summary == "Gateway online"


def test_fetch_status_nonzero_with_json_still_parses():
    client = GatewayStatusClient(status_command=["fake-status"])
    degraded_json = json.dumps(
        {
            "v": 1,
            "checked_at": "2026-10-13T20:00:00Z",
            "device_id": "host-1",
            "state": "degraded",
            "summary": "Local SSH not reachable",
            "errors": ["sshd connect failed"],
        }
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout=degraded_json.encode("utf-8"),
            stderr=b"some warning",
        )
        model = client.fetch_status()

    assert model.state == "degraded"
    assert model.summary == "Local SSH not reachable"
    assert "sshd connect failed" in model.errors


def test_fetch_status_timeout():
    client = GatewayStatusClient(status_command=["fake-status"])
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="fake-status", timeout=4.0)):
        model = client.fetch_status()

    assert model.state == "error"
    assert "timed out" in model.summary.lower()


def test_fetch_status_corrupted_output():
    client = GatewayStatusClient(status_command=["fake-status"])
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout=b"Not valid json at all",
            stderr=b"Fatal error in daemon",
        )
        model = client.fetch_status()

    assert model.state == "error"
    assert "Fatal error in daemon" in model.summary


def test_start_stop_restart_gateway():
    client = GatewayStatusClient()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=b"Gateway started", stderr=b"")
        ok, msg = client.start_gateway()
        assert ok is True
        assert "Gateway started" in msg

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=b"Gateway stopped", stderr=b"")
        ok, msg = client.stop_gateway()
        assert ok is True
        assert "Gateway stopped" in msg

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=b"Gateway restarted", stderr=b"")
        ok, msg = client.restart_gateway()
        assert ok is True
        assert "Gateway restarted" in msg


def test_copy_to_clipboard():
    assert copy_to_clipboard("") is False

    with patch("shutil.which", return_value="/usr/bin/wl-copy"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert copy_to_clipboard("device-id-123") is True
            mock_run.assert_called_once()


def test_resolve_logs_dir():
    dir_path = resolve_logs_dir()
    assert isinstance(dir_path, Path)
    assert "logs" in str(dir_path)


def test_open_logs_folder(tmp_path: Path):
    with patch("pocketshell.tray.status_client.resolve_logs_dir", return_value=tmp_path / "logs"):
        with patch("subprocess.Popen") as mock_popen:
            ok, path_str = open_logs_folder()
            assert ok is True
            assert (tmp_path / "logs").is_dir()
            mock_popen.assert_called_once()
