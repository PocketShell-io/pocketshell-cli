"""Tests for the TrayApp runtime integration."""

from __future__ import annotations

import pytest

from unittest.mock import MagicMock

from pocketshell.tray.app import TrayApp
from pocketshell.tray.model import ConnectedClient, TrayModel


def test_tray_app_poll_once_and_notifications():
    mock_client = MagicMock()
    mock_autostart_checker = MagicMock(return_value=False)

    app = TrayApp(
        status_client=mock_client,
        autostart_checker=mock_autostart_checker,
    )
    notifications = []
    app.notify = lambda msg, title="": notifications.append((title, msg))

    # 1. Baseline poll
    m1 = TrayModel(state="offline", summary="Gateway offline")
    mock_client.fetch_status.return_value = m1
    res1 = app.poll_once()
    assert res1.state == "offline"
    assert len(notifications) == 0

    # 2. State transition to online (no clients yet)
    m2 = TrayModel(
        state="online",
        summary="Gateway online",
        clients=(),
    )
    mock_client.fetch_status.return_value = m2
    app.poll_once()

    assert len(notifications) == 1
    assert "Online" in notifications[0][0]

    # 3. First client connects
    m3 = TrayModel(
        state="online",
        summary="Gateway online",
        clients=(ConnectedClient(user="alice", key_comment="macbook"),),
    )
    mock_client.fetch_status.return_value = m3
    app.poll_once()

    assert len(notifications) == 2
    assert "New Gateway Connection" in notifications[1][0]
    assert "alice (macbook) connected" in notifications[1][1]

    # 4. Second client connects
    m4 = TrayModel(
        state="online",
        summary="Gateway online",
        clients=(
            ConnectedClient(user="alice", key_comment="macbook"),
            ConnectedClient(user="bob", key_comment="phone"),
        ),
    )
    mock_client.fetch_status.return_value = m4
    app.poll_once()

    assert len(notifications) == 3
    assert "bob (phone) connected" in notifications[2][1]


def test_tray_app_toggle_autostart():
    installed = False

    def fake_install():
        nonlocal installed
        installed = True
        return True, "installed"

    def fake_remove():
        nonlocal installed
        installed = False
        return True, "removed"

    app = TrayApp(
        autostart_checker=lambda: installed,
        autostart_installer=fake_install,
        autostart_remover=fake_remove,
    )
    assert app._autostart_checked is False

    # Toggle on
    app.do_toggle_autostart()
    assert installed is True
    assert app._autostart_checked is True

    # Toggle off
    app.do_toggle_autostart()
    assert installed is False
    assert app._autostart_checked is False


def test_tray_app_actions():
    mock_client = MagicMock()
    app = TrayApp(status_client=mock_client)
    mock_client.fetch_status.return_value = TrayModel(state="offline")

    app.do_start()
    mock_client.start_gateway.assert_called_once()

    app.do_stop()
    mock_client.stop_gateway.assert_called_once()

    app.do_restart()
    mock_client.restart_gateway.assert_called_once()


def test_run_control_notifies_on_failure_result():
    mock_client = MagicMock()
    mock_client.start_gateway.return_value = (False, "task refused the start")
    mock_client.fetch_status.return_value = TrayModel(state="offline")
    app = TrayApp(status_client=mock_client)
    notifications = []
    app.notify = lambda msg, title="": notifications.append((title, msg))

    app.do_start()

    assert len(notifications) == 1
    assert "Gateway needs attention" in notifications[0][0]
    assert "task refused the start" in notifications[0][1]


def test_run_control_notifies_on_raised_exception():
    mock_client = MagicMock()
    mock_client.stop_gateway.side_effect = RuntimeError("no link process appeared within 15s")
    mock_client.fetch_status.return_value = TrayModel(state="offline")
    app = TrayApp(status_client=mock_client)
    notifications = []
    app.notify = lambda msg, title="": notifications.append((title, msg))

    app.do_stop()

    assert len(notifications) == 1
    assert "gateway stop failed" in notifications[0][1]


def test_run_control_success_stays_silent():
    mock_client = MagicMock()
    mock_client.restart_gateway.return_value = (True, "restarted pocketshell-gateway.service")
    mock_client.fetch_status.return_value = TrayModel(state="online")
    app = TrayApp(status_client=mock_client)
    notifications = []
    app.notify = lambda msg, title="": notifications.append((title, msg))

    app.do_restart()

    assert notifications == []


def test_tray_app_build_menu():
    pystray = pytest.importorskip("pystray")

    model = TrayModel(
        state="online",
        summary="Running",
        device_id="dev-123",
        clients=(ConnectedClient(user="alexey", key_comment="laptop"),),
    )
    app = TrayApp(initial_model=model)
    app.model = model

    menu = app._build_pystray_menu()
    assert isinstance(menu, pystray.Menu)
    items = list(menu.items)
    assert len(items) >= 8

    # First item is header
    assert "PocketShell: Online" in items[0].text
