"""Tests for the pure TrayModel, MenuItemSpec, and NotificationDetector."""

from __future__ import annotations

import pytest

from pocketshell.tray.model import (
    ConnectedClient,
    NotificationDetector,
    SessionInfo,
    TrayModel,
)

SAMPLE_STATUS_JSON = {
    "v": 1,
    "checked_at": "2026-10-13T19:20:00Z",
    "device_id": "host-desktop-fp4op26-venv",
    "state": "online",
    "summary": "Gateway is online and reachable",
    "agent": {
        "installed": True,
        "running": True,
        "pid": 1234,
        "connected": True,
        "connected_since": "2026-10-13T18:00:00Z",
        "source": "presence",
        "last_error": None,
    },
    "sshd": {"running": True, "port": 22, "reachable": True},
    "clients": [
        {
            "user": "alexey",
            "key_fingerprint": "SHA256:abc123def456",
            "key_comment": "grok-bot",
            "since": "2026-10-13T19:00:00Z",
            "via": "gateway",
        }
    ],
    "sessions": [
        {
            "name": "proj:tag",
            "id": "sess-1",
            "engine": "claude",
            "state": "running",
            "agent_state": "working",
        }
    ],
    "errors": [],
}


def test_tray_model_parses_sample_json():
    model = TrayModel.from_status_dict(SAMPLE_STATUS_JSON)

    assert model.v == 1
    assert model.checked_at == "2026-10-13T19:20:00Z"
    assert model.device_id == "host-desktop-fp4op26-venv"
    assert model.state == "online"
    assert model.icon_state == "online"
    assert model.summary == "Gateway is online and reachable"
    assert len(model.clients) == 1
    assert model.clients[0].user == "alexey"
    assert model.clients[0].key_comment == "grok-bot"
    assert len(model.sessions) == 1
    assert model.sessions[0].name == "proj:tag"
    assert model.sessions[0].engine == "claude"
    assert model.sessions[0].agent_state == "working"


def test_tray_model_from_error():
    model = TrayModel.from_error("Connection refused")
    assert model.state == "error"
    assert model.icon_state == "error"
    assert model.summary == "Connection refused"
    assert model.errors == ("Connection refused",)
    assert model.can_start is True
    assert model.can_stop is False
    assert model.can_restart is True


def test_tooltip_formatting():
    model = TrayModel.from_status_dict(SAMPLE_STATUS_JSON)
    assert model.tooltip == "Gateway is online and reachable (1 connected · 1 sessions)"

    # Test empty clients and sessions
    doc_empty = dict(SAMPLE_STATUS_JSON, clients=[], sessions=[])
    model_empty = TrayModel.from_status_dict(doc_empty)
    assert model_empty.tooltip == "Gateway is online and reachable (0 connected · 0 sessions)"

    # Test truncation when summary is extremely long (to protect Windows NOTIFYICONDATA 128 char limit)
    doc_long = dict(SAMPLE_STATUS_JSON, summary="A" * 200)
    model_long = TrayModel.from_status_dict(doc_long)
    assert len(model_long.tooltip) <= 127
    assert model_long.tooltip.endswith("… (1 connected · 1 sessions)")


@pytest.mark.parametrize(
    "state,expected_header,can_start,can_stop,can_restart",
    [
        ("online", "PocketShell: Online", False, True, True),
        ("degraded", "PocketShell: Degraded", False, True, True),
        ("offline", "PocketShell: Offline", True, False, False),
        ("not_installed", "PocketShell: Not Installed", True, False, False),
        ("error", "PocketShell: Error", True, False, True),
    ],
)
def test_states_header_and_permissions(state, expected_header, can_start, can_stop, can_restart):
    doc = dict(SAMPLE_STATUS_JSON, state=state)
    model = TrayModel.from_status_dict(doc)

    assert model.header_title == expected_header
    assert model.can_start is can_start
    assert model.can_stop is can_stop
    assert model.can_restart is can_restart


def test_menu_spec_structure_online():
    model = TrayModel.from_status_dict(SAMPLE_STATUS_JSON)
    menu = model.menu_spec(autostart_checked=True)

    # 1. Header
    assert menu[0].text == "PocketShell: Online"
    assert menu[0].enabled is False

    # 2. Clients submenu
    assert menu[1].text == "Connected now (1)"
    assert len(menu[1].children) == 1
    assert "alexey · grok-bot" in menu[1].children[0].text

    # 3. Sessions submenu
    assert menu[2].text == "Sessions (1)"
    assert len(menu[2].children) == 1
    assert "proj:tag · claude · working" in menu[2].children[0].text

    # 4. Separator
    assert menu[3].is_separator is True

    # 5. Start / Stop / Restart actions
    start_item = next(i for i in menu if i.action_id == "start")
    stop_item = next(i for i in menu if i.action_id == "stop")
    restart_item = next(i for i in menu if i.action_id == "restart")

    assert start_item.enabled is False
    assert stop_item.enabled is True
    assert restart_item.enabled is True

    # 6. Utilities
    open_logs = next(i for i in menu if i.action_id == "open_logs")
    copy_dev = next(i for i in menu if i.action_id == "copy_device_id")
    autostart = next(i for i in menu if i.action_id == "toggle_autostart")
    quit_item = next(i for i in menu if i.action_id == "quit")

    assert open_logs.enabled is True
    assert copy_dev.enabled is True
    assert autostart.checked is True
    assert quit_item.enabled is True


def test_menu_spec_structure_empty_clients_and_no_device_id():
    doc = dict(SAMPLE_STATUS_JSON, clients=[], sessions=[], device_id=None, state="offline")
    model = TrayModel.from_status_dict(doc)
    menu = model.menu_spec(autostart_checked=False)

    # Connected now (0) with (None) child
    connected_menu = menu[1]
    assert connected_menu.text == "Connected now (0)"
    assert len(connected_menu.children) == 1
    assert connected_menu.children[0].text == "(None)"
    assert connected_menu.children[0].enabled is False

    # Sessions (0) with (None) child
    sessions_menu = menu[2]
    assert sessions_menu.text == "Sessions (0)"
    assert len(sessions_menu.children) == 1
    assert sessions_menu.children[0].text == "(None)"

    # Copy device id should be disabled when device_id is None
    copy_dev = next(i for i in menu if i.action_id == "copy_device_id")
    assert copy_dev.enabled is False

    # Start enabled, stop disabled in offline state
    start_item = next(i for i in menu if i.action_id == "start")
    stop_item = next(i for i in menu if i.action_id == "stop")
    assert start_item.enabled is True
    assert stop_item.enabled is False


def test_client_display_lines():
    c1 = ConnectedClient(user="user1", key_comment="laptop", since="10:00")
    assert c1.display_line == "user1 · laptop · 10:00"

    c2 = ConnectedClient(user="user2", key_fingerprint="SHA256:12345678901234567890", since="11:00")
    assert c2.display_line == "user2 · SHA256:123456789… · 11:00"

    c3 = ConnectedClient(user="user3")
    assert c3.display_line == "user3"


def test_session_display_lines():
    s1 = SessionInfo(name="proj:dev", engine="codex", agent_state="idle")
    assert s1.display_line == "proj:dev · codex · idle"

    s2 = SessionInfo(name="proj:eval", engine="claude", state="running", agent_state=None)
    assert s2.display_line == "proj:eval · claude · running"

    s3 = SessionInfo(name="bare")
    assert s3.display_line == "bare"


def test_notification_detector_transitions_and_new_clients():
    detector = NotificationDetector()

    # Initial update: sets baseline, no spurious notifications
    model1 = TrayModel.from_status_dict(SAMPLE_STATUS_JSON)
    events1 = detector.update(model1)
    assert len(events1) == 0

    # Repeat poll with same state and clients: no notifications
    events_repeat = detector.update(model1)
    assert len(events_repeat) == 0

    # State transition: online -> degraded is debounced (no instant balloon)
    doc_degraded = dict(SAMPLE_STATUS_JSON, state="degraded", summary="Local SSH server is not running")
    model2 = TrayModel.from_status_dict(doc_degraded)
    events2 = detector.update(model2)
    assert len(events2) == 0

    # Client connects: new client added (client notifications are not debounced)
    clients_with_new = list(SAMPLE_STATUS_JSON["clients"]) + [
        {
            "user": "bob",
            "key_fingerprint": "SHA256:bob999",
            "key_comment": "bob-workstation",
            "since": "2026-10-13T19:30:00Z",
        }
    ]
    doc_new_client = dict(doc_degraded, clients=clients_with_new)
    model3 = TrayModel.from_status_dict(doc_new_client)
    events3 = detector.update(model3)
    assert len(events3) == 1
    assert events3[0].title == "New Gateway Connection"
    assert "bob (bob-workstation) connected" in events3[0].message

    # Both state recovery and new client in same poll: recovery was never
    # announced (the blip stayed silent), so only the client event fires.
    clients_third = list(clients_with_new) + [
        {
            "user": "charlie",
            "key_fingerprint": "SHA256:charlie123",
            "key_comment": None,
            "since": "2026-10-13T19:40:00Z",
        }
    ]
    doc_both = dict(SAMPLE_STATUS_JSON, state="online", summary="Back online", clients=clients_third)
    model4 = TrayModel.from_status_dict(doc_both)
    events4 = detector.update(model4)
    assert len(events4) == 1
    assert any("charlie connected" in e.message for e in events4)


class _FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def _model(state, summary="s"):
    return TrayModel.from_status_dict(dict(SAMPLE_STATUS_JSON, state=state, summary=summary))


def test_notification_detector_offline_hysteresis_needs_60s():
    clock = _FakeClock()
    detector = NotificationDetector(clock=clock)
    assert detector.update(_model("online")) == []

    # A single bad poll stays completely silent.
    clock.advance(5)
    assert detector.update(_model("offline")) == []

    # Still silent just before the 60s window closes (window opened at t=1005).
    clock.advance(54.9)
    assert detector.update(_model("offline")) == []

    # Persisting past the window announces the outage once.
    clock.advance(5.2)
    events = detector.update(_model("offline"))
    assert len(events) == 1
    assert events[0].title == "PocketShell Gateway: Offline"

    # No repeat announcements while the outage continues.
    clock.advance(120)
    assert detector.update(_model("offline")) == []


def test_notification_detector_blip_resolving_inside_window_stays_silent():
    clock = _FakeClock()
    detector = NotificationDetector(clock=clock)
    assert detector.update(_model("online")) == []

    clock.advance(10)
    assert detector.update(_model("offline")) == []
    # Recovers before the window closes: no outage was announced, so no
    # recovery announcement either.
    clock.advance(10)
    assert detector.update(_model("online")) == []


def test_notification_detector_recovery_after_announced_outage_is_immediate():
    clock = _FakeClock()
    detector = NotificationDetector(clock=clock)
    assert detector.update(_model("online")) == []

    clock.advance(1)
    assert detector.update(_model("degraded")) == []
    clock.advance(60)
    events = detector.update(_model("degraded"))
    assert len(events) == 1

    clock.advance(1)
    recovered = detector.update(_model("online", summary="Back online"))
    assert len(recovered) == 1
    assert recovered[0].title == "PocketShell Gateway: Online"


def test_notification_detector_down_state_switch_keeps_original_timer():
    clock = _FakeClock()
    detector = NotificationDetector(clock=clock)
    assert detector.update(_model("online")) == []

    clock.advance(1)
    assert detector.update(_model("offline")) == []
    # Switching between down states does not restart the debounce window.
    clock.advance(50)
    assert detector.update(_model("degraded")) == []
    clock.advance(10)
    events = detector.update(_model("degraded"))
    assert len(events) == 1
    assert events[0].title == "PocketShell Gateway: Degraded"


def test_notification_detector_minimum_hysteresis_is_60s():
    assert NotificationDetector.DEBOUNCE_SECONDS >= 60.0
    assert NotificationDetector(clock=_FakeClock())._debounce_seconds >= 60.0
