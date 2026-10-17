"""Pure data model for the PocketShell system tray application.

Decouples status JSON parsing, menu item generation, and notification
event detection from any GUI toolkit (pystray/Pillow).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass(frozen=True)
class ConnectedClient:
    """Represents a client connected to the gateway SSH server."""

    user: str
    key_fingerprint: Optional[str] = None
    key_comment: Optional[str] = None
    since: Optional[str] = None
    via: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConnectedClient:
        return cls(
            user=str(data.get("user") or "unknown"),
            key_fingerprint=data.get("key_fingerprint"),
            key_comment=data.get("key_comment"),
            since=data.get("since"),
            via=data.get("via"),
        )

    @property
    def key_identifier(self) -> str:
        """Stable identifier for connection tracking and notification deduplication."""
        if self.key_fingerprint:
            return self.key_fingerprint
        return f"{self.user}@{self.since or ''}"

    @property
    def display_line(self) -> str:
        """Format: user · key comment (or fingerprint) · since."""
        parts = [self.user]
        comment_or_fp = self.key_comment or (
            self.key_fingerprint[:16] + "…"
            if self.key_fingerprint and len(self.key_fingerprint) > 16
            else self.key_fingerprint
        )
        if comment_or_fp:
            parts.append(comment_or_fp)
        if self.since:
            parts.append(self.since)
        return " · ".join(parts)


@dataclass(frozen=True)
class SessionInfo:
    """Represents an active aplexer session."""

    name: str
    id: Optional[str] = None
    engine: Optional[str] = None
    state: Optional[str] = None
    agent_state: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionInfo:
        return cls(
            name=str(data.get("name") or data.get("id") or "session"),
            id=data.get("id"),
            engine=data.get("engine"),
            state=data.get("state"),
            agent_state=data.get("agent_state"),
        )

    @property
    def display_line(self) -> str:
        """Format: name · engine · agent_state (or state)."""
        parts = [self.name]
        if self.engine:
            parts.append(self.engine)
        detail = self.agent_state or self.state
        if detail:
            parts.append(detail)
        return " · ".join(parts)


@dataclass(frozen=True)
class MenuItemSpec:
    """Toolkit-independent description of a tray menu item."""

    text: str
    action_id: Optional[str] = None
    enabled: bool = True
    checked: Optional[bool] = None
    is_separator: bool = False
    children: tuple[MenuItemSpec, ...] = ()


STATE_LABELS = {
    "online": "Online",
    "degraded": "Degraded",
    "offline": "Offline",
    "not_installed": "Not Installed",
    "error": "Error",
}


@dataclass(frozen=True)
class TrayModel:
    """State snapshot for the tray app derived from `gateway status --json`."""

    v: int = 1
    checked_at: Optional[str] = None
    device_id: Optional[str] = None
    state: str = "offline"  # online | degraded | offline | not_installed | error
    summary: str = "Gateway status unknown"
    agent: dict[str, Any] = field(default_factory=dict)
    sshd: dict[str, Any] = field(default_factory=dict)
    clients: tuple[ConnectedClient, ...] = ()
    sessions: tuple[SessionInfo, ...] = ()
    errors: tuple[str, ...] = ()

    @classmethod
    def from_status_dict(cls, doc: dict[str, Any]) -> TrayModel:
        clients_raw = doc.get("clients") or []
        clients = tuple(
            ConnectedClient.from_dict(c) for c in clients_raw if isinstance(c, dict)
        )

        sessions_raw = doc.get("sessions") or []
        sessions = tuple(
            SessionInfo.from_dict(s) for s in sessions_raw if isinstance(s, dict)
        )

        errors_raw = doc.get("errors") or []
        errors = tuple(str(e) for e in errors_raw)

        return cls(
            v=int(doc.get("v", 1)),
            checked_at=doc.get("checked_at"),
            device_id=doc.get("device_id"),
            state=str(doc.get("state", "offline")),
            summary=str(doc.get("summary") or "Gateway status unavailable"),
            agent=doc.get("agent") or {},
            sshd=doc.get("sshd") or {},
            clients=clients,
            sessions=sessions,
            errors=errors,
        )

    @classmethod
    def from_error(cls, message: str) -> TrayModel:
        return cls(
            state="error",
            summary=message,
            errors=(message,),
        )

    @property
    def icon_state(self) -> str:
        if self.state in ("online", "degraded", "offline", "not_installed", "error"):
            return self.state
        return "error"

    @property
    def tooltip(self) -> str:
        """Tooltip text per spec: summary (+ 'N connected · M sessions').

        Capped to 127 characters to obey Windows NOTIFYICONDATA buffer bounds.
        """
        n_clients = len(self.clients)
        n_sessions = len(self.sessions)
        suffix = f" ({n_clients} connected · {n_sessions} sessions)"
        max_total = 127
        if len(self.summary) + len(suffix) <= max_total:
            return f"{self.summary}{suffix}"
        allowed_len = max_total - len(suffix) - 3
        if allowed_len > 10:
            return f"{self.summary[:allowed_len]}…{suffix}"
        return (self.summary + suffix)[:max_total]

    @property
    def header_title(self) -> str:
        label = STATE_LABELS.get(self.state, self.state.capitalize())
        return f"PocketShell: {label}"

    @property
    def connected_menu_title(self) -> str:
        return f"Connected now ({len(self.clients)})"

    @property
    def sessions_menu_title(self) -> str:
        return f"Sessions ({len(self.sessions)})"

    @property
    def can_start(self) -> bool:
        """Start is enabled when the gateway is offline, not installed, or in error."""
        return self.state in ("offline", "not_installed", "error")

    @property
    def can_stop(self) -> bool:
        """Stop is enabled when the gateway is running (online or degraded)."""
        return self.state in ("online", "degraded")

    @property
    def can_restart(self) -> bool:
        """Restart is enabled when running or in an error state."""
        return self.state in ("online", "degraded", "error")

    def menu_spec(self, autostart_checked: bool = False) -> tuple[MenuItemSpec, ...]:
        """Produce the full menu structure per spec."""
        items: list[MenuItemSpec] = []

        # 1. Header line with state (disabled)
        items.append(MenuItemSpec(text=self.header_title, enabled=False))

        # 2. "Connected now (N)" submenu
        client_children: list[MenuItemSpec] = []
        if self.clients:
            for client in self.clients:
                client_children.append(
                    MenuItemSpec(text=client.display_line, enabled=False)
                )
        else:
            client_children.append(MenuItemSpec(text="(None)", enabled=False))
        items.append(
            MenuItemSpec(
                text=self.connected_menu_title,
                children=tuple(client_children),
            )
        )

        # 3. "Sessions (M)" submenu
        session_children: list[MenuItemSpec] = []
        if self.sessions:
            for session in self.sessions:
                session_children.append(
                    MenuItemSpec(text=session.display_line, enabled=False)
                )
        else:
            session_children.append(MenuItemSpec(text="(None)", enabled=False))
        items.append(
            MenuItemSpec(
                text=self.sessions_menu_title,
                children=tuple(session_children),
            )
        )

        # 4. Separator
        items.append(MenuItemSpec(text="", is_separator=True))

        # 5. Start / Stop / Restart actions
        items.append(
            MenuItemSpec(
                text="Start gateway",
                action_id="start",
                enabled=self.can_start,
            )
        )
        items.append(
            MenuItemSpec(
                text="Stop gateway",
                action_id="stop",
                enabled=self.can_stop,
            )
        )
        items.append(
            MenuItemSpec(
                text="Restart",
                action_id="restart",
                enabled=self.can_restart,
            )
        )

        # 6. Separator
        items.append(MenuItemSpec(text="", is_separator=True))

        # 7. Utilities
        items.append(
            MenuItemSpec(
                text="Open logs folder",
                action_id="open_logs",
                enabled=True,
            )
        )
        items.append(
            MenuItemSpec(
                text="Copy device id",
                action_id="copy_device_id",
                enabled=bool(self.device_id),
            )
        )
        items.append(
            MenuItemSpec(
                text="Start at login",
                action_id="toggle_autostart",
                enabled=True,
                checked=autostart_checked,
            )
        )

        # 8. Separator & Quit
        items.append(MenuItemSpec(text="", is_separator=True))
        items.append(
            MenuItemSpec(
                text="Quit tray",
                action_id="quit",
                enabled=True,
            )
        )

        return tuple(items)


@dataclass(frozen=True)
class NotificationEvent:
    title: str
    message: str


class NotificationDetector:
    """Detects state changes and new client connections across poll cycles.

    Downward transitions (offline / degraded / error) are debounced: the
    announcement only goes out once the new state has persisted for
    ``debounce_seconds`` across polls, so a single bad poll (a slow broker
    probe, a link process restart between guardian checks) no longer
    produces an "offline" balloon followed by an "online" one. The tray
    icon still tracks the real state on every poll; only the balloons are
    debounced. Recovery to a healthy state is announced immediately, but
    only after the outage itself was announced — a blip that resolved
    inside the window stays completely silent.
    """

    DOWN_STATES = ("offline", "degraded", "error")
    DEBOUNCE_SECONDS = 60.0

    def __init__(
        self,
        *,
        debounce_seconds: float = DEBOUNCE_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._last_state: Optional[str] = None
        self._known_client_keys: Optional[set[str]] = None
        # The last state the user was told about (the first poll counts as
        # announced baseline), the down state waiting out its debounce
        # window, and when that window started.
        self._announced_state: Optional[str] = None
        self._pending_state: Optional[str] = None
        self._pending_since: float = 0.0
        self._debounce_seconds = max(0.0, float(debounce_seconds))
        self._clock = clock

    def update(self, model: TrayModel) -> list[NotificationEvent]:
        events: list[NotificationEvent] = []
        now = self._clock()
        state = model.state

        # 1. Debounced state-transition notification
        if self._last_state is None:
            # Baseline: the first poll sets the reference, never notifies.
            self._announced_state = state
        elif state != self._last_state:
            if state in self.DOWN_STATES:
                # An outage is only announced once it persists; switching
                # between down states keeps the original timer running.
                if self._pending_state is None:
                    self._pending_since = now
                self._pending_state = state
            else:
                self._pending_state = None
                if self._announced_state is not None and state != self._announced_state:
                    events.append(
                        NotificationEvent(
                            title=f"PocketShell Gateway: {STATE_LABELS.get(state, state.capitalize())}",
                            message=model.summary,
                        )
                    )
                self._announced_state = state
        elif (
            self._pending_state is not None
            and state == self._pending_state
            and now - self._pending_since >= self._debounce_seconds
        ):
            events.append(
                NotificationEvent(
                    title=f"PocketShell Gateway: {STATE_LABELS.get(state, state.capitalize())}",
                    message=model.summary,
                )
            )
            self._announced_state = state
            self._pending_state = None
        self._last_state = state

        # 2. New client connection notification
        current_keys = {c.key_identifier for c in model.clients}
        if self._known_client_keys is not None:
            new_keys = current_keys - self._known_client_keys
            for c in model.clients:
                if c.key_identifier in new_keys:
                    comment = f" ({c.key_comment})" if c.key_comment else ""
                    events.append(
                        NotificationEvent(
                            title="New Gateway Connection",
                            message=f"{c.user}{comment} connected",
                        )
                    )
        self._known_client_keys = current_keys

        return events
