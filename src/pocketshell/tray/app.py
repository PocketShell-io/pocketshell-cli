"""System tray application runner with pystray integration."""

from __future__ import annotations

import logging
import threading
from typing import Any, Callable, Optional

from pocketshell.tray.autostart import install_autostart, is_autostart_installed, remove_autostart
from pocketshell.tray.icons import generate_tray_icon
from pocketshell.tray.model import MenuItemSpec, NotificationDetector, TrayModel
from pocketshell.tray.status_client import (
    GatewayStatusClient,
    copy_to_clipboard,
    open_logs_folder,
)

logger = logging.getLogger(__name__)


class TrayApp:
    """Manages the background system tray icon, menu, polling, and notifications."""

    def __init__(
        self,
        status_client: Optional[GatewayStatusClient] = None,
        poll_interval: float = 5.0,
        initial_model: Optional[TrayModel] = None,
        autostart_checker: Optional[Callable[[], bool]] = None,
        autostart_installer: Optional[Callable[[], tuple[bool, str]]] = None,
        autostart_remover: Optional[Callable[[], tuple[bool, str]]] = None,
    ) -> None:
        self.status_client = status_client or GatewayStatusClient()
        self.poll_interval = max(1.0, float(poll_interval))
        self.model = initial_model or TrayModel()
        self.notification_detector = NotificationDetector()

        self._autostart_checker = autostart_checker or is_autostart_installed
        self._autostart_installer = autostart_installer or install_autostart
        self._autostart_remover = autostart_remover or remove_autostart

        self._autostart_checked = False
        try:
            self._autostart_checked = self._autostart_checker()
        except Exception as exc:
            logger.debug("Failed to check autostart status: %s", exc)

        self._stop_event = threading.Event()
        self._poll_thread: Optional[threading.Thread] = None
        self._icon: Any = None

    def poll_once(self) -> TrayModel:
        """Fetch fresh status and update UI state and notifications."""
        new_model = self.status_client.fetch_status()
        self.model = new_model

        # Check for state transitions and new client connections
        events = self.notification_detector.update(new_model)
        for event in events:
            self.notify(event.message, event.title)

        # Refresh tray icon and menu if running
        self._refresh_icon()
        return new_model

    def notify(self, message: str, title: str = "PocketShell Gateway") -> None:
        """Display a system tray balloon notification."""
        if self._icon and hasattr(self._icon, "notify"):
            try:
                self._icon.notify(message, title)
            except Exception as exc:
                logger.debug("Tray notification failed: %s", exc)

    def _refresh_icon(self) -> None:
        if not self._icon:
            return
        try:
            self._icon.icon = generate_tray_icon(self.model.icon_state)
            self._icon.title = self.model.tooltip
            self._icon.menu = self._build_pystray_menu()
            if hasattr(self._icon, "update_menu"):
                self._icon.update_menu()
        except Exception as exc:
            logger.debug("Failed to refresh tray icon: %s", exc)

    def _build_pystray_menu(self) -> Any:
        import pystray

        specs = self.model.menu_spec(autostart_checked=self._autostart_checked)
        items = [self._convert_spec_to_pystray(spec) for spec in specs]
        return pystray.Menu(*items)

    def _convert_spec_to_pystray(self, spec: MenuItemSpec) -> Any:
        import pystray

        if spec.is_separator:
            return pystray.Menu.SEPARATOR

        if spec.children:
            sub_items = [self._convert_spec_to_pystray(child) for child in spec.children]
            return pystray.MenuItem(spec.text, pystray.Menu(*sub_items), enabled=spec.enabled)

        action = self._resolve_action(spec.action_id)
        checked_fn = (lambda item: self._autostart_checked) if spec.checked is not None else None
        return pystray.MenuItem(
            spec.text,
            action,
            enabled=spec.enabled,
            checked=checked_fn,
        )

    def _resolve_action(self, action_id: Optional[str]) -> Optional[Callable[..., None]]:
        if not action_id:
            return None

        actions: dict[str, Callable[[], None]] = {
            "start": lambda: self._spawn(self.do_start),
            "stop": lambda: self._spawn(self.do_stop),
            "restart": lambda: self._spawn(self.do_restart),
            "open_logs": lambda: self._spawn(self.do_open_logs),
            "copy_device_id": lambda: self._spawn(self.do_copy_device_id),
            "toggle_autostart": lambda: self._spawn(self.do_toggle_autostart),
            "quit": self.quit,
        }
        fn = actions.get(action_id)
        if not fn:
            return None
        return lambda icon, item: fn()

    def _spawn(self, target: Callable[[], None]) -> None:
        """Run an action in a background worker thread to keep the tray UI responsive."""
        thread = threading.Thread(target=target, daemon=True)
        thread.start()

    def do_start(self) -> None:
        logger.info("Starting gateway...")
        self.status_client.start_gateway()
        self.poll_once()

    def do_stop(self) -> None:
        logger.info("Stopping gateway...")
        self.status_client.stop_gateway()
        self.poll_once()

    def do_restart(self) -> None:
        logger.info("Restarting gateway...")
        self.status_client.restart_gateway()
        self.poll_once()

    def do_open_logs(self) -> None:
        open_logs_folder()

    def do_copy_device_id(self) -> None:
        if self.model.device_id:
            copy_to_clipboard(self.model.device_id)

    def do_toggle_autostart(self) -> None:
        if self._autostart_checked:
            ok, _ = self._autostart_remover()
            if ok:
                self._autostart_checked = False
        else:
            ok, _ = self._autostart_installer()
            if ok:
                self._autostart_checked = True
        self._refresh_icon()

    def _poll_worker(self) -> None:
        """Periodic status polling loop."""
        while not self._stop_event.is_set():
            try:
                self.poll_once()
            except Exception as exc:
                logger.error("Status polling failed: %s", exc)
            self._stop_event.wait(self.poll_interval)

    def run(self) -> None:
        """Start the background poll thread and run the pystray main loop."""
        import pystray

        # Initial poll to populate model
        try:
            self.model = self.status_client.fetch_status()
            self.notification_detector.update(self.model)
        except Exception as exc:
            self.model = TrayModel.from_error(f"Initial status fetch error: {exc}")

        # Initialize pystray Icon
        icon_img = generate_tray_icon(self.model.icon_state)
        self._icon = pystray.Icon(
            name="PocketShell",
            icon=icon_img,
            title=self.model.tooltip,
            menu=self._build_pystray_menu(),
        )

        # Launch background poller
        self._stop_event.clear()
        self._poll_thread = threading.Thread(target=self._poll_worker, daemon=True)
        self._poll_thread.start()

        try:
            self._icon.run()
        finally:
            self._stop_event.set()

    def quit(self) -> None:
        """Stop polling and close the tray icon."""
        self._stop_event.set()
        if self._icon:
            self._icon.stop()
