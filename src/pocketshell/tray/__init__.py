"""PocketShell background system tray application package."""

from __future__ import annotations

__all__ = ["TrayModel", "TrayApp"]


def __getattr__(name: str):
    if name == "TrayModel":
        from pocketshell.tray.model import TrayModel

        return TrayModel
    if name == "TrayApp":
        from pocketshell.tray.app import TrayApp

        return TrayApp
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
