"""Direct entry point for PocketShell tray application."""

from __future__ import annotations

import sys

from pocketshell.tray.cli import tray_command

if __name__ == "__main__":
    sys.exit(tray_command())
