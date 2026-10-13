"""Pytest fixtures for tray app tests."""

from __future__ import annotations

import os
import sys

import pytest


@pytest.fixture(autouse=True)
def ensure_display_for_headless_linux(monkeypatch):
    """Ensure DISPLAY is present on Linux so pystray can import its backend."""
    if sys.platform.startswith("linux") and not os.environ.get("DISPLAY"):
        monkeypatch.setenv("DISPLAY", ":99")
