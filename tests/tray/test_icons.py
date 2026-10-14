"""Tests for tray icon generation."""

from __future__ import annotations

import pytest

# Pillow ships only with the optional `tray` extra; CI installs `link` only.
Image = pytest.importorskip("PIL.Image")

from pocketshell.tray.icons import _STATE_COLORS, generate_tray_icon


@pytest.mark.parametrize("state", ["online", "degraded", "offline", "not_installed", "error"])
def test_generate_tray_icon_states(state):
    img = generate_tray_icon(state)
    assert isinstance(img, Image.Image)
    assert img.size == (64, 64)
    assert img.mode == "RGBA"


def test_generate_tray_icon_caching():
    img1 = generate_tray_icon("online", size=64)
    img2 = generate_tray_icon("online", size=64)
    assert img1 is img2

    # Different size produces different object
    img3 = generate_tray_icon("online", size=32)
    assert img3.size == (32, 32)
    assert img3 is not img1


def test_generate_tray_icon_fallback_to_error():
    img = generate_tray_icon("unrecognized_state")
    assert isinstance(img, Image.Image)
    assert img.size == (64, 64)


def test_icon_dot_has_state_color():
    for state, color in _STATE_COLORS.items():
        img = generate_tray_icon(state, size=64)
        # Dot center is around (48, 48)
        px = img.getpixel((48, 48))
        assert px == color
