"""In-code system tray icon generation using Pillow.

Draws a terminal glyph with a colored status dot indicating the gateway state:
- online: green
- degraded: amber
- offline: red
- not_installed: grey
- error: red
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from PIL import Image

_ICON_CACHE: dict[tuple[str, int], Any] = {}

# RGB(A) color definitions
_STATE_COLORS: dict[str, tuple[int, int, int, int]] = {
    "online": (34, 197, 94, 255),       # #22c55e green
    "degraded": (245, 158, 11, 255),    # #f59e0b amber
    "offline": (239, 68, 68, 255),      # #ef4444 red
    "not_installed": (156, 163, 175, 255),  # #9ca3af grey
    "error": (239, 68, 68, 255),        # #ef4444 red
}


def generate_tray_icon(state: str, size: int = 64) -> Image.Image:
    """Generate or retrieve a cached PIL Image for the given gateway state."""
    cache_key = (state, size)
    if cache_key in _ICON_CACHE:
        return _ICON_CACHE[cache_key]

    from PIL import Image, ImageDraw

    # Create transparent canvas
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # 1. Terminal window background (dark rounded rectangle)
    # Scale coordinates to `size`
    scale = size / 64.0
    pad = int(4 * scale)
    corner_radius = max(2, int(8 * scale))

    term_box = (pad, pad, size - pad, size - pad)
    term_bg = (24, 24, 37, 255)       # dark slate background
    term_border = (69, 71, 90, 255)   # border outline

    draw.rounded_rectangle(
        term_box,
        radius=corner_radius,
        fill=term_bg,
        outline=term_border,
        width=max(1, int(2 * scale)),
    )

    # 2. Terminal prompt symbol: `>`
    p1 = (int(14 * scale), int(20 * scale))
    p2 = (int(25 * scale), int(30 * scale))
    p3 = (int(14 * scale), int(40 * scale))
    prompt_color = (205, 214, 244, 255)  # light off-white
    draw.line([p1, p2, p3], fill=prompt_color, width=max(2, int(3 * scale)), joint="miter")

    # 3. Terminal cursor: `_`
    c_start = (int(28 * scale), int(39 * scale))
    c_end = (int(39 * scale), int(39 * scale))
    cursor_color = (166, 173, 200, 255)  # muted light
    draw.line([c_start, c_end], fill=cursor_color, width=max(2, int(3 * scale)))

    # 4. Status dot in bottom-right corner
    dot_color = _STATE_COLORS.get(state, _STATE_COLORS["error"])
    dot_border_color = (17, 17, 27, 255)  # dark ring for high contrast

    # Center around (48, 48) on a 64-grid
    dot_center_x = int(48 * scale)
    dot_center_y = int(48 * scale)
    dot_radius = int(11 * scale)

    dot_bbox = (
        dot_center_x - dot_radius,
        dot_center_y - dot_radius,
        dot_center_x + dot_radius,
        dot_center_y + dot_radius,
    )

    # Outer border ring for contrast against terminal background
    draw.ellipse(
        dot_bbox,
        fill=dot_color,
        outline=dot_border_color,
        width=max(1, int(2 * scale)),
    )

    _ICON_CACHE[cache_key] = img
    return img
