"""Make server-provided strings safe to show in a terminal.

The broker (and anything between us and it) is not trusted to send benign
text. A label, email, user code or error code containing ESC sequences could
rewrite the terminal (fake prompts, hidden text, OSC-52 clipboard writes,
title changes), and bidi/zero-width format characters could disguise a URL.
Everything a server returns goes through :func:`clean_text` before it is
printed, and URLs we print or open must pass :func:`https_url`.
"""

from __future__ import annotations

import unicodedata
from urllib.parse import urlsplit

_MAX_URL = 2048


def clean_text(value: object, *, max_len: int = 200) -> str:
    """Strip control/format/unassigned characters and cap the length.

    Drops every Unicode ``C*`` category (Cc controls incl. ESC/CR/LF/TAB,
    Cf format incl. bidi overrides and zero-width joiners, Cs, Co, Cn) plus
    line/paragraph separators. Non-strings render as ``""``.
    """
    if not isinstance(value, str):
        return ""
    kept = [
        ch
        for ch in value
        if not unicodedata.category(ch).startswith("C")
        and unicodedata.category(ch) not in ("Zl", "Zp")
    ]
    text = "".join(kept).strip()
    if len(text) > max_len:
        text = text[: max_len - 3] + "..."
    return text


def https_url(value: object) -> str | None:
    """Return ``value`` if it is a plain, printable ``https://host/...`` URL.

    Anything else (non-string, non-ASCII, whitespace or control characters,
    another scheme, userinfo, no host, over-long) returns ``None``. The URL is
    returned unchanged, so what we print is exactly what we validated.
    """
    if not isinstance(value, str) or not value or len(value) > _MAX_URL:
        return None
    if any(not (0x21 <= ord(ch) <= 0x7E) for ch in value):
        return None
    try:
        parts = urlsplit(value)
        host = parts.hostname
        parts.port  # noqa: B018 - raises ValueError on a malformed port
    except ValueError:
        return None
    if parts.scheme != "https" or not host or "@" in parts.netloc:
        return None
    return value
