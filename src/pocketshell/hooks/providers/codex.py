"""Merge-style install/uninstall of the notify program in Codex config.toml."""
from __future__ import annotations
import json
import re
from typing import Optional, Sequence


# Match a top-level ``notify = [...]`` assignment. Top-level means it
# appears before the first ``[table]`` header. We only ever touch the
# first such line.
_NOTIFY_LINE_RE = re.compile(r"^\s*notify\s*=", re.MULTILINE)


_TABLE_HEADER_RE = re.compile(r"^\s*\[", re.MULTILINE)


def _toml_value(value: Sequence[str]) -> str:
    """Render a list-of-strings as a TOML inline array."""
    parts = ", ".join(json.dumps(item) for item in value)
    return f"[{parts}]"


def _find_top_level_notify(text: str) -> Optional[tuple[int, int]]:
    """Return ``(start, end)`` span of the top-level ``notify`` line.

    The span covers the whole physical line (without its trailing
    newline). Returns ``None`` if no top-level ``notify`` assignment
    exists. A ``notify`` that only appears inside a ``[table]`` is
    ignored (Codex's ``notify`` is a top-level key).
    """
    first_table = _TABLE_HEADER_RE.search(text)
    table_pos = first_table.start() if first_table else len(text)
    match = _NOTIFY_LINE_RE.search(text)
    if match is None or match.start() >= table_pos:
        return None
    line_start = text.rfind("\n", 0, match.start()) + 1
    line_end = text.find("\n", match.start())
    if line_end == -1:
        line_end = len(text)
    return line_start, line_end


def _extract_notify_command(line: str) -> Optional[list[str]]:
    """Best-effort parse of the array on a ``notify = [...]`` line.

    Uses ``tomllib`` on just that line. Returns ``None`` when it cannot
    be parsed as a list of strings.
    """
    import tomllib

    try:
        parsed = tomllib.loads(line)
    except tomllib.TOMLDecodeError:
        return None
    value = parsed.get("notify")
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    return None


def _merge_existing_notify(
    text: str,
    span: tuple[int, int],
    *,
    notify_value: Sequence[str],
    notify_line: str,
    replace_values: Sequence[Sequence[str]],
) -> tuple[str, str]:
    """Decide among ``present`` / ``migrated`` / ``skipped`` for an existing
    top-level ``notify`` line occupying ``span``."""
    start, end = span
    existing = _extract_notify_command(text[start:end])
    if existing == list(notify_value):
        return text, "present"
    if any(existing == list(old_value) for old_value in replace_values):
        return text[:start] + notify_line + text[end:], "migrated"
    return text, "skipped"


def codex_install(
    text: str,
    notify_value: Sequence[str],
    *,
    replace_values: Sequence[Sequence[str]] = (),
) -> tuple[str, str]:
    """Merge our ``notify`` into Codex config ``text``.

    Returns ``(new_text, status)``: ``"added"`` (no ``notify`` existed),
    ``"present"`` (already ours — idempotent no-op), ``"migrated"`` (an
    explicitly listed old PocketShell value was replaced), or ``"skipped"``
    (``notify`` is set to *something else* — never clobber the user's
    program). All other TOML content is preserved.
    """
    span = _find_top_level_notify(text)
    notify_line = f"notify = {_toml_value(notify_value)}"

    if span is None:
        # Prepend our notify line, keeping the rest of the document
        # intact. A leading newline is fine for TOML; existing content
        # follows unchanged.
        return notify_line + "\n" + text, "added"

    return _merge_existing_notify(
        text,
        span,
        notify_value=notify_value,
        notify_line=notify_line,
        replace_values=replace_values,
    )


def codex_uninstall(text: str, notify_value: Sequence[str]) -> tuple[str, str]:
    """Remove our ``notify`` line from Codex config ``text``.

    Returns ``(new_text, status)`` where ``status`` is one of
    ``"removed"`` (our line was present and dropped), ``"absent"`` (no
    top-level ``notify``), or ``"skipped"`` (a ``notify`` set to
    something else — left untouched). Idempotent.
    """
    span = _find_top_level_notify(text)
    if span is None:
        return text, "absent"
    start, end = span
    existing = _extract_notify_command(text[start:end])
    if existing != list(notify_value):
        return text, "skipped"
    # Drop the whole line including its trailing newline (if any).
    drop_end = end + 1 if end < len(text) and text[end] == "\n" else end
    return text[:start] + text[drop_end:], "removed"
