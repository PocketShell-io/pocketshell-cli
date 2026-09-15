"""Park malformed history lines for later diagnosis."""
from __future__ import annotations
from collections import deque
import json
from pathlib import Path
from typing import Any
# --- sibling modules ---
from pocketshell.usage_capture.durability import _write_private
from pocketshell.usage_capture.paths import DEFAULT_MALFORMED_MAX_LINES, HISTORY_FILENAME, MALFORMED_HISTORY_FILENAME, MAX_MALFORMED_LINE_LENGTH, _ensure_dir


def _truncate_malformed_line(line: str) -> str:
    if len(line) <= MAX_MALFORMED_LINE_LENGTH:
        return line
    return line[:MAX_MALFORMED_LINE_LENGTH] + "…[truncated]"


def _malformed_diagnostic(
    *, source: str, line_number: int, line: str, reason: str
) -> dict[str, Any]:
    return {
        "source": source,
        "line_number": line_number,
        "reason": reason,
        "raw_line": _truncate_malformed_line(line),
    }


def _default_malformed_file(history_file: Path) -> Path:
    if history_file.name == HISTORY_FILENAME:
        return history_file.with_name(MALFORMED_HISTORY_FILENAME)
    return history_file.with_name(history_file.name + ".malformed.jsonl")


def _retained_existing_diagnostic(
    quarantine_file: Path, line_number: int, raw_line: str
) -> dict[str, Any]:
    """Normalise one existing sidecar line into a bounded diagnostic item."""
    try:
        parsed = json.loads(raw_line)
    except json.JSONDecodeError:
        return _malformed_diagnostic(
            source=quarantine_file.name,
            line_number=line_number,
            line=raw_line,
            reason="invalid_diagnostic_json",
        )
    if not isinstance(parsed, dict):
        return _malformed_diagnostic(
            source=quarantine_file.name,
            line_number=line_number,
            line=raw_line,
            reason="diagnostic_not_object",
        )
    item = dict(parsed)
    raw_value = item.get("raw_line")
    if isinstance(raw_value, str):
        item["raw_line"] = _truncate_malformed_line(raw_value)
    return item


def _read_existing_diagnostics(
    quarantine_file: Path, retained: deque[dict[str, Any]]
) -> int:
    """Fold existing sidecar entries into ``retained``; return their count.

    The sidecar is itself bounded, so retain only the tail while reading it.
    This keeps a manually corrupted or very old sidecar from turning the
    next capture into an unbounded read/alloc.
    """
    existing_count = 0
    try:
        diagnostic_stream = quarantine_file.open("r", encoding="utf-8")
    except FileNotFoundError:
        return 0
    with diagnostic_stream:
        for line_number, raw_line in enumerate(diagnostic_stream, start=1):
            raw_line = raw_line.rstrip("\r\n")
            if not raw_line.strip():
                continue
            retained.append(
                _retained_existing_diagnostic(quarantine_file, line_number, raw_line)
            )
            existing_count += 1
    return existing_count


def _bounded_retained_list(
    retained: deque[dict[str, Any]],
    *,
    total_count: int,
) -> list[dict[str, Any]]:
    """Trim to the cap, prefixing a truncation marker when items were dropped."""
    cap = DEFAULT_MALFORMED_MAX_LINES - 1
    retained_list = list(retained)[-cap:]
    if total_count > cap:
        marker = {
            "source": "pocketshell.usage_capture",
            "reason": "diagnostics_truncated",
            "dropped": total_count - cap,
        }
        retained_list = [marker, *retained_list]
    return retained_list


def _append_quarantine_locked(
    quarantine_file: Path,
    diagnostics: list[dict[str, Any]],
    *,
    dropped_count: int = 0,
) -> None:
    """Append bounded diagnostic objects while the parent state lock is held.

    ``diagnostics`` is already the retained tail when the caller processed a
    large input. ``dropped_count`` carries the count of older diagnostics so
    the sidecar can retain an honest truncation marker without first building
    an unbounded list.
    """
    if not diagnostics:
        return
    _ensure_dir(quarantine_file.parent)
    retained = deque[dict[str, Any]](maxlen=DEFAULT_MALFORMED_MAX_LINES - 1)
    existing_count = _read_existing_diagnostics(quarantine_file, retained)
    all_count = existing_count + dropped_count + len(diagnostics)
    retained.extend(diagnostics)
    retained_list = _bounded_retained_list(retained, total_count=all_count)
    _write_private(
        quarantine_file,
        "\n".join(json.dumps(item, sort_keys=True, ensure_ascii=False) for item in retained_list)
        + "\n",
    )
