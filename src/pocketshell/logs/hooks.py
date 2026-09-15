"""One-way bridge from the hooks event bus into the log store."""
from __future__ import annotations
import json
import os
from typing import Any, Optional
# --- sibling modules ---
from pocketshell.logs.events import ingest_event
from pocketshell.logs.paths import LogsPaths, NEW_FILE_MODE


def _read_cursor(paths: LogsPaths) -> int:
    if not paths.cursor_file.exists():
        return 0
    try:
        return int(paths.cursor_file.read_text(encoding="utf-8").strip() or "0")
    except (ValueError, OSError):
        return 0


def _write_cursor(paths: LogsPaths, offset: int) -> None:
    paths.logs_dir.mkdir(parents=True, exist_ok=True)
    if paths.cursor_file.exists():
        paths.cursor_file.write_text(str(offset), encoding="utf-8")
        return
    fd = os.open(str(paths.cursor_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, NEW_FILE_MODE)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(str(offset))


def _hook_record_to_event(rec: dict[str, Any], *, target_host: Optional[str]) -> dict[str, Any]:
    """Map a #267 hooks-bus record into a canonical engine_event.

    The hooks bus emits ``{ts, engine, state, source, session_id, cwd,
    ...}``. We carry those through, tag ``kind=engine_event`` and
    ``source=cli`` (the dev box produced it), set ``action`` to the
    engine state for greppability, and attach ``target_host`` (the
    canonical host) so every event has one. The full original payload is
    preserved under ``detail`` for debugging.
    """
    event: dict[str, Any] = {
        "ts": rec.get("ts"),
        "kind": "engine_event",
        "source": "cli",
        "engine": rec.get("engine"),
        "state": rec.get("state"),
        "action": rec.get("state") or "engine_event",
        "session_id": rec.get("session_id"),
        "cwd": rec.get("cwd"),
        "target_host": target_host,
        "result": "ok",
        "detail": rec,
    }
    return event


def _consumable_chunk(data: bytes, cursor: int) -> Optional[tuple[int, bytes]]:
    """``(adjusted_start, complete_bytes)`` to consume, or ``None``.

    A cursor past the end means the bus was truncated/rotated under us —
    restart from the top. Consumption stops at the last newline so a
    half-written final line is left for the next run.
    """
    start = cursor if cursor <= len(data) else 0
    chunk = data[start:]
    last_nl = chunk.rfind(b"\n")
    if last_nl == -1:
        return None
    return start, chunk[: last_nl + 1]


def _forward_records(
    paths: LogsPaths,
    consumable: bytes,
    *,
    target_host: Optional[str],
) -> int:
    """Ingest each complete JSON line as an engine_event; return the count."""
    forwarded = 0
    for raw_line in consumable.decode("utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(rec, dict):
            continue
        event = _hook_record_to_event(rec, target_host=target_host)
        ingest_event(paths, event, default_source="cli")
        forwarded += 1
    return forwarded


def import_hooks(paths: LogsPaths, *, target_host: Optional[str]) -> int:
    """Drain new hooks-bus lines into the canonical logs as engine_events.

    Idempotent: only bus bytes after the persisted cursor are read, and
    the cursor advances to the end of the last *complete* line consumed.
    Returns the number of engine events forwarded this run (0 on a
    re-run with no new bus activity).
    """
    bus = paths.hooks_events_file
    if not bus.exists():
        return 0

    data = bus.read_bytes()
    located = _consumable_chunk(data, _read_cursor(paths))
    if located is None:
        return 0

    start, consumable = located
    forwarded = _forward_records(paths, consumable, target_host=target_host)
    _write_cursor(paths, start + len(consumable))
    return forwarded
