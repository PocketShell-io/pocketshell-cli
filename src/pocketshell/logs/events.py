"""Normalise, append, and read the phone/agent event logs."""
from __future__ import annotations
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
# --- sibling modules ---
from pocketshell.logs.paths import KNOWN_KINDS, KNOWN_SOURCES, LogsPaths, NEW_FILE_MODE, SCHEMA_VERSION
from pocketshell.logs.redact import redact


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _day_from_ts(ts: str) -> str:
    """Return the ``YYYYMMDD`` UTC day for an ISO-8601 ``ts``.

    Falls back to *today* (UTC) when ``ts`` cannot be parsed, so a record
    is never dropped just because its timestamp is odd.
    """
    try:
        parsed = datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return datetime.now(timezone.utc).strftime("%Y%m%d")
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc)
    return parsed.strftime("%Y%m%d")


def _normalize_result(event: dict[str, Any]) -> None:
    """Coerce ``result`` to ``ok``/``error`` when present."""
    result = event.get("result")
    if result is not None and result not in ("ok", "error"):
        event["result"] = "error" if str(result).lower() in ("err", "fail", "failed") else "ok"


def _normalize_fields(event: dict[str, Any], *, default_source: str) -> None:
    """Force ``ts``/``schema``/``source``/``kind``/``result`` in place.

    Missing/unknown ``source`` and ``kind`` fall back to greppable defaults
    so a malformed event still lands somewhere rather than being dropped.
    """
    ts = event.get("ts")
    event["ts"] = ts if isinstance(ts, str) and ts.strip() else _now_iso()
    event["schema"] = SCHEMA_VERSION

    source = event.get("source")
    event["source"] = source if source in KNOWN_SOURCES else default_source

    kind = event.get("kind")
    event["kind"] = kind if kind in KNOWN_KINDS else "agent_action"
    _normalize_result(event)


def normalize_event(raw: dict[str, Any], *, default_source: str = "phone") -> dict[str, Any]:
    """Normalize an ingested event dict into the canonical schema.

    Stamps ``ts`` (ISO-8601 UTC) when absent and ``schema`` =
    :data:`SCHEMA_VERSION`; defaults ``source``/``kind``; coerces
    ``result`` to ``ok``/``error``. The caller's other keys are preserved
    (e.g. ``engine``, ``state``, ``session_id``). Redaction is the final
    step, deny-by-default, so *nothing* written to disk can carry a
    secret value.
    """
    event = dict(raw)
    _normalize_fields(event, default_source=default_source)
    return redact(event)


def _append_jsonl(path: Path, record: dict[str, Any]) -> None:
    """Append one JSON record as a line to ``path`` (mode 0600 on create).

    The parent dir is created if needed. A pre-existing file keeps its
    perms; a freshly-created file is opened ``0600`` before any bytes are
    written.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, sort_keys=True) + "\n"
    if path.exists():
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line)
        return
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, NEW_FILE_MODE)
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        handle.write(line)


def ingest_event(
    paths: LogsPaths,
    raw: dict[str, Any],
    *,
    default_source: str = "phone",
) -> dict[str, Any]:
    """Normalize + redact ``raw`` and append it to the right dated file.

    Returns the normalized record that was written (already redacted) so
    callers/tests can assert on it without re-reading the file.
    """
    record = normalize_event(raw, default_source=default_source)
    day = _day_from_ts(record["ts"])
    target = paths.file_for_kind(record["kind"], day)
    _append_jsonl(target, record)
    return record


def read_records(paths: LogsPaths, family: str, *, limit: Optional[int] = None) -> list[dict[str, Any]]:
    """Read records for a log ``family`` (``agent``/``app``), oldest first.

    Reads every dated file for the family in chronological order and
    concatenates their records. ``limit`` keeps only the last N records
    (most recent). Malformed/blank lines are skipped.
    """
    records: list[dict[str, Any]] = []
    for path in paths.files_for_family(family):
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(obj, dict):
                records.append(obj)
    if limit is not None and limit >= 0:
        records = records[-limit:]
    return records
