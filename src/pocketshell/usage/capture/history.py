"""Capture provider usage into the cache + JSONL history."""
from __future__ import annotations
from collections import deque
from contextlib import contextmanager
import errno
import json
import os
import threading
from pathlib import Path
from typing import Any, Iterator, Optional
# --- sibling modules ---
from pocketshell.usage.capture.durability import _write_private
from pocketshell.usage.capture.paths import DEFAULT_HISTORY_MAX_LINES, DEFAULT_MALFORMED_MAX_LINES, HISTORY_LOCK_FILENAME, NEW_FILE_MODE, UsagePaths, _ensure_dir, _now_iso, resolve_paths
from pocketshell.usage.capture.quarantine import _append_quarantine_locked, _default_malformed_file, _malformed_diagnostic


try:
    import fcntl
except ImportError:  # pragma: no cover - PocketShell's host is POSIX
    fcntl = None  # type: ignore[assignment]


# `flock` is the process boundary; this lock prevents threads in one process
# from racing through the read/trim/publish transaction before they reach the
# kernel lock. The number of usage-state directories is tiny in practice.
_HISTORY_THREAD_LOCKS: dict[str, threading.Lock] = {}


_HISTORY_THREAD_LOCKS_GUARD = threading.Lock()


def _history_thread_lock(history_file: Path) -> threading.Lock:
    lock_path = os.path.abspath(str(history_file.parent / HISTORY_LOCK_FILENAME))
    with _HISTORY_THREAD_LOCKS_GUARD:
        lock = _HISTORY_THREAD_LOCKS.get(lock_path)
        if lock is None:
            lock = threading.Lock()
            _HISTORY_THREAD_LOCKS[lock_path] = lock
        return lock


_UNSUPPORTED_FLOCK_ERRNOS = {
    errno.EINVAL,
    errno.ENOTSUP,
    errno.EOPNOTSUPP,
    errno.ENOSYS,
}


def _acquire_flock(fd: int, history_file: Path) -> None:
    """Take an exclusive flock or refuse the write when it is unsupported."""
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
    except OSError as error:
        if error.errno not in _UNSUPPORTED_FLOCK_ERRNOS:
            raise
        raise RuntimeError(
            "cross-process history locking is unavailable; "
            f"refusing an unsafe usage-history write in {history_file.parent}"
        ) from error


@contextmanager
def _history_writer_lock(history_file: Path) -> Iterator[None]:
    """Serialize a history read/trim/publish transaction across writers."""
    _ensure_dir(history_file.parent)
    lock_path = history_file.parent / HISTORY_LOCK_FILENAME
    thread_lock = _history_thread_lock(history_file)
    with thread_lock:
        if fcntl is None:
            raise RuntimeError(
                "cross-process history locking is unavailable; "
                "refusing an unsafe usage-history write"
            )
        fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, NEW_FILE_MODE)
        try:
            _acquire_flock(fd, history_file)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def _classify_stdout_line(
    line: str, line_number: int
) -> tuple[Optional[dict[str, Any]], Optional[dict[str, Any]]]:
    """Return ``(record, diagnostic)`` — exactly one of the two is set."""
    try:
        parsed = json.loads(line)
    except json.JSONDecodeError:
        return None, _malformed_diagnostic(
            source="capture-stdout",
            line_number=line_number,
            line=line,
            reason="invalid_json",
        )
    if isinstance(parsed, dict):
        return parsed, None
    return None, _malformed_diagnostic(
        source="capture-stdout",
        line_number=line_number,
        line=line,
        reason="line_not_object",
    )


def _quarantine_malformed(
    quarantine_file: Path,
    diagnostics: deque[dict[str, Any]],
    malformed_count: int,
) -> None:
    """Record skipped lines in a bounded sidecar, never silently dropped."""
    with _history_writer_lock(quarantine_file):
        _append_quarantine_locked(
            quarantine_file,
            list(diagnostics),
            dropped_count=malformed_count - len(diagnostics),
        )


def _parse_ndjson_records(
    stdout: str,
    *,
    quarantine_file: Optional[Path] = None,
) -> list[dict[str, Any]]:
    """Parse ``pocketshell usage --json`` NDJSON stdout into a record list.

    Tolerant: skips blank lines and any line that is not a JSON object so a
    stray warning printed to stdout never wedges the capture. When a
    ``quarantine_file`` is supplied, skipped non-blank lines are recorded in a
    bounded sidecar rather than disappearing without evidence.
    """
    records: list[dict[str, Any]] = []
    diagnostics = deque[dict[str, Any]](maxlen=DEFAULT_MALFORMED_MAX_LINES - 1)
    malformed_count = 0

    for line_number, line in enumerate(stdout.splitlines(), start=1):
        if not line.strip():
            continue
        record, diagnostic = _classify_stdout_line(line, line_number)
        if record is not None:
            records.append(record)
        else:
            malformed_count += 1
            diagnostics.append(diagnostic)
    if quarantine_file is not None and malformed_count:
        _quarantine_malformed(quarantine_file, diagnostics, malformed_count)
    return records


def _detect_and_push_resets(
    previous_cache: Optional[dict[str, Any]],
    cache_obj: dict[str, Any],
    paths: UsagePaths,
) -> list[dict[str, Any]]:
    """Best-effort reset detection + FCM push; returns new reset events.

    A bad reading must never wedge the cache write the app's
    stale-while-revalidate render depends on, so any failure is swallowed
    and treated as "no reset events" (the history entry stays plain).
    """
    try:
        # Lazy import avoids the capture <-> reset circular import.
        from pocketshell.usage import reset as _reset

        reset_events = _reset.record_resets(previous_cache, cache_obj, paths=paths)
        if reset_events:
            # Push delivery (#690) is best-effort and fail-soft: a missing
            # credential / token / google-auth never breaks the capture
            # (push_reset_events itself no-ops and never raises).
            from pocketshell import push as _push

            _push.push_reset_events(reset_events, paths=paths)
        return reset_events
    except Exception:
        return []


def _write_cache(
    paths: UsagePaths,
    captured_at: str,
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build + durably persist the cache object; returns it."""
    cache_obj: dict[str, Any] = {
        "captured_at": captured_at,
        "records": records,
    }
    _write_private(paths.cache_file, json.dumps(cache_obj, sort_keys=True) + "\n")
    return cache_obj


def _history_entry(
    cache_obj: dict[str, Any],
    reset_events: list[dict[str, Any]],
) -> dict[str, Any]:
    """The history line payload; reset events ride along when present."""
    if reset_events:
        return {**cache_obj, "reset_events": reset_events}
    return cache_obj


def write_capture(
    stdout: str,
    *,
    paths: Optional[UsagePaths] = None,
    captured_at: Optional[str] = None,
    history_max_lines: int = DEFAULT_HISTORY_MAX_LINES,
) -> dict[str, Any]:
    """Persist a fresh capture: write the cache + append to history.

    ``stdout`` is the raw NDJSON ``pocketshell usage --json`` output. Returns
    the cache object that was written (also useful for the ``--capture``
    command to emit so the operator/cron can see what landed).
    """
    if paths is None:
        paths = resolve_paths()
    captured_at = captured_at or _now_iso()
    records = _parse_ndjson_records(stdout, quarantine_file=paths.malformed_file)

    # Read the PREVIOUS cached reading BEFORE we overwrite it, so reset
    # detection (#690) can compare the current reading to the last one.
    previous_cache = read_cache(paths)
    cache_obj = _write_cache(paths, captured_at, records)

    reset_events = _detect_and_push_resets(previous_cache, cache_obj, paths)
    _append_history(
        paths.history_file,
        _history_entry(cache_obj, reset_events),
        history_max_lines=history_max_lines,
    )
    return cache_obj


def _classify_history_line(
    raw_line: str,
) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    """``(parsed, None)`` for a valid JSON object, else ``(None, reason)``."""
    try:
        parsed = json.loads(raw_line)
    except json.JSONDecodeError:
        return None, "invalid_json"
    if isinstance(parsed, dict):
        return parsed, None
    return None, "line_not_object"


def _scan_existing_history(
    history_file: Path,
    existing: deque[str] | list[str],
    malformed: deque[dict[str, Any]],
) -> int:
    """Fold valid lines into ``existing``, park bad ones in quarantine.

    Returns the total malformed count (may exceed ``len(malformed)`` —
    the quarantine deque is bounded).
    """
    malformed_count = 0
    try:
        history_stream = history_file.open("r", encoding="utf-8")
    except FileNotFoundError:
        return 0
    with history_stream:
        for line_number, raw_line in enumerate(history_stream, start=1):
            raw_line = raw_line.rstrip("\r\n")
            if not raw_line.strip():
                continue
            parsed, reason = _classify_history_line(raw_line)
            if parsed is not None:
                existing.append(raw_line)
                continue
            malformed_count += 1
            malformed.append(_malformed_diagnostic(
                source=history_file.name, line_number=line_number,
                line=raw_line, reason=reason,
            ))
    return malformed_count


def _existing_buffer(history_max_lines: int) -> deque[str] | list[str]:
    """Bounded tail buffer when a line cap is set, else an unbounded list."""
    if history_max_lines > 0:
        return deque(maxlen=history_max_lines)
    return []


def _append_history(
    history_file: Path,
    entry: dict[str, Any],
    *,
    history_max_lines: int,
    quarantine_file: Optional[Path] = None,
) -> None:
    """Append ``entry`` as one JSON line, then trim to the line cap.

    At ~1 capture/hour the file is tiny, so a full read+rewrite per append
    is cheap and avoids an external logrotate dependency. The whole
    read/trim/publish transaction is held under the per-directory writer
    lock, so concurrent captures cannot lose a valid line or publish a
    mixed update. Existing malformed lines are quarantined first.
    """
    quarantine_file = quarantine_file or _default_malformed_file(history_file)
    with _history_writer_lock(history_file):
        existing = _existing_buffer(history_max_lines)
        malformed = deque[dict[str, Any]](maxlen=DEFAULT_MALFORMED_MAX_LINES - 1)
        malformed_count = _scan_existing_history(history_file, existing, malformed)

        if malformed:
            _append_quarantine_locked(
                quarantine_file,
                list(malformed),
                dropped_count=malformed_count - len(malformed),
            )

        existing.append(json.dumps(entry, sort_keys=True))
        _write_private(history_file, "\n".join(existing) + "\n")


def read_cache(paths: Optional[UsagePaths] = None) -> Optional[dict[str, Any]]:
    """Return the cached latest reading, or ``None`` if absent/unreadable."""
    if paths is None:
        paths = resolve_paths()
    cache_file = paths.cache_file
    if not cache_file.exists():
        return None
    try:
        parsed = json.loads(cache_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


def cached_document(paths: Optional[UsagePaths] = None) -> Optional[str]:
    """Return the cached reading as the app-facing JSON document.

    Unlike the live ``pocketshell usage --json`` path (which emits NDJSON,
    one provider per line), the cached read emits a SINGLE JSON object
    ``{"captured_at": ..., "records": [...]}``. The app reads this for an
    instant cached-first render: ``captured_at`` powers the "last captured
    at <time>" label and ``records`` are the same provider objects the live
    NDJSON carries. Returns ``None`` when there is no cache yet.
    """
    cache = read_cache(paths)
    if cache is None:
        return None
    records = cache.get("records")
    if not isinstance(records, list):
        records = []
    captured_at = cache.get("captured_at")
    return (
        json.dumps(
            {"captured_at": captured_at, "records": records},
            sort_keys=True,
        )
        + "\n"
    )
