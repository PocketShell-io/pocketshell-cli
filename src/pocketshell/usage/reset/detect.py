"""Pure reset detection: compare two cached readings, emit reset events.

No I/O — :func:`detect_resets` takes the previous and current cache objects
(and the set of already-known ``reset_key`` values for cross-run de-dup)
and returns the new event dicts. Persistence lives in
:mod:`pocketshell.usage.reset.store`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

# Minimum jump (percentage points) in ``percent_remaining`` for the
# "usage dropped back toward baseline" reset signal. A real window reset
# restores most/all of the budget, so 30 points comfortably separates a
# reset from normal hour-to-hour noise (a heavy hour rarely *recovers* 30
# points without a reset).
RESET_RECOVERY_THRESHOLD = 30.0


def _parse_iso(value: Any) -> Optional[datetime]:
    """Parse an ISO-8601 UTC timestamp (``...Z``) into an aware datetime."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _window_obj(record: Any, window: str) -> Optional[dict[str, Any]]:
    """Return the record's window object for ``window`` (a ``windows``-map
    key), or ``None`` when absent / not an object."""
    if not isinstance(record, dict):
        return None
    windows = record.get("windows")
    if not isinstance(windows, dict):
        return None
    obj = windows.get(window)
    return obj if isinstance(obj, dict) else None


def _window_names(record: Any) -> list[str]:
    """The window labels present on a record's unified ``windows`` map."""
    if not isinstance(record, dict):
        return []
    windows = record.get("windows")
    if not isinstance(windows, dict):
        return []
    return [name for name, obj in windows.items() if isinstance(obj, dict)]


def _records_by_provider(cache: Optional[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Index a cache object's records by provider name (lower-cased)."""
    out: dict[str, dict[str, Any]] = {}
    if not isinstance(cache, dict):
        return out
    records = cache.get("records")
    if not isinstance(records, list):
        return out
    for record in records:
        if not isinstance(record, dict):
            continue
        provider = record.get("provider")
        if isinstance(provider, str) and provider.strip():
            out[provider.strip().lower()] = record
    return out


def _recovery_signal(previous: dict[str, Any], current: dict[str, Any]) -> bool:
    """Signal 1: usage dropped back toward baseline (large recovery).

    A fresh limit window resets the meter, so a large recovery is the
    strongest signal a reset happened.
    """
    prev_pct = previous.get("percent_remaining")
    cur_pct = current.get("percent_remaining")
    if not isinstance(prev_pct, (int, float)) or not isinstance(cur_pct, (int, float)):
        return False
    return float(cur_pct) - float(prev_pct) >= RESET_RECOVERY_THRESHOLD


def _window_rolled_signal(
    previous: dict[str, Any],
    current: dict[str, Any],
    prev_reset_dt: Optional[datetime],
    cur_reset_dt: Optional[datetime],
    captured_dt: Optional[datetime],
) -> bool:
    """Signal 2: a fixed window rolled after its previously stated deadline.

    Providers revise future deadlines and continuously move rolling-window
    deadlines, neither of which proves that quota was restored — so rolling
    windows only reset via the stronger recovery signal.
    """
    rolling = previous.get("rolling") is True or current.get("rolling") is True
    if rolling:
        return False
    if any(value is None for value in (prev_reset_dt, cur_reset_dt, captured_dt)):
        return False
    return cur_reset_dt > prev_reset_dt and captured_dt >= prev_reset_dt


def _early_timing(
    captured_dt: Optional[datetime],
    prev_reset_dt: Optional[datetime],
) -> tuple[str, Optional[int]]:
    """Classify early-vs-stated and the minutes-early delta.

    Without a captured/stated time to compare we cannot claim "early" —
    default to on/after.
    """
    early = (
        captured_dt is not None
        and prev_reset_dt is not None
        and captured_dt < prev_reset_dt
    )
    timing = "early" if early else "on_or_after_stated"
    minutes_early: Optional[int] = None
    if early:
        delta = (prev_reset_dt - captured_dt).total_seconds()
        if delta > 0:
            minutes_early = int(delta // 60)
    return timing, minutes_early


def _percent_field(value: Any) -> Optional[float]:
    """``value`` as a float, or ``None`` when it isn't numeric."""
    return float(value) if isinstance(value, (int, float)) else None


def _reset_key_part(cur_reset_at: Any, captured_at: str) -> str:
    """The key's window identity: the new ``reset_at``, else detection time."""
    if isinstance(cur_reset_at, str) and cur_reset_at.strip():
        return cur_reset_at
    return captured_at


def _reset_event(
    provider: str, window: str, captured_at: str,
    previous: dict[str, Any], current: dict[str, Any],
    timing: str, minutes_early: Optional[int], signals: list[str],
) -> dict[str, Any]:
    """Assemble the event envelope; ``reset_key`` names the *new* window.

    The key prefers the new window's advertised ``reset_at`` so the same
    reset is never re-flagged; it falls back to the detection moment when
    the provider gives no new deadline.
    """
    prev_pct = previous.get("percent_remaining")
    cur_pct = current.get("percent_remaining")
    prev_reset_at = previous.get("reset_at")
    cur_reset_at = current.get("reset_at")
    return {
        "type": "reset",
        "provider": provider,
        "window": window,
        "detected_at": captured_at,
        "detected_reset_at": captured_at,
        "stated_reset_at": prev_reset_at if isinstance(prev_reset_at, str) else None,
        "new_reset_at": cur_reset_at if isinstance(cur_reset_at, str) else None,
        "timing": timing,
        "minutes_early": minutes_early,
        "previous_percent_remaining": _percent_field(prev_pct),
        "current_percent_remaining": _percent_field(cur_pct),
        "signals": signals,
        "reset_key": f"{provider}|{window}|{_reset_key_part(cur_reset_at, captured_at)}",
    }


def _reset_signals(
    previous: dict[str, Any],
    current: dict[str, Any],
    prev_reset_dt: Optional[datetime],
    cur_reset_dt: Optional[datetime],
    captured_dt: Optional[datetime],
) -> list[str]:
    """The observed reset signals (``recovery``, ``window_rolled``)."""
    signals: list[str] = []
    if _recovery_signal(previous, current):
        signals.append("recovery")
    rolled = _window_rolled_signal(
        previous, current, prev_reset_dt, cur_reset_dt, captured_dt
    )
    if rolled:
        signals.append("window_rolled")
    return signals


def _detect_window_reset(
    provider: str,
    window: str,
    previous: dict[str, Any],
    current: dict[str, Any],
    *,
    captured_at: str,
) -> Optional[dict[str, Any]]:
    """Return a reset event dict for one provider+window, or ``None``.

    ``previous``/``current`` are the window objects (entries of the record's
    unified ``windows`` map) from the previous and current readings. A reset
    is flagged when usage recovered toward baseline OR a new window boundary
    started.
    """
    prev_reset_dt = _parse_iso(previous.get("reset_at"))
    cur_reset_dt = _parse_iso(current.get("reset_at"))
    captured_dt = _parse_iso(captured_at)

    signals = _reset_signals(
        previous, current, prev_reset_dt, cur_reset_dt, captured_dt
    )
    if not signals:
        return None

    timing, minutes_early = _early_timing(captured_dt, prev_reset_dt)
    return _reset_event(
        provider, window, captured_at, previous, current,
        timing, minutes_early, signals,
    )


def _provider_reset_events(
    provider: str,
    prev_record: dict[str, Any],
    cur_record: dict[str, Any],
    *,
    captured_at: str,
    known: set[str],
    seen_keys: set[str],
) -> list[dict[str, Any]]:
    """Detect de-duplicated window resets for one provider."""
    events: list[dict[str, Any]] = []
    # The producer-normalized map keys are the window labels; compare
    # like-for-like by label.
    for window in _window_names(cur_record):
        prev_window = _window_obj(prev_record, window)
        cur_window = _window_obj(cur_record, window)
        if prev_window is None or cur_window is None:
            continue
        event = _detect_window_reset(
            provider, window, prev_window, cur_window, captured_at=captured_at
        )
        if event is None:
            continue
        key = event["reset_key"]
        # Per-run + cross-run de-dup: one event per reset_key.
        if key in known or key in seen_keys:
            continue
        seen_keys.add(key)
        events.append(event)
    return events


def _captured_at_of(cache: dict[str, Any]) -> str:
    """The reading's ``captured_at`` string (empty when absent/malformed)."""
    value = cache.get("captured_at")
    return value if isinstance(value, str) else ""


def _all_provider_reset_events(
    prev_by_provider: dict[str, dict[str, Any]],
    cur_by_provider: dict[str, dict[str, Any]],
    *,
    captured_at: str,
    known: set[str],
) -> list[dict[str, Any]]:
    """Detect de-duplicated resets for every provider present in both readings."""
    events: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    for provider, cur_record in cur_by_provider.items():
        prev_record = prev_by_provider.get(provider)
        if prev_record is None:
            continue
        events.extend(_provider_reset_events(
            provider, prev_record, cur_record,
            captured_at=captured_at, known=known, seen_keys=seen_keys,
        ))
    return events


def detect_resets(
    previous_cache: Optional[dict[str, Any]], current_cache: dict[str, Any],
    *, known_reset_keys: Optional[set[str]] = None,
) -> list[dict[str, Any]]:
    """Compare two readings and return de-duplicated reset events.

    ``previous_cache`` is the last cached reading (``None`` on the first
    capture — nothing to compare, so no events). ``known_reset_keys`` are
    ``reset_key`` values already recorded in the reset-events log; matching
    events are suppressed (cross-run de-dup).
    """
    if previous_cache is None:
        return []

    known = known_reset_keys if known_reset_keys is not None else set()
    return _all_provider_reset_events(
        _records_by_provider(previous_cache),
        _records_by_provider(current_cache),
        captured_at=_captured_at_of(current_cache),
        known=known,
    )
