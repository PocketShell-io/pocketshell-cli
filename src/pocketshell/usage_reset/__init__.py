"""Server-side usage limit/session reset detection (issue #690).

Builds on the hourly usage capture (#689). Each scheduled
``pocketshell usage --capture`` writes a cached latest reading
(``usage-latest.json``) and appends one entry to the history log
(``usage-history.jsonl``). The detector compares the *current* reading to
the *previous* cached one and flags a **reset event** when a provider's
limit/session window has reset — usage dropped back toward baseline, or a
new window boundary started — **especially when it happens earlier than the
stated reset time**.

A reset event is recorded so the app (a later slice) and a
``pocketshell usage --reset-events`` read can surface
"limits reset at <time>". The FCM push delivery + the app-side notification
are explicitly OUT of scope for this slice; this is the detection + logging
foundation only.

What counts as a reset
----------------------

For each provider, and each entry of PocketShell's canonical ``windows`` map
(the keys are the producer-normalized window labels), we compare the previous
reading to the current one:

1. **Usage dropped back toward baseline.** ``percent_remaining`` jumped UP
   by at least :data:`RESET_RECOVERY_THRESHOLD` percentage points (e.g.
   from 8% remaining to 100% remaining). A fresh limit window resets the
   meter, so a large recovery is the strongest signal a reset happened.
2. **A fixed-window boundary started.** The previous reading carried a
   ``reset_at`` and the current ``reset_at`` has advanced *past* the old
   one after the old deadline elapsed. Rolling-window deadline motion is not
   a boundary signal; it requires the strong percentage-recovery signal.

Either signal flags a reset. Both being present strengthens confidence but
is not required.

Early-vs-stated
---------------

The previous reading stated a ``reset_at`` (the provider's advertised reset
time). If the reset is *detected* (this capture's ``captured_at``) **before**
that stated time, it is an **early** reset — the interesting case the
maintainer cares about ("resume heavy work the moment limits actually
reset"). Otherwise it is ``on_or_after_stated``. The event records both the
detected time and the previously-stated time so the app can say
"limits reset at <detected>, ~Nm earlier than stated".

De-duplication (#619 don't-renotify principle)
----------------------------------------------

One reset event per *actual* reset. Two guards:

1. **Per-run guard.** Within a single capture, a provider+window can emit at
   most one event.
2. **Cross-run guard.** A reset event carries a ``reset_key`` derived from
   the provider, window, and the new window's identity (its ``reset_at``, or
   the detected time when no new ``reset_at`` is known). The detector
   suppresses any event whose ``reset_key`` already exists in the recent
   reset-events log, so the same reset is never re-flagged on the next hourly
   run (where ``percent_remaining`` is still high relative to the pre-reset
   reading, but it is the *same* window we already logged).

Modules
-------

- :mod:`pocketshell.usage_reset.detect` — pure reading-vs-reading detection.
- :mod:`pocketshell.usage_reset.store` — the reset-events log on disk and
  the app-facing JSON document.
"""
from __future__ import annotations

from pocketshell.usage_reset.detect import (
    RESET_RECOVERY_THRESHOLD,
    detect_resets,
)
from pocketshell.usage_reset.store import (
    DEFAULT_RESET_EVENTS_MAX_LINES,
    RESET_EVENTS_FILENAME,
    read_reset_events,
    record_resets,
    reset_events_document,
    reset_events_file,
)

__all__ = [
    "DEFAULT_RESET_EVENTS_MAX_LINES",
    "RESET_EVENTS_FILENAME",
    "RESET_RECOVERY_THRESHOLD",
    "detect_resets",
    "read_reset_events",
    "record_resets",
    "reset_events_document",
    "reset_events_file",
]
