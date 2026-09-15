"""Usage-state file locations and tuning constants."""
from __future__ import annotations
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# File permissions for the cache + history files. ``0600`` keeps the
# per-provider quota detail readable only by the owning user.
NEW_FILE_MODE = 0o600


# Default history line cap. ~1 capture/hour * 24 * ~83 days ≈ 2000 lines,
# each ~a few hundred bytes, so the file stays well under ~1 MB.
DEFAULT_HISTORY_MAX_LINES = 2000


CACHE_FILENAME = "usage-latest.json"


HISTORY_FILENAME = "usage-history.jsonl"


MALFORMED_HISTORY_FILENAME = "usage-history-malformed.jsonl"


# A malformed provider line must remain diagnosable without allowing a noisy
# producer to create an unbounded second log. The raw line is also clipped so
# a single broken output cannot consume the entire diagnostic budget.
DEFAULT_MALFORMED_MAX_LINES = 100


MAX_MALFORMED_LINE_LENGTH = 4096


# One lock file per state directory covers the usage history and its related
# append-only logs. It is coordination state, not user-visible history.
HISTORY_LOCK_FILENAME = ".usage-history.lock"


@dataclass(frozen=True)
class UsagePaths:
    """Resolved filesystem locations for the usage cache + history.

    Both paths are fields so the unit suite can point them at a tmp dir.
    Nothing in this module reads ``~`` directly — everything flows through
    :func:`resolve_paths`.
    """

    usage_dir: Path

    @property
    def cache_file(self) -> Path:
        return self.usage_dir / CACHE_FILENAME

    @property
    def history_file(self) -> Path:
        return self.usage_dir / HISTORY_FILENAME

    @property
    def malformed_file(self) -> Path:
        return self.usage_dir / MALFORMED_HISTORY_FILENAME


def resolve_paths(
    *,
    home: Optional[Path] = None,
    env: Optional[dict[str, str]] = None,
) -> UsagePaths:
    """Return the :class:`UsagePaths` for the current (or given) environment.

    Precedence for the usage state dir:

    1. ``$XDG_STATE_HOME/pocketshell/usage`` when ``$XDG_STATE_HOME`` is set.
    2. ``<home>/.local/state/pocketshell/usage``.
    """
    env_map = env if env is not None else os.environ
    base_home = home if home is not None else Path(os.path.expanduser("~"))

    xdg_state = env_map.get("XDG_STATE_HOME")
    if xdg_state:
        state_root = Path(os.path.expanduser(xdg_state))
    else:
        state_root = base_home / ".local" / "state"
    usage_dir = state_root / "pocketshell" / "usage"
    return UsagePaths(usage_dir=usage_dir)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except PermissionError:
        pass
