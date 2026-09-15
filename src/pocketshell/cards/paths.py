"""Card directory resolution and session detection."""
from __future__ import annotations
import base64
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional


def _encode_session(session: str) -> str:
    """Reversibly encode a session as one safe path segment."""
    encoded = base64.urlsafe_b64encode(session.encode("utf-8")).decode("ascii")
    return "s-" + encoded.rstrip("=")


@dataclass(frozen=True)
class CardPaths:
    """Resolved filesystem location for the per-session card store.

    The dir is a field so the unit suite can point it at a tmp dir; nothing in
    this module reads ``~`` directly — everything flows through
    :func:`resolve_paths`.
    """

    cards_dir: Path

    def session_file(self, session: str) -> Path:
        return self.cards_dir / f"{_encode_session(session)}.yaml"


# Env override for the cards root, so tests (and a non-default deployment) can
# relocate the store without touching ``~``.
CARDS_DIR_ENV = "POCKETSHELL_CARDS_DIR"


def resolve_paths(
    *,
    home: Optional[Path] = None,
    env: Optional[Mapping[str, str]] = None,
) -> CardPaths:
    """Return the :class:`CardPaths` for the current (or given) environment.

    Precedence for the cards dir:

    1. ``$POCKETSHELL_CARDS_DIR`` when set (tests / non-default deployments).
    2. ``<home>/.pocketshell/cards`` — the issue-specified default that mirrors
       the ``~/inbox/pocketshell/reviews/`` convention (#714).
    """
    env_map = env if env is not None else os.environ
    override = env_map.get(CARDS_DIR_ENV)
    if override:
        return CardPaths(cards_dir=Path(os.path.expanduser(override)))
    base_home = home if home is not None else Path(os.path.expanduser("~"))
    return CardPaths(cards_dir=base_home / ".pocketshell" / "cards")


def detect_session(
    *,
    explicit: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
) -> Optional[str]:
    """Resolve the target session.

    Precedence:

    1. ``explicit`` (the ``--session`` CLI override) when given.
    2. ``$POCKETSHELL_SESSION`` when set by the session workload.

    Returns ``None`` when neither yields a session (the CLI then errors with a
    clear message rather than guessing).
    """
    if explicit and explicit.strip():
        return explicit.strip()
    env_map = env if env is not None else os.environ
    session = env_map.get("POCKETSHELL_SESSION", "").strip()
    return session or None
