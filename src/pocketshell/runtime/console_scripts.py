"""Candidate directories for this CLI's bundled console-scripts.

Both dependencies that ship binaries — aplexer's ``a``/``aplexer``
(:mod:`pocketshell.runtime.aplexer`) and ``quse``
(:mod:`pocketshell.usage.quse`) — resolve their console-script next to the
running interpreter and NEVER on ``PATH`` (D22, issue #2543). This module
owns that candidate list so the two resolvers cannot drift.
"""

from __future__ import annotations

import site
import sys
import sysconfig
from pathlib import Path


def user_scripts_dir() -> Path | None:
    """The user-scheme scripts dir — but ONLY for a ``pip install --user`` CLI.

    Under ``python3 -m pip install --user pocketshell`` (issue #6) the
    console-scripts land in the user scripts dir (``~/.local/bin``) while
    ``sys.executable`` stays the system interpreter, so interpreter-anchored
    candidates never contain them. The dir is returned only when THIS
    pocketshell package is installed in the running interpreter's user
    site-packages — the exact ``--user`` layout, where that dir's ``a`` /
    ``quse`` ARE the pinned ones. Under ``uv tool`` / ``pipx`` / a venv the
    package lives elsewhere, so ``None`` keeps ``~/.local/bin`` — where an
    unrelated, unpinned binary may sit — out of the candidate list. That is
    the #2543 separate-install hazard, not reopened.
    """
    if not site.ENABLE_USER_SITE:
        return None
    try:
        user_site = Path(site.getusersitepackages()).resolve()
        package_root = Path(__file__).resolve().parent.parent.parent
    except OSError:  # pragma: no cover - unreadable install paths
        return None
    if package_root != user_site:
        return None
    scripts = sysconfig.get_path("scripts", "posix_user")
    return Path(scripts) if scripts else None


def bundled_bin_dirs() -> list[Path]:
    """Directories that can hold the bundled console-scripts, highest first.

    1. Next to the UNRESOLVED ``sys.executable`` — the venv / ``uv tool`` /
       ``pipx`` layout, where console-scripts land.
    2. Next to the RESOLVED interpreter, for layouts where ``bin/python`` is a
       real file in a shared interpreter dir.
    3. The user scripts dir, only when this package is itself user-installed
       (:func:`user_scripts_dir`, issue #6).

    None of these is a ``PATH`` search: every candidate is anchored to the
    running interpreter or to its own user scheme, so a separately-installed
    binary elsewhere on the box is never picked up (#2543).
    """
    exe_dir = Path(sys.executable).parent
    dirs = [exe_dir]
    resolved_dir = Path(sys.executable).resolve().parent
    if resolved_dir != exe_dir:
        dirs.append(resolved_dir)
    user_dir = user_scripts_dir()
    if user_dir is not None and user_dir not in dirs:
        dirs.append(user_dir)
    return dirs
