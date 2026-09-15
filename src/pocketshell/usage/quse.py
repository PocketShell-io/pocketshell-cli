"""Run the bundled `quse` CLI as a one-shot subprocess.

quse is a hard dependency of pocketshell (see `pyproject.toml`), so its
console-script ships in the SAME bin directory as the running interpreter.
`_resolve_quse_binary` resolves that bundled copy via the shared interpreter-
anchored candidate list and NEVER falls back to PATH — a host-level `quse`
must not shadow the bundled copy, and a missing bundled copy is a
packaging-integrity error (fail loud), not a user "install quse" nag.

`pocketshell usage` keeps NO provider allowlist of its own: the positional
`provider` argument is forwarded verbatim to the bundled quse, which owns
provider validation and its error message. New providers can therefore arrive
through a compatible quse upgrade without a PocketShell provider list.
"""

from __future__ import annotations

import subprocess
import sys
from typing import Optional, Sequence

import click

from pocketshell.runtime.console_scripts import bundled_bin_dirs
from pocketshell.usage.normalize import normalize_usage_stdout

# quse is bundled WITH pocketshell as a hard dependency (issue #1318). A
# missing bundled quse is therefore a packaging-integrity error, NOT a user
# "install quse" nag: the fix is reinstalling pocketshell, not installing a
# separate host tool. Exit non-zero (but NOT 127 — 127 is reserved for
# "pocketshell itself not found" on the app side) with a clear message.
_QUSE_MISSING_MESSAGE = (
    "pocketshell: the bundled `quse` usage backend is missing from this "
    "pocketshell install. Reinstall pocketshell (e.g. "
    "`uv tool install --force pocketshell`) to restore it."
)
_QUSE_MISSING_EXIT_CODE = 1


def _resolve_quse_binary() -> Optional[str]:
    """Resolve the bundled `quse` console-script shipped with pocketshell.

    quse is a hard dependency, so its console-script lands in the SAME ``bin``
    directory as the ``pocketshell`` interpreter. We resolve it via the shared
    candidate list (:mod:`pocketshell.runtime.console_scripts`) — never via
    ``PATH`` (a host executable must not shadow the bundled copy) — and return
    ``None`` when it is missing (a packaging-integrity error, not an
    "install quse" nag). The candidates cover the interpreter's own ``bin``
    dir, its resolved dir, and — only for a ``pip install --user`` pocketshell
    — the user scripts dir (issue #6); every candidate is anchored to the
    running interpreter, so an unrelated host binary is never picked up.
    """
    for bin_dir in bundled_bin_dirs():
        candidate = bin_dir / "quse"
        if candidate.exists():
            return str(candidate)
    return None


def _run_quse(args: Sequence[str]) -> int:
    """Invoke the bundled `quse` with [args]; proxy stdout/stderr and exit.

    Used for the human-readable (non-JSON) path where output stays
    byte-identical to `quse`.
    """
    quse_path = _resolve_quse_binary()
    if quse_path is None:
        click.echo(_QUSE_MISSING_MESSAGE, err=True)
        return _QUSE_MISSING_EXIT_CODE

    completed = subprocess.run(
        [quse_path, *args],
        check=False,
        capture_output=True,
        text=True,
    )
    # Human-readable output stays byte-identical to `quse`.
    if completed.stdout:
        sys.stdout.write(completed.stdout)
    if completed.stderr:
        sys.stderr.write(completed.stderr)
    return completed.returncode


def _run_quse_json(args: Sequence[str]) -> int:
    """Invoke the bundled `quse --json` and flatten its output before proxying.

    quse emits a provider-keyed JSON object; ``normalize_usage_stdout``
    flattens it into per-provider NDJSON for the app. On a non-zero exit the
    raw quse stdout/stderr is proxied verbatim (a failed fetch is not
    flattened) so the app's exit!=0 provider-error path sees the real output.
    """
    quse_path = _resolve_quse_binary()
    if quse_path is None:
        click.echo(_QUSE_MISSING_MESSAGE, err=True)
        return _QUSE_MISSING_EXIT_CODE

    completed = subprocess.run(
        [quse_path, *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        if completed.stdout:
            sys.stdout.write(completed.stdout)
        if completed.stderr:
            sys.stderr.write(completed.stderr)
        return completed.returncode
    if completed.stdout:
        sys.stdout.write(normalize_usage_stdout(completed.stdout))
    if completed.stderr:
        sys.stderr.write(completed.stderr)
    return completed.returncode


def _capture_via_quse(provider: Optional[str]) -> tuple[Optional[str], str, int]:
    """Run quse once and flatten its output; never flattens a failed fetch."""
    quse_path = _resolve_quse_binary()
    if quse_path is None:
        return (None, _QUSE_MISSING_MESSAGE + "\n", _QUSE_MISSING_EXIT_CODE)
    args: list[str] = [quse_path]
    if provider:
        args.append(provider)
    args.append("--json")
    completed = subprocess.run(args, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        # A failed live fetch is not flattened/cached — return quse's raw
        # stdout so the caller can decide (it will not be persisted).
        return completed.stdout, completed.stderr, completed.returncode
    return normalize_usage_stdout(completed.stdout), completed.stderr, completed.returncode
