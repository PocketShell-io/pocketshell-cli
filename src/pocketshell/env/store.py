"""Read, merge, write, unset, and copy env keys per directory."""
from __future__ import annotations
import os
import shlex
from dataclasses import dataclass
from pathlib import Path
# --- sibling modules ---
from pocketshell.env.parse import ENV_FILE, ENV_FILENAMES, _FILE_PREFIX, _folded_values, parse_assignment, parse_env_file


# Permissions for a freshly-created env file. ``0600`` keeps secrets
# readable only by the owning user — these files hold credentials.
NEW_FILE_MODE = 0o600


@dataclass(frozen=True)
class EnvKey:
    """One key as surfaced by ``env list``.

    ``value`` is deliberately *not* part of this shape — ``list`` is
    write-only by default (D24). ``has_value`` records whether the
    parsed assignment had a non-empty right-hand side.
    """

    key: str
    file: str
    has_value: bool


def env_files_in(directory: Path) -> list[str]:
    """Return the basenames of env files that exist in ``directory``.

    Order is fixed (``.env`` before ``.envrc``) so merged output is
    deterministic regardless of filesystem listing order.
    """
    return [name for name in ENV_FILENAMES if (directory / name).exists()]


def list_keys(directory: Path) -> list[EnvKey]:
    """List keys across both env files in ``directory`` (no values).

    Each :class:`EnvKey` records the file it came from. The same key
    name appearing in both files yields two entries (one per file) so
    the caller can disambiguate. Sorted by ``(key, file)`` for a stable
    schema.
    """
    keys: list[EnvKey] = []
    seen: set[tuple[str, str]] = set()
    for name in env_files_in(directory):
        for key, value in parse_env_file(directory / name):
            ident = (key, name)
            if ident in seen:
                # Last-wins on has_value within a single file: update the
                # existing entry rather than emitting a duplicate.
                for idx, existing in enumerate(keys):
                    if existing.key == key and existing.file == name:
                        keys[idx] = EnvKey(key=key, file=name, has_value=bool(value))
                        break
                continue
            seen.add(ident)
            keys.append(EnvKey(key=key, file=name, has_value=bool(value)))
    keys.sort(key=lambda k: (k.key, k.file))
    return keys


def get_values(directory: Path, requested: list[str]) -> dict[str, str]:
    """Return ``{key: value}`` for each requested key found in ``directory``.

    Both files are consulted; ``.envrc`` wins over ``.env`` when a key
    is defined in both (direnv is sourced after a plain ``.env`` in most
    setups, so its value is the effective one). Missing keys are simply
    absent from the result — that is not an error.
    """
    merged: dict[str, str] = {}
    # ``.env`` first, then ``.envrc`` so the latter overrides.
    for name in env_files_in(directory):
        merged.update(_folded_values(directory / name))
    return {key: merged[key] for key in requested if key in merged}


def merged_exports(directory: Path) -> dict[str, str]:
    """Return the merged ``{key: value}`` map across both files.

    Used by ``export``. ``.envrc`` overrides ``.env`` on conflict, for
    the same reason as :func:`get_values`. Insertion order follows file
    order then in-file order, which keeps the emitted block stable.
    """
    merged: dict[str, str] = {}
    for name in env_files_in(directory):
        for key, value in parse_env_file(directory / name):
            merged[key] = value
    return merged


def _format_value(value: str) -> str:
    """Render ``value`` for the right-hand side of an assignment.

    Empty, or anything containing whitespace, ``#``, or a quote, is
    wrapped in double quotes with embedded double-quotes/backslashes
    escaped so the file round-trips through :func:`parse_assignment`.
    Plain tokens are written bare to keep human-edited files tidy.
    """
    if value == "":
        return '""'
    needs_quote = any(c.isspace() for c in value) or any(c in value for c in '#"\'=`$')
    if not needs_quote:
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _assignment_line(file_name: str, key: str, value: str) -> str:
    """Build the full assignment line for ``key`` in ``file_name``."""
    return f"{_FILE_PREFIX[file_name]}{key}={_format_value(value)}"


def _line_matches_key(file_name: str, line: str, key: str) -> bool:
    """Return True when ``line`` is an assignment to ``key``.

    Used by the surgical rewriter to find lines to replace/delete while
    leaving comments and other keys untouched.
    """
    parsed = parse_assignment(line)
    return parsed is not None and parsed[0] == key


def _rewrite_existing_lines(
    lines: list[str], updates: dict[str, str], file_name: str
) -> tuple[list[str], dict[str, str]]:
    """Rewrite assignment lines for updated keys in place; return the rest."""
    remaining = dict(updates)
    new_lines: list[str] = []
    for line in lines:
        replaced = False
        for key in list(remaining):
            if _line_matches_key(file_name, line, key):
                new_lines.append(_assignment_line(file_name, key, remaining.pop(key)))
                replaced = True
                break
        if not replaced:
            new_lines.append(line)
    return new_lines, remaining


def _append_new_keys(
    new_lines: list[str],
    updates: dict[str, str],
    remaining: dict[str, str],
    file_name: str,
) -> None:
    """Append keys not already present, in caller order."""
    for key, value in updates.items():
        if key in remaining:
            new_lines.append(_assignment_line(file_name, key, value))
            remaining.pop(key, None)


def _render_content(new_lines: list[str], had_trailing_newline: bool) -> str:
    """Join the rewritten lines, preserving the file's trailing-newline state."""
    content = "\n".join(new_lines)
    if content and had_trailing_newline:
        content += "\n"
    elif not content:
        # An all-new file with content always ends in a newline; an
        # empty result stays empty.
        content = ""
    return content


def _create_private(path: Path, content: str) -> None:
    """Create ``path`` with restrictive perms before writing any secret bytes."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, NEW_FILE_MODE)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)


def write_keys(directory: Path, file_name: str, updates: dict[str, str]) -> None:
    """Create/update ``updates`` in ``directory/file_name`` surgically.

    Existing lines for an updated key are rewritten in place (preserving
    their position); brand-new keys are appended. Comments, blank lines,
    ordering, and untouched keys are preserved byte-for-byte aside from
    the rewritten assignment lines.

    A new file is created mode ``0600``. An existing file keeps its perms.
    """
    if file_name not in _FILE_PREFIX:
        raise ValueError(f"unsupported env file: {file_name}")
    path = directory / file_name
    existed = path.exists()

    original = path.read_text(encoding="utf-8") if existed else ""
    lines = original.splitlines()
    # Preserve a trailing-newline-or-not decision: most env files end in
    # a newline. We rebuild line-by-line and re-join with "\n".
    had_trailing_newline = original.endswith("\n") if original else True

    new_lines, remaining = _rewrite_existing_lines(lines, updates, file_name)
    _append_new_keys(new_lines, updates, remaining, file_name)
    content = _render_content(new_lines, had_trailing_newline)

    if not existed:
        _create_private(path, content)
    else:
        path.write_text(content, encoding="utf-8")


def unset_keys(directory: Path, keys: list[str]) -> int:
    """Delete ``keys`` from both env files in ``directory``.

    Returns the number of assignment lines removed. Comments and other
    keys are preserved. A key absent from every file is a no-op (not an
    error).
    """
    removed = 0
    targets = set(keys)
    for name in env_files_in(directory):
        path = directory / name
        original = path.read_text(encoding="utf-8")
        had_trailing_newline = original.endswith("\n") if original else True
        kept: list[str] = []
        for line in original.splitlines():
            parsed = parse_assignment(line)
            if parsed is not None and parsed[0] in targets:
                removed += 1
                continue
            kept.append(line)
        content = "\n".join(kept)
        if content and had_trailing_newline:
            content += "\n"
        path.write_text(content, encoding="utf-8")
    return removed


def copy_keys(
    src_dir: Path,
    dst_dir: Path,
    keys: list[str],
    *,
    dst_file: str = ENV_FILE,
) -> dict[str, str]:
    """Copy ``keys`` values from ``src_dir`` into ``dst_dir/dst_file``.

    Source values are read merged across both source files (``.envrc``
    wins, same as :func:`get_values`). Keys missing from the source are
    skipped. Returns the ``{key: value}`` map actually written.
    """
    available = get_values(src_dir, keys)
    if available:
        write_keys(dst_dir, dst_file, available)
    return available


def render_export(directory: Path) -> str:
    """Render the merged env as an ``eval``-safe ``export`` block.

    Every key is emitted as ``export KEY=<shell-quoted value>`` using
    :func:`shlex.quote` so values with spaces, quotes, ``#``, or ``$``
    survive a round-trip through ``eval``. Trailing newline included
    when non-empty.
    """
    merged = merged_exports(directory)
    if not merged:
        return ""
    lines = [f"export {key}={shlex.quote(value)}" for key, value in merged.items()]
    return "\n".join(lines) + "\n"
