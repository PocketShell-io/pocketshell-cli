"""Parse .env/.envrc assignments (quotes, exports, comments)."""
from __future__ import annotations
from pathlib import Path
from typing import Optional


# Recognised env-file basenames and their write-time prefixes. ``.envrc``
# uses direnv's ``export `` prefix; ``.env`` is bare ``KEY=value``.
ENV_FILE = ".env"


ENVRC_FILE = ".envrc"


ENV_FILENAMES: tuple[str, ...] = (ENV_FILE, ENVRC_FILE)


ENV_FILENAMES: tuple[str, ...] = (ENV_FILE, ENVRC_FILE)


# Prefix written in front of every key in ``.envrc``. ``.env`` has no
# prefix. Keyed by basename so the writer and the parser agree.
_FILE_PREFIX: dict[str, str] = {ENV_FILE: "", ENVRC_FILE: "export "}


# Prefix written in front of every key in ``.envrc``. ``.env`` has no
# prefix. Keyed by basename so the writer and the parser agree.
_FILE_PREFIX: dict[str, str] = {ENV_FILE: "", ENVRC_FILE: "export "}


def _strip_export_prefix(line: str) -> str:
    """Return ``line`` with a leading ``export `` token removed.

    Only strips a single ``export`` token followed by whitespace; an
    identifier that merely starts with ``export`` (e.g. ``exportable``)
    is left alone because the token must be word-bounded by whitespace.
    """
    stripped = line.lstrip()
    if stripped.startswith("export") and len(stripped) > 6 and stripped[6].isspace():
        return stripped[6:].lstrip()
    return stripped


def parse_assignment(line: str) -> Optional[tuple[str, str]]:
    """Parse one ``KEY=value`` (or ``export KEY=value``) line.

    Returns ``(key, value)`` with the value unquoted, or ``None`` when
    the line is blank, a comment, or not a valid assignment.

    Quoting rules:

    - ``KEY="a b"`` / ``KEY='a b'`` — the matching outer quotes are
      stripped; inner content (including ``#`` and ``=``) is preserved
      verbatim.
    - ``KEY=a b # note`` — for *unquoted* values an inline ``#`` that is
      preceded by whitespace starts a trailing comment and is dropped;
      the value is then right-trimmed. This matches common ``.env``
      loaders. A ``#`` inside quotes is always literal.
    - Surrounding whitespace around the key and the unquoted value is
      trimmed.
    """
    raw = _strip_export_prefix(line)
    if not raw or raw.startswith("#"):
        return None
    eq = raw.find("=")
    if eq <= 0:
        return None
    key = raw[:eq].strip()
    if not key or not _is_valid_key(key):
        return None
    value_part = raw[eq + 1 :]
    return key, _parse_value(value_part)


def _is_valid_key(key: str) -> bool:
    """Return True when ``key`` is a POSIX-ish shell identifier.

    ``[A-Za-z_][A-Za-z0-9_]*``. Keeps us from mis-parsing arbitrary text
    (e.g. a wrapped continuation line) as an assignment.
    """
    if not key:
        return False
    first = key[0]
    if not (first.isalpha() or first == "_"):
        return False
    return all(c.isalnum() or c == "_" for c in key)


def _parse_value(value_part: str) -> str:
    """Unquote the right-hand side of an assignment.

    See :func:`parse_assignment` for the quoting rules this implements.
    """
    text = value_part.strip()
    if len(text) >= 2 and text[0] == "'" and text[-1] == "'":
        # Single quotes: literal, no escape processing (POSIX semantics).
        return text[1:-1]
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        # Double quotes: undo the ``\"`` / ``\\`` escaping that
        # :func:`_format_value` emits so the value round-trips exactly.
        return _unescape_double_quoted(text[1:-1])
    # Unquoted: an inline ``#`` preceded by whitespace begins a comment.
    hash_idx = _find_inline_comment(text)
    if hash_idx is not None:
        text = text[:hash_idx]
    return text.rstrip()


def _unescape_double_quoted(inner: str) -> str:
    """Undo the ``\\\\`` / ``\\"`` escaping applied by :func:`_format_value`.

    Only backslash-escapes for ``\\`` and ``"`` are recognised (the only
    sequences the writer ever emits); any other backslash is left
    literal so a value like ``a\\nb`` survives unchanged.
    """
    out: list[str] = []
    i = 0
    while i < len(inner):
        ch = inner[i]
        if ch == "\\" and i + 1 < len(inner) and inner[i + 1] in ('"', "\\"):
            out.append(inner[i + 1])
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _find_inline_comment(text: str) -> Optional[int]:
    """Return the index of an inline ``#`` comment, or ``None``.

    A ``#`` only starts a comment when it is at the start of the value
    or preceded by whitespace. ``KEY=a#b`` keeps ``a#b`` as the value;
    ``KEY=a #b`` keeps ``a``.
    """
    for i, ch in enumerate(text):
        if ch == "#" and (i == 0 or text[i - 1].isspace()):
            return i
    return None


def parse_env_file(path: Path) -> list[tuple[str, str]]:
    """Parse ``path`` into an ordered list of ``(key, value)`` pairs.

    Later assignments to the same key win (last-wins), matching shell
    sourcing semantics, but the returned list preserves *all* parsed
    pairs in file order so callers that need the canonical value can
    fold them. Non-assignment lines (blanks, comments) are skipped.

    A missing file yields an empty list — callers treat "no file" and
    "empty file" identically.
    """
    if not path.exists():
        return []
    pairs: list[tuple[str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        parsed = parse_assignment(line)
        if parsed is not None:
            pairs.append(parsed)
    return pairs


def _folded_values(path: Path) -> dict[str, str]:
    """Return the last-wins ``{key: value}`` map for one file."""
    result: dict[str, str] = {}
    for key, value in parse_env_file(path):
        result[key] = value
    return result
