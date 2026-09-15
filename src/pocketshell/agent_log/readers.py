"""Line reading, tailing, and byte-clamping for session logs."""
from __future__ import annotations
from pathlib import Path
from typing import Iterable, List, Optional


# Issue #1225/#1267: sentinel emitted in place of a transcript line that
# exceeded ``--max-line-bytes``, immediately followed by the line's original
# UTF-8 byte length. MUST stay byte-identical to ``LINE_TRUNCATION_SENTINEL``
# in the Kotlin ``AgentConversationRepository`` so the app recognises it and
# renders a VISIBLE truncation marker instead of feeding the (now absent)
# oversized JSON to the parser. This is the Codex/OpenCode counterpart of the
# ``awk`` per-line byte clamp #1225 applied to the Claude flat-JSONL tail: one
# multi-megabyte rollout line (an inline base64 image, a huge ``tool_result``)
# is degraded server-side so its bytes never cross SSH into the phone's heap.
_LINE_TRUNCATION_SENTINEL = "@@PS_LINE_TRUNCATED@@"


def _read_lines(path: Path) -> List[str]:
    """Read a JSONL file as a list of newline-stripped strings.

    Uses ``errors='replace'`` so a truncated last line (mid-write from a
    live agent) doesn't crash the read — the Android side already
    tolerates partial rows in its tail loop (``ConversationParser``
    swallows ``JsonReader`` exceptions per line).
    """
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        # ``splitlines`` strips the trailing newline whether or not the
        # file ends with one; the JSONL contract is one event per line
        # so dropping the empty trailing element is correct.
        return handle.read().splitlines()


def _tail(lines: Iterable[str], n: Optional[int]) -> List[str]:
    """Return the last ``n`` items of ``lines`` (or all if ``n`` is None).

    Materialises ``lines`` if it is not already a list; the JSONL files
    are bounded in practice (a long Claude session is a few thousand
    lines, well under 100 MB) so loading into memory is acceptable and
    keeps the implementation small.
    """
    materialised = lines if isinstance(lines, list) else list(lines)
    if n is None or n <= 0 or n >= len(materialised):
        return list(materialised)
    return materialised[-n:]


def _clamp_line_bytes(lines: List[str], max_line_bytes: Optional[int]) -> List[str]:
    """Byte-bound each line, server-side, before it is emitted.

    Any line whose UTF-8 byte length exceeds ``max_line_bytes`` is replaced by
    ``<_LINE_TRUNCATION_SENTINEL><byte-length>`` so a single multi-megabyte
    rollout line (an inline base64 image, a huge ``tool_result``) never crosses
    SSH into the phone's heap — the Codex/OpenCode counterpart of the Claude
    ``awk`` clamp (#1225/#1267). ``None`` or a non-positive cap disables the
    clamp (the whole-file default); normal lines pass through verbatim.
    """
    if not max_line_bytes or max_line_bytes <= 0:
        return lines
    clamped: List[str] = []
    for line in lines:
        byte_length = len(line.encode("utf-8"))
        if byte_length > max_line_bytes:
            clamped.append(f"{_LINE_TRUNCATION_SENTINEL}{byte_length}")
        else:
            clamped.append(line)
    return clamped
