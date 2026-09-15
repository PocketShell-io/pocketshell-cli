"""Secret redaction for keys, values, and nested payloads."""
from __future__ import annotations
import re
from typing import Any, Optional


# Replacement token written in place of any redacted secret value.
REDACTED = "<redacted>"


# A dict key (or an env var name in an inline assignment) whose *value*
# must be masked. Matches common secret suffixes/words case-insensitively.
_SECRET_KEY_RE = re.compile(
    r"(?i)(?:^|_)(?:key|token|secret|password|passwd|pwd|credential|"
    r"credentials|apikey|auth|access[_-]?key|private[_-]?key|session[_-]?token)$"
)


# A few standalone secret-ish names that don't end in the words above.
_SECRET_KEY_EXTRA = re.compile(r"(?i)^(?:password|passwd|pwd|secret|token|apikey|api_key)$")


# Token-shaped string values redacted regardless of the key they sit under.
_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-[A-Za-z0-9_\-]{8,}"),               # OpenAI-style
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}"),           # Anthropic
    re.compile(r"gh[pousr]_[A-Za-z0-9]{16,}"),          # GitHub PAT family
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),        # GitHub fine-grained
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),       # Slack
    re.compile(r"AKIA[0-9A-Z]{16}"),                    # AWS access key id
    re.compile(r"AIza[0-9A-Za-z_\-]{20,}"),             # Google API key
    re.compile(r"glpat-[A-Za-z0-9_\-]{16,}"),           # GitLab PAT
    re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]+"),  # JWT
    # Generic long high-entropy blob (base64/hex). Length guard avoids
    # eating ordinary words; the charset requires at least mixed alnum.
    re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"),
    re.compile(r"\b[A-Fa-f0-9]{40,}\b"),
)


# Token-shaped string values redacted regardless of the key they sit under.
_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-[A-Za-z0-9_\-]{8,}"),               # OpenAI-style
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}"),           # Anthropic
    re.compile(r"gh[pousr]_[A-Za-z0-9]{16,}"),          # GitHub PAT family
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),        # GitHub fine-grained
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),       # Slack
    re.compile(r"AKIA[0-9A-Z]{16}"),                    # AWS access key id
    re.compile(r"AIza[0-9A-Za-z_\-]{20,}"),             # Google API key
    re.compile(r"glpat-[A-Za-z0-9_\-]{16,}"),           # GitLab PAT
    re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]+"),  # JWT
    # Generic long high-entropy blob (base64/hex). Length guard avoids
    # eating ordinary words; the charset requires at least mixed alnum.
    re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"),
    re.compile(r"\b[A-Fa-f0-9]{40,}\b"),
)


# An inline ``KEY=value`` (optionally ``export KEY=value``) assignment
# whose KEY is secret-named — we keep the key, mask the value. Captures
# an optional ``export`` + leading-quote run so quoted values mask fully.
_INLINE_ASSIGN_RE = re.compile(
    r"((?:export\s+)?[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(['\"]?)([^'\"\s]*)\2"
)


def _key_is_secret(key: str) -> bool:
    """True when a dict key / env var name denotes a secret value."""
    if not isinstance(key, str):
        return False
    return bool(_SECRET_KEY_RE.search(key) or _SECRET_KEY_EXTRA.search(key))


def _name_part_is_secret(name: str) -> bool:
    """True for an inline-assignment LHS like ``export OPENAI_API_KEY``.

    Strips a leading ``export`` token before the secret-name test.
    """
    bare = re.sub(r"^export\s+", "", name).strip()
    return _key_is_secret(bare)


def _redact_string(value: str) -> str:
    """Redact token-shaped substrings and inline secret assignments.

    Inline secret assignments are masked first (so the env var name is
    preserved as evidence — ``export OPENAI_API_KEY=<redacted>``), then
    any remaining token-shaped substrings anywhere in the string.
    """

    def _assign_sub(m: re.Match[str]) -> str:
        name = m.group(1)
        if _name_part_is_secret(name):
            return f"{name}={REDACTED}"
        return m.group(0)

    redacted = _INLINE_ASSIGN_RE.sub(_assign_sub, value)
    for pattern in _TOKEN_PATTERNS:
        redacted = pattern.sub(REDACTED, redacted)
    return redacted


def redact(obj: Any, *, parent_key: Optional[str] = None) -> Any:
    """Return a deep copy of ``obj`` with every secret value redacted.

    Walks dicts and lists recursively:

    - a value under a secret-named key becomes ``"<redacted>"`` outright;
    - any string value (anywhere) has token-shaped substrings and inline
      secret assignments masked.

    Non-container, non-string scalars (int/float/bool/None) pass through.
    """
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for key, value in obj.items():
            if isinstance(key, str) and _key_is_secret(key):
                out[key] = REDACTED
            else:
                out[key] = redact(value, parent_key=key if isinstance(key, str) else None)
        return out
    if isinstance(obj, list):
        return [redact(item, parent_key=parent_key) for item in obj]
    if isinstance(obj, str):
        return _redact_string(obj)
    return obj
