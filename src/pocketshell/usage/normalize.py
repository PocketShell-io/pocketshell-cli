"""Normalize quse's provider-keyed JSON into per-provider NDJSON.

The pinned PyPI `quse==0.0.15` contract (upstream a86959e, issue #2293) is a
six-provider, provider-keyed object whose records ALREADY carry the canonical
top-level `windows` map the Android parser reads — `claude`, `codex`,
`copilot`, `go` (OpenCode on the Go backend), `grok`, `zai`. PocketShell's
producer boundary is therefore a passthrough: it injects the provider name
from the object key and forwards the record unchanged. It never re-derives
quota values, reset times, window labels, or provider details.

#2283's `short_term` / `long_term` translation existed only because the
published wheel lagged quse HEAD; with the pin at 0.0.15 that producer no
longer exists, so the translation is hard-cut (D22) and a legacy-shaped record
now fails loudly. A schema mismatch (non-JSON / non-object payload, malformed
window container, or a missing canonical `windows` map) raises rather than
silently emptying the panel.
"""

from __future__ import annotations

import json
from typing import Any, Optional

_CLAUDE_USAGE_AUTH_SETUP_MESSAGE = (
    "Claude usage authentication needs setup on this host. "
    "Open Claude Code on the host and complete sign-in, then refresh usage."
)
_GROK_USAGE_AUTH_SETUP_MESSAGE = (
    "Grok authentication is missing on this host. "
    "Sign in with `grok` on the host, then refresh usage."
)


def _claude_actionable_error(lower: str) -> bool:
    """Whether a Claude error string matches a known sign-in failure."""
    login_markers = ("claude /login", "run `claude", "run claude", "authentication failed")
    auth_markers = ("http error 401", "unauthorized")
    return (
        any(marker in lower for marker in login_markers)
        or any(marker in lower for marker in auth_markers)
        or lower in {"no-credentials", "no credentials"}
    )


def _actionable_error(provider: str, error: Any) -> Optional[str]:
    """Rewrite a provider `error` string into an actionable, human message.

    This is genuine error-message UX, NOT schema re-derivation: quse owns the
    schema and reports the raw upstream error; pocketshell only translates a
    couple of known auth failures into a "here is what to do" message so the
    app surfaces "sign in on the host" instead of a bare "HTTP Error 401".
    Idempotent — the rewritten messages do not re-match these patterns.
    """
    if error is None:
        return None
    text = str(error).strip()
    if not text:
        return None
    lower = text.lower()
    if provider == "claude" and _claude_actionable_error(lower):
        return _CLAUDE_USAGE_AUTH_SETUP_MESSAGE
    if provider == "codex" and lower in {"no auth token", "no-auth-token", "no credentials"}:
        return (
            "Codex authentication is missing on this host. "
            "Run `codex login` in the host shell, then refresh usage."
        )
    if provider in {"grok", "grok-build"} and (
        lower in {"no-credentials", "no credentials", "no-auth-token", "no auth token"}
        or "auth.json" in lower
    ):
        return _GROK_USAGE_AUTH_SETUP_MESSAGE
    return text


def _canonicalize_quse_record(
    provider: str,
    record: dict[str, Any],
) -> dict[str, Any]:
    """Normalize one provider record at the PocketShell producer boundary.

    The pinned ``quse==0.0.15`` wheel IS the canonical producer: every record
    already carries the top-level ``windows`` map the Android parser reads. The
    only thing this boundary does is inject the ``provider`` name that quse
    keeps in the object key — quse's ``--json`` document is provider-keyed and
    the app wire is one self-describing record per line. Nothing else is
    touched: windows, percentages, reset times, ``rolling`` flags and
    provider-owned ``details`` are forwarded verbatim.

    Fail loud (D22 hard cut): a record without a canonical ``windows`` object
    is a schema drift — most plausibly a stale/shadowed quse — and must surface
    as an error, not be silently re-shaped. There is deliberately no
    ``short_term`` / ``long_term`` fallback here any more (#2283 → #2293).
    """
    if "windows" not in record:
        raise ValueError(
            f"quse provider '{provider}' is missing the canonical 'windows' map"
        )
    if not isinstance(record["windows"], dict):
        raise ValueError(
            f"quse provider '{provider}' top-level 'windows' is not a JSON object"
        )
    return {"provider": provider, **record}


def _parse_quse_document(stdout: str) -> dict[str, Any]:
    """Parse quse stdout into the provider-keyed object, failing loudly."""
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"quse --json did not emit valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError(
            "quse --json must be a provider-keyed JSON object, got "
            f"{type(parsed).__name__}"
        )
    return parsed


def normalize_usage_stdout(stdout: str) -> str:
    """Flatten quse's provider-keyed object into per-provider NDJSON.

    Published ``quse==0.0.15`` records already carry the canonical top-level
    ``windows`` map, so each record passes through unchanged apart from the
    injected ``provider`` key. This function never invents percentages or
    reset times.

    Strict / fail-loud: non-JSON stdout, a non-object top-level payload, a
    non-object provider value, or a record missing/mis-typing the canonical
    ``windows`` map all raise ``ValueError`` so a schema mismatch fails visibly
    instead of silently emptying the usage panel. Empty/blank stdout passes
    through untouched (the caller decides what an empty read means).
    """
    if not stdout.strip():
        return stdout
    parsed = _parse_quse_document(stdout)
    lines: list[str] = []
    for provider, record in parsed.items():
        if not isinstance(record, dict):
            raise ValueError(
                f"quse --json provider '{provider}' is not a JSON object "
                f"(got {type(record).__name__})"
            )
        flattened = _canonicalize_quse_record(provider, record)
        if flattened.get("error") is not None:
            flattened["error"] = _actionable_error(provider, flattened["error"])
        lines.append(json.dumps(flattened, sort_keys=True))
    return "\n".join(lines) + "\n"
