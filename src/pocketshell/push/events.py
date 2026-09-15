"""Translate usage-reset events into push notifications."""
from __future__ import annotations
from typing import Any, Optional
from pocketshell.usage_capture import (
    UsagePaths,
    resolve_paths,
)
# --- sibling modules ---
from pocketshell.push.fcm import FcmSender, _resolve_service_account_path
from pocketshell.push.store import DEFAULT_SENT_LOG_MAX_LINES, _mark_sent, read_token, sent_reset_keys


def _provider_display_name(provider: str) -> str:
    """Mirror the app's ``ResetPushPayload.providerDisplayName`` copy."""
    lowered = provider.strip().lower()
    if lowered in ("codex", "openai", "chatgpt"):
        return "Codex"
    if lowered in ("claude", "anthropic"):
        return "Claude"
    stripped = provider.strip()
    return stripped[:1].upper() + stripped[1:] if stripped else "Provider"


def reset_event_to_data(event: dict[str, Any]) -> Optional[dict[str, str]]:
    """Map a reset event to the ``ResetPushPayload`` data-message keys.

    Returns ``None`` when the event lacks the de-dup ``reset_key`` (the app
    drops such a push, so there is nothing to send). Pre-renders ``title`` /
    ``body`` to match the app's default copy so a foreground receive shows the
    same wording as a background one.
    """
    reset_key = event.get("reset_key")
    if not isinstance(reset_key, str) or not reset_key.strip():
        return None
    provider = event.get("provider")
    provider_str = provider.strip() if isinstance(provider, str) and provider.strip() else "provider"
    display = _provider_display_name(provider_str)
    return {
        "type": "usage_reset",
        "provider": provider_str,
        "reset_key": reset_key.strip(),
        "title": f"{display} limits reset",
        "body": f"Your {display} usage limits just reset. Heavy work can resume.",
    }


def _resolve_sender(
    paths: UsagePaths,
    sender: Optional[FcmSender],
    env: Optional[dict[str, str]],
) -> Optional[FcmSender]:
    """Build an FCM sender from the service account when not injected."""
    if sender is not None:
        return sender
    sa_path = _resolve_service_account_path(paths, env=env)
    if sa_path is None:
        return None
    return FcmSender.from_service_account(sa_path)


def _send_new_events(
    events: list[dict[str, Any]],
    *,
    paths: UsagePaths,
    sender: FcmSender,
    token: str,
    already_sent: set[str],
    sent_log_max_lines: int,
) -> list[str]:
    """Send each not-yet-sent event, marking keys on success only."""
    pushed: list[str] = []
    for event in events:
        data = reset_event_to_data(event)
        if data is None:
            continue
        reset_key = data["reset_key"]
        if reset_key in already_sent:
            continue
        if sender.send_data_message(token=token, data=data):
            _mark_sent(reset_key, paths=paths, sent_log_max_lines=sent_log_max_lines)
            already_sent.add(reset_key)
            pushed.append(reset_key)
        # On failure: deliberately do NOT mark - next capture retries.
    return pushed


def _token_and_sender(
    paths: UsagePaths,
    sender: Optional[FcmSender],
    env: Optional[dict[str, str]],
) -> Optional[tuple[str, FcmSender]]:
    """The device token + FCM sender, or ``None`` when push isn't configured."""
    token = read_token(paths)
    resolved_sender = _resolve_sender(paths, sender, env)
    if token is None or resolved_sender is None:
        return None
    return token, resolved_sender


def _push_configured_events(
    events: list[dict[str, Any]],
    *,
    paths: UsagePaths,
    sender: Optional[FcmSender],
    env: Optional[dict[str, str]],
    sent_log_max_lines: int,
) -> list[str]:
    """Send all not-yet-sent events; a failure anywhere aborts quietly."""
    pair = _token_and_sender(paths, sender, env)
    if pair is None:
        return []
    token, resolved_sender = pair
    return _send_new_events(
        events,
        paths=paths,
        sender=resolved_sender,
        token=token,
        already_sent=sent_reset_keys(paths),
        sent_log_max_lines=sent_log_max_lines,
    )


def push_reset_events(
    events: list[dict[str, Any]],
    *,
    paths: Optional[UsagePaths] = None,
    sender: Optional[FcmSender] = None,
    env: Optional[dict[str, str]] = None,
    sent_log_max_lines: int = DEFAULT_SENT_LOG_MAX_LINES,
) -> list[str]:
    """Push NEW reset ``events`` to the registered device. Fail-soft.

    Returns the ``reset_key`` values pushed THIS call (empty when push isn't
    configured or nothing new was sent). Never raises — the hourly
    ``--capture`` calls this right after ``record_resets`` and must not
    break when Firebase isn't set up. Per ``reset_key``, keys already in
    the server-side sent-log are skipped and keys are recorded on success
    only, so a failed send stays un-marked and the next capture RETRIES.
    """
    if not events:
        return []
    try:
        return _push_configured_events(
            events,
            paths=paths if paths is not None else resolve_paths(),
            sender=sender,
            env=env,
            sent_log_max_lines=sent_log_max_lines,
        )
    except Exception:
        # Absolute fail-soft backstop: push delivery must never wedge capture.
        return []
