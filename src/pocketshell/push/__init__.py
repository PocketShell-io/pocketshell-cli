"""Server-side FCM push delivery for usage-reset events (issue #690).

This module owns the *server* half of the reset-push pipeline. The detection
half (``usage.reset.record_resets``) and the entire Android receive path
(``PocketShellMessagingService`` / ``ResetPushPayload`` / ``PushDedupStore``)
already ship. Here we:

1. **Store the device token** the app delivers over a live foreground SSH
   session — ``pocketshell push register-token <token>`` (R1). The token is
   written atomically with mode ``0600`` alongside the usage state, mirroring
   :mod:`pocketshell.usage.capture`'s private-write style.
2. **Send a data push** for each NEW reset event the hourly ``--capture``
   produces (R2). The push is an FCM **HTTP v1** *data* message whose keys match
   the app's ``ResetPushPayload`` contract exactly (``type=usage_reset``,
   ``provider``, ``reset_key``, ``title``, ``body``). A short-lived OAuth2
   service-account bearer authenticates the call.

Design constraints
------------------

- **Service-account auth, not a legacy server key.** The HTTP v1 endpoint is
  ``POST https://fcm.googleapis.com/v1/projects/<project-id>/messages:send``
  with an ``Authorization: Bearer <oauth2-token>`` header. The bearer is minted
  + cached on the host via :mod:`google.auth` (an *optional* dependency).
- **Server-side per-``reset_key`` "already pushed" marker.** A successful send
  records the ``reset_key`` so it is NEVER re-POSTed, while a transient FCM
  failure leaves the marker absent so the next hourly capture RETRIES. The
  app's ``PushDedupStore`` is a second line of defense, not the primary guard.
- **Fail-soft.** If no service-account credential is configured, no token is
  registered, or :mod:`google.auth` is not installed, :func:`push_reset_events`
  no-ops and returns an empty list WITHOUT raising. The hourly ``--capture``
  must never break because push delivery is not set up (mirrors the best-effort
  ``record_resets`` hook in :mod:`pocketshell.usage.capture`).

Storage layout (under the usage state dir, ``$XDG_STATE_HOME/pocketshell/usage/``):

- ``push-token.json`` — the registered device token (mode ``0600``).
- ``push-sent.jsonl`` — append-only log of ``reset_key`` values successfully
  pushed (the server-side de-dup source of truth; mode ``0600``).

Credential discovery for the service-account JSON, in precedence order:

1. ``$POCKETSHELL_FCM_SERVICE_ACCOUNT`` — explicit path to the JSON.
2. ``<usage-state-dir>/fcm-service-account.json``.

The maintainer's one-time Firebase setup (S0) drops that JSON on the host; until
then every send path no-ops cleanly.
"""
from __future__ import annotations

from pocketshell.push.cli import (
    push_group,
)
from pocketshell.push.events import (
    reset_event_to_data,
    push_reset_events,
)
from pocketshell.push.fcm import (
    SERVICE_ACCOUNT_FILENAME,
    SERVICE_ACCOUNT_ENV,
    FCM_SEND_SCOPE,
    _resolve_service_account_path,
    FcmSender,
)
from pocketshell.push.store import (
    TOKEN_FILENAME,
    SENT_LOG_FILENAME,
    token_file,
    sent_log_file,
    register_token,
    read_token,
    sent_reset_keys,
    _mark_sent,
)

from pocketshell.usage.capture import resolve_paths  # noqa: F401  (legacy push.resolve_paths)

__all__ = [
    "TOKEN_FILENAME",
    "SENT_LOG_FILENAME",
    "SERVICE_ACCOUNT_FILENAME",
    "SERVICE_ACCOUNT_ENV",
    "FCM_SEND_SCOPE",
    "token_file",
    "sent_log_file",
    "register_token",
    "read_token",
    "sent_reset_keys",
    "_mark_sent",
    "_resolve_service_account_path",
    "FcmSender",
    "reset_event_to_data",
    "push_reset_events",
    "push_group",
]
