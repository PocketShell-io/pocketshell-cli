"""Firebase Cloud Messaging auth + HTTP sender."""
from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Any, Optional
from pocketshell.usage_capture import (
    UsagePaths,
)


# Default service-account JSON name searched under the usage state dir when
# $POCKETSHELL_FCM_SERVICE_ACCOUNT is unset.
SERVICE_ACCOUNT_FILENAME = "fcm-service-account.json"


SERVICE_ACCOUNT_ENV = "POCKETSHELL_FCM_SERVICE_ACCOUNT"


# OAuth2 scope for the FCM HTTP v1 send endpoint.
FCM_SEND_SCOPE = "https://www.googleapis.com/auth/firebase.messaging"


def _resolve_service_account_path(
    paths: UsagePaths,
    *,
    env: Optional[dict[str, str]] = None,
) -> Optional[Path]:
    """Locate the service-account JSON, or ``None`` when unconfigured.

    Precedence: ``$POCKETSHELL_FCM_SERVICE_ACCOUNT`` then
    ``<usage-state-dir>/fcm-service-account.json``.
    """
    env_map = env if env is not None else os.environ
    explicit = env_map.get(SERVICE_ACCOUNT_ENV)
    if explicit:
        candidate = Path(os.path.expanduser(explicit))
        return candidate if candidate.exists() else None
    default = paths.usage_dir / SERVICE_ACCOUNT_FILENAME
    return default if default.exists() else None


def _service_account_project_id(path: Path) -> Optional[str]:
    """Read the ``project_id`` out of a service-account JSON file."""
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if isinstance(parsed, dict):
        project_id = parsed.get("project_id")
        if isinstance(project_id, str) and project_id.strip():
            return project_id.strip()
    return None


class FcmSender:
    """Mint a service-account bearer and POST FCM HTTP v1 data messages.

    Split out from the module functions so the unit suite can subclass it and
    intercept :meth:`_post` (the only network boundary) without a real Firebase
    project or a real ``google.auth`` install. :meth:`from_service_account`
    returns ``None`` when credentials or :mod:`google.auth` are unavailable —
    the fail-soft path.
    """

    def __init__(self, *, project_id: str, credentials: Any) -> None:
        self._project_id = project_id
        self._credentials = credentials

    @property
    def endpoint(self) -> str:
        return f"https://fcm.googleapis.com/v1/projects/{self._project_id}/messages:send"

    @classmethod
    def from_service_account(cls, path: Path) -> Optional["FcmSender"]:
        """Build a sender from a service-account JSON, or ``None`` fail-soft.

        Returns ``None`` (never raises) when the JSON lacks a ``project_id`` or
        when :mod:`google.auth` is not installed, so an unconfigured host's
        hourly capture is unaffected.
        """
        project_id = _service_account_project_id(path)
        if project_id is None:
            return None
        try:
            # Optional dependency: import lazily so a host without google-auth
            # (the common pre-S0 state) simply no-ops instead of ImportError.
            from google.oauth2 import service_account as _sa  # type: ignore
        except Exception:
            return None
        try:
            credentials = _sa.Credentials.from_service_account_file(
                str(path),
                scopes=[FCM_SEND_SCOPE],
            )
        except Exception:
            return None
        return cls(project_id=project_id, credentials=credentials)

    def _bearer(self) -> Optional[str]:
        """Mint/refresh the short-lived OAuth2 bearer, or ``None`` on failure.

        ``google.auth`` caches the token on the credentials object and only
        hits the network when the cached token is missing/expired, so calling
        this once per capture is cheap on subsequent runs.
        """
        try:
            from google.auth.transport.requests import Request  # type: ignore

            self._credentials.refresh(Request())
        except Exception:
            return None
        token = getattr(self._credentials, "token", None)
        return token if isinstance(token, str) and token else None

    def _post(self, *, bearer: str, message: dict[str, Any]) -> bool:
        """POST one FCM HTTP v1 message. Returns True on a 2xx response.

        Network boundary — overridden in tests. Uses ``urllib`` to avoid a
        ``requests`` dependency (the rest of the CLI already uses ``urllib``).
        """
        import urllib.error
        import urllib.request

        body = json.dumps({"message": message}).encode("utf-8")
        req = urllib.request.Request(
            self.endpoint,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {bearer}",
                "Content-Type": "application/json; charset=UTF-8",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                return 200 <= int(resp.status) < 300
        except urllib.error.HTTPError:
            return False
        except (urllib.error.URLError, OSError):
            return False

    def send_data_message(self, *, token: str, data: dict[str, str]) -> bool:
        """Send an FCM **data** message to ``token``. Returns True on success.

        Builds the HTTP v1 envelope ``{"message": {"token", "data"}}`` — a pure
        data message (no ``notification`` block) so the app builds the
        notification itself (matching ``ResetPushPayload`` semantics). Returns
        False (never raises) if the bearer can't be minted or the POST fails, so
        the caller leaves the ``reset_key`` un-marked and RETRIES next capture.
        """
        bearer = self._bearer()
        if bearer is None:
            return False
        message = {"token": token, "data": data}
        return self._post(bearer=bearer, message=message)
