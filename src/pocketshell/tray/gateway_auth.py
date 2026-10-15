"""Per-host gateway auth policy for the tray (key vault, design section 7).

The tray shows and sets which authorized keys gateway SSH accepts on this
host by running ``pocketshell gateway auth show|set --json``, which wraps
``pocketshell-link gateway-auth``. The helper owns the policy files and
validates everything again; the checks here only explain refusals before
anything runs and never widen what the helper accepts.

Managed keys are vault PUBLIC keys. The host never sees a private key or
the vault passphrase. Only type, fingerprint and comment are displayed,
never key bytes. Windows endpoints are loopback endpoints, which support
only the ``host`` policy.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Optional, Sequence

from pocketshell.tray.model import MenuItemSpec

POLICIES = ("host", "managed", "both")
POLICY_LABELS = {
    "host": "Host keys only (~/.ssh/authorized_keys)",
    "managed": "Vault keys only (managed)",
    "both": "Host keys and vault keys",
}

# Mirrors the helper's own limits so the tray can explain a refusal first.
MAX_MANAGED_KEYS = 64
MAX_MANAGED_BYTES = 64 * 1024
PUBLIC_KEY_TYPES = frozenset({
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
})

WINDOWS_HOST_ONLY = (
    "This Windows gateway uses a loopback SSH endpoint, which can only "
    "accept the host's own authorized keys. Vault-only and combined "
    "policies need the private exec endpoint (Linux and macOS hosts)."
)
MANAGED_IMPORT_HELP = (
    "Vault public keys normally reach this host from the PocketShell web "
    "keys page or a client ('Apply to host'). Importing pastes authorized_keys "
    "lines of PUBLIC keys and replaces the whole managed set. Private keys and "
    "the vault passphrase never belong on the host."
)


class GatewayAuthError(Exception):
    """A refusal with a message that is safe to show to the user."""


@dataclass(frozen=True)
class ManagedKey:
    type: str
    fingerprint: str
    comment: str = ""

    @property
    def display_line(self) -> str:
        parts = [self.type, self.fingerprint]
        if self.comment:
            parts.append(self.comment)
        return " · ".join(parts)


@dataclass(frozen=True)
class GatewayAuthState:
    """What ``gateway auth show --json`` reported, or why it could not."""

    policy: str = "host"
    source: str = "default"  # configured | default
    endpoint: str = ""  # exec | loopback | "" (not enrolled)
    managed_keys: tuple[ManagedKey, ...] = ()
    error: Optional[str] = None

    @classmethod
    def unavailable(cls, reason: str) -> GatewayAuthState:
        return cls(error=reason)

    @property
    def available(self) -> bool:
        return self.error is None

    @property
    def host_only(self) -> bool:
        return self.endpoint == "loopback" or sys.platform == "win32"

    @property
    def summary(self) -> str:
        if not self.available:
            return "Key policy: unknown"
        suffix = "" if self.source == "configured" else ", default"
        return f"Key policy: {self.policy}{suffix}"


def parse_show_output(text: str) -> GatewayAuthState:
    """Parse the helper's one-line JSON; anything unexpected is refused."""
    lines = [line for line in text.strip().splitlines() if line.strip()]
    if not lines:
        raise GatewayAuthError("gateway auth returned no output")
    try:
        doc = json.loads(lines[-1])
    except ValueError:
        raise GatewayAuthError("gateway auth returned output that is not JSON") from None
    if not isinstance(doc, dict):
        raise GatewayAuthError("gateway auth returned an unexpected document")
    policy = doc.get("policy")
    if policy not in POLICIES:
        raise GatewayAuthError(f"gateway auth reported an unknown policy {policy!r}")
    keys_raw = doc.get("managed_keys") or []
    if not isinstance(keys_raw, list):
        raise GatewayAuthError("gateway auth reported malformed managed keys")
    keys = []
    for item in keys_raw:
        if not isinstance(item, dict):
            raise GatewayAuthError("gateway auth reported malformed managed keys")
        keys.append(ManagedKey(
            type=str(item.get("type") or "?"),
            fingerprint=str(item.get("fingerprint") or "?"),
            comment=str(item.get("comment") or ""),
        ))
    return GatewayAuthState(
        policy=policy,
        source=str(doc.get("source") or "default"),
        endpoint=str(doc.get("endpoint") or ""),
        managed_keys=tuple(keys),
    )


def policy_refusal(state: GatewayAuthState, policy: str) -> Optional[str]:
    """Why ``policy`` must not be set on this host, or None when it may."""
    if policy not in POLICIES:
        return f"Unknown policy {policy!r}."
    if not state.available:
        return f"The current key policy could not be read: {state.error}"
    if policy == "host":
        return None
    if state.host_only:
        return WINDOWS_HOST_ONLY
    if state.endpoint != "exec":
        return "Enroll this host with the private exec endpoint before choosing vault keys."
    if policy == "managed" and not state.managed_keys:
        return ("No vault public keys are installed on this host yet, so a vault-only "
                "policy would refuse every login. Import the keys first, or choose "
                "'Host keys and vault keys'.")
    return None


def prefilter_public_keys(text: str) -> list[str]:
    """authorized_keys lines of PUBLIC keys, or a refusal.

    Never echoes the input back: a pasted private key must not end up in a
    dialog, a notification or a log.
    """
    if "PRIVATE KEY" in text:
        raise GatewayAuthError("That is a PRIVATE key. Only public keys (ssh-ed25519 AAAA...) may be imported.")
    if len(text.encode("utf-8")) > MAX_MANAGED_BYTES:
        raise GatewayAuthError(f"Too much input: at most {MAX_MANAGED_BYTES // 1024} KiB of public keys.")
    lines = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if fields[0] not in PUBLIC_KEY_TYPES:
            if "-cert-v01@openssh.com" in fields[0]:
                raise GatewayAuthError(f"Line {number}: certificates are not accepted.")
            raise GatewayAuthError(
                f"Line {number}: expected a public key line starting with a key type "
                "(for example ssh-ed25519); key options are not accepted."
            )
        if len(fields) < 2:
            raise GatewayAuthError(f"Line {number}: the key data is missing.")
        lines.append(" ".join(fields))
    if len(lines) > MAX_MANAGED_KEYS:
        raise GatewayAuthError(f"Too many keys: at most {MAX_MANAGED_KEYS}.")
    return lines


def menu_spec(state: Optional[GatewayAuthState]) -> MenuItemSpec:
    """The 'Gateway key policy' submenu for the tray."""
    if state is None:
        return MenuItemSpec(text="Key policy: checking…", enabled=False)
    children: list[MenuItemSpec] = []
    if not state.available:
        children.append(MenuItemSpec(text=_clip(state.error or "unavailable"), enabled=False))
        children.append(MenuItemSpec(text="Refresh", action_id="gateway_auth_refresh"))
        return MenuItemSpec(text=state.summary, children=tuple(children))

    for policy in POLICIES:
        children.append(MenuItemSpec(
            text=POLICY_LABELS[policy],
            action_id=f"gateway_auth_policy:{policy}",
            # A refused choice stays clickable so the tray can say why.
            checked=policy == state.policy,
        ))
    if state.host_only:
        children.append(MenuItemSpec(text="Windows: host keys only (why?)", action_id="gateway_auth_explain"))
    children.append(MenuItemSpec(text="", is_separator=True))
    key_rows = [MenuItemSpec(text=_clip(k.display_line), enabled=False) for k in state.managed_keys]
    if not key_rows:
        key_rows = [MenuItemSpec(text="(None)", enabled=False)]
    children.append(MenuItemSpec(text=f"Vault keys on this host ({len(state.managed_keys)})",
                                 children=tuple(key_rows)))
    if not state.host_only:
        children.append(MenuItemSpec(text="Import vault public keys from clipboard…",
                                     action_id="gateway_auth_import_clipboard"))
        children.append(MenuItemSpec(text="Import vault public keys from file…",
                                     action_id="gateway_auth_import_file"))
        children.append(MenuItemSpec(text="Remove all vault keys…", action_id="gateway_auth_clear",
                                     enabled=bool(state.managed_keys)))
    children.append(MenuItemSpec(text="Refresh", action_id="gateway_auth_refresh"))
    return MenuItemSpec(text=state.summary, children=tuple(children))


def _clip(text: str, limit: int = 90) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


_CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


class GatewayAuthClient:
    """Runs ``gateway auth show|set --json``; never puts key bytes in argv."""

    def __init__(self, command: Optional[Sequence[str]] = None, *, config_dir: Optional[str] = None,
                 timeout: float = 20.0) -> None:
        self.command = list(command or [sys.executable, "-m", "pocketshell", "gateway", "auth"])
        self.config_dir = config_dir
        self.timeout = timeout

    def _run(self, args: Sequence[str], stdin: bytes = b"") -> subprocess.CompletedProcess:
        kwargs: dict[str, Any] = {"input": stdin, "capture_output": True, "timeout": self.timeout}
        if _CREATE_NO_WINDOW:
            kwargs["creationflags"] = _CREATE_NO_WINDOW
        tail = ["--config-dir", self.config_dir] if self.config_dir else []
        return subprocess.run([*self.command, *args, *tail], **kwargs)

    def _state(self, proc: subprocess.CompletedProcess) -> GatewayAuthState:
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace").strip().splitlines()
            raise GatewayAuthError(_clip(err[-1] if err else f"gateway auth exited with {proc.returncode}", 300))
        return parse_show_output(proc.stdout.decode("utf-8", "replace"))

    def show(self) -> GatewayAuthState:
        try:
            return self._state(self._run(["show", "--json"]))
        except GatewayAuthError as exc:
            return GatewayAuthState.unavailable(str(exc))
        except (OSError, subprocess.TimeoutExpired) as exc:
            return GatewayAuthState.unavailable(f"cannot run gateway auth: {type(exc).__name__}")

    def set_policy(self, current: GatewayAuthState, policy: str) -> GatewayAuthState:
        refusal = policy_refusal(current, policy)
        if refusal:
            raise GatewayAuthError(refusal)
        return self._set(["--policy", policy])

    def replace_managed_keys(self, current: GatewayAuthState, lines: Sequence[str]) -> GatewayAuthState:
        if current.host_only:
            raise GatewayAuthError(WINDOWS_HOST_ONLY)
        if current.policy == "managed" and not lines:
            raise GatewayAuthError("The policy is vault-only; removing every vault key would refuse all logins. "
                                   "Switch the policy first.")
        payload = "".join(line + "\n" for line in lines).encode("utf-8")
        return self._set(["--keys-stdin"], stdin=payload)

    def _set(self, args: Sequence[str], stdin: bytes = b"") -> GatewayAuthState:
        try:
            return self._state(self._run(["set", *args, "--json"], stdin=stdin))
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GatewayAuthError(f"cannot run gateway auth: {type(exc).__name__}") from None
