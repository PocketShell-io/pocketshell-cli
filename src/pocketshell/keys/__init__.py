"""Device-password-protected SSH key vault (``pocketshell keys``, docs/keys.md).

Private keys are stored encrypted (PBKDF2-SHA256 → AES-256-GCM, the
web/desktop clients' envelope parameters) under a password that never
leaves this device and is never stored. ``gateway ssh --key NAME`` loads
one into a private, short-lived ssh-agent for a single session.
"""

from pocketshell.keys.cli import keys_group

__all__ = ["keys_group"]
