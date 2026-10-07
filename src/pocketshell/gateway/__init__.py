"""PocketShell gateway host agent: user-facing wrappers for the Go
`pocketshell-link` helper (``pocketshell gateway enroll|run|show``).

The wrappers exec the installed Go binary (see
:mod:`pocketshell.gateway.helper`); no transport, enrollment, or SSH logic
lives in Python. Independent from the legacy shared-token
:mod:`pocketshell.link` transport.
"""

from pocketshell.gateway.cli import gateway_group

__all__ = ["gateway_group"]
