"""Shared host-runtime primitives used by PocketShell feature packages.

The runtime layer contains adapters and host-state readers whose callers span
multiple CLI features.  It intentionally has no eager feature-package imports
so agents, sessions, profiles, engines, and tree code can depend on it without
creating an import cycle.
"""
