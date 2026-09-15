"""The aplexer-only ``pocketshell sessions`` command group."""
from __future__ import annotations

from pocketshell.sessions.attach import (
    ATTACH_EXIT_NOT_FOUND,
    ATTACH_EXIT_AMBIGUOUS,
    ATTACH_EXIT_NO_BINARY,
    APLEXER_ID_PREFIX_MIN,
    _exec,
    _match_attach_target,
    _attach_live_rows,
    sessions_attach,
)
from pocketshell.sessions.cli import (
    sessions_group,
)
from pocketshell.sessions.create import (
    CREATE_SCHEMA_VERSION,
    _CreateError,
    _resolve_aplexer,
    _aplexer_unresolved_message,
    _run_aplexer,
    _aplexer_snapshot,
    aplexer_start_argv,
    _cap_unenforceable_hint,
    _create_on_aplexer,
    sessions_create,
)
from pocketshell.sessions.kill import (
    KILL_SCHEMA_VERSION,
    sessions_kill,
)
from pocketshell.sessions.rename import (
    RENAME_SCHEMA_VERSION,
    sessions_rename,
)
from pocketshell.sessions.listing import (
    _emit_envelope,
    _try_daemon_sessions_list,
    _list_envelope,
    daemon_handler_list,
    sessions_list,
)
from pocketshell.runtime import memcap as _memcap  # noqa: F401  (tests patch sessions._memcap)
from pocketshell import profiles as _profiles  # noqa: F401  (tests patch sessions._profiles)
from pocketshell.runtime import sessions as _session_enum  # noqa: F401  (tests patch sessions._session_enum)

__all__ = [
    "sessions_group",
    "CREATE_SCHEMA_VERSION",
    "KILL_SCHEMA_VERSION",
    "_emit_envelope",
    "_try_daemon_sessions_list",
    "_list_envelope",
    "daemon_handler_list",
    "sessions_list",
    "_CreateError",
    "_resolve_aplexer",
    "_aplexer_unresolved_message",
    "_run_aplexer",
    "_aplexer_snapshot",
    "aplexer_start_argv",
    "_cap_unenforceable_hint",
    "_create_on_aplexer",
    "sessions_create",
    "ATTACH_EXIT_NOT_FOUND",
    "ATTACH_EXIT_AMBIGUOUS",
    "ATTACH_EXIT_NO_BINARY",
    "APLEXER_ID_PREFIX_MIN",
    "_exec",
    "_match_attach_target",
    "_attach_live_rows",
    "sessions_attach",
    "sessions_kill",
    "RENAME_SCHEMA_VERSION",
    "sessions_rename",
]
