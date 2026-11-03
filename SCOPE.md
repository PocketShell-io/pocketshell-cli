# PocketShell scope

The [PocketShell product charter](https://github.com/PocketShell-io/pocketshell/blob/main/SCOPE.md)
is the scope policy for this repository, including its in-scope, owner-labelled
NOT and "Removed (Hub owns this)" lists.

This repo: the host access adapter for human terminals and local display-only
`quse`. Cards, push notifications, quota history/capture/reset detection,
agent conversation handoff exports, and Hub-managed agent automation are
outside this repo's scope. Manual `pocketshell agent` launches and active
`pocketshell hooks` event handlers remain for local use.

PocketShell must work without Hub. Hub owns managed agent work and may stop/delete
any session, including manual PocketShell/psc sessions; PocketShell owns live human access.
