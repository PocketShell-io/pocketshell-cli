# PocketShell package architecture

PocketShell is a host-side CLI. The source tree is organized around the
feature boundary exposed to the client, not around the historical order in
which individual issues added files.

## Target tree

```text
src/pocketshell/
├── __main__.py                  # python -m pocketshell
├── cli.py                       # root Click composition and daemon lifecycle
├── github.py                    # one-file `github status` integration
├── serve.py                     # one-file foreground HTTP integration
├── agent_log/                   # conversation-log discovery and handoff
├── agents/                      # agent launch plus kind-command CLI
│   ├── cli.py                   # `pocketshell agent`
│   └── kind.py                  # `pocketshell agents kind`
├── cards/                       # typed agent→app cards
│   └── push.py                  # card FCM notification adapter
├── daemon/                      # Unix-socket JSON-RPC server/client
├── engines/                     # engine registry and harness probes
├── env/                         # .env/.envrc parsing and persistence
├── hooks/                       # agent hook installation and event handlers
├── logs/                        # normalized host-side event log
├── profiles/                    # aplexer profile discovery/resolution
├── attachments/                 # uploaded attachment domain
│   ├── cli.py                   # `pocketshell prune-attachments`
│   └── retention.py             # TTL and size-cap policy
├── push/                        # FCM transport and usage-reset pushes
├── repos/                       # local/remote repository discovery
├── runtime/                     # shared host-runtime primitives
│   ├── aplexer.py               # bundled `a` backend adapter
│   ├── cgroups.py               # cgroup/proc agent classifier
│   ├── memcap.py                # session memory-cap policy
│   └── sessions.py              # live-session wire model and probing
├── sessions/                    # aplexer session lifecycle commands
├── tree/                        # durable tree/workspace registry
│   └── workspace_cli.py         # `pocketshell workspaces`
└── usage/                       # the complete usage boundary
    ├── cli.py                   # live/cache/reset-events command modes
    ├── quse.py                  # thin process boundary to quse
    ├── capture/                 # cache, history, durability, quarantine
    └── reset/                   # reset detection and event persistence
```

The remaining root modules are deliberately small integrations shared by more
than one feature package. A new multi-file feature belongs in a package; a
single-file external-tool adapter does not need a package solely to gain an
`__init__.py`.

## Ownership rules

- `cli.py` only composes public command objects and owns daemon lifecycle
  callbacks. Feature behavior stays in the feature package.
- A feature package's `__init__.py` is its public compatibility surface. Code
  inside the package imports implementation modules directly to avoid circular
  imports through the public surface.
- `runtime` owns host primitives shared by unrelated feature packages:
  aplexer resolution, cgroup/proc classification, memory-cap policy, and live
  session enumeration. It has no eager feature-package imports.
- `sessions` owns aplexer lifecycle commands and delegates shared policy and
  enumeration to `runtime`.
- `agents` owns agent launch and the CLI seam for runtime process-kind
  detection. The plural `agents` command and singular `agent` command are
  separate Click commands exposed from the same package.
- `tree` owns the registry and its workspace membership extension. Live
  session enumeration is imported from `runtime`, never duplicated in the
  tree store.
- `cards` owns card persistence and card-specific notification payloads;
  `push` owns the FCM transport and usage-reset payloads.
- `usage` owns PocketShell-specific persistence and client integration:
  capture history, reset-event detection, daemon caching, and push hooks.
  Provider collection, provider schemas, and provider-specific formatting
  belong to `quse`; PocketShell should not reimplement them.

## Dependency direction

```text
root CLI
  └── feature public surfaces
        ├── feature implementation modules
        ├── shared host adapters (runtime, daemon, filesystem stores)
        └── external providers (quse, gh, FCM)
```

Implementation modules may depend downward on shared adapters, but shared
adapters must not import Click command registration. Persistence code should
be reusable by both a CLI command and a daemon handler. Tests should patch the
module that owns the symbol being exercised rather than a re-exporting
package.

## Usage boundary with quse

`quse` is the provider backend: it discovers credentials, calls provider APIs,
normalizes provider records, and formats provider-owned output. PocketShell is
the host integration: it optionally proxies through its daemon, converts
successful live readings into the client wire format, persists captures,
detects resets across captures, and sends best-effort notifications.

When a transformation is provider/schema logic, it should be implemented and
tested in `quse`; when it is PocketShell state or client transport logic, it
stays in `pocketshell.usage`.
