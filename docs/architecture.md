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
├── agents/                      # agent domain
│   ├── kind.py                  # `pocketshell agents kind`
│   ├── conversations/            # conversation-log discovery and handoff
│   │   ├── cli.py               # `pocketshell agent-log`
│   │   ├── handoff.py           # compact cross-agent handoff export
│   │   ├── messages.py          # conversation message extraction
│   │   ├── readers.py           # bounded JSONL reads
│   │   ├── resolve.py           # provider log resolution
│   │   └── roots.py             # provider storage roots
│   └── launch/                  # launch application and execution support
│       ├── cli.py               # `pocketshell agent`
│       ├── command.py            # argv construction
│       ├── environment.py        # launch environment policy
│       ├── run.py                # process execution
│       ├── spec.py               # aplexer launch specs
│       └── trust.py              # provider trust preparation
├── cards/                       # typed agent→app cards
│   ├── types/                   # registry and concrete card behaviors
│   │   ├── registry.py
│   │   ├── checklist.py
│   │   └── note.py
│   └── push.py                  # card FCM notification adapter
├── daemon/                      # Unix-socket JSON-RPC server/client
├── engines/                     # engine registry and harness probes
├── env/                         # .env/.envrc parsing and persistence
├── hooks/                       # agent hook installation and event handlers
│   └── providers/               # provider-specific configuration formats
│       ├── claude.py
│       └── codex.py
├── logs/                        # normalized host-side event log
├── profiles/                    # aplexer profile discovery/resolution
├── attachments/                 # uploaded attachment domain
│   ├── cli.py                   # `pocketshell prune-attachments`
│   └── prune.py                 # TTL and size-cap policy
├── push/                        # FCM transport and usage-reset pushes
├── repos/                       # local/remote repository discovery
├── runtime/                     # shared host-runtime primitives
│   ├── aplexer.py               # bundled `a` backend adapter
│   ├── console_scripts.py       # interpreter-anchored console-script dirs
│   ├── cgroups.py               # cgroup/proc agent classifier
│   ├── memcap.py                # session memory-cap policy
│   └── sessions.py              # live-session wire model and probing
├── sessions/                    # aplexer session lifecycle commands
├── tree/                        # durable tree/workspace registry
│   ├── workspaces/              # workspace membership subdomain
│   │   ├── membership.py        # durable workspace records
│   │   └── cli.py               # `pocketshell workspaces`
│   └── ...                       # tree registry and reconciliation
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
- `agents` owns three related but separate domains: launch preparation and
  execution under `launch/`, conversation discovery and handoff under
  `conversations/`, and live process-kind detection in `kind.py`. The plural
  `agents` command and singular `agent` command remain separate Click
  commands.
- `attachments` owns the uploaded-attachment domain. `cli.py` is only the
  command surface; `prune.py` contains the deletion policy and filesystem
  sweep.
- `tree` owns the registry and reconciliation. Workspace membership is a
  nested subdomain under `tree/workspaces/`; live session enumeration is
  imported from `runtime`, never duplicated in the tree store.
- `cards` owns card persistence and delivery. Concrete card behavior and its
  registry live under `cards/types/`, while FCM notification construction
  remains in `cards/push.py`; `push` owns usage-reset transport.
- `hooks/providers` owns provider-specific configuration formats; installation
  orchestration and generated handlers remain in the parent `hooks` package.
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
be reusable by both a CLI command and a daemon handler. The daemon method
table is an application-composition boundary and may import feature handlers;
transport and protocol modules underneath it must stay reusable. Usage and
push intentionally share capture paths and reset-event records, so that
cross-domain dependency is documented rather than hidden behind re-exports.
Tests should patch the module that owns the symbol being exercised rather than
a re-exporting package.

## Usage boundary with quse

`quse` is the provider backend: it discovers credentials, calls provider APIs,
normalizes provider records, and formats provider-owned output. PocketShell is
the host integration: it optionally proxies through its daemon, converts
successful live readings into the client wire format, persists captures,
detects resets across captures, and sends best-effort notifications.

When a transformation is provider/schema logic, it should be implemented and
tested in `quse`; when it is PocketShell state or client transport logic, it
stays in `pocketshell.usage`.

## Aplexer boundary

The checked-out aplexer implementation is the source of truth for the
session runtime and for agent launch resolution. PocketShell must consume that
authority rather than grow a parallel implementation.

| Aplexer owns | PocketShell keeps |
| --- | --- |
| Engine/profile configuration and discovery (`a engines`, `a profiles`) | Picker-facing labels, usage-provider metadata, host availability probes, and the optional PocketShell presentation/config layer in `engines/` and `profiles/` |
| Launch argv, profile environment, provider-key removal, cwd, and skip-permission arguments (`a launch-spec`) | Folder `.env`/`.envrc` exports, explicit profile-to-directory UX, Claude trust seeding, binary preflight, and the thin `launch-spec` adapter |
| Session creation/claiming, worker and workload lifecycle, PTY/history/cgroup containment, `start`, `snapshot`, `status`, `attach`, `kill`, and `forget` | Schema-3 rows, display-name/target resolution, idempotent create policy, memory-cap policy, attach chrome suppression, JSON envelopes, and client-facing recovery diagnostics |
| Query-time agent/profile detection for a recorded session | `agents.kind_for_panes`, which classifies arbitrary pane PIDs and therefore has a different input and client contract |

The `runtime/aplexer.py` module is only the bundled-binary integrity and
subprocess boundary. `runtime/sessions.py` is only a client-wire model and
normalizer. Neither is a second session backend.

The old host-side launch metadata hooks were removed because they were no-op
compatibility shims after aplexer became the owner of session metadata. The
old host-side dead-record reaper was removed for the same reason: `a start`
owns workspace/tag reclamation, while `a kill` reports whether its own final
record removal succeeded. PocketShell does not issue a second `forget --force`
or inspect workload PIDs to reproduce those lifecycle decisions. The
remaining native engine/profile launch code is intentionally fallback and
presentation code for custom PocketShell configuration and hosts where the
`a` launcher probe is disabled; it is not authoritative on the normal Linux
path. Any future removal of that fallback must first migrate those custom
configuration fields into aplexer.
