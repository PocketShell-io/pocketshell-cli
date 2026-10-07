# Gateway host agent: `pocketshell gateway`

`pocketshell gateway enroll|run|show` are the user-facing entry points for the
PocketShell **gateway transport**: the reverse-tunnel host agent for machines
that have no inbound SSH (a phone cannot dial into a laptop behind NAT). The
host holds one outbound WSS connection to the SSH gateway; the gateway opens
multiplexed streams over it, each bridged to the host's own sshd listening on
loopback. No inbound ports are opened anywhere.

The Python commands are deliberately thin: they resolve the installed Go
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

Options you omit are not forwarded at all, so the helper's own defaults
apply — this CLI does not carry a second copy of them:

| Option | Forwarded only when passed | Helper default |
| --- | --- | --- |
| `--server` | yes | `wss://gateway.pocketshell.io` |
| `--config-dir` | yes | `${XDG_CONFIG_HOME:-$HOME/.config}/pocketshell-link` |
| `--ssh-host` | yes (`enroll`) | `127.0.0.1:22`, loopback only |
| `--device-id` | yes (`enroll`) | auto-generated from the hostname |
| `--expect-host-key` | yes (`enroll`) | none (the probed key is pinned unverified) |
| `--re-enroll` | yes (`enroll`) | off — re-enrollment is refused without it |
| `--dev-broker-issuer` | yes (`enroll`, dev-guarded) | production broker issuer |
| `--insecure-dev` | yes, never defaulted | off |

## 1. Install the helper

`pocketshell` does **not** bundle or download `pocketshell-link` (and accepts
no credentials for fetching it). Build it from a checkout of the private
[pocketshell-gateway](https://github.com/PocketShell-io/pocketshell-gateway)
repository — you need access to that repo and a Go toolchain:

```bash
cd /path/to/pocketshell-gateway
go build -o "$HOME/.local/bin/pocketshell-link" ./cmd/pocketshell-link
```

Resolution order, and what happens when it fails:

1. `POCKETSHELL_GATEWAY_HELPER` — an explicit pin to a trusted binary. A pin
   that is missing or not executable is a hard error; the wrapper never
   silently falls back to a different binary off PATH.
2. `pocketshell-link` on `PATH`.

With neither, every `gateway` subcommand exits **127** and prints the build
instructions above. (The helper's other subcommands, e.g.
`pocketshell-link version`, are reachable by calling the helper directly;
this CLI wraps exactly `enroll`, `run`, and `show`.)

How the helper is *distributed* — today (build it yourself), the planned
checksum-verified platform wheels, which platforms are unsupported, and why
the wrapper performs no version check yet — is specified in
[docs/gateway-distribution.md](gateway-distribution.md).

## 2. Prerequisites on the host

The tunnel carries **real SSH, end to end**. It is not a shell-execution
protocol: the SSH session terminates at your host's own sshd, with standard
SSH cryptography between the client and sshd. That makes the prerequisites
the ordinary ones for SSH-ing into this machine:

- **A running local sshd** reachable on loopback (default `127.0.0.1:22`).
  The helper only ever bridges to a loopback address — a non-loopback
  `--ssh-host` is rejected.
- **Key-based access configured.** Put the client device's SSH public key in
  your `~/.ssh/authorized_keys` for the user who will connect. This pairing
  is entirely between you and your host: the gateway never issues, stores, or
  brokers your SSH user keys.
- **Your sshd host key fingerprint**, if you want to pin it explicitly at
  enroll time (recommended):

  ```bash
  ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
  # 256 SHA256:AbCd…/Fp= (ED25519)
  ```

There are four distinct credential relationships, and keeping them separate
is the point of the design:

- **Host key (sshd → client):** your sshd's real public host key. `enroll`
  probes it over loopback and pins it in the local state; the tunnel-side
  client expects exactly that key. Pass `--expect-host-key` with the
  authorized_keys line or the `SHA256:…` fingerprint to abort enrollment if
  the probed key is not the one you expected (e.g. an unexpected listener on
  port 22).
- **User key (client → sshd):** regular `authorized_keys` authentication for
  your user account. Unchanged by the gateway; you provision it yourself.
- **Device key (host agent → gateway):** an Ed25519 keypair generated locally
  at enroll time, used to prove device identity to the gateway via a signed
  challenge. It authorizes a *tunnel to sshd*, never a *shell*: a paired
  device still needs a valid SSH user key to get past sshd.
- **Enrollment token (operator → gateway):** a short-lived (≤ 5 minutes)
  RS256 JWT scoped to `pocketshell-gateway`, minted by the trusted PocketShell
  token service (`https://a7sota2qic.execute-api.eu-west-1.amazonaws.com`,
  `POST /gateway/token`) in exchange for your web-client sign-in. The
  gateway verifies this broker token only — your raw account sign-in
  credential never reaches the gateway. The token authorizes identity
  management and routing during enrollment, nothing more, and expires within
  five minutes (or with your upstream sign-in, whichever is sooner).

## 3. Enroll the host

One-time per host. You need a fresh **gateway enrollment token** — a
short-lived (≤ 5 minutes) token scoped to `pocketshell-gateway`, minted by
the trusted PocketShell token service in exchange for your web-client
sign-in. Generate it in the PocketShell web client's gateway settings
(**Generate enrollment token**), then pipe it in:

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
    --device-id "office workstation" \
    --ssh-host 127.0.0.1:22 \
    --expect-host-key "SHA256:AbCd…/Fp=" \
    --re-enroll
```

- `--token-stdin` is required; `enroll` refuses to run without it. The token
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

Run it under any supervisor. A reproducible **systemd user unit** (no root,
runs as the same user who enrolled — so it sees the same config dir, the
pinned host key, and the device key; the helper is pinned by absolute path
so the unit cannot be satisfied by an arbitrary binary that happens to be on
PATH; no `--ssh-host` override: the unit serves exactly the enrolled
loopback sshd):

```ini
# ~/.config/systemd/user/pocketshell-gateway.service
[Unit]
Description=PocketShell gateway host agent (reverse tunnel)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%h/.local/bin/pocketshell gateway run --verbose
Environment=POCKETSHELL_GATEWAY_HELPER=%h/.local/bin/pocketshell-link
# XDG_CONFIG_HOME must match the enroll-time value; the default below is
# what `gateway enroll` used when the variable was unset for that user.
Environment=XDG_CONFIG_HOME=%h/.config
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now pocketshell-gateway.service
journalctl --user -u pocketshell-gateway.service -f
```

Adjust the two absolute paths (`ExecStart`, `POCKETSHELL_GATEWAY_HELPER`) to
where `pocketshell` and the built `pocketshell-link` actually live for this
user — `pocketshell gateway show` must run as this same user and print the
enrolled state before you enable the unit; if it prints nothing, the unit
would enroll nothing either.

## 5. Show the enrolled state

```bash
pocketshell gateway show
# server:            wss://gateway.pocketshell.io
# device id:         …
# local ssh:         127.0.0.1:22 (loopback only)
# device key:        SHA256:…
# pinned ssh host key: …
```

`show` prints no secrets (the device private key stays in its `0600` file in
the config dir).

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
  `--insecure-dev`, without an explicit `--server`, and never lets it target
  the production gateway.
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
  bridges only to the configured loopback sshd endpoint (default
  `127.0.0.1:22`), and `--insecure-dev` never lifts that. Enrollment probes
  and pins the lab host's real sshd host key independently of the enrollment
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

`pocketshell gateway` documents and wraps the host-side agent only. How the
PocketShell phone/desktop app pairs and connects through this tunnel is
separate, in-progress work elsewhere; nothing here implies that any client
already uses it. The same goes for the enrollment-token flow: the web
client's **Generate enrollment token** action and its broker exchange are
being built (web client and token-service integration in progress, not
deployed/production yet) — until they land, obtain tokens from lab tooling
as in §6. This wrapper treats the token on stdin as opaque bytes either way;
it will not change when the issuer UI ships.
