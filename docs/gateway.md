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
| `--insecure-dev` | yes, never defaulted | off |

## 1. Install the helper

`pocketshell` does **not** bundle or download `pocketshell-link` (and accepts
no credentials for fetching it). Build it from a checkout of the private
`pocketshell-gateway-tunnel` repository — you need access to that repo and a
Go toolchain:

```bash
cd /path/to/pocketshell-gateway-tunnel
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

There are two distinct key relationships, and keeping them separate is the
point of the design:

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

## 3. Enroll the host

One-time per host (repeat to re-enroll). You need a fresh Google ID token for
the account your PocketShell client is signed in with — obtain it from the
client / gateway tooling and pipe it in:

```bash
google-token print | pocketshell gateway enroll --token-stdin
```

Useful flags:

```bash
pocketshell gateway enroll --token-stdin \
    --device-id "office workstation" \
    --ssh-host 127.0.0.1:22 \
    --expect-host-key "SHA256:AbCd…/Fp="
```

- `--token-stdin` is required; `enroll` refuses to run without it. The token
  only ever travels inside the enroll request body — never in a URL, argv, or
  log line.
- `--expect-host-key` pins the sshd host key you expect; a mismatch aborts
  enrollment. Without it, the helper still probes and pins whatever the local
  sshd presents — pass the flag when you can verify the fingerprint.
- The Google account identity (issuer + subject) is what the gateway checks;
  device registration additionally requires proof of possession of the
  generated device key.

## 4. Run the agent

```bash
pocketshell gateway run
```

Foreground process; stop with Ctrl+C or SIGTERM (clean exit 0). It reads the
state written by `enroll` from the config dir. `--server` overrides the
enrolled URL; `--verbose` turns on debug logging (to stderr). Run it under
your supervisor of choice (systemd user unit, tmux, …).

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

Against a gateway running locally or in Docker (plain `ws://`, no TLS):

```bash
pocketshell gateway enroll --token-stdin \
    --server ws://gateway:8080 --insecure-dev
pocketshell gateway run --server ws://gateway:8080 --insecure-dev
```

`--insecure-dev` must be passed explicitly on **every** command that talks to
a plain `ws://` / `http://` URL; it is never sticky and never defaulted. It
exists for development only: TLS certificate verification is never skipped
either way, and the local SSH bridge stays loopback-only even in dev mode.

## 7. Relationship to the legacy `link` transport

This is a different protocol from the older experimental transport, and the
two are **not interoperable**:

| | `pocketshell gateway …` (this doc) | `pocketshell link run` / `pocketshell relay serve` |
| --- | --- | --- |
| Transport | Go `pocketshell-link` helper → SSH gateway | Python daemon → generic relay (`docs/link-transport.md`) |
| Auth | Per-device Ed25519 key enrolled via Google-account challenge | One shared relay token (`--token`) |
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
already uses it.
