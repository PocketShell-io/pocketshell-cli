# Link transport — reaching hosts without inbound SSH

Status: implemented (CLI reference daemon + relay, core `LinkCapability`).

## Problem

PocketShell clients reach a host over SSH. Laptops, home and office machines
behind NAT have no inbound SSH: a phone on mobile data, or a desktop on a
different network, cannot reach them at all — no sessions, no attach, no
tree. The host is not a server; we cannot ask users to port-forward or
expose `sshd`.

## Idea

The host dials OUT to a relay over an outbound WebSocket and keeps that
socket alive. Clients also dial the relay. The relay pairs the legs by
`host_id` and forwards channel frames between them. No inbound connectivity
is ever required at the host; the only requirement is that the host can make
outbound WebSocket connections — the same requirement a browser has.

The transport enters at the `SshCapability` seam
(`pocketshell-core/src/sshCapability.ts`): `ConnectionController`,
`HostCliCore` and `AplexerCore` sit on that interface and are
transport-agnostic by construction, so session create stays an `exec` of
`pocketshell sessions create …`, attach stays a PTY on `a attach …`, and the
tree stays an `exec` of `pocketshell tree --json` — byte-identical commands,
just over link instead of SSH. SFTP and port forwarding are the two things a
relay cannot carry; they fail with a typed `UNSUPPORTED` error instead of
silently misbehaving.

## Components

### 0. Client glue — implemented (transport level)

- **Desktop**: `LinkTransport.ts` shapes the link capability as an ssh2
  client, so `SshService.connect` registers a link dial in the same
  registry and every consumer (exec, tracked shells, SFTP/port-forward
  failures) works unchanged; `tests/integration/LinkTransport.integration`
  drives a real relay+daemon in containers. The renderer still needs the
  "Link host" form + per-host token storage (keychain) — the IPC payload
  (`link`, `linkToken`) is ready for it.
- **Web**: `src/terminal/linkConnection.ts` adapts the capability to the
  browser's `SshConnection` surface; `webApi.connectHost` routes a synced
  host with `entry.link` to it, the relay token riding the vault's
  password slot. `tests/linkConnection.test.ts` drives a canned host.
- **Android/shared app**: the hub's controller factory receives the dial
  target; `platform/android/linkCapability.ts` swaps in core's link
  capability (WebView WebSocket, no native-plugin involvement) for
  `link-token` targets; the host store saves/resolves link hosts. Until
  the pocketshell-core submodule pin is bumped (after committing core),
  the app's source-integrity gate reports the vendored diff — expected.
- Add-a-link-host UI (all three) and a managed relay with real auth are
  the remaining product work; everything below the UI ships and tests.

### 1. Host daemon — `pocketshell link run` (this CLI)

Runs on the NAT'd machine, foreground or under a systemd unit:

```
pocketshell link run --relay wss://relay.example:8765 \
                     --token "$POCKETSHELL_LINK_TOKEN" \
                     --host-id my-laptop [--name "Alexey laptop"]
```

- Dials `<relay>/host?token=…&host_id=…`, sends `hello`, waits for `ready`,
  then serves channels until the socket drops.
- Reconnects forever with capped exponential backoff (0.5 s → 30 s, jitter);
  the backoff resets after a healthy minute of uptime. A relay restart or a
  laptop sleep/wake is invisible to clients beyond in-flight operations
  failing.
- `--token` honours `POCKETSHELL_LINK_TOKEN` and accepts `-` (one line from
  stdin) so tokens stay out of shell history and `ps`.

The daemon is a generic exec/PTY executor: exec channels run a shell command
(`subprocess`, separate stderr channel), PTY channels run under a real
terminal (`os.openpty`, controlling tty, `TIOCSWINSZ` resize). It knows
nothing about sessions, aplexer or workspaces — the trust surface is exactly
"someone with a shell on this box".

### 2. Reference relay — `pocketshell relay serve` (this CLI)

```
pocketshell relay serve --listen 0.0.0.0:8765 --token "$POCKETSHELL_LINK_TOKEN"
```

- One shared token for both legs (personal relay; a managed multi-tenant
  relay comes later).
- Host leg: `GET /host?token=…&host_id=…` registers the socket (last
  registration wins; the stale socket is closed).
- Client leg: `GET /client?token=…&host_id=…` pairs with the registered
  host or is rejected with an `error` frame `HOST_OFFLINE`.
- Channel-id namespacing: client channel ids are per client connection; the
  relay rewrites them into a host-connection counter and keeps a
  bidirectional map, so two clients (phone + desktop) attached to the same
  laptop cannot collide. The relay never inspects payload bytes.

Deploy it wherever inbound TCP works (VPS, forwarded port, tunnel target).
Serve WSS in production (TLS terminator in front is fine).

### 3. Core capability — `LinkCapability` (pocketshell-core)

`src/linkCapability.ts` implements `SshCapability` on top of one client
WebSocket. The socket is injected as a `LinkSocketFactory`, so the desktop
main process passes Electron's `ws`, the web client passes the browser's
native `WebSocket`, and tests pass an in-memory pair. Mapping:

| SshCapability | link protocol |
| --- | --- |
| `connect` | dial + `hello`/`ready`; synthesizes a `PresentedHostKey` (see trust model) |
| `exec` | `open` mode `exec` → binary stdout frames, stderr on `err_ch`, `exit` |
| `openPty` | `open` mode `pty` (`cmd`, `cols`, `rows`, `term`) |
| `readPty` | per-channel buffer; `waitMs` bounds the wait |
| `writePty` / `resizePty` / `closePty` | binary frame / `resize` / `close` |
| connection state | socket close → `connectionState` event `lost` |
| `sftp*`, `openPortForward` | `SshCapabilityError` code `UNSUPPORTED` |
| `timeoutMs` (exec) | enforced client-side; expiry sends `close`, `timedOut: true` |

### 4. Clients (glue only)

- **Desktop**: a "Link" host type (relay URL + token + host id) whose
  connections are served by a `LinkService` beside
  `src/main/ssh/SshService.ts` (the desktop implements SSH in its Electron
  main, not through core's controller).
- **Web**: a link transport beside `src/terminal/direct.ts` — the web client
  has its own WebSocket seam (browser runs the client itself over the dumb
  CF relay for SSH); link plugs in as a sibling transport.
- **Android**: the one client that consumes `SshCapability` directly
  (`SshCapabilityPlugin.java`); it either speaks the link protocol natively
  in a sibling plugin or proxies through a thin WS bridge into the existing
  plugin surface.

### 5. Exec stdin (protocol v1 addition)

Client data frames on an exec channel are the command's stdin; the
client→host `eof` control frame is its EOF (the daemon closes the pipe).
The relay forwards `eof` like `resize`/`close`. `pocketshell env set`
feeds its JSON payload this way — stdin never touches a command line.

## Protocol (v1)

One WebSocket per role. Control frames are JSON text with `v` (version) and
`t` (type). Channel data rides binary frames: `u32BE channel-id | payload`.
The token rides the query string so both legs authenticate on the HTTP
upgrade itself; a relay must reject bad tokens with HTTP 401 before
upgrading.

Handshake:

```
client  {"v":1,"t":"hello","role":"client","host_id":"laptop","proto":1}
relay   {"v":1,"t":"ready","host_name":"…"}          (after pairing)
        {"v":1,"t":"error","code":"HOST_OFFLINE"}    (or, if unpaired)
host    {"v":1,"t":"hello","role":"host","host_id":"laptop","proto":1,"name":…}
relay   {"v":1,"t":"ready"}
```

Channels (client → relay → host; the relay rewrites `ch` in both
directions):

```
client→ {"v":1,"t":"open","ch":7,"mode":"exec","cmd":"pocketshell tree --json","timeout_ms":15000}
        {"v":1,"t":"open","ch":8,"mode":"pty","cmd":"a attach --no-status s1","cols":80,"rows":24,"term":"xterm-256color"}
host→   {"v":1,"t":"opened","ch":H,"ok":true,"err_ch":H2}     (err_ch for exec only)
host→   {"v":1,"t":"opened","ch":H,"ok":false,"code":"EXEC_SPAWN_FAILED","message":"…"}
both    binary: u32BE ch | bytes                              (pty io / exec stdout / stderr → err_ch)
host→   {"v":1,"t":"exit","ch":H,"exit_code":0,"timed_out":false}
host→   {"v":1,"t":"eof","ch":H}                              (pty child ended; exit follows)
client→ binary on exec main channel: stdin bytes for the command
client→ {"v":1,"t":"eof","ch":H}   (client→host: exec stdin EOF; host→client:
                                    the PTY child ended — direction disambiguates)
client→ {"v":1,"t":"resize","ch":H,"cols":100,"rows":40}
client→ {"v":1,"t":"close","ch":H}
host→   {"v":1,"t":"ch_error","ch":H,"code":"…","message":"…"}
```

Error codes: `UNSUPPORTED`, `EXEC_SPAWN_FAILED`, `PTY_OPEN_FAILED`,
`NO_SUCH_CHANNEL`, `HOST_OFFLINE`, `AUTH_FAILED`, `PROTOCOL_ERROR`.

Compatibility rule: unknown `t` is ignored, unknown fields are ignored, a
`proto` mismatch is answered with `PROTOCOL_ERROR`. v2 can add frames
without breaking v1 daemons.

## Trust model

The shared token authenticates both directions; WSS gives confidentiality on
the wire. There is no SSH host key on a link host — the synthesized
`PresentedHostKey` fingerprint is `SHA256:` over
`"pocketshell-link-v1|" + canonical relay URL + "|" + SHA256(token)`, and
`LinkCapability` verifies it against the stored pin with the regular
`verifyHostKeyTrustPin` path. That buys TOFU pinning for free: if the relay
URL or token changes, the user sees the existing host-key-change UX instead
of a silent re-auth. Pinning does not protect against a malicious relay (the
relay sees the token); it makes configuration mistakes visible.

## Not supported over link (v1)

- SFTP (browse/upload/download) and port forwarding → typed `UNSUPPORTED`.
- Everything else clients do — sessions, attach, tree, usage capture — works
  unchanged, including multiple concurrent clients per host.

## Testing

- `tests/link/test_protocol.py` — codec unit tests.
- `tests/link/test_loopback.py` — real relay + real daemon in-process:
  auth failure, host-offline, exec (stdout/stderr/exit), exec timeout, PTY
  round-trip, two-client namespacing, host reconnect, bad hello.
- `tests/docker/link/e2e.sh` — the NAT proof: relay container publishes one
  loopback port; the host container publishes NOTHING and dials out; the
  client container execs and drives a PTY inside the host container purely
  through the relay.
- `pocketshell-core/tests/linkCapability.test.ts` — vitest against an
  in-memory socket pair: connect/TOFU, exec, timeout, PTY io/resize,
  UNSUPPORTED, connection-lost events.

## Later

- Managed relay (Cognito auth, per-user tokens, TLS) in aws-infra.
- Windows hosts: the daemon needs a ConPTY equivalent for PTY channels.
- Link-host inventory in the clients (list of hosts registered on a relay).
