# Login through a TLS-intercepting egress proxy (design and blocker)

Status: **broker deployed and production key pinned (2026-11-27).**
The plain path still refuses an intercepting proxy, which is correct. The opt-in
sealed transport (`POCKETSHELL_BROKER_SEALED=1`, `pocketshell.account.sealed`) is
in this repo, and its broker route came from PocketShell-io/pocketshell-sync PR #3
(`docs/SEALED-TRANSPORT.md` there has the wire format and the key runbook). The
broker serves `POST /sealed` with the SSM key `/pocketshell-sync/sealed-transport-key`;
its public half is pinned in `PINNED_KEYS` (`sealed.py`, kid `575a6a86`). Sealed
mode works from the first CLI release that contains this pin.

Rotation is not supported yet: the broker accepts only its current key, so the
CLI must pin exactly one key until the broker accepts a current+previous pair.

Usage once released: `POCKETSHELL_BROKER_SEALED=1 pocketshell login --no-open`
with the sandbox's `HTTPS_PROXY` (and CA bundle) set. Sealed mode applies to
`login`, `whoami`, `logout` and token mints against the production broker only.
`pocketshell gateway ssh/proxy` talk to the gateway, not the broker, and are not
covered.

## The case

Some managed cloud sandboxes have no direct DNS or routing. Their only egress
is an environment HTTP proxy (`HTTPS_PROXY`) that terminates TLS and
re-signs it with its own CA. For example, a `CONNECT` probe of the production
broker through one such proxy completes, but the leaf certificate is issued by
the proxy operator, not by a public CA. Everything sent inside that "TLS"
session is readable by the proxy, including `device_code` and the `psc_`
session token returned by `/auth/device/token`.

## Why the current client refuses (and must keep refusing)

See [account.md](account.md#network-and-trust). Token-bearing requests ignore
proxy variables and `SSL_CERT_FILE`/`SSL_CERT_DIR`, never follow redirects, and
verify against the platform CA bundle only.

Each of the usual fixes breaks that guarantee:

| Change | Why it is not acceptable |
| --- | --- |
| Honour `HTTPS_PROXY` | Direct DNS fails, so this is needed, but alone it makes the request go to the interceptor and then fail certificate verification. |
| Also trust the proxy CA / `SSL_CERT_FILE` | The proxy then reads `device_code` and the 30-day `psc_` token. The proxy is an eavesdropper by construction. |
| Insecure mode, pinning the proxy leaf | Same disclosure. |
| Pinning the broker's own TLS leaf | Fails closed, as it should: the proxy presents a different leaf, so nothing completes. |

TLS between the CLI and the broker cannot be end-to-end through this proxy, so
the protection has to live **above TLS**.

## Verified facts

- Broker: AWS API Gateway HTTP API + Lambda in eu-west-1 (default endpoint
  `https://a7sota2qic.execute-api.eu-west-1.amazonaws.com`). Canonical repo:
  private `PocketShell-io/pocketshell-sync` (`lambda/device-flow.mjs`,
  `docs/CLI-DEVICE-FLOW.md`). Infra stack lives in `aws-infra`.
- Nothing in that repo (or in this one) provides an application-layer sealed
  channel, a pinned broker key for the CLI, or a first-party tunnel that avoids
  the interceptor. The only broker public key is the RS256 gateway-JWT key at
  `GET /gateway/jwks`, which signs tokens and cannot be used to protect a
  request, and which would itself be fetched through the proxy.
- This repo's latest PyPI release when checked was 0.5.15; `main` is 0.5.16.
  No released version supports this case.

## Design (as implemented)

Use an established construction, not custom crypto: **HPKE (RFC 9180) with
Oblivious-HTTP-style request/response encapsulation (RFC 9458)**. The proxy
acts as the (untrusted) relay.

1. The broker publishes an HPKE key config (for example DHKEM(P-256) or
   X25519, HKDF-SHA256, AES-128-GCM). The private key stays server-side; with
   P-256 it can stay in AWS KMS (`DeriveSharedSecret`).
2. The **public key and key id are pinned inside the CLI release**, with a short
   list of accepted keys for rotation. It is never fetched through the proxy
   and never taken from the environment.
3. A new broker route accepts `POST` of an encapsulated request (`message/ohttp-req`
   style): the inner request is the existing `/auth/device/start`,
   `/auth/device/token`, `/cli/gateway/token`, `/cli/session` or `/cli/logout`
   call, including its body and `Authorization` header. The Lambda decapsulates,
   dispatches internally to the existing handlers and encapsulates the
   response, so `device_code` and `psc_` never appear in clear outside the
   client and the Lambda. The `Origin`-refusal rule applies to the inner request.
4. The CLI uses this transport only when explicitly opted in (`POCKETSHELL_BROKER_SEALED=1`, exact value). The default direct
   TLS path is unchanged.
5. In sealed mode the outer connection may use the environment proxy and its CA,
   but carries only ciphertext and public routing data. There is no fallback to
   the plain path in either direction: any decapsulation, key id, length or
   replay failure aborts the command.
6. Only the approved origins are contacted, with no redirects. The verification
   URL printed to the user stays pinned to `https://app.pocketshell.io`. The
   user approves in their own browser, so the cloud never holds a browser session.

Residual exposure the proxy still has: it sees that a login happened, its timing
and size, and can withhold service. It cannot read or alter the credentials.

## Work split

- `pocketshell-sync` (broker): key config, sealed route, tests with fixed vectors,
  deploy. This must land and be deployed first. It needs an owner decision on
  key custody (KMS vs Secrets Manager) and rollout.
- `pocketshell-cli` (this repo): pinned key list, opt-in transport in
  `pocketshell.account.broker`, a vetted HPKE implementation (for example
  `cryptography`'s HPKE support if the pinned version has it, otherwise a
  maintained library), and tests against the broker vectors: synthetic secrets,
  an intercepting fake proxy that records every byte, a wrong-key broker, and
  replay/truncation cases.
- Hub: nothing, except tracking the dependency.

## What was not verified

The cloud sandbox itself was not reachable from the worker that wrote this, so
the real proxy behaviour above rests on the probe reported in the task. No
login credentials were created or sent.
