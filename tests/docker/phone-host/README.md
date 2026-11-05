# Disposable phone acceptance host

This image runs the selected CLI revision as an ordinary `orin` container user.
Its gateway connection is outbound WSS. The SSH endpoint is a private
`sshd -i` process per stream, with public-key authentication. It publishes no
ports and uses no host SSH server, host account credentials or Docker socket.

Build from a clean source archive in a temporary context containing:

- `cli/`: `git archive` of the exact CLI revision under test;
- `helper/`: a linux-amd64 helper wheel verified against its trusted CI manifest;
- `tests/docker/phone-host/`: this fixture directory.

Pass `--build-arg CLI_REVISION=<full commit>` and
`--build-arg HELPER_SHA256=<trusted embedded binary digest>` and use this
Dockerfile. The build verifies the installed helper bytes before ensuring its
executable permission (pip may not preserve a data file's execute bit). Keep
credentials outside the build context. Do not commit or bake generated keys,
account sessions or enrollment tokens into an image.

Run with a dedicated named volume on `/home/orin`, `--cap-drop ALL`,
`--security-opt no-new-privileges`, resource limits and no `-p` flags or host
mounts. In the running container, use `pocketshell login --no-open` with the
test account, then `pocketshell gateway enroll --device-id <unique-test-id>`.
Approve the CLI pairing using that same account. The entrypoint starts the
outbound agent after enrollment succeeds.

Authorize only the phone-generated **public** client key in the private
endpoint's `authorized_keys` (mode 0600); never transfer the phone's private
key. Read and independently compare the container's host public key with the
phone's pin. Verify an actual terminal command from the phone, a rejected
unrelated account, and `docker port <name>` showing no published ports.
Sign out/revoke the fixture's own CLI session and remove its registration
before retiring the disposable container and its volume.
