#!/usr/bin/env bash
# Link-transport E2E: the NAT proof.
#
#   relay container  — publishes ONE port, to the operator's loopback only
#   host container   — publishes NOTHING (this is the NAT'd laptop)
#   client container — reaches the host only through the relay
#
# Every assertion runs from the client container: exec, stderr separation,
# PTY write/echo/resize/exit. If `docker port link-e2e-host` is non-empty,
# the proof is void.
set -euo pipefail

cd "$(dirname "$0")/../../.."   # repo root (tests/docker/link -> repo)

NET=link-e2e-net
RELAY=link-e2e-relay
HOST=link-e2e-host
CLIENT=link-e2e-client
TOKEN=link-e2e-token-$$
IMAGE=python:3.12-slim

cleanup() {
  docker rm -f "$RELAY" "$HOST" "$CLIENT" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== building stage: network + containers"
docker network create "$NET" >/dev/null
# The relay is the only thing with inbound reachability; its published port
# binds to the operator's loopback (where real users would run TLS in front).
docker run -d --name "$RELAY" --network "$NET" -p 127.0.0.1:18765:8765 "$IMAGE" sleep infinity >/dev/null
# The host: NO -p flags at all. Docker records that as zero published ports.
docker run -d --name "$HOST" --network "$NET" "$IMAGE" sleep infinity >/dev/null
# The client: a different container, same story as a phone on mobile data.
docker run -d --name "$CLIENT" --network "$NET" "$IMAGE" sleep infinity >/dev/null

echo "== shipping the link package into the containers"
for c in "$RELAY" "$HOST" "$CLIENT"; do
  docker exec "$c" mkdir -p /srv/src
  docker cp src/pocketshell "$c:/srv/src/pocketshell" >/dev/null
  # pocketshell/__init__.py reads its version from the pyproject beside src/
  docker cp pyproject.toml "$c:/srv/pyproject.toml" >/dev/null
  docker exec "$c" pip install --quiet --no-input "websockets>=13,<17"
done
docker cp tests/docker/link/relay_entry.py "$RELAY:/srv/" >/dev/null
docker cp tests/docker/link/host_entry.py "$HOST:/srv/" >/dev/null
docker cp tests/docker/link/e2e_client.py "$CLIENT:/srv/" >/dev/null

echo "== NAT proof: host container must publish zero ports"
PUBLISHED="$(docker port "$HOST" || true)"
if [ -n "$PUBLISHED" ]; then
  echo "FAIL: host container publishes ports:" >&2
  echo "$PUBLISHED" >&2
  exit 1
fi
echo "host container published ports: (none) — OK"

echo "== starting relay + host daemon (outbound dial only)"
docker exec -d "$RELAY" env LINK_TOKEN="$TOKEN" python /srv/relay_entry.py
docker exec -d "$HOST" env LINK_RELAY_URL="ws://$RELAY:8765" LINK_TOKEN="$TOKEN" \
  LINK_HOST_ID=docker-laptop python /srv/host_entry.py

echo "== driving the host from the client container through the relay"
docker exec -e LINK_RELAY_URL="ws://$RELAY:8765" -e LINK_TOKEN="$TOKEN" \
  -e LINK_HOST_ID=docker-laptop "$CLIENT" python /srv/e2e_client.py

echo "== also proving the operator's loopback can reach the relay"
python3 - "$TOKEN" <<'PYEOF'
import socket, sys
# the published port answers on the host machine's loopback
with socket.create_connection(("127.0.0.1", 18765), timeout=5) as sock:
    print("operator loopback -> relay port: reachable (TCP) — OK")
PYEOF

echo "LINK-E2E-OK"
