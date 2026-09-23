#!/bin/bash
# Builds the MCP server image locally (own Dockerfile in ./app, no image published to
# any registry) and deploys it. Published only on 127.0.0.1:8000 on purpose (not on the
# whole LAN) -- a reverse proxy in front (e.g. Caddy with --network host) reaches it just
# the same over loopback, so this service stays protected behind MCP_AUTH_TOKEN without
# being directly exposed on the local network. Meant to be connected as a "Connector"
# from Mistral AI (see README.md).
set -euo pipefail
cd "$(dirname "$0")"
source ./config.env

if [ ! -f ./secrets/mcp-token.env ]; then
  echo "Missing secrets/mcp-token.env -- copy secrets/mcp-token.env.example and fill in a random token." >&2
  exit 1
fi

if [ ! -f ./secrets/adguard-credentials.env ]; then
  echo "Missing secrets/adguard-credentials.env -- copy secrets/adguard-credentials.env.example and fill in the AdGuard Home admin username/password." >&2
  exit 1
fi

podman build -t "$IMAGE_NAME" ./app

podman run -d --name "$CONTAINER_NAME" --replace \
  --restart=always \
  --env-file ./secrets/mcp-token.env \
  --env-file ./secrets/adguard-credentials.env \
  -e ADGUARD_URL="$ADGUARD_URL" \
  -e METRICS_PORT="$METRICS_PORT" \
  -p 127.0.0.1:8000:8000 \
  -p "127.0.0.1:$METRICS_PORT:$METRICS_PORT" \
  -v /run/user/1000/podman/podman.sock:/run/podman/podman.sock \
  -v /mnt/storage:/mnt/storage:ro \
  -v /mnt/media:/mnt/media:ro \
  -v /run:/host-run:ro \
  "$IMAGE_NAME"

echo
echo "Deployed. Check with: podman logs -f $CONTAINER_NAME"
echo "Prometheus metrics (from the server itself only): curl -s http://127.0.0.1:$METRICS_PORT/metrics"
