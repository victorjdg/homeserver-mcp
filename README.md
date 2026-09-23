# Homeserver MCP

A read-only **[Model Context Protocol](https://modelcontextprotocol.io)** server exposing my
home server's live status to LLMs — so I can just ask "how's my server doing?" from any
MCP-aware chat client (I use it from Mistral AI's Le Chat, connected as a Connector).

No write access anywhere: it can't start/stop containers, modify files, or change any
configuration. It only answers questions.

## Why it needs the Podman socket and read-only disk mounts

To answer things like "which containers are running?" or "how much free space is left?", the
server itself needs to see that state, so it gets:

- The **Podman socket**, so the tools can do the equivalent of `podman ps`/`podman logs`
  without needing their own SSH credentials.
- The data disks, mounted **read-only** (`:ro`) — it can read to answer questions, but can
  never write or delete anything.

## Tools

| Tool | What it does |
|---|---|
| `list_containers` | Status of every Podman container (running and stopped), with image, state, and published ports |
| `disk_usage` | Total/used/free space (and % used) on the configured data mounts |
| `system_load` | Load average and memory usage of the host |
| `uptime_and_reboot` | How long the host has been up, and whether a pending update requires a reboot |
| `vpn_health` | Whether a WireGuard tunnel container is still active and not leaking the real home IP |
| `cert_expiry` | Real HTTPS certificate expiry for a configured list of public domains (connects over TLS, doesn't trust cached metadata) |
| `adguard_stats` | AdGuard Home stats: total/blocked DNS queries, block %, average response time, top domains/clients |
| `service_logs(container_name, lines?)` | Last N log lines from one container — restricted to a fixed allow-list, any other name is rejected before running anything |

## Metrics (Prometheus)

A `/metrics` endpoint in Prometheus format, served on a **separate port** from the MCP
transport (`9100` by default) — it doesn't live inside the MCP app or go through the Bearer
auth middleware, so it stays internal-only (not proxied publicly) without needing its own auth.

| Metric | Type | What it measures |
|---|---|---|
| `mcp_tool_calls_total{tool, status}` | Counter | Calls per tool, `status="ok"` or `"exception"` |
| `mcp_tool_call_duration_seconds{tool}` | Histogram | Duration of each tool call |
| `mcp_auth_failures_total` | Counter | Requests rejected by the Bearer auth middleware |

Most tools already catch their own expected failures (Podman unreachable, AdGuard down, etc.)
and return them as normal text — that counts as `status="ok"` (the MCP call itself succeeded).
`"exception"` only increments on an uncaught bug in the server itself.

## Security

- Bearer token auth (`MCP_AUTH_TOKEN`) via a custom ASGI middleware, checked with a
  timing-safe comparison, rejecting with 401 before the request reaches the MCP handler.
- `adguard_stats` needs separate AdGuard Home admin credentials (`ADGUARD_USERNAME`/
  `ADGUARD_PASSWORD`) — used only to call its read-only `/control/stats` endpoint, never to
  change its configuration.
- Meant to be published on loopback only, with a reverse proxy (HTTPS) and its own auth in
  front if exposed to the internet — see `01-deploy.sh` and `config.env`.

## Deploying

```bash
cp secrets/mcp-token.env.example secrets/mcp-token.env
# fill in MCP_AUTH_TOKEN — generate one with:
#   tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 48

cp secrets/adguard-credentials.env.example secrets/adguard-credentials.env
# fill in your AdGuard Home admin username/password

./01-deploy.sh
```

Adjust `config.env` first — paths, ports, and the list of allowed containers/monitored domains
in `app/server.py` are specific to my setup and meant to be edited for yours.

## Registering as an MCP Connector (Mistral Studio)

1. Studio → **Connectors** → new Connector.
2. Server URL: your deployed `/mcp` endpoint.
3. Headers → `Authorization` → `Bearer <your MCP_AUTH_TOKEN>`.

**Gotcha**: the header *value* field in Mistral Studio does not prepend `Bearer` for you — type
the literal string `Bearer <token>` (with the space), not just the token, or every call 401s.
