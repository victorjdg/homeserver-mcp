"""
Read-only MCP (Model Context Protocol) server for a Debian host running Podman.

Exposes 8 read-only tools so a model (e.g. Mistral AI, used as a remote "Connector" over
HTTP) can query the state of Podman containers, disk usage, system load, VPN health,
HTTPS certificate expiry, AdGuard Home ad-blocking stats, and whether the host needs a
reboot -- without being able to modify anything.

Transport: Streamable HTTP (official `mcp` SDK, FastMCP class) mounted exactly at "/mcp",
listening on 0.0.0.0:8000 inside the container.

Auth: a mandatory "Authorization: Bearer <token>" header on every request, compared
against the MCP_AUTH_TOKEN environment variable. Implemented as an ASGI middleware
wrapping the Starlette app returned by FastMCP.streamable_http_app(), so unauthenticated
requests get rejected with 401 BEFORE reaching the MCP handler.

Note on SDK version: uses `mcp` 1.x (`pip install "mcp>=1.30.0,<2"`). The SDK's 2.x branch
(mcp>=2.0.0) renamed the `FastMCP` class to `MCPServer`
(`mcp.server.mcpserver.MCPServer`) and changed other APIs; since this deployment needs
`FastMCP`, requirements.txt explicitly pins `mcp<2`.
"""

from __future__ import annotations

import datetime
import functools
import http.cookiejar
import json
import os
import secrets
import shutil
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

import docker
import docker.errors
import uvicorn
from mcp.server.fastmcp import FastMCP
from prometheus_client import Counter, Histogram, start_http_server
from starlette.responses import JSONResponse
from starlette.types import Receive, Scope, Send

# ---------------------------------------------------------------------------
# Configuration and environment validation
# ---------------------------------------------------------------------------

try:
    MCP_AUTH_TOKEN: str = os.environ["MCP_AUTH_TOKEN"]
except KeyError as exc:
    sys.stderr.write(
        "FATAL ERROR: the MCP_AUTH_TOKEN environment variable is required and not "
        "set. Set MCP_AUTH_TOKEN to a secret token before starting the server (e.g. "
        "-e MCP_AUTH_TOKEN=... on the container).\n"
    )
    raise RuntimeError(
        "Missing required environment variable MCP_AUTH_TOKEN."
    ) from exc

if not MCP_AUTH_TOKEN.strip():
    raise RuntimeError(
        "The MCP_AUTH_TOKEN environment variable is set but empty. "
        "It must contain a non-empty secret token."
    )

PODMAN_SOCKET_URL = "unix:///run/podman/podman.sock"

DISK_PATHS = ["/mnt/storage", "/mnt/media"]

# Fixed allow-list of container names that logs can be queried for.
# Any name outside this list is rejected without running anything.
ALLOWED_CONTAINERS = [
    "qbittorrent",
    "prowlarr",
    "sonarr",
    "radarr",
    "jellyfin",
    "gluetun",
    "caddy",
    "immich-server",
    "immich-machine-learning",
    "immich-database",
    "immich-redis",
    "ovh-ddns",
    "craftycontainer-pod-craftycontainer",
    "mcp-server",
]

MAX_LOG_LINES = 500
DEFAULT_LOG_LINES = 50

GB = 1024**3

# Marker file left by apt/unattended-upgrades when the host needs a reboot. The whole
# host /run is mounted at /host-run (see 01-deploy.sh) instead of just this one file,
# because Podman won't let you bind-mount a file that doesn't exist on the host -- and
# this file normally does NOT exist (it only appears when a reboot is actually needed).
REBOOT_REQUIRED_PATH = "/host-run/reboot-required"

# Container that holds the WireGuard tunnel (qbittorrent shares its network).
GLUETUN_CONTAINER = "gluetun"

# Cache file from a dynamic-DNS updater, with the last known real public home IP. Lives
# inside /mnt/storage, already mounted read-only.
DDNS_CACHE_FILE = "/mnt/storage/appdata/ovh-ddns/lastip"

# Public domains served over HTTPS by the reverse proxy (a Minecraft domain isn't
# included here: that's the raw Minecraft TCP protocol, not HTTPS).
MONITORED_DOMAINS = ["immich.victorjdg.com", "jellyfin.victorjdg.com", "mcp.victorjdg.com"]

# AdGuard Home runs with --network host on the same server, but this container is NOT on
# --network host (published on loopback only, see 01-deploy.sh) -- so it can't reach
# AdGuard Home via the host's LAN IP: the hairpin NAT of "pasta" (rootless network
# backend) doesn't let a container connect back to the LAN/public IP of the very host
# hosting it (tested live: "Connection refused" against the LAN IP, while it works fine
# from the host itself). The fix is "host.containers.internal", the special hostname
# Podman resolves inside the container to an address that does route correctly to the
# host (verified with curl).
ADGUARD_URL = os.environ.get("ADGUARD_URL", "http://host.containers.internal:3001")
ADGUARD_USERNAME = os.environ.get("ADGUARD_USERNAME")
ADGUARD_PASSWORD = os.environ.get("ADGUARD_PASSWORD")

# Port for the /metrics endpoint (Prometheus), served separately from the MCP transport
# (see why further down). Not a secret -- instead of its own auth, it's protected by
# only being published on 127.0.0.1 (see 01-deploy.sh) and not sitting behind the
# reverse proxy, so it's unreachable from both the LAN and the internet.
METRICS_PORT = int(os.environ.get("METRICS_PORT", "9100"))


# ---------------------------------------------------------------------------
# Podman client (Docker-compatible API), lazily initialized
# ---------------------------------------------------------------------------

_docker_client: docker.DockerClient | None = None


def _get_client() -> docker.DockerClient:
    """Creates (once) and returns the Docker client pointed at the Podman socket."""
    global _docker_client
    if _docker_client is None:
        _docker_client = docker.DockerClient(base_url=PODMAN_SOCKET_URL)
    return _docker_client


# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------
#
# Served on a separate HTTP port (start_http_server, further down), NOT mounted on
# FastMCP's ASGI app or behind BearerAuthMiddleware. Reason: the reverse proxy sends ALL
# traffic for the MCP domain to 127.0.0.1:8000 -- if /metrics lived on that same
# port/app, it would end up published on the internet by accident. Living on its own
# port (9100), published only on 127.0.0.1 of the host and untouched by the reverse
# proxy, /metrics is unreachable from both the LAN and the outside -- same exposure
# level as any other internal-only monitoring endpoint, without needing its own auth.

TOOL_CALLS_TOTAL = Counter(
    "mcp_tool_calls_total",
    "Number of calls to each MCP tool, by outcome.",
    ["tool", "status"],  # status: "ok" | "exception"
)

TOOL_CALL_DURATION_SECONDS = Histogram(
    "mcp_tool_call_duration_seconds",
    "Duration of each MCP tool call, in seconds.",
    ["tool"],
)

AUTH_FAILURES_TOTAL = Counter(
    "mcp_auth_failures_total",
    "Requests rejected by the Bearer middleware (missing or invalid token).",
)


def track_tool_metrics(tool_name: str):
    """Decorator that measures duration and counts invocations of an MCP tool.

    Careful with what "status=exception" means here: almost every tool in this file
    already catches its own expected errors (Podman down, AdGuard unreachable, etc.) and
    returns them as plain text (e.g. "Error: ..."), not as an exception -- that kind of
    expected failure gets counted in TOOL_CALLS_TOTAL with status="ok" (the MCP call
    itself succeeded, even though the content says something failed). "exception" only
    increments on a failure not caught by the tool itself, i.e. a real bug in this
    server. Distinguishing expected failures from metrics alone would require parsing
    the response text -- out of scope for this first instrumentation pass.

    Applied BELOW @mcp.tool() (closer to the function) so FastMCP still sees the
    original signature and docstring when building the tool's schema: functools.wraps
    leaves a __wrapped__ attribute that `inspect.signature` follows by default.
    """

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            status = "ok"
            try:
                return func(*args, **kwargs)
            except Exception:
                status = "exception"
                raise
            finally:
                TOOL_CALL_DURATION_SECONDS.labels(tool=tool_name).observe(
                    time.perf_counter() - start
                )
                TOOL_CALLS_TOTAL.labels(tool=tool_name, status=status).inc()

        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="debian-podman-readonly",
    instructions=(
        "Read-only server for inspecting a Debian host running Podman: container "
        "status, disk usage, system load, and logs of specific services. No tool "
        "modifies the system."
    ),
    host="0.0.0.0",
    port=8000,
    streamable_http_path="/mcp",
)


@mcp.tool()
@track_tool_metrics("list_containers")
def list_containers() -> str:
    """Lists every Podman container on the host (running and stopped).

    For each container returns: name, image, state (running, exited, etc.) and
    published ports (container_port/protocol -> host:host_port mapping). Uses the
    Podman socket via the Docker-compatible API. Doesn't modify anything. Useful for
    questions like "which containers are running?", "is jellyfin down?" or "what
    ports does caddy expose?".
    """
    try:
        client = _get_client()
        containers = client.containers.list(all=True)
    except docker.errors.DockerException as exc:
        return f"Error connecting to the Podman socket ({PODMAN_SOCKET_URL}): {exc}"
    except Exception as exc:  # noqa: BLE001 - we want a readable message, not a stack trace
        return f"Unexpected error listing containers: {exc}"

    if not containers:
        return "No containers found (running or stopped)."

    lines = []
    for c in containers:
        try:
            image = c.image.tags[0] if c.image and c.image.tags else (c.image.short_id if c.image else "unknown")
        except Exception:  # noqa: BLE001
            image = "unknown"

        status = c.status

        ports_map = (c.attrs or {}).get("NetworkSettings", {}).get("Ports") or {}
        port_strs = []
        for container_port, bindings in ports_map.items():
            if not bindings:
                port_strs.append(f"{container_port} (not published)")
                continue
            for b in bindings:
                host_ip = b.get("HostIp") or "0.0.0.0"
                host_port = b.get("HostPort")
                port_strs.append(f"{container_port} -> {host_ip}:{host_port}")
        ports_repr = ", ".join(port_strs) if port_strs else "no published ports"

        lines.append(f"- {c.name} | image: {image} | status: {status} | ports: {ports_repr}")

    return "Podman containers (running and stopped):\n" + "\n".join(lines)


@mcp.tool()
@track_tool_metrics("disk_usage")
def disk_usage() -> str:
    """Shows disk usage for the /mnt/storage and /mnt/media mount points.

    Returns total, used, free (in GB) and percentage used for each path. Doesn't
    modify anything, only reads filesystem disk usage. Useful for questions like
    "how much free space is left on storage?" or "is the media disk filling up?".
    """
    lines = []
    for path in DISK_PATHS:
        try:
            usage = shutil.disk_usage(path)
        except FileNotFoundError:
            lines.append(f"- {path}: the path doesn't exist or isn't mounted in the container.")
            continue
        except OSError as exc:
            lines.append(f"- {path}: error reading disk usage: {exc}")
            continue
        except Exception as exc:  # noqa: BLE001
            lines.append(f"- {path}: unexpected error: {exc}")
            continue

        total_gb = usage.total / GB
        used_gb = usage.used / GB
        free_gb = usage.free / GB
        percent_used = (usage.used / usage.total * 100) if usage.total else 0.0

        lines.append(
            f"- {path}: total {total_gb:.1f} GB, used {used_gb:.1f} GB "
            f"({percent_used:.1f}%), free {free_gb:.1f} GB"
        )

    return "Disk usage:\n" + "\n".join(lines)


@mcp.tool()
@track_tool_metrics("system_load")
def system_load() -> str:
    """Returns the system's load average and the host's memory usage.

    Reads /proc/loadavg (1, 5 and 15-minute load average) and /proc/meminfo
    (total/used/free memory in GB) directly from the host. Read-only, no special
    mount needed. Useful for questions like "is the server overloaded?" or "how
    much free RAM is left?".
    """
    result_lines = []

    try:
        with open("/proc/loadavg", "r", encoding="utf-8") as f:
            loadavg_raw = f.read().split()
        load1, load5, load15 = loadavg_raw[0], loadavg_raw[1], loadavg_raw[2]
        result_lines.append(f"Load average: 1min={load1}, 5min={load5}, 15min={load15}")
    except FileNotFoundError:
        result_lines.append("Could not read /proc/loadavg (doesn't exist on this system).")
    except Exception as exc:  # noqa: BLE001
        result_lines.append(f"Error reading /proc/loadavg: {exc}")

    try:
        meminfo = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) != 2:
                    continue
                key = parts[0].strip()
                value_kb = parts[1].strip().split()[0]
                meminfo[key] = int(value_kb)

        total_kb = meminfo.get("MemTotal", 0)
        available_kb = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
        used_kb = max(total_kb - available_kb, 0)

        total_gb = total_kb / (1024**2)
        available_gb = available_kb / (1024**2)
        used_gb = used_kb / (1024**2)

        result_lines.append(
            f"Memory: total {total_gb:.2f} GB, used {used_gb:.2f} GB, "
            f"free/available {available_gb:.2f} GB"
        )
    except FileNotFoundError:
        result_lines.append("Could not read /proc/meminfo (doesn't exist on this system).")
    except Exception as exc:  # noqa: BLE001
        result_lines.append(f"Error reading /proc/meminfo: {exc}")

    return "\n".join(result_lines)


@mcp.tool()
@track_tool_metrics("uptime_and_reboot")
def uptime_and_reboot() -> str:
    """Shows how long the server has been up, and whether a pending update requires a
    reboot (a marker file left by apt/unattended-upgrades after installing certain
    updates, e.g. a kernel update). Read-only. Useful for questions like "how long has
    the server been up?" or "does it need a reboot for a pending update?".
    """
    lines_out = []

    try:
        with open("/proc/uptime", "r", encoding="utf-8") as f:
            uptime_seconds = float(f.read().split()[0])
        days, rem = divmod(int(uptime_seconds), 86400)
        hours, rem = divmod(rem, 3600)
        minutes, _ = divmod(rem, 60)
        lines_out.append(f"The server has been up for {days}d {hours}h {minutes}m.")
    except FileNotFoundError:
        lines_out.append("Could not read /proc/uptime (doesn't exist on this system).")
    except Exception as exc:  # noqa: BLE001
        lines_out.append(f"Error reading /proc/uptime: {exc}")

    if os.path.isfile(REBOOT_REQUIRED_PATH):
        lines_out.append(
            "YES, there is a pending update that requires a server reboot."
        )
        try:
            with open(REBOOT_REQUIRED_PATH, "r", encoding="utf-8") as f:
                detail = f.read().strip()
            if detail:
                lines_out.append(f"Detail: {detail}")
        except Exception:  # noqa: BLE001
            pass
    else:
        lines_out.append("No pending update requires a reboot.")

    return "\n".join(lines_out)


@mcp.tool()
@track_tool_metrics("vpn_health")
def vpn_health() -> str:
    """Checks that qBittorrent's WireGuard tunnel (via the gluetun container) is still
    active and that the outbound IP is the VPN's, not the real home IP -- if they
    matched, that would be a VPN leak. Read-only, doesn't modify anything. Useful for
    questions like "is the VPN still working?" or "is qbittorrent leaking my real IP?".
    """
    try:
        client = _get_client()
        gluetun = client.containers.get(GLUETUN_CONTAINER)
    except docker.errors.NotFound:
        return f"Error: container '{GLUETUN_CONTAINER}' not found."
    except docker.errors.DockerException as exc:
        return f"Error connecting to the Podman socket ({PODMAN_SOCKET_URL}): {exc}"
    except Exception as exc:  # noqa: BLE001
        return f"Unexpected error getting container '{GLUETUN_CONTAINER}': {exc}"

    if gluetun.status != "running":
        return (
            f"ALERT: container '{GLUETUN_CONTAINER}' is not running "
            f"(status: {gluetun.status}). The VPN is not active."
        )

    try:
        result = gluetun.exec_run(["cat", "/tmp/gluetun/ip"])
        vpn_ip = result.output.decode(errors="replace").strip()
    except Exception as exc:  # noqa: BLE001
        return f"Error reading the IP detected by gluetun: {exc}"

    if not vpn_ip:
        return (
            "Could not determine the VPN's outbound IP (file empty or not "
            "available yet inside gluetun)."
        )

    home_ip = None
    try:
        with open(DDNS_CACHE_FILE, "r", encoding="utf-8") as f:
            home_ip = f.read().strip()
    except (FileNotFoundError, OSError):
        pass

    if home_ip and vpn_ip == home_ip:
        return (
            f"ALERT: the VPN's outbound IP ({vpn_ip}) matches the real home IP "
            f"({home_ip}). This means the VPN is NOT protecting the traffic."
        )

    msg = f"VPN active. qBittorrent/gluetun outbound IP: {vpn_ip}"
    if home_ip:
        msg += f" (different from the real home IP, {home_ip} -- correct, the VPN works)."
    else:
        msg += " (couldn't compare against the real home IP, but the tunnel is active)."
    return msg


@mcp.tool()
@track_tool_metrics("cert_expiry")
def cert_expiry() -> str:
    """Checks the real expiry date of the HTTPS certificate actually being served by
    each public domain in MONITORED_DOMAINS, connecting over TLS to each one just like
    a browser would. Read-only. Useful for catching a failed Let's Encrypt auto-renewal
    before the certificate actually expires and breaks.
    """
    lines_out = []
    for domain in MONITORED_DOMAINS:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
        except Exception as exc:  # noqa: BLE001
            lines_out.append(f"- {domain}: error checking the certificate: {exc}")
            continue

        not_after = cert.get("notAfter") if cert else None
        if not not_after:
            lines_out.append(f"- {domain}: could not read the expiry date.")
            continue

        try:
            expires_dt = datetime.datetime.strptime(
                not_after, "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=datetime.timezone.utc)
        except ValueError as exc:
            lines_out.append(f"- {domain}: could not parse the date ({exc}).")
            continue

        days_left = (expires_dt - datetime.datetime.now(datetime.timezone.utc)).days
        warn = "  WARNING: expires soon" if days_left < 14 else ""
        lines_out.append(
            f"- {domain}: expires on {expires_dt.strftime('%Y-%m-%d')} "
            f"({days_left} days left){warn}"
        )

    return "HTTPS certificate expiry:\n" + "\n".join(lines_out)


def _adguard_get(path: str, timeout: float = 8.0) -> dict:
    """Logs in (a fresh session every time, the cookie isn't cached -- these stats are
    queried rarely enough that the added complexity isn't worth it) against the AdGuard
    Home API and returns the JSON for `path`. Raises RuntimeError/urllib.error.* on
    failure."""
    if not ADGUARD_USERNAME or not ADGUARD_PASSWORD:
        raise RuntimeError(
            "Missing ADGUARD_USERNAME/ADGUARD_PASSWORD environment variables "
            "(see secrets/adguard-credentials.env)."
        )

    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    login_payload = json.dumps({"name": ADGUARD_USERNAME, "password": ADGUARD_PASSWORD}).encode()
    login_req = urllib.request.Request(
        f"{ADGUARD_URL}/control/login",
        data=login_payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with opener.open(login_req, timeout=timeout):
        pass  # we only care about the session cookie left in the jar

    data_req = urllib.request.Request(f"{ADGUARD_URL}{path}")
    with opener.open(data_req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


@mcp.tool()
@track_tool_metrics("adguard_stats")
def adguard_stats() -> str:
    """AdGuard Home stats (network-wide ad-blocking DNS server): total DNS queries, how
    many were blocked (and what percentage), average response time, and the most active
    domains/clients over the recent period AdGuard Home keeps in memory (usually the
    last 24h). Read-only -- logs into the AdGuard Home API with read-only credentials
    and doesn't change any configuration. Useful for questions like "how many ads got
    blocked today?" or "which device generates the most DNS traffic?".
    """
    try:
        stats = _adguard_get("/control/stats")
    except urllib.error.HTTPError as exc:
        detail = "wrong credentials" if exc.code in (401, 403) else exc.reason
        return f"Error querying AdGuard Home ({ADGUARD_URL}): HTTP {exc.code} ({detail})."
    except urllib.error.URLError as exc:
        return f"Connection error with AdGuard Home ({ADGUARD_URL}): {exc.reason}"
    except RuntimeError as exc:
        return f"Error: {exc}"
    except Exception as exc:  # noqa: BLE001
        return f"Unexpected error querying AdGuard Home: {exc}"

    total = stats.get("num_dns_queries", 0) or 0
    blocked = stats.get("num_blocked_filtering", 0) or 0
    percent_blocked = (blocked / total * 100) if total else 0.0
    # avg_processing_time already comes in milliseconds from the AdGuard Home API
    # (verified against the raw live value: ~13ms is a plausible average DNS resolution
    # time; treating it as seconds would give ~13 seconds, absurd for DNS).
    avg_time_ms = stats.get("avg_processing_time") or 0.0
    period = stats.get("time_units", "unknown")

    lines_out = [
        f"AdGuard Home stats (period: {period}):",
        f"- Total DNS queries: {total}",
        f"- Blocked by filters: {blocked} ({percent_blocked:.1f}%)",
    ]
    lines_out.append(
        f"- Average response time: {avg_time_ms:.1f} ms" if avg_time_ms
        else "- Average response time: no data"
    )

    def _add_top(key: str, label: str, n: int = 5) -> None:
        entries = stats.get(key) or []
        if not entries:
            return
        lines_out.append(f"- {label}:")
        for entry in entries[:n]:
            for name, count in entry.items():
                lines_out.append(f"    - {name}: {count}")

    _add_top("top_queried_domains", "Most queried domains")
    _add_top("top_blocked_domains", "Most blocked domains")
    _add_top("top_clients", "Clients with the most queries")

    return "\n".join(lines_out)


@mcp.tool()
@track_tool_metrics("service_logs")
def service_logs(container_name: str, lines: int = DEFAULT_LOG_LINES) -> str:
    """Returns the last N log lines from a specific container.

    For security, `container_name` must be exactly one of the containers in a fixed
    allow-list (known services on the host); any other name is rejected without
    running anything. `lines` is how many trailing log lines to return (default 50),
    capped at 500 even if more is requested. Doesn't modify the container, only reads
    its log. Useful for debugging why a service like "jellyfin" or "sonarr" is failing.

    Args:
        container_name: exact container name (must be in the allow-list).
        lines: number of trailing log lines to return (1-500).
    """
    if container_name not in ALLOWED_CONTAINERS:
        allowed = ", ".join(ALLOWED_CONTAINERS)
        return (
            f"Error: '{container_name}' is not in the list of allowed containers. "
            f"Allowed containers: {allowed}"
        )

    try:
        safe_lines = int(lines)
    except (TypeError, ValueError):
        safe_lines = DEFAULT_LOG_LINES
    safe_lines = max(1, min(safe_lines, MAX_LOG_LINES))

    try:
        client = _get_client()
        container = client.containers.get(container_name)
    except docker.errors.NotFound:
        return f"Error: no container named '{container_name}' found in Podman."
    except docker.errors.DockerException as exc:
        return f"Error connecting to the Podman socket ({PODMAN_SOCKET_URL}): {exc}"
    except Exception as exc:  # noqa: BLE001
        return f"Unexpected error getting container '{container_name}': {exc}"

    try:
        raw_logs = container.logs(tail=safe_lines)
        log_text = raw_logs.decode(errors="replace")
    except Exception as exc:  # noqa: BLE001
        return f"Error getting logs for '{container_name}': {exc}"

    if not log_text.strip():
        return f"Container '{container_name}' has no log output available."

    return f"Last {safe_lines} log lines from '{container_name}':\n{log_text}"


# ---------------------------------------------------------------------------
# Bearer-token auth ASGI middleware, and server startup
# ---------------------------------------------------------------------------


class BearerAuthMiddleware:
    """Pure ASGI middleware that requires `Authorization: Bearer <token>` on /mcp.

    Applied before dispatching to the MCP handler: if the header is missing or
    doesn't match MCP_AUTH_TOKEN, it responds with 401 directly without invoking the
    wrapped app. "lifespan" events are passed through without any check (they're
    process start/stop, not HTTP requests), so FastMCP's StreamableHTTPSessionManager
    starts and stops correctly.
    """

    def __init__(self, app, token: str) -> None:
        self.app = app
        self._expected_header = f"Bearer {token}"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        auth_header = headers.get(b"authorization", b"").decode("latin-1")

        if not auth_header or not secrets.compare_digest(auth_header, self._expected_header):
            AUTH_FAILURES_TOTAL.inc()
            response = JSONResponse(
                {"error": "unauthorized", "detail": "Missing or invalid Authorization: Bearer <token> header."},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


# Underlying ASGI app exposing FastMCP over Streamable HTTP, mounted at "/mcp"
# (settings.mount_path="/" + settings.streamable_http_path="/mcp" -> final path "/mcp").
_streamable_http_app = mcp.streamable_http_app()

# Final app: auth middleware wrapping the MCP app.
app = BearerAuthMiddleware(_streamable_http_app, MCP_AUTH_TOKEN)


if __name__ == "__main__":
    # start_http_server starts its own HTTP server on a background thread and returns
    # right away (non-blocking) -- that's why it can go before uvicorn.run, which does
    # block. Port and reasoning for isolating it from the MCP app: see the "Prometheus
    # metrics" section comment above.
    start_http_server(METRICS_PORT)
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
