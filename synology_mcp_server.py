"""
=============================================================================
synology_mcp_server.py  —  Synology LAN HTTP MCP Server
=============================================================================

WHAT THIS DOES:
  Runs as a persistent HTTP service on your Synology NAS, accessible to any
  machine on your home network. Exposes four tools to Claude agents:
    - post_discord_message     → send alerts/summaries to your Discord channel
    - run_sentinel_kql_query   → query Azure Sentinel Log Analytics via KQL
    - create_jira_ticket       → open a new issue in your JIRA project
    - update_jira_ticket       → comment on or transition an existing ticket

ACCESS:
  http://<synology-ip>:9000/mcp
  All requests require a Bearer token (set MCP_AUTH_TOKEN in mcp.env)

HOW TO START:
  bash /volume1/Misc/scripts/mcp_server/start_mcp_server.sh

HOW TO RUN MANUALLY (for testing):
  set -a; source /volume1/Misc/scripts/mcp_server/mcp.env; set +a
  python3.11 /volume1/Misc/scripts/mcp_server/synology_mcp_server.py

HOW TO STOP:
  pkill -f synology_mcp_server.py

HOW TO CHECK IF RUNNING:
  pgrep -f synology_mcp_server.py && echo "Running" || echo "Not running"

REQUIREMENTS:
  pip install fastmcp uvicorn requests azure-identity azure-monitor-query \
              --break-system-packages

=============================================================================
"""

import os
import secrets
import sys
from datetime import datetime, timedelta

import requests as http_requests
import uvicorn
from azure.identity import ClientSecretCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from mcp.server.fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response


# =============================================================================
# CONFIGURATION
# =============================================================================
# All values are loaded from mcp.env via the startup script.
# NEVER hardcode secrets here — always use environment variables.
#
# To verify your env is loaded correctly before starting:
#   echo $MCP_AUTH_TOKEN   (should print your token)
#   echo $DISCORD_WEBHOOK_URL
# =============================================================================

# ── Server ────────────────────────────────────────────────────────────────────
# MCP_HOST:  IP to bind to. 0.0.0.0 means accept connections on all interfaces.
#            Your Synology's LAN IP (e.g. 192.168.50.173) also works if you want
#            to be more restrictive.
# MCP_PORT:  Port the server listens on. Default 9000.
SERVER_HOST    = os.environ.get("MCP_HOST", "0.0.0.0")
SERVER_PORT    = int(os.environ.get("MCP_PORT", "9000"))

# ── Auth ──────────────────────────────────────────────────────────────────────
# MCP_AUTH_TOKEN: shared secret between this server and the orchestrator.
# Generate a new one with:
#   python3 -c "import secrets; print(secrets.token_hex(32))"
MCP_AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN", "")

# ── Discord ───────────────────────────────────────────────────────────────────
# DISCORD_WEBHOOK_URL: from Discord channel → Integrations → Webhooks → Copy URL
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")

# ── Azure Sentinel ────────────────────────────────────────────────────────────
# These come from your Azure App Registration (service principal).
# Azure Portal → Azure Active Directory → App registrations → your app
AZURE_TENANT_ID     = os.environ.get("AZURE_TENANT_ID", "")
AZURE_CLIENT_ID     = os.environ.get("AZURE_CLIENT_ID", "")
AZURE_CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET", "")

# Azure Portal → Log Analytics workspaces → your workspace → Overview
AZURE_WORKSPACE_ID  = os.environ.get("AZURE_WORKSPACE_ID", "")

# ── JIRA ──────────────────────────────────────────────────────────────────────
# JIRA_URL:         your Atlassian domain, no trailing slash
# JIRA_EMAIL:       email address on your Atlassian account
# JIRA_TOKEN:       from https://id.atlassian.com/manage-profile/security/api-tokens
# JIRA_PROJECT_KEY: short key for your project (e.g. PLY, SES, SOC)
JIRA_URL         = os.environ.get("JIRA_URL", "")
JIRA_EMAIL       = os.environ.get("JIRA_EMAIL", "")
JIRA_TOKEN       = os.environ.get("JIRA_TOKEN", "")
JIRA_PROJECT_KEY = os.environ.get("JIRA_PROJECT_KEY", "SES")


# =============================================================================
# AUTH MIDDLEWARE
# =============================================================================
# Checks the Bearer token on every incoming request before any tool runs.
# Requests without a valid token receive a 401 Unauthorized response.
#
# secrets.compare_digest() is used instead of == to prevent timing attacks,
# where an attacker could guess the token character-by-character by measuring
# how long the comparison takes.
# =============================================================================

class BearerTokenMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # Health check endpoint is public — used by start_mcp_server.sh
        # to verify the server is alive without needing the token
        if request.url.path == "/health":
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")

        # Token must be sent as:  Authorization: Bearer <token>
        if not auth_header.startswith("Bearer "):
            return Response("Unauthorized", status_code=401)

        provided = auth_header[len("Bearer "):]

        # Constant-time comparison — prevents timing-based token guessing
        if not MCP_AUTH_TOKEN or not secrets.compare_digest(provided, MCP_AUTH_TOKEN):
            return Response("Unauthorized", status_code=401)

        return await call_next(request)


# =============================================================================
# MCP SERVER
# =============================================================================
# stateless_http=True means each HTTP request is handled independently.
# No session state is maintained between calls — safe and simple for LAN use.
#
# TransportSecuritySettings: DNS rebinding protection is disabled here because
# we're accessing the server by IP address on the LAN, not by hostname.
# Enabling it would cause all LAN requests to be rejected.
# =============================================================================

from mcp.server.transport_security import TransportSecuritySettings

mcp = FastMCP(
    name="synology-homelab-mcp",
    stateless_http=True,
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False)
)


# =============================================================================
# HELPERS
# =============================================================================
# Internal utility functions — not exposed to Claude as tools.
# These keep the tool functions clean and readable.
# =============================================================================

def _azure_client():
    """
    Build and return an authenticated Azure Log Analytics client.
    Uses a service principal (app registration) with client secret auth.
    This is the standard non-interactive auth method for automation.
    """
    cred = ClientSecretCredential(
        tenant_id=AZURE_TENANT_ID,
        client_id=AZURE_CLIENT_ID,
        client_secret=AZURE_CLIENT_SECRET
    )
    return LogsQueryClient(cred)


def _jira_auth():
    """Return JIRA basic auth tuple (email, api_token)."""
    return (JIRA_EMAIL, JIRA_TOKEN)


def _jira_headers():
    """Return standard JIRA REST API headers."""
    return {"Content-Type": "application/json", "Accept": "application/json"}


def _check_config(*keys):
    """
    Verify that required environment variables are set.
    Returns an error string if any are missing, None if all present.
    Called at the top of each tool to give a clear error if mcp.env
    wasn't loaded or is missing a value.
    """
    missing = [k for k in keys if not os.environ.get(k)]
    if missing:
        return f"ERROR: Missing config: {', '.join(missing)}. Check mcp.env."
    return None


def _to_json(obj):
    """Serialize an object to JSON string, handling non-serializable types."""
    import json
    return json.dumps(obj, default=str)


# =============================================================================
# TOOLS
# =============================================================================
# Each @mcp.tool() function is exposed to Claude via the MCP protocol.
# Claude reads the docstring to understand when and how to use each tool.
# FastMCP automatically builds the JSON input schema from Python type hints.
#
# Rules for good tool docstrings:
#   - Describe WHEN Claude should call this tool
#   - List what parameters do
#   - Describe what the return value looks like
# =============================================================================

@mcp.tool()
def post_discord_message(message: str, username: str = "Synology MCP Agent") -> str:
    """
    Send a message to the home lab Discord channel via webhook.

    Use this to report findings, deliver task summaries, or alert on threats.
    Always call this at the end of every task to confirm completion.
    Supports Discord markdown formatting (bold, code blocks, bullet lists).

    Args:
        message:  The text to post. Keep under 2000 characters (Discord limit).
        username: Display name shown on the message. Default: 'Synology MCP Agent'.

    Returns:
        Confirmation string with UTC timestamp, or an error message.
    """
    err = _check_config("DISCORD_WEBHOOK_URL")
    if err:
        return err

    try:
        resp = http_requests.post(
            DISCORD_WEBHOOK_URL,
            json={"content": message, "username": username},
            timeout=15
        )
        resp.raise_for_status()
        return f"Discord message sent at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC."

    except http_requests.RequestException as e:
        return f"Failed to send Discord message: {str(e)}"


@mcp.tool()
def run_sentinel_kql_query(query: str, lookback_hours: int = 24) -> str:
    """
    Run a KQL query against the Azure Sentinel Log Analytics workspace.

    Use this to hunt for threats, investigate alerts, check ingestion health,
    or enrich findings with data about a specific IP, user, or host.
    Returns up to 50 rows as JSON. Results are from the past lookback_hours.

    Args:
        query:          KQL query string. Do not include a time filter —
                        the lookback_hours parameter controls the time window.
        lookback_hours: How far back to query. Default: 24 hours.

    Returns:
        JSON rows as a string, a 'no results' message, or an error.

    Example query:
        Syslog
        | where SyslogMessage contains 'Failed password'
        | extend AttackerIP = extract(@'from (\\d+\\.\\d+\\.\\d+\\.\\d+)', 1, SyslogMessage)
        | summarize Hits=count() by AttackerIP
        | order by Hits desc
    """
    err = _check_config("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_WORKSPACE_ID")
    if err:
        return err

    try:
        end_time   = datetime.utcnow()
        start_time = end_time - timedelta(hours=lookback_hours)

        response = _azure_client().query_workspace(
            workspace_id=AZURE_WORKSPACE_ID,
            query=query,
            timespan=(start_time, end_time)
        )

        if response.status == LogsQueryStatus.SUCCESS:
            rows = []
            for table in response.tables:
                # Normalize column names — some SDK versions return objects, some strings
                cols = [col.name if hasattr(col, "name") else col for col in table.columns]
                for row in table.rows:
                    rows.append(dict(zip(cols, [str(v) for v in row])))

            if not rows:
                return f"No results for the past {lookback_hours}h."

            result  = f"KQL results: {len(rows)} rows from last {lookback_hours}h\n\n"
            result += "\n".join(_to_json(r) for r in rows[:50])

            if len(rows) > 50:
                result += f"\n\n...{len(rows) - 50} additional rows truncated."

            return result

        return f"KQL partial failure: {getattr(response, 'partial_error', 'Unknown error')}"

    except Exception as e:
        return f"Failed to run KQL query: {str(e)}"


@mcp.tool()
def create_jira_ticket(
    summary:     str,
    description: str,
    priority:    str       = "Medium",
    issue_type:  str       = "Task",
    labels:      list[str] = []
) -> str:
    """
    Create a new issue in the JIRA security project.

    Use for suspicious activity that needs tracking, failed controls,
    detected threats, or scheduled review tasks.

    Args:
        summary:     Short title for the ticket (shown in board/list views).
        description: Full details — include IPs, timestamps, affected resources.
        priority:    Highest | High | Medium | Low | Lowest. Default: Medium.
        issue_type:  Task | Bug | Story | Epic. Default: Task.
        labels:      List of label strings (e.g. ['brute-force', 'cross-cloud']).

    Returns:
        Ticket key and URL on success (e.g. PLY-42), or an error message.
    """
    err = _check_config("JIRA_URL", "JIRA_EMAIL", "JIRA_TOKEN")
    if err:
        return err

    try:
        resp = http_requests.post(
            f"{JIRA_URL}/rest/api/3/issue",
            headers=_jira_headers(),
            auth=_jira_auth(),
            json={
                "fields": {
                    "project":     {"key": JIRA_PROJECT_KEY},
                    "summary":     summary,
                    # JIRA API v3 uses Atlassian Document Format (ADF) for descriptions
                    "description": {
                        "type": "doc", "version": 1,
                        "content": [{
                            "type": "paragraph",
                            "content": [{"type": "text", "text": description}]
                        }]
                    },
                    "issuetype": {"name": issue_type},
                    "priority":  {"name": priority},
                    "labels":    labels
                }
            },
            timeout=15
        )
        resp.raise_for_status()
        key = resp.json().get("key", "UNKNOWN")
        return f"JIRA ticket created: {key}\nURL: {JIRA_URL}/browse/{key}"

    except http_requests.RequestException as e:
        detail = e.response.text if hasattr(e, "response") and e.response else ""
        return f"Failed to create JIRA ticket: {str(e)}\n{detail}"


@mcp.tool()
def update_jira_ticket(
    ticket_key:      str,
    comment:         str = "",
    transition_name: str = ""
) -> str:
    """
    Add a comment to a JIRA ticket, transition its status, or both.

    Use to post investigation updates, add findings, or move a ticket
    through the workflow (e.g. from 'To Do' to 'In Progress' to 'Done').

    Args:
        ticket_key:      Ticket identifier, e.g. 'PLY-42'.
        comment:         Text to add as a comment. Optional.
        transition_name: Workflow status to move the ticket to. Optional.
                         Examples: 'In Progress', 'Under Review', 'Done'.
                         Must match an available transition for that ticket.

    Returns:
        Result of each operation attempted, or an error message.
    """
    err = _check_config("JIRA_URL", "JIRA_EMAIL", "JIRA_TOKEN")
    if err:
        return err

    if not comment and not transition_name:
        return "ERROR: Provide at least one of: comment, transition_name."

    results = []

    # ── Add comment ───────────────────────────────────────────────────────────
    if comment:
        try:
            resp = http_requests.post(
                f"{JIRA_URL}/rest/api/3/issue/{ticket_key}/comment",
                headers=_jira_headers(),
                auth=_jira_auth(),
                json={
                    "body": {
                        "type": "doc", "version": 1,
                        "content": [{
                            "type": "paragraph",
                            "content": [{"type": "text", "text": comment}]
                        }]
                    }
                },
                timeout=15
            )
            resp.raise_for_status()
            results.append(f"Comment added to {ticket_key}.")

        except http_requests.RequestException as e:
            results.append(f"Failed to add comment: {str(e)}")

    # ── Apply workflow transition ─────────────────────────────────────────────
    # Transitions are ticket-specific — we fetch available ones first,
    # then match by name (case-insensitive) to get the transition ID.
    if transition_name:
        try:
            t_url = f"{JIRA_URL}/rest/api/3/issue/{ticket_key}/transitions"
            transitions = http_requests.get(
                t_url, headers=_jira_headers(), auth=_jira_auth(), timeout=15
            ).json().get("transitions", [])

            matched = next(
                (t for t in transitions if t["name"].lower() == transition_name.lower()),
                None
            )

            if matched:
                http_requests.post(
                    t_url,
                    headers=_jira_headers(),
                    auth=_jira_auth(),
                    json={"transition": {"id": matched["id"]}},
                    timeout=15
                ).raise_for_status()
                results.append(f"Ticket {ticket_key} moved to '{matched['name']}'.")
            else:
                available = [t["name"] for t in transitions]
                results.append(
                    f"Transition '{transition_name}' not found. "
                    f"Available transitions: {available}"
                )

        except http_requests.RequestException as e:
            results.append(f"Failed to apply transition: {str(e)}")

    return "\n".join(results)


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":

    # Refuse to start if the auth token is missing — running without it would
    # expose all tools to anyone on the LAN without authentication.
    if not MCP_AUTH_TOKEN:
        print(
            "ERROR: MCP_AUTH_TOKEN not set.\n"
            "Generate one with: python3.11 -c \"import secrets; print(secrets.token_hex(32))\"\n"
            "Then add it to mcp.env and restart.",
            file=sys.stderr
        )
        sys.exit(1)

    # Startup banner — confirms which integrations are configured
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Synology Home Lab MCP Server", file=sys.stderr)
    print(f"  Listening on:  http://{SERVER_HOST}:{SERVER_PORT}/mcp", file=sys.stderr)
    print(f"  Auth:          Bearer token configured", file=sys.stderr)
    print(f"  Discord:       {'OK' if DISCORD_WEBHOOK_URL else 'NOT CONFIGURED'}", file=sys.stderr)
    print(f"  Azure Sentinel:{'OK' if AZURE_WORKSPACE_ID  else 'NOT CONFIGURED'}", file=sys.stderr)
    print(f"  JIRA:          {'OK' if JIRA_URL            else 'NOT CONFIGURED'}", file=sys.stderr)

    # MCP_ALLOW_ANY_HOST disables FastMCP's strict host-header validation.
    # Without this, requests from IP addresses (not hostnames) are rejected.
    # Required for LAN access via IP (e.g. http://192.168.50.173:9000/mcp).
    os.environ["MCP_ALLOW_ANY_HOST"] = "1"

    app = mcp.streamable_http_app()
    app.add_middleware(BearerTokenMiddleware)
    uvicorn.run(app, host=SERVER_HOST, port=SERVER_PORT)
