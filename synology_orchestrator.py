"""
=============================================================================
synology_orchestrator.py  —  Claude Agent Runner (LAN HTTP Version)
=============================================================================

WHAT THIS DOES:
  Connects to the persistent MCP server running on your Synology NAS and
  uses Claude as an AI agent to execute security tasks. Claude calls tools
  on the MCP server (Sentinel, JIRA, Discord) in an agentic loop until the
  task is complete.

HOW IT WORKS:
  1. Loads all config from environment (sourced from mcp.env by the caller)
  2. Connects to http://<synology-ip>:9000/mcp with a Bearer token
  3. Fetches available tools from the MCP server
  4. Sends the task prompt + tool list to Claude
  5. Claude calls tools via the MCP server as needed (agentic loop)
  6. Returns Claude's final response when done

USAGE:
  # Run a named task
  python3 synology_orchestrator.py --task daily_security
  python3 synology_orchestrator.py --task sentinel_threat_hunt
  python3 synology_orchestrator.py --task jira_weekly_review
  python3 synology_orchestrator.py --task sentinel_health_check

  # Run a custom one-off prompt
  python3 synology_orchestrator.py --prompt "Check if ticket PLY-42 was resolved and post an update to Discord"

  # List all available named tasks
  python3 synology_orchestrator.py --list

SCHEDULING IN SYNOLOGY TASK SCHEDULER:
  DSM → Control Panel → Task Scheduler → Create → Scheduled Task → User-defined script
  Command:
    set -a; source /volume1/Misc/scripts/mcp_server/mcp.env; set +a
    python3.11 /volume1/Misc/scripts/mcp_server/synology_orchestrator.py --task daily_security

REQUIREMENTS:
  pip install anthropic "mcp[cli]" --break-system-packages

=============================================================================
"""

import asyncio
import argparse
import json
import os
import sys
from datetime import datetime

import anthropic

# httpx is an async HTTP client used internally by the MCP SDK to connect
# to HTTP-based MCP servers. It's installed automatically with the mcp package.
from mcp.client.streamable_http import streamablehttp_client
from mcp import ClientSession


# =============================================================================
# CONFIGURATION
# =============================================================================
# All values are loaded from environment variables set by mcp.env.
# NEVER hardcode secrets here — the env file is the single source of truth.
#
# To load mcp.env manually for testing:
#   set -a; source /volume1/Misc/scripts/mcp_server/mcp.env; set +a
#   python3.11 synology_orchestrator.py --task sentinel_health_check
# =============================================================================

# ── Anthropic ─────────────────────────────────────────────────────────────────
# Your Anthropic API key — from console.anthropic.com → API Keys
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

# ── MCP Server ────────────────────────────────────────────────────────────────
# MCP_SERVER_URL: full URL to your Synology MCP server endpoint.
#   Built from MCP_HOST and MCP_PORT in mcp.env.
#   Falls back to the Synology LAN IP if MCP_SERVER_URL isn't explicitly set.
#
# MCP_AUTH_TOKEN: shared secret — must match the value on the server side.
#   This is how the orchestrator proves it's allowed to use the MCP tools.
_mcp_host = os.environ.get("MCP_HOST", "")
_mcp_port = os.environ.get("MCP_PORT", "")
MCP_SERVER_URL = os.environ.get(
    "MCP_SERVER_URL",
    f"http://{_mcp_host}:{_mcp_port}/mcp/"
)
MCP_AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN", "")

# ── Claude Model ──────────────────────────────────────────────────────────────
# claude-opus-4-6:    most capable — best for complex multi-step tasks
# claude-sonnet-4-6:  faster and cheaper — good for simpler or routine tasks
# Override by setting CLAUDE_MODEL in mcp.env if desired.
CLAUDE_MODEL = os.environ.get("CLAUDE_MODEL", "claude-opus-4-6")

# ── Safety Limit ──────────────────────────────────────────────────────────────
# Maximum number of tool-call rounds per task.
# Prevents runaway loops if Claude gets stuck or a tool keeps failing.
MAX_TOOL_ROUNDS = 10


# =============================================================================
# NAMED TASKS
# =============================================================================
# Pre-written prompts for recurring security workflows.
# Each task has:
#   system_prompt: tells Claude who it is and how to behave
#   user_prompt:   the actual task instructions
#
# Use {date} anywhere in user_prompt — it's replaced with today's date at runtime.
# Add new tasks here as you automate more of your SOC workflows.
# =============================================================================

TASKS = {

    # ── Daily cross-cloud threat review ───────────────────────────────────────
    "daily_security": {
        "system_prompt": (
            "You are a home network and cloud security analyst. You have tools to query "
            "Azure Sentinel, create and update JIRA tickets, and post to Discord. "
            "Be concise and decisive. When you find something noteworthy, act on it — "
            "don't just describe it. Create JIRA tickets for issues that need tracking, "
            "then always finish by posting a summary to Discord."
        ),
        "user_prompt": (
            "Perform the daily cloud security review:\n"
            "1. Run this Sentinel KQL query to get unique external IPs hitting your Azure VM:\n"
            "   Syslog\n"
            "   | where TimeGenerated > ago(24h)\n"
            "   | where SyslogMessage contains 'Failed password' or SyslogMessage contains 'Invalid user'\n"
            "   | extend AttackerIP = extract(@'from (\\d+\\.\\d+\\.\\d+\\.\\d+)', 1, SyslogMessage)\n"
            "   | where isnotempty(AttackerIP)\n"
            "   | summarize Hits=count() by AttackerIP\n"
            "   | order by Hits desc\n"
            "2. Run this second query to get unique external IPs hitting your AWS honeypot:\n"
            "   AWSVPCFlow\n"
            "   | where TimeGenerated > ago(24h)\n"
            "   | where FlowDirection == 'ingress'\n"
            "   | where SrcAddr !startswith '10.' and SrcAddr !startswith '172.16.' and SrcAddr !startswith '192.168.'\n"
            "   | summarize Hits=count() by SrcAddr\n"
            "   | order by Hits desc\n"
            "3. Compare the two IP lists. If any IP appears in both, that is a cross-cloud "
            "   attacker — create a JIRA ticket with priority 'High', label 'cross-cloud-attacker', "
            "   and list the IP, hit counts per cloud, and recommended action.\n"
            "4. If either cloud has a single IP with more than 100 hits, create a JIRA ticket "
            "   with priority 'Medium' and label 'brute-force'.\n"
            "5. Post a Discord summary covering:\n"
            "   - Unique attacker IPs on Azure: <count>\n"
            "   - Unique attacker IPs on AWS: <count>\n"
            "   - Cross-cloud attackers found: <count or 'none'>\n"
            "   - Any JIRA tickets created: <keys or 'none'>\n"
            "   Keep it under 15 lines."
        )
    },

    # ── Threat hunt: successful brute force detection ─────────────────────────
    "sentinel_threat_hunt": {
        "system_prompt": (
            "You are a threat hunter with expertise in KQL and Microsoft Sentinel. "
            "You have tools to run KQL queries, create JIRA tickets, and post to Discord. "
            "Be methodical: start broad, narrow down on hits, document everything."
        ),
        "user_prompt": (
            "Run a focused threat hunt for the last 48 hours:\n"
            "1. Query for any IP addresses that appear in both failed and successful "
            "   sign-in attempts (potential successful brute force):\n"
            "   let failed = SigninLogs | where ResultType != '0' | distinct IPAddress;\n"
            "   let success = SigninLogs | where ResultType == '0' | distinct IPAddress;\n"
            "   success | where IPAddress in (failed) | join kind=inner "
            "   (SigninLogs | where ResultType == '0') on IPAddress\n"
            "   | project TimeGenerated, UserPrincipalName, IPAddress, Location\n"
            "2. For any hits, create a JIRA ticket with priority 'Highest', issue type 'Bug', "
            "   and label 'possible-compromise'. Include the affected users and IPs.\n"
            "3. Post a Discord summary with your findings and any ticket numbers created."
        )
    },

    # ── Weekly detection lifecycle review ticket ──────────────────────────────
    "jira_weekly_review": {
        "system_prompt": (
            "You are a security operations manager running a weekly detection review. "
            "You have tools to create JIRA tickets and post to Discord."
        ),
        "user_prompt": (
            "Create the weekly detection lifecycle review:\n"
            "1. Create a JIRA ticket with:\n"
            "   - Summary: 'Weekly Detection Review - {date}'\n"
            "   - Issue type: Task\n"
            "   - Priority: Medium\n"
            "   - Labels: ['weekly-review', 'detection-lifecycle']\n"
            "   - Description: 'Weekly review of enabled detections. Review coverage gaps, "
            "     false positive rates, and tuning opportunities for the week of {date}.'\n"
            "2. Post a Discord message announcing the review ticket was created. "
            "   Include the ticket key, URL, and a note that the review should be "
            "   completed by end of week."
        )
    },

    # ── Sentinel workspace ingestion health check ─────────────────────────────
    "sentinel_health_check": {
        "system_prompt": (
            "You are a Sentinel workspace administrator. You have tools to run KQL queries "
            "and post to Discord. Focus on data freshness and ingestion health."
        ),
        "user_prompt": (
            "Check the health of the Sentinel workspace:\n"
            "1. Query for data ingestion in the last 2 hours across key tables:\n"
            "   union SigninLogs, AzureActivity, SecurityEvent\n"
            "   | where TimeGenerated > ago(2h)\n"
            "   | summarize Count=count(), LastEvent=max(TimeGenerated) by Type\n"
            "   | order by LastEvent asc\n"
            "2. Flag any table where LastEvent is more than 90 minutes ago — that "
            "   suggests an ingestion delay or connector issue.\n"
            "3. Post a Discord status message. Use ✅ for healthy tables and ⚠️ for "
            "   delayed ones. Keep it short — one line per table."
        )
    },

}


# =============================================================================
# AGENT RUNNER
# =============================================================================

async def run_agent(task_name: str = None, custom_prompt: str = None) -> str | None:
    """
    Connect to the LAN MCP server and run Claude as an agent until the
    task is complete or the MAX_TOOL_ROUNDS limit is reached.

    The agentic loop works like this:
      1. Send user prompt + available tools to Claude
      2. If Claude wants to call a tool (stop_reason == 'tool_use'):
           - Execute the tool call on the MCP server
           - Feed the result back to Claude as a user message
           - Repeat
      3. When Claude is done (stop_reason == 'end_turn'):
           - Return the final text response
    """

    # ── Resolve the task ──────────────────────────────────────────────────────
    today = datetime.now().strftime("%Y-%m-%d")

    if task_name and task_name in TASKS:
        task          = TASKS[task_name]
        system_prompt = task["system_prompt"]
        user_prompt   = task["user_prompt"].replace("{date}", today)
        label         = task_name

    elif custom_prompt:
        # Custom one-off prompt — generic system context
        system_prompt = (
            "You are a home lab automation assistant with access to Azure Sentinel, "
            "JIRA, and Discord tools. Complete the requested task using available tools. "
            "Always post a Discord summary when you're done."
        )
        user_prompt = custom_prompt
        label       = "custom"

    else:
        print("ERROR: Provide --task <name> or --prompt <text>.", file=sys.stderr)
        sys.exit(1)

    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Task:      {label}")
    print(f"[{datetime.now().strftime('%H:%M:%S')}] MCP URL:   {MCP_SERVER_URL}")
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Model:     {CLAUDE_MODEL}")

    # ── Validate auth token ───────────────────────────────────────────────────
    if not MCP_AUTH_TOKEN:
        print("ERROR: MCP_AUTH_TOKEN is not set. Check mcp.env.", file=sys.stderr)
        sys.exit(1)

    # Every HTTP request to the MCP server must include this header.
    # The server's BearerTokenMiddleware validates it before running any tool.
    headers = {"Authorization": f"Bearer {MCP_AUTH_TOKEN}"}

    # ── Connect to the MCP server ─────────────────────────────────────────────
    # streamablehttp_client opens a persistent HTTP connection using SSE.
    # The 'async with' block ensures the connection is cleanly closed when done,
    # even if an exception occurs.
    async with streamablehttp_client(MCP_SERVER_URL, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:

            # Protocol handshake — client and server agree on MCP version
            await session.initialize()
            print(f"[{datetime.now().strftime('%H:%M:%S')}] MCP session established.")

            # Fetch the list of available tools from the server
            tools_resp = await session.list_tools()
            available  = tools_resp.tools
            tool_names = [t.name for t in available]
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Available tools: {tool_names}\n")

            # Convert MCP tool definitions to Anthropic API format.
            # The structures are nearly identical — this bridges the small differences.
            anthropic_tools = [
                {
                    "name":         t.name,
                    "description":  t.description,
                    "input_schema": t.inputSchema
                }
                for t in available
            ]

            # ── Initialize Anthropic client ───────────────────────────────────
            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

            # ── Seed the conversation with the task prompt ────────────────────
            messages = [{"role": "user", "content": user_prompt}]

            # ── Agentic loop ──────────────────────────────────────────────────
            for round_num in range(1, MAX_TOOL_ROUNDS + 1):
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Round {round_num}: calling Claude...")

                response = client.messages.create(
                    model=CLAUDE_MODEL,
                    max_tokens=4096,
                    system=system_prompt,
                    tools=anthropic_tools,
                    messages=messages
                )

                print(f"[{datetime.now().strftime('%H:%M:%S')}] Stop reason: {response.stop_reason}")

                # ── Task complete ─────────────────────────────────────────────
                if response.stop_reason == "end_turn":
                    final = "".join(
                        block.text for block in response.content
                        if hasattr(block, "text")
                    )
                    print(f"\n{'='*60}\nFINAL RESPONSE:\n{'='*60}\n{final}\n{'='*60}\n")
                    return final

                # ── Tool calls ────────────────────────────────────────────────
                elif response.stop_reason == "tool_use":

                    # Append Claude's full response (including tool_use blocks) to history.
                    # This is required — Claude needs to see its own tool calls in context.
                    messages.append({"role": "assistant", "content": response.content})

                    tool_results = []

                    for block in response.content:
                        if block.type != "tool_use":
                            continue

                        print(f"[{datetime.now().strftime('%H:%M:%S')}]   → {block.name}({json.dumps(block.input)[:120]})")

                        try:
                            # Execute the tool on the MCP server over HTTP
                            result     = await session.call_tool(block.name, block.input)
                            result_str = "".join(
                                c.text for c in result.content if hasattr(c, "text")
                            )
                            print(f"[{datetime.now().strftime('%H:%M:%S')}]   ← {result_str[:150]}")

                        except Exception as e:
                            result_str = f"Tool error: {str(e)}"
                            print(f"[{datetime.now().strftime('%H:%M:%S')}]   ← ERROR: {result_str}", file=sys.stderr)

                        # Each tool result must reference the tool_use_id from Claude's request
                        tool_results.append({
                            "type":        "tool_result",
                            "tool_use_id": block.id,
                            "content":     result_str
                        })

                    # Feed all tool results back to Claude as a user message to continue the loop
                    messages.append({"role": "user", "content": tool_results})

                else:
                    print(f"Unexpected stop reason: {response.stop_reason}", file=sys.stderr)
                    break

            print("WARNING: Hit maximum tool rounds without task completion.", file=sys.stderr)
            return None


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Run Claude as an agent via the Synology LAN MCP server.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 synology_orchestrator.py --task daily_security
  python3 synology_orchestrator.py --task sentinel_threat_hunt
  python3 synology_orchestrator.py --task jira_weekly_review
  python3 synology_orchestrator.py --task sentinel_health_check
  python3 synology_orchestrator.py --prompt "Did PLY-42 get resolved? Post an update to Discord."
  python3 synology_orchestrator.py --list
        """
    )
    parser.add_argument("--task",   type=str, help="Name of a pre-defined task.")
    parser.add_argument("--prompt", type=str, help="Custom one-off task prompt.")
    parser.add_argument("--list",   action="store_true", help="List all available named tasks.")
    args = parser.parse_args()

    if args.list:
        print("\nAvailable tasks:")
        for name, task in TASKS.items():
            preview = task["user_prompt"].split("\n")[0]
            print(f"  {name:<28} {preview[:60]}")
        print()
        sys.exit(0)

    if not ANTHROPIC_API_KEY:
        print("ERROR: ANTHROPIC_API_KEY is not set. Check mcp.env.", file=sys.stderr)
        sys.exit(1)

    asyncio.run(run_agent(task_name=args.task, custom_prompt=args.prompt))


if __name__ == "__main__":
    main()
