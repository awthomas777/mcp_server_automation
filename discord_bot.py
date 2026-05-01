"""
=============================================================================
discord_bot.py  —  Discord Keyword Bot for Synology MCP Server
=============================================================================

WHAT THIS DOES:
  Listens to an input Discord channel for exact keyword commands.
  When a keyword is detected, it posts an acknowledgement in the input
  channel, runs a Claude agent task via the Synology MCP server, and
  posts the full results to a separate output channel.

CHANNELS:
  Input  (keywords typed here): DISCORD_CHANNEL_ID in mcp.env
  Output (results posted here): DISCORD_OUTPUT_CHANNEL_ID in mcp.env

KEYWORDS:
  threat_intel   → searches open source threat intel sources for recent
                   threat actor activity, posts summary to JIRA (PLY-14)
  sentinel_vms   → queries Azure Sentinel for unique IPs hitting both VMs
                   since the last time this keyword was run, posts to JIRA (PLY-12)
  gold           → web search for gold price, trends, and economic indicators
  fidelity       → web search for FZROX and FZILX performance and projections

HOW TO RUN:
  set -a; source /volume1/Misc/scripts/mcp_server/mcp.env; set +a
  python3.11 /volume1/Misc/scripts/mcp_server/discord_bot.py

HOW TO RUN AS BACKGROUND SERVICE:
  nohup python3.11 /volume1/Misc/scripts/mcp_server/discord_bot.py \
    >> /volume1/Misc/logs/discord_bot.log 2>&1 &

HOW TO STOP:
  pkill -f discord_bot.py

HOW TO CHECK IF RUNNING:
  pgrep -f discord_bot.py && echo "Running" || echo "Not running"

ADDING TO TASK SCHEDULER (boot task):
  bash /volume1/Misc/scripts/mcp_server/start_discord_bot.sh

REQUIREMENTS:
  pip install discord.py anthropic "mcp[cli]" --break-system-packages

DISCORD BOT SETUP (one-time):
  1. Go to https://discord.com/developers/applications
  2. New Application → give it a name
  3. Bot → Add Bot → copy the token → add as DISCORD_BOT_TOKEN in mcp.env
  4. Bot → enable 'Message Content Intent' (required to read message text)
  5. OAuth2 → URL Generator → scopes: bot → permissions: Read Messages,
     Send Messages, Read Message History
  6. Copy the generated URL, open it, add the bot to your server
  7. Get your channel ID: Discord → Settings → Advanced → enable Developer
     Mode → right-click your channel → Copy Channel ID
     Add as DISCORD_CHANNEL_ID in mcp.env

=============================================================================
"""

import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path

import anthropic
import discord
from mcp.client.streamable_http import streamablehttp_client
from mcp import ClientSession


# =============================================================================
# CONFIGURATION
# =============================================================================
# All values loaded from mcp.env — never hardcode secrets here.
# =============================================================================

# ── Discord ───────────────────────────────────────────────────────────────────
# DISCORD_BOT_TOKEN:         from Discord Developer Portal → your app → Bot → Token
# DISCORD_CHANNEL_ID:        input channel — where you type keywords
# DISCORD_OUTPUT_CHANNEL_ID: output channel — where results are posted
#                            Both IDs: right-click channel → Copy Channel ID
#                            (requires Developer Mode in Discord settings)
DISCORD_BOT_TOKEN         = os.environ.get("DISCORD_BOT_TOKEN", "")
DISCORD_CHANNEL_ID        = int(os.environ.get("DISCORD_CHANNEL_ID", "0"))
DISCORD_OUTPUT_CHANNEL_ID = int(os.environ.get("DISCORD_OUTPUT_CHANNEL_ID", "0"))

# ── MCP Server ────────────────────────────────────────────────────────────────
_mcp_host      = os.environ.get("MCP_HOST", "")
_mcp_port      = os.environ.get("MCP_PORT", "")
MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", f"http://{_mcp_host}:{_mcp_port}/mcp/")
MCP_AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN", "")

# ── Anthropic ─────────────────────────────────────────────────────────────────
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

# ── Models ────────────────────────────────────────────────────────────────────
# Default model for tasks that need deep reasoning (Sentinel queries, JIRA logic)
CLAUDE_MODEL_DEFAULT = os.environ.get("CLAUDE_MODEL", "claude-opus-4-6")

# Research/summarization tasks (threat_intel, gold, fidelity) use Sonnet:
#   - Higher rate limits (less likely to hit 429 with large web search results)
#   - Handles summarization and web research just as well as Opus
#   - Significantly more token-efficient for long web search responses
CLAUDE_MODEL_RESEARCH = "claude-sonnet-4-6"

# Per-task model assignment — override here if you want to change a specific task
TASK_MODELS = {
    "threat_intel":  CLAUDE_MODEL_RESEARCH,  # web research — uses Sonnet
    "sentinel_vms":  CLAUDE_MODEL_DEFAULT,   # KQL + JIRA logic — uses Opus
    "gold":          CLAUDE_MODEL_RESEARCH,  # web research — uses Sonnet
    "fidelity":      CLAUDE_MODEL_RESEARCH,  # web research — uses Sonnet
}

# ── JIRA Epics ────────────────────────────────────────────────────────────────
# These Epic keys are used to link new tickets to the correct Epic in JIRA.
# PLY-14 = threat_intel Epic
# PLY-12 = microsoft_azure / sentinel Epic
JIRA_EPIC_THREAT_INTEL = "PLY-14"
JIRA_EPIC_SENTINEL     = "PLY-12"

# ── Last-run tracking ─────────────────────────────────────────────────────────
# sentinel_vms tracks when it last ran so it only queries new data each time.
# The timestamp is stored in this file on the NAS.
LAST_RUN_FILE = "/volume1/Misc/scripts/mcp_server/.last_run_times.json"

# ── Agent safety limit ────────────────────────────────────────────────────────
MAX_TOOL_ROUNDS = 15


# =============================================================================
# LAST-RUN TRACKING
# =============================================================================
# Reads and writes timestamps to a local JSON file so sentinel_vms knows
# how far back to query each time it runs.
# =============================================================================

def load_last_run_times() -> dict:
    """Load the last-run timestamp dict from disk. Returns empty dict if missing."""
    try:
        with open(LAST_RUN_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_last_run_time(keyword: str):
    """Save the current UTC time as the last-run timestamp for a keyword."""
    times = load_last_run_times()
    times[keyword] = datetime.utcnow().isoformat()
    Path(LAST_RUN_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(LAST_RUN_FILE, "w") as f:
        json.dump(times, f, indent=2)


def get_hours_since_last_run(keyword: str) -> int:
    """
    Return how many hours have passed since the keyword last ran.
    Defaults to 24 hours if no prior run is recorded.
    """
    times = load_last_run_times()
    if keyword not in times:
        return 24  # default on first run
    last = datetime.fromisoformat(times[keyword])
    delta = datetime.utcnow() - last
    hours = max(1, int(delta.total_seconds() / 3600))
    return hours


# =============================================================================
# KEYWORD TASK DEFINITIONS
# =============================================================================
# Each keyword maps to a system_prompt and user_prompt for Claude.
# The agent runner below executes these via the MCP server tools.
# {lookback_hours} is replaced at runtime with the actual hours since last run.
# =============================================================================

def build_tasks(lookback_hours: int) -> dict:
    return {

        # ── Threat Intel ──────────────────────────────────────────────────────
        # Searches open source threat intel for recent actor activity,
        # creates a JIRA ticket linked to the threat_intel Epic (PLY-14).
        "threat_intel": {
            "system_prompt": (
                "You are a cyber threat intelligence analyst. You have tools to search "
                "the web, create JIRA tickets, and post to Discord. "
                "Be concise and structured. Focus only on the most actionable findings."
            ),
            "user_prompt": (
                "Perform a focused threat intelligence sweep for the last 7 days:\n"
                "1. Run two searches only. You MUST only use articles or advisories published in the last 7 days — ignore anything older:\n"
                f"   - Search 1: 'threat actor activity {datetime.now().strftime('%B %Y')} site:thedfirreport.com'\n"
                f"   - Search 2: 'CVE exploited in the wild {datetime.now().strftime('%B %Y')} site:cisa.gov'\n"
                "   If no results are found from the last 7 days on either source, say so explicitly and do not substitute older articles.\n"
                "2. From the results identify the top 2-3 most notable findings. For each collect:\n"
                "   - Actor name or CVE ID\n"
                "   - Targeted industries\n"
                "   - Key indicators or TTPs (keep to 2-3 bullet points max)\n"
                "   - Source URL\n"
                f"3. Create a single JIRA ticket with:\n"
                "   - Summary: 'Weekly Threat Intel Summary - {date}'\n"
                "   - Issue type: Task\n"
                "   - Priority: Medium\n"
                f"   - Labels: ['threat-intel', 'weekly-review']\n"
                f"   - Epic Link: {JIRA_EPIC_THREAT_INTEL}\n"
                "   - Description: concise list of findings with actor/CVE, industries, indicators, source\n"
                "4. Post a Discord summary (5-8 lines max) with:\n"
                "   - Top findings and targeted industries\n"
                "   - JIRA ticket key and full URL (e.g. PLY-42: https://...atlassian.net/browse/PLY-42)"
            ).replace("{date}", datetime.now().strftime("%Y-%m-%d"))
        },

        # ── Sentinel VMs ──────────────────────────────────────────────────────
        # Queries both cloud VM logs for unique attacker IPs since last run,
        # creates a JIRA ticket linked to the azure Epic (PLY-12).
        "sentinel_vms": {
            "system_prompt": (
                "You are a cloud security analyst. You have tools to query Azure Sentinel, "
                "create JIRA tickets, and post to Discord. "
                "Be concise and data-driven. Focus on unique IPs and top hitters. Make no assumptions."
            ),
            "user_prompt": (
                f"Query both cloud VM logs for the past {lookback_hours} hours "
                f"(since the last time this ran):\n"
                "1. Run this KQL query for the Azure VM (SSH brute force attempts):\n"
                "   Syslog\n"
                f"  | where TimeGenerated > ago({lookback_hours}h)\n"
                "   | where SyslogMessage contains 'Failed password' or SyslogMessage contains 'Invalid user'\n"
                "   | extend AttackerIP = extract(@'from (\\d+\\.\\d+\\.\\d+\\.\\d+)', 1, SyslogMessage)\n"
                "   | where isnotempty(AttackerIP)\n"
                "   | summarize Hits=count() by AttackerIP\n"
                "   | order by Hits desc\n"
                "2. Run this KQL query for the AWS honeypot VM (VPC flow ingress):\n"
                "   AWSVPCFlow\n"
                f"  | where TimeGenerated > ago({lookback_hours}h)\n"
                "   | where FlowDirection == 'ingress'\n"
                "   | where SrcAddr !startswith '10.' and SrcAddr !startswith '172.16.' and SrcAddr !startswith '192.168.'\n"
                "   | summarize Hits=count() by SrcAddr\n"
                "   | order by Hits desc\n"
                "3. Summarize the results:\n"
                "   - Total unique IPs per cloud\n"
                "   - Top 5 IPs by hit count per cloud\n"
                "   - Any IPs appearing in BOTH clouds (cross-cloud attackers)\n"
                "4. Create a JIRA ticket with:\n"
                "   - Summary: 'VM Attacker IP Summary - {date}'\n"
                "   - Issue type: Task\n"
                "   - Priority: Medium\n"
                f"  - Labels: ['sentinel', 'vm-traffic', 'ip-summary']\n"
                f"  - Epic Link: {JIRA_EPIC_SENTINEL}\n"
                "   - Description: full IP summary table with hit counts per cloud, "
                "     flagging any cross-cloud IPs as High priority findings\n"
                "5. Post a Discord summary (under 15 lines) covering:\n"
                "   - Lookback window used\n"
                "   - Unique attacker IPs: Azure vs AWS\n"
                "   - Top hitter per cloud\n"
                "   - Cross-cloud attackers: count or 'none'\n"
                "   - JIRA ticket key and full URL"
            ).replace("{date}", datetime.now().strftime("%Y-%m-%d"))
        },

        # ── Gold ──────────────────────────────────────────────────────────────
        # Web search for current gold price, trends, and economic indicators.
        "gold": {
            "system_prompt": (
                "You are a commodity market analyst. You have tools to search the web "
                "and post to Discord. Be concise and focus on actionable price insights."
            ),
            "user_prompt": (
                "Research the current gold market:\n"
                "1. Search the web for:\n"
                "   - Current gold spot price (USD per troy ounce)\n"
                "   - Gold price trend over the past 7 days\n"
                "   - Top 2-3 recent news articles on gold (last 7 days)\n"
                "   - Economic indicators relevant to gold (USD strength, inflation data, Fed rates)\n"
                "2. Post a Discord summary covering all the of the content found in the web search. Please provide 4 bullet points with the spot price, the 7 day trend, and two or three top economic indicators. Link the sources in the discord output.\n"
            )
        },

        # ── Fidelity Index Funds ──────────────────────────────────────────────
        # Web search for FZROX and FZILX current prices and performance data.
        "fidelity": {
            "system_prompt": (
                "You are a personal finance analyst specializing in index funds. You are particularly skilled in prediction markets and long-term investing strategy."
                "You have tools to search the web and post to Discord. "
                "Be factual, concise, and only provide objective analysis on the data collected with no assumptions made."
            ),
            "user_prompt": (
                "Research the current performance of two Fidelity ZERO index funds:\n"
                "1. Search the web for current data on FZROX (Fidelity ZERO Total Market Index Fund) and FZILX (Fidelity ZERO International Index Fund):\n"
                "   - Current NAV/price of both index funds\n"
                "   - Recent performance (1 week, YTD if available)\n"
                "   - 2 bullet points on public performance projections or economic indicators\n"
                "     relevant to US total market funds (GDP, earnings season, Fed policy)\n"
                "3. Post a Discord summary structured as:\n"
                "   **FZROX** (US Total Market)\n"
                "   - Price: $X.XX | 1W: +/-X% | YTD: +/-X%\n"
                "   - [bullet 1]\n"
                "   - [bullet 2]\n\n"
                "   **FZILX** (International)\n"
                "   - Price: $X.XX | 1W: +/-X% | YTD: +/-X%\n"
                "   - [bullet 1]\n"
                "   - [bullet 2]\n\n"
                "   Keep the total post under 10 lines."
            )
        },
    }


# =============================================================================
# AGENT RUNNER
# =============================================================================
# Connects to the MCP server and runs Claude in an agentic loop until
# the task is complete or MAX_TOOL_ROUNDS is hit.
# =============================================================================

async def run_agent(system_prompt: str, user_prompt: str, model: str, label: str, input_channel) -> str | None:
    """
    Connect to the LAN MCP server and run Claude as an agent.
    Returns Claude's final text response, or None if the loop hit the round limit.
    """
    if not MCP_AUTH_TOKEN:
        print("ERROR: MCP_AUTH_TOKEN not set.", file=sys.stderr)
        return None

    headers = {"Authorization": f"Bearer {MCP_AUTH_TOKEN}"}

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Running agent task: {label} (model: {model})")

    try:
        async with streamablehttp_client(MCP_SERVER_URL, headers=headers) as (read, write, _):
            async with ClientSession(read, write) as session:
                return await _agent_loop(session, system_prompt, user_prompt, model, label, input_channel)

    except ExceptionGroup as eg:
        # MCP nests TaskGroups multiple levels deep — recursively unwrap
        # until we find the actual root exceptions
        def unwrap(exc_group, depth=0):
            results = []
            for e in exc_group.exceptions:
                if isinstance(e, ExceptionGroup):
                    results.extend(unwrap(e, depth + 1))
                else:
                    results.append(e)
            return results

        root_errors = unwrap(eg)
        real_errors = "\n".join(f"  - {type(e).__name__}: {e}" for e in root_errors)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Root errors:\n{real_errors}", file=sys.stderr)
        raise RuntimeError(f"MCP connection failed:\n{real_errors}") from eg


async def _agent_loop(session, system_prompt: str, user_prompt: str, model: str, label: str, input_channel) -> str | None:
    """Inner agent loop — separated so TaskGroup exceptions can be caught cleanly."""

    await session.initialize()

    tools_resp  = await session.list_tools()
    # MCP tools (Discord, Sentinel, JIRA) from the local server
    mcp_tools = [
        {
            "name":         t.name,
            "description":  t.description,
            "input_schema": t.inputSchema
        }
        for t in tools_resp.tools
    ]

    # Anthropic's built-in web search tool — provides live search results
    # directly via the Anthropic API with no extra API keys needed.
    # Used by gold and fidelity tasks to pull current market data.
    web_search_tool = {"type": "web_search_20250305", "name": "web_search"}

    # Combine both tool sets — Claude can use any of them
    anthropic_tools = mcp_tools + [web_search_tool]

    client   = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    messages = [{"role": "user", "content": user_prompt}]

    for round_num in range(1, MAX_TOOL_ROUNDS + 1):
        print(f"[{datetime.now().strftime('%H:%M:%S')}]   Round {round_num}...")

        # Retry loop for rate limit errors (429).
        # The token limit resets every 60 seconds — we wait and retry up to 3 times
        # before giving up. This handles occasional spikes from large web search results.
        response = None
        for attempt in range(3):
            try:
                response = client.messages.create(
                    model=model,
                    max_tokens=8192,
                    system=system_prompt,
                    tools=anthropic_tools,
                    messages=messages
                )
                break  # success — exit retry loop
            except anthropic.RateLimitError as e:
                wait = 60 * (attempt + 1)  # 60s, 120s, 180s
                print(
                    f"[{datetime.now().strftime('%H:%M:%S')}]   Rate limit hit "
                    f"(attempt {attempt + 1}/3) — waiting {wait}s...",
                    file=sys.stderr
                )
                await asyncio.sleep(wait)
                if attempt == 2:
                    raise  # re-raise after final attempt

        if response is None:
            break

        if response.stop_reason == "end_turn":
            final = "".join(
                block.text for block in response.content
                if hasattr(block, "text")
            )
            print(f"[{datetime.now().strftime('%H:%M:%S')}]   Task complete.")
            return final

        elif response.stop_reason == "tool_use":
            messages.append({"role": "assistant", "content": response.content})
            tool_results = []

            for block in response.content:
                if block.type != "tool_use":
                    continue

                # web_search is handled natively by the Anthropic API —
                # we don't call it ourselves or return a tool_result for it.
                # Claude receives the search results automatically.
                if block.name == "web_search":
                    print(f"[{datetime.now().strftime('%H:%M:%S')}]   → web_search (native)")
                    continue

                # All other tools are MCP tools — call them on the local server
                print(f"[{datetime.now().strftime('%H:%M:%S')}]   → {block.name}({json.dumps(block.input)[:100]})")

                try:
                    result     = await session.call_tool(block.name, block.input)
                    result_str = "".join(
                        c.text for c in result.content if hasattr(c, "text")
                    )
                    print(f"[{datetime.now().strftime('%H:%M:%S')}]   ← {result_str[:120]}")
                except Exception as e:
                    result_str = f"Tool error: {str(e)}"
                    print(f"[{datetime.now().strftime('%H:%M:%S')}]   ← ERROR: {result_str}", file=sys.stderr)

                tool_results.append({
                    "type":        "tool_result",
                    "tool_use_id": block.id,
                    "content":     result_str
                })

            # Only append user message if there are MCP tool results to feed back.
            # Web search results are already in the assistant message content.
            if tool_results:
                messages.append({"role": "user", "content": tool_results})

        else:
            print(f"Unexpected stop reason: {response.stop_reason}", file=sys.stderr)
            break

    print("WARNING: Hit maximum tool rounds.", file=sys.stderr)
    return None


# =============================================================================
# DISCORD BOT
# =============================================================================

# intents define what events the bot can receive.
# message_content is required to read the text of messages — must also be
# enabled in the Discord Developer Portal under Bot → Privileged Gateway Intents.
intents                 = discord.Intents.default()
intents.message_content = True

client = discord.Client(intents=intents)


@client.event
async def on_ready():
    """Fired once when the bot successfully connects to Discord."""
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Discord bot online as {client.user}")
    print(f"  Input channel  (keywords): {DISCORD_CHANNEL_ID}")
    print(f"  Output channel (results):  {DISCORD_OUTPUT_CHANNEL_ID}")
    print(f"  Keywords: threat_intel | sentinel_vms | gold | fidelity")


@client.event
async def on_message(message: discord.Message):
    """
    Fired on every message in any channel the bot can see.
    - Listens for keywords in the input channel only
    - Posts acknowledgement back to the input channel
    - Posts all results to the output channel
    """

    # Ignore messages from the bot itself — prevents feedback loops
    if message.author == client.user:
        return

    # Only process messages from the input channel
    if message.channel.id != DISCORD_CHANNEL_ID:
        return

    # Exact keyword match only — strip whitespace, case-insensitive
    keyword = message.content.strip().lower()

    valid_keywords = {"threat_intel", "sentinel_vms", "gold", "fidelity"}
    if keyword not in valid_keywords:
        return

    # ── Get both channels ─────────────────────────────────────────────────────
    input_channel  = message.channel
    output_channel = client.get_channel(DISCORD_OUTPUT_CHANNEL_ID)

    if not output_channel:
        await input_channel.send(
            f"❌ Could not find output channel ID `{DISCORD_OUTPUT_CHANNEL_ID}`. "
            f"Check DISCORD_OUTPUT_CHANNEL_ID in mcp.env."
        )
        return

    # ── Acknowledge in the input channel ─────────────────────────────────────
    # Lets you know the bot saw the keyword — results will appear in output channel
    await input_channel.send(
        f"⚙️ **`{keyword}`** received — running task now. "
        f"Results will be posted in <#{DISCORD_OUTPUT_CHANNEL_ID}>. "
        f"If it takes longer than expected, the bot may be cycling through rate limit retries — this is normal."
    )

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Keyword triggered: {keyword} by {message.author}")

    # ── Build the task ────────────────────────────────────────────────────────
    lookback_hours = get_hours_since_last_run("sentinel_vms") if keyword == "sentinel_vms" else 24
    tasks          = build_tasks(lookback_hours)
    task           = tasks[keyword]

    # ── Run the agent as a background task ───────────────────────────────────
    # asyncio.create_task() runs the agent concurrently without blocking the
    # Discord event loop. This keeps the bot responsive to new keywords while
    # a long-running task (gold, fidelity) is still executing.
    asyncio.create_task(
        _run_and_post(keyword, task, TASK_MODELS.get(keyword, CLAUDE_MODEL_DEFAULT), input_channel, output_channel)
    )


async def _run_and_post(
    keyword:        str,
    task:           dict,
    model:          str,
    input_channel:  discord.TextChannel,
    output_channel: discord.TextChannel
):
    """
    Runs the agent task and posts the result to the output channel.
    Posts failure notifications to the input channel so the user knows
    not to wait for results that won't be coming.
    Runs as a background asyncio task so the Discord event loop stays free.
    """
    try:
        result = await run_agent(
            system_prompt=task["system_prompt"],
            user_prompt=task["user_prompt"],
            model=model,
            label=keyword,
            input_channel=input_channel
        )

        # Save last-run time for sentinel_vms after a successful run
        if keyword == "sentinel_vms" and result:
            save_last_run_time("sentinel_vms")
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Last-run time saved for sentinel_vms.")

        # Task hit the round limit without finishing — notify both channels
        if not result:
            await input_channel.send(
                f"⚠️ **`{keyword}`** hit the tool round limit and did not complete. "
                f"No output will be posted."
            )
            await output_channel.send(
                f"⚠️ **`{keyword}`** task hit the tool round limit without completing. "
                f"Check `/volume1/Misc/logs/discord_bot.log` for details."
            )

    except Exception as e:
        error_msg = str(e)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR during {keyword}: {error_msg}", file=sys.stderr)
        # Notify input channel so user knows results won't be coming
        await input_channel.send(
            f"❌ **`{keyword}`** failed — no output will be posted. "
            f"Error: `{error_msg[:200]}`"
        )
        # Post full error detail to output channel for debugging
        await output_channel.send(
            f"❌ **`{keyword}`** task failed with an error:\n```{error_msg[:500]}```"
        )


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":

    # Validate required config before starting
    missing = []
    if not DISCORD_BOT_TOKEN:
        missing.append("DISCORD_BOT_TOKEN")
    if not DISCORD_CHANNEL_ID:
        missing.append("DISCORD_CHANNEL_ID")
    if not DISCORD_OUTPUT_CHANNEL_ID:
        missing.append("DISCORD_OUTPUT_CHANNEL_ID")
    if not ANTHROPIC_API_KEY:
        missing.append("ANTHROPIC_API_KEY")
    if not MCP_AUTH_TOKEN:
        missing.append("MCP_AUTH_TOKEN")

    if missing:
        print(f"ERROR: Missing required config: {', '.join(missing)}", file=sys.stderr)
        print("Add these to /volume1/Misc/scripts/mcp_server/mcp.env and reload.", file=sys.stderr)
        sys.exit(1)

    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting Discord bot...")
    print(f"  Channel ID:    {DISCORD_CHANNEL_ID}")
    print(f"  MCP Server:    {MCP_SERVER_URL}")
    print(f"  Model default: {CLAUDE_MODEL_DEFAULT}")
    print(f"  Model research:{CLAUDE_MODEL_RESEARCH}")

    client.run(DISCORD_BOT_TOKEN)
