#!/bin/bash
# =============================================================================
# start_mcp_server.sh  —  MCP Server Startup Script
# =============================================================================
#
# WHAT THIS DOES:
#   1. Loads your secrets from mcp.env (the single source of truth for all config)
#   2. Checks if the server is already running (avoids duplicate processes)
#   3. Starts synology_mcp_server.py in the background
#   4. Logs all output to /volume1/Misc/logs/mcp_server.log
#
# HOW TO SCHEDULE ON SYNOLOGY (Boot Task):
#   DSM → Control Panel → Task Scheduler → Create → Triggered Task
#     Task name:  Start MCP Server
#     User:       your username (not root)
#     Event:      Boot-up
#     Command:    bash /volume1/Misc/scripts/mcp_server/start_mcp_server.sh
#
# HOW TO SCHEDULE A HEALTH CHECK (Hourly Restart-if-Crashed):
#   DSM → Control Panel → Task Scheduler → Create → Scheduled Task → User-defined script
#     Task name:  MCP Server Health Check
#     Schedule:   Every hour
#     Command:    bash /volume1/Misc/scripts/mcp_server/start_mcp_server.sh
#   The script safely exits if the server is already running, so this is safe
#   to run hourly — it only starts the server if it isn't already up.
#
# HOW TO RUN MANUALLY:
#   bash /volume1/Misc/scripts/mcp_server/start_mcp_server.sh
#
# HOW TO STOP THE SERVER:
#   pkill -f synology_mcp_server.py
#
# HOW TO CHECK IF IT'S RUNNING:
#   pgrep -f synology_mcp_server.py && echo "Running" || echo "Not running"
#
# HOW TO CHECK THE LOGS:
#   tail -f /volume1/Misc/logs/mcp_server.log
#
# =============================================================================

# ── Paths ─────────────────────────────────────────────────────────────────────
# All scripts and config live together in the mcp_server directory.
# Update these paths if you move the directory.
ENV_FILE="/volume1/Misc/scripts/mcp_server/mcp.env"
SERVER_SCRIPT="/volume1/Misc/scripts/mcp_server/synology_mcp_server.py"
LOG_FILE="/volume1/Misc/logs/mcp_server/mcp_server.log"

# Full path to Python 3.11 installed via SynoCommunity.
# Verify with: which python3.11
PYTHON="/usr/local/bin/python3.11"

# ── Load environment variables from mcp.env ───────────────────────────────────
# 'set -a' automatically exports every variable defined after this line.
# 'source' reads the file and sets those variables in the current shell.
# 'set +a' turns off auto-export so it doesn't affect anything after.
# This makes all secrets available to the Python process launched below.
if [ ! -f "$ENV_FILE" ]; then
    echo "[$(date)] ERROR: $ENV_FILE not found. Cannot start MCP server." >&2
    exit 1
fi

set -a
source "$ENV_FILE"
set +a

# ── Create log directory if it doesn't exist ──────────────────────────────────
mkdir -p "$(dirname "$LOG_FILE")"

# ── Check if already running ──────────────────────────────────────────────────
# pgrep searches running processes for a matching pattern.
# If it finds synology_mcp_server.py already running, we exit cleanly.
# This makes the script safe to run on boot AND as an hourly health check.
if pgrep -f "synology_mcp_server.py" > /dev/null 2>&1; then
    echo "[$(date)] MCP server is already running. Nothing to do." >> "$LOG_FILE"
    exit 0
fi

# ── Start the server ──────────────────────────────────────────────────────────
echo "[$(date)] Starting Synology MCP server..." >> "$LOG_FILE"
echo "[$(date)] Python:  $PYTHON"                >> "$LOG_FILE"
echo "[$(date)] Script:  $SERVER_SCRIPT"         >> "$LOG_FILE"
echo "[$(date)] Port:    ${MCP_PORT:-9000}"      >> "$LOG_FILE"
echo "[$(date)] Env:     $ENV_FILE"              >> "$LOG_FILE"

# nohup:        keeps the process alive after this script exits
# >> $LOG_FILE: append stdout to the log file
# 2>&1:         redirect stderr to the same log file
# &:            run in the background so this script returns immediately
nohup "$PYTHON" "$SERVER_SCRIPT" >> "$LOG_FILE" 2>&1 &

# Capture the PID of the background process we just started
MCP_PID=$!
echo "[$(date)] MCP server started with PID $MCP_PID." >> "$LOG_FILE"

# ── Verify the server didn't immediately crash ────────────────────────────────
# Wait 3 seconds for the server to initialize, then check it's still alive.
# kill -0 sends no signal — it just checks if the PID exists.
sleep 3

if kill -0 "$MCP_PID" 2>/dev/null; then
    echo "[$(date)] MCP server confirmed running (PID $MCP_PID)." >> "$LOG_FILE"
    echo "[$(date)] Access at: http://$(hostname -I | awk '{print $1}'):${MCP_PORT:-9000}/mcp" >> "$LOG_FILE"
else
    echo "[$(date)] ERROR: MCP server died immediately after launch. Check the log above for Python errors." >> "$LOG_FILE"
    exit 1
fi
