#!/bin/bash
# =============================================================================
# start_discord_bot.sh  —  Discord Bot Startup Script
# =============================================================================
#
# WHAT THIS DOES:
#   1. Loads secrets from mcp.env
#   2. Checks if the bot is already running
#   3. Starts discord_bot.py in the background
#   4. Logs output to /volume1/Misc/logs/discord_bot.log
#
# HOW TO SCHEDULE ON SYNOLOGY (Boot Task):
#   DSM → Control Panel → Task Scheduler → Create → Triggered Task
#     Task name:  Start Discord Bot
#     User:       your username (not root)
#     Event:      Boot-up
#     Command:    bash /volume1/Misc/scripts/mcp_server/start_discord_bot.sh
#
# HOW TO RUN MANUALLY:
#   bash /volume1/Misc/scripts/mcp_server/start_discord_bot.sh
#
# HOW TO STOP:
#   pkill -f discord_bot.py
#
# HOW TO CHECK IF RUNNING:
#   pgrep -f discord_bot.py && echo "Running" || echo "Not running"
#
# HOW TO CHECK LOGS:
#   tail -f /volume1/Misc/logs/discord_bot.log
# =============================================================================

ENV_FILE="/volume1/Misc/scripts/mcp_server/mcp.env"
BOT_SCRIPT="/volume1/Misc/scripts/mcp_server/discord_bot.py"
LOG_FILE="/volume1/Misc/logs/discord_bot.log"
PYTHON="/usr/local/bin/python3.11"

# ── Load environment variables ────────────────────────────────────────────────
if [ ! -f "$ENV_FILE" ]; then
    echo "[$(date)] ERROR: $ENV_FILE not found." >&2
    exit 1
fi

set -a
source "$ENV_FILE"
set +a

# ── Create log directory ──────────────────────────────────────────────────────
mkdir -p "$(dirname "$LOG_FILE")"

# ── Check if already running ──────────────────────────────────────────────────
if pgrep -f "discord_bot.py" > /dev/null 2>&1; then
    echo "[$(date)] Discord bot is already running. Nothing to do." >> "$LOG_FILE"
    exit 0
fi

# ── Start the bot ─────────────────────────────────────────────────────────────
echo "[$(date)] Starting Discord bot..." >> "$LOG_FILE"
nohup "$PYTHON" "$BOT_SCRIPT" >> "$LOG_FILE" 2>&1 &

BOT_PID=$!
echo "[$(date)] Discord bot started with PID $BOT_PID." >> "$LOG_FILE"

sleep 3

if kill -0 "$BOT_PID" 2>/dev/null; then
    echo "[$(date)] Discord bot confirmed running (PID $BOT_PID)." >> "$LOG_FILE"
else
    echo "[$(date)] ERROR: Discord bot died immediately. Check log above for errors." >> "$LOG_FILE"
    exit 1
fi
