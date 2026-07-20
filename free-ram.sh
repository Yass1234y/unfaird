#!/bin/bash
# free-ram.sh — GENTLY free RAM before a heavy decrypt. It only runs `purge`
# (reclaims the inactive file cache); it does NOT kill any app or process, so
# whatever you have open stays open. Called automatically by app.py; safe to run
# by hand too. Needs the macOS login password to `sudo purge` — it reads it from
# MAC_PASSWORD (taken from the .env next to this script, or the environment).
DIR="$(cd "$(dirname "$0")" && pwd)"
[ -f "$DIR/.env" ] && { set -a; . "$DIR/.env"; set +a; }
SUDO_PASS="${MAC_PASSWORD:-}"

before=$(vm_stat | awk '/Pages free/{printf "%.0f",$3*16384/1048576}')
echo "$SUDO_PASS" | sudo -S purge 2>/dev/null
sleep 1
after=$(vm_stat | awk '/Pages free/{printf "%.0f",$3*16384/1048576}')
echo "free RAM: ${before}MB -> ${after}MB (purge only, no processes killed)"
