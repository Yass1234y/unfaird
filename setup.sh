#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
#  macOSAppstoreDecrypter — all-in-one installer for macOS (Apple Silicon, macOS 11+)
#
#  Sets up the IPA download + decrypt web service and lets you choose how to
#  expose it:
#     1) local      — reachable on your Mac + your LAN only
#     2) cloudflare — also published on the internet through a Cloudflare Tunnel
#
#  Usage:   chmod +x setup.sh && ./setup.sh
#  It is safe to re-run (idempotent).
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
PLIST_LABEL="com.macOSAppstoreDecrypter.server"
PLIST="/Library/LaunchDaemons/${PLIST_LABEL}.plist"
PORT="6347"

c_g(){ printf '\033[1;32m%s\033[0m\n' "$*"; }   # green
c_y(){ printf '\033[1;33m%s\033[0m\n' "$*"; }   # yellow
c_r(){ printf '\033[1;31m%s\033[0m\n' "$*"; }   # red
c_b(){ printf '\033[1;36m%s\033[0m\n' "$*"; }   # cyan
hr(){  printf '%s\n' "────────────────────────────────────────────────────────"; }

hr; c_b "  macOSAppstoreDecrypter installer"; hr

# ── 0. sanity checks ────────────────────────────────────────────────────────
[ "$(uname -s)" = "Darwin" ] || { c_r "This installer is for macOS only."; exit 1; }
ARCH="$(uname -m)"
[ "$ARCH" = "arm64" ] || c_y "⚠  Bundled binaries are arm64 (Apple Silicon). You are on '$ARCH' — they may not run."
command -v python3 >/dev/null || { c_r "python3 not found. Install the Xcode Command Line Tools:  xcode-select --install"; exit 1; }

# ── 1. unquarantine + make executables runnable ─────────────────────────────
# Files downloaded from GitHub carry com.apple.quarantine, which makes Gatekeeper
# refuse to run these unsigned binaries. Strip it and set the exec bit.
c_g "→ Preparing bundled tools (bin/ipatool, bin/unfair-core)…"
xattr -dr com.apple.quarantine "$REPO" 2>/dev/null
chmod +x "$REPO/bin/ipatool" "$REPO/bin/unfair-core" "$REPO/free-ram.sh" "$REPO/app.py" "$REPO/lidawake" 2>/dev/null

# ── 2. python deps ──────────────────────────────────────────────────────────
c_g "→ Installing Python dependencies (Flask)…"
python3 -m pip install --user --quiet --disable-pip-version-check -r "$REPO/requirements.txt" \
  || python3 -m pip install --user --break-system-packages --quiet -r "$REPO/requirements.txt" \
  || { c_r "pip install failed. Try:  python3 -m pip install --user Flask"; exit 1; }

# ── 3. .env ─────────────────────────────────────────────────────────────────
if [ ! -f "$REPO/.env" ]; then
  cp "$REPO/.env.example" "$REPO/.env"
  chmod 600 "$REPO/.env"
  c_y "→ Created .env from the template. Fill in your macOS password + Apple ID now."
  read -rp "   Open it in an editor now? [Y/n] " ed
  if [[ ! "$ed" =~ ^[Nn]$ ]]; then "${EDITOR:-nano}" "$REPO/.env"; fi
else
  c_g "→ .env already exists — leaving it untouched."
fi
chmod 600 "$REPO/.env" 2>/dev/null

# Load .env so we can log ipatool in for the configured account.
set -a; # shellcheck disable=SC1091
source "$REPO/.env" 2>/dev/null; set +a

# ── 4. ipatool login (interactive, so 2-factor codes can be typed) ──────────
if [ -n "${APPLE_ID_EMAIL:-}" ] && [ -n "${APPLE_ID_PASSWORD:-}" ]; then
  c_g "→ Logging ipatool into ${APPLE_ID_EMAIL} (enter the 2FA code if asked)…"
  KP="${MAC_PASSWORD:-macOSAppstoreDecrypter}"
  if "$REPO/bin/ipatool" --non-interactive --keychain-passphrase "$KP" auth info >/dev/null 2>&1; then
    c_g "   Already logged in."
  else
    "$REPO/bin/ipatool" --keychain-passphrase "$KP" auth login \
       -e "$APPLE_ID_EMAIL" -p "$APPLE_ID_PASSWORD" || \
       c_y "   ⚠  Login didn't complete. You can retry later:  bin/ipatool auth login -e <email> -p <pass>"
  fi
else
  c_y "→ No APPLE_ID_EMAIL in .env (multi-region setup?). Log each account in manually:"
  c_y "     HOME=<region-home> $REPO/bin/ipatool --keychain-passphrase <mac-pass> auth login -e <email> -p <pass>"
fi

# ── 5. install the auto-start service ───────────────────────────────────────
WHOAMI="$(whoami)"
c_g "→ Installing the auto-start service ($PLIST_LABEL) as user '$WHOAMI'…"
TMP_PLIST="$(mktemp)"
cat > "$TMP_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>${PLIST_LABEL}</string>
    <key>UserName</key><string>${WHOAMI}</string>
    <key>WorkingDirectory</key><string>${REPO}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>${REPO}/app.py</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>HOME</key><string>${HOME}</string>
        <key>PATH</key><string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>ThrottleInterval</key><integer>5</integer>
    <key>StandardOutPath</key><string>${REPO}/server.log</string>
    <key>StandardErrorPath</key><string>${REPO}/server.log</string>
</dict>
</plist>
PLIST
sudo cp "$TMP_PLIST" "$PLIST"; rm -f "$TMP_PLIST"
sudo chown root:wheel "$PLIST"; sudo chmod 644 "$PLIST"
sudo launchctl bootout system/"$PLIST_LABEL" 2>/dev/null
sudo launchctl bootstrap system "$PLIST" 2>/dev/null || sudo launchctl load -w "$PLIST"
sudo launchctl kickstart -k system/"$PLIST_LABEL" 2>/dev/null

sleep 2
if curl -s --max-time 5 "http://127.0.0.1:${PORT}/health" | grep -q '"status":"ok"'; then
  c_g "   Server is up on port ${PORT}."
else
  c_y "   Server not answering yet — check the log:  tail -f $REPO/server.log"
fi

# ── 5b. power resilience ────────────────────────────────────────────────────
# Best-effort. On DESKTOP Macs (mini / Studio / iMac) autorestart makes the
# machine power itself back on when AC returns after an outage — then the
# LaunchDaemon above brings the server up automatically. On LAPTOPS the battery
# keeps the Mac running through an outage instead, so macOS marks autorestart
# "not supported"; that's fine — combine it with `lidawake` (below) to keep the
# service alive with the lid shut. Either way these are harmless.
c_g "→ Configuring power resilience (auto power-on after outage + wake-on-LAN)…"
sudo pmset -a autorestart 1 2>/dev/null || true   # power back on when AC returns (desktop Macs)
sudo pmset -c womp 1 2>/dev/null || true          # wake for network access while on AC
if pmset -g | grep -qiE "autorestart[[:space:]]+1"; then
  c_g "   autorestart ON — this Mac will power on by itself when AC returns."
else
  c_y "   autorestart not supported on this Mac (normal for laptops — the battery is the UPS)."
fi

# ── 6. choose exposure method ───────────────────────────────────────────────
hr; c_b "  How do you want to reach the service?"
echo "    1) local       — this Mac + your local network only"
echo "    2) cloudflare  — also publish it on the internet (Cloudflare Tunnel)"
read -rp "  Choose [1/2] (default 1): " METHOD
METHOD="${METHOD:-1}"

LAN_IP="$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo '127.0.0.1')"

if [ "$METHOD" = "2" ]; then
  hr; c_b "  Cloudflare Tunnel setup"
  command -v cloudflared >/dev/null || {
    c_g "→ Installing cloudflared via Homebrew…"
    command -v brew >/dev/null || { c_r "Homebrew not found. Install it from https://brew.sh then re-run."; exit 1; }
    brew install cloudflared || { c_r "cloudflared install failed."; exit 1; }
  }
  c_y "→ A browser will open — log in and pick the domain you want to use."
  cloudflared tunnel login
  read -rp "  Public hostname to serve on (e.g. decrypt.example.com): " HOSTNAME
  TUNNEL_NAME="macOSAppstoreDecrypter"
  cloudflared tunnel create "$TUNNEL_NAME" 2>/dev/null || c_y "  (tunnel '$TUNNEL_NAME' may already exist — continuing)"
  TUNNEL_ID="$(cloudflared tunnel list 2>/dev/null | awk -v n="$TUNNEL_NAME" '$2==n{print $1}' | head -1)"
  [ -n "$TUNNEL_ID" ] || { c_r "Could not determine tunnel id."; exit 1; }

  CF_DIR="$HOME/.cloudflared"
  cat > "$CF_DIR/config.yml" <<CFG
tunnel: ${TUNNEL_ID}
credentials-file: ${CF_DIR}/${TUNNEL_ID}.json
ingress:
  - hostname: ${HOSTNAME}
    service: http://127.0.0.1:${PORT}
    originRequest:
      connectTimeout: 30s
      keepAliveTimeout: 120s
  - service: http_status:404
CFG
  cloudflared tunnel route dns "$TUNNEL_ID" "$HOSTNAME" || c_y "  (DNS route may already exist)"
  c_g "→ Installing cloudflared as a background service…"
  sudo cloudflared service install 2>/dev/null || true
  sudo launchctl kickstart -k system/com.cloudflare.cloudflared 2>/dev/null || cloudflared tunnel run "$TUNNEL_NAME" &

  hr; c_g "  ✅ Done!"
  echo "     Public : https://${HOSTNAME}"
  echo "     LAN    : http://${LAN_IP}:${PORT}"
  echo "     Admin  : https://${HOSTNAME}/admin   (password in $REPO/server.log on first run)"
else
  hr; c_g "  ✅ Done!"
  echo "     LAN    : http://${LAN_IP}:${PORT}"
  echo "     Local  : http://127.0.0.1:${PORT}"
  echo "     Admin  : http://${LAN_IP}:${PORT}/admin   (password in $REPO/server.log on first run)"
fi

# ── 7. keep-awake with the lid closed (optional) ────────────────────────────
hr; c_b "  Keep the Mac running with the lid CLOSED?"
echo "  Installs 'lidawake' so you can shut the laptop and the service keeps running."
echo "  (Re-applied automatically on every reboot. Keep the Mac on AC power.)"
read -rp "  Enable now? [y/N] " LID
if [[ "$LID" =~ ^[Yy]$ ]]; then
  sudo cp "$REPO/lidawake" /usr/local/bin/lidawake && sudo chmod +x /usr/local/bin/lidawake
  sudo /usr/local/bin/lidawake on
  c_g "   lidawake enabled (also installed to /usr/local/bin/lidawake)."
else
  c_y "   Skipped. Enable later with:  sudo $REPO/lidawake on"
fi

# ── summary ─────────────────────────────────────────────────────────────────
hr; c_g "  These start automatically on every reboot — no need to re-run setup:"
echo "    • ${PLIST_LABEL}        (the web server)"
[ "$METHOD" = "2" ] && echo "    • com.cloudflare.cloudflared (the public tunnel)"
[[ "${LID:-}" =~ ^[Yy]$ ]] && echo "    • com.macOSAppstoreDecrypter.lidawake       (stay awake with lid closed)"
hr
echo "  Logs           : tail -f $REPO/server.log"
echo "  Restart server : sudo launchctl kickstart -k system/${PLIST_LABEL}"
echo "  Stop / remove  : sudo launchctl bootout system/${PLIST} && sudo rm ${PLIST}"
echo "  Lid awake      : sudo lidawake on | off | status"
echo "  Admin password : grep 'default admin' $REPO/server.log   (or see \${DATA_DIR}/ADMIN_PASSWORD.txt)"
hr
