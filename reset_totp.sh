#!/usr/bin/env bash
# ==============================================================================
# Headwind MDM - 2FA TOTP Reset Tool (Emergency Recovery)
# ==============================================================================
# Use this tool if an administrator or user loses access to their authenticator
# app or recovery backup codes.
#
# Usage:
#   sudo ./reset_totp.sh                  # List all users with 2FA enabled
#   sudo ./reset_totp.sh <username>       # Reset 2FA for a specific user
#   sudo ./reset_totp.sh --all            # Reset 2FA for all users
# ==============================================================================

set -e

COLOR_RESET="\033[0m"
COLOR_GREEN="\033[1;32m"
COLOR_CYAN="\033[1;36m"
COLOR_YELLOW="\033[1;33m"
COLOR_RED="\033[1;31m"
COLOR_BOLD="\033[1m"

if [ "$EUID" -ne 0 ]; then
    echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} This script must be run as root: sudo ./reset_totp.sh"
    exit 1
fi

# Locate headwind-totp.json configuration file
CONF_FILE=""
for c in "/etc/tomcat10/Catalina/headwind-totp.json" \
         "/var/lib/tomcat10/conf/headwind-totp.json" \
         "/var/lib/tomcat9/conf/headwind-totp.json" \
         "/etc/headwind-totp/config.json"; do
    if [ -f "$c" ]; then
        CONF_FILE="$c"
        break
    fi
done

if [ -z "$CONF_FILE" ]; then
    echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} No TOTP configuration file found. 2FA is currently not configured for any user."
    exit 0
fi

TARGET="$1"

# Case 1: No arguments -> List all configured users
if [ -z "$TARGET" ]; then
    echo -e "${COLOR_BOLD}=== Headwind MDM 2FA TOTP - Configured Users ===${COLOR_RESET}"
    if command -v jq >/dev/null 2>&1; then
        USERS=$(jq -r '.users | keys[]' "$CONF_FILE" 2>/dev/null || true)
    else
        USERS=$(grep -o '"[a-zA-Z0-9_.@-]*"[[:space:]]*:[[:space:]]*{' "$CONF_FILE" | sed -E 's/"([^"]*)".*/\1/' | grep -v "users" || true)
    fi

    if [ -z "$USERS" ]; then
        echo "No users currently have 2FA enabled."
    else
        echo "The following users have 2FA TOTP active:"
        for u in $USERS; do
            echo -e "  - ${COLOR_CYAN}${u}${COLOR_RESET}"
        done
        echo ""
        echo "To reset a user's 2FA, run: sudo ./reset_totp.sh <username>"
    fi
    exit 0
fi

# Case 2: Reset ALL users
if [ "$TARGET" = "--all" ]; then
    read -r -p "Are you sure you want to reset 2FA for ALL users? (y/N): " CONFIRM
    if [ "$CONFIRM" = "y" ] || [ "$CONFIRM" = "Y" ]; then
        echo '{"users":{}}' > "$CONF_FILE"
        echo -e "${COLOR_GREEN}[OK]${COLOR_RESET} 2FA has been reset for all users. They will be prompted to re-register on next login."
    else
        echo "Aborted."
    fi
    exit 0
fi

# Case 3: Reset specific user
CLEAN_TARGET=$(echo "$TARGET" | tr '[:upper:]' '[:lower:]' | tr -d ' ')

if command -v jq >/dev/null 2>&1; then
    USER_EXISTS=$(jq -r --arg u "$CLEAN_TARGET" '.users[$u] // empty' "$CONF_FILE")
    if [ -z "$USER_EXISTS" ]; then
        echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} User '${CLEAN_TARGET}' does not have 2FA configured in ${CONF_FILE}."
        exit 0
    fi
    TMP_JSON=$(mktemp)
    jq --arg u "$CLEAN_TARGET" 'del(.users[$u])' "$CONF_FILE" > "$TMP_JSON"
    mv "$TMP_JSON" "$CONF_FILE"
    chown tomcat:tomcat "$CONF_FILE" 2>/dev/null || true
    chmod 664 "$CONF_FILE" 2>/dev/null || true
else
    # Fallback with python or sed
    python3 -c "
import json
with open('$CONF_FILE', 'r') as f: data = json.load(f)
if '$CLEAN_TARGET' in data.get('users', {}):
    del data['users']['$CLEAN_TARGET']
    with open('$CONF_FILE', 'w') as f: json.dump(data, f, indent=2)
    print('Reset completed.')
else:
    print('User not found.')
"
fi

echo -e "${COLOR_GREEN}[OK]${COLOR_RESET} 2FA successfully reset for user: ${COLOR_CYAN}${CLEAN_TARGET}${COLOR_RESET}."
echo -e "On their next login, they will be prompted with a new QR Code to register their authenticator app."
