#!/usr/bin/env bash
# ==============================================================================
# Headwind MDM - 2FA TOTP Authentication Plugin Installer
# https://github.com/hmdm-auth-totp
# ==============================================================================
# Zero-configuration, non-invasive installer for Headwind MDM servers.
#
# Usage:
#   sudo ./install.sh
# ==============================================================================

set -e

COLOR_RESET="\033[0m"
COLOR_GREEN="\033[1;32m"
COLOR_CYAN="\033[1;36m"
COLOR_YELLOW="\033[1;33m"
COLOR_RED="\033[1;31m"
COLOR_BOLD="\033[1m"

log_info() { echo -e "${COLOR_CYAN}[INFO]${COLOR_RESET} $1"; }
log_ok()   { echo -e "${COLOR_GREEN}[OK]${COLOR_RESET} $1"; }
log_warn() { echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $1"; }
log_err()  { echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $1"; }

echo -e "${COLOR_BOLD}"
echo "======================================================================"
echo "    Headwind MDM - 2FA TOTP Authentication Plugin Installer"
echo "    Non-invasive, Drop-in Two-Factor Authentication (RFC 6238)"
echo "======================================================================"
echo -e "${COLOR_RESET}"

# 1. Root check
if [ "$EUID" -ne 0 ]; then
    log_err "This installer must be run as root. Please run: sudo ./install.sh"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 2. Detect Tomcat Directory
log_info "Detecting Headwind MDM environment..."
TOMCAT_DIR=""
TOMCAT_USER="tomcat"
TOMCAT_SERVICE=""

for candidate in "/var/lib/tomcat10" "/var/lib/tomcat9" "/opt/tomcat"; do
    if [ -d "$candidate/webapps/ROOT" ]; then
        TOMCAT_DIR="$candidate"
        if [ "$candidate" = "/var/lib/tomcat10" ]; then
            TOMCAT_SERVICE="tomcat10"
        elif [ "$candidate" = "/var/lib/tomcat9" ]; then
            TOMCAT_SERVICE="tomcat9"
            TOMCAT_USER="tomcat9"
        fi
        break
    fi
done

if [ -z "$TOMCAT_DIR" ]; then
    log_err "Could not locate Headwind MDM at /var/lib/tomcat10 or /var/lib/tomcat9."
    exit 1
fi
log_ok "Found Headwind MDM at: ${TOMCAT_DIR} (service: ${TOMCAT_SERVICE:-tomcat})"

# 3. Create / Secure Configuration Storage
mkdir -p "${TOMCAT_DIR}/conf" "/etc/${TOMCAT_SERVICE}/Catalina" 2>/dev/null || true
CONF_FILE="/etc/${TOMCAT_SERVICE}/Catalina/headwind-totp.json"
FALLBACK_CONF="${TOMCAT_DIR}/conf/headwind-totp.json"

if [ ! -f "$CONF_FILE" ] && [ ! -f "$FALLBACK_CONF" ]; then
    log_info "Creating initial 2FA storage file..."
    echo '{"users":{}}' > "$CONF_FILE"
    cp -f "$CONF_FILE" "$FALLBACK_CONF" 2>/dev/null || true
fi

chown -R "${TOMCAT_USER}:${TOMCAT_USER}" "$CONF_FILE" "$FALLBACK_CONF" 2>/dev/null || true
chmod 664 "$CONF_FILE" "$FALLBACK_CONF" 2>/dev/null || true
log_ok "2FA storage file initialized and secured."

# 4. Deploy auth-totp.war
WAR_SRC="${SCRIPT_DIR}/auth-totp.war"
if [ ! -f "$WAR_SRC" ]; then
    WAR_SRC=$(find "${SCRIPT_DIR}" -name "auth-totp.war" 2>/dev/null | head -n 1 || true)
fi

if [ -f "$WAR_SRC" ]; then
    log_info "Deploying auth-totp.war into ${TOMCAT_DIR}/webapps/..."
    cp -f "$WAR_SRC" "${TOMCAT_DIR}/webapps/auth-totp.war"
    chown "${TOMCAT_USER}:${TOMCAT_USER}" "${TOMCAT_DIR}/webapps/auth-totp.war"
    log_ok "Deployed auth-totp.war successfully."
else
    log_err "auth-totp.war not found in ${SCRIPT_DIR}. Please build the WAR first."
    exit 1
fi

# 5. Install Watchdog & Inject Hook into ROOT/index.html
SYNC_SCRIPT="/usr/local/bin/headwind-totp-sync"
log_info "Installing hook auto-sync watchdog to: ${SYNC_SCRIPT}..."

cat <<'EOF' > "$SYNC_SCRIPT"
#!/usr/bin/env bash
set -e

TOMCAT_DIR=""
for candidate in "/var/lib/tomcat10" "/var/lib/tomcat9" "/opt/tomcat"; do
    if [ -d "$candidate/webapps/ROOT" ]; then
        TOMCAT_DIR="$candidate"
        break
    fi
done

INDEX_HTML="${TOMCAT_DIR}/webapps/ROOT/index.html"
NGSW_JSON="${TOMCAT_DIR}/webapps/ROOT/ngsw.json"
HOOK_TAG='<script src="/auth-totp/totp-hook.js" defer></script>'

if [ -n "$TOMCAT_DIR" ] && [ -f "$INDEX_HTML" ]; then
    if ! grep -q "totp-hook.js" "$INDEX_HTML"; then
        echo "[headwind-totp-sync] Injecting 2FA hook into ${INDEX_HTML}..."
        sed -i "s|</body>|${HOOK_TAG}</body>|" "$INDEX_HTML"
        chown tomcat:tomcat "$INDEX_HTML" 2>/dev/null || true

        # Update Angular Service Worker hash if present
        if [ -f "$NGSW_JSON" ] && command -v sha1sum >/dev/null 2>&1; then
            NEW_SHA=$(sha1sum "$INDEX_HTML" | awk '{print $1}')
            sed -i -E "s|(\"/index.html\"[[:space:]]*:[[:space:]]*)\"[a-f0-9]{40}\"|\1\"${NEW_SHA}\"|g" "$NGSW_JSON"
            chown tomcat:tomcat "$NGSW_JSON" 2>/dev/null || true
            echo "[headwind-totp-sync] Synced ngsw.json SHA-1 hash to: ${NEW_SHA}"
        fi
    fi
fi
EOF

chmod +x "$SYNC_SCRIPT"
"$SYNC_SCRIPT"
log_ok "Injected 2FA TOTP hook into Headwind MDM interface."

# 6. Install Systemd Path for Update Persistence
SYSTEMD_SERVICE="/etc/systemd/system/headwind-totp-sync.service"
SYSTEMD_PATH="/etc/systemd/system/headwind-totp-sync.path"

cat <<EOF > "$SYSTEMD_SERVICE"
[Unit]
Description=Headwind MDM 2FA Hook Auto-Restorer Watchdog
After=${TOMCAT_SERVICE}.service

[Service]
Type=oneshot
ExecStart=${SYNC_SCRIPT}
EOF

cat <<EOF > "$SYSTEMD_PATH"
[Unit]
Description=Watch Headwind MDM index.html for Changes
After=${TOMCAT_SERVICE}.service

[Path]
PathModified=${TOMCAT_DIR}/webapps/ROOT/index.html
Unit=headwind-totp-sync.service

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now headwind-totp-sync.path >/dev/null 2>&1 || true
log_ok "Update watchdog enabled: any Headwind MDM upgrade will automatically preserve 2FA."

# 7. Success Banner
echo ""
echo -e "${COLOR_GREEN}${COLOR_BOLD}======================================================================${COLOR_RESET}"
echo -e "${COLOR_GREEN}${COLOR_BOLD}     Headwind MDM 2FA TOTP Plugin Installed Successfully!             ${COLOR_RESET}"
echo -e "${COLOR_GREEN}${COLOR_BOLD}======================================================================${COLOR_RESET}"
echo ""
echo -e "  ${COLOR_BOLD}Plugin Status:${COLOR_RESET}   Active and running under Tomcat."
echo -e "  ${COLOR_BOLD}How it works:${COLOR_RESET}    When any user logs into Headwind MDM:"
echo -e "                   - On first login, a QR Code is displayed to link"
echo -e "                     Google Authenticator / Microsoft Authenticator."
echo -e "                   - On subsequent logins, a 6-digit TOTP code is required."
echo ""
echo -e "  ${COLOR_BOLD}Emergency Reset:${COLOR_RESET}"
echo -e "  If an administrator loses their phone, run on the server:"
echo -e "  ${COLOR_CYAN}sudo ./reset_totp.sh <username>${COLOR_RESET}"
echo ""
