#!/usr/bin/env bash
# ==============================================================================
# Headwind MDM - 2FA TOTP Authentication Plugin Updater
# ==============================================================================
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo ./update.sh"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "=== Updating Headwind MDM 2FA TOTP Plugin ==="

TOMCAT_DIR=""
for candidate in "/var/lib/tomcat10" "/var/lib/tomcat9" "/opt/tomcat"; do
    if [ -d "$candidate/webapps/ROOT" ]; then
        TOMCAT_DIR="$candidate"
        break
    fi
done

if [ -n "$TOMCAT_DIR" ] && [ -f "${SCRIPT_DIR}/auth-totp.war" ]; then
    echo "Updating ${TOMCAT_DIR}/webapps/auth-totp.war..."
    cp -f "${SCRIPT_DIR}/auth-totp.war" "${TOMCAT_DIR}/webapps/auth-totp.war"
    chown tomcat:tomcat "${TOMCAT_DIR}/webapps/auth-totp.war" 2>/dev/null || true
    echo "[OK] Updated auth-totp.war."
fi

# Re-run hook sync
if [ -f "/usr/local/bin/headwind-totp-sync" ]; then
    /usr/local/bin/headwind-totp-sync
    echo "[OK] Refreshed 2FA hook in Headwind MDM."
fi

echo "=== Update complete ==="
