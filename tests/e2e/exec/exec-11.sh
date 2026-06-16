#!/usr/bin/env bash
# Exec story 11 (destructive): ConfigureFirewall cycle — add then remove ftp service
# Intent: add ftp to public zone, assert present, remove, assert absent.
# Pass criteria:
#   - firewall-cmd --list-services shows ftp after add
#   - firewall-cmd --list-services does NOT show ftp after remove
# Risk: Medium — uses printf 'y\n' | sysknife.
# `ftp` is a built-in firewalld service name (no custom definition needed).
# firewall-cmd --permanent + --reload writes persistent config and applies immediately.
set -euo pipefail

DISTRO_FAMILY="${SYSKNIFE_DISTRO_FAMILY:-$(. /etc/os-release && echo "${ID_LIKE:-$ID}" | tr ' ' '\n' | head -1)}"
case "$DISTRO_FAMILY" in
  fedora|rhel|centos) ;;
  *)
    echo "SKIP: $0 requires a Fedora-family host (got: $DISTRO_FAMILY)"
    exit 0
    ;;
esac

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIP: set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run firewall mutation stories"
  exit 0
fi

ZONE="public"
SERVICE="ftp"

# Helper: check if SERVICE is listed in ZONE's active services.
service_in_zone() {
  firewall-cmd --zone="$ZONE" --list-services 2>/dev/null | tr ' ' '\n' | grep -qx "$SERVICE"
}

# Cleanup trap: remove service from zone if story fails mid-way.
cleanup() {
  if service_in_zone 2>/dev/null; then
    firewall-cmd --permanent --zone="$ZONE" --remove-service="$SERVICE" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "=== Exec 11: ConfigureFirewall cycle (add→assert→remove→assert) ==="

# Pre-condition: ensure ftp is NOT already open (idempotency guard).
if service_in_zone; then
  echo "Pre-condition: $SERVICE already in $ZONE — removing first"
  firewall-cmd --permanent --zone="$ZONE" --remove-service="$SERVICE" >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
fi

# --- Phase 1: Open ftp ---
INTENT_ADD="allow ftp service through the $ZONE firewall zone"
echo "Intent (add): $INTENT_ADD"

OUTPUT_ADD=$(printf 'y\n' | sysknife "$INTENT_ADD" 2>/tmp/sysknife-exec-11-add-stderr.log)
echo "--- Add output ---"
echo "$OUTPUT_ADD"

if ! service_in_zone; then
  echo "FAIL: ftp not found in $ZONE zone services after ConfigureFirewall enable"
  echo "Current services: $(firewall-cmd --zone=$ZONE --list-services 2>/dev/null || echo 'error')"
  cat /tmp/sysknife-exec-11-add-stderr.log || true
  exit 1
fi
echo "add: $SERVICE present in $ZONE zone [OK]"

# --- Phase 2: Close ftp ---
INTENT_REMOVE="block ftp service in the $ZONE firewall zone"
echo "Intent (remove): $INTENT_REMOVE"

OUTPUT_REMOVE=$(printf 'y\n' | sysknife "$INTENT_REMOVE" 2>/tmp/sysknife-exec-11-remove-stderr.log)
echo "--- Remove output ---"
echo "$OUTPUT_REMOVE"

if service_in_zone; then
  echo "FAIL: $SERVICE still in $ZONE zone after ConfigureFirewall disable"
  echo "Current services: $(firewall-cmd --zone=$ZONE --list-services 2>/dev/null || echo 'error')"
  cat /tmp/sysknife-exec-11-remove-stderr.log || true
  exit 1
fi
echo "remove: $SERVICE absent from $ZONE zone [OK]"

trap - EXIT
echo "PASS: Exec 11 — ConfigureFirewall add→assert→remove→assert cycle succeeded"
