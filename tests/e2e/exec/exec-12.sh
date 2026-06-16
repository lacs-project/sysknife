#!/usr/bin/env bash
# Exec story 12 (destructive): UfwAllow + UfwDeny cycle — open then block port 8080
# Intent: allow port 8080 via ufw, assert present, deny port 8080, assert absent.
# Pass criteria:
#   - ufw status shows 8080 ALLOW after UfwAllow
#   - ufw status does NOT show 8080 ALLOW after UfwDeny
# Risk: Medium — uses printf 'y\n' | sysknife.
# Ubuntu equivalent of exec-11 (which tests ConfigureFirewall + firewall-cmd on Fedora).
set -euo pipefail

DISTRO_FAMILY="${SYSKNIFE_DISTRO_FAMILY:-$(. /etc/os-release && echo "${ID_LIKE:-$ID}" | tr ' ' '\n' | head -1)}"
case "$DISTRO_FAMILY" in
  ubuntu|debian) ;;
  *)
    echo "SKIP: $0 requires an Ubuntu/Debian host (got: $DISTRO_FAMILY)"
    exit 0
    ;;
esac

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIP: set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run firewall mutation stories"
  exit 0
fi

PORT="8080"

# Helper: check if PORT is listed in ufw status as ALLOW.
port_allowed() {
  ufw status 2>/dev/null | grep -qE "^${PORT}.*ALLOW"
}

# Cleanup trap: deny the port if the story fails mid-way.
cleanup() {
  if port_allowed 2>/dev/null; then
    ufw deny "$PORT" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "=== Exec 12: UfwAllow + UfwDeny cycle (allow→assert→deny→assert) ==="

# Pre-condition: ensure port is NOT already open (idempotency guard).
if port_allowed; then
  echo "Pre-condition: $PORT already open — denying first"
  ufw deny "$PORT" >/dev/null 2>&1 || true
fi

# --- Phase 1: Allow port 8080 ---
INTENT_ADD="allow port $PORT through the firewall for my web app"
echo "Intent (allow): $INTENT_ADD"

OUTPUT_ADD=$(printf 'y\n' | sysknife "$INTENT_ADD" 2>/tmp/sysknife-exec-12-add-stderr.log)
echo "--- Allow output ---"
echo "$OUTPUT_ADD"

if ! port_allowed; then
  echo "FAIL: port $PORT not found in ufw status after UfwAllow"
  echo "Current ufw status: $(ufw status 2>/dev/null || echo 'error')"
  cat /tmp/sysknife-exec-12-add-stderr.log || true
  exit 1
fi
echo "allow: port $PORT open in ufw [OK]"

# --- Phase 2: Deny port 8080 ---
INTENT_REMOVE="block port $PORT in the firewall"
echo "Intent (deny): $INTENT_REMOVE"

OUTPUT_REMOVE=$(printf 'y\n' | sysknife "$INTENT_REMOVE" 2>/tmp/sysknife-exec-12-remove-stderr.log)
echo "--- Deny output ---"
echo "$OUTPUT_REMOVE"

if port_allowed; then
  echo "FAIL: port $PORT still open in ufw after UfwDeny"
  echo "Current ufw status: $(ufw status 2>/dev/null || echo 'error')"
  cat /tmp/sysknife-exec-12-remove-stderr.log || true
  exit 1
fi
echo "deny: port $PORT blocked in ufw [OK]"

trap - EXIT
echo "PASS: Exec 12 — UfwAllow + UfwDeny cycle for port $PORT succeeded"
