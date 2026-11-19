#!/bin/sh
# Runs INSIDE the demo container. Two modes:
#   seed   an agent works through six requests against a real daemon, with a real
#          LLM planning each one; the operator approves only the Low-risk steps.
#   shell  start the daemon on the state a seed left behind and hand over a prompt.
set -eu

export SYSKNIFE_LISTEN_URI=unix:///run/sysknife/daemon.sock
export SYSKNIFE_SOCKET=/run/sysknife/daemon.sock
export SYSKNIFE_DATABASE_PATH=/var/lib/sysknife/daemon.sqlite
export SYSKNIFE_AUDIT_KEY_PATH=/var/lib/sysknife/audit-key

start_daemon() {
    mkdir -p /run/sysknife
    sysknife-daemon >/var/log/sysknife-daemon.log 2>&1 &
    n=0
    while [ ! -S "$SYSKNIFE_SOCKET" ]; do
        n=$((n + 1))
        [ "$n" -le 50 ] || { cat /var/log/sysknife-daemon.log >&2; echo "daemon did not start" >&2; exit 1; }
        sleep 0.2
    done
    # Demo only: the packaged unit manages socket groups; here the agent user just needs to connect.
    chmod 666 "$SYSKNIFE_SOCKET"
}

case "${1:-}" in
seed)
    groupadd sysknife-admin
    useradd -m -s /bin/sh -G sysknife-admin ops
    start_daemon
    cat >/tmp/agent.sh <<'AGENT'
exec python3 /audit-tamper-agent.py low \
    "how much disk space is left?" \
    "which processes use the most memory?" \
    "install curl" \
    "open port 22 in the firewall" \
    "turn off ssh password login" \
    "show me the listening network ports"
AGENT
    su -p -s /bin/sh ops -c 'HOME=/home/ops sh /tmp/agent.sh'
    echo "--- history"
    sysknife history
    echo "--- verify"
    sysknife audit verify | cut -c1-120
    done_rows="$(sqlite3 "$SYSKNIFE_DATABASE_PATH" "select count(*) from transactions where status = '\"succeeded\"'")"
    open_rows="$(sqlite3 "$SYSKNIFE_DATABASE_PATH" "select count(*) from transactions where status = '\"queued\"'")"
    echo "seeded: $done_rows executed, $open_rows previewed and never approved"
    if [ "$done_rows" -lt 2 ] || [ "$open_rows" -lt 2 ]; then
        echo "seed did not leave the expected mix" >&2
        exit 1
    fi
    ;;
shell)
    start_daemon
    cd /var/lib/sysknife
    exec env PS1='\[\e[1;32m\]root@web01\[\e[0m\]# ' bash --norc -i
    ;;
*)
    echo "usage: $0 seed|shell" >&2
    exit 2
    ;;
esac
