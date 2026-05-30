#!/bin/sh
# remote-docker-agent.sh — Push local Docker container inventory to Castellum.
#
# USAGE
#   CASTELLUM_URL=https://your-host CASTELLUM_TOKEN=<token> sh remote-docker-agent.sh
#   sh remote-docker-agent.sh --url https://your-host --token <token>
#
# SECURITY
#   The token is read from env or --token flag only. It is NEVER echoed, logged,
#   or included in any script output.
#
# CRON EXAMPLE (every 5 minutes):
#   */5 * * * * CASTELLUM_URL=https://your-host CASTELLUM_TOKEN=<token> /path/to/remote-docker-agent.sh
#
# SYSTEMD TIMER EXAMPLE:
#   # /etc/systemd/system/castellum-docker-agent.service
#   [Unit]
#   Description=Castellum remote Docker agent
#   [Service]
#   Type=oneshot
#   EnvironmentFile=/etc/castellum-docker-agent.env
#   ExecStart=/opt/castellum/remote-docker-agent.sh
#
#   # /etc/systemd/system/castellum-docker-agent.timer
#   [Unit]
#   Description=Run Castellum Docker agent every 5 minutes
#   [Timer]
#   OnBootSec=2min
#   OnUnitActiveSec=5min
#   [Install]
#   WantedBy=timers.target
#
#   # /etc/castellum-docker-agent.env
#   CASTELLUM_URL=https://your-host
#   CASTELLUM_TOKEN=<token>    # keep this file mode 0600

set -eu

# ── Defaults ──────────────────────────────────────────────────────────────────
CASTELLUM_URL="${CASTELLUM_URL:-}"
CASTELLUM_TOKEN="${CASTELLUM_TOKEN:-}"
AGENT_ID=""
AGENT_HOSTNAME=""
PRIMARY_IP=""

usage() {
    cat >&2 <<EOF
Usage: $(basename "$0") [OPTIONS]

  --url URL        Castellum base URL (or set CASTELLUM_URL)
  --token TOKEN    Bearer token (or set CASTELLUM_TOKEN)
  --agent-id ID    Stable agent identifier (default: hostname-derived)
  --hostname H     Hostname to report (default: \$(hostname))
  --primary-ip IP  Primary non-loopback IPv4 to report (default: auto-detect)
  -h, --help       Show this help

Environment variables: CASTELLUM_URL, CASTELLUM_TOKEN
EOF
    exit 1
}

# ── Argument parsing ──────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --url)      shift; CASTELLUM_URL="$1" ;;
        --token)    shift; CASTELLUM_TOKEN="$1" ;;
        --agent-id) shift; AGENT_ID="$1" ;;
        --hostname) shift; AGENT_HOSTNAME="$1" ;;
        --primary-ip) shift; PRIMARY_IP="$1" ;;
        -h|--help)  usage ;;
        *)          printf 'Unknown option: %s\n' "$1" >&2; usage ;;
    esac
    shift
done

# ── Validate required params ──────────────────────────────────────────────────
if [ -z "$CASTELLUM_URL" ]; then
    printf 'Error: CASTELLUM_URL is required (--url or env var)\n' >&2
    exit 2
fi
if [ -z "$CASTELLUM_TOKEN" ]; then
    printf 'Error: CASTELLUM_TOKEN is required (--token or env var)\n' >&2
    exit 2
fi

# ── Derived defaults ──────────────────────────────────────────────────────────
if [ -z "$AGENT_HOSTNAME" ]; then
    AGENT_HOSTNAME="$(hostname)"
fi

if [ -z "$AGENT_ID" ]; then
    # Stable ID: hostname + machine-id if available, else just hostname
    MACHINE_ID=""
    if [ -f /etc/machine-id ]; then
        MACHINE_ID="$(cat /etc/machine-id 2>/dev/null || true)"
    fi
    if [ -n "$MACHINE_ID" ]; then
        AGENT_ID="${AGENT_HOSTNAME}-${MACHINE_ID}"
    else
        AGENT_ID="${AGENT_HOSTNAME}"
    fi
fi

if [ -z "$PRIMARY_IP" ]; then
    # First non-loopback IPv4: try hostname -I, then ip route, then fallback
    PRIMARY_IP=""
    if command -v hostname >/dev/null 2>&1; then
        PRIMARY_IP="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -v '^127\.' | head -1 || true)"
    fi
    if [ -z "$PRIMARY_IP" ] && command -v ip >/dev/null 2>&1; then
        PRIMARY_IP="$(ip route get 1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}' || true)"
    fi
    if [ -z "$PRIMARY_IP" ]; then
        printf 'Warning: could not determine primary IP; using 127.0.0.1\n' >&2
        PRIMARY_IP="127.0.0.1"
    fi
fi

# ── Collect container data ────────────────────────────────────────────────────
CONTAINER_IDS="$(docker ps -q 2>/dev/null || true)"

if [ -z "$CONTAINER_IDS" ]; then
    CONTAINERS_JSON="[]"
else
    CONTAINERS_JSON="$(docker inspect $CONTAINER_IDS 2>/dev/null || echo '[]')"
fi

# ── Build JSON payload ────────────────────────────────────────────────────────
# Escape strings for JSON: replace backslash, double-quote, and control chars.
# Using printf to avoid bash echo -e portability issues.
json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g'
}

AGENT_ID_ESC="$(json_escape "$AGENT_ID")"
HOSTNAME_ESC="$(json_escape "$AGENT_HOSTNAME")"
IP_ESC="$(json_escape "$PRIMARY_IP")"

# ── POST to Castellum ─────────────────────────────────────────────────────────
# -f: fail on 4xx/5xx (non-zero exit for cron alerting)
# -s: silent (no progress meter)
# -S: show errors even when -s
# Token is passed via header only — never echoed to stdout/stderr
printf '{"agentId":"%s","hostname":"%s","primaryIp":"%s","containers":%s}' \
    "$AGENT_ID_ESC" "$HOSTNAME_ESC" "$IP_ESC" "$CONTAINERS_JSON" | \
    curl -fsS \
         -X POST \
         -H "Authorization: Bearer $CASTELLUM_TOKEN" \
         -H "Content-Type: application/json" \
         -d @- \
         "${CASTELLUM_URL}/api/discovery/remote-docker"

printf '\nRemote Docker discovery submitted successfully.\n'
