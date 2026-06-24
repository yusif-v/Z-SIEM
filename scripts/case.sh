#!/bin/bash
# Z-SIEM case helper — start (open) and end (close) a DFIR-IRIS case via the
# n8n webhooks.
#
# Usage:
#   ./scripts/case.sh start [offense_id] [type] [severity]
#   ./scripts/case.sh close <case_id> [close_reason]
#
# Examples:
#   ./scripts/case.sh start
#   ./scripts/case.sh start OFF-2026-1234 ransomware_indicator critical
#   ./scripts/case.sh close 10
#   ./scripts/case.sh close 10 "false positive"
#
# Override the n8n base URL if not on localhost:
#   N8N_URL=http://my-host:5678 ./scripts/case.sh start

set -e

N8N_URL="${N8N_URL:-http://localhost:5678}"

cmd_start() {
    offense_id="${1:-OFF-2026-$(( (RANDOM % 9000) + 1000 ))}"
    type="${2:-ransomware_indicator}"
    severity="${3:-critical}"

    echo "Opening case for offense ${offense_id} (${type}, ${severity})..." >&2
    resp=$(curl -s -X POST "${N8N_URL}/webhook/siem-offense" \
        -H 'Content-Type: application/json' \
        -d "{
            \"offense_id\": \"${offense_id}\",
            \"type\": \"${type}\",
            \"severity\": \"${severity}\",
            \"description\": \"SIEM offense ${offense_id} (${type})\",
            \"indicator\": \"e3b0c44298fc1c149afbf4c8996fb924\",
            \"indicator_type\": \"file_hash\",
            \"confidence\": 96,
            \"source\": { \"ip\": \"45.142.212.100\", \"hostname\": \"WS-FINANCE-12\" },
            \"asset\": { \"hostname\": \"WS-FINANCE-12\", \"ip\": \"10.0.5.120\", \"criticality\": \"high\" }
        }")

    echo "$resp"
    case_id=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('case_id',''))" 2>/dev/null || echo "")
    if [ -n "$case_id" ]; then
        echo "" >&2
        echo "Case opened: ${case_id}" >&2
        echo "  Close it with: ./scripts/case.sh close ${case_id}" >&2
    fi
}

cmd_close() {
    case_id="$1"
    close_reason="${2:-resolved}"
    if [ -z "$case_id" ]; then
        echo "ERROR: case_id required. Usage: ./scripts/case.sh close <case_id> [reason]" >&2
        exit 1
    fi

    echo "Closing case ${case_id} (reason: ${close_reason})..." >&2
    curl -s -X POST "${N8N_URL}/webhook/siem-close-case" \
        -H 'Content-Type: application/json' \
        -d "{\"case_id\": ${case_id}, \"close_reason\": \"${close_reason}\"}"
    echo
}

case "${1:-}" in
    start) shift; cmd_start "$@" ;;
    close|end) shift; cmd_close "$@" ;;
    *)
        echo "Z-SIEM case helper"
        echo ""
        echo "Usage:"
        echo "  $0 start [offense_id] [type] [severity]   Open a case (prints case_id)"
        echo "  $0 close <case_id> [reason]               Close a case (prints SLA duration)"
        echo ""
        echo "Examples:"
        echo "  $0 start"
        echo "  $0 start OFF-2026-1234 lateral_movement high"
        echo "  $0 close 10"
        exit 1
        ;;
esac
