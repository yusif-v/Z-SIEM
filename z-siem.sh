#!/bin/bash
# Z-SIEM Stack Manager
# Usage: ./z-siem.sh <command>
# Commands: start, stop, restart, status, logs, demo, setup

set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

cmd_start() {
    log_info "Starting Z-SIEM stack..."
    
    # Create .env if missing
    if [ ! -f .env ]; then
        log_warn ".env not found, copying from .env.example"
        cp .env.example .env
    fi
    
    # Start all services
    docker compose up -d
    
    log_info "Waiting for services to be healthy..."
    sleep 5
    
    # Check PostgreSQL
    if docker compose exec -T postgres pg_isready -U iris > /dev/null 2>&1; then
        log_ok "PostgreSQL: ready"
    else
        log_warn "PostgreSQL: still starting..."
    fi
    
    # Check IRIS (takes longer)
    log_info "Waiting for IRIS web app (this may take 60-90 seconds)..."
    for i in $(seq 1 30); do
        if curl -sf http://localhost:8000/login > /dev/null 2>&1; then
            log_ok "DFIR-IRIS: ready at http://localhost:8000"
            break
        fi
        if [ "$i" -eq 30 ]; then
            log_error "IRIS failed to start. Check: docker compose logs iris-web"
            exit 1
        fi
        sleep 3
    done
    
    # Check N8N
    if curl -sf http://localhost:5678/health > /dev/null 2>&1; then
        log_ok "N8N: ready at http://localhost:5678"
    else
        log_warn "N8N: still starting..."
    fi
    
    echo ""
    log_ok "Z-SIEM Stack is running!"
    echo ""
    echo "  DFIR-IRIS:  http://localhost:8000"
    echo "  N8N:        http://localhost:5678"
    echo "  RabbitMQ:   http://localhost:15672"
    echo ""
    echo "Next steps:"
    echo "  1. Open IRIS at http://localhost:8000 and complete setup"
    echo "  2. Get your IRIS API key from Users -> Your User -> API Key"
    echo "  3. Import the N8N workflow: n8n/workflows/z-siem-offense-to-case.json"
    echo "  4. Create N8N credential 'IRIS API Key' (type: Header Auth)"
    echo "  5. Activate the workflow"
    echo "  6. Run demo: ./z-siem.sh demo"
}

cmd_stop() {
    log_info "Stopping Z-SIEM stack..."
    docker compose down
    log_ok "Stack stopped."
}

cmd_restart() {
    cmd_stop
    sleep 2
    cmd_start
}

cmd_status() {
    echo "Z-SIEM Service Status:"
    echo "======================"
    for svc in postgres redis rabbitmq iris-web iris-worker n8n; do
        status=$(docker compose ps --format json "$svc" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('State','unknown'))" 2>/dev/null || echo "not found")
        if [ "$status" = "running" ]; then
            echo -e "  $svc: ${GREEN}running${NC}"
        else
            echo -e "  $svc: ${RED}${status}${NC}"
        fi
    done
}

cmd_logs() {
    service="${1:-}"
    if [ -z "$service" ]; then
        docker compose logs --tail=50 -f
    else
        docker compose logs --tail=50 -f "$service"
    fi
}

cmd_demo() {
    log_info "Running Z-SIEM demo..."
    echo ""
    
    # Check if N8N webhook is reachable
    if ! curl -sf http://localhost:5678/health > /dev/null 2>&1; then
        log_error "N8N is not running. Start with: ./z-siem.sh start"
        exit 1
    fi
    
    WEBHOOK_URL="http://localhost:5678/webhook/siem-offense"
    
    log_info "Sending 3 test offenses to N8N webhook..."
    echo ""
    
    python3 scripts/siem_simulator.py \
        --url "$WEBHOOK_URL" \
        --count 3 \
        --wait 3
    
    echo ""
    log_ok "Demo offenses sent!"
    echo ""
    echo "Check N8N at http://localhost:5678 to see the workflow executions."
    echo "Check IRIS at http://localhost:8000 to see created cases."
    echo ""
    echo "To close a case (simulate analyst action):"
    echo '  curl -X POST http://localhost:5678/webhook/siem-close-case \'
    echo '    -H "Content-Type: application/json" \'
    echo "    -d '{\"case_id\": 1, \"close_reason\": \"resolved\"}'"
}

cmd_setup() {
    log_info "Z-SIEM Initial Setup"
    echo ""
    
    # Step 1: Start stack
    cmd_start
    
    echo ""
    echo "═══════════════════════════════════════════"
    echo "  POST-STARTUP CHECKLIST"
    echo "═══════════════════════════════════════════"
    echo ""
    echo "1. Open DFIR-IRIS: http://localhost:8000"
    echo "   - Complete initial setup (admin account)"
    echo "   - Go to Users -> admin -> API Key"
    echo "   - Copy the API key"
    echo ""
    echo "2. Open N8N: http://localhost:5678"
    echo "   - Create account on first visit"
    echo "   - Go to Settings -> Credentials -> Add New"
    echo "   - Choose 'Header Auth' type"
    echo "   - Name: 'IRIS API Key'"
    echo "   - Header Name: 'Authorization'"
    echo "   - Value: 'Bearer <YOUR_IRIS_API_KEY>'"
    echo "   - Save"
    echo ""
    echo "3. Import workflow:"
    echo "   - Go to Workflows -> Import from File"
    echo "   - Select: n8n/workflows/z-siem-offense-to-case.json"
    echo "   - Update the 'Create IRIS Case' node credential to 'IRIS API Key'"
    echo "   - Activate the workflow"
    echo ""
    echo "4. Test the webhook:"
    echo "   ./z-siem.sh demo"
    echo ""
}

# Main
case "${1:-}" in
    start)   cmd_start ;;
    stop)    cmd_stop ;;
    restart) cmd_restart ;;
    status)  cmd_status ;;
    logs)    cmd_logs "$2" ;;
    demo)    cmd_demo ;;
    setup)   cmd_setup ;;
    *)
        echo "Z-SIEM Stack Manager"
        echo ""
        echo "Usage: $0 <command>"
        echo ""
        echo "Commands:"
        echo "  start    Start all services"
        echo "  stop     Stop all services"
        echo "  restart  Restart all services"
        echo "  status   Show service status"
        echo "  logs     Show logs (optional: service name)"
        echo "  demo     Run demo (send test offenses)"
        echo "  setup    Full setup guide"
        echo ""
        exit 1
        ;;
esac
