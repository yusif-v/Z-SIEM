# Z-SIEM Design Spec — Phase 1: N8N + DFIR-IRIS Integration

Date: 2026-06-24
Status: Approved
Author: OWL (pairing with user)

## Goal

Build a working demo of automated SIEM offense-to-case pipeline:
1. SIEM offense arrives via webhook
2. N8N creates a case in DFIR-IRIS
3. SLA timer starts automatically
4. Analyst closes the case
5. SLA timer stops, duration logged

## Architecture

### Components
- **DFIR-IRIS** (port 8000): Case management with REST API, token auth
- **N8N** (port 5678): Workflow engine with webhook trigger + HTTP Request nodes
- **PostgreSQL** (port 5432): Shared database for both IRIS and N8N
- **Redis** (port 6379): IRIS cache/sessions
- **RabbitMQ** (port 5672): IRIS Celery task queue
- **Python Simulator**: Generates synthetic SIEM offenses

### Data Flow

```
[Simulator] --POST /webhook/siem-offense--> [N8N Webhook]
    [N8N] --POST /api/v2/cases--> [IRIS API]
    [N8N] stores {case_id, sla_start} in JSONL
    ...
    [Analyst] --POST /webhook/siem-close-case--> [N8N Webhook]
    [N8N] --POST /api/v2/cases/{id}/close--> [IRIS API]
    [N8N] calculates duration, appends to JSONL
```

### SLA Strategy (Hybrid)
- IRIS built-in SLA (`case_sla_id`) for UI display
- N8N external JSONL logging for metrics/dashboarding
- SLA IDs: 1=normal(24h), 2=elevated(8h), 3=critical(4h)

### Error Handling
- Invalid payload -> 400 response
- IRIS API failure -> 2 retries, 3s between
- Missing SLA record on close -> log warning, still close case

## Decisions Made

1. **SLA tracking**: Hybrid (IRIS fields + N8N JSONL) — best of both
2. **Database**: Single PostgreSQL instance, two databases (iris, n8n)
3. **Authentication**: IRIS API key via N8N Header Auth credential
4. **Workflow format**: N8N JSON (importable, version-controlled)
5. **Demo simulator**: Python script with configurable interval/count

## Implementation Order

1. docker-compose.yaml (infrastructure)
2. N8N workflow JSON (automation logic)
3. Python simulator (testing/demo)
4. Stack manager script (convenience)
5. Documentation (README + this spec)

## Future Phases

- Phase 2: SIEM-specific adapters (Splunk, Sentinel, QRadar)
- Phase 3: Enrichment (VT, AbuseIPDB, Shodan)
- Phase 4: ML classification (Sphinx model)
- Phase 5: Grafana dashboard
