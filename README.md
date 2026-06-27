---
type: project
slug: z-siem
status: active
visibility: public
start_date: 2026-06-24
target_date:
repo:
website:
tech: [docker, n8n, dfir-iris, postgresql, python, rabbitmq, redis]
tags: [devsecops, siem-automation, soar, orchestration]
summary: Zero-touch SIEM automation stack connecting SIEM offenses to DFIR-IRIS case management with SLA tracking.
cover:
---

# Z-SIEM

> Zero-touch SIEM automation stack — webhook-driven offense ingestion, case creation, and SLA tracking between SIEMs and DFIR-IRIS.

## Status

**Current:** active

Latest update — 2026-06-24: Phase 1 MVP — N8N + DFIR-IRIS integration with SLA timer.

## Overview

Z-SIEM is an open-source orchestration layer that bridges the gap between SIEM detection and incident response. It ingests offense alerts via webhooks, automatically creates cases in DFIR-IRIS, starts SLA timers, and tracks resolution metrics — all without manual intervention.

**Phase 1 (current):** N8N receives SIEM offenses via webhook, creates IRIS cases with type-based classification, and tracks case lifecycle (SLA start/close duration) end-to-end.

## Features

- **Webhook offense ingestion** — Accepts structured SIEM payloads (Splunk ES, Sentinel, QRadar format compatible)
- **Automated case creation** — Creates DFIR-IRIS cases with type-based classification
- **SLA timer tracking** — Records case creation time, calculates duration on close
- **JSONL metrics export** — SLA metrics written to file for future Grafana/dashboard integration
- **Demo simulator** — Python script generates synthetic offenses for testing
- **Docker Compose** — Single-command deployment of entire stack

## Tech Stack

| Component | Role | Port |
|-----------|------|------|
| N8N | Workflow engine | 5678 |
| DFIR-IRIS | Case management | 8000 |
| PostgreSQL | Database (IRIS + N8N) | 5432 |
| Redis | Cache / session store | 6379 |
| RabbitMQ | Message broker (IRIS workers) | 5672/15672 |
| Python 3 | SIEM simulator script | — |

## Architecture

```
┌─────────────────┐     webhook      ┌──────────────────┐     API     ┌─────────────┐
│  SIEM Simulator │ ───────────────> │  N8N Workflow    │ ──────────> │ DFIR-IRIS   │
│  (Python)       │                  │                  │             │ (Case Mgmt) │
└─────────────────┘                  │  1. Parse        │             └─────────────┘
                                     │  2. Create case  │                    │
┌─────────────────┐                  │  3. Start SLA    │                    │
│  Analyst        │ ── close case ──> │  4. Close case   │ <──────────────────┘
│  (UI or API)    │                  │  5. End SLA      │
└─────────────────┘                  │  6. Log metrics  │
                                     └──────────────────┘
                                            │
                                            ▼
                                     ┌──────────────┐
                                     │ JSONL Metrics│
                                     │ (SLA logs)   │
                                     └──────────────┘
```

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.8+ (for simulator)

### 1. Start the stack

```bash
cd Z-SIEM
./z-siem.sh start
```

This starts all services. IRIS takes ~90 seconds to initialize on first run.

### 2. Complete setup

```bash
./z-siem.sh setup
```

Follows the post-startup checklist:
1. Open IRIS at http://localhost:8000 — complete initial setup
2. Get your IRIS API key (Users -> Your User -> API Key)
3. Open N8N at http://localhost:5678 — create account
4. Create N8N credential "IRIS API Key" (Header Auth: `Authorization: Bearer <YOUR_KEY>`)
5. Import `n8n/workflows/z-siem-offense-to-case.json`
6. Link the credential to the "Create IRIS Case" and "Close IRIS Case" nodes
7. Activate the workflow

### 3. Run the demo

```bash
./z-siem.sh demo
```

Sends 3 synthetic offenses through the full lifecycle. Check N8N executions and IRIS cases.

### 4. Manual testing

Send a single offense:
```bash
curl -X POST http://localhost:5678/webhook/siem-offense \
  -H "Content-Type: application/json" \
  -d '{
    "offense_id": "TEST-001",
    "severity": "critical",
    "type": "malware_c2",
    "description": "Test offense",
    "indicator": "203.0.113.50",
    "indicator_type": "source_ip",
    "confidence": 95,
    "source": {"ip": "203.0.113.50", "hostname": "TEST-PC"},
    "asset": {"hostname": "TEST-PC", "ip": "10.0.1.50", "criticality": "high"}
  }'
```

Close the case:
```bash
curl -X POST http://localhost:5678/webhook/siem-close-case \
  -H "Content-Type: application/json" \
  -d '{"case_id": 1, "close_reason": "resolved"}'
```

## SLA Tracking

SLA tracking in Phase 1 is **wall-clock duration logging**, not enforced IRIS SLAs. On case creation the workflow records `sla_start`; on close it computes elapsed seconds and writes a `sla_closed` event. There is no breach detection or alerting yet (planned — see Roadmap).

**Target policy** (reference only — not yet enforced by the workflow):

| Severity | Target |
|----------|--------|
| critical | 4 hours |
| high | 8 hours |
| medium | 24 hours |
| low | 24 hours |

Note: IRIS **case classification** is assigned from the offense `type` (not severity): `malware_c2`/`ransomware_indicator` → 3, `lateral_movement`/`privilege_escalation` → 2, all others → 1.

Metrics are logged to `/home/node/.n8n/workspace/siem-sla-metrics.jsonl` inside the N8N container:

```jsonl
{"case_id": 1, "offense_id": "OFF-2026-1001", "sla_start": "2026-06-24T12:00:00Z", "severity": "critical", "event": "sla_started"}
{"case_id": 1, "sla_start": "2026-06-24T12:00:00Z", "sla_end": "2026-06-24T12:05:00Z", "sla_duration_seconds": 300, "event": "sla_closed"}
```

## Project Structure

```
Z-SIEM/
├── docker-compose.yaml          # Full stack definition
├── z-siem.sh                    # Stack manager script
├── .env.example                 # Environment template
├── config/
│   ├── iris/                    # IRIS configuration files
│   ├── n8n.env                  # N8N environment variables
│   └── postgres/
│       └── init-n8n-db.sh       # Multi-database initialization
├── n8n/
│   ├── workflows/
│   │   └── z-siem-offense-to-case.json  # Main workflow
│   └── workspace/               # Runtime (gitignored)
├── scripts/
│   ├── siem_simulator.py        # Offense simulator
│   └── requirements.txt         # Python dependencies
└── docs/                        # Additional documentation
```

## Roadmap

- [x] Phase 1: N8N + DFIR-IRIS integration with SLA tracking
- [ ] Phase 2: SIEM-specific webhook adapters (Splunk ES, Sentinel, QRadar)
- [ ] Phase 3: Automated triage (VirusTotal, AbuseIPDB, Shodan enrichment)
- [ ] Phase 4: ML-based offense classification (Sphinx model integration)
- [ ] Phase 5: SLA reporting dashboard (Grafana + JSONL connector)
- [ ] Phase 6: Multi-tenancy support (customer-scoped cases)
- [ ] Phase 7: SOAR playbook library (20+ prebuilt response actions)

## Links

- Repository: (local vault project)
- Demo: (run `./z-siem.sh demo`)
- N8N Docs: https://docs.n8n.io/
- DFIR-IRIS Docs: https://docs.dfir-iris.org/

## Notes

- Default credentials are for demo only — change all passwords for production
- IRIS initial login: complete the setup wizard on first visit
- The N8N workflow uses Header Auth credential type (not stored in workflow JSON)
- PostgreSQL creates two databases: `iris` (IRIS app) and `n8n` (N8N workflows)
- All services communicate on the `z-siem-network` Docker bridge network

## Log

- 2026-06-24: created — Phase 1 MVP with docker-compose, N8N workflow, and SIEM simulator
