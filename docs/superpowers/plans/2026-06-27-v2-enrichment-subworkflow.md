# Z-SIEM v2 Enrichment Sub-Workflow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a best-effort threat-intel enrichment sub-workflow that, after each IRIS case is created, looks up its indicators (AbuseIPDB/Shodan/OTX), caches verdicts in Redis, and attaches findings as an IRIS note + registered IOCs — never blocking the webhook or changing classification.

**Architecture:** The existing `z-siem-offense-to-case` workflow gains one `Execute Sub-workflow` node placed *after* `Respond OK`, so the caller is already acked. The new `z-siem-enrichment` sub-workflow is item-oriented: it expands indicators into (provider × target) work items, checks a Redis per-provider cache, calls only the missed providers in parallel (5s timeout, 1 retry, continue-on-error), caches successes, aggregates per target, and posts a note + IOCs to IRIS.

**Tech Stack:** n8n 1.74.1 (Code nodes, native Redis node, HTTP Request nodes, Execute Workflow node), Redis 7 (existing `z-siem-redis`), DFIR-IRIS v2.4.20 REST API, docker-compose.

## Global Constraints

- n8n version: **1.74.1** — node `typeVersion`s must match what this n8n ships (Code v2, HTTP Request v4.2, IF v2, Redis v1, Execute Workflow v1.1). Copy existing nodes' versions from `z-siem-offense-to-case.json`.
- Redis is the **existing** `z-siem-redis` service: host `redis`, port `6379`, password `${IRIS_REDIS_PASSWORD:-redisdemo2026}`. Do **not** add a new Redis service.
- All enrichment Redis keys MUST be prefixed `enrich:` to avoid colliding with IRIS Celery keys.
- Enrichment is **additive only**: never modify `case_classification`; never fail or block case creation.
- IRIS API base inside the network: `http://iris-web:8000` (env `IRIS_API_URL`). Reuse the existing `IRIS API Key` header-auth credential.
- Providers free-tier only; **no VirusTotal**. IP targets → AbuseIPDB + Shodan + OTX; domain/url/hash targets → OTX only.
- `asset_ip` is never enriched (internal host). `source_ip` is enriched only when it is a **public** IP.
- Workflows are imported/activated **manually** via the n8n UI at http://localhost:5678 (the repo mounts `./n8n/workflows` read-only; n8n does not auto-import). Runtime tests require the stack up (`./z-siem.sh start`) and both workflows imported + active.
- Spec: `docs/superpowers/specs/2026-06-27-v2-enrichment-subworkflow-design.md`.
- Commit style: no `Co-Authored-By` trailer (user's global rule).

---

## File Structure

- **Create** `n8n/workflows/z-siem-enrichment.json` — the enrichment sub-workflow.
- **Create** `scripts/verify_iris_enrichment_api.sh` — one-shot probe confirming IRIS note/IOC endpoints.
- **Create** `test/enrichment-smoke.sh` — runtime test-matrix driver (curl + redis-cli assertions).
- **Modify** `n8n/workflows/z-siem-offense-to-case.json` — add `Enrich Case` Execute-Workflow node after `Respond OK`.
- **Modify** `docker-compose.yaml` — add provider/redis/TTL env vars to the `n8n` service.
- **Modify** `.env.example` and `.env` — provider API keys + TTL knobs.
- **Modify** `README.md` — Features, Roadmap (Phase 3), provider-key setup, Redis note.

---

## Task 1: Verify IRIS note + IOC API endpoints (blocking)

The spec's note/IOC endpoints are **assumed**. Confirm the real paths/params/body schema against the running IRIS v2.4.20 before building anything that depends on them.

**Files:**
- Create: `scripts/verify_iris_enrichment_api.sh`

**Interfaces:**
- Produces: confirmed values for `IOC_ADD_PATH`, `NOTE_ADD_PATH`, their query params (e.g. `cid`), and the JSON body field names. Record them at the top of `n8n/workflows/z-siem-enrichment.json` as a `// VERIFIED:` comment block and in this plan's Task 6/7.

- [ ] **Step 1: Write the probe script**

```bash
# scripts/verify_iris_enrichment_api.sh
#!/usr/bin/env bash
# Probe DFIR-IRIS note + IOC endpoints against the running instance.
# Requires: stack up, a real case id, and IRIS_API_KEY exported.
set -euo pipefail

IRIS_URL="${IRIS_API_URL:-http://localhost:8000}"
API_KEY="${IRIS_API_KEY:?export IRIS_API_KEY first}"
CID="${1:?usage: verify_iris_enrichment_api.sh <case_id>}"

auth=(-H "Authorization: Bearer ${API_KEY}" -H "Content-Type: application/json")

echo "== add IOC =="
curl -sS "${auth[@]}" -X POST \
  "${IRIS_URL}/case/ioc/add?cid=${CID}" \
  -d '{"ioc_type_id":1,"ioc_value":"203.0.113.7","ioc_description":"enrichment probe","ioc_tags":"siem,enrichment","ioc_tlp_id":2}' \
  -w '\nHTTP %{http_code}\n'

echo "== add note =="
curl -sS "${auth[@]}" -X POST \
  "${IRIS_URL}/case/notes/add?cid=${CID}" \
  -d '{"note_title":"Enrichment probe","note_content":"hello"}' \
  -w '\nHTTP %{http_code}\n'

echo "== list IOC types (to confirm ioc_type_id mapping) =="
curl -sS "${auth[@]}" "${IRIS_URL}/manage/ioc-types/list" -w '\nHTTP %{http_code}\n'
```

- [ ] **Step 2: Run it against a real case**

Create a throwaway case first (use `scripts/case.sh` open helper or the simulator), then:

Run:
```bash
chmod +x scripts/verify_iris_enrichment_api.sh
IRIS_API_KEY=<key> ./scripts/verify_iris_enrichment_api.sh <case_id>
```
Expected: HTTP 200 from both add calls; note `ioc_type_id` values from the ioc-types list (commonly `1=ip-src`, look up the real ids). If a path 404s, try the documented alternates (`/case/ioc/add` vs `/api/case/ioc/add`) and record what actually works.

- [ ] **Step 3: Record verified facts**

Write the confirmed paths, the `cid` param style, the exact body field names, and the `ioc_type_id` for ip/domain/url/hash into a `VERIFIED-IRIS-API.md` note next to the spec, and update Task 6 & 7 below if anything differs from the assumed values.

- [ ] **Step 4: Commit**

```bash
git add scripts/verify_iris_enrichment_api.sh docs/superpowers/specs/VERIFIED-IRIS-API.md
git commit -m "chore(z-siem): verify IRIS note/IOC API endpoints for enrichment"
```

---

## Task 2: Add Redis + provider + TTL env to n8n service

Give n8n the connection + secrets it needs. No new service — wire the existing Redis and pass provider keys through.

**Files:**
- Modify: `docker-compose.yaml` (n8n `environment:` block, after line ~171)
- Modify: `.env.example`
- Modify: `.env`

**Interfaces:**
- Produces: env vars available to n8n — `REDIS_HOST`, `REDIS_PORT`, `IRIS_REDIS_PASSWORD`, `ABUSEIPDB_API_KEY`, `SHODAN_API_KEY`, `OTX_API_KEY`, `ENRICH_TTL_IP`, `ENRICH_TTL_SHODAN`, `ENRICH_TTL_OTX`, `ENRICH_TTL_HASH`.

- [ ] **Step 1: Add env vars to the n8n service**

In `docker-compose.yaml`, inside the `n8n:` `environment:` block, immediately after the `IRIS_API_URL: "http://iris-web:8000"` line, add:

```yaml
      # Redis (reuse existing z-siem-redis for enrichment verdict cache)
      REDIS_HOST: redis
      REDIS_PORT: 6379
      IRIS_REDIS_PASSWORD: ${IRIS_REDIS_PASSWORD:-redisdemo2026}
      # Threat-intel provider API keys (v2 enrichment)
      ABUSEIPDB_API_KEY: ${ABUSEIPDB_API_KEY:-}
      SHODAN_API_KEY: ${SHODAN_API_KEY:-}
      OTX_API_KEY: ${OTX_API_KEY:-}
      # Enrichment cache TTLs (seconds)
      ENRICH_TTL_IP: ${ENRICH_TTL_IP:-86400}
      ENRICH_TTL_SHODAN: ${ENRICH_TTL_SHODAN:-86400}
      ENRICH_TTL_OTX: ${ENRICH_TTL_OTX:-86400}
      ENRICH_TTL_HASH: ${ENRICH_TTL_HASH:-604800}
```

Also add `redis` to the n8n `depends_on:` block:

```yaml
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
```

- [ ] **Step 2: Add the keys to `.env.example`**

Append:

```bash
# ─── v2 Enrichment (threat-intel providers) ───
# AbuseIPDB: https://www.abuseipdb.com/account/api  (free 1000 checks/day)
ABUSEIPDB_API_KEY=
# Shodan: https://account.shodan.io/  (free tier limited)
SHODAN_API_KEY=
# AlienVault OTX: https://otx.alienvault.com/api  (free, no hard limit)
OTX_API_KEY=
# Cache TTLs (seconds): IP reputation 24h, Shodan host 24h, OTX 24h, hashes 7d
ENRICH_TTL_IP=86400
ENRICH_TTL_SHODAN=86400
ENRICH_TTL_OTX=86400
ENRICH_TTL_HASH=604800
```

Mirror the same keys (with your real values) into `.env`.

- [ ] **Step 3: Validate compose**

Run: `docker compose config >/dev/null && echo OK`
Expected: `OK` (no YAML/interpolation errors).

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yaml .env.example
git commit -m "feat(z-siem): wire redis + threat-intel provider env for v2 enrichment"
```

---

## Task 3: Create n8n credentials (manual, documented)

n8n credentials live in n8n's own DB, not in repo files. This task documents the exact credentials to create so the workflow JSON can reference them by name.

**Files:**
- Modify: `README.md` (add a "v2 setup" subsection — full content in Task 8)

**Interfaces:**
- Produces: three named credentials referenced by later workflow nodes:
  - `Z-SIEM Redis` (type: Redis) → host `redis`, port `6379`, password `={{$env.IRIS_REDIS_PASSWORD}}` (or paste value), database `0`.
  - Providers use **header/query auth inline via `$env`** (no credential needed) to keep secrets in env, not n8n DB. Confirmed in Task 5.

- [ ] **Step 1: Create the Redis credential in the n8n UI**

In n8n → Credentials → New → Redis: Host `redis`, Port `6379`, Password = the value of `IRIS_REDIS_PASSWORD`, Database `0`. Name it exactly `Z-SIEM Redis`. Save & test (must connect).

- [ ] **Step 2: Note the credential id**

After saving, open the credential and copy its id from the URL (e.g. `.../credentials/abc123`). Record it; Task 5 references `Z-SIEM Redis` by name and id.

- [ ] **Step 3: Commit** (nothing to commit yet — credential is in n8n DB; README copy comes in Task 8). Skip.

---

## Task 4: Sub-workflow skeleton — trigger + Build Targets

Create the new workflow with the trigger and the target-expansion Code node, plus a temporary passthrough end so it's importable and testable in isolation.

**Files:**
- Create: `n8n/workflows/z-siem-enrichment.json`

**Interfaces:**
- Consumes: input JSON `{ case_id, indicator, indicator_type, source_ip }` from the Execute-Workflow caller (Task 9).
- Produces: one item **per (provider × target)** with shape
  `{ case_id, target_value, target_type, provider, cache_key }` where
  `cache_key = "enrich:" + provider + ":" + target_type + ":" + target_value`.

- [ ] **Step 1: Write the workflow file with trigger + Build Targets + temp end**

```json
{
  "name": "Z-SIEM Enrichment",
  "nodes": [
    {
      "name": "Enrichment Trigger",
      "type": "n8n-nodes-base.executeWorkflowTrigger",
      "typeVersion": 1,
      "position": [200, 300],
      "parameters": {},
      "notes": "Called by z-siem-offense-to-case after Respond OK. Input: case_id, indicator, indicator_type, source_ip"
    },
    {
      "name": "Build Targets",
      "type": "n8n-nodes-base.code",
      "typeVersion": 2,
      "position": [420, 300],
      "parameters": {
        "jsCode": "// Expand offense into (provider x target) work items.\nconst input = $input.first().json;\nconst caseId = input.case_id;\n\nfunction isPublicIp(ip) {\n  if (!ip || ip === 'unknown') return false;\n  const m = ip.match(/^(\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)$/);\n  if (!m) return false;\n  const o = m.slice(1).map(Number);\n  if (o.some(x => x > 255)) return false;\n  if (o[0] === 10) return false;\n  if (o[0] === 127) return false;\n  if (o[0] === 169 && o[1] === 254) return false;\n  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return false;\n  if (o[0] === 192 && o[1] === 168) return false;\n  if (o[0] === 0) return false;\n  return true;\n}\n\nconst PROVIDERS_BY_TYPE = {\n  ip: ['abuseipdb', 'shodan', 'otx'],\n  domain: ['otx'],\n  url: ['otx'],\n  hash: ['otx']\n};\n\n// Collect unique targets\nconst targets = [];\nconst seen = new Set();\nfunction addTarget(value, type) {\n  if (!value || value === 'unknown') return;\n  const k = type + ':' + value;\n  if (seen.has(k)) return;\n  seen.add(k);\n  targets.push({ value, type });\n}\n\nconst itype = (input.indicator_type || '').toLowerCase();\nconst normType = ['ip','ipv4','ip-src'].includes(itype) ? 'ip'\n  : ['domain','hostname'].includes(itype) ? 'domain'\n  : ['url'].includes(itype) ? 'url'\n  : ['hash','md5','sha1','sha256','file'].includes(itype) ? 'hash'\n  : null;\nif (normType) addTarget(input.indicator, normType);\nif (isPublicIp(input.source_ip)) addTarget(input.source_ip, 'ip');\n\n// Fan out to provider work items\nconst items = [];\nfor (const t of targets) {\n  const providers = PROVIDERS_BY_TYPE[t.type] || [];\n  for (const provider of providers) {\n    items.push({\n      json: {\n        case_id: caseId,\n        target_value: t.value,\n        target_type: t.type,\n        provider,\n        cache_key: `enrich:${provider}:${t.type}:${t.value}`\n      }\n    });\n  }\n}\n\n// If nothing to enrich, emit a single sentinel so downstream note step can still run\nif (items.length === 0) {\n  return [{ json: { case_id: caseId, target_value: null, target_type: null, provider: null, cache_key: null, _empty: true } }];\n}\nreturn items;"
      },
      "notes": "Expand indicator + public source_ip into provider work items"
    },
    {
      "name": "Temp End",
      "type": "n8n-nodes-base.noOp",
      "typeVersion": 1,
      "position": [640, 300],
      "parameters": {},
      "notes": "Placeholder — replaced in later tasks"
    }
  ],
  "connections": {
    "Enrichment Trigger": { "main": [[{ "node": "Build Targets", "type": "main", "index": 0 }]] },
    "Build Targets": { "main": [[{ "node": "Temp End", "type": "main", "index": 0 }]] }
  },
  "settings": { "executionOrder": "v1" }
}
```

- [ ] **Step 2: Validate JSON + the Build Targets logic offline**

Run (extracts the jsCode and exercises it with node):
```bash
python3 -c "import json;d=json.load(open('n8n/workflows/z-siem-enrichment.json'));print('nodes',len(d['nodes']))"
```
Expected: `nodes 3`.

Then unit-check the routing logic by pasting the function into a quick node REPL — confirm:
- input `{indicator:'8.8.8.8',indicator_type:'ip',source_ip:'10.0.0.5'}` → 3 items (abuseipdb/shodan/otx for 8.8.8.8), source_ip skipped (private).
- input `{indicator:'evil.com',indicator_type:'domain',source_ip:'203.0.113.9'}` → 1 OTX item for evil.com + 3 items for 203.0.113.9 = 4 items.

Run:
```bash
node -e "$(python3 -c "import json;print(json.load(open('n8n/workflows/z-siem-enrichment.json'))['nodes'][1]['parameters']['jsCode'].replace('\$input.first().json','INPUT'))"); " 2>/dev/null || echo "manual check in n8n"
```
(If the one-liner is awkward, verify in the n8n editor by pinning sample input on Build Targets — both cases must match the counts above.)

- [ ] **Step 3: Commit**

```bash
git add n8n/workflows/z-siem-enrichment.json
git commit -m "feat(z-siem): scaffold enrichment sub-workflow (trigger + target expansion)"
```

---

## Task 5: Cache lookup, provider fan-out, cache write

Insert the Redis cache check, the per-provider HTTP calls (best-effort), normalization, and the cache write. Replace `Temp End`'s inbound wiring.

**Files:**
- Modify: `n8n/workflows/z-siem-enrichment.json`

**Interfaces:**
- Consumes: work items from Build Targets (`{case_id,target_value,target_type,provider,cache_key}`).
- Produces: per work item a normalized field `result` =
  `{ provider, ok: boolean, data: object|null }` plus passthrough of `case_id,target_value,target_type`. Cache hits and fresh calls both converge to this shape before Aggregate (Task 6).

- [ ] **Step 1: Add the cache-get + split nodes**

Add these nodes to the `nodes` array. First a guard so the empty-indicator sentinel
(`provider == null`, `cache_key == null`) never reaches the Redis GET / Switch (which would
strand it — Switch `fallbackOutput: none` drops it and Aggregate would then see no input).
The guard routes real work to `Cache Get` and sentinels straight to `Aggregate Verdict`
(Task 6 handles `target_value == null` by emitting `verdicts: []`):

```json
    {
      "name": "Has Targets?",
      "type": "n8n-nodes-base.if",
      "typeVersion": 2,
      "position": [560, 300],
      "parameters": {
        "conditions": {
          "options": { "caseSensitive": true, "typeValidation": "loose" },
          "combinator": "and",
          "conditions": [
            { "id": "t1", "leftValue": "={{ $json.target_value }}", "rightValue": "", "operator": { "type": "string", "operation": "notEmpty", "singleValue": true } }
          ]
        },
        "options": {}
      },
      "notes": "True = real target → cache/providers; False = sentinel → straight to Aggregate"
    },
```

Then the Redis GET + hit/miss split. Use the `Z-SIEM Redis` credential id from Task 3 — replace `REDIS_CRED_ID`:

```json
    {
      "name": "Cache Get",
      "type": "n8n-nodes-base.redis",
      "typeVersion": 1,
      "position": [640, 300],
      "parameters": {
        "operation": "get",
        "key": "={{ $json.cache_key }}",
        "options": { "dotNotation": false },
        "propertyName": "cached_raw"
      },
      "credentials": { "redis": { "id": "REDIS_CRED_ID", "name": "Z-SIEM Redis" } },
      "notes": "Look up per-provider cached verdict; empty if miss or sentinel"
    },
    {
      "name": "Cache Hit?",
      "type": "n8n-nodes-base.if",
      "typeVersion": 2,
      "position": [860, 300],
      "parameters": {
        "conditions": {
          "options": { "caseSensitive": true, "typeValidation": "loose" },
          "combinator": "and",
          "conditions": [
            { "id": "h1", "leftValue": "={{ $json.cached_raw }}", "rightValue": "", "operator": { "type": "string", "operation": "notEmpty", "singleValue": true } }
          ]
        },
        "options": {}
      },
      "notes": "True = cached verdict present; False = needs live provider call"
    }
```

> Note on the `_empty` sentinel item: its `cache_key` is null → Redis GET returns empty → routed to the miss branch. Guard against it in the Switch (Step 2) by routing `provider == null` straight to Aggregate via a passthrough.

- [ ] **Step 2: Add provider routing + HTTP nodes (miss branch)**

Add a Switch on `provider`, three HTTP nodes, and a normalizing Code node. Provider secrets come from `$env` inline (no credential).

```json
    {
      "name": "Route Provider",
      "type": "n8n-nodes-base.switch",
      "typeVersion": 3,
      "position": [1080, 360],
      "parameters": {
        "rules": {
          "values": [
            { "conditions": { "options": { "caseSensitive": true, "typeValidation": "loose" }, "combinator": "and", "conditions": [ { "leftValue": "={{ $json.provider }}", "rightValue": "abuseipdb", "operator": { "type": "string", "operation": "equals" } } ] }, "outputKey": "abuseipdb" },
            { "conditions": { "options": { "caseSensitive": true, "typeValidation": "loose" }, "combinator": "and", "conditions": [ { "leftValue": "={{ $json.provider }}", "rightValue": "shodan", "operator": { "type": "string", "operation": "equals" } } ] }, "outputKey": "shodan" },
            { "conditions": { "options": { "caseSensitive": true, "typeValidation": "loose" }, "combinator": "and", "conditions": [ { "leftValue": "={{ $json.provider }}", "rightValue": "otx", "operator": { "type": "string", "operation": "equals" } } ] }, "outputKey": "otx" }
          ]
        },
        "options": { "fallbackOutput": "none" }
      },
      "notes": "Send each work item to its provider HTTP node"
    },
    {
      "name": "AbuseIPDB",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 4.2,
      "position": [1300, 240],
      "onError": "continueRegularOutput",
      "retryOnFail": true,
      "maxTries": 2,
      "waitBetweenTries": 1500,
      "parameters": {
        "method": "GET",
        "url": "https://api.abuseipdb.com/api/v2/check",
        "sendQuery": true,
        "queryParameters": { "parameters": [ { "name": "ipAddress", "value": "={{ $json.target_value }}" }, { "name": "maxAgeInDays", "value": "90" } ] },
        "sendHeaders": true,
        "headerParameters": { "parameters": [ { "name": "Key", "value": "={{ $env.ABUSEIPDB_API_KEY }}" }, { "name": "Accept", "value": "application/json" } ] },
        "options": { "timeout": 5000 }
      },
      "notes": "IP reputation; failure → continue with empty body"
    },
    {
      "name": "Shodan",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 4.2,
      "position": [1300, 360],
      "onError": "continueRegularOutput",
      "retryOnFail": true,
      "maxTries": 2,
      "waitBetweenTries": 1500,
      "parameters": {
        "method": "GET",
        "url": "=https://api.shodan.io/shodan/host/{{ $json.target_value }}",
        "sendQuery": true,
        "queryParameters": { "parameters": [ { "name": "key", "value": "={{ $env.SHODAN_API_KEY }}" } ] },
        "options": { "timeout": 5000 }
      },
      "notes": "Host context; 404 = no info (treated as clean), not failure"
    },
    {
      "name": "OTX",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 4.2,
      "position": [1300, 480],
      "onError": "continueRegularOutput",
      "retryOnFail": true,
      "maxTries": 2,
      "waitBetweenTries": 1500,
      "parameters": {
        "method": "GET",
        "url": "=https://otx.alienvault.com/api/v1/indicators/{{ ({ip:'IPv4',domain:'domain',url:'url',hash:'file'})[$json.target_type] }}/{{ encodeURIComponent($json.target_value) }}/general",
        "sendHeaders": true,
        "headerParameters": { "parameters": [ { "name": "X-OTX-API-KEY", "value": "={{ $env.OTX_API_KEY }}" } ] },
        "options": { "timeout": 5000 }
      },
      "notes": "OTX pulses for ip/domain/url/hash"
    },
    {
      "name": "Normalize Result",
      "type": "n8n-nodes-base.code",
      "typeVersion": 2,
      "position": [1540, 360],
      "parameters": {
        "jsCode": "// Normalize whichever provider produced this item. Best-effort: HTTP errors\n// arrive as items with an `error` field or non-2xx; mark ok=false.\nreturn $input.all().map(item => {\n  const j = item.json;\n  const provider = j.provider;\n  const base = { case_id: j.case_id, target_value: j.target_value, target_type: j.target_type, provider };\n  // n8n continueRegularOutput puts failures in j.error or leaves body empty\n  const failed = j.error !== undefined || j.statusCode >= 500 || (j.body && j.body.error);\n  let data = null, ok = false;\n  try {\n    if (provider === 'abuseipdb' && j.data) { data = { confidence: j.data.abuseConfidenceScore, reports: j.data.totalReports, country: j.data.countryCode }; ok = true; }\n    else if (provider === 'shodan') {\n      if (j.ports || j.data || j.vulns) { data = { ports: j.ports || [], vulns: Object.keys(j.vulns || {}), org: j.org || null }; ok = true; }\n      else if (j.statusCode === 404 || (j.error && String(j.error).includes('404'))) { data = { ports: [], vulns: [], org: null, note: 'no shodan info' }; ok = true; }\n    }\n    else if (provider === 'otx' && j.pulse_info) { data = { pulses: j.pulse_info.count || 0, top: (j.pulse_info.pulses || []).slice(0,3).map(p => p.name) }; ok = true; }\n  } catch (e) { ok = false; }\n  if (failed && !ok) ok = false;\n  return { json: { ...base, result: { provider, ok, data: ok ? data : null } } };\n});"
      },
      "notes": "Map raw provider responses into {provider, ok, data}"
    },
    {
      "name": "Cache Set",
      "type": "n8n-nodes-base.redis",
      "typeVersion": 1,
      "position": [1760, 300],
      "parameters": {
        "operation": "set",
        "key": "=enrich:{{ $json.result.provider }}:{{ $json.target_type }}:{{ $json.target_value }}",
        "value": "={{ JSON.stringify($json.result) }}",
        "keyType": "string",
        "expire": true,
        "ttl": "={{ $json.target_type === 'hash' ? Number($env.ENRICH_TTL_HASH) : ($json.result.provider === 'shodan' ? Number($env.ENRICH_TTL_SHODAN) : ($json.result.provider === 'otx' ? Number($env.ENRICH_TTL_OTX) : Number($env.ENRICH_TTL_IP))) }}"
      },
      "credentials": { "redis": { "id": "REDIS_CRED_ID", "name": "Z-SIEM Redis" } },
      "notes": "Cache only successful results (failed ones skipped before this node)"
    },
    {
      "name": "Only Cache OK",
      "type": "n8n-nodes-base.if",
      "typeVersion": 2,
      "position": [1540, 220],
      "parameters": {
        "conditions": { "options": { "caseSensitive": true, "typeValidation": "loose" }, "combinator": "and", "conditions": [ { "id": "ok1", "leftValue": "={{ $json.result.ok }}", "rightValue": "true", "operator": { "type": "boolean", "operation": "true", "singleValue": true } } ] },
        "options": {}
      },
      "notes": "Gate: only ok results get written to cache"
    }
```

- [ ] **Step 2b: Add a hit-branch decoder**

Cache hits carry `cached_raw` (a JSON string). Add a Code node converting it to the same `result` shape:

```json
    {
      "name": "Decode Cache Hit",
      "type": "n8n-nodes-base.code",
      "typeVersion": 2,
      "position": [1080, 200],
      "parameters": {
        "jsCode": "return $input.all().map(item => {\n  const j = item.json;\n  let result = null;\n  try { result = JSON.parse(j.cached_raw); } catch (e) { result = { provider: j.provider, ok: false, data: null }; }\n  return { json: { case_id: j.case_id, target_value: j.target_value, target_type: j.target_type, provider: j.provider, result } };\n});"
      },
      "notes": "Cache hit → parse stored result JSON back to {provider,ok,data}"
    }
```

- [ ] **Step 3: Rewire connections for this segment**

Replace the `connections` object so the flow is:
Build Targets → Cache Get → Cache Hit? — (true)→ Decode Cache Hit → Aggregate(Task 6); (false)→ Route Provider → [AbuseIPDB|Shodan|OTX] → Normalize Result → Only Cache OK — (true)→ Cache Set → Aggregate; (false)→ Aggregate.

```json
  "connections": {
    "Enrichment Trigger": { "main": [[{ "node": "Build Targets", "type": "main", "index": 0 }]] },
    "Build Targets": { "main": [[{ "node": "Has Targets?", "type": "main", "index": 0 }]] },
    "Has Targets?": { "main": [
      [{ "node": "Cache Get", "type": "main", "index": 0 }],
      [{ "node": "Aggregate Verdict", "type": "main", "index": 0 }]
    ] },
    "Cache Get": { "main": [[{ "node": "Cache Hit?", "type": "main", "index": 0 }]] },
    "Cache Hit?": { "main": [
      [{ "node": "Decode Cache Hit", "type": "main", "index": 0 }],
      [{ "node": "Route Provider", "type": "main", "index": 0 }]
    ] },
    "Route Provider": { "main": [
      [{ "node": "AbuseIPDB", "type": "main", "index": 0 }],
      [{ "node": "Shodan", "type": "main", "index": 0 }],
      [{ "node": "OTX", "type": "main", "index": 0 }]
    ] },
    "AbuseIPDB": { "main": [[{ "node": "Normalize Result", "type": "main", "index": 0 }]] },
    "Shodan": { "main": [[{ "node": "Normalize Result", "type": "main", "index": 0 }]] },
    "OTX": { "main": [[{ "node": "Normalize Result", "type": "main", "index": 0 }]] },
    "Normalize Result": { "main": [[{ "node": "Only Cache OK", "type": "main", "index": 0 }]] },
    "Only Cache OK": { "main": [
      [{ "node": "Cache Set", "type": "main", "index": 0 }],
      [{ "node": "Aggregate Verdict", "type": "main", "index": 0 }]
    ] },
    "Cache Set": { "main": [[{ "node": "Aggregate Verdict", "type": "main", "index": 0 }]] },
    "Decode Cache Hit": { "main": [[{ "node": "Aggregate Verdict", "type": "main", "index": 0 }]] }
  }
```

(`Aggregate Verdict` is created in Task 6; importing before then will warn about the missing node — that is expected and resolved next task. Remove the `Temp End` node.)

- [ ] **Step 4: Validate JSON**

Run: `python3 -c "import json; d=json.load(open('n8n/workflows/z-siem-enrichment.json')); print('nodes', len(d['nodes']))"`
Expected: prints the node count without a JSON error.

- [ ] **Step 5: Commit**

```bash
git add n8n/workflows/z-siem-enrichment.json
git commit -m "feat(z-siem): add cache lookup + provider fan-out + cache write to enrichment"
```

---

## Task 6: Aggregate verdict per target

Collapse the per-provider items back into one verdict per target.

**Files:**
- Modify: `n8n/workflows/z-siem-enrichment.json`

**Interfaces:**
- Consumes: items `{case_id,target_value,target_type,provider,result:{provider,ok,data}}` from both branches.
- Produces: one item per target: `{ case_id, value, type, sources, summary, unavailable }` matching spec §4.5.

- [ ] **Step 1: Add the Aggregate Verdict Code node**

```json
    {
      "name": "Aggregate Verdict",
      "type": "n8n-nodes-base.code",
      "typeVersion": 2,
      "position": [1980, 300],
      "parameters": {
        "jsCode": "// Group per-provider results back into one verdict per target.\nconst items = $input.all().map(i => i.json).filter(j => j.target_value);\nif (items.length === 0) {\n  // _empty sentinel path: nothing was enriched\n  const caseId = $input.first().json.case_id;\n  return [{ json: { case_id: caseId, verdicts: [] } }];\n}\nconst caseId = items[0].case_id;\nconst byTarget = {};\nfor (const it of items) {\n  const key = it.target_type + ':' + it.target_value;\n  if (!byTarget[key]) byTarget[key] = { value: it.target_value, type: it.target_type, sources: {}, unavailable: [] };\n  const r = it.result || { provider: it.provider, ok: false, data: null };\n  if (r.ok && r.data) byTarget[key].sources[r.provider] = r.data;\n  else byTarget[key].unavailable.push(r.provider);\n}\nconst verdicts = Object.values(byTarget).map(v => {\n  const parts = [];\n  if (v.sources.abuseipdb) parts.push(`AbuseIPDB ${v.sources.abuseipdb.confidence}%`);\n  if (v.sources.otx) parts.push(`OTX ${v.sources.otx.pulses} pulses`);\n  if (v.sources.shodan) parts.push(`Shodan ${(v.sources.shodan.ports||[]).length} ports`);\n  v.summary = parts.length ? parts.join(' · ') : 'no provider data';\n  return v;\n});\nreturn [{ json: { case_id: caseId, verdicts } }];"
      },
      "notes": "One verdict per target with per-provider sources + summary"
    }
```

Ensure `Temp End` is removed and the Task 5 connections already point both branches at `Aggregate Verdict`.

- [ ] **Step 2: Validate JSON + dry-run aggregate logic**

Run: `python3 -c "import json; d=json.load(open('n8n/workflows/z-siem-enrichment.json')); names=[n['name'] for n in d['nodes']]; assert 'Aggregate Verdict' in names and 'Temp End' not in names; print('ok', len(names))"`
Expected: `ok <count>`.

In the n8n editor, pin two sample provider-result items for the same IP (one abuseipdb ok, one shodan unavailable) on Aggregate's input → output must be a single verdict with `sources.abuseipdb` set, `unavailable: ['shodan']`, and a `summary` string.

- [ ] **Step 3: Commit**

```bash
git add n8n/workflows/z-siem-enrichment.json
git commit -m "feat(z-siem): aggregate per-provider results into per-target verdicts"
```

---

## Task 7: Post note + register IOCs to IRIS

Turn verdicts into an IRIS note and IOC registrations. **Use the endpoint paths/fields confirmed in Task 1** — the values below are the assumed defaults; correct them if Task 1 found otherwise.

**Files:**
- Modify: `n8n/workflows/z-siem-enrichment.json`

**Interfaces:**
- Consumes: `{ case_id, verdicts:[{value,type,sources,summary,unavailable}] }`.
- Produces: side effects only (note + IOCs on the IRIS case). Terminal node.

- [ ] **Step 1: Add a Build IRIS Payloads Code node**

```json
    {
      "name": "Build IRIS Payloads",
      "type": "n8n-nodes-base.code",
      "typeVersion": 2,
      "position": [2200, 300],
      "parameters": {
        "jsCode": "// Build one note payload + N ioc payloads from verdicts.\nconst { case_id, verdicts } = $input.first().json;\nconst IOC_TYPE_ID = { ip: 1, domain: 20, url: 22, hash: 90 }; // replace with ids verified in Task 1\n\nif (!verdicts || verdicts.length === 0) {\n  return [{ json: { case_id, note: { note_title: 'Automated enrichment', note_content: 'No external indicators to enrich for this offense.' }, iocs: [] } }];\n}\n\nlet md = '## Automated threat-intel enrichment\\n\\n';\nfor (const v of verdicts) {\n  md += `### ${v.type.toUpperCase()} \\`${v.value}\\`\\n\\n`;\n  md += `**Summary:** ${v.summary}\\n\\n`;\n  md += '| Provider | Finding |\\n|---|---|\\n';\n  if (v.sources.abuseipdb) md += `| AbuseIPDB | confidence ${v.sources.abuseipdb.confidence}%, ${v.sources.abuseipdb.reports} reports (${v.sources.abuseipdb.country||'?'}) |\\n`;\n  if (v.sources.shodan) md += `| Shodan | ports ${(v.sources.shodan.ports||[]).join(', ')||'none'}; vulns ${(v.sources.shodan.vulns||[]).join(', ')||'none'} |\\n`;\n  if (v.sources.otx) md += `| OTX | ${v.sources.otx.pulses} pulses${v.sources.otx.top&&v.sources.otx.top.length?': '+v.sources.otx.top.join('; '):''} |\\n`;\n  for (const u of (v.unavailable||[])) md += `| ${u} | unavailable |\\n`;\n  md += '\\n';\n}\n\nconst iocs = verdicts.map(v => ({\n  ioc_type_id: IOC_TYPE_ID[v.type] || 1,\n  ioc_value: v.value,\n  ioc_description: `SIEM enrichment: ${v.summary}`,\n  ioc_tags: 'siem,enrichment',\n  ioc_tlp_id: 2\n}));\n\nreturn [{ json: { case_id, note: { note_title: 'Automated enrichment', note_content: md }, iocs } }];"
      },
      "notes": "Compose IRIS note markdown + IOC payloads from verdicts"
    },
    {
      "name": "Post Note",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 4.2,
      "position": [2420, 220],
      "onError": "continueRegularOutput",
      "parameters": {
        "method": "POST",
        "url": "={{$env.IRIS_API_URL || 'http://iris-web:8000'}}/case/notes/add?cid={{ $json.case_id }}",
        "authentication": "predefinedCredentialType",
        "nodeCredentialType": "httpHeaderAuth",
        "sendBody": true,
        "specifyBody": "json",
        "jsonBody": "={{ JSON.stringify($json.note) }}",
        "options": { "timeout": 8000 }
      },
      "credentials": { "httpHeaderAuth": { "id": "iris-api-key", "name": "IRIS API Key" } },
      "notes": "Post enrichment note to the IRIS case (best-effort)"
    },
    {
      "name": "Split IOCs",
      "type": "n8n-nodes-base.code",
      "typeVersion": 2,
      "position": [2420, 380],
      "parameters": {
        "jsCode": "const j = $input.first().json;\nreturn (j.iocs || []).map(ioc => ({ json: { case_id: j.case_id, ...ioc } }));"
      },
      "notes": "Emit one item per IOC for the IOC POST node"
    },
    {
      "name": "Register IOC",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 4.2,
      "position": [2640, 380],
      "onError": "continueRegularOutput",
      "parameters": {
        "method": "POST",
        "url": "={{$env.IRIS_API_URL || 'http://iris-web:8000'}}/case/ioc/add?cid={{ $json.case_id }}",
        "authentication": "predefinedCredentialType",
        "nodeCredentialType": "httpHeaderAuth",
        "sendBody": true,
        "specifyBody": "json",
        "jsonBody": "={{ JSON.stringify({ ioc_type_id: $json.ioc_type_id, ioc_value: $json.ioc_value, ioc_description: $json.ioc_description, ioc_tags: $json.ioc_tags, ioc_tlp_id: $json.ioc_tlp_id }) }}",
        "options": { "timeout": 8000 }
      },
      "credentials": { "httpHeaderAuth": { "id": "iris-api-key", "name": "IRIS API Key" } },
      "notes": "Register each target as an IOC on the case (best-effort)"
    }
```

- [ ] **Step 2: Wire the terminal segment**

Add to `connections`:

```json
    "Aggregate Verdict": { "main": [[{ "node": "Build IRIS Payloads", "type": "main", "index": 0 }]] },
    "Build IRIS Payloads": { "main": [[
      { "node": "Post Note", "type": "main", "index": 0 },
      { "node": "Split IOCs", "type": "main", "index": 0 }
    ]] },
    "Split IOCs": { "main": [[{ "node": "Register IOC", "type": "main", "index": 0 }]] }
```

- [ ] **Step 3: Validate JSON + connectivity sanity**

Run:
```bash
python3 - <<'PY'
import json
d=json.load(open('n8n/workflows/z-siem-enrichment.json'))
names={n['name'] for n in d['nodes']}
need={'Build IRIS Payloads','Post Note','Split IOCs','Register IOC','Aggregate Verdict'}
assert need<=names, need-names
# every connection target exists
for src,c in d['connections'].items():
    for outs in c['main']:
        for e in outs:
            assert e['node'] in names, f"dangling: {e['node']}"
print('graph ok', len(names), 'nodes')
PY
```
Expected: `graph ok <n> nodes` with no assertion error.

- [ ] **Step 4: Commit**

```bash
git add n8n/workflows/z-siem-enrichment.json
git commit -m "feat(z-siem): post enrichment note + register IOCs to IRIS"
```

---

## Task 8: Wire `Enrich Case` into the main workflow + README

Connect the main workflow to the sub-workflow and document setup.

**Files:**
- Modify: `n8n/workflows/z-siem-offense-to-case.json` (add node after `Respond OK`)
- Modify: `README.md`

**Interfaces:**
- Consumes: `Respond OK` output (which carries `iris_case_id` and the Extract Fields data via `$('Extract Fields')`).
- Produces: triggers `z-siem-enrichment` with `{case_id,indicator,indicator_type,source_ip}`.

- [ ] **Step 1: Add the Execute-Workflow node**

In `n8n/workflows/z-siem-offense-to-case.json` `nodes` array, add (set `ENRICH_WF_ID` to the imported sub-workflow's id, or use `cachedResultName`):

```json
    {
      "name": "Enrich Case",
      "type": "n8n-nodes-base.executeWorkflow",
      "typeVersion": 1.1,
      "position": [1300, 250],
      "parameters": {
        "source": "database",
        "workflowId": "ENRICH_WF_ID",
        "mode": "once",
        "options": { "waitForSubWorkflow": false },
        "workflowInputs": {
          "mappingMode": "defineBelow",
          "value": {
            "case_id": "={{ $json.iris_case_id || $('Store SLA Start').first().json.iris_case_id }}",
            "indicator": "={{ $('Extract Fields').first().json.indicator }}",
            "indicator_type": "={{ $('Extract Fields').first().json.indicator_type }}",
            "source_ip": "={{ $('Extract Fields').first().json.source_ip }}"
          }
        }
      },
      "notes": "Fire enrichment AFTER Respond OK so the webhook ack is not blocked"
    }
```

- [ ] **Step 2: Rewire `Store SLA Start` to chain Respond OK → Enrich Case**

`Respond OK` is a terminal respond node; n8n keeps executing downstream nodes after it. Change the `Store SLA Start` connection to fan out to both `Respond OK` and `Enrich Case`:

```json
    "Store SLA Start": {
      "main": [
        [
          { "node": "Respond OK", "type": "main", "index": 0 },
          { "node": "Enrich Case", "type": "main", "index": 0 }
        ]
      ]
    },
```

(Fanning out from `Store SLA Start` — rather than chaining off `Respond OK` — guarantees `Enrich Case` runs even though `Respond OK` ends the HTTP response. Both receive the same item carrying `iris_case_id`.)

- [ ] **Step 3: Validate JSON**

Run:
```bash
python3 - <<'PY'
import json
d=json.load(open('n8n/workflows/z-siem-offense-to-case.json'))
names={n['name'] for n in d['nodes']}
assert 'Enrich Case' in names
conn=d['connections']['Store SLA Start']['main'][0]
assert {e['node'] for e in conn}=={'Respond OK','Enrich Case'}
print('main workflow wired ok')
PY
```
Expected: `main workflow wired ok`.

- [ ] **Step 4: Update README**

Add a Features bullet under the existing list:
```markdown
- **Threat-intel enrichment (v2)** — On case creation, indicators are enriched via AbuseIPDB/Shodan/AlienVault OTX (best-effort, Redis-cached) and attached as an IRIS note + registered IOCs. Never blocks the webhook; never changes classification.
```
Flip the Roadmap line:
```markdown
- [x] Phase 3: Automated triage enrichment (AbuseIPDB / Shodan / OTX → notes + IOCs)
```
Add a "## v2 Enrichment Setup" section documenting: the three API keys in `.env` (with signup links), that Redis is reused, that both `z-siem-offense-to-case.json` and `z-siem-enrichment.json` must be imported + activated, and the `Z-SIEM Redis` credential creation from Task 3.

- [ ] **Step 5: Commit**

```bash
git add n8n/workflows/z-siem-offense-to-case.json README.md
git commit -m "feat(z-siem): trigger enrichment sub-workflow after case creation; document v2 setup"
```

---

## Task 9: Runtime end-to-end test matrix

Verify the whole thing against the live stack. Requires `./z-siem.sh start`, both workflows imported + active, and real provider keys in `.env`.

**Files:**
- Create: `test/enrichment-smoke.sh`

**Interfaces:**
- Consumes: running stack + active workflows.
- Produces: pass/fail report for the spec §7 matrix.

- [ ] **Step 1: Write the smoke-test driver**

```bash
# test/enrichment-smoke.sh
#!/usr/bin/env bash
set -euo pipefail
N8N="http://localhost:5678/webhook/siem-offense"
RPASS="${IRIS_REDIS_PASSWORD:-redisdemo2026}"
redis() { docker exec z-siem-redis redis-cli -a "$RPASS" "$@" 2>/dev/null; }

echo "== T1: known-bad IP enriches =="
redis FLUSHDB >/dev/null
body='{"offense_id":"SMOKE-1","severity":"high","type":"malware_c2","indicator":"45.83.122.10","indicator_type":"ip","source":{"ip":"203.0.113.50"},"asset":{"hostname":"web01","ip":"10.0.0.5"},"confidence":80,"description":"smoke c2"}'
t0=$(date +%s%N); resp=$(curl -s -X POST "$N8N" -H 'Content-Type: application/json' -d "$body"); t1=$(date +%s%N)
echo "  response: $resp"
echo "  webhook latency ms: $(( (t1 - t0)/1000000 ))   (T6: should be well under provider timeout)"
cid=$(echo "$resp" | python3 -c "import sys,json;print(json.load(sys.stdin).get('case_id',''))")
sleep 8
echo "  redis enrich keys after run:"; redis KEYS 'enrich:*'

echo "== T2: cache hit (same indicator, expect zero new provider calls) =="
before=$(redis KEYS 'enrich:*' | wc -l)
curl -s -X POST "$N8N" -H 'Content-Type: application/json' -d "${body/SMOKE-1/SMOKE-2}" >/dev/null
sleep 5
after=$(redis KEYS 'enrich:*' | wc -l)
echo "  enrich keys before=$before after=$after (should be equal → served from cache)"

echo "== T5: private source_ip skipped =="
echo "  (inspect SMOKE-1 case note: only indicator 45.83.122.10 enriched, asset/private IP absent)"

echo "Now open IRIS case $cid and confirm: enrichment note present + IOC registered (T-IRIS)."
```

- [ ] **Step 2: Run the matrix**

Run:
```bash
chmod +x test/enrichment-smoke.sh
./z-siem.sh start   # if not already up; import + activate both workflows in the UI first
IRIS_REDIS_PASSWORD=<pass> ./test/enrichment-smoke.sh
```
Expected:
- T1: response has a `case_id`; `enrich:*` keys appear; webhook latency low (ack not blocked).
- T2: key count unchanged on the second fire (cache hit).
- Manually: IRIS case shows the enrichment note + IOC.

- [ ] **Step 3: Provider-down check**

Temporarily set `SHODAN_API_KEY` to an obviously bad value (or point the Shodan node URL at `http://127.0.0.1:1`), restart n8n, fire SMOKE-3. Confirm the note still posts with `| shodan | unavailable |` and the case is unaffected.

- [ ] **Step 4: Commit**

```bash
git add test/enrichment-smoke.sh
git commit -m "test(z-siem): add enrichment end-to-end smoke matrix"
```

---

## Self-Review Notes (for the implementer)

- **Task 1 gates everything that writes to IRIS** (Tasks 7–9). If endpoints differ, fix the `Post Note`/`Register IOC` URLs and the `IOC_TYPE_ID` map before runtime testing.
- **Redis credential id** (`REDIS_CRED_ID`) and **sub-workflow id** (`ENRICH_WF_ID`) are environment-specific — fill them after creating the credential / importing the workflow.
- **n8n node typeVersions** must match 1.74.1; if the editor upgrades a node on import, re-export and commit the upgraded JSON.
- **Best-effort invariant:** every node touching the network uses `onError: continueRegularOutput`. Never add a node on the enrichment path that can hard-fail the execution before the case is safe (it always is — the case is created and acked before `Enrich Case` runs).
