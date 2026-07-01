#!/usr/bin/env python3
"""Pin stable workflow ids + canonical credential ids into the repo workflow
files so `n8n import:workflow` binds deterministically on any server.

Canonical ids (created by `z-siem.sh bootstrap`):
  workflows:    offense=7MzueHl2x3xo7GDp  enrichment=zsiemEnrichWf01  poller=zsiemSlaPoller1
  credentials:  httpHeaderAuth=iris-api-key  redis=zsiemRedisCred01

Note: the QRadar poller (z-siem-qradar-poller.json) ships as a credential-free
template — bind the `QRadar SEC` and `IRIS API Key` credentials in the n8n UI on
import. It is intentionally not managed here so no credential ids are committed.
"""
import json, sys

WF_DIR = "n8n/workflows"
IRIS_CRED = {"id": "iris-api-key", "name": "IRIS API Key"}
REDIS_CRED = {"id": "zsiemRedisCred01", "name": "Z-SIEM Redis"}
WF_IDS = {
    "z-siem-offense-to-case.json": "7MzueHl2x3xo7GDp",
    "z-siem-enrichment.json": "zsiemEnrichWf01",
    "z-siem-sla-poller.json": "zsiemSlaPoller1",
}

for fname, wid in WF_IDS.items():
    path = f"{WF_DIR}/{fname}"
    d = json.load(open(path))
    d["id"] = wid
    for n in d["nodes"]:
        c = n.get("credentials") or {}
        if "httpHeaderAuth" in c:
            c["httpHeaderAuth"] = dict(IRIS_CRED)
        if "redis" in c:
            c["redis"] = dict(REDIS_CRED)
        # pin the offense->enrichment sub-workflow reference
        if n["name"] == "Enrich Case":
            n["parameters"]["workflowId"] = {"__rl": True, "value": "zsiemEnrichWf01", "mode": "id"}
    json.dump(d, open(path, "w"), indent=2, ensure_ascii=False)
    print(f"  normalized {fname} (id={wid})")
print("done")
