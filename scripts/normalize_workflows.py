#!/usr/bin/env python3
"""Pin stable workflow ids + canonical credential ids into the repo workflow
files so `n8n import:workflow` binds deterministically on any server.

Canonical ids (created by `z-siem.sh bootstrap`):
  workflows:    offense=7MzueHl2x3xo7GDp  enrichment=zsiemEnrichWf01  poller=zsiemSlaPoller1
                qradar=zsiemQradarWf01
  credentials:  httpHeaderAuth=iris-api-key  redis=zsiemRedisCred01  redacted-credential=redacted-credential
"""
import json, sys

WF_DIR = "n8n/workflows"
IRIS_CRED = {"id": "iris-api-key", "name": "IRIS API Key"}
REDIS_CRED = {"id": "zsiemRedisCred01", "name": "Z-SIEM Redis"}
QRADAR_SEC_CRED = {"id": "redacted-credential", "name": "QRadar SEC"}
WF_IDS = {
    "z-siem-offense-to-case.json": "7MzueHl2x3xo7GDp",
    "z-siem-enrichment.json": "zsiemEnrichWf01",
    "z-siem-sla-poller.json": "zsiemSlaPoller1",
    "z-siem-qradar-poller.json": "zsiemQradarWf01",
}
# Nodes that authenticate to QRadar (not IRIS) use the QRadar SEC header credential.
QRADAR_SEC_NODES = {"QRadar Get Offenses"}

for fname, wid in WF_IDS.items():
    path = f"{WF_DIR}/{fname}"
    d = json.load(open(path))
    d["id"] = wid
    for n in d["nodes"]:
        c = n.get("credentials") or {}
        if "httpHeaderAuth" in c:
            c["httpHeaderAuth"] = dict(
                QRADAR_SEC_CRED if n["name"] in QRADAR_SEC_NODES else IRIS_CRED
            )
        if "redis" in c:
            c["redis"] = dict(REDIS_CRED)
        # pin the offense->enrichment sub-workflow reference
        if n["name"] == "Enrich Case":
            n["parameters"]["workflowId"] = {"__rl": True, "value": "zsiemEnrichWf01", "mode": "id"}
    json.dump(d, open(path, "w"), indent=2, ensure_ascii=False)
    print(f"  normalized {fname} (id={wid})")
print("done")
