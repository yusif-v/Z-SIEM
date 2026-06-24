#!/usr/bin/env python3
"""
Z-SIEM SIEM Offense Simulator
Generates synthetic SIEM offense payloads and sends them via webhook to N8N.
Simulates Splunk ES / Sentinel / QRadar offense format.

Usage:
    python3 siem_simulator.py --url http://localhost:5678/webhook/siem-offense
    python3 siem_simulator.py --url http://localhost:5678/webhook/siem-offense --interval 30
    python3 siem_simulator.py --url http://localhost:5678/webhook/siem-offense --count 5 --wait 2
"""

import argparse
import json
import random
import sys
import time
import uuid
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("ERROR: requests library required. Install with: pip install requests")
    sys.exit(1)

# Offense templates mimicking SIEM detection output
OFFENSE_TYPES = [
    {
        "type": "malware_c2",
        "description": "Malware C2 communication detected to known malicious IP",
        "severity": "critical",
        "indicator_type": "file_hash",
        "confidence": 95,
    },
    {
        "type": "lateral_movement",
        "description": "Suspicious lateral movement detected via PsExec",
        "severity": "high",
        "indicator_type": "source_ip",
        "confidence": 88,
    },
    {
        "type": "phishing_email",
        "description": "Spear-phishing email with malicious attachment detected",
        "severity": "high",
        "indicator_type": "email",
        "confidence": 92,
    },
    {
        "type": "brute_force",
        "description": "Multiple failed authentication attempts from single source",
        "severity": "medium",
        "indicator_type": "source_ip",
        "confidence": 85,
    },
    {
        "type": "data_exfiltration",
        "description": "Unusual outbound data transfer volume to external IP",
        "severity": "critical",
        "indicator_type": "destination_ip",
        "confidence": 78,
    },
    {
        "type": "privilege_escalation",
        "description": "User account added to Domain Admins group outside change window",
        "severity": "critical",
        "indicator_type": "user",
        "confidence": 91,
    },
    {
        "type": "dns_tunneling",
        "description": "DNS queries with high entropy suggesting data tunneling",
        "severity": "medium",
        "indicator_type": "domain",
        "confidence": 72,
    },
    {
        "type": "ransomware_indicator",
        "description": "File encryption patterns consistent with ransomware activity",
        "severity": "critical",
        "indicator_type": "file_hash",
        "confidence": 96,
    },
]

MALICIOUS_IPS = [
    "203.0.113.50", "198.51.100.72", "192.0.2.146",
    "185.220.101.33", "45.142.212.100", "104.248.50.87",
    "159.89.123.45", "51.15.43.208",
]

MALICIOUS_DOMAINS = [
    "evil-domain.xyz", "c2-server.dark", "malware-cdn.top",
    "data-leak.online", "exfiltration.xyz",
]

MALICIOUS_HASHES = [
    "a3f2b8c1d4e5f67890abcdef1234567890abcdef1234567890abcdef12345678",
    "b4c5d6e7f8901234567890abcdef1234567890abcdef1234567890abcdef12",
    "c5d6e7f8901234567890abcdef1234567890abcdef1234567890abcdef1234",
]

USERS = ["jsmith", "agarcia", "mchen", "kpatel", "dlee", "bwilson"]

ASSETS = [
    {"hostname": "DC-PROD-01", "os": "Windows Server 2022", "ip": "10.0.1.10"},
    {"hostname": "WEB-APP-03", "os": "Ubuntu 24.04", "ip": "10.0.3.45"},
    {"hostname": "WS-FINANCE-12", "os": "Windows 11", "ip": "10.0.5.120"},
    {"hostname": "DB-PROD-02", "os": "RHEL 9", "ip": "10.0.2.30"},
    {"hostname": "EMAIL-EXCH-01", "os": "Windows Server 2022", "ip": "10.0.1.25"},
]


def generate_offense() -> dict:
    """Generate a single SIEM offense payload."""
    template = random.choice(OFFENSE_TYPES)
    asset = random.choice(ASSETS)
    offense_id = f"OFF-2026-{str(random.randint(1000, 9999))}"

    offense = {
        "offense_id": offense_id,
        "type": template["type"],
        "severity": template["severity"],
        "description": template["description"],
        "indicator_type": template["indicator_type"],
        "confidence": template["confidence"],
        "source": {
            "ip": random.choice(MALICIOUS_IPS),
            "hostname": asset["hostname"],
            "os": asset["os"],
        },
        "asset": {
            "hostname": asset["hostname"],
            "ip": asset["ip"],
            "os": asset["os"],
            "criticality": random.choice(["high", "medium", "low"]),
        },
        "indicator": None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "id": str(uuid.uuid4()),
    }

    # Set the indicator based on type
    indicator_map = {
        "file_hash": random.choice(MALICIOUS_HASHES),
        "source_ip": offense["source"]["ip"],
        "destination_ip": random.choice(MALICIOUS_IPS),
        "domain": random.choice(MALICIOUS_DOMAINS),
        "email": f"phishing-{random.randint(100,999)}@evil-domain.xyz",
        "user": random.choice(USERS),
    }
    offense["indicator"] = indicator_map.get(template["indicator_type"], offense["source"]["ip"])

    return offense


def send_offense(url: str, offense: dict) -> bool:
    """Send offense payload to N8N webhook."""
    try:
        response = requests.post(
            url,
            json=offense,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if response.status_code in (200, 201, 202, 204):
            offense_id = offense.get("offense_id", "unknown")
            print(f"[OK] Offense {offense_id} sent -> HTTP {response.status_code}")
            return True
        else:
            print(f"[FAIL] HTTP {response.status_code}: {response.text[:200]}")
            return False
    except requests.exceptions.ConnectionError as e:
        print(f"[ERROR] Connection refused: {e}")
        return False
    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Z-SIEM SIEM Offense Simulator")
    parser.add_argument(
        "--url",
        required=True,
        help="N8N webhook URL (e.g. http://host:5678/webhook/siem-offense)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Seconds between offenses (default: 60)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Number of offenses to send (0 = infinite, default: 0)",
    )
    parser.add_argument(
        "--wait",
        type=float,
        default=2.0,
        help="Seconds to wait between burst sends (default: 2.0)",
    )
    args = parser.parse_args()

    print(f"Z-SIEM Offense Simulator")
    print(f"  Webhook URL: {args.url}")
    print(f"  Interval:    {args.interval}s" if args.count == 0 else f"  Count:       {args.count}")
    print(f"  Wait:        {args.wait}s")
    print(f"-" * 40)

    sent = 0
    errors = 0

    try:
        if args.count > 0:
            # Finite mode: send N offenses
            for i in range(args.count):
                offense = generate_offense()
                if send_offense(args.url, offense):
                    sent += 1
                else:
                    errors += 1

                if i < args.count - 1:
                    time.sleep(args.wait)
        else:
            # Infinite mode: send continuously
            while True:
                offense = generate_offense()
                if send_offense(args.url, offense):
                    sent += 1
                else:
                    errors += 1

                time.sleep(args.interval)

    except KeyboardInterrupt:
        pass

    print(f"-" * 40)
    print(f"Done. Sent: {sent}, Errors: {errors}")


if __name__ == "__main__":
    main()
