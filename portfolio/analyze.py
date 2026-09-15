"""Offline defensive-security exercises; Python standard library only."""
import argparse
import csv
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
import xml.etree.ElementTree as ET


def auth_alerts(text, threshold=3, window_minutes=5):
    """Alert on failed logins per source IP in an inclusive rolling window."""
    if threshold < 1 or window_minutes < 1:
        raise ValueError("Threshold and window must be positive")
    rows = []
    for number, row in enumerate(csv.DictReader(text.splitlines()), 2):
        if not {"timestamp", "source_ip", "username", "result"} <= row.keys():
            raise ValueError("Missing required CSV columns")
        try:
            stamp = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
            if stamp.tzinfo is None:
                raise ValueError("Timezone required")
        except ValueError as exc:
            raise ValueError(f"Invalid timestamp on row {number}") from exc
        if row["result"] not in {"failure", "success"}:
            raise ValueError(f"Unknown result on row {number}")
        rows.append((stamp, row))
    buckets = defaultdict(deque)
    alerts = []
    for stamp, row in sorted(rows, key=lambda item: item[0]):
        if row["result"] != "failure":
            continue
        bucket = buckets[row["source_ip"]]
        while bucket and stamp - bucket[0][0] > timedelta(minutes=window_minutes):
            bucket.popleft()
        bucket.append((stamp, row["username"]))
        if len(bucket) >= threshold:
            alerts.append({"timestamp": stamp.isoformat(), "source_ip": row["source_ip"],
                           "failed_attempts": len(bucket), "users": sorted({u for _, u in bucket}),
                           "finding": "Repeated authentication failures; investigate, not proof of compromise"})
    return alerts


def nmap_inventory(text):
    """Read existing Nmap XML without initiating network activity."""
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ValueError("DTD and entity declarations are not supported")
    root = ET.fromstring(text)
    if root.tag != "nmaprun":
        raise ValueError("Expected Nmap XML")
    inventory = []
    for host in root.findall("host"):
        addresses = [a.get("addr") for a in host.findall("address") if a.get("addrtype") in {"ipv4", "ipv6"}]
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            inventory.append({"addresses": addresses, "protocol": port.get("protocol"),
                              "port": int(port.get("portid")),
                              "service": service.get("name", "unknown") if service is not None else "unknown",
                              "interpretation": "Open service; not a confirmed vulnerability"})
    return inventory


def header_review(text):
    """Review a saved final HTTPS response header block, not a live website."""
    headers = defaultdict(list)
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()].append(value.strip())
    guidance = {
        "content-security-policy": "Review allowed sources and directives; presence alone does not prove XSS protection.",
        "strict-transport-security": "Check max-age and domain coverage; applicable to HTTPS responses.",
        "x-content-type-options": "Expected value: nosniff.",
        "referrer-policy": "Review policy against application privacy requirements.",
        "permissions-policy": "Limit browser features to the application requirements.",
    }
    findings = []
    for name, note in guidance.items():
        values = headers.get(name, [])
        status = "present: manual review required" if values else "missing: review recommended"
        if name == "x-content-type-options" and values:
            status = "nosniff configured" if values == ["nosniff"] else "unexpected or duplicate value"
        findings.append({"header": name, "values": values, "status": status, "guidance": note})
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["auth", "nmap", "headers"])
    parser.add_argument("input", type=Path)
    parser.add_argument("--threshold", type=int, default=3)
    parser.add_argument("--window-minutes", type=int, default=5)
    args = parser.parse_args()
    try:
        text = args.input.read_text(encoding="utf-8")
        result = auth_alerts(text, args.threshold, args.window_minutes) if args.mode == "auth" else {"nmap": nmap_inventory, "headers": header_review}[args.mode](text)
        print(json.dumps(result, indent=2))
    except (OSError, ValueError, ET.ParseError) as exc:
        parser.exit(2, f"Input error: {exc}\n")

if __name__ == "__main__":
    main()
