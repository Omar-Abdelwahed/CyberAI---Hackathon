"""
=======================================================
PHASE 2 — IOC EXTRACTION
=======================================================
Input  : data/phase1_output.json   (output of Phase 1)
Output : data/phase2_output.json   (input for Phase 3)

How to test:
    cd CyberAI---Hackathon
    python cyberIA/preprocessing/cleaner.py

No API keys. No internet. Pure extraction.
=======================================================
"""

import os
import re
import json
from datetime import datetime

# ── Paths ──────────────────────────────────────────────
# cleaner.py is at: CyberAI---Hackathon/cyberIA/preprocessing/cleaner.py
# We need to go up 3 levels to reach CyberAI---Hackathon/
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
INPUT_FILE  = os.path.join(BASE_DIR, "data", "phase1_output.json")
OUTPUT_FILE = os.path.join(BASE_DIR, "data", "phase2_output.json")

# ── Limits (avoid processing full file) ───────────────
MAX_NETWORK_FLOWS = 300
MAX_CVE           = 150
MAX_URLS          = 150

# ── Regex patterns ─────────────────────────────────────
IP_PATTERN     = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|ru|cn|io|xyz|info|sh|bin|php)\b')
CVE_PATTERN    = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
HASH_PATTERN   = re.compile(r'\b[a-fA-F0-9]{32,64}\b')


# ═══════════════════════════════════════════════════════
# EXTRACTOR 1 — Network flows (CICIDS)
# ═══════════════════════════════════════════════════════
def extract_from_network_flows(records):
    print(f"\n[1/3] Extracting IOCs from network flows ({len(records)} records)...")
    iocs = []

    for row in records[:MAX_NETWORK_FLOWS]:
        label    = str(row.get("Label", "UNKNOWN")).strip()
        src_ip   = str(row.get("Source IP", "")).strip()
        dst_ip   = str(row.get("Destination IP", "")).strip()
        dst_port = str(row.get("Destination Port", "")).strip()
        protocol = str(row.get("Protocol", "")).strip()
        src_file = row.get("source_file", "")

        # Source IP
        if src_ip and IP_PATTERN.match(src_ip):
            iocs.append({
                "ioc_value":    src_ip,
                "ioc_type":     "ip",
                "role":         "source",
                "threat_label": label,
                "protocol":     protocol,
                "dst_port":     dst_port,
                "source":       "CICIDS2017",
                "context":      f"{src_ip} → {dst_ip}:{dst_port} [{label}]",
                "source_file":  src_file
            })

        # Destination IP
        if dst_ip and IP_PATTERN.match(dst_ip):
            iocs.append({
                "ioc_value":    dst_ip,
                "ioc_type":     "ip",
                "role":         "destination",
                "threat_label": label,
                "protocol":     protocol,
                "dst_port":     dst_port,
                "source":       "CICIDS2017",
                "context":      f"{src_ip} → {dst_ip}:{dst_port} [{label}]",
                "source_file":  src_file
            })

    # Stats
    labels = {}
    for ioc in iocs:
        l = ioc["threat_label"]
        labels[l] = labels.get(l, 0) + 1
    print(f"      ✓ Extracted {len(iocs)} IP IOCs | Labels: {labels}")
    return iocs


# ═══════════════════════════════════════════════════════
# EXTRACTOR 2 — CVE vulnerabilities
# ═══════════════════════════════════════════════════════
def extract_from_cve(records):
    print(f"\n[2/3] Extracting IOCs from CVE records ({len(records)} records)...")
    iocs = []

    for row in records[:MAX_CVE]:
        cve_id      = str(row.get("cve_id", "")).strip()
        severity    = str(row.get("severity", "UNKNOWN")).strip().upper()
        cvss_score  = str(row.get("cvss_score", "")).strip()
        description = str(row.get("description", "")).strip()
        src_file    = row.get("source_file", "")

        if not cve_id:
            continue

        # CVE ID itself as IOC
        iocs.append({
            "ioc_value":    cve_id,
            "ioc_type":     "cve",
            "role":         "vulnerability",
            "threat_label": severity,
            "cvss_score":   cvss_score,
            "source":       "CVE_INTEL",
            "context":      description[:200],
            "source_file":  src_file
        })

        # Extract any extra CVE IDs mentioned in description
        extra_cves = CVE_PATTERN.findall(description)
        for extra in extra_cves:
            if extra != cve_id:
                iocs.append({
                    "ioc_value":    extra,
                    "ioc_type":     "cve_reference",
                    "role":         "related_vulnerability",
                    "threat_label": severity,
                    "cvss_score":   "",
                    "source":       "CVE_INTEL",
                    "context":      f"Referenced in {cve_id}: {description[:100]}",
                    "source_file":  src_file
                })

    sev_counts = {}
    for ioc in iocs:
        s = ioc["threat_label"]
        sev_counts[s] = sev_counts.get(s, 0) + 1
    print(f"      ✓ Extracted {len(iocs)} CVE IOCs | Severity: {sev_counts}")
    return iocs


# ═══════════════════════════════════════════════════════
# EXTRACTOR 3 — URLhaus malicious URLs
# ═══════════════════════════════════════════════════════
def extract_from_urls(records):
    print(f"\n[3/3] Extracting IOCs from URLhaus records ({len(records)} records)...")
    iocs = []

    for row in records[:MAX_URLS]:
        url      = str(row.get("url", "")).strip()
        threat   = str(row.get("threat", "malware")).strip()
        tags     = str(row.get("tags", "")).strip()
        src_file = row.get("source_file", "")

        if not url:
            continue

        # Full URL as IOC
        iocs.append({
            "ioc_value":    url,
            "ioc_type":     "url",
            "role":         "malicious_url",
            "threat_label": threat,
            "tags":         tags,
            "source":       "URLhaus_OSINT",
            "context":      f"Threat: {threat} | Tags: {tags}",
            "source_file":  src_file
        })

        # Extract IP from URL if present
        ips_in_url = IP_PATTERN.findall(url)
        for ip in ips_in_url:
            iocs.append({
                "ioc_value":    ip,
                "ioc_type":     "ip",
                "role":         "malicious_host",
                "threat_label": threat,
                "tags":         tags,
                "source":       "URLhaus_OSINT",
                "context":      f"Extracted from URL: {url}",
                "source_file":  src_file
            })

        # Extract domain from URL if present
        domains = DOMAIN_PATTERN.findall(url)
        for domain in domains:
            iocs.append({
                "ioc_value":    domain,
                "ioc_type":     "domain",
                "role":         "malicious_host",
                "threat_label": threat,
                "tags":         tags,
                "source":       "URLhaus_OSINT",
                "context":      f"Extracted from URL: {url}",
                "source_file":  src_file
            })

    threat_counts = {}
    for ioc in iocs:
        t = ioc["threat_label"]
        threat_counts[t] = threat_counts.get(t, 0) + 1
    print(f"      ✓ Extracted {len(iocs)} URL/IP/domain IOCs | Threats: {threat_counts}")
    return iocs


# ═══════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════
def run():
    print("=" * 60)
    print("  PHASE 2 — IOC EXTRACTION")
    print("=" * 60)
    print(f"\n  Reading: {INPUT_FILE}")

    if not os.path.exists(INPUT_FILE):
        print(f"\n  ✗ Input file not found. Run Phase 1 first.")
        return

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    network_flows   = data.get("network_flows", [])
    vulnerabilities = data.get("vulnerabilities", [])
    malicious_urls  = data.get("malicious_urls", [])

    print(f"\n  Loaded  → {len(network_flows)} flows | {len(vulnerabilities)} CVEs | {len(malicious_urls)} URLs")
    print(f"  Capped  → {MAX_NETWORK_FLOWS} flows | {MAX_CVE} CVEs | {MAX_URLS} URLs")

    # Extract from each section
    iocs_network = extract_from_network_flows(network_flows)
    iocs_cve     = extract_from_cve(vulnerabilities)
    iocs_url     = extract_from_urls(malicious_urls)

    all_iocs = iocs_network + iocs_cve + iocs_url

    # Count by type
    type_counts = {}
    for ioc in all_iocs:
        t = ioc["ioc_type"]
        type_counts[t] = type_counts.get(t, 0) + 1

    output = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "phase":        "2 - IOC Extraction",
            "total_iocs":   len(all_iocs),
            "by_type":      type_counts,
            "limits_applied": {
                "network_flows": MAX_NETWORK_FLOWS,
                "cve":           MAX_CVE,
                "urls":          MAX_URLS
            }
        },
        "iocs": all_iocs
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, default=str)

    print(f"\n{'=' * 60}")
    print(f"  ✓ PHASE 2 COMPLETE")
    print(f"{'=' * 60}")
    print(f"  IP IOCs      : {type_counts.get('ip', 0):>5}")
    print(f"  CVE IOCs     : {type_counts.get('cve', 0):>5}")
    print(f"  URL IOCs     : {type_counts.get('url', 0):>5}")
    print(f"  Domain IOCs  : {type_counts.get('domain', 0):>5}")
    print(f"  ─────────────────────────")
    print(f"  Total IOCs   : {len(all_iocs):>5}")
    print(f"\n  Output → {OUTPUT_FILE}")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    run()