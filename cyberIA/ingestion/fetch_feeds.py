"""
=======================================================
PHASE 1 — DATA INGESTION & FILTERING
=======================================================
Input  : data/public_dataset/cicids/*.csv
         data/threat_intel/cve_cisa_epss_enriched_dataset.csv
         data/threat_intel/cve_corpus.csv
         data/osint/urlhaus.abuse.ch.csv

Output : data/phase1_output.json   ← input for Phase 2

How to test:
    cd cyberIA
    python ingestion/fetch_feeds.py

No API keys. No internet. Pure local filtering.
=======================================================
"""

import os
import json
import pandas as pd
from datetime import datetime

# ── Paths ──────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CICIDS_DIR  = os.path.join(BASE_DIR, "data", "public_dataset", "cicids")
THREAT_DIR  = os.path.join(BASE_DIR, "data", "threat_intel")
OSINT_DIR   = os.path.join(BASE_DIR, "data", "osint")
OUTPUT_FILE = os.path.join(BASE_DIR, "data", "phase1_output.json")

# ── CICIDS columns we actually need ───────────────────
CICIDS_KEEP = [
    " Source IP", " Destination IP", " Source Port",
    " Destination Port", " Protocol", " Label",
    " Flow Duration", " Total Fwd Packets", " Total Backward Packets",
    " Flow Bytes/s", " Flow Packets/s", " Flow IAT Mean",
    " Fwd PSH Flags", " Bwd PSH Flags",
    " SYN Flag Count", " RST Flag Count", " ACK Flag Count",
]

# Attack label keywords to keep (filter out BENIGN-only rows in big files)
ATTACK_LABELS = [
    "DDoS", "PortScan", "Bot", "Infiltration",
    "Web Attack", "DoS", "Heartbleed", "FTP-Patator",
    "SSH-Patator", "BENIGN"          # keep BENIGN too for anomaly contrast
]

# ── CVE columns we need ────────────────────────────────
CVE_KEEP = ["cve_id", "cvss_score", "severity", "description",
            "epss_score", "cwe_id"]

# ── URLhaus columns ────────────────────────────────────
URLHAUS_KEEP = ["url", "url_status", "threat", "tags", "urlhaus_link"]


# ═══════════════════════════════════════════════════════
# LOADER 1 — CICIDS network traffic
# ═══════════════════════════════════════════════════════

# Columns we want — matched after stripping spaces
ESSENTIAL_COLS = [
    "Source IP", "Destination IP", "Source Port",
    "Destination Port", "Protocol", "Label"
]

def load_cicids():
    print("\n[1/3] Loading CICIDS dataset...")

    if not os.path.isdir(CICIDS_DIR):
        print(f"      ERR Folder not found: {CICIDS_DIR}")
        return []

    csv_files = [f for f in os.listdir(CICIDS_DIR) if f.endswith(".csv")]
    if not csv_files:
        print("      ERR No CSV files found in cicids/")
        return []

    records = []
    for fname in csv_files:
        fpath = os.path.join(CICIDS_DIR, fname)
        try:
            df = pd.read_csv(fpath, low_memory=False)

            # Strip ALL column names
            df.columns = df.columns.str.strip()

            # Find which essential columns actually exist (case-insensitive)
            col_map = {c.lower(): c for c in df.columns}
            cols_to_keep = [
                col_map[want.lower()]
                for want in ESSENTIAL_COLS
                if want.lower() in col_map
            ]

            if not cols_to_keep:
                print(f"      ERR {fname} — no matching columns found")
                print(f"         Available: {list(df.columns[:8])}...")
                continue

            df = df[cols_to_keep]

            # Find the Label column (whatever it's called after stripping)
            label_col = next((c for c in df.columns if c.lower() == "label"), None)

            if label_col:
                # Prefer attack rows, add up to 50 BENIGN for contrast
                attacks = df[df[label_col].str.strip() != "BENIGN"].head(100)
                benign  = df[df[label_col].str.strip() == "BENIGN"].head(50)
                df = pd.concat([attacks, benign], ignore_index=True)
            else:
                df = df.head(150)

            df = df.dropna(how="all")
            df["source_file"] = fname
            df["data_source"] = "CICIDS2017"
            df["record_type"] = "network_flow"

            chunk = df.to_dict(orient="records")
            records.extend(chunk)

            label_counts = df[label_col].value_counts().to_dict() if label_col else {}
            print(f"      OK {fname:<55} -> {len(chunk):>4} rows | {label_counts}")

        except Exception as e:
            print(f"      ERR Error reading {fname}: {e}")

    print(f"\n      Total CICIDS records : {len(records)}")
    return records


# ═══════════════════════════════════════════════════════
# LOADER 2 — CVE / threat intelligence
# ═══════════════════════════════════════════════════════
def load_cve():
    print("\n[2/3] Loading CVE / threat intel dataset...")
    records = []

    files = {
        "cve_cisa_epss_enriched_dataset.csv": CVE_KEEP,
        "cve_corpus.csv":                     None        # keep all cols
    }

    for fname, keep_cols in files.items():
        fpath = os.path.join(THREAT_DIR, fname)
        if not os.path.exists(fpath):
            print(f"      ERR Not found: {fname}")
            continue

        try:
            df = pd.read_csv(fpath, low_memory=False)
            df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_")

            if keep_cols:
                available = [c for c in keep_cols if c in df.columns]
                df = df[available]

            # Filter: only HIGH / CRITICAL severity if column exists
            if "severity" in df.columns:
                df = df[df["severity"].str.strip().str.upper().isin(
                    ["HIGH", "CRITICAL", "MEDIUM"]
                )]

            # Drop rows missing cve_id
            if "cve_id" in df.columns:
                df = df.dropna(subset=["cve_id"])

            df = df.dropna(how="all")
            df["source_file"]  = fname
            df["data_source"]  = "CVE_INTEL"
            df["record_type"]  = "vulnerability"

            chunk = df.to_dict(orient="records")
            records.extend(chunk)
            print(f"      OK {fname:<55} -> {len(chunk):>5} rows")

        except Exception as e:
            print(f"      ERR Error reading {fname}: {e}")

    print(f"\n      Total CVE records : {len(records)}")
    return records


# ═══════════════════════════════════════════════════════
# LOADER 3 — URLhaus OSINT feed
# ═══════════════════════════════════════════════════════
def load_urlhaus():
    print("\n[3/3] Loading URLhaus OSINT feed...")
    records = []

    fpath = os.path.join(OSINT_DIR, "urlhaus.abuse.ch.csv")
    if not os.path.exists(fpath):
        print(f"      ERR Not found: {fpath}")
        return []

    try:
        # URLhaus CSV has comment lines starting with #
        df = pd.read_csv(fpath, comment="#", low_memory=False)
        df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_")

        available = [c for c in URLHAUS_KEEP if c in df.columns]
        df = df[available] if available else df

        # Keep only online/active malicious URLs
        if "url_status" in df.columns:
            df = df[df["url_status"].str.strip().str.lower().isin(["online", "unknown"])]

        df = df.dropna(how="all")
        df["source_file"]  = "urlhaus.abuse.ch.csv"
        df["data_source"]  = "URLhaus_OSINT"
        df["record_type"]  = "malicious_url"

        chunk = df.to_dict(orient="records")
        records.extend(chunk)
        print(f"      OK urlhaus.abuse.ch.csv -> {len(chunk)} rows")

    except Exception as e:
        print(f"      ✗ Error reading URLhaus: {e}")

    print(f"\n      Total URLhaus records : {len(records)}")
    return records


# ═══════════════════════════════════════════════════════
# MAIN — combine all sources → one output file
# ═══════════════════════════════════════════════════════
def run():
    print("=" * 60)
    print("  PHASE 1 — DATA INGESTION & FILTERING")
    print("=" * 60)

    cicids   = load_cicids()
    cve      = load_cve()
    urlhaus  = load_urlhaus()

    # Combine all into a single structured output
    output = {
        "metadata": {
            "generated_at":  datetime.now().isoformat(),
            "phase":         "1 - Data Ingestion & Filtering",
            "total_records": len(cicids) + len(cve) + len(urlhaus),
            "sources": {
                "cicids_network_flows": len(cicids),
                "cve_vulnerabilities":  len(cve),
                "urlhaus_osint":        len(urlhaus)
            }
        },
        "network_flows":   cicids,
        "vulnerabilities": cve,
        "malicious_urls":  urlhaus
    }

    # Save
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, default=str)

    # ── Summary ──────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"  OK PHASE 1 COMPLETE")
    print(f"{'=' * 60}")
    print(f"  Network flows (CICIDS) : {len(cicids):>6}")
    print(f"  Vulnerabilities (CVE)  : {len(cve):>6}")
    print(f"  Malicious URLs         : {len(urlhaus):>6}")
    print(f"  ─────────────────────────────")
    print(f"  Total records          : {len(cicids)+len(cve)+len(urlhaus):>6}")
    print(f"\n  Output → {OUTPUT_FILE}")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    run()