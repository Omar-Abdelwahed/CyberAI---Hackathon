import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ingestion.load_data import load_all_data


def filter_attack_vectors():
    attacks, osint, cves, assets = load_all_data()

    # 1) CICIDS : attaques proches de phishing, lateral movement, exfiltration
    keep_labels = [
        "Web Attack",
        "Infiltration",
        "Bot",
        "PortScan",
        "FTP-Patator",
        "SSH-Patator"
    ]

    label_col = " Label"

    cicids_filtered = attacks[
        attacks[label_col].astype(str).str.contains(
            "|".join(keep_labels),
            case=False,
            na=False
        )
    ]

    # 2) URLhaus : IOC utiles pour phishing / malware / C2
    osint_filtered = osint[
        osint["url"].astype(str).str.contains(
            "login|phish|payload|c2|malware|bank|secure|account",
            case=False,
            na=False
        )
    ]

    # 3) CVE : on garde HIGH/CRITICAL pour plus tard
    cves_filtered = cves[
        cves["base_severity"].astype(str).str.upper().isin(["HIGH", "CRITICAL"])
    ]

    return cicids_filtered, osint_filtered, cves_filtered


if __name__ == "__main__":
    cicids_filtered, osint_filtered, cves_filtered = filter_attack_vectors()

    print("CICIDS filtered:", cicids_filtered.shape)
    print(cicids_filtered[" Label"].value_counts())

    print("OSINT filtered:", osint_filtered.shape)
    print(osint_filtered.head())

    print("CVEs filtered:", cves_filtered.shape)
    print(cves_filtered[["cve_id", "base_severity", "base_score"]].head())

    # ---------------- SAVE FILTERED DATASETS ----------------

    import os

    os.makedirs("data/processed", exist_ok=True)

    cicids_filtered.to_csv(
        "data/processed/cicids_filtered.csv",
        index=False
    )

    osint_filtered.to_csv(
        "data/processed/osint_filtered.csv",
        index=False
    )

    cves_filtered.to_csv(
        "data/processed/cves_filtered.csv",
        index=False
    )

    print("Filtered datasets saved.")