import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

def load_all_data():
    cicids_dir = BASE_DIR / "data" / "public_dataset" / "cicids"

    attacks = pd.concat(
        [pd.read_csv(file) for file in cicids_dir.glob("*.csv")],
        ignore_index=True
    )

    urlhaus_columns = [
        "id",
        "date_added",
        "url",
        "url_status",
        "threat",
        "tags",
        "urlhaus_link",
        "reporter",
        "extra"
    ]

    osint = pd.read_csv(
        BASE_DIR / "data" / "osint" / "urlhaus.abuse.ch.csv",
        comment="#",
        header=None,
        names=urlhaus_columns
    )

    cves = pd.read_csv(
        BASE_DIR / "data" / "threat_intel" / "cve_cisa_epss_enriched_dataset.csv"
    )

    assets = pd.read_csv(
        BASE_DIR / "data" / "assets.csv"
    )

    return attacks, osint, cves, assets


if __name__ == "__main__":
    attacks, osint, cves, assets = load_all_data()

    print("CICIDS:", attacks.shape)
    print(attacks.head())

    print("OSINT:", osint.shape)
    print(osint.head())

    print("CVES:", cves.shape)
    print(cves.head())

    print("ASSETS:", assets.shape)
    print(assets.head())