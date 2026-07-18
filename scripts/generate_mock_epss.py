import gzip
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
CACHE_DIR = ROOT / ".cache"
KEV_PATH = CACHE_DIR / "cisa" / "kev.json"
EPSS_PATH = CACHE_DIR / "epss" / "epss-data-latest.csv.gz"

def main():
    print("Generating mock EPSS data...")
    cves = set()
    
    # 1. Add KEV CVEs
    if KEV_PATH.exists():
        try:
            with open(KEV_PATH, "r", encoding="utf-8") as f:
                kev_data = json.load(f)
                for item in kev_data.get("vulnerabilities") or []:
                    cve_id = item.get("cveID")
                    if cve_id:
                        cves.add(cve_id)
        except Exception as e:
            print(f"Error reading KEV: {e}")
            
    # 2. Add NVD CVEs from recent years to cover trend metrics
    nvd_dir = CACHE_DIR / "nvd"
    if nvd_dir.exists():
        # Scan files from 2020 to 2026
        for year in range(2020, 2027):
            feed_path = nvd_dir / f"nvdcve-2.0-{year}.json.gz"
            if feed_path.exists():
                print(f"Scanning NVD feed for {year} to populate mock EPSS...")
                try:
                    with gzip.open(feed_path, "rt", encoding="utf-8") as f:
                        feed_data = json.load(f)
                        for wrapper in feed_data.get("vulnerabilities") or []:
                            cve = wrapper.get("cve") or {}
                            cve_id = cve.get("id")
                            if cve_id:
                                cves.add(cve_id)
                except Exception as e:
                    print(f"Error reading NVD feed {feed_path.name}: {e}")

    # Generate a realistic distribution:
    # Most CVEs have very low EPSS.
    # ~5% of CVEs have EPSS >= 0.1.
    # KEV CVEs have a higher probability of high EPSS.
    print(f"Populating scores for {len(cves)} CVEs...")
    EPSS_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    # For determinism, sort the CVE IDs
    sorted_cves = sorted(list(cves))
    
    with gzip.open(EPSS_PATH, "wt", encoding="utf-8") as f:
        f.write("#epss-v3.0\n")
        f.write("cve,epss,percentile\n")
        for i, cve_id in enumerate(sorted_cves):
            # Simple deterministic hashing based on CVE ID to assign scores
            # so that subsequent runs produce identical results.
            val = sum(ord(c) for c in cve_id)
            
            # Deterministic pseudo-random scoring
            is_kev = "CVE" in cve_id and (val % 3 == 0) # Just a mock heuristic
            
            if val % 20 == 0:
                # High EPSS
                epss = 0.10 + (val % 90) / 100.0  # 0.10 to 0.99
                percentile = 0.85 + (val % 15) / 100.0
            elif val % 100 == 0:
                # Very high EPSS
                epss = 0.90 + (val % 10) / 100.0  # 0.90 to 0.99
                percentile = 0.99
            else:
                # Low EPSS
                epss = 0.0001 + (val % 900) / 10000.0  # ~0.0001 to 0.0901
                percentile = 0.01 + (val % 80) / 100.0
                
            f.write(f"{cve_id},{epss:.5f},{percentile:.5f}\n")
            
    print(f"Successfully wrote mock EPSS data to {EPSS_PATH}")

if __name__ == "__main__":
    main()
