import os
import json
import time
import requests
from datetime import datetime, timezone, timedelta

NIST_API_KEY = os.environ.get("NIST_API_KEY", "")
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NIST_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

KEYWORDS = [
    ("Windows Server", "Windows Server"),
    ("Windows 10", "Windows Desktop"),
    ("Windows 11", "Windows Desktop"),
    ("FortiOS", "Fortinet"),
    ("FortiManager", "Fortinet"),
    ("SonicWall", "SonicWall"),
    ("SonicOS", "SonicWall"),
    ("Cisco Meraki", "Cisco Meraki")
]

def get_cisa_kevs():
    try:
        res = requests.get(CISA_KEV_URL, timeout=15)
        if res.status_code == 200:
            data = res.json()
            return {item["cveID"]: item for item in data.get("vulnerabilities", [])}
    except Exception as e:
        print(f"Warning: Failed to fetch CISA KEV: {e}")
    return {}

def fetch_cves_for_keyword(keyword, platform, cisa_kevs):
    headers = {"apiKey": NIST_API_KEY} if NIST_API_KEY else {}
    
    # Query updates from the last 120 days
    now = datetime.now(timezone.utc)
    start_date = (now - timedelta(days=120)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end_date = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    
    params = {
        "keywordSearch": keyword,
        "lastModStartDate": start_date,
        "lastModEndDate": end_date,
        "resultsPerPage": 40
    }
    
    records = []
    try:
        res = requests.get(NIST_API_URL, headers=headers, params=params, timeout=25)
        if res.status_code == 200:
            data = res.json()
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                
                metrics = cve.get("metrics", {})
                cvss_data = None
                if "cvssMetricV31" in metrics:
                    cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                elif "cvssMetricV30" in metrics:
                    cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                
                if not cvss_data:
                    continue
                
                score = cvss_data.get("baseScore", 0.0)
                if score < 7.0:
                    continue
                
                desc = "No description provided."
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value")
                        break

                records.append({
                    "id": cve_id,
                    "platform": platform,
                    "title": f"{keyword} Vulnerability ({cve_id})",
                    "score": score,
                    "severity": cvss_data.get("baseSeverity", "HIGH"),
                    "vector": cvss_data.get("attackVector", "NETWORK"),
                    "published": cve.get("published", "")[:10],
                    "cisaKev": cve_id in cisa_kevs,
                    "description": desc,
                    "source": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                })
        else:
            print(f"NIST API status {res.status_code} for {keyword}")
    except Exception as e:
        print(f"Error querying NIST for {keyword}: {e}")
        
    return records

def main():
    print("Starting automated vulnerability ingestion...")
    cisa_kevs = get_cisa_kevs()
    all_cves = {}
    
    for kw, plat in KEYWORDS:
        print(f"Fetching updates for {kw}...")
        results = fetch_cves_for_keyword(kw, plat, cisa_kevs)
        for r in results:
            all_cves[r["id"]] = r
        time.sleep(2)  # Respect rate limits

    output_dir = "data"
    os.makedirs(output_dir, exist_ok=True)
    out_file = os.path.join(output_dir, "cves.json")
    
    payload = {
        "lastUpdated": datetime.now(timezone.utc).isoformat(),
        "total": len(all_cves),
        "vulnerabilities": sorted(list(all_cves.values()), key=lambda x: x["score"], reverse=True)
    }
    
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        
    print(f"Successfully wrote {len(all_cves)} CVEs to {out_file}")

if __name__ == "__main__":
    main()
