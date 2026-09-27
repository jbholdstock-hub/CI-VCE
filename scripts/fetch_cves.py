import os
import json
import time
import requests
from datetime import datetime, timezone, timedelta

NIST_API_KEY = os.environ.get("NIST_API_KEY", "")
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NIST_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Broadened keyword queries
KEYWORDS = [
    ("Windows", "Windows Server"),
    ("Windows Server", "Windows Server"),
    ("Windows 11", "Windows Desktop"),
    ("Windows 10", "Windows Desktop"),
    ("Fortinet", "Fortinet"),
    ("FortiOS", "Fortinet"),
    ("FortiGate", "Fortinet"),
    ("SonicWall", "SonicWall"),
    ("SonicOS", "SonicWall"),
    ("Cisco Meraki", "Cisco Meraki")
]

# Explicit watchlist for critical zero-days that may lag in broad keyword searches
CRITICAL_WATCHLIST = [
    ("CVE-2026-81963", "Windows Server", "Windows Update Stack EoP Zero-Day"),
    ("CVE-2026-69730", "Fortinet", "FortiOS SSL-VPN Memory Corruption RCE"),
    ("CVE-2026-69525", "SonicWall", "SonicWall SonicOS / SMA Authentication Bypass"),
    ("CVE-2026-72979", "Windows Server", "Windows Remote Access Connection Manager EoP")
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

def extract_cvss(metrics):
    """Extract CVSS from NIST or fallback to Vendor/CNA metrics if awaiting analysis."""
    for key in ["cvssMetricV31", "cvssMetricV30"]:
        if key in metrics and len(metrics[key]) > 0:
            return metrics[key][0].get("cvssData")
    # If NIST has not analyzed it yet, check CNA / vendor score
    if "cvssMetricV31_cna" in metrics and len(metrics["cvssMetricV31_cna"]) > 0:
        return metrics["cvssMetricV31_cna"][0].get("cvssData")
    return None

def fetch_single_cve(cve_id, default_platform, default_title, cisa_kevs):
    """Direct lookup for specific high-priority CVE IDs."""
    headers = {"apiKey": NIST_API_KEY} if NIST_API_KEY else {}
    params = {"cveId": cve_id}
    try:
        res = requests.get(NIST_API_URL, headers=headers, params=params, timeout=20)
        if res.status_code == 200:
            data = res.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                cve = vulns[0].get("cve", {})
                metrics = cve.get("metrics", {})
                cvss_data = extract_cvss(metrics)
                
                score = cvss_data.get("baseScore", 8.0) if cvss_data else 8.0
                desc = "No description provided."
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value")
                        break
                        
                return {
                    "id": cve_id,
                    "platform": default_platform,
                    "title": default_title,
                    "score": score,
                    "severity": cvss_data.get("baseSeverity", "HIGH") if cvss_data else "HIGH",
                    "vector": cvss_data.get("attackVector", "NETWORK") if cvss_data else "NETWORK",
                    "published": cve.get("published", "")[:10] or "2026-09-08",
                    "cisaKev": cve_id in cisa_kevs,
                    "description": desc,
                    "source": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                }
    except Exception as e:
        print(f"Error fetching single CVE {cve_id}: {e}")
    return None

def fetch_cves_for_keyword(keyword, platform, cisa_kevs):
    headers = {"apiKey": NIST_API_KEY} if NIST_API_KEY else {}
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
                cvss_data = extract_cvss(metrics)
                
                # If no score yet, default to 7.5 if actively in CISA KEV
                score = cvss_data.get("baseScore", 0.0) if cvss_data else (7.5 if cve_id in cisa_kevs else 0.0)
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
                    "severity": cvss_data.get("baseSeverity", "HIGH") if cvss_data else "HIGH",
                    "vector": cvss_data.get("attackVector", "NETWORK") if cvss_data else "NETWORK",
                    "published": cve.get("published", "")[:10],
                    "cisaKev": cve_id in cisa_kevs,
                    "description": desc,
                    "source": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                })
    except Exception as e:
        print(f"Error querying NIST for {keyword}: {e}")
        
    return records

def main():
    print("Starting automated vulnerability ingestion...")
    cisa_kevs = get_cisa_kevs()
    all_cves = {}
    
    # 1. Fetch targeted high-priority watchlist CVEs directly
    for cve_id, plat, title in CRITICAL_WATCHLIST:
        print(f"Checking watchlist entry {cve_id}...")
        item = fetch_single_cve(cve_id, plat, title, cisa_kevs)
        if item:
            all_cves[cve_id] = item
        time.sleep(1)

    # 2. Ingest relevant CISA KEV entries directly
    for cve_id, kev_item in cisa_kevs.items():
        desc = kev_item.get("shortDescription", "")
        vendor = kev_item.get("vendorProject", "").lower()
        product = kev_item.get("product", "").lower()
        
        target_platform = None
        if "microsoft" in vendor or "windows" in product:
            target_platform = "Windows Server" if "server" in product else "Windows Desktop"
        elif "fortinet" in vendor:
            target_platform = "Fortinet"
        elif "sonicwall" in vendor:
            target_platform = "SonicWall"
        elif "meraki" in vendor or "cisco" in vendor:
            target_platform = "Cisco Meraki"
            
        if target_platform and cve_id not in all_cves:
            all_cves[cve_id] = {
                "id": cve_id,
                "platform": target_platform,
                "title": f"{kev_item.get('vulnerabilityName', 'Zero-Day Exploit')}",
                "score": 8.0,
                "severity": "HIGH",
                "vector": "LOCAL" if "privilege" in desc.lower() else "NETWORK",
                "published": kev_item.get("dateAdded", "")[:10],
                "cisaKev": True,
                "description": desc,
                "source": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            }

    # 3. Ingest broad keyword queries from NIST NVD
    for kw, plat in KEYWORDS:
        print(f"Fetching updates for {kw}...")
        results = fetch_cves_for_keyword(kw, plat, cisa_kevs)
        for r in results:
            all_cves[r["id"]] = r
        time.sleep(2)

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
        
    print(f"Successfully wrote {len(all_cves)} high/critical CVEs to {out_file}")

if __name__ == "__main__":
    main()
