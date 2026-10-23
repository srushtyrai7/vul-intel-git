import requests, json

def fetch_cves(limit=100):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    r = requests.get(url, params={"resultsPerPage": limit}, timeout=30)
    r.raise_for_status()
    out = []
    for item in r.json().get("vulnerabilities", []):
        c = item["cve"]
        desc = next((d["value"] for d in c["descriptions"] if d["lang"] == "en"), "")
        metrics = c.get("metrics", {})
        m = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
        score = m[0]["cvssData"].get("baseScore") if m else None
        out.append({"cve_id": c["id"], "description": desc, "cvss": score, "published": c["published"]})
    return out

if __name__ == "__main__":
    data = fetch_cves(100)
    with open("cves.json", "w") as f:
        json.dump(data, f, indent=2)
    print("Saved", len(data), "CVEs to cves.json")
