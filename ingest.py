import os, time, requests
from dotenv import load_dotenv
from supabase import create_client
from langchain_google_genai import GoogleGenerativeAIEmbeddings

load_dotenv()
sb = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_KEY"])
embedder = GoogleGenerativeAIEmbeddings(model="models/gemini-embedding-001", output_dimensionality=768)

def fetch_cves(limit=100):
    from datetime import datetime, timedelta, timezone
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=60)
    r = requests.get(url, params={
        "resultsPerPage": limit,
        "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT23:59:59.999"),
    }, timeout=60)
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

def main():
    cves = fetch_cves(100)
    print("Fetched", len(cves), "CVEs. Starting embeddings...")
    for i, c in enumerate(cves, 1):
        text = c["cve_id"] + ": " + c["description"]
        vec = embedder.embed_query(text)
        sb.table("cve_vectors").insert({
            "content": text,
            "embedding": vec,
            "metadata": {"cve_id": c["cve_id"], "cvss": c["cvss"], "published": c["published"]},
        }).execute()
        print(i, "inserted:", c["cve_id"])
        time.sleep(0.3)
    print("DONE. Inserted", len(cves), "CVEs")

if __name__ == "__main__":
    main()
