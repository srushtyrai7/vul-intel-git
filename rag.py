import os
import json
import requests
from dotenv import load_dotenv
from supabase import create_client
from langchain_google_genai import GoogleGenerativeAIEmbeddings
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

load_dotenv()

sb = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_KEY"])
embedder = GoogleGenerativeAIEmbeddings(model="models/gemini-embedding-001", output_dimensionality=768)
llm = ChatGroq(model="openai/gpt-oss-120b", temperature=0)

prompt = ChatPromptTemplate.from_messages([
    ("system",
     "You are a vulnerability intelligence assistant. You will be given a question and "
     "relevant CVE descriptions. Answer clearly and practically, prioritizing by severity "
     "and relevance. Be concise."),
    ("human", "Question: {question}\n\nRelevant CVEs:\n{context}"),
])

chain = prompt | llm | StrOutputParser()


def get_epss(cve_id):
    try:
        r = requests.get("https://api.first.org/data/v1/epss", params={"cve": cve_id}, timeout=15)
        r.raise_for_status()
        data = r.json().get("data", [])
        return float(data[0]["epss"]) if data else 0.0
    except Exception:
        return 0.0


def ask(question, asset_criticality=5):
    vec = embedder.embed_query(question)

    result = sb.rpc("match_cves", {
        "query_embedding": vec,
        "match_count": 5,
    }).execute()

    matches = result.data or []

    ranked = []
    for m in matches:
        meta = m.get("metadata") or {}
        cve_id = meta.get("cve_id", "unknown")
        cvss = meta.get("cvss") or 0.0
        epss = get_epss(cve_id)
        real_risk = round(float(cvss) * epss * (asset_criticality / 10.0), 2)
        ranked.append({
            "cve_id": cve_id,
            "description": m.get("content", ""),
            "similarity": round(m.get("similarity", 0.0), 4),
            "cvss": cvss,
            "epss": epss,
            "real_risk": real_risk,
        })

    ranked.sort(key=lambda x: x["real_risk"], reverse=True)

    context = "\n\n".join(
        f"{c['cve_id']} (CVSS {c['cvss']}, EPSS {c['epss']}): {c['description']}"
        for c in ranked
    )

    answer = chain.invoke({"question": question, "context": context})

    return {"answer": answer, "ranked_cves": ranked}


if __name__ == "__main__":
    out = ask("What vulnerabilities should I worry about on my web server?", 8)
    print(json.dumps(out, indent=2))
