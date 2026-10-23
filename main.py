import os
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from supabase import create_client
from pydantic import BaseModel
from typing import Optional

load_dotenv()
sb = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_KEY"])

app = FastAPI(title="Vuln Intel API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # change to the Vercel URL later
    allow_methods=["*"],
    allow_headers=["*"],
)

from rag import ask

class Asset(BaseModel):
    name: str
    type: str
    criticality: int
    exposure: str = "internal"

class Decision(BaseModel):
    cve_id: str
    asset_id: Optional[str] = None
    action: str

class AskPayload(BaseModel):
    question: str
    asset_criticality: float = 5.0

@app.get("/")
def home():
    return {"status": "ok", "service": "vuln-intel-api"}

@app.post("/ask")
def ask_route(payload: AskPayload):
    return ask(payload.question, payload.asset_criticality)

@app.get("/assets")
def list_assets():
    return sb.table("assets").select("*").execute().data

@app.post("/assets")
def add_asset(asset: Asset):
    return sb.table("assets").insert(asset.model_dump()).execute().data

@app.post("/decisions")
def record_decision(d: Decision):
    return sb.table("decisions").insert({
        "cve_id": d.cve_id,
        "asset_id": d.asset_id,
        "action": d.action,
    }).execute().data
    import repo_scan
from pydantic import BaseModel, Field

class RepoScanRequest(BaseModel):
    repo_url: str
    asset_criticality: int = Field(10, ge=1, le=10)
    include_llm: bool = True
    include_rag: bool = True

@app.post("/scan-repo")
def scan_repo_route(body: RepoScanRequest):
    try:
        return repo_scan.scan_repo(
            repo_url=body.repo_url,
            asset_criticality=body.asset_criticality,
            include_llm=body.include_llm,
            include_rag=body.include_rag,
        )
    except ValueError as exc:
        return {"error": str(exc)}
    except Exception as exc:
        return {"error": f"scan failed: {exc}"}

@app.get("/scan-repo")
def scan_repo_get(repo_url: str, asset_criticality: int = 10):
    return scan_repo_route(RepoScanRequest(repo_url=repo_url, asset_criticality=asset_criticality))

@app.get("/dashboard")
def dashboard():
    assets = sb.table("assets").select("id", count="exact").execute().count or 0
    return {"total_assets": assets, "note": "add CVE stats here as data grows"}
