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

@app.get("/dashboard")
def dashboard():
    assets = sb.table("assets").select("id", count="exact").execute().count or 0
    return {"total_assets": assets, "note": "add CVE stats here as data grows"}
