import os
from datetime import datetime, timezone
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from supabase import create_client
from pydantic import BaseModel, Field
from typing import Optional

import repo_scan
import text_scan

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

# ---------------------------------------------------------------------------
# Push alerts (Slack / Teams). Fires after a scan when findings meet the
# severity threshold. Webhook comes from the SLACK_WEBHOOK_URL env var or the
# request body; failures never affect the scan response.
# ---------------------------------------------------------------------------
import alerts
app.include_router(alerts.router)

# ---------------------------------------------------------------------------
# Feedback loop: analyst action vocabulary (lower-cased for matching)
# ---------------------------------------------------------------------------
PATCHED_ACTIONS = ("accept", "accepted", "patch", "patched")
DISMISS_ACTIONS = ("dismiss", "dismissed", "not_applicable", "not-applicable")

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

class RepoScanRequest(BaseModel):
    repo_url: str
    asset_criticality: int = Field(10, ge=1, le=10)
    include_llm: bool = True
    include_rag: bool = True
    notify: bool = True  # fire a Slack/Teams alert when the scan crosses the threshold
    webhook_url: Optional[str] = None  # demo-friendly: per-request webhook wins over env

class TextScanRequest(BaseModel):
    text: str = Field(..., min_length=3, max_length=200_000)  # pasted manifest / pip freeze / npm ls
    asset_criticality: int = Field(10, ge=1, le=10)
    include_llm: bool = False  # paste mode is the fast demo path — enrichments opt-in
    include_rag: bool = False
    notify: bool = True
    webhook_url: Optional[str] = None

@app.get("/")
def home():
    return {"status": "ok", "service": "vuln-intel-api"}

@app.post("/ask")
def ask_route(payload: AskPayload):
    result = ask(payload.question, payload.asset_criticality)
    # Feedback loop: CVEs the team dismissed are demoted 50% in future
    # rankings. Best-effort by design — /ask must never fail because of the
    # feedback read, so any error here is silently ignored.
    try:
        rows = (sb.table("decisions")
                .select("cve_id,action").limit(500).execute().data) or []
        dismissed = {r.get("cve_id") for r in rows
                     if (r.get("action") or "").lower() in DISMISS_ACTIONS}
        ranked = result.get("ranked_cves") if isinstance(result, dict) else None
        if dismissed and ranked:
            for c in ranked:
                if c.get("cve_id") in dismissed:
                    c["real_risk"] = round((c.get("real_risk") or 0) * 0.5, 4)
                    c["demoted_by_feedback"] = True
            ranked.sort(key=lambda c: -(c.get("real_risk") or 0))
            result["feedback_applied"] = True
    except Exception:
        pass
    return result

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

@app.get("/decisions")
def list_decisions(limit: int = 50):
    """Read-side of the feedback loop: latest analyst decisions first."""
    try:
        rows = (sb.table("decisions")
                .select("id,cve_id,asset_id,action,created_at")
                .order("created_at", desc=True)
                .limit(min(limit, 200))
                .execute().data) or []
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"decisions read failed: {e}")
    return rows

@app.get("/insights")
def insights():
    """Feedback signal: what the team accepted (patched) vs dismissed."""
    try:
        rows = (sb.table("decisions")
                .select("cve_id,action,created_at")
                .order("created_at", desc=True)
                .limit(500)
                .execute().data) or []
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"insights read failed: {e}")

    patched = [r.get("cve_id") for r in rows
               if (r.get("action") or "").lower() in PATCHED_ACTIONS]
    dismissed = [r.get("cve_id") for r in rows
                 if (r.get("action") or "").lower() in DISMISS_ACTIONS]
    return {
        "patched": patched,
        "dismissed": dismissed,
        "patched_count": len(patched),
        "dismissed_count": len(dismissed),
        "total_decisions": len(rows),
        "note": "dismissed CVEs are demoted 50% in future /ask rankings",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

@app.get("/dashboard")
def dashboard():
    assets = sb.table("assets").select("id", count="exact").execute().count or 0
    return {"total_assets": assets, "note": "add CVE stats here as data grows"}

@app.post("/scan-repo")
def scan_repo_route(body: RepoScanRequest):
    try:
        result = repo_scan.scan_repo(
            repo_url=body.repo_url,
            asset_criticality=body.asset_criticality,
            include_llm=body.include_llm,
            include_rag=body.include_rag,
        )
    except ValueError as exc:
        return {"error": str(exc)}
    except Exception as exc:
        return {"error": f"scan failed: {exc}"}
    # Push alert after a successful scan — best effort, never fails the scan.
    if isinstance(result, dict) and not result.get("error") and body.notify:
        try:
            alerts.maybe_alert(result, repo_url=body.repo_url, webhook_url=body.webhook_url)
        except Exception:
            pass
    return result

@app.get("/scan-repo")
def scan_repo_get(repo_url: str, asset_criticality: int = 10):
    return scan_repo_route(RepoScanRequest(repo_url=repo_url, asset_criticality=asset_criticality))

@app.post("/scan-text")
def scan_text_route(body: TextScanRequest):
    """Scan a pasted dependency list (requirements.txt / pip freeze / package.json /
    npm ls --json). Same pipeline and result shape as /scan-repo — no repo needed."""
    result = text_scan.scan_text(
        text=body.text,
        asset_criticality=body.asset_criticality,
        include_llm=body.include_llm,
        include_rag=body.include_rag,
    )
    # Push alert after a successful paste scan — best effort, never fails the scan.
    if isinstance(result, dict) and not result.get("error") and body.notify:
        try:
            alerts.maybe_alert(result, repo_url=result.get("repo") or "pasted input",
                               webhook_url=body.webhook_url)
        except Exception:
            pass
    return result
