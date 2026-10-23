#!/usr/bin/env python3
"""
scan_server.py -- standalone REST API for the VulnIntel repo scanner.

Deploy this as its own Render service (zero risk to your production
vuln-intel-api-dev2.onrender.com), or copy the two routes below into your
existing FastAPI app (see app_integration_snippet.py).

Endpoints
---------
GET  /health      -> {"status": "ok"}
POST /scan-repo   body {"repo_url": "...", "asset_criticality": 1-10,
                        "include_llm": true, "include_rag": true}
GET  /scan-repo?repo_url=...&asset_criticality=10
                  -> same scan, browser-friendly (demo-day convenience)

Run locally:
    pip install -r requirements-scanner.txt
    python scan_server.py            # serves on $PORT or 8000
"""

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional

import repo_scan

app = FastAPI(title="VulnIntel Repo Scanner", version="1.0.0")

# Wide-open CORS so the frontend teammate can call this directly from the UI.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    repo_url: str = Field(..., examples=["https://github.com/OWASP/NodeGoat"])
    asset_criticality: int = Field(10, ge=1, le=10)
    include_llm: bool = True
    include_rag: bool = True


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "vulnintel-repo-scanner",
        "formula": repo_scan.RISK_FORMULA,
        "advisory_model": repo_scan.GROQ_MODEL,
        "keys_loaded": {
            "gemini": bool(repo_scan.GEMINI_API_KEY),
            "groq": bool(repo_scan.GROQ_API_KEY),
            "supabase": bool(repo_scan.SUPABASE_URL and repo_scan.SUPABASE_KEY),
            "github_token": bool(repo_scan.GITHUB_TOKEN),
        },
    }


def _run_scan(repo_url: str, asset_criticality: int, include_llm: bool, include_rag: bool):
    try:
        return repo_scan.scan_repo(
            repo_url=repo_url,
            asset_criticality=asset_criticality,
            include_llm=include_llm,
            include_rag=include_rag,
        )
    except ValueError as exc:          # bad URL / private repo / not found
        return {"error": str(exc)}
    except Exception as exc:           # noqa: BLE001 - keep the API alive
        return {"error": f"scan failed: {exc}"}


@app.post("/scan-repo")
def scan_repo_post(body: ScanRequest):
    return _run_scan(body.repo_url, body.asset_criticality,
                     body.include_llm, body.include_rag)


@app.get("/scan-repo")
def scan_repo_get(repo_url: str, asset_criticality: int = 10,
                  include_llm: bool = True, include_rag: bool = True):
    """GET variant so judges can trigger a scan straight from the browser."""
    return _run_scan(repo_url, max(1, min(10, asset_criticality)),
                     include_llm, include_rag)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
