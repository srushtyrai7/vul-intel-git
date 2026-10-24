"""VulnIntel self-learning engine — adapted from the TRIAD design.

=====================================================================
WHAT CHANGED vs the original TRIAD file (for the teammate, plain list)
=====================================================================
1. REMOVED  `import events`            -> VulnIntel has no realtime bus.
                                        Event emission is now a log line.
2. REMOVED  `from db import supabase`  -> VulnIntel has no db.py. This module
                                        builds its own Supabase client from
                                        SUPABASE_URL + SUPABASE_SERVICE_KEY
                                        (the same env vars main.py uses).
3. NEW TABLES: writes go to `learning_decisions` and `learning_state`
   (NOT the existing `decisions` table — that one belongs to the
   dashboard feedback loop with columns cve_id/asset_id/action and must
   never be touched by this engine).
4. Real Risk scale: VulnIntel computes Real Risk = CVSS x EPSS x
   criticality/10, which lands in the 0-10 range (top demo finding ~4.8).
   The original TRIAD threshold was 25 on a 0-100 scale -> the equivalent
   here is 2.5. Override with env var LEARN_DEFER_THRESHOLD if needed.
5. Column name: `unified_score` -> `real_risk` (clean semantics, new
   table, no legacy constraint).
6. Reset filter: original used .gt("id", 0) which fails on uuid primary
   keys -> now .gt("created_at", epoch) which works for uuid tables.
7. HTTP contract FROZEN, byte-identical to the original:
     POST /api/decisions        record a decision, learn, return adjustment
     GET  /api/learning/state   per-asset-class learned adjustments
     GET  /api/learning/recent  last N decisions (audit trail)
     POST /api/learning/reset   wipe all learning (demo replay)

=====================================================================
WHAT "SELF-LEARNING" MEANS HERE (plain terms)
=====================================================================
The platform watches how the team treats vulnerabilities over time and
quietly adapts its guidance, per asset class:

  * Team DEFERS a HIGH-risk bug (Real Risk >= threshold)  -> advice DOWN (-1.0)
  * Team fast-patches a LOW-risk bug (< threshold)        -> advice UP   (+1.0)
  * An INCIDENT is confirmed on any bug                   -> advice UP   (+1.2)

Each signal feeds an exponential moving average (EMA), clamped to
[-2.0, +2.0], over the last 20 decisions for that asset class.

LEARNING IS GUIDANCE ONLY
=========================
The adjustment NEVER changes a Real Risk score and NEVER re-orders the
ranked queue. Scores come from the scan pipeline alone; learning only
colors the advice around them. (The separate dashboard loop — dismiss -> 50%
demotion in /ask — lives in main.py and is untouched by this file.)
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
from datetime import datetime, timezone
from typing import Literal, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from supabase import create_client

log = logging.getLogger("vulnintel.self-learning")


# =========================================================== tunables =======
# All learning behaviour knobs in one place — tweak here, nothing else moves.
EMA_ALPHA = 0.3               # how fast the platform adapts to each new signal
ADJ_MIN, ADJ_MAX = -2.0, 2.0  # the nudge can never exceed +/- 2.0
# VulnIntel Real Risk is 0-10 (CVSS x EPSS x criticality/10). A defer only
# teaches us something when it happens on a HIGH-risk bug; 2.5 on this scale
# marks the same "top tier" the original 25 marked on a 0-100 scale.
DEFER_THRESHOLD = float(os.environ.get("LEARN_DEFER_THRESHOLD", "2.5"))
DECISION_WINDOW = 20          # how many past decisions the EMA looks at

TABLE_DECISIONS = "learning_decisions"
TABLE_STATE = "learning_state"


def _sb():
    """Own client — same env vars as main.py, no db.py needed."""
    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_SERVICE_KEY") or os.environ.get("SUPABASE_KEY")
    if not url or not key:
        raise HTTPException(status_code=503, detail="Supabase env vars not configured")
    return create_client(url, key)


# ============================================================== engine ======
# Pure math, no I/O — the whole learning brain. Unit-testable in isolation.

def clamp(v: float, lo: float = ADJ_MIN, hi: float = ADJ_MAX) -> float:
    """Keep the adjustment inside its safety bounds."""
    return max(lo, min(hi, v))


def apply_ema(old: float, signal: float, alpha: float = EMA_ALPHA) -> float:
    """One step of exponential moving average, clamped.

    alpha = 1 would jump straight to the signal; the default 0.3 means each
    decision moves the needle ~30% of the way — smooth, forgiving of one-off
    choices, responsive to real trends.
    """
    return clamp(old + alpha * (signal - old))


def signal_from_decision(d: dict) -> float:
    """Translate ONE human decision into learning evidence.

      defer on a HIGH-risk bug (real_risk >= threshold) -> -1.0
      patch_now on a LOW-risk bug (< threshold)         -> +1.0
      incident_confirmed                                -> +1.2 (always)
      anything matching our own advice                  -> 0.0 (teaches nothing)
    """
    if d.get("decision") == "incident_confirmed":
        return 1.2
    if d.get("decision") == "defer" and d.get("real_risk", 0) >= DEFER_THRESHOLD:
        return -1.0
    if d.get("decision") == "patch_now" and d.get("real_risk", 10) < DEFER_THRESHOLD:
        return 1.0
    return 0.0


def compute_adjustment(decisions: list) -> dict:
    """Fold a decision history into one adjustment + a plain explanation.

    Oldest first so the EMA 'ends' on the most recent evidence. Decisions
    without a timestamp keep their given order.
    """
    ds = list(decisions)
    if ds and all(d.get("created_at") for d in ds):
        ds = sorted(ds, key=lambda d: d["created_at"])
    adj = 0.0
    n_defer = n_patch = n_incident = 0
    for d in ds:
        s = signal_from_decision(d)
        if s == -1.0:
            n_defer += 1
        elif s == 1.0:
            n_patch += 1
        elif s == 1.2:
            n_incident += 1
        if s != 0.0:
            adj = apply_ema(adj, s)
    explanation = (
        f"{n_defer} defers(Real Risk>={DEFER_THRESHOLD:g}), "
        f"{n_patch} fast-patches(<{DEFER_THRESHOLD:g}), "
        f"{n_incident} incidents -> adj {round(adj, 2)}"
    )
    return {"adjustment": adj, "explanation": explanation}


# ========================================================== persistence =====
# Supabase reads/writes. Blocking calls — wrap in asyncio.to_thread from
# async contexts (the router below already does this).

def record_decision(d: dict) -> dict:
    """Store one decision, then re-learn that asset class's adjustment.

    d keys: vuln_id, asset_class, decision, real_risk, decided_by,
    reason (optional).
    """
    client = _sb()
    client.table(TABLE_DECISIONS).insert({
        "vuln_id": d["vuln_id"],
        "asset_class": d["asset_class"],
        "decision": d["decision"],
        "real_risk": d["real_risk"],
        "decided_by": d["decided_by"],
        "reason": d.get("reason"),
    }).execute()

    rows = (
        client.table(TABLE_DECISIONS)
        .select("decision, real_risk, created_at")
        .eq("asset_class", d["asset_class"])
        .order("created_at", desc=True)
        .limit(DECISION_WINDOW)
        .execute()
        .data
    ) or []
    rows.reverse()  # oldest first, so the EMA ends on the newest evidence
    result = compute_adjustment(rows)

    client.table(TABLE_STATE).upsert({
        "asset_class": d["asset_class"],
        "adjustment": result["adjustment"],
        "explanation": result["explanation"],
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }).execute()

    return {
        "ok": True,
        "new_adjustment": result["adjustment"],
        "explanation": result["explanation"],
    }


def get_learning_adjustment(asset_class: str) -> float:
    """Current learned nudge for one asset class (0.0 = nothing learned)."""
    rows = (
        _sb().table(TABLE_STATE)
        .select("adjustment")
        .eq("asset_class", asset_class)
        .execute()
        .data
    ) or []
    if not rows:
        return 0.0
    return float(rows[0]["adjustment"])


def get_state_rows(asset_class: Optional[str] = None) -> list:
    """All learned adjustments (optionally one class), test-* junk filtered."""
    query = _sb().table(TABLE_STATE).select(
        "asset_class, adjustment, explanation, updated_at"
    )
    if asset_class:
        query = query.eq("asset_class", asset_class)
    else:
        query = query.order("asset_class")
    data = query.execute().data or []
    return [r for r in data if not re.match(r"^test-", r.get("asset_class", ""))]


def get_recent_decisions(limit: int = 12) -> list:
    """Last N decisions, newest first — the audit trail behind the math."""
    limit = max(1, min(limit, 100))
    return (
        _sb().table(TABLE_DECISIONS)
        .select("vuln_id, asset_class, decision, real_risk, decided_by, created_at")
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
        .data
    ) or []


def reset_learning() -> None:
    """Wipe all learning (decisions + state) — used for demo replay."""
    client = _sb()
    # uuid PKs cannot be compared with .gt("id", 0) — filter on timestamp.
    client.table(TABLE_DECISIONS).delete().gt("created_at", "1970-01-01T00:00:00Z").execute()
    client.table(TABLE_STATE).delete().neq("asset_class", "").execute()


# ============================================================ http api ======
# Every learning endpoint, mounted wholesale by main.py:
#   import self_learning
#   app.include_router(self_learning.router)
# Paths are frozen (frontend contract) — do not rename.

router = APIRouter(tags=["self-learning"])


class DecisionIn(BaseModel):
    vuln_id: str
    asset_class: str = "default"
    decision: Literal["defer", "patch_now", "incident_confirmed"]
    real_risk: float
    decided_by: str = "analyst"
    reason: Optional[str] = None


@router.post("/api/decisions")
async def decisions(body: DecisionIn):
    """LEARN: record a decision, re-compute the EMA, log the movement."""
    d = body.model_dump()
    try:
        old_adjustment = await asyncio.to_thread(get_learning_adjustment, body.asset_class)
        signal = signal_from_decision(d)
        result = await asyncio.to_thread(record_decision, d)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        log.exception("decision recording failed")
        raise HTTPException(status_code=502, detail=f"learning engine error: {exc}") from exc

    log.info("learn %s: %.2f -> %.2f (signal %.1f) [%s]",
             body.asset_class, old_adjustment, result["new_adjustment"],
             signal, result["explanation"])
    return {
        "ok": True,
        "old_adjustment": old_adjustment,
        "signal": signal,
        "new_adjustment": result["new_adjustment"],
        "explanation": result["explanation"],
    }


@router.get("/api/learning/state")
def learning_state(asset_class: Optional[str] = None):
    """Per-asset-class learned adjustments, as shown on the Learn page."""
    try:
        return get_state_rows(asset_class)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"learning state read failed: {exc}") from exc


@router.get("/api/learning/recent")
def learning_recent(limit: int = 12):
    """The recent decision audit trail."""
    try:
        return get_recent_decisions(limit)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"learning recent read failed: {exc}") from exc


@router.post("/api/learning/reset")
def learning_reset():
    """Wipe all learning — the Learn page 'Reset to pristine' button."""
    try:
        reset_learning()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"learning reset failed: {exc}") from exc
    return {"ok": True}
