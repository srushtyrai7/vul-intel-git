"""VulnIntel push alerts — Slack / Teams webhook notifications.

Fires after a repo scan when findings meet the severity threshold, and via
POST /api/alerts/test for setup checks and live demos.

CONFIG (env vars on Render — all optional):
  SLACK_WEBHOOK_URL   https://hooks.slack.com/services/...
  TEAMS_WEBHOOK_URL   https://xxxxx.webhook.office.com/...
  ALERT_SEVERITY      minimum severity that triggers: critical|high|medium|low
                      (default: critical)
  ALERT_TOP_N         max findings listed inside one message (default: 5)
  ALERT_DEDUP_TTL     seconds an identical alert is suppressed (default: 300)

The dashboard may also pass `webhook_url` per request (demo-friendly — no
Render env edit needed); the request value wins over the env var.

DESIGN RULES
------------
* Scans are NEVER affected by alert problems: sending is best-effort, every
  failure is captured into result["alert"]["error"], HTTP status stays 200.
* Channel is auto-detected from the URL (webhook.office.com -> Teams plain
  text, everything else -> Slack Block Kit).
* Identical re-alerts (same repo + same finding set) are suppressed for
  ALERT_DEDUP_TTL seconds so demo double-clicks don't spam the channel.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
import urllib.request
from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel

log = logging.getLogger("vulnintel.alerts")

router = APIRouter(tags=["alerts"])

# severity ranking — a finding at or above the threshold rank triggers an alert
_SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _cfg(name: str, default: str) -> str:
    return (os.environ.get(name) or default).strip()


def _threshold() -> str:
    sev = _cfg("ALERT_SEVERITY", "critical").lower()
    return sev if sev in _SEV_RANK else "critical"


def _finding_severity(f: dict) -> str:
    """Severity of one finding — use the pipeline's value, else derive from CVSS."""
    sev = (f.get("severity") or "").lower()
    if sev in _SEV_RANK:
        return sev
    cvss = f.get("cvss")
    try:
        cvss = float(cvss)
    except (TypeError, ValueError):
        return "low"
    return "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"


def _repo_display(repo_url: str) -> str:
    return (repo_url or "").replace("https://github.com/", "").strip("/") or "repo"


def resolve_webhook(body_url: Optional[str] = None) -> tuple[Optional[str], str]:
    """Pick the webhook to use. Returns (url, channel). Body value wins."""
    url = (body_url or "").strip()
    if url:
        return url, ("teams" if "office.com" in url else "slack")
    url = (os.environ.get("SLACK_WEBHOOK_URL") or "").strip()
    if url:
        return url, "slack"
    url = (os.environ.get("TEAMS_WEBHOOK_URL") or "").strip()
    if url:
        return url, "teams"
    return None, "none"


def _post(url: str, payload: dict, timeout: float = 8.0) -> int:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status


# ------------------------------------------------------------- formatting ---
def _slack_payload(repo: str, hits: list, threshold: str, deps: str) -> dict:
    lines = []
    for i, f in enumerate(hits, 1):
        epss = f.get("epss")
        epss_txt = f" · EPSS {float(epss)*100:.2f}%" if epss is not None else ""
        risk = f.get("real_risk")
        risk_txt = f"{float(risk):.2f}" if risk is not None else "—"
        lines.append(
            f"{i}. *{f.get('cve', '?')}* — {f.get('package', '?')}@{f.get('installed', '?')}"
            f" · CVSS {f.get('cvss', '—')}{epss_txt} — Real Risk *{risk_txt}*"
        )
    top_risk = max((float(f.get("real_risk") or 0) for f in hits), default=0)
    return {
        "text": f"VulnIntel: {len(hits)} finding(s) >= {threshold} in {repo}",
        "blocks": [
            {"type": "header",
             "text": {"type": "plain_text", "emoji": True,
                      "text": f":rotating_light: VulnIntel — {repo}"}},
            {"type": "section",
             "text": {"type": "mrkdwn",
                      "text": (f"*{len(hits)}* finding(s) at or above *{threshold}* severity\n"
                               f"*Top Real Risk:* `{top_risk:.2f}`{deps}")}},
            {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}},
            {"type": "context",
             "elements": [{"type": "mrkdwn",
                           "text": "Real Risk = CVSS x EPSS x asset criticality · VulnIntel scan alert"}]},
        ],
    }


def _teams_payload(repo: str, hits: list, threshold: str, deps: str) -> dict:
    rows = []
    for i, f in enumerate(hits, 1):
        risk = f.get("real_risk")
        risk_txt = f"{float(risk):.2f}" if risk is not None else "-"
        rows.append(f"{i}. {f.get('cve', '?')} — {f.get('package', '?')}@{f.get('installed', '?')}"
                    f" (CVSS {f.get('cvss', '-')}) Real Risk {risk_txt}")
    top_risk = max((float(f.get("real_risk") or 0) for f in hits), default=0)
    text = (f"VULNINTEL ALERT — {repo}\n"
            f"{len(hits)} finding(s) >= {threshold} severity | Top Real Risk {top_risk:.2f}{deps}\n"
            + "\n".join(rows)
            + "\nReal Risk = CVSS x EPSS x asset criticality")
    return {"text": text}


# ----------------------------------------------------------------- dedup ----
_dedup_lock = threading.Lock()
_dedup: dict[str, float] = {}


def _dedup_key(repo: str, hits: list) -> str:
    cves = ",".join(sorted(f.get("cve", "?") for f in hits))
    top = max((float(f.get("real_risk") or 0) for f in hits), default=0)
    return hashlib.sha1(f"{repo}|{cves}|{top:.4f}".encode()).hexdigest()


def _is_duplicate(key: str) -> tuple[bool, int]:
    ttl = int(_cfg("ALERT_DEDUP_TTL", "300"))
    now = time.time()
    with _dedup_lock:
        last = _dedup.get(key)
        if last is not None and now - last < ttl:
            return True, int(ttl - (now - last))
        _dedup[key] = now
        # prune stale entries so the dict cannot grow forever
        for k in [k for k, v in _dedup.items() if now - v > ttl]:
            _dedup.pop(k, None)
    return False, ttl


# ------------------------------------------------------------ main entry ----
def maybe_alert(result: dict, repo_url: str = "", webhook_url: Optional[str] = None) -> dict:
    """Best-effort alert after a scan. Returns the alert status dict and also
    stores it at result['alert']. Never raises; never touches finding data."""
    alert: dict = {"sent": False}
    try:
        url, channel = resolve_webhook(webhook_url)
        if not url:
            alert["reason"] = "no webhook configured (set SLACK_WEBHOOK_URL or paste one in the dashboard)"
            return _finish(result, alert)

        threshold = _threshold()
        findings = result.get("findings") or []
        hits = [f for f in findings
                if _SEV_RANK.get(_finding_severity(f), 0) >= _SEV_RANK[threshold]]
        hits.sort(key=lambda f: -(f.get("real_risk") or 0))
        if not hits:
            alert["reason"] = f"no findings at or above {threshold} severity"
            return _finish(result, alert)

        top_n = int(_cfg("ALERT_TOP_N", "5"))
        shown = hits[:top_n]
        repo = _repo_display(repo_url or (result.get("repo") or ""))
        deps = ""
        d = result.get("dependencies") or {}
        if d.get("total"):
            deps = f" · deps {d.get('pinned', '?')}/{d['total']} pinned"

        dup, info = _is_duplicate(_dedup_key(repo, hits))
        if dup:
            alert["reason"] = f"duplicate suppressed for {info}s (same repo + same findings)"
            return _finish(result, alert)

        payload = (_teams_payload(repo, shown, threshold, deps) if channel == "teams"
                   else _slack_payload(repo, shown, threshold, deps))
        status = _post(url, payload)
        alert.update({"sent": status == 200, "channel": channel,
                      "count": len(hits), "threshold": threshold,
                      "http_status": status})
        if status != 200:
            alert["error"] = f"webhook responded {status}"
    except Exception as exc:  # noqa: BLE001 — alerting must never break a scan
        log.warning("alert send failed: %s", exc)
        alert["error"] = str(exc)[:200]
    return _finish(result, alert)


def _finish(result: dict, alert: dict) -> dict:
    if isinstance(result, dict):
        result["alert"] = alert
    log.info("scan alert: %s", alert)
    return alert


# -------------------------------------------------------------- test api ----
class TestAlertIn(BaseModel):
    webhook_url: Optional[str] = None
    channel: Optional[str] = None  # "slack" | "teams" — auto-detected if omitted


@router.post("/api/alerts/test")
def test_alert(body: TestAlertIn):
    """Send a test card to the webhook. Verifies setup before demo day."""
    url, channel = resolve_webhook(body.webhook_url)
    if not url:
        return {"ok": False,
                "error": "no webhook configured — paste one in the dashboard or set SLACK_WEBHOOK_URL on Render"}
    if body.channel in ("slack", "teams"):
        channel = body.channel
    payload = {
        "slack": lambda: _slack_payload("demo/test", [{
            "cve": "CVE-2023-25813", "package": "sequelize", "installed": "6.19.0",
            "cvss": 10.0, "epss": 0.0144, "real_risk": 1.44,
        }], "critical", " · test card — safe to ignore"),
        "teams": lambda: _teams_payload("demo/test", [{
            "cve": "CVE-2023-25813", "package": "sequelize", "installed": "6.19.0",
            "cvss": 10.0, "epss": 0.0144, "real_risk": 1.44,
        }], "critical", " · test card — safe to ignore"),
    }[channel]()
    try:
        status = _post(url, payload)
        return {"ok": status == 200, "channel": channel, "http_status": status,
                "note": "check your Slack/Teams channel"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "channel": channel, "error": str(exc)[:200]}
