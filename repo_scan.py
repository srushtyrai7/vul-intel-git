#!/usr/bin/env python3
"""
repo_scan.py -- GitHub Repository Vulnerability Scanner (VulnIntel, Dev 2)

Bolt-on feature for the existing RAG pipeline (rag.py + ingest.py):

    GitHub URL --> dependency manifests (requirements*.txt / package.json / pyproject.toml)
               --> OSV.dev querybatch --> CVE IDs per dependency
               --> CVSS base score (computed locally from the CVSS v3.1 vector)
               --> live EPSS (api.first.org, never stored -- same as rag.py)
               --> Real Risk = CVSS x EPSS x (asset_criticality / 10)   <-- same USP formula
               --> optional: RAG enrichment (Supabase pgvector, your cve_vectors table)
               --> optional: Groq LLM advisory (openai/gpt-oss-120b, temperature 0)

Zero new heavy dependencies: only `requests` (rag.py already needs it).
Works with NO API keys at all (GitHub / OSV / EPSS are open). Gemini, Supabase
and Groq keys only unlock the enrichment + advisory layers, exactly like rag.py.

CLI:
    python repo_scan.py https://github.com/OWASP/NodeGoat --criticality 8
    python repo_scan.py --local ./demo-vulnerable-app --criticality 10 --no-llm
"""

import json
import math
import os
import re
import sys
import time
from datetime import datetime, timezone

import requests

# --------------------------------------------------------------------------
# Configuration (env vars -- same names your rag.py / ingest.py already use)
# --------------------------------------------------------------------------

def _load_dotenv(path: str = ".env") -> None:
    """Tiny .env loader so the CLI works without python-dotenv installed."""
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, val = line.split("=", 1)
                        os.environ.setdefault(key.strip().strip('"'), val.strip().strip('"'))
    except Exception:
        pass


_load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "models/gemini-embedding-001")

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

SUPABASE_URL = os.getenv("SUPABASE_URL") or os.getenv("SUPABASE_PROJECT_URL")
SUPABASE_KEY = (os.getenv("SUPABASE_KEY") or os.getenv("SUPABASE_SERVICE_KEY")
                or os.getenv("SUPABASE_ANON_KEY"))
# Name of the pgvector match function your ingest.py setup created.
SUPABASE_MATCH_RPC = os.getenv("SUPABASE_MATCH_RPC", "match_documents")

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")

EPSS_URL = "https://api.first.org/data/v1/epss"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"

MAX_MANIFEST_FILES = int(os.getenv("MAX_MANIFEST_FILES", "6"))
MAX_VULN_DETAILS = int(os.getenv("MAX_VULN_DETAILS", "40"))
TIMEOUT = 25

RISK_FORMULA = "real_risk = cvss x epss x (asset_criticality / 10)"

# --------------------------------------------------------------------------
# Small HTTP helpers with retry / backoff
# --------------------------------------------------------------------------

def _get(url, params=None, headers=None, retries=2):
    hdrs = {"User-Agent": "vulnintel-repo-scanner/1.0", "Accept": "application/json"}
    hdrs.update(headers or {})
    last = None
    for attempt in range(retries + 1):
        try:
            resp = requests.get(url, params=params, headers=hdrs, timeout=TIMEOUT)
            if resp.status_code == 429 or resp.status_code >= 500:
                time.sleep(1.5 * (attempt + 1))
                last = resp
                continue
            return resp
        except requests.RequestException as exc:
            last = exc
            time.sleep(1.5 * (attempt + 1))
    if isinstance(last, requests.Response):
        return last
    raise last


def _post(url, payload, headers=None, retries=2):
    hdrs = {"User-Agent": "vulnintel-repo-scanner/1.0", "Content-Type": "application/json"}
    hdrs.update(headers or {})
    last = None
    for attempt in range(retries + 1):
        try:
            resp = requests.post(url, data=json.dumps(payload), headers=hdrs, timeout=TIMEOUT)
            if resp.status_code == 429 or resp.status_code >= 500:
                time.sleep(1.5 * (attempt + 1))
                last = resp
                continue
            return resp
        except requests.RequestException as exc:
            last = exc
            time.sleep(1.5 * (attempt + 1))
    if isinstance(last, requests.Response):
        return last
    raise last


def _chunks(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


# --------------------------------------------------------------------------
# CVSS v3.1 base score -- computed locally from the vector string, so we do
# not burn slow NVD API calls. Equation per FIRST CVSS v3.1 specification.
# --------------------------------------------------------------------------

_CVSS_W = {
    "AV": {"N": 0.85, "A": 0.77, "L": 0.62, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},   # Scope unchanged
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},    # Scope changed
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _cvss_roundup(value: float) -> float:
    """FIRST-spec Roundup: smallest 1-decimal number >= value."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000.0) + 1) / 10.0


def cvss31_base_score(vector: str):
    """Return the CVSS v3.x base score for a vector like
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' (9.8), or None if the
    vector is missing / unsupported (e.g. CVSS v4)."""
    if not vector:
        return None
    v = vector.strip()
    if not v.upper().startswith("CVSS:3.0") and not v.upper().startswith("CVSS:3.1"):
        return None
    metrics = {}
    for part in v.split("/")[1:]:
        if ":" in part:
            key, val = part.split(":", 1)
            metrics[key.upper()] = val.upper()
    try:
        av = _CVSS_W["AV"][metrics["AV"]]
        ac = _CVSS_W["AC"][metrics["AC"]]
        ui = _CVSS_W["UI"][metrics["UI"]]
        c = _CVSS_W["CIA"][metrics["C"]]
        i = _CVSS_W["CIA"][metrics["I"]]
        a = _CVSS_W["CIA"][metrics["A"]]
        scope_changed = metrics.get("S") == "C"
        pr = _CVSS_W["PR_C" if scope_changed else "PR_U"][metrics["PR"]]
    except KeyError:
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _cvss_roundup(min(1.08 * (impact + exploitability), 10))
    return _cvss_roundup(min(impact + exploitability, 10))


# Severity band fallback when a record has no CVSS vector (GHSA band labels).
SEVERITY_BAND_ESTIMATES = {"CRITICAL": 9.5, "HIGH": 8.0, "MODERATE": 5.5,
                           "MEDIUM": 5.5, "LOW": 2.5}


def _version_key(version: str):
    """Best-effort comparable key for picking the newest 'fixed' version."""
    out = []
    for part in re.split(r"[.\-+]", str(version)):
        if part.isdigit():
            out.append((0, int(part), ""))
        else:
            m = re.match(r"(\d+)(.*)", part)
            if m:
                out.append((0, int(m.group(1)), m.group(2)))
            else:
                out.append((1, 0, part))
    return out


# --------------------------------------------------------------------------
# Dependency manifest discovery + parsing
# --------------------------------------------------------------------------

SKIP_DIRS = {"node_modules", ".git", ".github", "docs", "doc", "examples",
             "example", "tests", "test", "dist", "build", "vendor",
             ".venv", "venv", "site-packages", "__pycache__"}


def normalize_pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower().strip()


def parse_repo_url(url: str):
    """'https://github.com/owner/repo/tree/branch/sub/dir'
        -> (owner, repo, tree_parts) where tree_parts = ['branch','sub','dir'].
    The branch/subdir split is resolved later with the GitHub API (a branch
    name may itself contain '/')."""
    u = url.strip().rstrip("/")
    u = re.sub(r"^https?://", "", u)
    u = re.sub(r"^www\.", "", u)
    if not u.startswith("github.com/"):
        raise ValueError(f"Not a GitHub URL: {url!r} (expected https://github.com/owner/repo)")
    rest = re.sub(r"\.git$", "", u[len("github.com/"):])
    parts = [p for p in rest.split("/") if p]
    if len(parts) < 2 or not parts[0] or not parts[1]:
        raise ValueError(f"Could not parse owner/repo from: {url!r}")
    owner, repo = parts[0], parts[1]
    tree_parts = parts[3:] if len(parts) >= 3 and parts[2] == "tree" else []
    return owner, repo, tree_parts


def _is_manifest(path: str) -> str:
    """Return ecosystem if the path is a dependency manifest we support."""
    base = path.rsplit("/", 1)[-1].lower()
    if re.match(r"requirements[\w.-]*\.txt$", base):
        return "PyPI"
    if base == "pyproject.toml":
        return "PyPI"
    if base == "package.json":
        return "npm"
    return ""


def _gh_headers():
    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return headers


RAW_PROBE_PATHS = ["requirements.txt", "package.json", "pyproject.toml",
                   "requirements-prod.txt", "requirements-base.txt"]


def _raw_fallback_paths(owner: str, repo: str):
    """GitHub API quota exhausted -> probe common root manifests via
    raw.githubusercontent.com (served by Fastly, no API quota involved)."""
    found = []
    for path in RAW_PROBE_PATHS:
        if fetch_raw_file(owner, repo, "HEAD", path) is not None:
            found.append(path)
    return found


def list_manifest_paths(owner: str, repo: str, tree_parts=None):
    """Find manifest files. Returns (branch, [paths], note).

    Uses the GitHub tree API; if the API is unavailable (rate limit), falls
    back to probing common root paths over raw.githubusercontent.com so the
    scan still works (demo-day Wi-Fi and shared IPs included)."""
    note = ""
    tree = None
    branch = None
    subdir = ""

    if tree_parts:
        # Branch names may contain '/', so try progressively longer prefixes.
        candidates = []
        for k in range(1, min(3, len(tree_parts)) + 1):
            candidates.append(("/".join(tree_parts[:k]), "/".join(tree_parts[k:])))
    else:
        candidates = [(None, "")]  # resolve default branch first

    for ref, sub in candidates:
        if ref is None:
            info = _get(f"https://api.github.com/repos/{owner}/{repo}", headers=_gh_headers())
            if info.status_code == 404:
                raise ValueError(f"GitHub repo not found or private: {owner}/{repo} "
                                 f"(for private repos set GITHUB_TOKEN in .env)")
            if info.status_code != 200:
                note = f"GitHub API HTTP {info.status_code} (rate limit?) - using raw fallback"
                break
            ref = info.json().get("default_branch", "main")
        resp = _get(f"https://api.github.com/repos/{owner}/{repo}/git/trees/{ref}",
                    params={"recursive": "1"}, headers=_gh_headers())
        if resp.status_code == 200:
            tree = resp.json()
            branch, subdir = ref, sub
            break
        if resp.status_code == 404 and len(candidates) > 1:
            continue  # branch guess with '/' inside - try the next split
        note = f"GitHub tree API HTTP {resp.status_code} (rate limit?) - using raw fallback"
        break

    if tree is not None:
        paths = []
        for entry in tree.get("tree", []):
            if entry.get("type") != "blob":
                continue
            path = entry["path"]
            parts = path.split("/")
            if any(seg.lower() in SKIP_DIRS for seg in parts[:-1]):
                continue
            if subdir and not (path == subdir or path.startswith(subdir + "/")):
                continue
            if _is_manifest(path):
                paths.append(path)
        paths.sort(key=lambda p: (0 if "/" not in p else 1, p.count("/"), p))
        if not paths:
            note = note or "no supported manifests in the GitHub tree - trying common root paths"
            fallback = _raw_fallback_paths(owner, repo)
            if fallback:
                return "HEAD", fallback, note
            return branch, [], note
        return branch, paths[:MAX_MANIFEST_FILES], note

    # Full raw fallback (API quota exhausted or no default-branch resolution).
    fallback = _raw_fallback_paths(owner, repo)
    if fallback:
        return "HEAD", fallback, (note or "GitHub API unavailable - using raw fallback")
    raise RuntimeError(note or "could not list repository manifests")


def fetch_raw_file(owner: str, repo: str, branch: str, path: str):
    resp = _get(f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}")
    if resp.status_code != 200:
        return None
    return resp.text


def _dep(ecosystem, name, version, source, dev=False, note=""):
    return {"ecosystem": ecosystem, "name": name, "version": version,
            "source": source, "dev": dev, "note": note}


def parse_requirements_txt(text: str, source: str):
    """Parse pip requirement specifiers. Only exact pins (==) are CVE-queried;
    anything looser is reported as unpinned (cannot assess honestly)."""
    deps = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):          # -r, -e, --index-url, --hash ...
            continue
        if "://" in line:                 # direct URLs / git+https
            continue
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$", line)
        if not m:
            continue
        name = normalize_pypi_name(m.group(1))
        spec = m.group(3).strip()
        vm = re.search(r"(?:===|==)\s*v?([0-9][0-9A-Za-z._+-]*)", spec)
        if vm:
            deps.append(_dep("PyPI", name, vm.group(1).rstrip("."), source))
        else:
            note = f"not exact-pinned (spec: {spec or 'none'})"
            deps.append(_dep("PyPI", name, None, source, note=note))
    return deps


def _clean_npm_spec(spec: str):
    """'^4.17.1' -> '4.17.1'. Returns (version_or_None, note)."""
    s = spec.strip()
    if s.startswith(("workspace:", "file:", "git", "github:", "http", "link:", "npm:")):
        return None, f"non-registry spec: {s[:40]}"
    s = s.split("||")[0].strip()          # first alternative of a range
    s = re.sub(r"^[~^>=<]*\s*", "", s)
    if not s or not re.match(r"^\d", s) or "*" in s or "x" in s.lower():
        return None, f"range not pinnable: {spec}"
    return s, ""


def parse_package_json(text: str, source: str):
    deps = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return [_dep("npm", "<invalid package.json>", None, source, note=str(exc)[:80])]
    for section, is_dev in (("dependencies", False), ("devDependencies", True)):
        for name, spec in (data.get(section) or {}).items():
            if not isinstance(spec, str):
                continue
            version, note = _clean_npm_spec(spec)
            deps.append(_dep("npm", name.lower(), version, source, dev=is_dev, note=note))
    return deps


def _pep508_split(req: str):
    m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$", req)
    if not m:
        return None, None
    name = normalize_pypi_name(m.group(1))
    spec = (m.group(3) or "").strip().strip("()").strip()
    vm = re.search(r"(?:===|==|~=)\s*v?([0-9][0-9A-Za-z._+-]*)", spec)
    return name, (vm.group(1).rstrip(".") if vm else None)


def parse_pyproject(text: str, source: str):
    """Parse [project] + [tool.poetry] dependency tables (tomllib, with a
    regex fallback for Pythons without tomllib)."""
    deps = []
    data = {}
    try:
        import tomllib
        data = tomllib.loads(text)
    except Exception:
        # Regex fallback: grab quoted entries under [project] dependencies.
        for line in text.splitlines():
            line = line.strip().strip(",")
            if line.startswith('"') and ("==" in line or ">=" in line or "~=" in line):
                name, version = _pep508_split(line.strip('"'))
                if name:
                    deps.append(_dep("PyPI", name, version, source,
                                     note="" if version else "not exact-pinned"))
        return deps

    project = data.get("project", {})
    for item in project.get("dependencies", []) or []:
        name, version = _pep508_split(str(item))
        if name:
            deps.append(_dep("PyPI", name, version, source,
                             note="" if version else "not exact-pinned"))
    for group in (project.get("optional-dependencies") or {}).values():
        for item in group or []:
            name, version = _pep508_split(str(item))
            if name:
                deps.append(_dep("PyPI", name, version, source, dev=True,
                                 note="" if version else "not exact-pinned"))
    poetry = (data.get("tool", {}).get("poetry", {}) or {}).get("dependencies", {}) or {}
    for name, spec in poetry.items():
        if name.lower() == "python":
            continue
        version = spec if isinstance(spec, str) else (spec or {}).get("version")
        version, note = (None, f"spec: {version}") if not isinstance(version, str) else _clean_npm_spec(version)
        deps.append(_dep("PyPI", normalize_pypi_name(name), version, source, note=note))
    return deps


def collect_dependencies_local(directory: str):
    """Same manifest discovery, but from a local directory (offline demo mode)."""
    manifests = []
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
        for fname in files:
            path = os.path.join(root, fname)
            rel = os.path.relpath(path, directory)
            if _is_manifest(rel):
                manifests.append((rel.replace(os.sep, "/"), _is_manifest(rel), path))
    manifests.sort(key=lambda m: (0 if "/" not in m[0] else 1, m[0].count("/"), m[0]))
    manifests = manifests[:MAX_MANIFEST_FILES]

    deps = []
    for rel, eco, path in manifests:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        deps.extend(_parse_manifest_text(eco, text, rel))
    return manifests, deps


def _parse_manifest_text(ecosystem: str, text: str, source: str):
    if source.endswith(".json") or ecosystem == "npm":
        return parse_package_json(text, source)
    if source.endswith(".toml"):
        return parse_pyproject(text, source)
    return parse_requirements_txt(text, source)


# --------------------------------------------------------------------------
# OSV.dev -- package/version -> known vulnerability IDs (CVE + GHSA aliases)
# --------------------------------------------------------------------------

def osv_query_batch(pinned_deps):
    """One querybatch call per 100 deps. Returns a list aligned with
    pinned_deps: each item is the list of vuln IDs affecting that dep."""
    results = []
    for chunk in _chunks(pinned_deps, 100):
        queries = [{"package": {"name": d["name"], "ecosystem": d["ecosystem"]},
                    "version": d["version"]} for d in chunk]
        resp = _post(OSV_BATCH_URL, {"queries": queries})
        if resp.status_code != 200:
            raise RuntimeError(f"OSV querybatch HTTP {resp.status_code}: {resp.text[:200]}")
        batch = resp.json().get("results", [])
        while len(batch) < len(chunk):
            batch.append({})
        results.extend(batch)
    return results


def fetch_vuln_details(vuln_ids):
    """Fetch full OSV records for the given IDs (deduped, capped)."""
    details = []
    for vid in vuln_ids[:MAX_VULN_DETAILS]:
        resp = _get(OSV_VULN_URL + requests.utils.quote(vid, safe=""))
        if resp.status_code != 200:
            details.append({"id": vid, "_unavailable": True})
            continue
        details.append(resp.json())
        time.sleep(0.1)  # be polite to the free API
    return details


def extract_cve_id(vuln):
    for alias in vuln.get("aliases", []) or []:
        if alias.upper().startswith("CVE-"):
            return alias.upper()
    return None


def extract_fixed_version(vuln, ecosystem, name):
    """Newest 'fixed' event across affected[] entries matching our package."""
    fixed = []
    no_fix = False
    for affected in vuln.get("affected", []) or []:
        pkg = affected.get("package", {}) or {}
        if pkg.get("ecosystem", "").lower() != ecosystem.lower():
            continue
        if normalize_pypi_name(pkg.get("name", "")) != normalize_pypi_name(name):
            continue
        for rng in affected.get("ranges", []) or []:
            if rng.get("type") in ("GIT",):
                continue
            for event in rng.get("events", []) or []:
                if "fixed" in event:
                    fixed.append(event["fixed"])
                elif "last_affected" in event:
                    no_fix = True
    if fixed:
        return max(fixed, key=_version_key), ""
    if no_fix:
        return None, "no fixed version published"
    return None, ""


def extract_severity(vuln):
    """(score, vector, source) -- CVSS v3 computed from vector, else a GHSA
    band estimate, else (None, None, 'unscored')."""
    for sev in vuln.get("severity", []) or []:
        if sev.get("type") == "CVSS_V3":
            vector = sev.get("score", "")
            score = cvss31_base_score(vector)
            if score is not None:
                return score, vector, "cvss_v3_vector"
    band = (vuln.get("database_specific", {}) or {}).get("severity", "")
    if band:
        return SEVERITY_BAND_ESTIMATES.get(band.upper()), None, f"band-estimate:{band.upper()}"
    return None, None, "unscored"


# --------------------------------------------------------------------------
# EPSS -- live from FIRST (same source rag.py uses; never stored)
# --------------------------------------------------------------------------

def fetch_epss(cve_ids):
    """Batch lookup (50 per request). Returns {cve: (epss, percentile)}."""
    out = {}
    ids = sorted({c for c in cve_ids if c})
    for chunk in _chunks(ids, 50):
        resp = _get(EPSS_URL, params={"cve": ",".join(chunk)})
        if resp.status_code != 200:
            continue
        for item in resp.json().get("data", []) or []:
            try:
                out[item["cve"]] = (float(item.get("epss") or 0.0),
                                    float(item.get("percentile") or 0.0))
            except (TypeError, ValueError):
                continue
        time.sleep(0.15)
    return out


# --------------------------------------------------------------------------
# Optional layers: Supabase pgvector RAG enrichment + Groq LLM advisory
# --------------------------------------------------------------------------

def gemini_embed(text):
    url = (f"https://generativelanguage.googleapis.com/v1beta/"
           f"{EMBEDDING_MODEL}:embedContent?key={GEMINI_API_KEY}")
    resp = _post(url, {"content": {"parts": [{"text": text}]}})
    if resp.status_code != 200:
        raise RuntimeError(f"Gemini embedding HTTP {resp.status_code}: {resp.text[:160]}")
    return resp.json()["embedding"]["values"]


def supabase_match(embedding, match_count=2):
    resp = _post(f"{SUPABASE_URL}/rest/v1/rpc/{SUPABASE_MATCH_RPC}",
                 {"query_embedding": embedding, "match_count": match_count},
                 headers={"apikey": SUPABASE_KEY,
                          "Authorization": f"Bearer {SUPABASE_KEY}"})
    if resp.status_code != 200:
        raise RuntimeError(f"RPC {SUPABASE_MATCH_RPC} HTTP {resp.status_code}: {resp.text[:160]}")
    return resp.json()


def rag_enrich(findings, top_n=3):
    """For the riskiest findings, find related CVEs in your cve_vectors table.
    Pure garnish: on any error we disable it and say why, never fail the scan."""
    if not (GEMINI_API_KEY and SUPABASE_URL and SUPABASE_KEY):
        return {"enabled": False,
                "reason": "missing GEMINI_API_KEY / SUPABASE_URL / SUPABASE_KEY"}
    try:
        related = {}
        for finding in findings[:top_n]:
            text = f"{finding['cve']} {finding['package']} {finding['summary']}"
            rows = supabase_match(gemini_embed(text), match_count=2)
            related[finding["cve"]] = [
                {"cve_id": r.get("cve_id") or r.get("content", "")[:60],
                 "similarity": r.get("similarity")} for r in rows
            ]
        return {"enabled": True, "top_n": top_n, "related": related}
    except Exception as exc:  # noqa: BLE001 - garnish must never crash the scan
        return {"enabled": False, "reason": str(exc)[:200]}


def groq_advisory(payload, asset_criticality):
    if not GROQ_API_KEY:
        return {"enabled": False, "reason": "GROQ_API_KEY not set"}
    findings = payload["findings"]
    if not findings:
        return {"enabled": False, "reason": "no findings to advise on"}
    lines = []
    for f in findings[:10]:
        lines.append(
            f"- {f['cve']} | pkg: {f['package']} {f['installed']} "
            f"(fix: {f['fixed'] or 'none published'}) | CVSS: {f['cvss']} "
            f"| EPSS: {f['epss']} | RealRisk: {f['real_risk']}"
        )
    unpinned = ", ".join(payload["dependencies"]["unpinned"][:15]) or "none"
    prompt = (
        f"Repo: {payload['repo']}\n"
        f"Asset criticality: {asset_criticality}/10 "
        f"(Real Risk = CVSS x EPSS x criticality/10)\n\n"
        f"Vulnerabilities found (ranked by Real Risk):\n" + "\n".join(lines) +
        f"\n\nUnpinned dependencies (could not be assessed): {unpinned}\n\n"
        "Write a security advisory in markdown with exactly these sections: "
        "Executive summary, Top priorities, Fix plan (exact upgrade targets), "
        "Watchlist. Explain each priority CVE in plain English: what an attacker "
        "gains, why its Real Risk ranks where it does given EPSS and asset "
        "criticality. Only reference CVEs listed above; never invent others."
    )
    resp = _post(GROQ_URL, {
        "model": GROQ_MODEL,
        "temperature": 0,
        "max_tokens": 1500,
        "messages": [
            {"role": "system", "content":
                "You are the advisory engine of VulnIntel, a vulnerability "
                "intelligence platform. You write precise, plain-English AppSec "
                "advisories for engineers. You never fabricate CVE data; you only "
                "use what is in the prompt."},
            {"role": "user", "content": prompt},
        ],
    }, headers={"Authorization": f"Bearer {GROQ_API_KEY}"})
    if resp.status_code != 200:
        return {"enabled": False, "reason": f"Groq HTTP {resp.status_code}: {resp.text[:160]}"}
    try:
        text = resp.json()["choices"][0]["message"]["content"]
    except Exception as exc:  # noqa: BLE001
        return {"enabled": False, "reason": f"unexpected Groq response: {exc}"}
    return {"enabled": True, "model": GROQ_MODEL, "advisory": text}


# --------------------------------------------------------------------------
# Orchestrator
# --------------------------------------------------------------------------

def _severity_band(score):
    if score is None:
        return "unscored"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def scan_repo(repo_url=None, asset_criticality=10, include_llm=True,
              include_rag=True, local_dir=None):
    """Main entry point. Returns a JSON-serialisable dict."""
    started = time.time()
    result = {"formula": RISK_FORMULA, "asset_criticality": asset_criticality}

    # 1. Collect dependency manifests -------------------------------------
    if local_dir:
        manifests, deps = collect_dependencies_local(local_dir)
        repo_name = f"local:{os.path.basename(os.path.abspath(local_dir))}"
        branch = "local"
        result["manifests"] = [m[0] for m in manifests]
    else:
        owner, repo, tree_parts = parse_repo_url(repo_url)
        repo_name = f"{owner}/{repo}" + (f"/{'/'.join(tree_parts)}" if tree_parts else "")
        branch, paths, gh_note = list_manifest_paths(owner, repo, tree_parts)
        deps = []
        for path in paths:
            text = fetch_raw_file(owner, repo, branch, path)
            if text is None:
                continue
            deps.extend(_parse_manifest_text(_is_manifest(path), text, path))
        result["manifests"] = paths
        if gh_note:
            result.setdefault("notes", []).append(gh_note)

    result.update({"repo": repo_name, "branch": branch,
                   "scanned_at": datetime.now(timezone.utc).isoformat()})

    pinned = [d for d in deps if d["version"]]
    unpinned = [d["name"] for d in deps if not d["version"]]
    result["dependencies"] = {
        "total": len(deps), "pinned": len(pinned), "unpinned": unpinned,
    }
    if not deps:
        result["error"] = ("No supported dependency manifests found "
                           "(looked for requirements*.txt, pyproject.toml, package.json).")
        return result

    # 2. Map deps -> CVEs via OSV -----------------------------------------
    vuln_lists = osv_query_batch(pinned)
    id_to_deps = {}
    for dep, vulns in zip(pinned, vuln_lists):
        for v in vulns.get("vulns", []) or []:
            id_to_deps.setdefault(v["id"], []).append(dep)

    # Round-robin across dependencies so the detail-fetch cap is shared
    # fairly (otherwise one huge package hogs the cap and hides the rest).
    queues = [[v["id"] for v in vl.get("vulns", []) or []] for vl in vuln_lists]
    unique_ids, seen = [], set()
    while any(queues):
        progressed = False
        for q in queues:
            while q:
                vid = q.pop(0)
                if vid not in seen:
                    seen.add(vid)
                    unique_ids.append(vid)
                    progressed = True
                    break
        if not progressed:
            break
    details = fetch_vuln_details(unique_ids)
    truncated = max(0, len(unique_ids) - MAX_VULN_DETAILS)

    # 3. Build findings: CVSS + fixed version per (dep, vuln) --------------
    findings = []
    for vuln in details:
        if vuln.get("_unavailable"):
            continue
        cve_id = extract_cve_id(vuln)
        display = cve_id or vuln.get("id", "unknown")
        score, vector, source = extract_severity(vuln)
        for dep in id_to_deps.get(vuln.get("id"), []):
            fixed, fix_note = extract_fixed_version(vuln, dep["ecosystem"], dep["name"])
            findings.append({
                "cve": display,
                "alias": vuln.get("id") if cve_id else None,
                "package": dep["name"],
                "ecosystem": dep["ecosystem"],
                "installed": dep["version"],
                "fixed": fixed,
                "fix_note": fix_note,
                "cvss": score,
                "cvss_vector": vector,
                "severity_source": source,
                "severity_band": _severity_band(score),
                "epss": None,
                "epss_percentile": None,
                "real_risk": None,
                "summary": vuln.get("summary") or (vuln.get("details") or "")[:200],
                "references": [r.get("url") for r in (vuln.get("references") or [])[:3]],
            })

    # One CVE can arrive via several records (PYSEC + GHSA siblings).
    # Keep the best record per (cve, package): scored > fixed > highest CVSS.
    best = {}
    for f in findings:
        key = (f["cve"], f["package"])
        rank = (f["cvss"] is not None, f["fixed"] is not None, f["cvss"] or 0)
        if key not in best or rank > (best[key]["cvss"] is not None,
                                      best[key]["fixed"] is not None,
                                      best[key]["cvss"] or 0):
            best[key] = f
    findings = list(best.values())

    # 4. Live EPSS + the USP formula ---------------------------------------
    epss_map = fetch_epss([f["cve"] for f in findings])
    for f in findings:
        epss, percentile = epss_map.get(f["cve"], (None, None))
        f["epss"], f["epss_percentile"] = epss, percentile
        if f["cvss"] is not None and epss is not None:
            f["real_risk"] = round(f["cvss"] * epss * (asset_criticality / 10.0), 4)
    findings.sort(key=lambda f: (-(f["real_risk"] if f["real_risk"] is not None else -1),
                                 -(f["epss"] if f["epss"] is not None else -1)))
    result["findings"] = findings
    result["ranked_cves"] = [f["cve"] for f in findings]
    result["summary"] = {
        "total_findings": len(findings),
        "by_severity": {band: sum(1 for f in findings if f["severity_band"] == band)
                        for band in ("critical", "high", "medium", "low", "unscored")},
        "with_known_fix": sum(1 for f in findings if f["fixed"]),
        "runtime_seconds": round(time.time() - started, 1),
    }

    notes = []
    if unpinned:
        notes.append(f"{len(unpinned)} dependency(ies) are not exact-pinned "
                     f"so their exposure could not be assessed: {', '.join(unpinned[:10])}")
    if truncated:
        notes.append(f"OSV returned {len(unique_ids)} advisories; detail fetch "
                     f"capped at {MAX_VULN_DETAILS} (raise MAX_VULN_DETAILS).")
    no_fix = [f['cve'] for f in findings if not f['fixed'] and f['fix_note']]
    if no_fix:
        notes.append(f"No fixed version published yet for: {', '.join(no_fix[:8])}")
    result["notes"] = notes

    # 5. Optional layers (never crash the core scan) -----------------------
    if include_rag:
        result["rag_related"] = rag_enrich(findings)
    else:
        result["rag_related"] = {"enabled": False, "reason": "disabled by flag"}
    if include_llm:
        result["advisory"] = groq_advisory(result, asset_criticality)
    else:
        result["advisory"] = {"enabled": False, "reason": "disabled by flag"}
    return result


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _print_summary(result):
    print(f"\n=== VulnIntel repo scan: {result.get('repo')} ({result.get('branch')}) ===")
    print(f"Manifests: {', '.join(result.get('manifests', []) or []) or 'none'}")
    deps = result.get("dependencies", {})
    print(f"Dependencies: {deps.get('total', 0)} total | {deps.get('pinned', 0)} pinned "
          f"| {len(deps.get('unpinned', []))} unpinned")
    findings = result.get("findings", [])
    if result.get("error"):
        print(f"ERROR: {result['error']}")
        return
    print(f"\nTop findings (Real Risk = CVSS x EPSS x criticality/10, "
          f"criticality={result['asset_criticality']}):")
    for f in findings[:10]:
        risk = f["real_risk"] if f["real_risk"] is not None else "n/a"
        fix = f["fixed"] or ("no fix yet" if f["fix_note"] else "unknown")
        print(f"  {f['cve']:<20} {f['package']:<24} {f['installed']:>10} -> {fix:<12} "
              f"CVSS {str(f['cvss']):>5} EPSS {str(f['epss']):>6} | RealRisk {risk}")
    if not findings:
        print("  (none - no known CVEs matched the pinned dependencies)")
    for note in result.get("notes", []):
        print(f"NOTE: {note}")
    advisory = result.get("advisory") or {}
    if advisory.get("enabled"):
        print("\n--- LLM advisory (Groq, temperature 0) ---\n")
        print(advisory["advisory"])
    elif advisory.get("reason"):
        print(f"\n(advisory disabled: {advisory['reason']})")


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description="VulnIntel GitHub repo vulnerability scanner")
    parser.add_argument("repo_url", nargs="?", help="https://github.com/owner/repo[/tree/branch/dir]")
    parser.add_argument("--local", help="scan a local directory instead of GitHub (offline demo)")
    parser.add_argument("--criticality", type=int, default=10,
                        help="asset criticality 1-10 (default 10)")
    parser.add_argument("--no-llm", action="store_true", help="skip the Groq advisory")
    parser.add_argument("--no-rag", action="store_true", help="skip Supabase RAG enrichment")
    parser.add_argument("--out", help="also write the full JSON result to this file")
    args = parser.parse_args(argv)
    if not args.repo_url and not args.local:
        parser.error("give a GitHub repo URL or --local DIR")

    result = scan_repo(repo_url=args.repo_url, asset_criticality=args.criticality,
                       include_llm=not args.no_llm, include_rag=not args.no_rag,
                       local_dir=args.local)
    _print_summary(result)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        print(f"\nFull JSON written to {args.out}")
    return result


if __name__ == "__main__":
    main()
