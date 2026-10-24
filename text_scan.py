"""VulnIntel paste-scan — scan a pasted dependency list instead of a GitHub repo.

Accepts (auto-detected):
  * requirements.txt / pip freeze output   (pkg==1.2.3 lines, comments allowed)
  * package.json                           (dependencies + devDependencies)
  * npm ls --json output                   (nested dependency tree, flattened)

How it works: the text is written to a temp manifest file and fed into
repo_scan.scan_repo(local_dir=...), so EVERYTHING downstream is identical to a
repo scan — OSV.dev queries, CVSS v3.1, live EPSS, Real Risk formula, optional
RAG enrichment and LLM advisory, fix versions, Slack/Teams alerts. Zero
pipeline duplication, zero drift between the two input modes.

No new dependencies. Errors return {"error": "..."} like scan-repo does.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import tempfile

import repo_scan

# a line that at least looks like "name == version" or a bare package name
_REQ_LINE = re.compile(r"^\s*[A-Za-z0-9_.\-]+(\[[a-z0-9_,.\-]+\])?\s*(==|>=|<=|~=|!=|>|<)\s*[0-9A-Za-z]", re.M)
_BARE_NAME = re.compile(r"^\s*[A-Za-z0-9_.\-]{2,}\s*$", re.M)


def _flatten_npm_ls(node: dict, out: list) -> None:
    """Collect {name, version} from a nested `npm ls --json` tree."""
    for name, info in (node.get("dependencies") or {}).items():
        if isinstance(info, dict) and info.get("version"):
            out.append({"name": name, "version": str(info["version"])})
        if isinstance(info, dict):
            _flatten_npm_ls(info, out)


def _write_manifest(tmpdir: str, text: str) -> str:
    """Write the paste as the right manifest file. Returns a kind label."""
    t = text.strip()
    if t.startswith("{"):
        try:
            data = json.loads(t)
        except ValueError as exc:
            raise ValueError(f"starts with {{ but is not valid JSON: {exc}") from None
        if not isinstance(data, dict):
            raise ValueError("JSON is not an object — paste a package.json or npm ls --json output")

        deps = data.get("dependencies")
        if isinstance(deps, dict) and deps and all(isinstance(v, dict) for v in deps.values()):
            # npm ls --json tree -> flatten into a plain package.json
            flat: list = []
            _flatten_npm_ls(data, flat)
            if not flat:
                raise ValueError("npm ls output contains no installed packages")
            pkg = {"dependencies": {d["name"]: d["version"] for d in flat}}
            with open(os.path.join(tmpdir, "package.json"), "w", encoding="utf-8") as fh:
                json.dump(pkg, fh, indent=2)
            return "npm ls"

        if isinstance(deps, dict) or isinstance(data.get("devDependencies"), dict):
            with open(os.path.join(tmpdir, "package.json"), "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
            return "package.json"

        raise ValueError("JSON parsed but has no dependencies/devDependencies — nothing to scan")

    # line-based: requirements.txt / pip freeze
    if not _REQ_LINE.search(text) and not _BARE_NAME.search(text):
        raise ValueError("unrecognised input — paste requirements.txt / pip freeze output, or a package.json")
    with open(os.path.join(tmpdir, "requirements.txt"), "w", encoding="utf-8") as fh:
        fh.write(text if text.endswith("\n") else text + "\n")
    return "requirements.txt"


def scan_text(text: str, asset_criticality: int = 10,
              include_llm: bool = False, include_rag: bool = False) -> dict:
    """Scan a pasted dependency list. Same result shape as /scan-repo."""
    text = (text or "").strip()
    if not text:
        return {"error": "paste a dependency list first (requirements.txt, pip freeze, or package.json)"}

    tmpdir = tempfile.mkdtemp(prefix="vulnintel_paste_")
    try:
        kind = _write_manifest(tmpdir, text)
        result = repo_scan.scan_repo(
            local_dir=tmpdir,
            asset_criticality=asset_criticality,
            include_llm=include_llm,
            include_rag=include_rag,
        )
        result["input"] = {"mode": "pasted_text", "kind": kind}
        if isinstance(result.get("error"), str):
            result["error"] += f" (pasted {kind})"
        else:
            result["repo"] = f"pasted:{kind}"
        return result
    except ValueError as exc:
        return {"error": str(exc)}
    except Exception as exc:  # noqa: BLE001 — mirror scan-repo's tolerant behaviour
        return {"error": f"paste scan failed: {exc}"}
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
