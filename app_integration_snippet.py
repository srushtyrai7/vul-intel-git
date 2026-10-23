# Paste these into your EXISTING app file (the one that serves /ask),
# right after `import repo_scan` is added at the top of the file.
#
# --- If your server is FastAPI (app = FastAPI(...) already exists) ---
#
# from fastapi.middleware.cors import CORSMiddleware  # if not already added
# from pydantic import BaseModel, Field
#
# class RepoScanRequest(BaseModel):
#     repo_url: str
#     asset_criticality: int = Field(10, ge=1, le=10)
#     include_llm: bool = True
#     include_rag: bool = True
#
# @app.post("/scan-repo")
# def scan_repo_route(body: RepoScanRequest):
#     try:
#         return repo_scan.scan_repo(
#             repo_url=body.repo_url,
#             asset_criticality=body.asset_criticality,
#             include_llm=body.include_llm,
#             include_rag=body.include_rag,
#         )
#     except ValueError as exc:
#         return {"error": str(exc)}
#     except Exception as exc:
#         return {"error": f"scan failed: {exc}"}
#
# @app.get("/scan-repo")   # browser-friendly variant for the stage demo
# def scan_repo_get(repo_url: str, asset_criticality: int = 10):
#     return scan_repo_route(RepoScanRequest(repo_url=repo_url,
#                                            asset_criticality=asset_criticality))
#
#
# --- If your server is Flask ---
#
# import repo_scan
# from flask import request, jsonify
#
# @app.route("/scan-repo", methods=["POST"])
# def scan_repo_route():
#     data = request.get_json(force=True, silent=True) or {}
#     try:
#         result = repo_scan.scan_repo(
#             repo_url=data.get("repo_url", ""),
#             asset_criticality=int(data.get("asset_criticality", 10)),
#         )
#         return jsonify(result)
#     except Exception as exc:
#         return jsonify({"error": str(exc)}), 500
#
# @app.route("/scan-repo", methods=["GET"])   # browser-friendly variant
# def scan_repo_get():
#     data = {
#         "repo_url": request.args.get("repo_url", ""),
#         "asset_criticality": request.args.get("asset_criticality", 10, type=int),
#     }
#     return scan_repo_route.__wrapped__() if hasattr(scan_repo_route, "__wrapped__") else None
#     # NOTE: Flask route stacking is fiddly - simplest is to register the GET
#     # handler to call the same scan logic as above.
