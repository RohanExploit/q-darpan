"""Local HTTP service behind the dashboard.

The problem statement asks for an interactive platform to visualise the scan,
the risks and the results. This exposes exactly the same engine the CLI drives
-- there is no second code path and no second source of truth, so what an
analyst sees in the browser is what the CBOM says.

Binds ``127.0.0.1`` by default. This is a tool for an air-gapped enclave; it
has no authentication because it is not meant to be reachable from anywhere
that would need it. Do not bind it to a routable address.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .canonical import default_registry
from .journal import TOOL_VERSION, RunJournal
from .pipeline import analyse, write_outputs
from .recommend import summarise_costs
from .risk import Policy, TIER_ORDER, summarise
from .scan import ScanOptions, scan

WEB_DIR = Path(__file__).parent / "web"


def _run_dirs(runs_root: Path) -> List[Path]:
    """Every directory under the runs root that holds a journal."""
    if not runs_root.is_dir():
        return []
    return sorted(
        (p for p in runs_root.iterdir() if p.is_dir() and (p / "findings.jsonl").exists()),
        key=lambda p: p.name,
        reverse=True,
    )


def _run_summary(run_dir: Path) -> Dict[str, Any]:
    journal = RunJournal.open(run_dir)
    manifest = journal.manifest
    return {
        "id": run_dir.name,
        "tool_version": manifest.tool_version,
        "registry_version": manifest.registry_version,
        "targets": [record.to_dict() for record in manifest.targets.values()],
        "target_count": len(manifest.targets),
        "has_cbom": (run_dir / "cbom.json").exists(),
    }


def create_app(runs_root: Path = Path("runs")):
    """Build the FastAPI application.

    Imported lazily by the CLI so that the core package keeps working when the
    optional API extra is not installed.
    """
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

    runs_root = Path(runs_root)
    app = FastAPI(
        title="Q-DARPAN",
        version=TOOL_VERSION,
        description="Cryptographic discovery, CBOM and post-quantum risk analysis.",
    )

    def _resolve(run_id: str) -> Path:
        """Resolve a run id to a directory, refusing anything that escapes root.

        The id arrives from a URL, so a traversal attempt has to be rejected
        rather than merely discouraged -- this process can read the whole disk.
        """
        candidate = (runs_root / run_id).resolve()
        if not str(candidate).startswith(str(runs_root.resolve())):
            raise HTTPException(status_code=400, detail="invalid run id")
        if not (candidate / "findings.jsonl").exists():
            raise HTTPException(status_code=404, detail="no such run")
        return candidate

    # -- dashboard ------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> str:
        index = WEB_DIR / "index.html"
        if not index.exists():
            raise HTTPException(status_code=500, detail="dashboard asset missing")
        return index.read_text(encoding="utf-8")

    # -- runs -----------------------------------------------------------

    @app.get("/api/runs")
    def list_runs() -> Dict[str, Any]:
        return {"runs": [_run_summary(d) for d in _run_dirs(runs_root)]}

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str) -> Dict[str, Any]:
        run_dir = _resolve(run_id)
        analysis = analyse(RunJournal.open(run_dir))
        return {
            "run": _run_summary(run_dir),
            "summary": {
                "assets": len(analysis.merged) - len(analysis.libraries),
                "libraries": len(analysis.libraries),
                "by_tier": summarise(analysis.assessments),
                "costs": summarise_costs(analysis.queue),
                "errors": len(analysis.errors),
            },
            "queue": [entry.to_dict() for entry in analysis.queue],
            "libraries": [item.to_dict() for item in analysis.libraries],
            "errors": analysis.errors,
        }

    @app.get("/api/runs/{run_id}/cbom")
    def get_cbom(run_id: str) -> JSONResponse:
        run_dir = _resolve(run_id)
        cbom = run_dir / "cbom.json"
        if not cbom.exists():
            analysis = analyse(RunJournal.open(run_dir))
            return JSONResponse(json.loads(analysis.cbom_json()))
        return JSONResponse(json.loads(cbom.read_text(encoding="utf-8")))

    @app.get("/api/runs/{run_id}/report", response_class=PlainTextResponse)
    def get_report(run_id: str) -> str:
        run_dir = _resolve(run_id)
        return analyse(RunJournal.open(run_dir)).markdown()

    # -- scanning -------------------------------------------------------

    @app.post("/api/scan")
    def start_scan(request: Dict[str, Any]) -> Dict[str, Any]:
        """Run a scan synchronously and return its results.

        Synchronous on purpose: an operator who clicks Scan wants the answer,
        and a background-job queue would be a second piece of state to keep
        consistent with the journal that already exists on disk.
        """
        targets = request.get("targets") or []
        if not targets:
            raise HTTPException(status_code=400, detail="no targets given")

        run_id = str(request.get("run_id") or "web")
        if "/" in run_id or "\\" in run_id or run_id in ("", ".", ".."):
            raise HTTPException(status_code=400, detail="invalid run id")

        options = ScanOptions(
            surfaces=request.get("surfaces") or ScanOptions.surfaces,
            surfaces_explicit=bool(request.get("surfaces")),
            offline=bool(request.get("offline", False)),
        )
        run_dir = runs_root / run_id
        try:
            summary = scan(targets, run_dir, options)
        except (ValueError, Exception) as exc:  # noqa: BLE001 - surfaced to the UI
            raise HTTPException(status_code=400, detail=str(exc))

        analysis = analyse(RunJournal.open(run_dir))
        write_outputs(analysis, run_dir, scan_summary=summary.to_dict())
        return {"run_id": run_id, "scan": summary.to_dict()}

    # -- policy ---------------------------------------------------------

    @app.get("/api/policy")
    def get_policy() -> Dict[str, Any]:
        policy = Policy.load()
        registry = default_registry()
        return {
            "policy": policy.raw(),
            "registry_version": registry.version,
            "families": sorted(registry.families()),
            "tier_order": TIER_ORDER,
        }

    @app.get("/api/health")
    def health() -> Dict[str, Any]:
        return {"status": "ok", "version": TOOL_VERSION, "runs_root": str(runs_root)}

    return app
