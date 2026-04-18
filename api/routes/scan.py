#!/usr/bin/env python3
"""
Scan routes
POST /api/scan/run         -- start a single scan (background task)
GET  /api/scan/{scan_id}   -- poll status / results
POST /api/scan/batch       -- start a batch of scans
GET  /api/scan/batch/{id}  -- poll batch status
POST /api/scan/preview     -- dry-run (no LLM calls)
"""

import asyncio
import json
import uuid
from pathlib import Path
from typing import Optional

import csv
import io

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request
from fastapi.responses import Response

from api.schemas.scan import (
    BatchScanRequest, BatchScanStatus,
    ScanRequest, ScanResponse, ScanStatusResponse,
)
from core.scanner import Scanner, ScanJob, ScanStatus, ModelVulnResult, ProbeResult

router = APIRouter()
_scanner = Scanner()


def _extract_chain_prompts(vulnerabilities: list) -> dict:
    """
    For each selected vulnerability, pull single-turn-viable step prompts from
    chain templates mapped to that vuln.  These are injected into regular scans
    so every scan automatically exercises chain-derived attack angles.

    Imports are deferred here to avoid the circular dependency:
      scanner.py → (would import) chain.py → override_engine → (ok)
    but chain.py already imports scanner implicitly via failure_store at module level.
    Importing from api.routes.chain inside this helper (called at request time)
    is safe because by then all modules are fully loaded.
    """
    try:
        from api.routes.chain import GOAL_TEMPLATES, VULN_TO_TEMPLATES
    except Exception:
        return {}

    result: dict = {}
    for vuln in (vulnerabilities or []):
        tpl_ids = VULN_TO_TEMPLATES.get(vuln, [])
        prompts: list = []
        seen: set = set()
        for tid in tpl_ids:
            tpl = GOAL_TEMPLATES.get(tid)
            if not tpl:
                continue
            # Include steps 2+ (skip step 0 which is usually a baseline probe question)
            for step in tpl.get("steps", [])[1:]:
                p = step.get("prompt", "").strip()
                # Skip steps with unfilled placeholders that need a target substitution
                if not p or "[TARGET REQUEST]" in p:
                    continue
                if p not in seen:
                    seen.add(p)
                    prompts.append(p)
        if prompts:
            result[vuln] = prompts
    return result

# -- Persistence ---------------------------------------------------------------
# Completed / failed scans are written to SCAN_PERSIST_DIR as individual JSON
# files so they survive server restarts.

SCAN_PERSIST_DIR = Path(__file__).parent.parent.parent / "data" / "scans"

def _scan_to_json(job: ScanJob) -> dict:
    """Serialise a ScanJob to a plain dict suitable for JSON storage."""
    results_serial: dict = {}
    for model, vr_list in job.results.items():
        results_serial[model] = [
            {
                "model":         vr.model,
                "vulnerability": vr.vulnerability,
                "bypass_count":  vr.bypass_count,
                "total_probes":  vr.total_probes,
                "probes": [
                    {
                        "vulnerability":  p.vulnerability,
                        "prompt":         p.prompt,
                        "wrapped_prompt": p.wrapped_prompt,
                        "response":       p.response,
                        "bypassed":       p.bypassed,
                        "override_mode":  p.override_mode,
                        "mutation":       p.mutation,
                        "latency_ms":     p.latency_ms,
                        "error":          p.error,
                    }
                    for p in vr.probes
                ],
            }
            for vr in vr_list
        ]
    return {
        "scan_id":           job.scan_id,
        "status":            job.status.value,
        "models":            job.models,
        "vulnerabilities":   job.vulnerabilities,
        "override_mode":     job.override_mode,
        "prompt_count":      job.prompt_count,
        "use_mutations":     job.use_mutations,
        "started_at":        job.started_at,
        "finished_at":       job.finished_at,
        "progress":          job.progress,
        "use_warm_pool":     job.use_warm_pool,
        "cancelled":         job.cancelled,
        "probes_completed":  job.probes_completed,
        "probes_total_hint": job.probes_total_hint,
        "errors":            job.errors,
        "results":           results_serial,
    }

def _json_to_scan(data: dict) -> ScanJob:
    """Reconstruct a ScanJob from a persisted JSON dict."""
    results: dict = {}
    for model, vr_list in data.get("results", {}).items():
        rebuilt: list = []
        for vr_data in vr_list:
            probes = [
                ProbeResult(
                    vulnerability  = p["vulnerability"],
                    prompt         = p["prompt"],
                    wrapped_prompt = p.get("wrapped_prompt"),
                    response       = p["response"],
                    bypassed       = p["bypassed"],
                    override_mode  = p["override_mode"],
                    mutation       = p.get("mutation"),
                    latency_ms     = p["latency_ms"],
                    error          = p.get("error"),
                )
                for p in vr_data.get("probes", [])
            ]
            bypass_count = vr_data.get("bypass_count", sum(1 for p in probes if p.bypassed))
            total_probes = vr_data.get("total_probes", len(probes))
            mvr = ModelVulnResult(
                model         = vr_data["model"],
                vulnerability = vr_data["vulnerability"],
                probes        = probes,
                bypass_count  = bypass_count,
                total_probes  = total_probes,
            )
            rebuilt.append(mvr)
        results[model] = rebuilt

    return ScanJob(
        scan_id           = data["scan_id"],
        status            = ScanStatus(data["status"]),
        models            = data["models"],
        vulnerabilities   = data["vulnerabilities"],
        override_mode     = data["override_mode"],
        prompt_count      = data.get("prompt_count", 5),
        use_mutations     = data.get("use_mutations", False),
        results           = results,
        errors            = data.get("errors", []),
        started_at        = data.get("started_at"),
        finished_at       = data.get("finished_at"),
        progress          = data.get("progress", 100),
        use_warm_pool     = data.get("use_warm_pool", True),
        cancelled         = data.get("cancelled", False),
        probes_completed  = data.get("probes_completed", 0),
        probes_total_hint = data.get("probes_total_hint", 0),
    )

def save_scan_to_disk(job: ScanJob) -> None:
    """Persist a completed/failed ScanJob as JSON so it survives restarts."""
    try:
        SCAN_PERSIST_DIR.mkdir(parents=True, exist_ok=True)
        path = SCAN_PERSIST_DIR / f"{job.scan_id}.json"
        path.write_text(json.dumps(_scan_to_json(job), indent=2), encoding="utf-8")
    except Exception as exc:
        print(f"[!] save_scan_to_disk failed for {job.scan_id}: {exc}")


def load_all_scans_from_disk(store: dict) -> int:
    """
    Load all persisted scan JSON files from SCAN_PERSIST_DIR into *store*.
    Returns the number of scans successfully loaded.
    """
    if not SCAN_PERSIST_DIR.exists():
        return 0

    loaded = 0
    for path in SCAN_PERSIST_DIR.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            job  = _json_to_scan(data)
            store[job.scan_id] = job
            loaded += 1
        except Exception as exc:
            print(f"[!] Failed to load persisted scan {path.name}: {exc}")

    return loaded

# -- helpers -------------------------------------------------------------------

def _get_store(request: Request) -> dict:
    return request.app.state.scan_store


def _get_batch_store(request: Request) -> dict:
    return request.app.state.batch_store


def _get_job(scan_id: str, store: dict) -> "ScanJob | None":
    """Return job from in-memory store; fall back to persisted disk file."""
    job = store.get(scan_id)
    if job is not None:
        return job
    path = SCAN_PERSIST_DIR / f"{scan_id}.json"
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            job  = _json_to_scan(data)
            store[scan_id] = job  # cache back into memory
            return job
        except Exception:
            pass
    return None


async def _run_job(scan_id: str, store: dict):
    job = store.get(scan_id)
    if job is None:
        return
    await _scanner.run_scan(job)
    # Persist completed and failed scans so they survive restarts
    if job.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
        save_scan_to_disk(job)

# -- Single scan ---------------------------------------------------------------

@router.post("/run", response_model=ScanResponse, status_code=202)
async def start_scan(
    req: ScanRequest,
    background_tasks: BackgroundTasks,
    request: Request,
):
    store = _get_store(request)
    extra = _extract_chain_prompts(req.vulnerabilities or [])
    job   = _scanner.create_scan_job(
        models          = req.models,
        vulnerabilities = req.vulnerabilities,
        override_mode   = req.override_mode,
        prompt_count    = req.prompt_count,
        use_mutations   = req.use_mutations,
        extra_prompts   = extra,
    )
    store[job.scan_id] = job
    background_tasks.add_task(_run_job, job.scan_id, store)
    chain_count = sum(len(v) for v in extra.values())
    return ScanResponse(
        scan_id = job.scan_id,
        status  = "pending",
        message = f"Scan queued — {len(req.models)} model(s) × {len(req.vulnerabilities or [])} vuln(s), +{chain_count} chain prompts",
    )


@router.get("/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str, request: Request):
    store = _get_store(request)
    job   = _get_job(scan_id, store)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
    d = job.to_dict()
    return ScanStatusResponse(**d)


@router.post("/{scan_id}/cancel", status_code=200)
async def cancel_scan(scan_id: str, request: Request):
    store = _get_store(request)
    job   = _get_job(scan_id, store)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
    job.cancelled = True
    return {"scan_id": scan_id, "status": "cancelling"}


@router.get("/{scan_id}/export", summary="Export scan results as JSON or CSV")
async def export_scan(
    scan_id: str,
    request: Request,
    fmt: str = Query("json", description="Export format: json or csv"),
):
    store = _get_store(request)
    job   = _get_job(scan_id, store)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")

    data = _scan_to_json(job)
    safe_id = scan_id[:8]

    if fmt == "json":
        return Response(
            content     = json.dumps(data, indent=2, ensure_ascii=False),
            media_type  = "application/json",
            headers     = {"Content-Disposition": f'attachment; filename="scan_{safe_id}.json"'},
        )
    elif fmt == "csv":
        buf    = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "scan_id", "model", "vulnerability",
            "prompt", "wrapped_prompt", "override_mode", "mutation",
            "bypassed", "latency_ms", "response", "error",
        ])
        for model, vr_list in data.get("results", {}).items():
            for vr in vr_list:
                for p in vr.get("probes", []):
                    writer.writerow([
                        scan_id,
                        model,
                        vr.get("vulnerability", ""),
                        p.get("prompt", ""),
                        p.get("wrapped_prompt", ""),
                        p.get("override_mode", ""),
                        p.get("mutation", ""),
                        p.get("bypassed", False),
                        p.get("latency_ms", 0),
                        (p.get("response") or "")[:500],
                        p.get("error", ""),
                    ])
        return Response(
            content     = buf.getvalue(),
            media_type  = "text/csv",
            headers     = {"Content-Disposition": f'attachment; filename="scan_{safe_id}.csv"'},
        )
    else:
        raise HTTPException(status_code=400, detail="fmt must be 'json' or 'csv'")


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(scan_id: str, request: Request):
    store = _get_store(request)
    if scan_id not in store:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
    del store[scan_id]
    # Also remove the persisted file if it exists
    persist_path = SCAN_PERSIST_DIR / f"{scan_id}.json"
    if persist_path.exists():
        try:
            persist_path.unlink()
        except Exception:
            pass

# -- Batch scan ---------------------------------------------------------------

async def _run_batch(batch_id: str, reqs: list, scan_ids: list, store: dict, batch_store: dict):
    for scan_id, req in zip(scan_ids, reqs):
        job = store.get(scan_id)
        if job:
            await _scanner.run_scan(job)
            if job.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
                save_scan_to_disk(job)
        batch = batch_store.get(batch_id)
        if batch:
            if job and job.status == ScanStatus.COMPLETED:
                batch["completed"] += 1
            elif job and job.status == ScanStatus.FAILED:
                batch["failed"] += 1
    batch = batch_store.get(batch_id)
    if batch:
        batch["status"] = "completed"


@router.post("/batch", response_model=BatchScanStatus, status_code=202)
async def start_batch_scan(
    req: BatchScanRequest,
    background_tasks: BackgroundTasks,
    request: Request,
):
    store       = _get_store(request)
    batch_store = _get_batch_store(request)
    batch_id    = str(uuid.uuid4())
    scan_ids    = []

    for scan_req in req.scans:
        extra = _extract_chain_prompts(scan_req.vulnerabilities or [])
        job = _scanner.create_scan_job(
            models          = scan_req.models,
            vulnerabilities = scan_req.vulnerabilities,
            override_mode   = scan_req.override_mode,
            prompt_count    = scan_req.prompt_count,
            use_mutations   = scan_req.use_mutations,
            extra_prompts   = extra,
        )
        store[job.scan_id] = job
        scan_ids.append(job.scan_id)

    batch_store[batch_id] = {
        "batch_id":  batch_id,
        "label":     req.label,
        "total":     len(scan_ids),
        "completed": 0,
        "failed":    0,
        "scan_ids":  scan_ids,
        "status":    "running",
    }

    background_tasks.add_task(
        _run_batch, batch_id, req.scans, scan_ids, store, batch_store
    )

    return BatchScanStatus(**batch_store[batch_id])


@router.get("/batch/{batch_id}", response_model=BatchScanStatus)
async def get_batch_status(batch_id: str, request: Request):
    batch_store = _get_batch_store(request)
    batch = batch_store.get(batch_id)
    if batch is None:
        raise HTTPException(status_code=404, detail=f"Batch {batch_id!r} not found")
    return BatchScanStatus(**batch)

# -- Jailbreak sweep ----------------------------------------------------------

async def _run_jailbreak_job(scan_id: str, store: dict):
    job = store.get(scan_id)
    if job is None:
        return
    await _scanner.run_jailbreak_scan(job)
    if job.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
        save_scan_to_disk(job)


@router.post("/jailbreak", response_model=ScanResponse, status_code=202,
             summary="Jailbreak sweep -- auto-cycles all override modes per probe")
async def start_jailbreak_scan(
    req: ScanRequest,
    background_tasks: BackgroundTasks,
    request: Request,
):
    """
    Run a jailbreak sweep scan.  For each prompt the scanner automatically
    tries every known override/persona mode (DAN, GodMode, AIM, STAN, DUDE,
    Evil Confidant, Claude Bypass, GPT Bypass, sudo, translator, ...) and
    records which mode achieves bypass.  The first successful bypass per
    probe is recorded; if none succeed, the baseline result is stored.
    """
    store = _get_store(request)
    job   = _scanner.create_jailbreak_job(
        models          = req.models,
        vulnerabilities = req.vulnerabilities,
        prompt_count    = req.prompt_count,
        use_mutations   = req.use_mutations,
    )
    store[job.scan_id] = job
    background_tasks.add_task(_run_jailbreak_job, job.scan_id, store)
    return ScanResponse(
        scan_id = job.scan_id,
        status  = "pending",
        message = f"Jailbreak sweep queued -- {len(_scanner.JAILBREAK_MODES)} modes x {len(req.models)} models x {len(req.vulnerabilities or [])} vulns",
    )

# -- Preview (dry-run) --------------------------------------------------------

@router.post("/preview")
async def preview_scan(req: ScanRequest):
    """Return the prompts that would be sent without calling any LLM."""
    return _scanner.preview_scan(
        models          = req.models,
        vulnerabilities = req.vulnerabilities,
        override_mode   = req.override_mode,
        prompt_count    = req.prompt_count,
        use_mutations   = req.use_mutations,
    )
