#!/usr/bin/env python3
"""
Scan routes
POST /api/scan/run              — start a single scan (background task)
GET  /api/scan/{scan_id}        — poll status / results
GET  /api/scan/{scan_id}/export — download results as JSON or CSV
POST /api/scan/batch            — start a batch of scans
GET  /api/scan/batch/{id}       — poll batch status
GET  /api/scan/history          — list all persisted scans
POST /api/scan/preview          — dry-run (no LLM calls)
"""

import asyncio
import csv
import io
import json
import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request
from fastapi.responses import Response, StreamingResponse

from api.schemas.scan import (
    BatchScanRequest, BatchScanStatus,
    ScanRequest, ScanResponse, ScanStatusResponse,
)
from core.scanner import Scanner, ScanStatus

router = APIRouter()
_scanner = Scanner()

# ── Disk persistence ──────────────────────────────────────────────────────────
_SCANS_DIR = Path(__file__).parent.parent.parent / "exploits" / "scans"
_SCANS_DIR.mkdir(parents=True, exist_ok=True)

_TERMINAL_STATUSES = {ScanStatus.COMPLETED.value, ScanStatus.FAILED.value, ScanStatus.CANCELLED.value}


def _persist_scan(data: dict) -> None:
    """Write a completed scan dict to exploits/scans/{scan_id}.json."""
    try:
        path = _SCANS_DIR / f"{data['scan_id']}.json"
        tmp  = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data))
        tmp.replace(path)
    except Exception:
        pass


def _load_scan_from_disk(scan_id: str) -> Optional[dict]:
    path = _SCANS_DIR / f"{scan_id}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def load_all_scans_from_disk(store: dict) -> int:
    """Load all persisted scans into store on startup. Returns count loaded."""
    loaded = 0
    for f in sorted(_SCANS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime):
        try:
            data = json.loads(f.read_text())
            sid  = data.get("scan_id")
            if sid and sid not in store:
                store[sid] = data
                loaded += 1
        except Exception:
            pass
    return loaded


def _to_csv(data: dict) -> str:
    out = io.StringIO()
    w   = csv.writer(out)
    w.writerow([
        "scan_id", "model", "vulnerability",
        "bypass_count", "total_probes", "bypass_rate",
        "prompt", "response", "bypassed",
        "override_mode", "mutation", "latency_ms",
    ])
    sid = data.get("scan_id", "")
    for model, vr_list in (data.get("results") or {}).items():
        for vr in (vr_list or []):
            for p in (vr.get("probes") or []):
                w.writerow([
                    sid, model, vr.get("vulnerability", ""),
                    vr.get("bypass_count", ""), vr.get("total_probes", ""),
                    vr.get("bypass_rate", ""),
                    (p.get("prompt") or "")[:500],
                    (p.get("response") or "")[:500],
                    p.get("bypassed", False),
                    p.get("override_mode", ""),
                    p.get("mutation", "") or "",
                    p.get("latency_ms", ""),
                ])
    return out.getvalue()


# ── helpers ───────────────────────────────────────────────────────────────────

def _get_store(request: Request) -> dict:
    return request.app.state.scan_store


def _get_batch_store(request: Request) -> dict:
    return request.app.state.batch_store


async def _run_job(scan_id: str, store: dict):
    job = store.get(scan_id)
    if job is None:
        return
    await _scanner.run_scan(job)
    if job.status.value in _TERMINAL_STATUSES:
        data = job.to_dict()
        _persist_scan(data)
        store[scan_id] = data  # replace live ScanJob with plain dict to free memory


# ── Single scan ───────────────────────────────────────────────────────────────

@router.post("/run", response_model=ScanResponse, status_code=202)
async def start_scan(
    req: ScanRequest,
    background_tasks: BackgroundTasks,
    request: Request,
):
    store = _get_store(request)
    job   = _scanner.create_scan_job(
        models          = req.models,
        vulnerabilities = req.vulnerabilities,
        override_mode   = req.override_mode,
        prompt_count    = req.prompt_count,
        use_mutations   = req.use_mutations,
    )
    store[job.scan_id] = job
    background_tasks.add_task(_run_job, job.scan_id, store)
    return ScanResponse(scan_id=job.scan_id, status="pending", message="Scan queued")


@router.get("/history", summary="List all persisted scans")
async def list_scan_history(request: Request):
    """Return summary of all persisted + in-memory scans."""
    store = _get_store(request)
    items = []
    seen  = set()
    # In-memory first (may be running)
    for sid, obj in store.items():
        d = obj if isinstance(obj, dict) else obj.to_dict()
        items.append({
            "scan_id":        d.get("scan_id", sid),
            "status":         d.get("status", "unknown"),
            "models":         d.get("models", []),
            "vulnerabilities":d.get("vulnerabilities", []),
            "override_mode":  d.get("override_mode", "none"),
            "total_probes":   d.get("total_probes", 0),
            "bypasses":       d.get("bypasses", 0),
            "elapsed_seconds":d.get("elapsed_seconds"),
        })
        seen.add(sid)
    # Disk — fill in anything not already in memory
    for f in sorted(_SCANS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            d = json.loads(f.read_text())
            sid = d.get("scan_id", f.stem)
            if sid in seen:
                continue
            items.append({
                "scan_id":        sid,
                "status":         d.get("status", "unknown"),
                "models":         d.get("models", []),
                "vulnerabilities":d.get("vulnerabilities", []),
                "override_mode":  d.get("override_mode", "none"),
                "total_probes":   d.get("total_probes", 0),
                "bypasses":       d.get("bypasses", 0),
                "elapsed_seconds":d.get("elapsed_seconds"),
            })
            seen.add(sid)
        except Exception:
            pass
    items.sort(key=lambda x: x.get("scan_id", ""), reverse=True)
    return {"scans": items, "total": len(items)}


@router.get("/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str, request: Request):
    store = _get_store(request)
    obj   = store.get(scan_id)
    if obj is None:
        # Fall back to disk
        obj = _load_scan_from_disk(scan_id)
        if obj is None:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
        store[scan_id] = obj  # cache back in memory
    d = obj if isinstance(obj, dict) else obj.to_dict()
    return ScanStatusResponse(**d)


@router.get("/{scan_id}/export")
async def export_scan(
    scan_id: str,
    request: Request,
    fmt: str = Query(default="json", regex="^(json|csv)$"),
):
    """Download scan results as JSON or CSV."""
    store = _get_store(request)
    obj   = store.get(scan_id)
    if obj is None:
        obj = _load_scan_from_disk(scan_id)
    if obj is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
    data = obj if isinstance(obj, dict) else obj.to_dict()

    if fmt == "csv":
        content = _to_csv(data)
        return Response(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="scan_{scan_id[:8]}.csv"'},
        )
    content = json.dumps(data, indent=2)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="scan_{scan_id[:8]}.json"'},
    )


@router.post("/{scan_id}/cancel", status_code=200)
async def cancel_scan(scan_id: str, request: Request):
    store = _get_store(request)
    job   = store.get(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
    if isinstance(job, dict):
        return {"scan_id": scan_id, "status": job.get("status", "unknown")}
    job.cancelled = True
    for t in list(job.active_tasks):
        t.cancel()
    return {"scan_id": scan_id, "status": "cancelling"}


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(scan_id: str, request: Request):
    store = _get_store(request)
    if scan_id not in store:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
    del store[scan_id]


# ── Batch scan ────────────────────────────────────────────────────────────────

async def _run_batch(batch_id: str, reqs: list, scan_ids: list, store: dict, batch_store: dict):
    for scan_id, req in zip(scan_ids, reqs):
        job = store.get(scan_id)
        if job:
            await _scanner.run_scan(job)
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
        job = _scanner.create_scan_job(
            models          = scan_req.models,
            vulnerabilities = scan_req.vulnerabilities,
            override_mode   = scan_req.override_mode,
            prompt_count    = scan_req.prompt_count,
            use_mutations   = scan_req.use_mutations,
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


# ── Jailbreak sweep ──────────────────────────────────────────────────────────

async def _run_jailbreak_job(scan_id: str, store: dict):
    job = store.get(scan_id)
    if job is None:
        return
    await _scanner.run_jailbreak_scan(job)


@router.post("/jailbreak", response_model=ScanResponse, status_code=202,
             summary="Jailbreak sweep — auto-cycles all override modes per probe")
async def start_jailbreak_scan(
    req: ScanRequest,
    background_tasks: BackgroundTasks,
    request: Request,
):
    """
    Run a jailbreak sweep scan.  For each prompt the scanner automatically
    tries every known override/persona mode (DAN, GodMode, AIM, STAN, DUDE,
    Evil Confidant, Claude Bypass, GPT Bypass, sudo, translator, …) and
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
        message = f"Jailbreak sweep queued — {len(_scanner.JAILBREAK_MODES)} modes × {len(req.models)} models × {len(req.vulnerabilities or [])} vulns",
    )


# ── Preview (dry-run) ─────────────────────────────────────────────────────────

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
