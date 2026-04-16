#!/usr/bin/env python3
"""
Scan routes
POST /api/scan/run         — start a single scan (background task)
GET  /api/scan/{scan_id}   — poll status / results
POST /api/scan/batch       — start a batch of scans
GET  /api/scan/batch/{id}  — poll batch status
POST /api/scan/preview     — dry-run (no LLM calls)
"""

import asyncio
import uuid
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request

from api.schemas.scan import (
    BatchScanRequest, BatchScanStatus,
    ScanRequest, ScanResponse, ScanStatusResponse,
)
from core.scanner import Scanner, ScanStatus

router = APIRouter()
_scanner = Scanner()


# ── helpers ───────────────────────────────────────────────────────────────────

def _get_store(request: Request) -> dict:
    return request.app.state.scan_store


def _get_batch_store(request: Request) -> dict:
    return request.app.state.batch_store


async def _run_job(scan_id: str, req: ScanRequest, store: dict):
    job = store.get(scan_id)
    if job is None:
        return
    await _scanner.run_scan(job)


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
    background_tasks.add_task(_run_job, job.scan_id, req, store)
    return ScanResponse(scan_id=job.scan_id, status="pending", message="Scan queued")


@router.get("/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str, request: Request):
    store = _get_store(request)
    job   = store.get(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
    d = job.to_dict()
    return ScanStatusResponse(**d)


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
