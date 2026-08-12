#!/usr/bin/env python3
"""
Import routes
POST /api/import/promptfoo          — upload a PromptFoo result file
POST /api/import/promptfoo/json     — submit raw JSON/dict body
GET  /api/import/stats              — current effective_prompts.json summary
GET  /api/import/extracted          — list all extracted bypassed prompts (paginated)
POST /api/import/inject             — create a scan job from extracted prompts
DELETE /api/import/reset            — wipe effective_prompts.json
"""

import json
import os
import re
import uuid
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, Query, Request, UploadFile
from pydantic import BaseModel, Field

from api.schemas.imports import ExploitsStatsResponse, ImportStatsResponse
from core.promptfoo_importer import PromptFooImporter
from core.scanner import Scanner, ScanStatus

router    = APIRouter()
_importer = PromptFooImporter()
_scanner  = Scanner()

# ── In-memory cache of last import's extracted prompts (per process) ──────────
_last_extracted: List[dict] = []

# ── Sanitization ──────────────────────────────────────────────────────────────

_VULN_RE    = re.compile(r'^[a-z][a-z0-9_-]{0,19}$')
_MODE_RE    = re.compile(r'^[a-z0-9_-]{1,50}$')
_MAX_PROMPT = 20_000   # chars
_MAX_BATCH  = 500      # prompts per request


def _sanitize_custom_prompts(prompts: Optional[List[dict]]) -> List[dict]:
    """
    Validate structure and sanitize each custom prompt entry.

    NOTE: prompt text is NOT HTML-stripped here — these are intentional attack
    payloads and may legitimately contain angle-brackets, script tags, etc.
    XSS prevention is the UI's responsibility (escHtml on render).
    This function enforces length limits and field-type correctness only.
    """
    if not prompts:
        return []
    out: List[dict] = []
    for p in prompts[:_MAX_BATCH]:
        if not isinstance(p, dict):
            continue
        text = str(p.get("prompt", "")).strip()
        if not text or len(text) > _MAX_PROMPT:
            continue
        vuln = str(p.get("vulnerability", "llm01")).lower().strip()
        if not _VULN_RE.match(vuln):
            vuln = "llm01"
        mode = str(p.get("winning_mode", "none")).lower().strip()
        if not _MODE_RE.match(mode):
            mode = "none"
        sr = p.get("success_rate", 0.0)
        out.append({
            "prompt":        text,
            "vulnerability": vuln,
            "source":        "custom",
            "model_key":     str(p.get("model_key", ""))[:200],
            "winning_mode":  mode,
            "success_rate":  float(sr) if isinstance(sr, (int, float)) else 0.0,
        })
    return out


# ── Schemas ───────────────────────────────────────────────────────────────────

class InjectionRequest(BaseModel):
    models:        List[str] = Field(..., min_length=1)
    override_mode: str       = Field(default="none")
    source_label:  Optional[str]  = None
    custom_prompts: Optional[List[dict]] = None


class AutoPwnInjectionRequest(BaseModel):
    models:         List[str]           = Field(..., min_length=1)
    source_label:   Optional[str]       = None
    vulns:          Optional[List[str]] = None          # None = all LLM01-10
    custom_prompts: Optional[List[dict]] = None         # additional user-supplied prompts


class GenerateSuiteRequest(BaseModel):
    models:        List[str]           = Field(..., min_length=1)
    vulns:         Optional[List[str]] = None
    max_per_vuln:  int                 = Field(default=5, ge=1, le=20)
    run_scan:      bool                = Field(default=True, description="Also queue an AutoPwn scan")
    extra_prompts: Optional[List[dict]] = None          # additional user-supplied seed prompts


class InjectionPreviewResponse(BaseModel):
    total_prompts:  int
    models:         List[str]
    vulns_covered:  List[str]
    prompts_sample: List[dict]   # first 10 entries
    scan_id:        Optional[str] = None
    message:        str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_extracted_from_db(source_label: Optional[str] = None) -> List[dict]:
    """Flatten effective_prompts.json into a list of injection-ready dicts."""
    db = _importer._load_exploits()
    ep = db.get("effective_prompts", {})
    out: List[dict] = []
    for model_key, vulns in ep.items():
        for vuln, entries in vulns.items():
            for entry in entries:
                if source_label and entry.get("source", "") != source_label:
                    if not entry.get("source", "").startswith(source_label):
                        continue
                out.append({
                    "prompt":        entry.get("prompt", ""),
                    "vulnerability": vuln,
                    "source":        entry.get("source", ""),
                    "model_key":     model_key,
                    "success_rate":  entry.get("success_rate", 0.0),
                })
    return out


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/promptfoo", response_model=ImportStatsResponse)
async def import_promptfoo_file(
    file: UploadFile = File(..., description="PromptFoo JSON or YAML result file"),
    source_label: str = "promptfoo_upload",
):
    """Accept a PromptFoo result file and import bypassed prompts into the exploits DB."""
    global _last_extracted
    contents = await file.read()
    try:
        raw = contents.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded")

    try:
        stats = _importer.import_raw(raw, source_label=source_label)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Import failed: {e}")

    _last_extracted = _load_extracted_from_db(source_label)
    return ImportStatsResponse(**stats, source_label=source_label)


@router.post("/promptfoo/json", response_model=ImportStatsResponse)
async def import_promptfoo_json(payload: dict, source_label: str = "promptfoo_api"):
    """Submit already-parsed PromptFoo JSON as a request body dict."""
    global _last_extracted
    try:
        stats = _importer.import_raw(payload, source_label=source_label)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Import failed: {e}")

    _last_extracted = _load_extracted_from_db(source_label)
    return ImportStatsResponse(**stats, source_label=source_label)


@router.get("/stats", response_model=ExploitsStatsResponse)
async def get_import_stats():
    """Return summary of all stored effective prompts."""
    return ExploitsStatsResponse(**_importer.get_stats())


@router.get("/extracted")
async def list_extracted_prompts(
    source: Optional[str] = Query(None, description="Filter by source label"),
    vuln:   Optional[str] = Query(None, description="Filter by vulnerability key"),
    limit:  int           = Query(50, ge=1, le=500),
    offset: int           = Query(0, ge=0),
):
    """
    Return all bypassed prompts stored in the exploits DB.
    Useful for reviewing what will be used in an injection scan.
    """
    prompts = _load_extracted_from_db(source)
    if vuln:
        prompts = [p for p in prompts if p.get("vulnerability") == vuln]
    total = len(prompts)
    page  = prompts[offset : offset + limit]
    return {
        "total":   total,
        "offset":  offset,
        "limit":   limit,
        "prompts": page,
    }


@router.post("/inject", response_model=InjectionPreviewResponse)
async def create_injection_scan(
    req: InjectionRequest,
    background_tasks: BackgroundTasks,
    request: Request,
):
    """
    Create an injection scan from previously imported PromptFoo bypassed prompts.

    1. Loads all prompts in effective_prompts.json (filtered by source_label if given)
    2. Optionally accepts custom_prompts to override the DB contents
    3. Builds a ScanJob and queues it in the background
    4. Returns a preview + scan_id for polling
    """
    store = request.app.state.scan_store

    # Decide which prompts to use
    if req.custom_prompts:
        prompts = req.custom_prompts
    else:
        prompts = _load_extracted_from_db(req.source_label)

    if not prompts:
        raise HTTPException(
            status_code=404,
            detail=(
                "No extracted prompts found. "
                "Upload a PromptFoo results file first via POST /api/import/promptfoo, "
                "or provide custom_prompts in the request body."
            ),
        )

    # De-duplicate by prompt text
    seen: set = set()
    deduped: List[dict] = []
    for p in prompts:
        txt = p.get("prompt", "")
        if txt and txt not in seen:
            seen.add(txt)
            deduped.append(p)

    vulns_covered = list({p.get("vulnerability", "llm01") for p in deduped})

    job = _scanner.create_injection_job(
        models         = req.models,
        custom_prompts = deduped,
        override_mode  = req.override_mode,
        label          = req.source_label or "injection",
    )
    store[job.scan_id] = job

    async def _run():
        await _scanner.run_injection_scan(job)

    background_tasks.add_task(_run)

    return InjectionPreviewResponse(
        total_prompts  = len(deduped),
        models         = req.models,
        vulns_covered  = vulns_covered,
        prompts_sample = deduped[:10],
        scan_id        = job.scan_id,
        message        = (
            f"Injection scan queued: {len(deduped)} prompts × "
            f"{len(req.models)} models = {len(deduped) * len(req.models)} probes. "
            f"Poll GET /api/scan/{job.scan_id} for results."
        ),
    )


@router.post("/autopwn", response_model=InjectionPreviewResponse,
             summary="AutoPwn injection — imported prompts + model-aware mode ordering")
async def create_autopwn_scan(
    req: AutoPwnInjectionRequest,
    background_tasks: BackgroundTasks,
    request: Request,
):
    """
    Combine the PromptFoo import DB with AutoPwn mode selection:
      1. Loads all imported bypass prompts (filtered by source_label/vulns)
      2. Injects winning_mode from the import DB — each prompt tries its known
         winning mode FIRST before falling through the model-specific suite
      3. Prepends any per-model winning modes discovered in past imports
      4. Queues a background scan and returns scan_id
    """
    store = request.app.state.scan_store
    prompts = _load_extracted_from_db(req.source_label)

    if req.vulns:
        prompts = [p for p in prompts if p.get("vulnerability") in req.vulns]

    # Merge sanitized user-supplied prompts (they take priority — prepended)
    extra = _sanitize_custom_prompts(req.custom_prompts)
    prompts = extra + prompts

    if not prompts:
        raise HTTPException(
            status_code=404,
            detail=(
                "No prompts found. Upload PromptFoo results first via POST /api/import/promptfoo "
                "or supply custom_prompts in the request body."
            ),
        )

    seen: set = set()
    deduped: List[dict] = []
    for p in prompts:
        txt = p.get("prompt", "")
        if txt and txt not in seen:
            seen.add(txt)
            deduped.append(p)

    # Pull per-model winning modes from the import DB
    stats = _importer.get_stats()
    extra_winning_modes = stats.get("winning_modes", {})

    vulns_covered = list({p.get("vulnerability", "llm01") for p in deduped})

    job = _scanner.create_autopwn_injection_job(
        models         = req.models,
        custom_prompts = deduped,
        label          = req.source_label or "autopwn_injection",
    )
    store[job.scan_id] = job

    async def _run():
        await _scanner.run_autopwn_injection_scan(job, extra_winning_modes=extra_winning_modes)

    background_tasks.add_task(_run)

    return InjectionPreviewResponse(
        total_prompts  = len(deduped),
        models         = req.models,
        vulns_covered  = vulns_covered,
        prompts_sample = deduped[:10],
        scan_id        = job.scan_id,
        message        = (
            f"AutoPwn injection queued: {len(deduped)} prompts × "
            f"{len(req.models)} models. Winning modes from imports prepended. "
            f"Poll GET /api/scan/{job.scan_id}"
        ),
    )


@router.post("/generate-suite",
             summary="Generate full LLM01–LLM10 attack suite from imported patterns")
async def generate_attack_suite(
    req: GenerateSuiteRequest,
    background_tasks: BackgroundTasks,
    request: Request,
):
    """
    Build a complete LLM01–LLM10 attack suite for the requested models:
      1. Uses imported bypass prompts as primary source
      2. Cross-pollinates from other models where gaps exist
      3. Fills remaining gaps with seeded attack templates
      4. Optionally immediately queues an AutoPwn scan on the generated suite

    Returns the generated prompts + optional scan_id.
    """
    suite = _importer.generate_attack_suite(
        models        = req.models,
        vulns         = req.vulns,
        max_per_vuln  = req.max_per_vuln,
        extra_prompts = _sanitize_custom_prompts(req.extra_prompts),
    )

    if not suite:
        raise HTTPException(status_code=500, detail="Suite generation returned empty result")

    scan_id = None
    if req.run_scan:
        store = request.app.state.scan_store
        stats = _importer.get_stats()
        extra_winning_modes = stats.get("winning_modes", {})

        job = _scanner.create_autopwn_injection_job(
            models         = req.models,
            custom_prompts = suite,
            label          = "generated_suite",
        )
        store[job.scan_id] = job
        scan_id = job.scan_id

        async def _run():
            await _scanner.run_autopwn_injection_scan(job, extra_winning_modes=extra_winning_modes)

        background_tasks.add_task(_run)

    # Group by vuln for the response summary
    by_vuln: dict = {}
    for p in suite:
        v = p["vulnerability"]
        by_vuln.setdefault(v, 0)
        by_vuln[v] += 1

    return {
        "total_prompts":   len(suite),
        "models":          req.models,
        "vulns_covered":   list(by_vuln.keys()),
        "prompts_by_vuln": by_vuln,
        "scan_id":         scan_id,
        "prompts":         suite,
        "message": (
            f"Generated {len(suite)} prompts across {len(by_vuln)} vulnerabilities. "
            + (f"AutoPwn scan queued: {scan_id}" if scan_id else "No scan queued (run_scan=false).")
        ),
    }


@router.delete("/reset", status_code=204)
async def reset_exploits():
    """Wipe effective_prompts.json."""
    global _last_extracted
    path = _importer.exploits_path
    if os.path.exists(path):
        os.remove(path)
    _last_extracted = []
