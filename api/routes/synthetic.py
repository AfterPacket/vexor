#!/usr/bin/env python3
"""
Synthetic data routes
GET  /api/synthetic/complexity               — list all complexity levels
GET  /api/synthetic/complexity/{level}       — describe one level
POST /api/synthetic/generate                 — generate prompts at one complexity
POST /api/synthetic/generate/batch           — generate across a range of levels
POST /api/synthetic/generate/all-vulns       — generate for all OWASP vulns
POST /api/synthetic/generate/llm             — use local LLM to produce novel variants
POST /api/synthetic/export                   — save generated prompts to effective_prompts.json
"""

from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException

from api.schemas.synthetic import (
    ComplexityDescription,
    ExportRequest,
    GenerateAllVulnsRequest,
    GenerateBatchRequest,
    GenerateSyntheticRequest,
    GenerateSyntheticResponse,
    LLMGenerateRequest,
    SyntheticPromptEntry,
)
from core.synthetic_data import SyntheticDataGenerator

router    = APIRouter()
_gen      = SyntheticDataGenerator()


# ── Complexity catalogue ──────────────────────────────────────────────────────

@router.get("/complexity", response_model=List[ComplexityDescription])
async def list_complexity_levels():
    """Return descriptions of all 10 complexity levels."""
    return _gen.list_complexity_levels()


@router.get("/complexity/{level}", response_model=ComplexityDescription)
async def get_complexity_level(level: int):
    if not 1 <= level <= 10:
        raise HTTPException(status_code=400, detail="Level must be between 1 and 10")
    return _gen.describe_complexity(level)


# ── Single-complexity generation ──────────────────────────────────────────────

@router.post("/generate", response_model=GenerateSyntheticResponse)
async def generate_synthetic(req: GenerateSyntheticRequest):
    """
    Generate attack prompts at a single complexity level.

    - **complexity 1-2**: raw prompts, no modification
    - **complexity 3-4**: character encoding (leet, base64)
    - **complexity 5-6**: + override persona (DAN, GodMode)
    - **complexity 7-8**: + many-shot normalization chain
    - **complexity 9-10**: + layered framing, nested personas, double encoding
    """
    items = _gen.generate(
        vulnerability = req.vulnerability,
        complexity    = req.complexity,
        count         = req.count,
        model_hint    = req.model_hint,
        seed_prompts  = req.seed_prompts,
    )
    return GenerateSyntheticResponse(
        vulnerability = req.vulnerability,
        complexity    = req.complexity,
        count         = len(items),
        prompts       = [SyntheticPromptEntry(**i) for i in items],
    )


# ── Batch (range of complexity levels) ───────────────────────────────────────

@router.post("/generate/batch")
async def generate_batch(req: GenerateBatchRequest):
    """
    Generate prompts across a range of complexity levels.
    Returns a dict mapping level → list of prompt entries.
    Useful for building a progressive test suite.
    """
    if req.complexity_min > req.complexity_max:
        raise HTTPException(status_code=400,
                            detail="complexity_min must be <= complexity_max")
    results = _gen.generate_batch(
        vulnerability    = req.vulnerability,
        complexity_range = (req.complexity_min, req.complexity_max),
        count_per_level  = req.count_per_level,
        model_hint       = req.model_hint,
    )
    # Convert int keys to strings for JSON serialisation
    return {str(k): v for k, v in results.items()}


# ── All OWASP vulns ───────────────────────────────────────────────────────────

@router.post("/generate/all-vulns")
async def generate_all_vulns(req: GenerateAllVulnsRequest):
    """
    Generate prompts for every OWASP GenAI vulnerability at one complexity level.
    Returns a dict mapping vulnerability key → list of prompt entries.
    """
    results = _gen.generate_all_vulns(
        complexity      = req.complexity,
        count_per_vuln  = req.count_per_vuln,
        vulnerabilities = req.vulnerabilities,
        model_hint      = req.model_hint,
    )
    return results


# ── LLM-assisted generation ───────────────────────────────────────────────────

@router.post("/generate/llm")
async def generate_with_llm(req: LLMGenerateRequest):
    """
    Use a local Ollama model to generate novel prompt variants.
    The LLM is prompted to rephrase and reframe a base prompt in
    `count` meaningfully different ways, then complexity techniques are applied.
    Falls back to rule-based generation if Ollama is unavailable.
    """
    items = _gen.llm_generate(
        vulnerability = req.vulnerability,
        base_prompt   = req.base_prompt,
        count         = req.count,
        model         = req.model,
        complexity    = req.complexity,
    )
    return {
        "vulnerability": req.vulnerability,
        "model_used":    req.model,
        "complexity":    req.complexity,
        "count":         len(items),
        "prompts":       items,
    }


# ── Export to exploits DB ─────────────────────────────────────────────────────

@router.post("/export")
async def export_to_exploits(req: ExportRequest):
    """
    Append generated prompts to exploits/effective_prompts.json.
    The prompts will then be used automatically by future scans against
    models matching the model_key.
    """
    added = _gen.export_to_exploits(
        prompts   = req.prompts,
        model_key = req.model_key,
    )
    return {
        "message":   f"Added {added} new prompts to effective_prompts.json",
        "added":     added,
        "model_key": req.model_key,
    }


# ── Quick complexity preview ──────────────────────────────────────────────────

@router.get("/preview/{vulnerability}/{complexity}")
async def preview_complexity(vulnerability: str, complexity: int):
    """
    Preview one generated prompt at the given complexity level.
    Useful for eyeballing what each level looks like before running a full scan.
    """
    if not 1 <= complexity <= 10:
        raise HTTPException(status_code=400, detail="Complexity must be 1-10")
    items = _gen.generate(vulnerability, complexity=complexity, count=1)
    if not items:
        raise HTTPException(status_code=404,
                            detail=f"No prompts found for {vulnerability}")
    item = items[0]
    desc = _gen.describe_complexity(complexity)
    return {
        "vulnerability":  vulnerability,
        "complexity":     complexity,
        "description":    desc["description"],
        "techniques":     item["techniques"],
        "base_prompt":    item["base_prompt"][:200],
        "final_prompt":   item["prompt"][:500],
        "full_prompt_length": len(item["prompt"]),
    }
