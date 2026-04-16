#!/usr/bin/env python3
"""
Prompt routes
GET  /api/prompts                  — list all vulnerability modules
GET  /api/prompts/{vuln}           — info for one vulnerability
POST /api/prompts/generate         — generate attack prompts
POST /api/prompts/mutate           — mutate a single prompt
GET  /api/prompts/mutations        — list available mutation techniques
"""

from fastapi import APIRouter, HTTPException

from api.schemas.prompts import (
    GeneratePromptsRequest, GeneratePromptsResponse,
    MutatePromptRequest, MutatePromptResponse,
    VulnInfoResponse,
)
from core.prompt_engine import ALL_VULNS, PromptEngine

router = APIRouter()
_engine = PromptEngine()


@router.get("")
async def list_vulnerabilities():
    """Return metadata for every OWASP GenAI vulnerability module."""
    result = []
    for vuln in ALL_VULNS:
        info = _engine.get_module_info(vuln)
        if info:
            result.append(info)
        else:
            result.append({"id": vuln.upper(), "name": vuln, "description": "", "impact": "", "mitigation": ""})
    return {"vulnerabilities": result, "total": len(result)}


@router.get("/mutations")
async def list_mutations():
    """List all available prompt mutation technique names."""
    return {"techniques": _engine.available_mutations()}


@router.get("/{vulnerability}", response_model=VulnInfoResponse)
async def get_vulnerability_info(vulnerability: str):
    info = _engine.get_module_info(vulnerability.lower())
    if info is None:
        raise HTTPException(status_code=404, detail=f"Vulnerability {vulnerability!r} not found")
    return VulnInfoResponse(**info)


@router.post("/generate", response_model=GeneratePromptsResponse)
async def generate_prompts(req: GeneratePromptsRequest):
    prompts = _engine.get_prompts(
        req.vulnerability,
        model   = req.model,
        count   = req.count,
        shuffle = req.shuffle,
    )
    if not prompts:
        raise HTTPException(
            status_code=404,
            detail=f"No prompts found for vulnerability {req.vulnerability!r}",
        )
    return GeneratePromptsResponse(
        vulnerability = req.vulnerability,
        model         = req.model,
        prompts       = prompts,
        total         = len(prompts),
    )


@router.post("/mutate", response_model=MutatePromptResponse)
async def mutate_prompt(req: MutatePromptRequest):
    all_variants = _engine.mutate_prompt(req.prompt)
    if req.techniques:
        variants = {t: all_variants[t] for t in req.techniques if t in all_variants}
        unknown  = [t for t in req.techniques if t not in all_variants]
        if unknown:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown techniques: {unknown}. Valid: {list(all_variants)}",
            )
    else:
        variants = all_variants

    return MutatePromptResponse(
        original   = req.prompt,
        variants   = variants,
        techniques = list(variants.keys()),
    )
