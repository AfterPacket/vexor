#!/usr/bin/env python3
"""
Override / jailbreak routes
GET  /api/overrides                     — list all override modes
POST /api/overrides/apply               — wrap a prompt with an override
GET  /api/overrides/recommend/{model}   — recommended overrides for a model
GET  /api/overrides/{mode}              — info for a specific override mode
"""

from fastapi import APIRouter, HTTPException

from api.schemas.overrides import (
    ApplyOverrideRequest, ApplyOverrideResponse,
    OverrideInfo, OverridesListResponse,
    RecommendedOverridesResponse,
)
from core.override_engine import OverrideEngine

router = APIRouter()
_engine = OverrideEngine()


@router.get("", response_model=OverridesListResponse)
async def list_overrides():
    items = _engine.list_overrides()
    return OverridesListResponse(
        overrides=[OverrideInfo(**o) for o in items],
        total=len(items),
    )


@router.post("/apply", response_model=ApplyOverrideResponse)
async def apply_override(req: ApplyOverrideRequest):
    override = _engine.get_override(req.override_mode)
    if override is None:
        raise HTTPException(
            status_code=404,
            detail=f"Override mode {req.override_mode!r} not found",
        )
    wrapped     = _engine.wrap_prompt(req.prompt, req.override_mode)
    system_inj  = _engine.get_system_injection(req.override_mode)
    full_system = _engine.build_full_system(req.base_system or "", req.override_mode)

    return ApplyOverrideResponse(
        original_prompt  = req.prompt,
        wrapped_prompt   = wrapped,
        system_injection = system_inj,
        full_system      = full_system,
        override_mode    = req.override_mode,
    )


@router.get("/recommend/{model:path}", response_model=RecommendedOverridesResponse)
async def recommend_overrides(model: str):
    recs = _engine.get_recommended_overrides(model)
    return RecommendedOverridesResponse(model=model, overrides=recs)


@router.get("/{mode}", response_model=OverrideInfo)
async def get_override_info(mode: str):
    items = {o["mode"]: o for o in _engine.list_overrides()}
    if mode not in items:
        raise HTTPException(status_code=404, detail=f"Override mode {mode!r} not found")
    return OverrideInfo(**items[mode])
