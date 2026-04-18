from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel


class OverrideInfo(BaseModel):
    mode:            str
    label:           str
    description:     str
    target_models:   List[str]
    aggressiveness:  int   # 1-10


class OverridesListResponse(BaseModel):
    overrides: List[OverrideInfo]
    total:     int


class ApplyOverrideRequest(BaseModel):
    prompt:        str
    override_mode: str
    base_system:   Optional[str] = None


class ApplyOverrideResponse(BaseModel):
    original_prompt:  str
    wrapped_prompt:   str
    system_injection: str
    full_system:      str
    override_mode:    str


class RecommendedOverridesResponse(BaseModel):
    model:     str
    overrides: List[str]
