from __future__ import annotations

from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class GeneratePromptsRequest(BaseModel):
    vulnerability: str = Field(..., description="e.g. llm01")
    model:         Optional[str] = None
    count:         int = Field(default=10, ge=1, le=100)
    shuffle:       bool = True


class GeneratePromptsResponse(BaseModel):
    vulnerability: str
    model:         Optional[str]
    prompts:       List[str]
    total:         int


class MutatePromptRequest(BaseModel):
    prompt:     str
    techniques: Optional[List[str]] = Field(
        default=None,
        description="Subset of mutation technique names. Omit for all.",
    )


class MutatePromptResponse(BaseModel):
    original:   str
    variants:   Dict[str, str]
    techniques: List[str]


class VulnInfoResponse(BaseModel):
    id:          str
    name:        str
    description: str
    impact:      str
    mitigation:  str
