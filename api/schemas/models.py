from __future__ import annotations

from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class ModelInfo(BaseModel):
    model_id:  str
    provider:  str
    available: bool
    aliases:   List[str] = []


class ModelsListResponse(BaseModel):
    models:   List[ModelInfo]
    total:    int


class ModelTestRequest(BaseModel):
    model:   str
    prompt:  str = Field(default="Hello, respond with one word.")
    system:  Optional[str] = None


class ModelTestResponse(BaseModel):
    model:      str
    response:   str
    latency_ms: float
    success:    bool
    error:      Optional[str] = None
