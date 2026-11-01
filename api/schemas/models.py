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
    requested_model: Optional[str] = None
    requested_provider: Optional[str] = None
    dispatched_provider: Optional[str] = None
    dispatched_model: Optional[str] = None
    reported_model: Optional[str] = None
    finish_reason: Optional[str] = None
    outcome: str = "unknown"
    failure_kind: Optional[str] = None
    evaluation_status: str = "not_evaluated"
    reported_model_differs: Optional[bool] = None
