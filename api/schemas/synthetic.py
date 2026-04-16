from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field


class GenerateSyntheticRequest(BaseModel):
    vulnerability:  str  = Field(..., description="OWASP key, e.g. llm01")
    complexity:     int  = Field(default=5, ge=1, le=10,
                                  description="1=raw prompt, 10=maximum obfuscation")
    count:          int  = Field(default=10, ge=1, le=100)
    model_hint:     Optional[str]       = None
    seed_prompts:   Optional[List[str]] = None


class GenerateBatchRequest(BaseModel):
    vulnerability:       str            = Field(..., description="OWASP key")
    complexity_min:      int            = Field(default=1, ge=1, le=10)
    complexity_max:      int            = Field(default=10, ge=1, le=10)
    count_per_level:     int            = Field(default=3, ge=1, le=20)
    model_hint:          Optional[str]  = None


class GenerateAllVulnsRequest(BaseModel):
    complexity:          int            = Field(default=5, ge=1, le=10)
    count_per_vuln:      int            = Field(default=5, ge=1, le=20)
    vulnerabilities:     Optional[List[str]] = None
    model_hint:          Optional[str]  = None


class LLMGenerateRequest(BaseModel):
    vulnerability:  str           = Field(..., description="OWASP key")
    base_prompt:    str           = Field(..., description="Seed prompt to vary")
    count:          int           = Field(default=5, ge=1, le=20)
    model:          str           = Field(default="llama3.1",
                                          description="Ollama model to use for generation")
    complexity:     int           = Field(default=5, ge=1, le=10)


class ExportRequest(BaseModel):
    prompts:        List[Dict[str, Any]]
    model_key:      str = Field(default="synthetic")


class SyntheticPromptEntry(BaseModel):
    prompt:         str
    base_prompt:    str
    complexity:     int
    techniques:     List[str]
    vulnerability:  str
    source:         Optional[str] = None


class GenerateSyntheticResponse(BaseModel):
    vulnerability:  str
    complexity:     int
    count:          int
    prompts:        List[SyntheticPromptEntry]


class ComplexityDescription(BaseModel):
    level:          int
    description:    str
    techniques:     Dict[str, Any]
