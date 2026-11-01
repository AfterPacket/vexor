from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    models: List[str] = Field(..., min_length=1, description="Model IDs to scan")
    vulnerabilities: Optional[List[str]] = Field(
        default=None,
        description="OWASP GenAI vuln keys (llm01-llm10). Defaults to all.",
    )
    override_mode: str = Field(
        default="none",
        description="Jailbreak/override persona (none, dan, godmode, claude_bypass, …)",
    )
    override_modes: Optional[List[str]] = Field(
        default=None,
        description="When set, each prompt is tested against every mode in this list (cross-product). Overrides override_mode.",
    )
    prompt_count: int = Field(default=5, ge=1, le=50)
    use_mutations: bool = Field(
        default=False,
        description="Also send mutated variants of each base prompt",
    )
    include_autopwn: bool = Field(
        default=False,
        description="After regular probes, sweep non-bypassed prompts through full autopwn suite",
    )
    use_warm_pool: bool = Field(
        default=True,
        description="Prepend previously successful (warm pool) prompts for this model+vuln pair",
    )


class ProbeResultSchema(BaseModel):
    prompt:        str
    response:      str
    response_truncated: bool = False
    response_full_length: Optional[int] = None
    validation_status: str = "unvalidated"
    validation_evaluator: Optional[str] = None
    model_diagnostics: Dict[str, Any] = Field(default_factory=dict)
    evaluation_status: str = "not_evaluated"
    bypassed:      bool
    heuristic_positive: bool = False
    override_mode: str
    mutation:      Optional[str]
    latency_ms:    float
    error:         Optional[str]


class ModelVulnResultSchema(BaseModel):
    vulnerability: str
    bypass_rate:   float
    bypass_count:  int
    confirmed_bypass_count: int = 0
    heuristic_positive_count: int = 0
    finding_status: str = "unvalidated"
    total_probes:  int
    vulnerable:    bool
    evaluation_status: str = "not_evaluated"
    evaluated_probes: int = 0
    not_evaluated_probes: int = 0
    probes:        List[ProbeResultSchema]


class ScanResponse(BaseModel):
    scan_id:    str
    status:     str
    message:    str = "Scan started"


class ScanStatusResponse(BaseModel):
    scan_id:         str
    status:          str
    models:          List[str]
    vulnerabilities: List[str]
    override_mode:   str
    progress:        int
    elapsed_seconds: Optional[float]
    errors:          List[str]
    total_probes:    int = 0
    bypasses:        int = 0
    heuristic_candidates: int = 0
    finding_count_basis: str = "independent_validation"
    mode_stats:       List[Dict[str, Any]] = []
    results:         Dict[str, List[Dict[str, Any]]]


class BatchScanRequest(BaseModel):
    scans: List[ScanRequest] = Field(..., min_length=1, max_length=20)
    label: Optional[str] = None


class BatchScanStatus(BaseModel):
    batch_id:   str
    label:      Optional[str]
    total:      int
    completed:  int
    failed:     int
    scan_ids:   List[str]
    status:     str
