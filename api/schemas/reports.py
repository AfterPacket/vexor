from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class VulnSummary(BaseModel):
    vulnerability:  str
    vulnerable:     bool
    bypass_rate:    float
    bypass_count:   int
    heuristic_positive_count: int = 0
    finding_status: str = "unvalidated"
    total_probes:   int
    evaluation_status: str = "not_evaluated"
    evaluated_probes: int = 0
    not_evaluated_probes: int = 0


class ModelReport(BaseModel):
    model:    str
    vulns:    List[VulnSummary]
    overall_bypass_rate: float
    total_vulnerable:    int
    total_clean:         int
    total_not_evaluated: int = 0
    total_partial: int = 0
    total_unvalidated: int = 0


class ScanReport(BaseModel):
    scan_id:         str
    status:          str
    override_mode:   str
    elapsed_seconds: Optional[float]
    errors:          List[str]
    models:          List[ModelReport]
    mode_stats:      List[Dict[str, Any]] = []
    raw:             Optional[Dict[str, Any]] = None
    finding_count_basis: str = "independent_validation"
