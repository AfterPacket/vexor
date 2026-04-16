from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class VulnSummary(BaseModel):
    vulnerability:  str
    vulnerable:     bool
    bypass_rate:    float
    bypass_count:   int
    total_probes:   int


class ModelReport(BaseModel):
    model:    str
    vulns:    List[VulnSummary]
    overall_bypass_rate: float
    total_vulnerable:    int
    total_clean:         int


class ScanReport(BaseModel):
    scan_id:         str
    status:          str
    override_mode:   str
    elapsed_seconds: Optional[float]
    errors:          List[str]
    models:          List[ModelReport]
    raw:             Optional[Dict[str, Any]] = None
