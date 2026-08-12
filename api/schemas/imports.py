from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class ImportStatsResponse(BaseModel):
    added:              int
    skipped_duplicates: int
    mutations_added:    int
    models_found:       List[str]
    vulns_covered:      List[str]
    total_bypassed:     int
    total_results:      int
    source_label:       Optional[str] = None
    winning_modes:      Optional[Dict[str, List[str]]] = None


class ExploitsStatsResponse(BaseModel):
    total_prompts:  int
    total_models:   int
    total_vulns:    int
    by_model:       Dict[str, int]
    by_vuln:        Dict[str, int]
    winning_modes:  Dict[str, List[str]] = {}
