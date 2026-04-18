#!/usr/bin/env python3
"""
Discovery routes — self-learning engine endpoints.

GET  /api/discovery/insights          — full insights report
GET  /api/discovery/signatures        — discovered method signatures
GET  /api/discovery/warm-pool         — warm pool entries (filterable)
GET  /api/discovery/defense-map       — per-model refusal clusters
GET  /api/discovery/transfer-matrix   — cross-model transfer scores
GET  /api/discovery/delta-scores      — per-mode behavioral delta per model
GET  /api/discovery/stats             — failure store statistics
POST /api/discovery/synthesize        — generate novel method candidates
POST /api/discovery/refine            — LLM-assisted warm-pool refinement
DELETE /api/discovery/reset           — wipe failure store
"""

from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel, Field

from core.failure_store import FailureStore
from core.method_discovery import MethodDiscoveryEngine

router = APIRouter()

# Share the same singleton instances used by the Scanner so discovery
# data is visible immediately without a process restart.
from core.scanner import _failure_store as _store, _discovery_engine as _engine


# ── Schemas ───────────────────────────────────────────────────────────────────

class RefineRequest(BaseModel):
    model:          str
    vuln:           Optional[str]  = None
    rewriter_model: str            = Field(default="gpt-4o-mini",
                                           description="Cheap model to use as the rewriter")
    max_entries:    int            = Field(default=5, ge=1, le=20)


class SynthesizeResponse(BaseModel):
    total:      int
    candidates: List[dict]


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/insights", summary="Full discovery insights report")
async def get_insights():
    """
    Aggregated insights from all four discovery subsystems:
      - top method signatures (by bypass rate)
      - per-model defense map (dominant defense types)
      - cross-model transfer opportunities
      - override mode delta leaders (modes that shift model behavior most)
    """
    return _engine.get_insights()


@router.get("/signatures", summary="Discovered method signatures")
async def get_signatures(
    min_successes: int = Query(1, ge=0, description="Minimum bypass count"),
    limit:         int = Query(50, ge=1, le=200),
):
    """Return all structural method signatures, ordered by bypass rate."""
    sigs = list(_store.method_signatures.values())
    sigs = [s for s in sigs if s.get("total_successes", 0) >= min_successes]
    sigs.sort(
        key=lambda s: s.get("total_successes", 0) / max(s.get("total_attempts", 1), 1),
        reverse=True,
    )
    return {"total": len(sigs), "signatures": sigs[:limit]}


@router.get("/warm-pool", summary="Warm pool entries (adaptable failed probes)")
async def get_warm_pool(
    model:     Optional[str] = Query(None),
    vuln:      Optional[str] = Query(None),
    min_score: int            = Query(1, ge=0, le=2),
    limit:     int            = Query(50, ge=1, le=500),
):
    """Return warm pool entries ordered by score descending."""
    entries = _store.get_warm_pool(model=model, vuln=vuln, min_score=min_score)
    return {
        "total":   len(entries),
        "entries": entries[:limit],
    }


@router.get("/defense-map", summary="Per-model refusal clusters and bypass strategies")
async def get_defense_map(
    model: Optional[str] = Query(None, description="Filter to a specific model"),
):
    """
    Return per-model refusal clusters grouped by detected defense type.
    Each cluster includes the dominant phrases, affected vulnerabilities,
    and suggested bypass strategies.
    """
    clusters = _store.defense_clusters
    if model:
        clusters = {model: clusters.get(model, [])} if model in clusters else {}

    # Summarize per model
    out = {}
    for m, model_clusters in clusters.items():
        by_defense: dict = {}
        for cl in model_clusters:
            dt = cl["defense_type"]
            if dt not in by_defense:
                by_defense[dt] = {
                    "defense_type":       dt,
                    "total_hits":         0,
                    "clusters":           [],
                    "bypass_strategies":  cl.get("bypass_strategies", []),
                }
            by_defense[dt]["total_hits"] += cl["count"]
            by_defense[dt]["clusters"].append({
                "cluster_id": cl["cluster_id"],
                "centroid":   cl["centroid"][:100],
                "count":      cl["count"],
                "samples":    cl.get("samples", [])[:3],
                "vulns":      cl.get("vulns", []),
            })
        out[m] = {
            "model":           m,
            "total_clusters":  len(model_clusters),
            "defenses":        sorted(by_defense.values(), key=lambda x: x["total_hits"], reverse=True),
        }
    return out


@router.get("/transfer-matrix", summary="Cross-model transfer scores")
async def get_transfer_matrix(
    min_score: float = Query(0.3, ge=0.0, le=1.0,
                             description="Minimum average transfer score to include"),
    limit:     int   = Query(50, ge=1, le=200),
):
    """
    Return cross-model transfer opportunities.
    A high score means prompts that worked on model_A are likely to work
    on model_B with adaptation.  Score 1.0 = partial compliance on model_B,
    0.5 = hedged, 0.0 = hard block.
    """
    matrix = _store.transfer_matrix
    pairs = []
    for key, val in matrix.items():
        avg = val["sum"] / val["count"] if val["count"] > 0 else 0
        if avg >= min_score:
            from_to_vuln = key.split(":", 1)
            from_to = from_to_vuln[0].split("→")
            pairs.append({
                "from_model": from_to[0] if len(from_to) > 1 else key,
                "to_model":   from_to[1] if len(from_to) > 1 else "",
                "vuln":       from_to_vuln[1] if len(from_to_vuln) > 1 else "",
                "avg_score":  round(avg, 3),
                "samples":    val["count"],
            })
    pairs.sort(key=lambda x: x["avg_score"], reverse=True)
    return {"total": len(pairs), "pairs": pairs[:limit]}


@router.get("/delta-scores", summary="Override mode behavioral delta scores per model")
async def get_delta_scores(
    model: Optional[str] = Query(None),
):
    """
    Per-model, per-mode delta score: how much does applying this override mode
    improve the probe score vs the baseline (no mode)?
    Positive delta = mode shifts responses toward partial/full compliance.
    Negative delta = mode makes things worse.
    """
    all_models = list(_store._data.get("delta_scores", {}).keys())
    if model:
        all_models = [m for m in all_models if m == model]

    out = {}
    for m in all_models:
        scores = _store.get_delta_scores(m)
        if scores:
            sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
            out[m] = [{"mode": mode, "avg_delta": round(delta, 3)} for mode, delta in sorted_scores]
    return out


@router.get("/stats", summary="Failure store statistics")
async def get_failure_stats():
    """Return summary statistics for the failure store and discovery engine."""
    return _store.get_stats()


@router.post("/synthesize", response_model=SynthesizeResponse,
             summary="Synthesize novel method candidates")
async def synthesize_methods():
    """
    Generate novel MethodTemplate candidates by combining discovered signatures
    with target model defense types.

    Candidates are derived from the synthesis strategy matrix — each maps a
    (source_frame_type, target_defense_type) pair to an adapted prompt template.
    Use the returned templates as override mode definitions for future scans.
    """
    candidates = _engine.synthesize_novel_methods()
    return SynthesizeResponse(
        total=len(candidates),
        candidates=[c.to_dict() for c in candidates],
    )


@router.post("/refine", summary="LLM-assisted refinement of warm pool entries")
async def refine_warm_pool(
    req: RefineRequest,
    background_tasks: BackgroundTasks,
):
    """
    Use a cheap LLM to suggest structural variants for top warm-pool entries.

    The rewriter model receives (failed_prompt, refusal_response) and is asked
    to suggest 3 structurally different reformulations.  Variants are stored in
    the warm pool and included in the next scan wave.

    Runs in the background — poll GET /api/discovery/warm-pool to see results.
    """
    async def _run():
        await _engine.llm_refine_warm_pool(
            model          = req.model,
            vuln           = req.vuln,
            rewriter_model = req.rewriter_model,
            max_entries    = req.max_entries,
        )

    background_tasks.add_task(_run)
    return {
        "status":  "queued",
        "message": (
            f"LLM refinement queued for model={req.model}, vuln={req.vuln or 'all'} "
            f"using rewriter={req.rewriter_model}. "
            f"Poll GET /api/discovery/warm-pool to see adapted variants."
        ),
    }


@router.delete("/templates/{template_id}", status_code=204,
               summary="Delete a synthesized method template")
async def delete_template(template_id: str):
    """Remove a synthesized template by ID. Use to prune bad or inaccurate templates."""
    store = _store._data.get("synthesized_templates", {})
    if template_id not in store:
        raise HTTPException(status_code=404, detail=f"Template {template_id!r} not found")
    del store[template_id]
    _store._data["synthesized_templates"] = store
    _store.save()


@router.delete("/warm-pool/{probe_id}", status_code=204,
               summary="Remove a warm pool entry")
async def delete_warm_pool_entry(probe_id: str):
    """Remove a specific warm pool entry by probe_id."""
    removed = False
    for key, entries in _store._data["warm_pool"].items():
        before = len(entries)
        _store._data["warm_pool"][key] = [e for e in entries if e.get("probe_id") != probe_id]
        if len(_store._data["warm_pool"][key]) < before:
            removed = True
    if not removed:
        raise HTTPException(status_code=404, detail=f"Probe {probe_id!r} not found in warm pool")
    _store.save()


@router.delete("/signatures/{sig_id}", status_code=204,
               summary="Remove a method signature")
async def delete_signature(sig_id: str):
    """Remove a discovered signature by ID. Use to prune signatures based on bad data."""
    sigs = _store.method_signatures
    if sig_id not in sigs:
        raise HTTPException(status_code=404, detail=f"Signature {sig_id!r} not found")
    del sigs[sig_id]
    _store.method_signatures = sigs
    _store.save()


@router.delete("/reset", status_code=204, summary="Wipe failure store")
async def reset_failure_store():
    """Delete the failure store — clears all failure records, warm pool, and discovery data."""
    import os
    path = _store._path
    if os.path.exists(path):
        os.remove(path)
    # Re-initialize in-memory state
    _store._data = {
        "version": "1.0", "probes": [], "warm_pool": {},
        "method_signatures": {}, "defense_clusters": {},
        "transfer_matrix": {}, "delta_scores": {},
    }
