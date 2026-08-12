#!/usr/bin/env python3
"""
Report routes
GET /api/reports/{scan_id}          — structured report for a completed scan
GET /api/reports/{scan_id}/summary  — high-level text summary
GET /api/reports                    — list all scan IDs in the store
"""

from typing import List

from fastapi import APIRouter, HTTPException, Request

from api.schemas.reports import ModelReport, ScanReport, VulnSummary

router = APIRouter()


def _get_store(request: Request) -> dict:
    return request.app.state.scan_store


def _build_report(job) -> ScanReport:
    model_reports: List[ModelReport] = []

    for model, vuln_results in (job.results or {}).items():
        vuln_summaries = []
        for vr in vuln_results:
            vuln_summaries.append(VulnSummary(
                vulnerability = vr["vulnerability"] if isinstance(vr, dict) else vr.vulnerability,
                vulnerable    = vr["vulnerable"]    if isinstance(vr, dict) else vr.vulnerable,
                bypass_rate   = vr["bypass_rate"]   if isinstance(vr, dict) else vr.bypass_rate,
                bypass_count  = vr["bypass_count"]  if isinstance(vr, dict) else vr.bypass_count,
                total_probes  = vr["total_probes"]  if isinstance(vr, dict) else vr.total_probes,
            ))

        total_probes = sum(v.total_probes for v in vuln_summaries)
        total_bypassed = sum(v.bypass_count for v in vuln_summaries)
        overall_rate = total_bypassed / total_probes if total_probes else 0.0

        model_reports.append(ModelReport(
            model                = model,
            vulns                = vuln_summaries,
            overall_bypass_rate  = round(overall_rate, 3),
            total_vulnerable     = sum(1 for v in vuln_summaries if v.vulnerable),
            total_clean          = sum(1 for v in vuln_summaries if not v.vulnerable),
        ))

    return ScanReport(
        scan_id         = job.scan_id,
        status          = job.status.value if hasattr(job.status, "value") else str(job.status),
        override_mode   = job.override_mode,
        elapsed_seconds = job.elapsed_seconds,
        errors          = job.errors or [],
        models          = model_reports,
    )


@router.get("")
async def list_scans(request: Request):
    store = _get_store(request)
    scans = []
    for scan_id, job in store.items():
        scans.append({
            "scan_id":   scan_id,
            "status":    job.status.value if hasattr(job.status, "value") else str(job.status),
            "models":    job.models,
            "progress":  job.progress,
            "elapsed_seconds": job.elapsed_seconds,
        })
    return {"scans": scans, "total": len(scans)}


@router.get("/{scan_id}", response_model=ScanReport)
async def get_report(scan_id: str, request: Request):
    store = _get_store(request)
    job   = store.get(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")

    # Build from to_dict output so we always work with plain dicts
    d = job.to_dict()

    model_reports: List[ModelReport] = []
    for model, vuln_list in d.get("results", {}).items():
        vuln_summaries = [
            VulnSummary(
                vulnerability = v["vulnerability"],
                vulnerable    = v["vulnerable"],
                bypass_rate   = v["bypass_rate"],
                bypass_count  = v["bypass_count"],
                total_probes  = v["total_probes"],
            )
            for v in vuln_list
        ]
        total_probes   = sum(v.total_probes for v in vuln_summaries)
        total_bypassed = sum(v.bypass_count for v in vuln_summaries)
        model_reports.append(ModelReport(
            model               = model,
            vulns               = vuln_summaries,
            overall_bypass_rate = round(total_bypassed / total_probes, 3) if total_probes else 0.0,
            total_vulnerable    = sum(1 for v in vuln_summaries if v.vulnerable),
            total_clean         = sum(1 for v in vuln_summaries if not v.vulnerable),
        ))

    return ScanReport(
        scan_id         = d["scan_id"],
        status          = d["status"],
        override_mode   = d["override_mode"],
        elapsed_seconds = d.get("elapsed_seconds"),
        errors          = d.get("errors", []),
        models          = model_reports,
        mode_stats      = d.get("mode_stats", []),
    )


@router.get("/{scan_id}/summary")
async def get_summary(scan_id: str, request: Request):
    """Plain-text executive summary of a scan."""
    store = _get_store(request)
    job   = store.get(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")

    d     = job.to_dict()
    lines = [
        f"Scan ID      : {d['scan_id']}",
        f"Status       : {d['status']}",
        f"Override     : {d['override_mode']}",
        f"Elapsed      : {d.get('elapsed_seconds', 'N/A')}s",
        f"Models       : {', '.join(d['models'])}",
        f"Errors       : {len(d.get('errors', []))}",
        "",
    ]

    for model, vuln_list in d.get("results", {}).items():
        lines.append(f"── {model} ──")
        for v in vuln_list:
            status = "VULNERABLE" if v["vulnerable"] else "clean"
            lines.append(
                f"  {v['vulnerability'].upper():8} {status:10} "
                f"bypass={v['bypass_count']}/{v['total_probes']} "
                f"({v['bypass_rate']*100:.1f}%)"
            )
        lines.append("")

    return {"summary": "\n".join(lines)}
