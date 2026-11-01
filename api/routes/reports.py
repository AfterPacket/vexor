#!/usr/bin/env python3
"""Reports derived from evidence-backed scan summaries, not stored legacy counts."""
from typing import List

from fastapi import APIRouter, HTTPException, Request

from api.schemas.reports import ModelReport, ScanReport, VulnSummary

router = APIRouter()


def _get_store(request: Request) -> dict:
    return request.app.state.scan_store


def _build_report(job) -> ScanReport:
    # ScanJob.to_dict recomputes confirmed counts from independently attributed
    # probe evidence. Do not trust old bypass_count fields from saved JSON.
    data = job.to_dict()
    model_reports: List[ModelReport] = []
    for model, vuln_list in data.get("results", {}).items():
        summaries = [VulnSummary(
            vulnerability=value["vulnerability"],
            vulnerable=value["vulnerable"],
            bypass_rate=value["bypass_rate"],
            bypass_count=value["bypass_count"],
            heuristic_positive_count=value.get("heuristic_positive_count", 0),
            finding_status=value.get("finding_status", "unvalidated"),
            total_probes=value["total_probes"],
            evaluation_status=value.get("evaluation_status", "not_evaluated"),
            evaluated_probes=value.get("evaluated_probes", 0),
            not_evaluated_probes=value.get("not_evaluated_probes", 0),
        ) for value in vuln_list]
        total_probes = sum(value.total_probes for value in summaries)
        confirmed = sum(value.bypass_count for value in summaries)
        model_reports.append(ModelReport(
            model=model,
            vulns=summaries,
            overall_bypass_rate=round(confirmed / total_probes, 3) if total_probes else 0.0,
            total_vulnerable=sum(value.vulnerable for value in summaries),
            total_clean=sum(value.finding_status == "no_finding" and value.evaluation_status == "evaluated" for value in summaries),
            total_not_evaluated=sum(value.evaluation_status == "not_evaluated" for value in summaries),
            total_partial=sum(value.evaluation_status == "partial" for value in summaries),
            total_unvalidated=sum(value.finding_status == "unvalidated" for value in summaries),
        ))
    return ScanReport(
        scan_id=data["scan_id"],
        status=data["status"],
        override_mode=data["override_mode"],
        elapsed_seconds=data.get("elapsed_seconds"),
        errors=data.get("errors", []),
        models=model_reports,
        mode_stats=data.get("mode_stats", []),
    )


@router.get("")
async def list_scans(request: Request):
    store = _get_store(request)
    scans = [{
        "scan_id": scan_id,
        "status": job.status.value if hasattr(job.status, "value") else str(job.status),
        "models": job.models,
        "progress": job.progress,
        "elapsed_seconds": job.elapsed_seconds,
    } for scan_id, job in store.items()]
    return {"scans": scans, "total": len(scans)}


@router.get("/{scan_id}", response_model=ScanReport)
async def get_report(scan_id: str, request: Request):
    job = _get_store(request).get(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
    return _build_report(job)


@router.get("/{scan_id}/summary")
async def get_summary(scan_id: str, request: Request):
    """Summary that distinguishes confirmed findings from unverified coverage."""
    job = _get_store(request).get(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
    data = job.to_dict()
    lines = [
        f"Scan ID      : {data['scan_id']}",
        f"Status       : {data['status']}",
        f"Override     : {data['override_mode']}",
        f"Elapsed      : {data.get('elapsed_seconds', 'N/A')}s",
        f"Models       : {', '.join(data['models'])}",
        f"Errors       : {len(data.get('errors', []))}",
        "Finding basis: independent validation; candidates are not confirmed bypasses",
        "",
    ]
    for model, vuln_list in data.get("results", {}).items():
        lines.append(f"── {model} ──")
        for value in vuln_list:
            status = "CONFIRMED" if value["vulnerable"] else value.get("finding_status", "unvalidated").upper()
            lines.append(
                f"  {value['vulnerability'].upper():8} {status:14} "
                f"confirmed={value['bypass_count']}/{value['total_probes']} "
                f"candidates={value.get('heuristic_positive_count', 0)} "
                f"coverage={value.get('evaluation_status', 'not_evaluated')}"
            )
        lines.append("")
    return {"summary": "\n".join(lines)}
