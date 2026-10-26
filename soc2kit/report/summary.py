"""Turns a ScanResult into a plain, JSON-safe summary used by every output format."""
from __future__ import annotations

from collections import defaultdict

from ..controls import CRITERIA, MANUAL_CONTROLS
from ..models import SEVERITY_ORDER, Status
from ..runner import ScanResult

TOOL_VERSION = "2.0.0"


def build_summary(scan: ScanResult) -> dict:
    counts = {s.value: 0 for s in Status}
    for r in scan.results:
        counts[r.status.value] += 1
    evaluated = counts["PASS"] + counts["FAIL"]
    score = round(100 * counts["PASS"] / evaluated) if evaluated else 0

    by_criterion: dict[str, dict] = defaultdict(lambda: {s.value: 0 for s in Status} | {"checks": set()})
    for r in scan.results:
        for c in r.check.criteria:
            by_criterion[c][r.status.value] += 1
            by_criterion[c]["checks"].add(r.check.id)
    criteria = []
    for cid in sorted(set(by_criterion) | {m.criterion for m in MANUAL_CONTROLS}, key=_criterion_key):
        row = by_criterion.get(cid, {s.value: 0 for s in Status} | {"checks": set()})
        criteria.append({
            "criterion": cid,
            "name": CRITERIA.get(cid, ""),
            "automated_checks": sorted(row["checks"]),
            "manual_controls": [m.id for m in MANUAL_CONTROLS if m.criterion == cid],
            "pass": row["PASS"], "fail": row["FAIL"], "error": row["ERROR"], "na": row["N/A"],
        })

    results = []
    for r in sorted(scan.results, key=lambda r: (_status_rank(r.status), SEVERITY_ORDER[r.check.severity], r.check.id, r.region)):
        results.append({
            "check_id": r.check.id,
            "title": r.check.title,
            "description": r.check.description,
            "criteria": list(r.check.criteria),
            "severity": r.check.severity.value,
            "service": r.check.service,
            "region": r.region if r.check.scope == "regional" else "global",
            "status": r.status.value,
            "summary": r.summary,
            "remediation": r.check.remediation,
            "error": r.error,
            "evidence_file": r.evidence_file,
            "evaluated_at": r.finished_at,
            "findings": [{"resource": f.resource, "status": f.status.value, "detail": f.detail} for f in r.findings],
        })

    return {
        "tool": {"name": "soc2kit", "version": TOOL_VERSION},
        "account_id": scan.account_id,
        "principal_arn": scan.principal_arn,
        "regions": scan.regions,
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
        "score": score,
        "counts": counts,
        "criteria": criteria,
        "results": results,
        "manual_controls": [m.__dict__ for m in MANUAL_CONTROLS],
        "disclaimer": ("Automated technical evidence only. Criteria mappings are guidance; your auditor "
                       "determines control sufficiency. Most SOC 2 controls are procedural - see manual_controls."),
    }


def _status_rank(s: Status) -> int:
    return {Status.FAIL: 0, Status.ERROR: 1, Status.PASS: 2, Status.NOT_APPLICABLE: 3}[s]


def _criterion_key(c: str):
    prefix = "".join(ch for ch in c if ch.isalpha())
    order = {"CC": 0, "A": 1, "C": 2, "PI": 3, "P": 4}.get(prefix, 9)
    major, minor = c[len(prefix):].split(".")
    return order, int(major), int(minor)
