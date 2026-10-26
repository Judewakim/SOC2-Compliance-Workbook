"""Turns a ScanResult into a plain, JSON-safe summary used by every output format.

Two levels:
- results: one row per check per region (the raw unit of evidence)
- checks:  one verdict per check, rolled up across regions. Scores and counts use this level,
           so a control that is off in 16 regions counts as one failing control, not sixteen.
"""
from __future__ import annotations

from collections import defaultdict

from ..controls import CRITERIA, MANUAL_CONTROLS
from ..models import SEVERITY_ORDER, CheckResult, Severity, Status
from ..runner import ScanResult

TOOL_VERSION = "2.1.0"
_ROLLUP_ORDER = (Status.FAIL, Status.ERROR, Status.PASS, Status.NOT_APPLICABLE)


def rollup(results: list[CheckResult]) -> Status:
    """A check fails if it fails anywhere; it only passes if it passed somewhere and nothing failed or errored."""
    statuses = {r.status for r in results}
    for s in _ROLLUP_ORDER:
        if s in statuses:
            return s
    return Status.NOT_APPLICABLE


def _check_summary(rows: list[CheckResult], status: Status) -> str:
    if rows[0].check.scope == "global":
        return rows[0].summary
    by = defaultdict(list)
    for r in rows:
        by[r.status].append(r.region)
    applicable = len(rows) - len(by[Status.NOT_APPLICABLE])
    resource_level = any(f.resource != r.region for r in rows for f in r.findings)
    if status == Status.FAIL and resource_level:
        total = sum(len(r.findings) for r in rows)
        bad = sum(1 for r in rows for f in r.findings if f.status == Status.FAIL)
        where = ", ".join(by[Status.FAIL][:4]) + (" and more" if len(by[Status.FAIL]) > 4 else "")
        return f"{bad} of {total} resources fail ({where})"
    if status == Status.FAIL:
        regions = by[Status.FAIL]
        listed = ", ".join(regions[:4]) + (f" and {len(regions) - 4} more" if len(regions) > 4 else "")
        return f"Fails in {len(regions)} of {applicable} regions ({listed})"
    if status == Status.ERROR:
        return f"Could not be evaluated in {len(by[Status.ERROR])} region(s)"
    if status == Status.PASS and resource_level:
        return f"All {sum(len(r.findings) for r in rows)} resources pass"
    if status == Status.PASS:
        return f"Passes in all {applicable} region(s) where it applies"
    return "No resources in scope in any region"


def build_summary(scan: ScanResult) -> dict:
    by_check: dict[str, list[CheckResult]] = defaultdict(list)
    for r in scan.results:
        by_check[r.check.id].append(r)

    checks = []
    for rows in by_check.values():
        rows.sort(key=lambda r: r.region)
        c = rows[0].check
        status = rollup(rows)
        failed = [{"region": r.region if c.scope == "regional" else "global", "resource": f.resource, "detail": f.detail}
                  for r in rows for f in r.findings if f.status == Status.FAIL]
        checks.append({
            "check_id": c.id,
            "title": c.title,
            "description": c.description,
            "criteria": list(c.criteria),
            "severity": c.severity.value,
            "service": c.service,
            "scope": c.scope,
            "status": status.value,
            "summary": _check_summary(rows, status),
            "regions": {s.value: [r.region for r in rows if r.status == s] for s in Status} if c.scope == "regional" else {},
            "failed_resources": failed,
            "errors": [f"{r.region}: {r.error}" for r in rows if r.error],
            "remediation": c.remediation,
            "evidence_files": [r.evidence_file for r in rows],
        })
    checks.sort(key=lambda x: (_status_rank(Status(x["status"])), SEVERITY_ORDER[Severity(x["severity"])], x["check_id"]))

    counts = {s.value: 0 for s in Status}
    for c in checks:
        counts[c["status"]] += 1
    evaluated = counts["PASS"] + counts["FAIL"]
    score = round(100 * counts["PASS"] / evaluated) if evaluated else 0

    result_counts = {s.value: 0 for s in Status}
    for r in scan.results:
        result_counts[r.status.value] += 1

    by_criterion: dict[str, dict] = defaultdict(lambda: {**{s.value: 0 for s in Status}, "checks": set()})
    for c in checks:
        for crit in c["criteria"]:
            by_criterion[crit][c["status"]] += 1
            by_criterion[crit]["checks"].add(c["check_id"])
    criteria = []
    for cid in sorted(set(by_criterion) | {m.criterion for m in MANUAL_CONTROLS}, key=_criterion_key):
        row = by_criterion.get(cid, {**{s.value: 0 for s in Status}, "checks": set()})
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
        "counts": counts,                 # per check (31 controls)
        "result_counts": result_counts,   # per check per region
        "checks": checks,
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
