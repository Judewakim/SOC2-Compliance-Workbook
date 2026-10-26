"""Session setup and check execution."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import boto3

from .context import CheckContext, error_code, utcnow
from .models import CheckDef, CheckResult, Finding, Status
from .registry import all_checks

HOME_REGION = "us-east-1"


@dataclass
class ScanResult:
    account_id: str
    principal_arn: str
    regions: list[str]
    started_at: str
    finished_at: str = ""
    results: list[CheckResult] = field(default_factory=list)


def build_session(profile: str | None = None, role_arn: str | None = None,
                  external_id: str | None = None) -> boto3.Session:
    base = boto3.Session(profile_name=profile) if profile else boto3.Session()
    if not role_arn:
        return base
    params = {"RoleArn": role_arn, "RoleSessionName": "soc2kit", "DurationSeconds": 3600}
    if external_id:
        params["ExternalId"] = external_id
    creds = base.client("sts", region_name=HOME_REGION).assume_role(**params)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def enabled_regions(session: boto3.Session) -> list[str]:
    resp = session.client("ec2", region_name=HOME_REGION).describe_regions(AllRegions=False)
    return sorted(r["RegionName"] for r in resp["Regions"])


def derive_status(findings: list[Finding]) -> tuple[Status, str]:
    if not findings:
        return Status.NOT_APPLICABLE, "No resources in scope"
    failed = [f for f in findings if f.status == Status.FAIL]
    if failed:
        return Status.FAIL, f"{len(failed)} of {len(findings)} failing"
    return Status.PASS, f"{len(findings)} of {len(findings)} passing"


def run_check(session: boto3.Session, check: CheckDef, region: str, account_id: str) -> CheckResult:
    ctx = CheckContext(session, region, account_id)
    started = utcnow()
    try:
        findings = check.func(ctx)
        status, summary = derive_status(findings)
        error = None
    except Exception as exc:  # any failure to evaluate is an ERROR, never a pass
        findings = []
        code = error_code(exc)
        status = Status.ERROR
        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthorizationError"):
            summary = "Access denied - the scan role is missing a permission"
        elif code in ("OptInRequired", "SubscriptionRequiredException", "UnrecognizedClientException"):
            summary = "Service not available in this region/account"
        else:
            summary = "Check could not be evaluated"
        error = f"{type(exc).__name__}: {exc}"
    return CheckResult(check=check, region=region, status=status, summary=summary, findings=findings,
                       evidence=ctx.evidence, error=error, started_at=started, finished_at=utcnow())


def scan(session: boto3.Session, regions: list[str] | None = None, check_ids: list[str] | None = None,
         max_workers: int = 8, progress=None) -> ScanResult:
    identity = session.client("sts", region_name=HOME_REGION).get_caller_identity()
    regions = regions or enabled_regions(session)
    checks = [c for c in all_checks() if not check_ids or c.id in check_ids]
    jobs = [(c, r) for c in checks for r in ([HOME_REGION] if c.scope == "global" else regions)]

    result = ScanResult(account_id=identity["Account"], principal_arn=identity["Arn"],
                        regions=regions, started_at=utcnow())
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(run_check, session, c, r, identity["Account"]) for c, r in jobs]
        for i, fut in enumerate(futures, 1):
            res = fut.result()
            result.results.append(res)
            if progress:
                progress(i, len(jobs), res)
    result.results.sort(key=lambda r: (r.check.id, r.region))
    result.finished_at = utcnow()
    return result
