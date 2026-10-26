"""Logging, monitoring and detection checks (CC7.1-CC7.3, CC8.1)."""
from __future__ import annotations

from ..context import CheckContext, error_code
from ..models import Finding, Severity, Status
from ..registry import check

LOG_RETENTION_MIN_DAYS = 365


def _trails(ctx: CheckContext) -> list[dict]:
    return ctx.call("cloudtrail", "describe_trails", includeShadowTrails=False)["trailList"]


@check(
    id="LOG-01",
    title="A multi-region CloudTrail trail is logging",
    description="At least one trail must cover all regions and be actively delivering logs.",
    criteria=["CC7.2", "CC7.3"],
    severity=Severity.CRITICAL,
    service="cloudtrail",
    scope="global",
    permissions=["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"],
    remediation="Create a multi-region trail (or an organization trail) delivering to a dedicated S3 bucket.",
)
def multi_region_trail(ctx: CheckContext):
    good = []
    for t in _trails(ctx):
        if not t.get("IsMultiRegionTrail"):
            continue
        status = ctx.call("cloudtrail", "get_trail_status", Name=t["TrailARN"])
        if status.get("IsLogging"):
            good.append(t["TrailARN"])
    acct = f"arn:aws:cloudtrail:::{ctx.account_id}"
    return [Finding(acct, Status.PASS if good else Status.FAIL,
                    f"Logging multi-region trail(s): {', '.join(good)}" if good else "No multi-region trail is logging")]


@check(
    id="LOG-02",
    title="CloudTrail log file validation is enabled",
    description="Digest files let you prove logs were not altered after delivery.",
    criteria=["CC7.2"],
    severity=Severity.MEDIUM,
    service="cloudtrail",
    scope="global",
    permissions=["cloudtrail:DescribeTrails"],
    remediation="Enable log file validation on the trail.",
)
def trail_validation(ctx: CheckContext):
    return [Finding(t["TrailARN"], Status.PASS if t.get("LogFileValidationEnabled") else Status.FAIL,
                    "Validation on" if t.get("LogFileValidationEnabled") else "Validation off")
            for t in _trails(ctx)]


@check(
    id="LOG-03",
    title="CloudTrail logs are encrypted with KMS",
    description="Encrypting trail logs with a customer-managed key restricts who can read them.",
    criteria=["CC6.1", "CC7.2"],
    severity=Severity.LOW,
    service="cloudtrail",
    scope="global",
    permissions=["cloudtrail:DescribeTrails"],
    remediation="Configure SSE-KMS on the trail with a dedicated customer-managed key.",
)
def trail_kms(ctx: CheckContext):
    return [Finding(t["TrailARN"], Status.PASS if t.get("KmsKeyId") else Status.FAIL,
                    "SSE-KMS" if t.get("KmsKeyId") else "No KMS key")
            for t in _trails(ctx)]


@check(
    id="LOG-04",
    title="AWS Config is recording",
    description="Config records resource configuration history, which is your change-management evidence.",
    criteria=["CC7.1", "CC8.1"],
    severity=Severity.HIGH,
    service="config",
    scope="regional",
    permissions=["config:DescribeConfigurationRecorders", "config:DescribeConfigurationRecorderStatus"],
    remediation="Enable AWS Config in this region, recording all resource types.",
)
def config_recording(ctx: CheckContext):
    recorders = ctx.call("config", "describe_configuration_recorders")["ConfigurationRecorders"]
    statuses = ctx.call("config", "describe_configuration_recorder_status")["ConfigurationRecordersStatus"]
    recording = [s["name"] for s in statuses if s.get("recording")]
    ok = bool(recorders) and bool(recording)
    return [Finding(ctx.region, Status.PASS if ok else Status.FAIL,
                    "Recording" if ok else ("Recorder exists but stopped" if recorders else "No recorder"))]


@check(
    id="LOG-05",
    title="GuardDuty is enabled",
    description="GuardDuty provides continuous threat detection over CloudTrail, VPC and DNS logs.",
    criteria=["CC6.8", "CC7.2"],
    severity=Severity.HIGH,
    service="guardduty",
    scope="regional",
    permissions=["guardduty:ListDetectors", "guardduty:GetDetector"],
    remediation="Enable GuardDuty in this region (ideally org-wide with a delegated admin).",
)
def guardduty(ctx: CheckContext):
    detectors = ctx.paginate("guardduty", "list_detectors", "DetectorIds")
    enabled = [d for d in detectors
               if ctx.call("guardduty", "get_detector", DetectorId=d).get("Status") == "ENABLED"]
    return [Finding(ctx.region, Status.PASS if enabled else Status.FAIL,
                    "Detector enabled" if enabled else "No enabled detector")]


@check(
    id="LOG-06",
    title="Security Hub is enabled",
    description="Security Hub aggregates findings and runs continuous best-practice checks.",
    criteria=["CC7.1"],
    severity=Severity.MEDIUM,
    service="securityhub",
    scope="regional",
    permissions=["securityhub:DescribeHub"],
    remediation="Enable Security Hub with the AWS Foundational Security Best Practices standard.",
)
def security_hub(ctx: CheckContext):
    try:
        hub = ctx.call("securityhub", "describe_hub")
        return [Finding(hub.get("HubArn", ctx.region), Status.PASS, "Enabled")]
    except Exception as exc:
        if error_code(exc) in ("InvalidAccessException", "ResourceNotFoundException"):
            ctx.record("securityhub", "describe_hub", {}, {"Error": error_code(exc)})
            return [Finding(ctx.region, Status.FAIL, "Not enabled")]
        raise


@check(
    id="LOG-07",
    title="Every VPC has flow logs",
    description="Flow logs record network traffic metadata needed to investigate incidents.",
    criteria=["CC7.2"],
    severity=Severity.MEDIUM,
    service="ec2",
    scope="regional",
    permissions=["ec2:DescribeVpcs", "ec2:DescribeFlowLogs"],
    remediation="Enable VPC flow logs (at least REJECT traffic) to CloudWatch Logs or S3.",
)
def vpc_flow_logs(ctx: CheckContext):
    vpcs = ctx.paginate("ec2", "describe_vpcs", "Vpcs")
    logs = ctx.paginate("ec2", "describe_flow_logs", "FlowLogs")
    covered = {fl["ResourceId"] for fl in logs if fl.get("FlowLogStatus") == "ACTIVE"}
    return [Finding(v["VpcId"], Status.PASS if v["VpcId"] in covered else Status.FAIL,
                    "Flow logs active" if v["VpcId"] in covered else "No active flow log")
            for v in vpcs]


@check(
    id="LOG-08",
    title=f"Log groups retain logs for at least {LOG_RETENTION_MIN_DAYS} days",
    description="Auditors typically expect a year of log history for the observation window.",
    criteria=["CC7.2"],
    severity=Severity.LOW,
    service="logs",
    scope="regional",
    permissions=["logs:DescribeLogGroups"],
    remediation=f"Set retention to {LOG_RETENTION_MIN_DAYS}+ days (or 'never expire') on each log group.",
)
def log_retention(ctx: CheckContext):
    findings = []
    for g in ctx.paginate("logs", "describe_log_groups", "logGroups"):
        days = g.get("retentionInDays")  # absent = never expire
        ok = days is None or days >= LOG_RETENTION_MIN_DAYS
        findings.append(Finding(g["logGroupName"], Status.PASS if ok else Status.FAIL,
                                "Never expires" if days is None else f"{days} days"))
    return findings
