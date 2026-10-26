"""Network boundary checks (CC6.6)."""
from __future__ import annotations

from ..context import CheckContext
from ..models import Finding, Severity, Status
from ..registry import check

ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
_OPEN = ("0.0.0.0/0", "::/0")


def _open_ranges(perm: dict) -> bool:
    return any(r.get("CidrIp") in _OPEN for r in perm.get("IpRanges", [])) or any(
        r.get("CidrIpv6") in _OPEN for r in perm.get("Ipv6Ranges", []))


def _exposed_admin_ports(perm: dict) -> list[str]:
    if not _open_ranges(perm):
        return []
    if perm.get("IpProtocol") == "-1":
        return ["all traffic"]
    if perm.get("IpProtocol") not in ("tcp", "6"):
        return []
    lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 65535)
    return [f"{name} ({port})" for port, name in ADMIN_PORTS.items() if lo <= port <= hi]


@check(
    id="NET-01",
    title="No security group exposes SSH or RDP to the internet",
    description="Admin ports open to 0.0.0.0/0 or ::/0 are a top initial-access vector.",
    criteria=["CC6.6"],
    severity=Severity.CRITICAL,
    service="ec2",
    scope="regional",
    permissions=["ec2:DescribeSecurityGroups"],
    remediation="Remove the open rule; use SSM Session Manager or a VPN / bastion with a narrow source range.",
)
def no_open_admin_ports(ctx: CheckContext):
    findings = []
    for sg in ctx.paginate("ec2", "describe_security_groups", "SecurityGroups"):
        exposed = sorted({p for perm in sg.get("IpPermissions", []) for p in _exposed_admin_ports(perm)})
        findings.append(Finding(f"{sg['GroupId']} ({sg.get('GroupName', '')})",
                                Status.FAIL if exposed else Status.PASS,
                                f"Open to internet: {', '.join(exposed)}" if exposed else "No open admin ports"))
    return findings


@check(
    id="NET-02",
    title="Default security groups allow no traffic",
    description="Default security groups get attached by accident; they should have no rules.",
    criteria=["CC6.6"],
    severity=Severity.LOW,
    service="ec2",
    scope="regional",
    permissions=["ec2:DescribeSecurityGroups"],
    remediation="Remove all inbound and outbound rules from each VPC's default security group.",
)
def default_sg_closed(ctx: CheckContext):
    sgs = ctx.paginate("ec2", "describe_security_groups", "SecurityGroups",
                       Filters=[{"Name": "group-name", "Values": ["default"]}])
    findings = []
    for sg in sgs:
        n = len(sg.get("IpPermissions", [])) + len(sg.get("IpPermissionsEgress", []))
        findings.append(Finding(f"{sg['GroupId']} ({sg.get('VpcId', '')})", Status.FAIL if n else Status.PASS,
                                f"{n} rule(s)" if n else "No rules"))
    return findings
