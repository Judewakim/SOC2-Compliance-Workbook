"""Availability and recovery checks (A1.2)."""
from __future__ import annotations

from ..context import CheckContext
from ..models import Finding, Severity, Status
from ..registry import check

MIN_BACKUP_RETENTION_DAYS = 7


@check(
    id="AVL-01",
    title=f"RDS automated backups are kept at least {MIN_BACKUP_RETENTION_DAYS} days",
    description="Automated backups enable point-in-time recovery.",
    criteria=["A1.2"],
    severity=Severity.HIGH,
    service="rds",
    scope="regional",
    permissions=["rds:DescribeDBInstances"],
    remediation=f"Set BackupRetentionPeriod to {MIN_BACKUP_RETENTION_DAYS} or more.",
)
def rds_backups(ctx: CheckContext):
    findings = []
    for db in ctx.paginate("rds", "describe_db_instances", "DBInstances"):
        days = db.get("BackupRetentionPeriod", 0)
        findings.append(Finding(db["DBInstanceArn"],
                                Status.PASS if days >= MIN_BACKUP_RETENTION_DAYS else Status.FAIL,
                                f"{days} day retention"))
    return findings


@check(
    id="AVL-02",
    title="RDS databases are Multi-AZ",
    description="Multi-AZ keeps a standby in another availability zone for automatic failover.",
    criteria=["A1.2"],
    severity=Severity.MEDIUM,
    service="rds",
    scope="regional",
    permissions=["rds:DescribeDBInstances"],
    remediation="Modify the instance to enable Multi-AZ (dev/test databases can be accepted as a documented exception).",
)
def rds_multi_az(ctx: CheckContext):
    return [Finding(db["DBInstanceArn"], Status.PASS if db.get("MultiAZ") else Status.FAIL,
                    "Multi-AZ" if db.get("MultiAZ") else "Single-AZ")
            for db in ctx.paginate("rds", "describe_db_instances", "DBInstances")]


@check(
    id="AVL-03",
    title="An AWS Backup plan exists",
    description="A backup plan gives centrally managed, scheduled backups with retention rules.",
    criteria=["A1.2"],
    severity=Severity.MEDIUM,
    service="backup",
    scope="regional",
    permissions=["backup:ListBackupPlans"],
    remediation="Create an AWS Backup plan covering production resources in this region.",
)
def backup_plan(ctx: CheckContext):
    plans = ctx.paginate("backup", "list_backup_plans", "BackupPlansList")
    return [Finding(ctx.region, Status.PASS if plans else Status.FAIL,
                    f"{len(plans)} backup plan(s)" if plans else "No backup plans")]
