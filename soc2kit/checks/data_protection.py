"""Data protection checks: encryption, public exposure, secrets (CC6.1, CC6.7, C1.1)."""
from __future__ import annotations

import json

from ..context import CheckContext, error_code
from ..models import Finding, Severity, Status
from ..registry import check

_BPA_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def _account_bpa(ctx: CheckContext) -> dict:
    try:
        return ctx.call("s3control", "get_public_access_block", AccountId=ctx.account_id)[
            "PublicAccessBlockConfiguration"]
    except Exception as exc:
        if error_code(exc) == "NoSuchPublicAccessBlockConfiguration":
            ctx.record("s3control", "get_public_access_block", {"AccountId": ctx.account_id},
                       {"Error": "NoSuchPublicAccessBlockConfiguration"})
            return {}
        raise


def _buckets(ctx: CheckContext) -> list[dict]:
    return ctx.call("s3", "list_buckets")["Buckets"]


@check(
    id="DATA-01",
    title="S3 Block Public Access is on at the account level",
    description="Account-level Block Public Access prevents any bucket from being made public by mistake.",
    criteria=["CC6.1", "C1.1"],
    severity=Severity.HIGH,
    service="s3",
    scope="global",
    permissions=["s3:GetAccountPublicAccessBlock"],
    remediation="Turn on all four Block Public Access settings for the account.",
)
def account_bpa(ctx: CheckContext):
    cfg = _account_bpa(ctx)
    off = [f for f in _BPA_FLAGS if not cfg.get(f)]
    return [Finding(f"arn:aws:s3:::account/{ctx.account_id}", Status.FAIL if off else Status.PASS,
                    f"Off: {', '.join(off)}" if off else "All four settings on")]


@check(
    id="DATA-02",
    title="Every S3 bucket is protected by Block Public Access",
    description=("Each bucket must be covered by all four Block Public Access settings (bucket or account level). "
                 "A bucket without them is not necessarily public today, but nothing stops it becoming public."),
    criteria=["CC6.1", "C1.1"],
    severity=Severity.CRITICAL,
    service="s3",
    scope="global",
    permissions=["s3:ListAllMyBuckets", "s3:GetBucketPublicAccessBlock", "s3:GetAccountPublicAccessBlock"],
    remediation="Enable Block Public Access on the bucket; serve public content through CloudFront with OAC instead.",
)
def bucket_public(ctx: CheckContext):
    account = _account_bpa(ctx)
    findings = []
    for b in _buckets(ctx):
        name = b["Name"]
        try:
            cfg = ctx.call("s3", "get_public_access_block", Bucket=name)["PublicAccessBlockConfiguration"]
        except Exception as exc:
            if error_code(exc) != "NoSuchPublicAccessBlockConfiguration":
                raise
            ctx.record("s3", "get_public_access_block", {"Bucket": name}, {"Error": error_code(exc)})
            cfg = {}
        off = [f for f in _BPA_FLAGS if not (cfg.get(f) or account.get(f))]
        findings.append(Finding(f"arn:aws:s3:::{name}", Status.FAIL if off else Status.PASS,
                                f"Not blocked: {', '.join(off)}" if off else "Public access blocked"))
    return findings


def _denies_insecure_transport(policy: dict) -> bool:
    stmts = policy.get("Statement", [])
    stmts = [stmts] if isinstance(stmts, dict) else stmts
    for s in stmts:
        cond = s.get("Condition", {}).get("Bool", {})
        if s.get("Effect") == "Deny" and str(cond.get("aws:SecureTransport", "")).lower() == "false":
            return True
    return False


@check(
    id="DATA-03",
    title="S3 buckets reject non-TLS requests",
    description="A bucket policy must deny requests where aws:SecureTransport is false.",
    criteria=["CC6.7"],
    severity=Severity.MEDIUM,
    service="s3",
    scope="global",
    permissions=["s3:ListAllMyBuckets", "s3:GetBucketPolicy"],
    remediation='Add a Deny statement for "s3:*" with Condition {"Bool": {"aws:SecureTransport": "false"}}.',
)
def bucket_tls(ctx: CheckContext):
    findings = []
    for b in _buckets(ctx):
        name = b["Name"]
        try:
            policy = json.loads(ctx.call("s3", "get_bucket_policy", Bucket=name)["Policy"])
        except Exception as exc:
            if error_code(exc) != "NoSuchBucketPolicy":
                raise
            ctx.record("s3", "get_bucket_policy", {"Bucket": name}, {"Error": "NoSuchBucketPolicy"})
            policy = {}
        ok = _denies_insecure_transport(policy)
        findings.append(Finding(f"arn:aws:s3:::{name}", Status.PASS if ok else Status.FAIL,
                                "TLS enforced" if ok else "No SecureTransport deny"))
    return findings


@check(
    id="DATA-04",
    title="S3 buckets have versioning enabled",
    description="Versioning lets you recover objects that were overwritten or deleted.",
    criteria=["A1.2", "C1.1"],
    severity=Severity.LOW,
    service="s3",
    scope="global",
    permissions=["s3:ListAllMyBuckets", "s3:GetBucketVersioning"],
    remediation="Enable versioning (and a lifecycle rule to expire old versions to control cost).",
)
def bucket_versioning(ctx: CheckContext):
    findings = []
    for b in _buckets(ctx):
        status = ctx.call("s3", "get_bucket_versioning", Bucket=b["Name"]).get("Status", "Disabled")
        findings.append(Finding(f"arn:aws:s3:::{b['Name']}", Status.PASS if status == "Enabled" else Status.FAIL,
                                f"Versioning {status}"))
    return findings


@check(
    id="DATA-05",
    title="EBS encryption by default is on",
    description="Ensures every new EBS volume and snapshot is encrypted at rest.",
    criteria=["CC6.1", "C1.1"],
    severity=Severity.MEDIUM,
    service="ec2",
    scope="regional",
    permissions=["ec2:GetEbsEncryptionByDefault"],
    remediation="Enable EBS encryption by default in this region.",
)
def ebs_default_encryption(ctx: CheckContext):
    on = ctx.call("ec2", "get_ebs_encryption_by_default").get("EbsEncryptionByDefault", False)
    return [Finding(ctx.region, Status.PASS if on else Status.FAIL, "On" if on else "Off")]


def _db_instances(ctx: CheckContext) -> list[dict]:
    return ctx.paginate("rds", "describe_db_instances", "DBInstances")


@check(
    id="DATA-06",
    title="RDS databases are encrypted at rest",
    description="Database storage, backups and snapshots must be encrypted.",
    criteria=["CC6.1", "C1.1"],
    severity=Severity.HIGH,
    service="rds",
    scope="regional",
    permissions=["rds:DescribeDBInstances"],
    remediation="Encryption can't be turned on in place: snapshot, copy the snapshot with encryption, restore.",
)
def rds_encrypted(ctx: CheckContext):
    return [Finding(db["DBInstanceArn"], Status.PASS if db.get("StorageEncrypted") else Status.FAIL,
                    "Encrypted" if db.get("StorageEncrypted") else "Not encrypted")
            for db in _db_instances(ctx)]


@check(
    id="DATA-07",
    title="RDS databases are not publicly accessible",
    description="Databases should only be reachable from inside the VPC.",
    criteria=["CC6.6"],
    severity=Severity.CRITICAL,
    service="rds",
    scope="regional",
    permissions=["rds:DescribeDBInstances"],
    remediation="Set PubliclyAccessible to false and place the instance in private subnets.",
)
def rds_private(ctx: CheckContext):
    return [Finding(db["DBInstanceArn"], Status.FAIL if db.get("PubliclyAccessible") else Status.PASS,
                    "Publicly accessible" if db.get("PubliclyAccessible") else "Private")
            for db in _db_instances(ctx)]


@check(
    id="DATA-08",
    title="Customer-managed KMS keys rotate automatically",
    description="Symmetric customer-managed keys should have automatic rotation enabled.",
    criteria=["CC6.1"],
    severity=Severity.MEDIUM,
    service="kms",
    scope="regional",
    permissions=["kms:ListKeys", "kms:DescribeKey", "kms:GetKeyRotationStatus"],
    remediation="Enable automatic key rotation on the key.",
)
def kms_rotation(ctx: CheckContext):
    findings = []
    for k in ctx.paginate("kms", "list_keys", "Keys"):
        meta = ctx.call("kms", "describe_key", KeyId=k["KeyId"])["KeyMetadata"]
        if (meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled"
                or meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT"
                or meta.get("Origin") != "AWS_KMS"):
            continue
        on = ctx.call("kms", "get_key_rotation_status", KeyId=k["KeyId"]).get("KeyRotationEnabled", False)
        findings.append(Finding(meta["Arn"], Status.PASS if on else Status.FAIL,
                                "Rotation on" if on else "Rotation off"))
    return findings


@check(
    id="DATA-09",
    title="Secrets Manager secrets rotate automatically",
    description="Secrets should have a rotation schedule so leaked values expire.",
    criteria=["CC6.1"],
    severity=Severity.LOW,
    service="secretsmanager",
    scope="regional",
    permissions=["secretsmanager:ListSecrets"],
    remediation="Configure a rotation Lambda and schedule for the secret.",
)
def secrets_rotation(ctx: CheckContext):
    # ListSecrets returns metadata only, never secret values.
    return [Finding(s["ARN"], Status.PASS if s.get("RotationEnabled") else Status.FAIL,
                    "Rotation on" if s.get("RotationEnabled") else "Rotation off")
            for s in ctx.paginate("secretsmanager", "list_secrets", "SecretList")]
