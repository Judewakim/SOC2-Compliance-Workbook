"""Identity and access management checks (CC6.1-CC6.3)."""
from __future__ import annotations

import csv
import io
import json
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

from ..context import CheckContext, error_code
from ..models import Finding, Severity, Status
from ..registry import check

KEY_MAX_AGE_DAYS = 90
UNUSED_CREDENTIAL_DAYS = 45


def _account(ctx: CheckContext) -> str:
    return f"arn:aws:iam::{ctx.account_id}:root"


def _credential_report(ctx: CheckContext) -> list[dict]:
    iam = ctx.client("iam")
    for _ in range(10):
        state = iam.generate_credential_report()["State"]
        if state == "COMPLETE":
            break
        time.sleep(2)
    raw = iam.get_credential_report()["Content"].decode("utf-8")
    rows = list(csv.DictReader(io.StringIO(raw)))
    ctx.record("iam", "get_credential_report", {}, {"rows": rows})
    return rows


def _parse_date(value: str) -> datetime | None:
    if not value or value in ("N/A", "no_information", "not_supported"):
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@check(
    id="IAM-01",
    title="Root account has MFA enabled",
    description="The root user can do anything in the account. It must be protected by MFA.",
    criteria=["CC6.1"],
    severity=Severity.CRITICAL,
    service="iam",
    scope="global",
    permissions=["iam:GetAccountSummary"],
    remediation="Sign in as root and enable a hardware or virtual MFA device under Security credentials.",
)
def root_mfa(ctx: CheckContext):
    summary = ctx.call("iam", "get_account_summary")["SummaryMap"]
    ok = summary.get("AccountMFAEnabled", 0) == 1
    return [Finding(_account(ctx), Status.PASS if ok else Status.FAIL,
                    "Root MFA enabled" if ok else "Root MFA is not enabled")]


@check(
    id="IAM-02",
    title="Root account has no access keys",
    description="Programmatic keys on the root user cannot be scoped down and should not exist.",
    criteria=["CC6.1"],
    severity=Severity.CRITICAL,
    service="iam",
    scope="global",
    permissions=["iam:GetAccountSummary"],
    remediation="Delete any root access keys and use IAM roles for programmatic access.",
)
def root_access_keys(ctx: CheckContext):
    summary = ctx.call("iam", "get_account_summary")["SummaryMap"]
    present = summary.get("AccountAccessKeysPresent", 0)
    return [Finding(_account(ctx), Status.FAIL if present else Status.PASS,
                    "Root access keys exist" if present else "No root access keys")]


@check(
    id="IAM-03",
    title="Password policy meets minimum strength",
    description="Requires length >= 14, all character classes, and reuse prevention of >= 24 passwords.",
    criteria=["CC6.1"],
    severity=Severity.MEDIUM,
    service="iam",
    scope="global",
    permissions=["iam:GetAccountPasswordPolicy"],
    remediation="Set an account password policy: minimum length 14, require upper/lower/number/symbol, prevent reuse of 24.",
)
def password_policy(ctx: CheckContext):
    try:
        policy = ctx.call("iam", "get_account_password_policy")["PasswordPolicy"]
    except Exception as exc:
        if error_code(exc) == "NoSuchEntity":
            ctx.record("iam", "get_account_password_policy", {}, {"Error": "NoSuchEntity"})
            return [Finding(_account(ctx), Status.FAIL, "No password policy is set")]
        raise
    problems = []
    if policy.get("MinimumPasswordLength", 0) < 14:
        problems.append(f"minimum length {policy.get('MinimumPasswordLength')} < 14")
    for flag in ("RequireUppercaseCharacters", "RequireLowercaseCharacters", "RequireNumbers", "RequireSymbols"):
        if not policy.get(flag):
            problems.append(f"{flag} is off")
    if policy.get("PasswordReusePrevention", 0) < 24:
        problems.append(f"reuse prevention {policy.get('PasswordReusePrevention', 0)} < 24")
    return [Finding(_account(ctx), Status.FAIL if problems else Status.PASS,
                    "; ".join(problems) or "Password policy meets baseline")]


@check(
    id="IAM-04",
    title="Every console user has MFA",
    description="Any IAM user with a console password must have MFA enabled.",
    criteria=["CC6.1"],
    severity=Severity.HIGH,
    service="iam",
    scope="global",
    permissions=["iam:GenerateCredentialReport", "iam:GetCredentialReport"],
    remediation="Enable MFA for each listed user, or remove their console password and use IAM Identity Center.",
)
def console_users_mfa(ctx: CheckContext):
    findings = []
    for row in _credential_report(ctx):
        if row["user"] == "<root_account>" or row.get("password_enabled") != "true":
            continue
        ok = row.get("mfa_active") == "true"
        findings.append(Finding(row["arn"], Status.PASS if ok else Status.FAIL,
                                "MFA active" if ok else "Console password without MFA"))
    return findings


@check(
    id="IAM-05",
    title="Access keys are rotated within 90 days",
    description=f"Active IAM user access keys must be younger than {KEY_MAX_AGE_DAYS} days.",
    criteria=["CC6.1", "CC6.2"],
    severity=Severity.MEDIUM,
    service="iam",
    scope="global",
    permissions=["iam:GenerateCredentialReport", "iam:GetCredentialReport"],
    remediation="Rotate old keys, or better, replace long-lived keys with IAM roles / IAM Identity Center.",
)
def access_key_rotation(ctx: CheckContext):
    now = datetime.now(timezone.utc)
    findings = []
    for row in _credential_report(ctx):
        if row["user"] == "<root_account>":
            continue
        for n in ("1", "2"):
            if row.get(f"access_key_{n}_active") != "true":
                continue
            rotated = _parse_date(row.get(f"access_key_{n}_last_rotated", ""))
            age = (now - rotated).days if rotated else None
            ok = age is not None and age <= KEY_MAX_AGE_DAYS
            findings.append(Finding(f"{row['arn']} (key {n})", Status.PASS if ok else Status.FAIL,
                                    f"Key age {age} days"))
    return findings


@check(
    id="IAM-06",
    title="Unused credentials are disabled",
    description=f"Passwords and active keys unused for more than {UNUSED_CREDENTIAL_DAYS} days should be removed.",
    criteria=["CC6.2", "CC6.3"],
    severity=Severity.MEDIUM,
    service="iam",
    scope="global",
    permissions=["iam:GenerateCredentialReport", "iam:GetCredentialReport"],
    remediation="Disable or delete the stale password / access key; review whether the user still needs access.",
)
def unused_credentials(ctx: CheckContext):
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=UNUSED_CREDENTIAL_DAYS)
    findings = []
    for row in _credential_report(ctx):
        if row["user"] == "<root_account>":
            continue
        created = _parse_date(row.get("user_creation_time", ""))
        stale = []
        if row.get("password_enabled") == "true":
            last = _parse_date(row.get("password_last_used", "")) or created
            if last and last < cutoff:
                stale.append("console password")
        for n in ("1", "2"):
            if row.get(f"access_key_{n}_active") == "true":
                last = (_parse_date(row.get(f"access_key_{n}_last_used_date", ""))
                        or _parse_date(row.get(f"access_key_{n}_last_rotated", "")))
                if last and last < cutoff:
                    stale.append(f"access key {n}")
        if row.get("password_enabled") != "true" and "true" not in (
            row.get("access_key_1_active"), row.get("access_key_2_active")
        ):
            continue
        findings.append(Finding(row["arn"], Status.FAIL if stale else Status.PASS,
                                f"Unused > {UNUSED_CREDENTIAL_DAYS} days: {', '.join(stale)}" if stale else "Credentials in use"))
    return findings


@check(
    id="IAM-07",
    title="IAM users get permissions through groups or roles only",
    description="Policies attached directly to users are hard to review and drift over time.",
    criteria=["CC6.3"],
    severity=Severity.LOW,
    service="iam",
    scope="global",
    permissions=["iam:ListUsers", "iam:ListAttachedUserPolicies", "iam:ListUserPolicies"],
    remediation="Move the user's policies onto a group or role and detach them from the user.",
)
def no_user_policies(ctx: CheckContext):
    findings = []
    for user in ctx.paginate("iam", "list_users", "Users"):
        name = user["UserName"]
        attached = ctx.paginate("iam", "list_attached_user_policies", "AttachedPolicies", UserName=name)
        inline = ctx.paginate("iam", "list_user_policies", "PolicyNames", UserName=name)
        n = len(attached) + len(inline)
        findings.append(Finding(user["Arn"], Status.FAIL if n else Status.PASS,
                                f"{n} policies attached directly" if n else "No direct policies"))
    return findings


def _statements(doc) -> list[dict]:
    if isinstance(doc, str):
        doc = json.loads(unquote(doc))
    stmts = doc.get("Statement", [])
    return [stmts] if isinstance(stmts, dict) else stmts


def _as_list(v) -> list:
    return v if isinstance(v, list) else [v]


@check(
    id="IAM-08",
    title="No customer-managed policy grants full admin (*:*)",
    description="Custom policies allowing Action '*' on Resource '*' bypass least privilege.",
    criteria=["CC6.3"],
    severity=Severity.HIGH,
    service="iam",
    scope="global",
    permissions=["iam:ListPolicies", "iam:GetPolicyVersion"],
    remediation="Replace '*:*' with the specific actions and resources the principal needs.",
)
def no_admin_policies(ctx: CheckContext):
    findings = []
    for pol in ctx.paginate("iam", "list_policies", "Policies", Scope="Local", OnlyAttached=False):
        version = ctx.call("iam", "get_policy_version", PolicyArn=pol["Arn"],
                           VersionId=pol["DefaultVersionId"])["PolicyVersion"]
        admin = any(
            s.get("Effect") == "Allow" and "*" in _as_list(s.get("Action", [])) and "*" in _as_list(s.get("Resource", []))
            for s in _statements(version["Document"])
        )
        findings.append(Finding(pol["Arn"], Status.FAIL if admin else Status.PASS,
                                "Allows *:*" if admin else "Scoped"))
    return findings


@check(
    id="IAM-09",
    title="IAM Access Analyzer is enabled",
    description="Access Analyzer flags resources shared outside the account or organization.",
    criteria=["CC6.1", "CC7.1"],
    severity=Severity.MEDIUM,
    service="access-analyzer",
    scope="regional",
    permissions=["access-analyzer:ListAnalyzers"],
    remediation="Create an account- or organization-level analyzer in this region.",
)
def access_analyzer(ctx: CheckContext):
    analyzers = ctx.paginate("accessanalyzer", "list_analyzers", "analyzers")
    active = [a for a in analyzers if a.get("status") == "ACTIVE"]
    return [Finding(f"{ctx.region}", Status.PASS if active else Status.FAIL,
                    f"{len(active)} active analyzer(s)" if active else "No active analyzer")]
