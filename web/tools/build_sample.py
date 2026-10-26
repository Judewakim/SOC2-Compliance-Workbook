"""Build the demo page's sample evidence pack.

Runs the real soc2kit scanner against a simulated AWS account (moto) set up to look like a
fictional company, "Northwind Health". Nothing here touches a real AWS account.

    pip install -e ".[dev]"
    python web/tools/build_sample.py

Writes web/sample/ (report.html, workbook.xlsx, evidence zip) and web/sample-report.js.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
             "AWS_DEFAULT_REGION": "us-east-1"}.items():
    os.environ[k] = v

import boto3  # noqa: E402
from moto import mock_aws  # noqa: E402

from soc2kit.report import write_pack  # noqa: E402
from soc2kit.runner import scan  # noqa: E402

REGIONS = ["us-east-1", "us-west-2"]
OUT = ROOT / "web" / "sample"


def tls_policy(bucket: str) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": [{
        "Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]})


def build_account(s: boto3.Session, account: str) -> None:
    east = {svc: s.client(svc, region_name="us-east-1") for svc in
            ("iam", "s3", "s3control", "cloudtrail", "config", "guardduty", "securityhub", "ec2",
             "rds", "kms", "secretsmanager", "logs", "backup")}
    west_ec2 = s.client("ec2", region_name="us-west-2")

    # --- IAM: a weak password policy, one user without MFA, a bot with a direct policy, a legacy admin policy
    iam = east["iam"]
    iam.update_account_password_policy(MinimumPasswordLength=8, RequireNumbers=True,
                                       RequireUppercaseCharacters=True, RequireLowercaseCharacters=True)
    iam.create_group(GroupName="engineers")
    for name, mfa in (("jane.ortiz", True), ("mark.chen", False)):
        iam.create_user(UserName=name)
        iam.add_user_to_group(GroupName="engineers", UserName=name)
        iam.create_login_profile(UserName=name, Password="Example-Only-Passw0rd!")
        if mfa:
            serial = iam.create_virtual_mfa_device(VirtualMFADeviceName=name)["VirtualMFADevice"]["SerialNumber"]
            iam.enable_mfa_device(UserName=name, SerialNumber=serial, AuthenticationCode1="123456",
                                  AuthenticationCode2="654321")
    iam.create_user(UserName="ci-deploy-bot")
    deploy = iam.create_policy(PolicyName="ci-deploy", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:PutObject", "cloudfront:CreateInvalidation"],
                                                "Resource": "*"}]}))["Policy"]["Arn"]
    iam.attach_user_policy(UserName="ci-deploy-bot", PolicyArn=deploy)
    iam.create_access_key(UserName="ci-deploy-bot")
    iam.create_policy(PolicyName="legacy-admin", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))

    # --- S3: account-level Block Public Access on; one bucket missing a TLS policy, one without versioning
    east["s3control"].put_public_access_block(AccountId=account, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3 = east["s3"]
    for b in ("northwind-patient-exports", "northwind-cloudtrail-logs", "northwind-app-logs", "northwind-web-assets"):
        s3.create_bucket(Bucket=b)
    for b in ("northwind-patient-exports", "northwind-cloudtrail-logs", "northwind-web-assets"):
        s3.put_bucket_policy(Bucket=b, Policy=tls_policy(b))
    for b in ("northwind-patient-exports", "northwind-cloudtrail-logs", "northwind-app-logs"):
        s3.put_bucket_versioning(Bucket=b, VersioningConfiguration={"Status": "Enabled"})

    # --- Logging and detection: a validated multi-region trail; Config, GuardDuty, Security Hub only in us-east-1
    ct = east["cloudtrail"]
    ct.create_trail(Name="northwind-org-trail", S3BucketName="northwind-cloudtrail-logs",
                    IsMultiRegionTrail=True, EnableLogFileValidation=True)
    ct.start_logging(Name="northwind-org-trail")
    cfg = east["config"]
    cfg.put_configuration_recorder(ConfigurationRecorder={
        "name": "default", "roleARN": f"arn:aws:iam::{account}:role/config-recorder",
        "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": True}})
    cfg.put_delivery_channel(DeliveryChannel={"name": "default", "s3BucketName": "northwind-cloudtrail-logs"})
    cfg.start_configuration_recorder(ConfigurationRecorderName="default")
    east["guardduty"].create_detector(Enable=True)
    east["securityhub"].enable_security_hub()
    logs = east["logs"]
    logs.create_log_group(logGroupName="/northwind/api")
    logs.put_retention_policy(logGroupName="/northwind/api", retentionInDays=400)
    logs.create_log_group(logGroupName="/aws/lambda/report-export")
    logs.put_retention_policy(logGroupName="/aws/lambda/report-export", retentionInDays=30)

    # --- Network: flow logs on the main VPC; a bastion with SSH open to the internet
    ec2 = east["ec2"]
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    ec2.create_flow_logs(ResourceIds=[vpc], ResourceType="VPC", TrafficType="ALL",
                         LogDestinationType="cloud-watch-logs", LogGroupName="/northwind/vpc-flow",
                         DeliverLogsPermissionArn=f"arn:aws:iam::{account}:role/flow-logs")
    bastion = ec2.create_security_group(GroupName="bastion", Description="Bastion host", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=bastion, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    web = ec2.create_security_group(GroupName="web-alb", Description="Public load balancer", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=web, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    for client in (ec2, west_ec2):
        for sg in client.describe_security_groups(Filters=[{"Name": "group-name", "Values": ["default"]}])["SecurityGroups"]:
            if sg["IpPermissionsEgress"]:
                client.revoke_security_group_egress(GroupId=sg["GroupId"], IpPermissions=sg["IpPermissionsEgress"])
            if sg["IpPermissions"]:
                client.revoke_security_group_ingress(GroupId=sg["GroupId"], IpPermissions=sg["IpPermissions"])
    ec2.enable_ebs_encryption_by_default()

    # --- Data stores: a well-configured production DB and a forgotten reporting DB
    rds = east["rds"]
    rds.create_db_instance(DBInstanceIdentifier="patients-prod", DBInstanceClass="db.r6g.large", Engine="postgres",
                           MasterUsername="app", MasterUserPassword="example-only-pw", AllocatedStorage=100,
                           StorageEncrypted=True, PubliclyAccessible=False, MultiAZ=True, BackupRetentionPeriod=14)
    rds.create_db_instance(DBInstanceIdentifier="reporting-replica", DBInstanceClass="db.t3.medium", Engine="mysql",
                           MasterUsername="report", MasterUserPassword="example-only-pw", AllocatedStorage=50,
                           StorageEncrypted=False, PubliclyAccessible=True, MultiAZ=False, BackupRetentionPeriod=1)
    kms = east["kms"]
    k1 = kms.create_key(Description="patients-prod storage")["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=k1)
    kms.create_key(Description="report exports")
    east["secretsmanager"].create_secret(Name="prod/patients-db", SecretString="example-only")
    east["backup"].create_backup_plan(BackupPlan={"BackupPlanName": "daily-prod", "Rules": [{
        "RuleName": "daily", "TargetBackupVaultName": "Default", "ScheduleExpression": "cron(0 5 * * ? *)",
        "Lifecycle": {"DeleteAfterDays": 35}}]})


def main() -> None:
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        account = session.client("sts").get_caller_identity()["Account"]
        build_account(session, account)
        result = scan(session, regions=REGIONS)

    # Label the simulated scanning principal plainly; it is not a real identity.
    result.principal_arn = f"arn:aws:iam::{account}:role/soc2kit-readonly (simulated)"
    for r in result.results:
        if r.error and "Not yet implemented" in r.error:
            r.error = "The AWS simulator used for this sample does not support this API."

    shutil.rmtree(OUT, ignore_errors=True)
    summary = write_pack(result, str(OUT))
    summary["sample"] = {"company": "Northwind Health (fictional)", "note": "Generated against a simulated AWS account."}
    js = "/* Generated by web/tools/build_sample.py - do not edit. */\nwindow.SOC2KIT_SAMPLE = "
    (ROOT / "web" / "sample-report.js").write_text(js + json.dumps(summary, indent=1) + ";\n", encoding="utf-8")
    zips = list(OUT.glob("*.zip"))
    zips[0].rename(OUT / "soc2-evidence-sample.zip")
    shutil.rmtree(OUT / "evidence")  # kept inside the zip; no need to publish 60 loose files
    (OUT / "manifest.json").unlink()
    (OUT / "report.json").unlink()
    c = summary["counts"]
    print(f"score {summary['score']}%  pass {c['PASS']} fail {c['FAIL']} error {c['ERROR']} n/a {c['N/A']}")


if __name__ == "__main__":
    main()
