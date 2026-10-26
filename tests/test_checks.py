import json

from botocore.exceptions import ClientError

from soc2kit.models import Status
from soc2kit.registry import all_checks
from soc2kit.runner import derive_status, run_check

from .conftest import REGION, run

# --- The bug that sank v1: "some output" must never mean "compliant" -------------------

def test_no_cloudtrail_is_a_fail_not_a_pass(session):
    res = run(session, "LOG-01")
    assert res.status == Status.FAIL


def test_multi_region_logging_trail_passes(session):
    session.client("s3").create_bucket(Bucket="trail-logs")
    ct = session.client("cloudtrail")
    ct.create_trail(Name="org", S3BucketName="trail-logs", IsMultiRegionTrail=True)
    ct.start_logging(Name="org")
    assert run(session, "LOG-01").status == Status.PASS


def test_no_resources_is_not_applicable_not_pass():
    assert derive_status([])[0] == Status.NOT_APPLICABLE


def test_access_denied_is_error_not_pass(session):
    check = next(c for c in all_checks() if c.id == "IAM-01")

    def denied(ctx):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "GetAccountSummary")

    res = run_check(session, check.__class__(**{**check.__dict__, "func": denied}), REGION, "123456789012")
    assert res.status == Status.ERROR
    assert "permission" in res.summary


# --- IAM ---------------------------------------------------------------------------------

def test_password_policy_missing_fails(session):
    assert run(session, "IAM-03").status == Status.FAIL


def test_password_policy_strong_passes(session):
    session.client("iam").update_account_password_policy(
        MinimumPasswordLength=14, RequireSymbols=True, RequireNumbers=True, RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True, PasswordReusePrevention=24)
    assert run(session, "IAM-03").status == Status.PASS


def test_user_with_direct_policy_fails(session):
    iam = session.client("iam")
    iam.create_user(UserName="bob")
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}]}
    arn = iam.create_policy(PolicyName="list", PolicyDocument=json.dumps(doc))["Policy"]["Arn"]
    iam.attach_user_policy(UserName="bob", PolicyArn=arn)
    iam.create_user(UserName="carol")
    res = run(session, "IAM-07")
    assert res.status == Status.FAIL
    assert {f.status for f in res.findings} == {Status.PASS, Status.FAIL}


def test_admin_policy_detected(session):
    iam = session.client("iam")
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    iam.create_policy(PolicyName="god", PolicyDocument=json.dumps(doc))
    assert run(session, "IAM-08").status == Status.FAIL


def test_console_user_without_mfa_fails(session):
    iam = session.client("iam")
    iam.create_user(UserName="dave")
    iam.create_login_profile(UserName="dave", Password="Sup3r-secret-pw!!")
    assert run(session, "IAM-04").status == Status.FAIL


# --- Data protection ---------------------------------------------------------------------

def test_bucket_without_block_public_access_fails(session):
    session.client("s3").create_bucket(Bucket="open-bucket")
    assert run(session, "DATA-02").status == Status.FAIL


def test_account_level_bpa_covers_buckets(session):
    s3 = session.client("s3")
    s3.create_bucket(Bucket="covered")
    account = session.client("sts").get_caller_identity()["Account"]
    session.client("s3control").put_public_access_block(AccountId=account, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    assert run(session, "DATA-01").status == Status.PASS
    assert run(session, "DATA-02").status == Status.PASS


def test_tls_enforcement(session):
    s3 = session.client("s3")
    s3.create_bucket(Bucket="no-policy")
    s3.create_bucket(Bucket="tls-only")
    s3.put_bucket_policy(Bucket="tls-only", Policy=json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Deny", "Principal": "*", "Action": "s3:*",
        "Resource": ["arn:aws:s3:::tls-only", "arn:aws:s3:::tls-only/*"],
        "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}))
    by_bucket = {f.resource: f.status for f in run(session, "DATA-03").findings}
    assert by_bucket == {"arn:aws:s3:::no-policy": Status.FAIL, "arn:aws:s3:::tls-only": Status.PASS}


def test_ebs_default_encryption(session):
    assert run(session, "DATA-05").status == Status.FAIL
    session.client("ec2").enable_ebs_encryption_by_default()
    assert run(session, "DATA-05").status == Status.PASS


def test_public_unencrypted_rds_fails(session):
    session.client("rds").create_db_instance(
        DBInstanceIdentifier="db1", DBInstanceClass="db.t3.micro", Engine="postgres",
        MasterUsername="admin", MasterUserPassword="password123", AllocatedStorage=20,
        PubliclyAccessible=True, StorageEncrypted=False, BackupRetentionPeriod=1)
    assert run(session, "DATA-06").status == Status.FAIL
    assert run(session, "DATA-07").status == Status.FAIL
    assert run(session, "AVL-01").status == Status.FAIL


def test_kms_rotation(session):
    kms = session.client("kms")
    key = kms.create_key()["KeyMetadata"]["KeyId"]
    assert run(session, "DATA-08").status == Status.FAIL
    kms.enable_key_rotation(KeyId=key)
    assert run(session, "DATA-08").status == Status.PASS


# --- Network ----------------------------------------------------------------------------

def _sg_with(session, perm):
    ec2 = session.client("ec2")
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    sg = ec2.create_security_group(GroupName="t", Description="t", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[perm])
    return sg


def test_ssh_open_to_world_fails(session):
    sg = _sg_with(session, {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]})
    res = run(session, "NET-01")
    assert res.status == Status.FAIL
    assert any(sg in f.resource and f.status == Status.FAIL for f in res.findings)


def test_port_range_covering_rdp_on_ipv6_fails(session):
    _sg_with(session, {"IpProtocol": "tcp", "FromPort": 3000, "ToPort": 4000, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]})
    assert run(session, "NET-01").status == Status.FAIL


def test_https_open_to_world_is_fine(session):
    _sg_with(session, {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]})
    assert run(session, "NET-01").status == Status.PASS


def test_evidence_is_captured_for_every_call(session):
    res = run(session, "DATA-05")
    assert res.evidence and res.evidence[0].operation == "get_ebs_encryption_by_default"
    assert res.evidence[0].captured_at


def test_open_ssh_group_says_whether_it_is_in_use(session):
    ec2 = session.client("ec2")
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    subnet = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc]}])["Subnets"][0]["SubnetId"]
    perm = {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    used = ec2.create_security_group(GroupName="used", Description="u", VpcId=vpc)["GroupId"]
    idle = ec2.create_security_group(GroupName="idle", Description="i", VpcId=vpc)["GroupId"]
    for g in (used, idle):
        ec2.authorize_security_group_ingress(GroupId=g, IpPermissions=[perm])
    ec2.create_network_interface(SubnetId=subnet, Groups=[used])
    details = {f.resource.split()[0]: f.detail for f in run(session, "NET-01").findings}
    assert "attached to a running resource" in details[used]
    assert "safe to delete" in details[idle]
