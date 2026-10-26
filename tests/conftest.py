import os

import boto3
import pytest
from moto import mock_aws

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def _fake_creds(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": REGION}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    yield


@pytest.fixture
def session():
    with mock_aws():
        yield boto3.Session(region_name=REGION)


def run(session, check_id, region=REGION):
    from soc2kit.registry import all_checks
    from soc2kit.runner import run_check

    check = next(c for c in all_checks() if c.id == check_id)
    account = session.client("sts").get_caller_identity()["Account"]
    return run_check(session, check, region, account)


os.environ.setdefault("AWS_DEFAULT_REGION", REGION)
