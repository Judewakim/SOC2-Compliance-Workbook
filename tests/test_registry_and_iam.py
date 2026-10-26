"""Keeps the IAM templates in lock-step with what the checks actually call."""
import json
import re
from pathlib import Path

from soc2kit.registry import all_checks, required_permissions

ROOT = Path(__file__).resolve().parents[1]


def test_check_ids_unique_and_complete():
    checks = all_checks()
    assert len({c.id for c in checks}) == len(checks) >= 30
    for c in checks:
        assert c.permissions and c.criteria and c.remediation, c.id


def test_policy_file_matches_checks():
    doc = json.loads((ROOT / "iam/soc2kit-readonly-policy.json").read_text())
    assert sorted(doc["Statement"][0]["Action"]) == required_permissions()


def test_cloudformation_matches_checks():
    text = (ROOT / "iam/cloudformation/soc2kit-readonly-role.yaml").read_text()
    actions = re.findall(r"^\s+- ([a-z0-9-]+:[A-Za-z]+)\s*$", text, re.M)
    assert sorted(actions) == required_permissions()


def test_policy_is_read_only():
    write_verbs = ("Put", "Create", "Delete", "Update", "Attach", "Detach", "Set", "Modify", "Tag", "Start", "Stop")
    for action in required_permissions():
        verb = action.split(":")[1]
        assert not verb.startswith(write_verbs), action
        # No data-plane reads (object contents, secret values, log contents).
        assert action not in ("s3:GetObject", "secretsmanager:GetSecretValue", "logs:GetLogEvents"), action


def test_no_shell_execution_anywhere():
    for py in (ROOT / "soc2kit").rglob("*.py"):
        src = py.read_text()
        assert "subprocess" not in src and "os.system" not in src and "shell=True" not in src, py
