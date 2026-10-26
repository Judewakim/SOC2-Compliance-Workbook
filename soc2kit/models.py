"""Core data types: check definitions, per-resource findings and check results."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    # The check could not be evaluated (e.g. AccessDenied, service not available in region).
    # An ERROR is never counted as a pass.
    ERROR = "ERROR"
    # Nothing to evaluate (e.g. no RDS instances). Not counted as a pass or a fail.
    NOT_APPLICABLE = "N/A"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}


@dataclass(frozen=True)
class CheckDef:
    id: str
    title: str
    description: str
    criteria: tuple[str, ...]          # SOC 2 Trust Services Criteria, e.g. ("CC6.1",)
    severity: Severity
    service: str
    scope: str                         # "global" (run once) or "regional" (run per region)
    permissions: tuple[str, ...]       # IAM actions the check needs; drives the generated policy
    remediation: str
    func: Callable[..., Any] = field(compare=False, repr=False)


@dataclass
class Finding:
    """Outcome for one resource (a bucket, a user, a security group...)."""
    resource: str
    status: Status
    detail: str = ""


@dataclass
class EvidenceRecord:
    """One raw API response captured as audit evidence."""
    service: str
    operation: str
    params: dict
    region: str
    captured_at: str
    response: Any


@dataclass
class CheckResult:
    check: CheckDef
    region: str
    status: Status
    summary: str
    findings: list[Finding] = field(default_factory=list)
    evidence: list[EvidenceRecord] = field(default_factory=list)
    error: str | None = None
    started_at: str = ""
    finished_at: str = ""

    @property
    def evidence_file(self) -> str:
        suffix = "" if self.check.scope == "global" else f"__{self.region}"
        return f"evidence/{self.check.id}{suffix}.json"
