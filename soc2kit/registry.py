"""Check registry. Every check is a plain function registered with @check."""
from __future__ import annotations

import re
from collections.abc import Callable

from .models import CheckDef, Severity

_REGISTRY: dict[str, CheckDef] = {}
_CRITERION = re.compile(r"^(CC\d\.\d|A1\.\d|C1\.\d|PI1\.\d|P\d\.\d)$")


def check(
    *,
    id: str,
    title: str,
    description: str,
    criteria: list[str],
    severity: Severity,
    service: str,
    scope: str,
    permissions: list[str],
    remediation: str,
) -> Callable:
    if scope not in ("global", "regional"):
        raise ValueError(f"{id}: scope must be 'global' or 'regional'")
    for c in criteria:
        if not _CRITERION.match(c):
            raise ValueError(f"{id}: invalid Trust Services Criterion {c!r}")

    def decorator(func: Callable) -> Callable:
        if id in _REGISTRY:
            raise ValueError(f"Duplicate check id {id}")
        _REGISTRY[id] = CheckDef(
            id=id,
            title=title,
            description=description,
            criteria=tuple(criteria),
            severity=severity,
            service=service,
            scope=scope,
            permissions=tuple(permissions),
            remediation=remediation,
            func=func,
        )
        return func

    return decorator


def all_checks() -> list[CheckDef]:
    # Importing the package registers every check module.
    from . import checks  # noqa: F401

    return sorted(_REGISTRY.values(), key=lambda c: c.id)


def required_permissions() -> list[str]:
    perms = {"sts:GetCallerIdentity", "ec2:DescribeRegions"}
    for c in all_checks():
        perms.update(c.permissions)
    return sorted(perms)
