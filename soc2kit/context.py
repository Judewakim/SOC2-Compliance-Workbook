"""Per-check execution context. All AWS calls go through it so every response is captured as evidence."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.config import Config

from .models import EvidenceRecord

_BOTO_CONFIG = Config(retries={"max_attempts": 8, "mode": "adaptive"}, user_agent_extra="soc2kit")


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class CheckContext:
    def __init__(self, session: boto3.Session, region: str, account_id: str):
        self.session = session
        self.region = region
        self.account_id = account_id
        self.evidence: list[EvidenceRecord] = []
        self._clients: dict[str, Any] = {}

    def client(self, service: str):
        if service not in self._clients:
            self._clients[service] = self.session.client(service, region_name=self.region, config=_BOTO_CONFIG)
        return self._clients[service]

    def call(self, service: str, operation: str, **params) -> dict:
        """Call one AWS API and record the raw response as evidence."""
        response = getattr(self.client(service), operation)(**params)
        response = {k: v for k, v in response.items() if k != "ResponseMetadata"}
        self._record(service, operation, params, response)
        return response

    def paginate(self, service: str, operation: str, key: str, **params) -> list:
        """Call a paginated AWS API, return the concatenated `key` list, record it as one evidence entry."""
        items: list = []
        for page in self.client(service).get_paginator(operation).paginate(**params):
            items.extend(page.get(key, []))
        self._record(service, operation, params, {key: items})
        return items

    def record(self, service: str, operation: str, params: dict, response: Any) -> None:
        """Record evidence for a call made outside call()/paginate() (e.g. an expected error)."""
        self._record(service, operation, params, response)

    def _record(self, service: str, operation: str, params: dict, response: Any) -> None:
        self.evidence.append(
            EvidenceRecord(
                service=service,
                operation=operation,
                params=params,
                region=self.region,
                captured_at=utcnow(),
                response=response,
            )
        )


def error_code(exc: Exception) -> str:
    return getattr(exc, "response", {}).get("Error", {}).get("Code", "")
