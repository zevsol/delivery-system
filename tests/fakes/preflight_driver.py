"""Deterministic read-only Driver fixture for the Preflight contract."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from delivery_system.drivers.contract import DriverReadResponse


class PreflightFakeDriver:
    def __init__(self, response: DriverReadResponse | None = None, error: Exception | None = None):
        self.response = response
        self.error = error
        self.trace: list[dict[str, Any]] = []

    def read_repository(self, repository: str, query_scope: Mapping[str, object]) -> DriverReadResponse:
        self.trace.append({"operation": "read_repository", "repository": repository, "query_scope": deepcopy(dict(query_scope))})
        if self.error is not None:
            raise self.error
        if self.response is None:
            raise RuntimeError("missing_fixture_response")
        return self.response

