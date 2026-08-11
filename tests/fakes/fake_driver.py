"""Deterministic repository fixture driver; never accesses the network."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


class FakeDriver:
    is_fake = True

    def __init__(self, repository: dict[str, Any] | None = None, issues: list[dict[str, Any]] | None = None):
        self.repository = deepcopy(repository or {
            "repository_id": "fake-repository",
            "owner_type": "user",
            "visibility": "private",
            "archived": False,
            "read_only": False,
            "can_read": True,
            "can_write": True,
            "permissions": {"read": True, "write": True},
            "capabilities": ["issues", "sub_issues", "dependencies", "labels", "milestones", "assignees"],
            "query_complete": True,
        })
        self.issues = deepcopy(issues or [])
        for issue in self.issues:
            if "item_type" not in issue:
                raise ValueError("FakeDriver fixtures require item_type")
        self.trace: list[dict[str, Any]] = []

    def inspect_repository(self, repository: str) -> dict[str, Any]:
        self.trace.append({"operation": "inspect_repository", "repository": repository})
        if self.repository.get("read_error"):
            raise RuntimeError(str(self.repository["read_error"]))
        result = deepcopy(self.repository)
        result["repository"] = repository
        return result

    def search_issues(self, repository: str, query: str) -> list[dict[str, Any]]:
        self.trace.append({"operation": "search_issues", "repository": repository, "query": query})
        return deepcopy(self.issues)

    def write(self, *_args: Any, **_kwargs: Any) -> None:
        self.trace.append({"operation": "write"})
        raise RuntimeError("FakeDriver is read-only and never performs writes")
