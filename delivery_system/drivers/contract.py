"""Typed, read-only boundary for repository Driver implementations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol, Sequence


PermissionValue = bool | None


def normalize_repository_identity(repository: str) -> str:
    if not isinstance(repository, str):
        raise ValueError("repository_identity_invalid")
    parts = [part.strip() for part in repository.split("/")]
    if len(parts) != 2 or not all(parts):
        raise ValueError("repository_identity_invalid")
    return "/".join(part.lower() for part in parts)


@dataclass(frozen=True)
class RuntimeEvidenceBinding:
    """Runtime-owned identity supplied separately from Driver facts."""

    workspace_identity: str
    preview_id: str
    revision: int


@dataclass(frozen=True)
class DriverReadResponse:
    """Untrusted remote facts; it contains no Runtime identity or Evidence ID."""

    requested_repository: str
    canonical_repository: str
    remote_repository_id: str
    authenticated_subject: str | None
    visibility: str | None
    permissions: Mapping[str, PermissionValue]
    capabilities: Mapping[str, PermissionValue]
    query_scope: Mapping[str, object]
    query_complete: bool
    pagination_complete: bool
    issue_records: Sequence[Mapping[str, object]]
    relationship_records: Sequence[Mapping[str, object]]
    evidence_material: Sequence[Mapping[str, object]]
    source_identity: str | None
    remote_content_digest: str


class ReadOnlyDriver(Protocol):
    """Minimum logical Driver contract consumed by offline Preflight."""

    def read_repository(
        self, repository: str, query_scope: Mapping[str, object]
    ) -> DriverReadResponse:
        """Read repository identity, capabilities, and scoped work-item facts."""

