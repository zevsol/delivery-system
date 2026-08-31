"""Typed and canonical remote repository snapshot contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Mapping

from delivery_system.canonical import digest, normalize


@dataclass(frozen=True)
class RemoteQueryScope:
    values: Mapping[str, object]

    def to_dict(self) -> dict[str, object]:
        return normalize(dict(self.values))


def _is_timezone_aware_timestamp(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


@dataclass(frozen=True)
class RemoteIssueRecord:
    issue_id: str
    item_type: str
    title: str
    updated_at: str
    repository_identity: str

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "RemoteIssueRecord":
        issue_id, item_type, title, updated_at, repository_identity = (value.get(key) for key in ("issue_id", "item_type", "title", "updated_at", "repository_identity"))
        if not isinstance(issue_id, (str, int)) or not str(issue_id):
            raise ValueError("remote_issue_identity_incomplete")
        if item_type not in {"issue", "pull_request"}:
            raise ValueError("remote_item_type_required")
        if not isinstance(title, str) or not title.strip():
            raise ValueError("remote_issue_title_required")
        if not isinstance(updated_at, str) or not updated_at.strip():
            raise ValueError("remote_issue_updated_at_required")
        if not isinstance(repository_identity, str) or not repository_identity.strip():
            raise ValueError("remote_issue_repository_identity_required")
        if not _is_timezone_aware_timestamp(updated_at):
            raise ValueError("remote_issue_updated_at_timezone_required")
        return cls(str(issue_id), str(item_type), title, updated_at, repository_identity)

    def to_dict(self) -> dict[str, str]:
        return {"issue_id": self.issue_id, "item_type": self.item_type, "title": self.title, "updated_at": self.updated_at, "repository_identity": self.repository_identity}


@dataclass(frozen=True)
class RemoteRelationshipRecord:
    relationship_type: str
    source_issue_id: str
    target_issue_id: str

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "RemoteRelationshipRecord":
        kind, source, target = value.get("kind"), value.get("from"), value.get("to")
        if kind not in {"existing_dependency", "existing_parent", "proposed_dependency_candidate", "proposed_parent_candidate"}:
            raise ValueError("remote_relationship_type_required")
        if not isinstance(source, (str, int)) or not isinstance(target, (str, int)):
            raise ValueError("remote_relationship_reference_required")
        return cls(str(kind), str(source), str(target))

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.relationship_type, "from": self.source_issue_id, "to": self.target_issue_id}


@dataclass(frozen=True)
class RemotePermissionSet:
    values: Mapping[str, bool]

    def to_dict(self) -> dict[str, bool]:
        if any(not isinstance(key, str) or not isinstance(value, bool) for key, value in self.values.items()):
            raise ValueError("remote_permission_boolean_required")
        return {key: self.values[key] for key in sorted(self.values)}


@dataclass(frozen=True)
class RemoteCapabilitySet:
    values: tuple[str, ...]

    def __post_init__(self) -> None:
        if any(not isinstance(value, str) or not value for value in self.values) or len(set(self.values)) != len(self.values):
            raise ValueError("remote_capability_set_invalid")

    def to_list(self) -> list[str]:
        return sorted(self.values)


@dataclass(frozen=True)
class TypedRemoteSnapshot:
    repository_identity: str
    query_scope: RemoteQueryScope
    query_complete: bool
    pagination_complete: bool
    issue_records: tuple[RemoteIssueRecord, ...]
    permissions: RemotePermissionSet
    capabilities: RemoteCapabilitySet
    relationship_records: tuple[RemoteRelationshipRecord, ...]
    evidence_ids: tuple[str, ...] = ()
    schema_version: str = "remote-snapshot-v1"
    observed_at: str | None = None

    @classmethod
    def from_records(cls, repository_identity: str, query_scope: Mapping[str, object],
                     query_complete: bool, pagination_complete: bool,
                     issue_records: list[Mapping[str, object]], permissions: Mapping[str, bool],
                     capabilities: list[str], relationship_records: list[Mapping[str, object]],
                     evidence_ids: list[str] | None = None, observed_at: str | None = None):
        if not isinstance(repository_identity, str) or not repository_identity.strip():
            raise ValueError("remote_repository_identity_required")
        if not isinstance(query_complete, bool) or not isinstance(pagination_complete, bool):
            raise ValueError("remote_query_completeness_boolean_required")
        issues = tuple(RemoteIssueRecord.from_dict(record) for record in issue_records)
        if any(issue.repository_identity != repository_identity for issue in issues):
            raise ValueError("remote_issue_repository_identity_mismatch")
        if any(issue.item_type == "pull_request" for issue in issues):
            raise ValueError("pull_request_not_issue_candidate")
        ids = [issue.issue_id for issue in issues]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate_remote_issue_id")
        relationships = tuple(RemoteRelationshipRecord.from_dict(record) for record in relationship_records)
        known = set(ids)
        if any(record.source_issue_id not in known or record.target_issue_id not in known for record in relationships):
            raise ValueError("remote_relationship_reference_required")
        evidence = tuple(evidence_ids or ())
        if len(evidence) != len(set(evidence)):
            raise ValueError("duplicate_remote_evidence_id")
        return cls(repository_identity, RemoteQueryScope(normalize(dict(query_scope))),
                   query_complete, pagination_complete, issues,
                   RemotePermissionSet(dict(permissions)), RemoteCapabilitySet(tuple(capabilities)),
                   relationships, tuple(sorted(evidence)), "remote-snapshot-v1", observed_at)

    def to_dict(self) -> dict[str, object]:
        return normalize({
            "repository_identity": self.repository_identity,
            "query_scope": self.query_scope.to_dict(),
            "query_complete": self.query_complete,
            "pagination_complete": self.pagination_complete,
            "issue_records": [record.to_dict() for record in sorted(self.issue_records, key=lambda item: item.issue_id)],
            "permissions": self.permissions.to_dict(),
            "capabilities": self.capabilities.to_list(),
            "relationship_records": [record.to_dict() for record in sorted(self.relationship_records, key=lambda item: (item.relationship_type, item.source_issue_id, item.target_issue_id))],
            "evidence_ids": sorted(self.evidence_ids),
            "schema_version": self.schema_version,
            "observed_at": self.observed_at,
        })

    def digest(self) -> str:
        payload = self.to_dict()
        payload.pop("observed_at", None)
        return digest(payload)
