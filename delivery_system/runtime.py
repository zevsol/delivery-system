"""Runtime-owned context, provenance, lineage, and local preview storage."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from enum import Enum
import hashlib
import os
from pathlib import Path
import sqlite3
import threading
from contextlib import closing
import subprocess
from typing import Any, Callable, Generic, Mapping, Protocol, Sequence, TypeVar
from copy import deepcopy
from datetime import datetime, timezone

def canonical_payload(value: Mapping[str, Any]) -> str:
    from delivery_system.protocol import canonical_payload as _canonical_payload
    return _canonical_payload(value)


def digest(value: Mapping[str, Any]) -> str:
    from delivery_system.protocol import digest as _digest
    return _digest(value)


def normalize(value: Any) -> Any:
    from delivery_system.protocol import normalize as _normalize
    return _normalize(value)


class DeclaredSource(str, Enum):
    USER_ASSERTED = "user_asserted"
    MODEL_PROPOSED = "model_proposed"
    MODEL_ASSUMPTION = "model_assumption"


class PreviewLevel(str, Enum):
    CONCEPTUAL = "Conceptual"
    REPOSITORY_AWARE = "RepositoryAware"
    WRITE_ELIGIBLE = "WriteEligible"


@dataclass(frozen=True)
class SealedPreview:
    """The only Runtime-owned Sealed Preview model."""
    workspace_identity: str
    request_id: str
    preview_id: str
    revision: int
    preview_level: str
    provenance_status: str
    repository_identity: str | None
    remote_authority: str | None
    semantic_payload: Mapping[str, Any]
    operation_intents: tuple[dict[str, Any], ...]
    plan_digest: str
    operation_set_digest: str
    remote_snapshot: Mapping[str, Any] | None
    remote_snapshot_digest: str | None
    items: tuple[dict[str, Any], ...]
    evidence_ids: tuple[str, ...]
    blockers: tuple[str, ...] = ()
    planner_observations: tuple[dict[str, Any], ...] = ()
    sealed_preview_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return normalize({
            "workspace_identity": self.workspace_identity,
            "request_id": self.request_id,
            "preview_id": self.preview_id,
            "revision": self.revision,
            "preview_level": self.preview_level,
            "provenance_status": self.provenance_status,
            "repository_identity": self.repository_identity,
            "remote_authority": self.remote_authority,
            "semantic_payload": dict(self.semantic_payload),
            "operation_intents": list(self.operation_intents),
            "plan_digest": self.plan_digest,
            "operation_set_digest": self.operation_set_digest,
            "remote_snapshot": self.remote_snapshot,
            "remote_snapshot_digest": self.remote_snapshot_digest,
            "items": list(self.items),
            "evidence_ids": list(self.evidence_ids),
            "blockers": list(self.blockers),
            "planner_observations": list(self.planner_observations),
            "sealed_preview_digest": self.sealed_preview_digest,
        })

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "SealedPreview":
        if not isinstance(payload, Mapping):
            raise ValueError("sealed_preview_required")
        required = {
            "workspace_identity", "request_id", "preview_id", "revision", "preview_level",
            "provenance_status", "repository_identity", "remote_authority", "semantic_payload",
            "operation_intents", "plan_digest", "operation_set_digest", "remote_snapshot",
            "remote_snapshot_digest", "items", "evidence_ids", "blockers", "planner_observations",
            "sealed_preview_digest",
        }
        if set(payload) != required:
            raise ValueError("sealed_preview_schema_invalid")
        if not all(isinstance(payload.get(key), str) and bool(payload.get(key)) for key in ("workspace_identity", "request_id", "preview_id")):
            raise ValueError("sealed_preview_identity_invalid")
        if not isinstance(payload.get("revision"), int) or isinstance(payload.get("revision"), bool) or payload["revision"] < 1:
            raise ValueError("sealed_preview_revision_invalid")
        if payload.get("preview_level") not in {level.value for level in PreviewLevel}:
            raise ValueError("sealed_preview_level_invalid")
        if payload.get("provenance_status") != "declared_unverified":
            raise ValueError("preview_provenance_invalid")
        if (not isinstance(payload.get("semantic_payload"), Mapping) or
                not isinstance(payload.get("operation_intents"), list) or
                not all(isinstance(value, Mapping) for value in payload["operation_intents"]) or
                not isinstance(payload.get("items"), list) or
                not all(isinstance(value, Mapping) for value in payload["items"]) or
                not isinstance(payload.get("evidence_ids"), list) or
                not all(isinstance(value, str) and bool(value) for value in payload.get("evidence_ids", [])) or
                not isinstance(payload.get("blockers"), list) or
                not all(isinstance(value, str) for value in payload["blockers"]) or
                not isinstance(payload.get("planner_observations"), list) or
                not all(isinstance(value, Mapping) for value in payload["planner_observations"])):
            raise ValueError("sealed_preview_payload_invalid")
        if not all(isinstance(payload.get(key), str) and bool(payload.get(key)) for key in ("plan_digest", "operation_set_digest", "sealed_preview_digest")):
            raise ValueError("sealed_preview_digest_field_invalid")
        if payload.get("repository_identity") is not None and (not isinstance(payload["repository_identity"], str) or not payload["repository_identity"].strip()):
            raise ValueError("sealed_preview_repository_invalid")
        if payload.get("remote_authority") is not None and not isinstance(payload["remote_authority"], str):
            raise ValueError("sealed_preview_authority_invalid")
        if payload.get("remote_snapshot") is not None and not isinstance(payload["remote_snapshot"], Mapping):
            raise ValueError("sealed_preview_remote_invalid")
        if payload.get("remote_snapshot_digest") is not None and (not isinstance(payload["remote_snapshot_digest"], str) or not payload["remote_snapshot_digest"]):
            raise ValueError("sealed_preview_remote_digest_invalid")
        return cls(
            workspace_identity=payload["workspace_identity"],
            request_id=payload["request_id"],
            preview_id=payload["preview_id"],
            revision=payload["revision"],
            preview_level=payload["preview_level"],
            provenance_status=payload["provenance_status"],
            repository_identity=payload.get("repository_identity"),
            remote_authority=payload.get("remote_authority"),
            semantic_payload=deepcopy(payload["semantic_payload"]),
            operation_intents=tuple(deepcopy(payload["operation_intents"])),
            plan_digest=payload["plan_digest"],
            operation_set_digest=payload["operation_set_digest"],
            remote_snapshot=deepcopy(payload.get("remote_snapshot")),
            remote_snapshot_digest=payload.get("remote_snapshot_digest"),
            items=tuple(deepcopy(payload["items"])),
            evidence_ids=tuple(str(value) for value in payload.get("evidence_ids", ())),
            blockers=tuple(str(value) for value in payload.get("blockers", ())),
            planner_observations=tuple(deepcopy(payload.get("planner_observations", ()))),
            sealed_preview_digest=payload["sealed_preview_digest"],
        )

    def is_stale(self, current_remote_snapshot_digest: str) -> bool:
        return self.remote_snapshot_digest != current_remote_snapshot_digest


T = TypeVar("T")


@dataclass(frozen=True)
class SourcedValue(Generic[T]):
    value: T
    declared_source: DeclaredSource

    @property
    def provenance_status(self) -> str:
        return "declared_unverified"

    def to_dict(self) -> dict[str, object]:
        return {
            "value": self.value,
            "declared_source": self.declared_source.value,
            "provenance_status": self.provenance_status,
        }


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    workspace_identity: str
    preview_id: str
    revision: int
    evidence_type: str
    source_kind: str
    declared_source: DeclaredSource | None
    verification_status: str
    source_identity: str
    repository_identity: str | None
    query_scope: Mapping[str, object] | None
    schema_version: str
    subject_ref: str
    payload: Any
    evidence_digest: str
    created_at: str | None = None

    @classmethod
    def create(cls, workspace_identity: str, preview_id: str, revision: int,
               evidence_type: str, source_kind: str,
               declared_source: DeclaredSource | None, subject_ref: str,
               payload: Any, created_at: str | None = None,
               source_identity: str = "declared-input",
               repository_identity: str | None = None,
               query_scope: Mapping[str, object] | None = None,
               schema_version: str = "evidence-v1") -> "EvidenceRecord":
        if source_kind in {"runtime", "driver"}:
            raise ValueError("controlled_evidence_source")
        return cls._create_controlled(
            workspace_identity, preview_id, revision, evidence_type, source_kind,
            declared_source, subject_ref, payload, created_at, source_identity,
            repository_identity, query_scope, schema_version,
        )

    @classmethod
    def _create_controlled(cls, workspace_identity: str, preview_id: str, revision: int,
                           evidence_type: str, source_kind: str,
                           declared_source: DeclaredSource | None, subject_ref: str,
                           payload: Any, created_at: str | None,
                           source_identity: str, repository_identity: str | None,
                           query_scope: Mapping[str, object] | None,
                           schema_version: str) -> "EvidenceRecord":
        if source_kind not in {"declared", "runtime", "driver"}:
            raise ValueError("invalid_evidence_source_kind")
        if source_kind != "declared":
            raise ValueError("controlled_evidence_source")
        if source_kind == "declared":
            if declared_source is None:
                raise ValueError("declared_source_required")
            verification_status = "declared_unverified"
        elif declared_source is not None:
            raise ValueError("declared_source_forbidden")
        else:
            verification_status = "declared_unverified"
        evidence_payload = {
            "evidence_type": evidence_type,
            "source_kind": source_kind,
            "declared_source": declared_source.value if declared_source else None,
            "subject_ref": subject_ref,
            "source_identity": source_identity,
            "repository_identity": repository_identity,
            "query_scope": query_scope,
            "schema_version": schema_version,
            "payload": payload,
        }
        evidence_digest = digest(evidence_payload)
        identity_payload = {
            "domain": "delivery-system:evidence-id:v1",
            "workspace_identity": workspace_identity,
            "preview_id": preview_id,
            "revision": revision,
            "evidence_type": evidence_type,
            "subject_ref": subject_ref,
            "evidence_digest": evidence_digest,
        }
        evidence_id = "ev_" + __import__("hashlib").sha256(
            canonical_payload(identity_payload).encode("utf-8")
        ).hexdigest()
        return cls(evidence_id, workspace_identity, preview_id, revision, evidence_type,
                   source_kind, declared_source, verification_status, source_identity,
                   repository_identity, normalize(query_scope) if query_scope is not None else None,
                   schema_version, subject_ref, normalize(payload), evidence_digest, created_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "workspace_identity": self.workspace_identity,
            "preview_id": self.preview_id,
            "revision": self.revision,
            "evidence_type": self.evidence_type,
            "source_kind": self.source_kind,
            "declared_source": self.declared_source.value if self.declared_source else None,
            "verification_status": self.verification_status,
            "source_identity": self.source_identity,
            "repository_identity": self.repository_identity,
            "query_scope": self.query_scope,
            "schema_version": self.schema_version,
            "subject_ref": self.subject_ref,
            "payload": self.payload,
            "evidence_digest": self.evidence_digest,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EvidenceRecord":
        source = data.get("declared_source")
        source_kind = str(data["source_kind"])
        if source_kind != "declared":
            if source_kind not in {"runtime", "driver"} or source is not None:
                raise ValueError("evidence_source_invalid")
            status = data.get("verification_status")
            expected_status = "runtime_verified" if source_kind == "runtime" else "driver_verified"
            if status != expected_status:
                raise ValueError("evidence_verification_status_invalid")
            record = cls(
                str(data["evidence_id"]), str(data["workspace_identity"]), str(data["preview_id"]), int(data["revision"]),
                str(data["evidence_type"]), source_kind, None, expected_status, str(data["source_identity"]),
                data.get("repository_identity"), normalize(data.get("query_scope")) if data.get("query_scope") is not None else None,
                str(data["schema_version"]), str(data["subject_ref"]), normalize(data["payload"]),
                str(data["evidence_digest"]), data.get("created_at"),
            )
            evidence_payload = {
                "evidence_type": record.evidence_type, "source_kind": record.source_kind,
                "declared_source": None, "subject_ref": record.subject_ref,
                "source_identity": record.source_identity, "repository_identity": record.repository_identity,
                "query_scope": record.query_scope, "schema_version": record.schema_version,
                "payload": record.payload,
            }
            if record.evidence_digest != digest(evidence_payload):
                raise ValueError("evidence_digest_mismatch")
            identity_payload = {
                "domain": "delivery-system:evidence-id:v1", "workspace_identity": record.workspace_identity,
                "preview_id": record.preview_id, "revision": record.revision,
                "evidence_type": record.evidence_type, "subject_ref": record.subject_ref,
                "evidence_digest": record.evidence_digest,
            }
            expected_id = "ev_" + hashlib.sha256(canonical_payload(identity_payload).encode("utf-8")).hexdigest()
            if record.evidence_id != expected_id:
                raise ValueError("evidence_id_mismatch")
            return record
        record = cls._create_controlled(
            str(data["workspace_identity"]), str(data["preview_id"]), int(data["revision"]),
            str(data["evidence_type"]), str(data["source_kind"]),
            DeclaredSource(source) if source is not None else None,
            str(data["subject_ref"]), data["payload"], data.get("created_at"),
            str(data["source_identity"]), data.get("repository_identity"),
            data.get("query_scope"), str(data["schema_version"]),
        )
        if record.evidence_id != data.get("evidence_id") or record.evidence_digest != data.get("evidence_digest"):
            raise ValueError("evidence_digest_mismatch")
        return record


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


class AuditResult(str, Enum):
    PASSED = "Passed"
    NEEDS_INFORMATION = "NeedsInformation"
    CHANGES_REQUIRED = "ChangesRequired"
    BLOCKED = "Blocked"


class AuditStatus(str, Enum):
    ACTIVE = "Active"
    STALE = "Stale"
    INVALID = "Invalid"


@dataclass(frozen=True)
class AuditRecord:
    audit_id: str
    preview_id: str
    revision: int
    plan_digest: str
    remote_snapshot_digest: str | None
    audit_digest: str
    result: AuditResult
    operation_set_digest: str
    status: AuditStatus
    sealed_preview_digest: str = ""
    workspace_identity: str = ""
    audit_scope: str = "Conceptual"
    audit_payload_digest: str = ""
    audit_context_digest: str = ""
    rule_registry_version: str | None = None
    rule_registry_digest: str | None = None
    rule_evaluations: tuple[dict[str, Any], ...] = ()
    findings: tuple[dict[str, Any], ...] = ()
    evidence_refs: tuple[str, ...] = ()
    created_at: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.result, AuditResult) or not isinstance(self.status, AuditStatus):
            raise TypeError("AuditRecord result and status must use approved enums")
        if (not isinstance(self.revision, int) or isinstance(self.revision, bool) or self.revision < 1 or
                any(not isinstance(value, str) or not value for value in (
            self.audit_id, self.preview_id, self.plan_digest,
            self.audit_digest, self.operation_set_digest,
        )) or (self.remote_snapshot_digest is not None and
                (not isinstance(self.remote_snapshot_digest, str) or not self.remote_snapshot_digest))):
            raise ValueError("AuditRecord required fields are invalid")
        if self.audit_payload_digest:
            if (not self.sealed_preview_digest or not self.workspace_identity or
                    not self.audit_context_digest or not self.rule_registry_version or
                    not self.rule_registry_digest or not self.created_at):
                raise ValueError("audit_record_formal_fields_invalid")
            try:
                parsed = datetime.fromisoformat(self.created_at.replace("Z", "+00:00"))
            except (TypeError, ValueError) as exc:
                raise ValueError("audit_created_at_invalid") from exc
            offset = parsed.utcoffset()
            if parsed.tzinfo is None or offset is None or offset.total_seconds() != 0:
                raise ValueError("audit_created_at_invalid")

    @classmethod
    def create(
        cls,
        audit_id: str,
        preview_id: str,
        revision: int,
        plan_digest: str,
        remote_snapshot_digest: str | None,
        operation_set_digest: str,
        result: AuditResult,
        *,
        sealed_preview_digest: str = "",
        workspace_identity: str = "",
        audit_scope: str = "Conceptual",
        audit_payload_digest: str = "",
        audit_context_digest: str = "",
        rule_registry_version: str | None = None,
        rule_registry_digest: str | None = None,
        rule_evaluations: tuple[dict[str, Any], ...] = (),
        findings: tuple[dict[str, Any], ...] = (),
        evidence_refs: tuple[str, ...] = (),
        created_at: str = "",
    ) -> "AuditRecord":
        record = cls(
            audit_id, preview_id, revision, plan_digest, remote_snapshot_digest,
            "pending", result, operation_set_digest, AuditStatus.ACTIVE,
            sealed_preview_digest, workspace_identity, audit_scope, audit_payload_digest, audit_context_digest,
            rule_registry_version, rule_registry_digest, tuple(rule_evaluations), tuple(findings),
            tuple(evidence_refs), created_at,
        )
        return replace(record, audit_digest=record._computed_digest())

    def _computed_digest(self) -> str:
        from delivery_system.protocol import digest
        return digest({
            "audit_id": self.audit_id,
            "preview_id": self.preview_id,
            "revision": self.revision,
            "plan_digest": self.plan_digest,
            "remote_snapshot_digest": self.remote_snapshot_digest,
            "operation_set_digest": self.operation_set_digest,
            "sealed_preview_digest": self.sealed_preview_digest,
            "result": self.result.value,
            "status": self.status.value,
            "workspace_identity": self.workspace_identity,
            "audit_scope": self.audit_scope,
            "audit_payload_digest": self.audit_payload_digest,
            "audit_context_digest": self.audit_context_digest,
            "rule_registry_version": self.rule_registry_version,
            "rule_registry_digest": self.rule_registry_digest,
        })

    def verify_digest(self) -> bool:
        return bool(self.audit_digest) and self.audit_digest == self._computed_digest()

    def with_status(self, status: AuditStatus) -> "AuditRecord":
        return replace(self, status=status)

    def transition(self, status: AuditStatus, reason: str) -> "AuditRecord":
        allowed = {
            AuditStatus.ACTIVE: {AuditStatus.STALE, AuditStatus.INVALID},
            AuditStatus.STALE: {AuditStatus.INVALID},
            AuditStatus.INVALID: set(),
        }
        if status == self.status:
            return self
        if status not in allowed[self.status]:
            raise ValueError("invalid audit status transition")
        del reason
        return replace(self.with_status(status), audit_digest="pending")._with_digest()

    def _with_digest(self) -> "AuditRecord":
        return replace(self, audit_digest=self._computed_digest())

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["result"] = self.result.value
        result["status"] = self.status.value
        return result

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AuditRecord":
        formal = all(key in data for key in (
            "sealed_preview_digest", "workspace_identity", "audit_scope",
            "audit_payload_digest", "audit_context_digest", "rule_registry_version",
            "rule_registry_digest", "created_at",
        ))
        return cls(
            data["audit_id"], data["preview_id"], data["revision"], data["plan_digest"],
            data["remote_snapshot_digest"], data["audit_digest"], AuditResult(data["result"]),
            data["operation_set_digest"], AuditStatus(data["status"]),
            data.get("sealed_preview_digest", "") if formal else "",
            data.get("workspace_identity", "") if formal else "",
            data.get("audit_scope", "Conceptual") if formal else "Conceptual",
            data.get("audit_payload_digest", "") if formal else "",
            data.get("audit_context_digest", "") if formal else "",
            data.get("rule_registry_version") if formal else None,
            data.get("rule_registry_digest") if formal else None,
            tuple(data.get("rule_evaluations", ())) if formal else (),
            tuple(data.get("findings", ())) if formal else (),
            tuple(data.get("evidence_refs", ())) if formal else (),
            data.get("created_at", "") if formal else "",
        )

    @property
    def approval_eligible(self) -> bool:
        return self.audit_scope == PreviewLevel.WRITE_ELIGIBLE.value and self.status is AuditStatus.ACTIVE and self.result is AuditResult.PASSED


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    audit_id: str
    audit_digest: str
    audit_result: AuditResult | str
    preview_id: str
    revision: int
    plan_digest: str
    remote_snapshot_digest: str
    operation_set_digest: str
    repository_identity: str | None
    approval_command: str
    approver_claim: str
    approved_at: str
    status: str

    def is_structurally_valid(self) -> bool:
        try:
            result = AuditResult(self.audit_result)
        except ValueError:
            return False
        try:
            parsed_time = datetime.fromisoformat(self.approved_at.replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return False
        return (
            result is AuditResult.PASSED
            and self.approval_command == f"批准写入 {self.preview_id} {self.revision}"
            and isinstance(self.repository_identity, str)
            and bool(self.repository_identity.strip())
            and parsed_time.tzinfo is not None
            and parsed_time.utcoffset() is not None
            and self.status == "valid"
            and all(
                isinstance(value, str) and value
                for value in (
                    self.approval_id,
                    self.audit_id,
                    self.audit_digest,
                    self.preview_id,
                    self.plan_digest,
                    self.remote_snapshot_digest,
                    self.operation_set_digest,
                    self.approval_command,
                    self.approver_claim,
                    self.approved_at,
                )
            )
        )

    def validate_against(self, audit: AuditRecord) -> bool:
        return (
            self.is_structurally_valid()
            and self.audit_result == AuditResult.PASSED
            and audit.result is AuditResult.PASSED
            and audit.status is AuditStatus.ACTIVE
            and audit.verify_digest()
            and self.audit_id == audit.audit_id
            and self.audit_digest == audit.audit_digest
            and self.preview_id == audit.preview_id
            and self.revision == audit.revision
            and self.plan_digest == audit.plan_digest
            and self.remote_snapshot_digest == audit.remote_snapshot_digest
            and self.operation_set_digest == audit.operation_set_digest
        )

    @classmethod
    def create(cls, approval_id: str, audit: AuditRecord, repository_identity: str,
               approver_claim: str, approved_at: str, approval_command: str) -> "ApprovalRecord":
        if audit.result is not AuditResult.PASSED or audit.status is not AuditStatus.ACTIVE:
            raise ValueError("approval_requires_passed_active_audit")
        if not isinstance(audit.remote_snapshot_digest, str) or not audit.remote_snapshot_digest:
            raise ValueError("approval_requires_remote_snapshot_digest")
        return cls(
            approval_id, audit.audit_id, audit.audit_digest, audit.result,
            audit.preview_id, audit.revision, audit.plan_digest,
            audit.remote_snapshot_digest, audit.operation_set_digest,
            repository_identity, approval_command, approver_claim, approved_at, "valid",
        )

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        if isinstance(self.audit_result, AuditResult):
            result["audit_result"] = self.audit_result.value
        return result


class StorePreflightError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _default_ignored(path: Path, workspace_root: Path) -> bool:
    try:
        relative = path.resolve(strict=False).relative_to(workspace_root).as_posix()
    except (ValueError, OSError) as exc:
        raise StorePreflightError("store_not_ignored_or_tracked") from exc
    result = subprocess.run(
        ["git", "check-ignore", "--quiet", "--no-index", "--", relative],
        cwd=workspace_root,
        capture_output=True,
        check=False,
        text=True,
    )
    return result.returncode == 0


def _default_tracked(path: Path, workspace_root: Path) -> bool:
    try:
        relative = path.resolve(strict=False).relative_to(workspace_root).as_posix()
    except (ValueError, OSError) as exc:
        raise StorePreflightError("store_not_ignored_or_tracked") from exc
    result = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "--", relative],
        cwd=workspace_root,
        capture_output=True,
        check=False,
        text=True,
    )
    return result.returncode == 0


def _is_reparse_or_symlink(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction) and is_junction():
        return True
    if os.name == "nt" and path.exists():
        try:
            return bool(os.stat(path, follow_symlinks=False).st_file_attributes & 0x400)
        except (AttributeError, OSError):
            return False
    return False


@dataclass(frozen=True)
class RuntimeContext:
    workspace_root: str
    normalized_workspace_root: str
    workspace_identity: str
    state_path: str

    @classmethod
    def from_workspace_root(cls, workspace_root: str | os.PathLike[str] | None) -> "RuntimeContext":
        if workspace_root is None:
            raise ValueError("workspace_identity_unavailable")
        path = Path(workspace_root).expanduser()
        if not path.is_absolute():
            path = Path.cwd() / path
        try:
            normalized = path.resolve(strict=True)
        except (FileNotFoundError, OSError) as exc:
            raise ValueError("workspace_identity_unavailable") from exc
        if not normalized.is_dir():
            raise ValueError("workspace_identity_unavailable")
        canonical = normalized.as_posix()
        if os.name == "nt":
            canonical = canonical.casefold()
        identity = "ws_v1_" + hashlib.sha256(
            ("delivery-system:workspace:v1:" + canonical).encode("utf-8")
        ).hexdigest()
        state_path = normalized / ".delivery-system" / "state.sqlite3"
        return cls(str(path.absolute()), str(normalized), identity, str(state_path))

    def ensure_store_ready(
        self,
        ignore_checker: Callable[[Path], bool] | None = None,
        tracked_checker: Callable[[Path], bool] | None = None,
    ) -> None:
        state = Path(self.state_path)
        root = Path(self.normalized_workspace_root)
        paths = (state.parent, state, *(Path(f"{state}-{suffix}") for suffix in ("wal", "shm", "journal")))
        if any(_is_reparse_or_symlink(path) for path in paths):
            raise StorePreflightError("store_not_ignored_or_tracked")
        try:
            for path in (state, *paths[2:]):
                if path.exists() and path.resolve(strict=True).parent.parent != root:
                    raise StorePreflightError("store_not_ignored_or_tracked")
            if state.parent.exists() and state.parent.resolve(strict=True) != root / ".delivery-system":
                raise StorePreflightError("store_not_ignored_or_tracked")
        except OSError as exc:
            raise StorePreflightError("store_not_ignored_or_tracked") from exc
        sidecars = (
            state,
            Path(f"{state}-wal"),
            Path(f"{state}-shm"),
            Path(f"{state}-journal"),
        )
        ignored = ignore_checker or (lambda path: _default_ignored(path, root))
        tracked = tracked_checker or (lambda path: _default_tracked(path, root))
        if not all(ignored(path) for path in sidecars) or any(tracked(path) for path in sidecars):
            raise StorePreflightError("store_not_ignored_or_tracked")
        if not state.parent.exists():
            state.parent.mkdir(parents=True, exist_ok=True)
        if state.parent.resolve() != root / ".delivery-system":
            raise StorePreflightError("store_not_ignored_or_tracked")


class PreviewStore(Protocol):
    def save_preview_revision(self, request_id: str, preview_id: str, revision: int,
                              plan_digest: str, remote_snapshot_digest: str | None,
                              operation_set_digest: str, repository_identity: str | None,
                              items: list[dict[str, object]], workspace_identity: str | None = None,
                              canonical_payload: dict[str, object] | None = None,
                              preview_level: str | None = None,
                              evidence_records: list[dict[str, object]] | None = None) -> None: ...
    def get_preview(self, workspace_identity: str, preview_id: str) -> dict[str, object]: ...
    def get_preview_revision(self, workspace_identity: str, preview_id: str, revision: int | None = None) -> dict[str, object]: ...
    def get_evidence_records(self, workspace_identity: str, evidence_ids: list[str]) -> list[dict[str, object]]: ...
    def resolve_item_id(self, workspace_identity: str, previous_preview_id: str, client_ref: str,
                        revision: int | None = None) -> str: ...
    def record_audit(self, audit: AuditRecord) -> None: ...
    def commit_audit(self, audit: AuditRecord) -> AuditRecord: ...
    def get_audit(self, workspace_identity: str, audit_id: str) -> AuditRecord: ...
    def find_audit_by_payload(self, workspace_identity: str, preview_id: str, revision: int, audit_payload_digest: str) -> AuditRecord | None: ...
    def list_active_audits(self, workspace_identity: str, preview_id: str, revision: int) -> list[AuditRecord]: ...
    def transition_audit_status(self, audit_id: str, status: AuditStatus, reason: str) -> AuditRecord: ...
    def record_approval(self, approval: ApprovalRecord) -> None: ...
    def get_approval(self, workspace_identity: str, approval_id: str) -> ApprovalRecord: ...
    def validate_approval_current(self, approval: ApprovalRecord) -> bool: ...
def _validate_preview_payload(canonical: Mapping[str, Any], request_id: str,
                              preview_id: str, revision: int,
                              plan_digest: str, operation_set_digest: str,
                              remote_snapshot_digest: str | None,
                              repository_identity: str | None,
                              evidence_records: list[dict[str, object]] | None,
                              expected_workspace_identity: str) -> dict[str, Any]:
    if not isinstance(canonical, Mapping):
        raise ValueError("sealed_preview_required")
    if (not isinstance(request_id, str) or not request_id or
            not isinstance(preview_id, str) or not preview_id or
            not isinstance(revision, int) or isinstance(revision, bool) or revision < 1 or
            not isinstance(plan_digest, str) or not plan_digest or
            not isinstance(operation_set_digest, str) or not operation_set_digest or
            (remote_snapshot_digest is not None and (not isinstance(remote_snapshot_digest, str) or not remote_snapshot_digest)) or
            (repository_identity is not None and (not isinstance(repository_identity, str) or not repository_identity.strip()))):
        raise ValueError("sealed_preview_argument_invalid")
    parsed = SealedPreview.from_dict(canonical)
    normalized = parsed.to_dict()
    if normalized != dict(canonical):
        raise ValueError("sealed_preview_not_canonical")
    canonical = normalized
    if canonical.get("request_id") != request_id or canonical.get("preview_id") != preview_id or canonical.get("revision") != revision:
        raise ValueError("preview_identity_mismatch")
    if canonical.get("workspace_identity") != expected_workspace_identity:
        raise ValueError("workspace_identity_mismatch")
    validate_sealed_preview_invariants(canonical, expected_workspace_identity)
    semantic = canonical.get("semantic_payload")
    operations = canonical.get("operation_intents")
    if not isinstance(semantic, Mapping) or not isinstance(operations, list):
        raise ValueError("sealed_preview_incomplete")
    if digest(semantic) != plan_digest or canonical.get("plan_digest") != plan_digest:
        raise ValueError("plan_digest_mismatch")
    operation_semantics = {"operation_intents": [
        {key: value for key, value in operation.items() if key not in {"operation_id", "id"}}
        for operation in operations
    ]}
    if digest(operation_semantics) != operation_set_digest or canonical.get("operation_set_digest") != operation_set_digest:
        raise ValueError("operation_set_digest_mismatch")
    if canonical.get("remote_snapshot_digest") != remote_snapshot_digest:
        raise ValueError("remote_snapshot_digest_mismatch")
    if canonical.get("repository_identity") != repository_identity:
        raise ValueError("repository_identity_mismatch")
    remote_payload = canonical.get("remote_snapshot")
    if remote_payload is not None:
        if not isinstance(remote_payload, Mapping):
            raise ValueError("remote_snapshot_invalid")
        query_complete = remote_payload.get("query_complete")
        pagination_complete = remote_payload.get("pagination_complete")
        if not isinstance(query_complete, bool) or not isinstance(pagination_complete, bool):
            raise ValueError("remote_snapshot_invalid")
        snapshot = TypedRemoteSnapshot.from_records(
            repository_identity=str(remote_payload.get("repository_identity", "")),
            query_scope=remote_payload.get("query_scope", {}),
            query_complete=query_complete,
            pagination_complete=pagination_complete,
            issue_records=remote_payload.get("issue_records", []),
            permissions=remote_payload.get("permissions", {}),
            capabilities=remote_payload.get("capabilities", []),
            relationship_records=remote_payload.get("relationship_records", []),
            evidence_ids=remote_payload.get("evidence_ids", []),
            observed_at=remote_payload.get("observed_at"),
        )
        if snapshot.digest() != remote_snapshot_digest:
            raise ValueError("remote_snapshot_digest_mismatch")
    evidence_records = evidence_records or []
    ids = sorted(str(record.get("evidence_id")) for record in evidence_records)
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate_evidence_id")
    canonical_ids = [str(value) for value in canonical.get("evidence_ids", [])]
    if len(canonical_ids) != len(set(canonical_ids)):
        raise ValueError("duplicate_evidence_id")
    if sorted(canonical_ids) != ids:
        raise ValueError("evidence_reference_mismatch")
    for record in evidence_records:
        if record.get("source_kind") != "declared":
            raise ValueError("controlled_evidence_source")
        parsed = EvidenceRecord.from_dict(record)
        if (parsed.workspace_identity != expected_workspace_identity or
                parsed.preview_id != preview_id or parsed.revision != revision):
            raise ValueError("evidence_scope_mismatch")
    unsigned = {key: value for key, value in canonical.items() if key != "sealed_preview_digest"}
    if canonical.get("sealed_preview_digest") != digest(unsigned):
        raise ValueError("sealed_preview_digest_mismatch")
    return normalized


def _preview_is_approval_eligible(preview: Mapping[str, Any]) -> bool:
    canonical = preview.get("canonical_payload")
    if not isinstance(canonical, Mapping):
        return False
    # OperationIntent is intentionally not an approved operation contract yet.
    # Until that contract exists, no product preview may become WriteEligible.
    return False


def _validate_formal_audit_boundary(audit: AuditRecord, canonical: Mapping[str, Any], expected_workspace_identity: str) -> None:
    """Validate the Runtime-owned formal AuditRecord before Store commit."""
    if not audit.audit_payload_digest or not audit.audit_context_digest or not audit.sealed_preview_digest:
        raise ValueError("audit_commit_boundary_required")
    if audit.workspace_identity != expected_workspace_identity:
        raise ValueError("audit_commit_boundary_required")
    if audit.preview_id != canonical.get("preview_id") or audit.revision != canonical.get("revision"):
        raise ValueError("audit_commit_boundary_required")
    if audit.audit_scope not in {level.value for level in PreviewLevel} or audit.audit_scope != canonical.get("preview_level"):
        raise ValueError("audit_commit_boundary_required")
    if audit.sealed_preview_digest != canonical.get("sealed_preview_digest"):
        raise ValueError("audit_commit_boundary_required")
    if audit.plan_digest != canonical.get("plan_digest") or audit.operation_set_digest != canonical.get("operation_set_digest"):
        raise ValueError("audit_commit_boundary_required")
    if audit.remote_snapshot_digest != canonical.get("remote_snapshot_digest"):
        raise ValueError("audit_commit_boundary_required")
    if not audit.rule_registry_version or not audit.rule_registry_digest:
        raise ValueError("audit_commit_boundary_required")
    if not audit.rule_evaluations or not audit.created_at:
        raise ValueError("audit_commit_boundary_required")
    try:
        created = datetime.fromisoformat(audit.created_at.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError("audit_commit_boundary_required") from exc
    offset = created.utcoffset()
    if created.tzinfo is None or offset is None or offset.total_seconds() != 0:
        raise ValueError("audit_commit_boundary_required")
    if any("finding_ref" in finding or not finding.get("finding_id") for finding in audit.findings):
        raise ValueError("audit_commit_boundary_required")
    canonical_evidence_ids = canonical.get("evidence_ids", [])
    if sorted(audit.evidence_refs) != sorted(canonical_evidence_ids) or len(set(audit.evidence_refs)) != len(audit.evidence_refs):
        raise ValueError("audit_commit_boundary_required")
    if any(any(not str(ref).startswith("finding_") for ref in evaluation.get("finding_refs", ()))
           for evaluation in audit.rule_evaluations):
        raise ValueError("audit_commit_boundary_required")
    if any(not isinstance(evaluation.get("rule_id"), str) or not isinstance(evaluation.get("outcome"), str)
           for evaluation in audit.rule_evaluations):
        raise ValueError("audit_commit_boundary_required")
    outcomes = {evaluation.get("outcome") for evaluation in audit.rule_evaluations}
    expected_result = (AuditResult.BLOCKED if "Blocked" in outcomes else
                       AuditResult.NEEDS_INFORMATION if "Unknown" in outcomes else
                       AuditResult.CHANGES_REQUIRED if "Failed" in outcomes else AuditResult.PASSED)
    if audit.result is not expected_result:
        raise ValueError("audit_commit_boundary_required")
    payload = {
        "workspace_identity": audit.workspace_identity,
        "preview_id": audit.preview_id,
        "revision": audit.revision,
        "audit_scope": audit.audit_scope,
        "sealed_preview_digest": audit.sealed_preview_digest,
        "plan_digest": audit.plan_digest,
        "operation_set_digest": audit.operation_set_digest,
        "remote_snapshot_digest": audit.remote_snapshot_digest,
        "audit_context_digest": audit.audit_context_digest,
        "rule_registry_version": audit.rule_registry_version,
        "rule_registry_digest": audit.rule_registry_digest,
        "semantic_evaluations": list(audit.rule_evaluations),
        "findings": list(audit.findings),
        "result": audit.result.value,
    }
    if digest(payload) != audit.audit_payload_digest or not audit.verify_digest():
        raise ValueError("audit_commit_boundary_required")


def _preview_binding_value(preview: Mapping[str, Any], key: str) -> Any:
    canonical = preview.get("canonical_payload")
    if isinstance(canonical, Mapping):
        return canonical.get(key)
    return preview.get(key)


def build_audit_context_payload(workspace_identity: str, preview_id: str, revision: int,
                                sealed_preview_digest: str,
                                evidence_records: Sequence[Mapping[str, Any]],
                                rule_registry_version: str | None = None,
                                rule_registry_digest: str | None = None,
                                audit_scope: str | None = None) -> dict[str, Any]:
    payload = {
        "workspace_identity": workspace_identity,
        "preview_id": preview_id,
        "revision": revision,
        "sealed_preview_digest": sealed_preview_digest,
        "rule_registry_version": rule_registry_version,
        "rule_registry_digest": rule_registry_digest,
        "evidence": sorted(
            [(str(record["evidence_id"]), str(record["evidence_digest"])) for record in evidence_records],
            key=lambda pair: pair[0],
        ),
    }
    if audit_scope is not None:
        payload["audit_scope"] = audit_scope
    return payload


def compute_audit_context_digest(workspace_identity: str, preview_id: str, revision: int,
                                 sealed_preview_digest: str,
                                 evidence_records: Sequence[Mapping[str, Any]],
                                 rule_registry_version: str | None = None,
                                 rule_registry_digest: str | None = None,
                                 audit_scope: str | None = None) -> str:
    return digest(build_audit_context_payload(
        workspace_identity, preview_id, revision, sealed_preview_digest,
        evidence_records, rule_registry_version, rule_registry_digest, audit_scope,
    ))


def _runtime_preview_level(canonical: Mapping[str, Any]) -> PreviewLevel:
    remote = canonical.get("remote_snapshot")
    if not isinstance(remote, Mapping) or canonical.get("remote_snapshot_digest") is None:
        return PreviewLevel.CONCEPTUAL
    if remote.get("query_complete") is True and remote.get("pagination_complete") is True:
        return PreviewLevel.REPOSITORY_AWARE
    return PreviewLevel.CONCEPTUAL


def validate_sealed_preview_invariants(canonical: Mapping[str, Any], expected_workspace_identity: str) -> None:
    """Validate the Runtime-owned state machine as one atomic invariant set."""
    if not isinstance(canonical, Mapping):
        raise ValueError("sealed_preview_required")
    if canonical.get("provenance_status") != "declared_unverified":
        raise ValueError("preview_provenance_invalid")
    if canonical.get("workspace_identity") != expected_workspace_identity:
        raise ValueError("workspace_identity_mismatch")
    level = canonical.get("preview_level")
    if level not in {level.value for level in PreviewLevel}:
        raise ValueError("preview_level_unverified")
    repository = canonical.get("repository_identity")
    remote = canonical.get("remote_snapshot")
    remote_digest = canonical.get("remote_snapshot_digest")
    if level == PreviewLevel.CONCEPTUAL.value:
        if repository is not None or remote is not None or remote_digest is not None or canonical.get("remote_authority") is not None:
            raise ValueError("conceptual_repository_forbidden")
        return
    if not isinstance(repository, str) or not repository.strip() or not isinstance(remote, Mapping) or not isinstance(remote_digest, str) or not remote_digest:
        raise ValueError("repository_identity_mismatch")
    if remote.get("repository_identity") != repository:
        raise ValueError("repository_identity_mismatch")
    for issue in remote.get("issue_records", []):
        if issue.get("repository_identity") != repository:
            raise ValueError("repository_identity_mismatch")
    # No trusted Typed Driver context exists in the current product Runtime.
    # A caller-controlled authority string can never promote a Preview.
    raise ValueError("preview_level_unverified")


@dataclass(frozen=True)
class _ItemRecord:
    workspace_identity: str
    preview_id: str
    client_ref: str
    item_id: str
    tombstone: bool = False
    revision: int = 1


class InMemoryPreviewStore:
    """Deterministic test store; production state is owned by a SQLite adapter."""

    def __init__(self, workspace_identity: str | None = None) -> None:
        self.workspace_identity = workspace_identity
        self._lock = threading.RLock()
        self._items: list[_ItemRecord] = []
        self._previews: dict[tuple[str, str], dict[str, object]] = {}
        self._preview_history: dict[tuple[str, str, int], dict[str, object]] = {}
        self._evidence: dict[tuple[str, str], EvidenceRecord] = {}
        self._audits: dict[tuple[str, str], AuditRecord] = {}
        self._approvals: dict[tuple[str, str], ApprovalRecord] = {}

    def save_preview_revision(self, request_id: str, preview_id: str, revision: int,
                              plan_digest: str, remote_snapshot_digest: str | None,
                              operation_set_digest: str, repository_identity: str | None,
                              items: list[dict[str, object]], workspace_identity: str | None = None,
                              canonical_payload: dict[str, object] | None = None,
                              preview_level: str | None = None,
                              evidence_records: list[dict[str, object]] | None = None) -> None:
        with self._lock:
            return self._save_preview_revision(
                request_id, preview_id, revision, plan_digest, remote_snapshot_digest,
                operation_set_digest, repository_identity, items, workspace_identity,
                canonical_payload, preview_level, evidence_records,
            )

    def _save_preview_revision(self, request_id: str, preview_id: str, revision: int,
                              plan_digest: str, remote_snapshot_digest: str | None,
                              operation_set_digest: str, repository_identity: str | None,
                              items: list[dict[str, object]], workspace_identity: str | None = None,
                              canonical_payload: dict[str, object] | None = None,
                              preview_level: str | None = None,
                              evidence_records: list[dict[str, object]] | None = None) -> None:
        if workspace_identity is not None and self.workspace_identity is not None and workspace_identity != self.workspace_identity:
            raise ValueError("workspace_identity_mismatch")
        scope = workspace_identity or self.workspace_identity or ""
        if canonical_payload is None:
            raise ValueError("sealed_preview_required")
        if preview_level is not None:
            raise ValueError("preview_level_runtime_owned")
        normalized_canonical = _validate_preview_payload(canonical_payload, request_id, preview_id, revision,
                                  plan_digest, operation_set_digest,
                                  remote_snapshot_digest, repository_identity, evidence_records, scope)
        if normalized_canonical.get("preview_level") != _runtime_preview_level(normalized_canonical).value:
            raise ValueError("preview_level_runtime_owned")
        if normalized_canonical.get("items") != items:
            raise ValueError("canonical_projection_mismatch")
        candidate_items = []
        for item in items:
            if "client_ref" not in item or "item_id" not in item:
                raise KeyError("item_id")
            if not isinstance(item["client_ref"], str) or not isinstance(item["item_id"], str):
                raise ValueError("preview_revision_write_failed")
            candidate_items.append(_ItemRecord(
                scope, preview_id,
                str(item["client_ref"]), str(item["item_id"]), False, revision,
            ))
        if len({item.client_ref for item in candidate_items}) != len(candidate_items):
            raise ValueError("preview_revision_write_failed")
        key = (scope, preview_id)
        prior = self._previews.get(key)
        payload = {"request_id": request_id, "preview_id": preview_id, "revision": revision,
                   "canonical_payload": deepcopy(normalized_canonical)}
        if prior is not None and prior == payload:
            return
        prior_revision = prior.get("revision") if prior is not None else None
        if prior is not None and (not isinstance(prior_revision, int) or isinstance(prior_revision, bool) or prior_revision >= revision):
            raise ValueError("preview_revision_write_failed")
        for audit_key, audit in list(self._audits.items()):
            if audit_key[0] == scope and audit.preview_id == preview_id and audit.status is AuditStatus.ACTIVE and (
                audit.revision != revision or audit.plan_digest != plan_digest
                or audit.remote_snapshot_digest != remote_snapshot_digest
                or audit.operation_set_digest != operation_set_digest
            ):
                self._audits[audit_key] = audit.transition(AuditStatus.STALE, "preview revision replaced")
        new_audits = dict(self._audits)
        for audit_key, audit in list(new_audits.items()):
            if audit_key[0] == scope and audit.preview_id == preview_id and audit.status is AuditStatus.ACTIVE and (
                audit.revision != revision or audit.plan_digest != plan_digest
                or audit.remote_snapshot_digest != remote_snapshot_digest
                or audit.operation_set_digest != operation_set_digest
            ):
                new_audits[audit_key] = audit.transition(AuditStatus.STALE, "preview revision replaced")
        new_items = list(self._items) + candidate_items
        new_evidence = dict(self._evidence)
        for record_data in evidence_records or []:
            record = EvidenceRecord.from_dict(record_data)
            new_evidence[(scope, record.evidence_id)] = record
        self.workspace_identity = self.workspace_identity or workspace_identity
        self._previews[key] = payload
        self._preview_history[(scope, preview_id, revision)] = payload
        self._audits = new_audits
        self._items = new_items
        self._evidence = new_evidence

    def get_preview(self, workspace_identity: str, preview_id: str) -> dict[str, object]:
        try:
            return deepcopy(self._previews[(workspace_identity, preview_id)])
        except KeyError as exc:
            raise ValueError("preview_not_found") from exc

    def get_preview_revision(self, workspace_identity: str, preview_id: str, revision: int | None = None) -> dict[str, object]:
        if workspace_identity != (self.workspace_identity or workspace_identity):
            raise ValueError("preview crosses Workspace boundary")
        if revision is None:
            return self.get_preview(workspace_identity, preview_id)
        try:
            return deepcopy(self._preview_history[(workspace_identity, preview_id, revision)])
        except KeyError as exc:
            raise ValueError("preview_not_found") from exc

    def get_evidence_records(self, workspace_identity: str, evidence_ids: list[str]) -> list[dict[str, object]]:
        if workspace_identity != (self.workspace_identity or workspace_identity):
            raise ValueError("evidence_workspace_mismatch")
        result = []
        for evidence_id in evidence_ids:
            record = self._evidence.get((workspace_identity, evidence_id))
            if record is None:
                raise ValueError("evidence_not_found")
            result.append(deepcopy(record.to_dict()))
        return result

    def resolve_item_id(self, workspace_identity: str, previous_preview_id: str, client_ref: str, revision: int | None = None) -> str:
        if revision is None:
            candidate_revisions = [
                value.get("revision")
                for key, value in self._previews.items()
                if key == (workspace_identity, previous_preview_id)
            ]
            valid_revisions = [value for value in candidate_revisions if isinstance(value, int) and not isinstance(value, bool)]
            revision = max(valid_revisions, default=1)
        matches = [
            item
            for item in self._items
            if item.workspace_identity == workspace_identity and item.preview_id == previous_preview_id and item.client_ref == client_ref and item.revision == revision
        ]
        if len(matches) != 1:
            raise ValueError("previous_client_ref must resolve to one Store item")
        item = matches[0]
        if item.preview_id != previous_preview_id or item.tombstone:
            raise ValueError("previous_client_ref is outside the active Preview lineage")
        return item.item_id

    def record_audit(self, audit: AuditRecord) -> None:
        with self._lock:
            return self._record_audit(audit)

    def _record_audit(self, audit: AuditRecord) -> None:
        if audit.audit_payload_digest:
            raise ValueError("audit_commit_boundary_required")
        if audit.status is not AuditStatus.ACTIVE or not audit.verify_digest():
            raise ValueError("audit_record_invalid")
        if audit.audit_payload_digest:
            if audit.workspace_identity and self.workspace_identity and audit.workspace_identity != self.workspace_identity:
                raise ValueError("workspace_identity_mismatch")
            preview = self.get_preview_revision(self.workspace_identity or audit.workspace_identity, audit.preview_id, audit.revision)
            canonical = preview.get("canonical_payload", {})
            if not isinstance(canonical, Mapping):
                raise ValueError("sealed_preview_unavailable")
            if audit.audit_scope not in {level.value for level in PreviewLevel}:
                raise ValueError("audit_scope_invalid")
            if canonical.get("preview_level") != audit.audit_scope:
                raise ValueError("audit_scope_mismatch")
        scopes = [
            scope
            for (scope, preview_id), value in self._previews.items()
            if preview_id == audit.preview_id
            and isinstance(value.get("revision"), int)
            and not isinstance(value.get("revision"), bool)
            and value.get("revision") == audit.revision
        ]
        self._audits[(scopes[0] if len(scopes) == 1 else "", audit.audit_id)] = audit

    def commit_audit(self, audit: AuditRecord) -> AuditRecord:
        with self._lock:
            preview = self.get_preview_revision(audit.workspace_identity, audit.preview_id, audit.revision)
            latest = self.get_preview(audit.workspace_identity, audit.preview_id)
            latest_revision = latest.get("revision")
            if (not isinstance(latest_revision, int) or isinstance(latest_revision, bool) or
                    latest_revision != audit.revision):
                raise ValueError("audit_context_stale")
            from delivery_system.auditor import validate_current_commit_context
            from delivery_system.rules import build_registry_v1
            canonical_payload = preview.get("canonical_payload")
            if not isinstance(canonical_payload, Mapping):
                raise ValueError("sealed_preview_unavailable")
            evidence = self.get_evidence_records(
                audit.workspace_identity,
                [str(value) for value in canonical_payload.get("evidence_ids", [])],
            )
            validate_current_commit_context(audit, preview, evidence, build_registry_v1(), self.workspace_identity or audit.workspace_identity)
            existing = self.find_audit_by_payload(audit.workspace_identity, audit.preview_id, audit.revision, audit.audit_payload_digest)
            if existing is not None and existing.status is AuditStatus.ACTIVE:
                return existing
            snapshot = (deepcopy(self._audits), deepcopy(self._approvals))
            try:
                for active in self.list_active_audits(audit.workspace_identity, audit.preview_id, audit.revision):
                    self._audits[(audit.workspace_identity, active.audit_id)] = active.transition(AuditStatus.STALE, "new audit payload")
                if any(identifier == audit.audit_id for (_, identifier) in self._audits):
                    raise ValueError("audit_persistence_failed")
                self._audits[(audit.workspace_identity, audit.audit_id)] = audit
                return audit
            except Exception as exc:
                self._audits, self._approvals = snapshot
                raise ValueError("audit_persistence_failed") from exc

    def get_audit(self, workspace_identity: str, audit_id: str) -> AuditRecord:
        try:
            return self._audits[(workspace_identity, audit_id)]
        except KeyError as exc:
            raise ValueError("audit_not_found") from exc

    def find_audit_by_payload(self, workspace_identity: str, preview_id: str, revision: int, audit_payload_digest: str) -> AuditRecord | None:
        for (scope, _), audit in self._audits.items():
            if (scope == workspace_identity and audit.preview_id == preview_id and audit.revision == revision
                    and audit.audit_payload_digest == audit_payload_digest):
                return audit
        return None

    def list_active_audits(self, workspace_identity: str, preview_id: str, revision: int) -> list[AuditRecord]:
        return [audit for (scope, _), audit in self._audits.items()
                if scope == workspace_identity and audit.preview_id == preview_id
                and audit.revision == revision and audit.status is AuditStatus.ACTIVE]

    def transition_audit_status(self, audit_id: str, status: AuditStatus, reason: str) -> AuditRecord:
        with self._lock:
            return self._transition_audit_status(audit_id, status, reason)

    def _transition_audit_status(self, audit_id: str, status: AuditStatus, reason: str) -> AuditRecord:
        matches = [value for (_, identifier), value in self._audits.items() if identifier == audit_id]
        if len(matches) != 1:
            raise ValueError("audit_not_found")
        current = matches[0]
        updated = current.transition(status, reason)
        scope = next(scope for (scope, identifier), value in self._audits.items() if identifier == audit_id and value is current)
        self._audits[(scope, audit_id)] = updated
        return updated

    def record_approval(self, approval: ApprovalRecord) -> None:
        with self._lock:
            return self._record_approval(approval)

    def _record_approval(self, approval: ApprovalRecord) -> None:
        if not approval.is_structurally_valid():
            raise ValueError("approval_invalid")
        if not self.validate_approval_current(approval):
            raise ValueError("approval_binding_mismatch")
        scope = next((scope for (scope, identifier), value in self._audits.items()
                      if identifier == approval.audit_id and value.preview_id == approval.preview_id), "")
        self._approvals[(scope, approval.approval_id)] = approval

    def get_approval(self, workspace_identity: str, approval_id: str) -> ApprovalRecord:
        try:
            return self._approvals[(workspace_identity, approval_id)]
        except KeyError as exc:
            raise ValueError("approval_not_found") from exc

    def validate_approval_current(self, approval: ApprovalRecord) -> bool:
        if not approval.is_structurally_valid():
            return False
        matches = [(scope, audit) for (scope, identifier), audit in self._audits.items()
                   if identifier == approval.audit_id and scope]
        if len(matches) != 1:
            return False
        scope, audit = matches[0]
        preview = self._previews.get((scope, approval.preview_id))
        if preview is None:
            return False
        preview_revision = preview.get("revision")
        if (not isinstance(preview_revision, int) or isinstance(preview_revision, bool) or
                preview_revision != approval.revision):
            return False
        if not _preview_is_approval_eligible(preview):
            return False
        return (
            approval.validate_against(audit)
            and approval.audit_result == AuditResult.PASSED
            and approval.plan_digest == _preview_binding_value(preview, "plan_digest")
            and approval.remote_snapshot_digest == _preview_binding_value(preview, "remote_snapshot_digest")
            and approval.operation_set_digest == _preview_binding_value(preview, "operation_set_digest")
            and approval.repository_identity == _preview_binding_value(preview, "repository_identity")
        )


class SQLitePreviewStore:
    """Transactional local store for Preview, Audit, Approval, and lineage records."""

    SCHEMA_VERSION = 3

    def __init__(
        self,
        context: RuntimeContext,
        ignore_checker: Callable[[Path], bool] | None = None,
        tracked_checker: Callable[[Path], bool] | None = None,
    ):
        context.ensure_store_ready(ignore_checker=ignore_checker, tracked_checker=tracked_checker)
        self.context = context
        self.path = Path(context.state_path)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            meta_row = connection.execute("SELECT schema_version FROM store_meta LIMIT 1").fetchone() if connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='store_meta'").fetchone() else None
            needs_migration = meta_row is not None and meta_row[0] < self.SCHEMA_VERSION
            item_columns = {row[1] for row in connection.execute("PRAGMA table_info(item_lineage)")}
            item_sql = connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='item_lineage'").fetchone()
            if needs_migration and item_columns and "revision" not in item_columns and item_sql and not connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='item_lineage_legacy'").fetchone():
                connection.execute("ALTER TABLE item_lineage RENAME TO item_lineage_legacy")
            record_columns = {row[1] for row in connection.execute("PRAGMA table_info(records)")}
            record_sql = connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='records'").fetchone()
            if needs_migration and record_columns and record_sql and "record_id, revision)" not in record_sql:
                connection.execute("ALTER TABLE records RENAME TO records_legacy")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS store_meta (
                    schema_version INTEGER NOT NULL,
                    workspace_identity TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS item_lineage (
                    workspace_identity TEXT NOT NULL,
                    preview_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    client_ref TEXT NOT NULL,
                    item_id TEXT NOT NULL,
                    tombstone INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (workspace_identity, preview_id, revision, client_ref)
                );
                CREATE TABLE IF NOT EXISTS records (
                    workspace_identity TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    revision INTEGER,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (workspace_identity, record_type, record_id, revision)
                );
                CREATE TABLE IF NOT EXISTS audit_history (
                    workspace_identity TEXT NOT NULL,
                    audit_id TEXT NOT NULL,
                    event_no INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    PRIMARY KEY (workspace_identity, audit_id, event_no)
                );
                """
            )
            row = connection.execute("SELECT schema_version, workspace_identity FROM store_meta").fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO store_meta(schema_version, workspace_identity) VALUES (?, ?)",
                    (self.SCHEMA_VERSION, self.context.workspace_identity),
                )
            elif row[1] != self.context.workspace_identity:
                connection.rollback()
                raise StorePreflightError("store_corrupt")
            elif row[0] != self.SCHEMA_VERSION:
                connection.execute("UPDATE store_meta SET schema_version=?", (self.SCHEMA_VERSION,))
            if connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='records_legacy'").fetchone():
                connection.execute(
                    "INSERT INTO records(workspace_identity, record_type, record_id, revision, payload) SELECT workspace_identity, record_type, record_id, COALESCE(revision, 1), payload FROM records_legacy"
                )
                connection.execute("DROP TABLE records_legacy")
            if connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='item_lineage_legacy'").fetchone():
                connection.execute(
                    "INSERT INTO item_lineage(workspace_identity, preview_id, revision, client_ref, item_id, tombstone) SELECT workspace_identity, preview_id, 1, client_ref, item_id, tombstone FROM item_lineage_legacy"
                )
                connection.execute("DROP TABLE item_lineage_legacy")
            connection.commit()

    def save_preview_revision(self, request_id: str, preview_id: str, revision: int,
                              plan_digest: str, remote_snapshot_digest: str | None,
                              operation_set_digest: str, repository_identity: str | None,
                              items: list[dict[str, object]], workspace_identity: str | None = None,
                              canonical_payload: dict[str, object] | None = None,
                              preview_level: str | None = None,
                              evidence_records: list[dict[str, object]] | None = None) -> None:
        import json
        if workspace_identity is not None and workspace_identity != self.context.workspace_identity:
            raise ValueError("workspace_identity_mismatch")
        if canonical_payload is None:
            raise ValueError("sealed_preview_required")
        if preview_level is not None:
            raise ValueError("preview_level_runtime_owned")
        normalized_canonical = _validate_preview_payload(canonical_payload, request_id, preview_id, revision,
                                  plan_digest, operation_set_digest,
                                  remote_snapshot_digest, repository_identity, evidence_records,
                                  self.context.workspace_identity)
        if normalized_canonical.get("preview_level") != _runtime_preview_level(normalized_canonical).value:
            raise ValueError("preview_level_runtime_owned")
        if normalized_canonical.get("items") != items:
            raise ValueError("canonical_projection_mismatch")
        if len({item.get("client_ref") for item in items}) != len(items):
            raise ValueError("preview_revision_write_failed")
        payload = {
            "request_id": request_id,
            "preview_id": preview_id,
            "revision": revision,
            "canonical_payload": deepcopy(normalized_canonical),
        }
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT payload FROM records WHERE workspace_identity=? AND record_type='preview' AND record_id=? AND revision=?",
                    (self.context.workspace_identity, preview_id, revision),
                ).fetchone()
                encoded = json.dumps(payload, sort_keys=True)
                if existing is not None:
                    if existing[0] == encoded:
                        connection.commit()
                        return
                    raise ValueError("preview_revision_write_failed")
                latest = connection.execute(
                    "SELECT MAX(revision) FROM records WHERE workspace_identity=? AND record_type='preview' AND record_id=?",
                    (self.context.workspace_identity, preview_id),
                ).fetchone()[0]
                if latest is not None and revision <= latest:
                    raise ValueError("preview_revision_write_failed")
                for item in items:
                    connection.execute(
                        "INSERT INTO item_lineage(workspace_identity, preview_id, revision, client_ref, item_id, tombstone) VALUES (?, ?, ?, ?, ?, 0)",
                        (self.context.workspace_identity, preview_id, revision,
                         item["client_ref"], item["item_id"]),
                    )
                connection.execute(
                    "INSERT INTO records(workspace_identity, record_type, record_id, revision, payload) VALUES (?, 'preview', ?, ?, ?)",
                    (self.context.workspace_identity, preview_id, revision, encoded),
                )
                for evidence in evidence_records or []:
                    connection.execute(
                        "INSERT INTO records(workspace_identity, record_type, record_id, revision, payload) VALUES (?, 'evidence', ?, ?, ?)",
                        (self.context.workspace_identity, evidence["evidence_id"], revision,
                         json.dumps(evidence, sort_keys=True)),
                    )
                active_rows = connection.execute(
                    "SELECT audit_id, payload FROM audit_history WHERE workspace_identity=? AND event_no=(SELECT MAX(h2.event_no) FROM audit_history h2 WHERE h2.workspace_identity=audit_history.workspace_identity AND h2.audit_id=audit_history.audit_id) AND json_extract(payload, '$.status')='Active' AND json_extract(payload, '$.preview_id')=?",
                    (self.context.workspace_identity, preview_id),
                ).fetchall()
                for audit_id, audit_payload in active_rows:
                    audit_data = json.loads(audit_payload)
                    if (
                        audit_data["revision"] != revision
                        or audit_data["plan_digest"] != plan_digest
                        or audit_data["remote_snapshot_digest"] != remote_snapshot_digest
                        or audit_data["operation_set_digest"] != operation_set_digest
                    ):
                        current = AuditRecord(
                            audit_data["audit_id"], audit_data["preview_id"], audit_data["revision"],
                            audit_data["plan_digest"], audit_data["remote_snapshot_digest"],
                            audit_data["audit_digest"], AuditResult(audit_data["result"]),
                            audit_data["operation_set_digest"], AuditStatus(audit_data["status"]),
                        )
                        stale = current.transition(AuditStatus.STALE, "preview revision replaced")
                        event_no = connection.execute(
                            "SELECT MAX(event_no)+1 FROM audit_history WHERE workspace_identity=? AND audit_id=?",
                            (self.context.workspace_identity, audit_id),
                        ).fetchone()[0]
                        connection.execute(
                            "INSERT INTO audit_history VALUES (?, ?, ?, ?, ?, ?)",
                            (self.context.workspace_identity, audit_id, event_no,
                             json.dumps(stale.to_dict(), sort_keys=True), "preview revision replaced", datetime.now().astimezone().isoformat()),
                        )
                connection.commit()
            except Exception as exc:
                connection.rollback()
                if isinstance(exc, ValueError):
                    raise
                raise ValueError("preview_revision_write_failed") from exc

    def get_preview(self, workspace_identity: str, preview_id: str) -> dict[str, object]:
        return self.get_preview_revision(workspace_identity, preview_id, None)

    def get_preview_revision(self, workspace_identity: str, preview_id: str, revision: int | None = None) -> dict[str, object]:
        import json

        if workspace_identity != self.context.workspace_identity:
            raise ValueError("preview crosses Workspace boundary")
        with closing(self._connect()) as connection:
            if revision is None:
                row = connection.execute(
                    "SELECT revision, payload FROM records WHERE workspace_identity=? AND record_type='preview' AND record_id=? ORDER BY revision DESC LIMIT 1",
                    (workspace_identity, preview_id),
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT revision, payload FROM records WHERE workspace_identity=? AND record_type='preview' AND record_id=? AND revision=?",
                    (workspace_identity, preview_id, revision),
                ).fetchone()
        if row is None:
            raise ValueError("preview_not_found")
        result = json.loads(row[1])
        result["revision"] = row[0]
        return result

    def get_evidence_records(self, workspace_identity: str, evidence_ids: list[str]) -> list[dict[str, object]]:
        if workspace_identity != self.context.workspace_identity:
            raise ValueError("evidence_workspace_mismatch")
        import json
        result = []
        with closing(self._connect()) as connection:
            for evidence_id in evidence_ids:
                row = connection.execute(
                    "SELECT payload FROM records WHERE workspace_identity=? AND record_type='evidence' AND record_id=? ORDER BY revision DESC LIMIT 1",
                    (workspace_identity, evidence_id),
                ).fetchone()
                if row is None:
                    raise ValueError("evidence_not_found")
                result.append(json.loads(row[0]))
        return result

    def resolve_item_id(self, workspace_identity: str, previous_preview_id: str, client_ref: str, revision: int | None = None) -> str:
        if workspace_identity != self.context.workspace_identity:
            raise ValueError("previous_client_ref crosses Workspace boundary")
        with closing(self._connect()) as connection:
            if revision is None:
                revision = connection.execute(
                    "SELECT MAX(revision) FROM records WHERE workspace_identity=? AND record_type='preview' AND record_id=?",
                    (workspace_identity, previous_preview_id),
                ).fetchone()[0]
            rows = connection.execute(
                "SELECT item_id, tombstone FROM item_lineage WHERE workspace_identity=? AND preview_id=? AND revision=? AND client_ref=?",
                (workspace_identity, previous_preview_id, revision, client_ref),
            ).fetchall()
        if len(rows) != 1 or rows[0][1]:
            raise ValueError("lineage_not_found")
        return rows[0][0]

    def record_audit(self, audit: AuditRecord) -> None:
        import json
        if audit.audit_payload_digest:
            raise ValueError("audit_commit_boundary_required")
        if audit.status is not AuditStatus.ACTIVE or not audit.verify_digest():
            raise ValueError("audit_record_invalid")
        if audit.audit_payload_digest:
            if audit.workspace_identity and audit.workspace_identity != self.context.workspace_identity:
                raise ValueError("workspace_identity_mismatch")
            preview = self.get_preview_revision(self.context.workspace_identity, audit.preview_id, audit.revision)
            canonical = preview.get("canonical_payload", {})
            if not isinstance(canonical, Mapping):
                raise ValueError("sealed_preview_unavailable")
            if audit.audit_scope not in {level.value for level in PreviewLevel}:
                raise ValueError("audit_scope_invalid")
            if canonical.get("preview_level") != audit.audit_scope:
                raise ValueError("audit_scope_mismatch")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO audit_history VALUES (?, ?, ?, ?, ?, ?)",
                (self.context.workspace_identity, audit.audit_id, 1,
                 json.dumps(audit.to_dict(), sort_keys=True), "created", datetime.now().astimezone().isoformat()),
            )
            connection.commit()

    def commit_audit(self, audit: AuditRecord) -> AuditRecord:
        import json
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                latest_row = connection.execute(
                    "SELECT MAX(revision) FROM records WHERE workspace_identity=? AND record_type='preview' AND record_id=?",
                    (self.context.workspace_identity, audit.preview_id),
                ).fetchone()
                if latest_row is None or latest_row[0] is None:
                    raise ValueError("preview_not_found")
                if int(latest_row[0]) != audit.revision:
                    raise ValueError("audit_context_stale")
                preview_row = connection.execute(
                    "SELECT payload FROM records WHERE workspace_identity=? AND record_type='preview' AND record_id=? AND revision=?",
                    (self.context.workspace_identity, audit.preview_id, audit.revision),
                ).fetchone()
                if preview_row is None:
                    raise ValueError("preview_not_found")
                preview_payload = json.loads(preview_row[0])
                canonical = preview_payload.get("canonical_payload")
                if not isinstance(canonical, dict):
                    raise ValueError("sealed_preview_unavailable")
                evidence = []
                for evidence_id in canonical.get("evidence_ids", []):
                    evidence_row = connection.execute(
                        "SELECT payload FROM records WHERE workspace_identity=? AND record_type='evidence' AND record_id=? AND revision=?",
                        (self.context.workspace_identity, evidence_id, audit.revision),
                    ).fetchone()
                    if evidence_row is None:
                        raise ValueError("evidence_not_found")
                    evidence.append(json.loads(evidence_row[0]))
                from delivery_system.auditor import validate_current_commit_context
                from delivery_system.rules import build_registry_v1
                validate_current_commit_context(audit, preview_payload, evidence, build_registry_v1(), self.context.workspace_identity)
                current_rows = connection.execute(
                    "SELECT audit_id, payload FROM audit_history WHERE workspace_identity=? ORDER BY audit_id, event_no",
                    (audit.workspace_identity,),
                ).fetchall()
                latest_audits: dict[str, AuditRecord] = {}
                for audit_id, payload in current_rows:
                    latest_audits[audit_id] = AuditRecord.from_dict(json.loads(payload))
                existing = next((value for value in latest_audits.values()
                                 if value.preview_id == audit.preview_id and value.revision == audit.revision
                                 and value.audit_payload_digest == audit.audit_payload_digest
                                 and value.status is AuditStatus.ACTIVE), None)
                if existing is not None:
                    connection.commit()
                    return existing
                for active in latest_audits.values():
                    if active.preview_id == audit.preview_id and active.revision == audit.revision and active.status is AuditStatus.ACTIVE:
                        stale = active.transition(AuditStatus.STALE, "new audit payload")
                        event_no = connection.execute(
                            "SELECT COALESCE(MAX(event_no), 0)+1 FROM audit_history WHERE workspace_identity=? AND audit_id=?",
                            (audit.workspace_identity, active.audit_id),
                        ).fetchone()[0]
                        connection.execute(
                            "INSERT INTO audit_history VALUES (?, ?, ?, ?, ?, ?)",
                            (audit.workspace_identity, active.audit_id, event_no, json.dumps(stale.to_dict(), sort_keys=True), "new audit payload", datetime.now(timezone.utc).isoformat()),
                        )
                if any(identifier == audit.audit_id for identifier in latest_audits):
                    raise ValueError("audit_persistence_failed")
                connection.execute(
                    "INSERT INTO audit_history VALUES (?, ?, ?, ?, ?, ?)",
                    (audit.workspace_identity, audit.audit_id, 1, json.dumps(audit.to_dict(), sort_keys=True), "created", datetime.now(timezone.utc).isoformat()),
                )
                connection.commit()
                return audit
            except ValueError:
                connection.rollback()
                raise
            except Exception as exc:
                connection.rollback()
                raise ValueError("audit_persistence_failed") from exc

    def get_audit(self, workspace_identity: str, audit_id: str) -> AuditRecord:
        import json
        if workspace_identity != self.context.workspace_identity:
            raise ValueError("audit_workspace_mismatch")
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT payload FROM audit_history WHERE workspace_identity=? AND audit_id=? ORDER BY event_no DESC LIMIT 1",
                (workspace_identity, audit_id),
            ).fetchone()
        if row is None:
            raise ValueError("audit_not_found")
        data = json.loads(row[0])
        return AuditRecord.from_dict(data)

    def _current_audits(self, workspace_identity: str) -> list[AuditRecord]:
        import json
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT audit_id, payload FROM audit_history WHERE workspace_identity=? ORDER BY audit_id, event_no",
                (workspace_identity,),
            ).fetchall()
        latest: dict[str, AuditRecord] = {}
        for audit_id, payload in rows:
            latest[audit_id] = AuditRecord.from_dict(json.loads(payload))
        return list(latest.values())

    def find_audit_by_payload(self, workspace_identity: str, preview_id: str, revision: int, audit_payload_digest: str) -> AuditRecord | None:
        return next((audit for audit in self._current_audits(workspace_identity)
                     if audit.preview_id == preview_id and audit.revision == revision
                     and audit.audit_payload_digest == audit_payload_digest), None)

    def list_active_audits(self, workspace_identity: str, preview_id: str, revision: int) -> list[AuditRecord]:
        return [audit for audit in self._current_audits(workspace_identity)
                if audit.preview_id == preview_id and audit.revision == revision
                and audit.status is AuditStatus.ACTIVE]

    def transition_audit_status(self, audit_id: str, status: AuditStatus, reason: str) -> AuditRecord:
        current = self.get_audit(self.context.workspace_identity, audit_id)
        updated = current.transition(status, reason)
        import json
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            event_no = connection.execute(
                "SELECT COALESCE(MAX(event_no), 0)+1 FROM audit_history WHERE workspace_identity=? AND audit_id=?",
                (self.context.workspace_identity, audit_id),
            ).fetchone()[0]
            connection.execute(
                "INSERT INTO audit_history VALUES (?, ?, ?, ?, ?, ?)",
                (self.context.workspace_identity, audit_id, event_no,
                 json.dumps(updated.to_dict(), sort_keys=True), reason, datetime.now().astimezone().isoformat()),
            )
            connection.commit()
        return updated

    def record_approval(self, approval: ApprovalRecord) -> None:
        import json
        if not approval.is_structurally_valid():
            raise ValueError("approval_invalid")
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                audit_row = connection.execute(
                    "SELECT payload FROM audit_history WHERE workspace_identity=? AND audit_id=? ORDER BY event_no DESC LIMIT 1",
                    (self.context.workspace_identity, approval.audit_id),
                ).fetchone()
                if audit_row is None:
                    raise ValueError("audit_not_found")
                audit_data = json.loads(audit_row[0])
                audit = AuditRecord(
                    audit_data["audit_id"], audit_data["preview_id"], audit_data["revision"],
                    audit_data["plan_digest"], audit_data["remote_snapshot_digest"], audit_data["audit_digest"],
                    AuditResult(audit_data["result"]), audit_data["operation_set_digest"], AuditStatus(audit_data["status"]),
                )
                if not audit.verify_digest() or audit.status is not AuditStatus.ACTIVE:
                    raise ValueError("approval_stale")
                preview_row = connection.execute(
                    "SELECT revision, payload FROM records WHERE workspace_identity=? AND record_type='preview' AND record_id=? AND revision=?",
                    (self.context.workspace_identity, approval.preview_id, approval.revision),
                ).fetchone()
                if preview_row is None:
                    raise ValueError("preview_not_found")
                preview = json.loads(preview_row[1])
                if not (
                    approval.validate_against(audit)
                    and approval.preview_id == audit.preview_id
                    and approval.revision == audit.revision
                    and approval.plan_digest == _preview_binding_value(preview, "plan_digest")
                    and approval.remote_snapshot_digest == _preview_binding_value(preview, "remote_snapshot_digest")
                    and approval.operation_set_digest == _preview_binding_value(preview, "operation_set_digest")
                    and approval.repository_identity == _preview_binding_value(preview, "repository_identity")
                    and _preview_is_approval_eligible(preview)
                ):
                    raise ValueError("approval_binding_mismatch")
                latest = connection.execute(
                    "SELECT MAX(revision) FROM records WHERE workspace_identity=? AND record_type='preview' AND record_id=?",
                    (self.context.workspace_identity, approval.preview_id),
                ).fetchone()[0]
                if latest != approval.revision:
                    raise ValueError("approval_stale")
                connection.execute(
                    "INSERT INTO records(workspace_identity, record_type, record_id, revision, payload) VALUES (?, 'approval', ?, ?, ?)",
                    (self.context.workspace_identity, approval.approval_id, approval.revision,
                     json.dumps(approval.to_dict(), sort_keys=True)),
                )
                connection.commit()
            except Exception as exc:
                connection.rollback()
                raise exc

    def get_approval(self, workspace_identity: str, approval_id: str) -> ApprovalRecord:
        import json
        if workspace_identity != self.context.workspace_identity:
            raise ValueError("approval_workspace_mismatch")
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT payload FROM records WHERE workspace_identity=? AND record_type='approval' AND record_id=?",
                (workspace_identity, approval_id),
            ).fetchone()
        if row is None:
            raise ValueError("approval_not_found")
        data = json.loads(row[0])
        return ApprovalRecord(
            data["approval_id"], data["audit_id"], data["audit_digest"],
            AuditResult(data["audit_result"]), data["preview_id"], data["revision"],
            data["plan_digest"], data["remote_snapshot_digest"], data["operation_set_digest"],
            data["repository_identity"], data["approval_command"], data["approver_claim"],
            data["approved_at"], data["status"],
        )

    def validate_approval_current(self, approval: ApprovalRecord) -> bool:
        if not approval.is_structurally_valid():
            return False
        try:
            audit = self.get_audit(self.context.workspace_identity, approval.audit_id)
            preview = self.get_preview(self.context.workspace_identity, approval.preview_id)
            preview_revision = preview.get("revision")
            if (not isinstance(preview_revision, int) or isinstance(preview_revision, bool) or
                    preview_revision != approval.revision):
                return False
            return (
                approval.validate_against(audit)
                and approval.audit_result == AuditResult.PASSED
                and approval.plan_digest == _preview_binding_value(preview, "plan_digest")
                and approval.remote_snapshot_digest == _preview_binding_value(preview, "remote_snapshot_digest")
                and approval.operation_set_digest == _preview_binding_value(preview, "operation_set_digest")
                and approval.repository_identity == _preview_binding_value(preview, "repository_identity")
                and _preview_is_approval_eligible(preview)
            )
        except ValueError:
            return False


class RuntimePlanner:
    """Shared Runtime planning boundary consumed by the MCP adapter."""

    def __init__(self, context: RuntimeContext, store: Any, driver: Any = None):
        self.context = context
        self.store = store
        if driver is not None:
            raise TypeError("no production Driver is implemented")
        self.driver = None

    @staticmethod
    def _id(prefix: str) -> str:
        import uuid
        return f"{prefix}-{uuid.uuid4().hex}"

    @staticmethod
    def _sourced(value: Mapping[str, Any]) -> dict[str, Any]:
        return SourcedValue(value["value"], DeclaredSource(value["declared_source"])).to_dict()

    def preview(self, plan: Mapping[str, Any], previous_preview_id: str | None = None) -> dict[str, Any]:
        work_items = list(plan.get("work_items", ()))
        refs = [item["client_ref"] for item in work_items]
        if len(refs) != len(set(refs)):
            raise ValueError("client_ref must be unique within a Draft")
        semantic = {
            "repository_claim": plan.get("repository_claim"),
            "existing_issue_claims": list(plan.get("existing_issue_claims", ())),
            "work_items": [
                {
                    "client_ref": item["client_ref"],
                    "previous_client_ref": item.get("previous_client_ref"),
                    **{field: self._sourced(item[field]) for field in (
                        "role", "title", "context_problem", "outcome", "scope", "non_goals",
                        "acceptance_criteria", "verification", "required_capabilities", "write_metadata",
                    )},
                }
                for item in work_items
            ],
            "planned_relationships": list(plan.get("planned_relationships", ())),
        }
        operation_candidates = list(plan.get("operation_intents", ()))
        operation_intents: list[dict[str, Any]] = []
        for operation in operation_candidates:
            if not isinstance(operation, Mapping):
                raise ValueError("invalid_input")
            operation_intents.append(dict(operation))
        plan_digest = digest(semantic)
        operation_semantics = {
            "operation_intents": [
                {key: value for key, value in operation.items() if key not in {"operation_id", "id"}}
                for operation in operation_intents
            ]
        }
        operation_set_digest = digest(operation_semantics)
        request_id = self._id("request")
        preview_id = self._id("preview")
        revision = 1
        if previous_preview_id is not None:
            prior = self.store.get_preview(self.context.workspace_identity, previous_preview_id)
            request_id = str(prior["request_id"])
            preview_id = previous_preview_id
            prior_revision = prior.get("revision")
            if not isinstance(prior_revision, int) or isinstance(prior_revision, bool):
                raise ValueError("preview_not_found")
            revision = prior_revision if (
                _preview_binding_value(prior, "plan_digest") == plan_digest
                and _preview_binding_value(prior, "operation_set_digest") == operation_set_digest
            ) else prior_revision + 1
        prior_items = {
            item["client_ref"]: item for item in (
                prior.get("canonical_payload", {}).get("items", ())
                if previous_preview_id is not None else ()
            )
        }
        sealed_items = []
        for item in work_items:
            previous_ref = item.get("previous_client_ref")
            if previous_preview_id is not None and revision == prior_revision and item["client_ref"] in prior_items:
                item_id = prior_items[item["client_ref"]]["item_id"]
            elif previous_ref is not None:
                item_id = self.store.resolve_item_id(
                    self.context.workspace_identity, previous_preview_id or "", previous_ref,
                    prior_revision if previous_preview_id is not None else None,
                )
            else:
                item_id = self._id("item")
            sealed_items.append({"client_ref": item["client_ref"], "previous_client_ref": previous_ref, "item_id": item_id})
        blockers = ["driver_unavailable"] if plan.get("repository_claim") is not None else []
        preview_level = PreviewLevel.CONCEPTUAL
        canonical = {
            "workspace_identity": self.context.workspace_identity,
            "request_id": request_id,
            "preview_id": preview_id,
            "revision": revision,
            "preview_level": preview_level.value,
            "provenance_status": "declared_unverified",
            "semantic_payload": semantic,
            "operation_intents": operation_intents,
            "plan_digest": plan_digest,
            "operation_set_digest": operation_set_digest,
            "repository_identity": None,
            "remote_authority": None,
            "remote_snapshot": None,
            "remote_snapshot_digest": None,
            "blockers": blockers,
            "planner_observations": [],
            "items": sealed_items,
        }
        canonical["sealed_preview_digest"] = digest({
            key: value for key, value in canonical.items()
            if key not in {"sealed_preview_digest"}
        })
        evidence = []
        for sealed_item in semantic["work_items"]:
            for field in ("role", "title", "context_problem", "outcome", "scope", "non_goals",
                          "acceptance_criteria", "verification", "required_capabilities", "write_metadata"):
                sourced_field = sealed_item[field]
                evidence.append(EvidenceRecord._create_controlled(
                    self.context.workspace_identity, preview_id, revision,
                    "declared_field", "declared",
                    DeclaredSource(sourced_field["declared_source"]),
                    f"{sealed_item['client_ref']}.{field}", sourced_field,
                    None, "runtime-planner", None, None, "evidence-v1",
                ))
        canonical["evidence_ids"] = [record.evidence_id for record in evidence]
        canonical["sealed_preview_digest"] = digest({
            key: value for key, value in canonical.items()
            if key != "sealed_preview_digest"
        })
        sealed_preview = SealedPreview.from_dict(canonical)
        canonical = sealed_preview.to_dict()
        self.store.save_preview_revision(
            request_id, preview_id, revision, plan_digest, None, operation_set_digest, None,
            sealed_items, workspace_identity=self.context.workspace_identity,
            canonical_payload=canonical,
            evidence_records=[record.to_dict() for record in evidence],
        )
        canonical["audit_context_digest"] = compute_audit_context_digest(
            self.context.workspace_identity, preview_id, revision,
            canonical["sealed_preview_digest"], [record.to_dict() for record in evidence],
        )
        result = dict(canonical)
        result.update({
            "remote_snapshot": None,
            "findings": [],
            "stale": False,
            "write_eligible": False,
            "audit_context_digest": canonical["audit_context_digest"],
        })
        return result


class AuditContextService:
    """Runtime-owned validation and construction of the Auditor input context."""

    def __init__(self, context: RuntimeContext, store: PreviewStore):
        self.context = context
        self.store = store

    def get(self, preview_id: str, revision: int) -> dict[str, Any]:
        latest = self.store.get_preview(self.context.workspace_identity, preview_id)
        latest_revision = latest.get("revision")
        if not isinstance(latest_revision, int) or isinstance(latest_revision, bool) or latest_revision != revision:
            raise ValueError("context_stale")
        preview = self.store.get_preview_revision(self.context.workspace_identity, preview_id, revision)
        canonical = preview.get("canonical_payload")
        if not isinstance(canonical, Mapping):
            raise ValueError("sealed_preview_unavailable")
        evidence_ids = [str(value) for value in canonical.get("evidence_ids", [])]
        evidence = self.store.get_evidence_records(self.context.workspace_identity, evidence_ids)
        try:
            _validate_preview_payload(
                canonical, str(preview["request_id"]), preview_id, revision,
                str(_preview_binding_value(preview, "plan_digest")), str(_preview_binding_value(preview, "operation_set_digest")),
                _preview_binding_value(preview, "remote_snapshot_digest"), _preview_binding_value(preview, "repository_identity"), evidence,
                self.context.workspace_identity,
            )
        except ValueError as exc:
            if str(exc) in {"plan_digest_mismatch", "operation_set_digest_mismatch", "remote_snapshot_digest_mismatch", "sealed_preview_digest_mismatch", "preview_identity_mismatch"}:
                raise ValueError("preview_digest_mismatch") from exc
            raise
        context_digest = compute_audit_context_digest(
            self.context.workspace_identity, preview_id, revision,
            canonical["sealed_preview_digest"], evidence,
        )
        return {
            "context_status": "preview_ready_rules_unavailable",
            "workspace_identity": self.context.workspace_identity,
            "preview_id": preview_id,
            "revision": revision,
            "sealed_preview": deepcopy(dict(canonical)),
            "evidence_records": sorted(deepcopy(evidence), key=lambda record: str(record["evidence_id"])),
            "audit_context_digest": context_digest,
            "rule_registry_version": None,
            "rule_registry_digest": None,
        }
