"""Evidence and provenance contracts owned below Runtime orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
from typing import Any, Generic, Mapping, TypeVar

from delivery_system.canonical import canonical_payload, digest, normalize


class DeclaredSource(str, Enum):
    USER_ASSERTED = "user_asserted"
    MODEL_PROPOSED = "model_proposed"
    MODEL_ASSUMPTION = "model_assumption"


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
    def create_verified_driver(cls, workspace_identity: str, preview_id: str, revision: int,
                               evidence_type: str, subject_ref: str, payload: Any,
                               source_identity: str, repository_identity: str,
                               query_scope: Mapping[str, object],
                               created_at: str | None = None,
                               schema_version: str = "evidence-v1") -> "EvidenceRecord":
        """Create Runtime-owned verified Driver evidence.

        Driver adapters provide only facts. Runtime owns the binding and the
        Evidence ID; the public ``create`` factory remains declared-only.
        """
        if (not isinstance(workspace_identity, str) or not workspace_identity.strip()
                or not isinstance(preview_id, str) or not preview_id.strip()
                or not isinstance(revision, int) or isinstance(revision, bool) or revision < 1
                or not isinstance(source_identity, str) or not source_identity.strip()
                or not isinstance(repository_identity, str) or not repository_identity.strip()
                or not isinstance(query_scope, Mapping)):
            raise ValueError("driver_evidence_binding_invalid")
        return cls._create_controlled(
            workspace_identity, preview_id, revision, evidence_type, "driver",
            None, subject_ref, payload, created_at, source_identity,
            repository_identity, query_scope, schema_version, verified=True,
        )

    @classmethod
    def _create_controlled(cls, workspace_identity: str, preview_id: str, revision: int,
                           evidence_type: str, source_kind: str,
                           declared_source: DeclaredSource | None, subject_ref: str,
                           payload: Any, created_at: str | None,
                           source_identity: str, repository_identity: str | None,
                           query_scope: Mapping[str, object] | None,
                           schema_version: str, *, verified: bool = False) -> "EvidenceRecord":
        if source_kind not in {"declared", "runtime", "driver"}:
            raise ValueError("invalid_evidence_source_kind")
        if not verified and source_kind != "declared":
            raise ValueError("controlled_evidence_source")
        if verified:
            if source_kind not in {"runtime", "driver"} or declared_source is not None:
                raise ValueError("verified_evidence_source_invalid")
            verification_status = f"{source_kind}_verified"
        elif source_kind == "declared":
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
