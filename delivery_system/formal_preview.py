"""Formal preview contracts shared by planning, auditing, and Runtime."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from delivery_system.canonical import normalize


class PreviewLevel(str, Enum):
    CONCEPTUAL = "Conceptual"
    REPOSITORY_AWARE = "RepositoryAware"
    WRITE_ELIGIBLE = "WriteEligible"


@dataclass(frozen=True)
class SealedPreview:
    """The canonical Sealed Preview model."""
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
