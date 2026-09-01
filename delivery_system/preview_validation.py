"""Pure sealed-preview validation below Runtime orchestration."""

from __future__ import annotations

from typing import Any, Mapping

from delivery_system.canonical import digest
from delivery_system.evidence import EvidenceRecord
from delivery_system.formal_preview import PreviewLevel, SealedPreview
from delivery_system.remote_snapshot import TypedRemoteSnapshot
from delivery_system.runtime_authority import RuntimePromotion
from delivery_system.write_operations import evaluate_write_operations, operation_set_digest_payload


def _validate_preview_payload(canonical: Mapping[str, Any], request_id: str,
                              preview_id: str, revision: int,
                              plan_digest: str, operation_set_digest: str,
                              remote_snapshot_digest: str | None,
                               repository_identity: str | None,
                               evidence_records: list[dict[str, object]] | None,
                               expected_workspace_identity: str,
                               promotion: RuntimePromotion | None = None) -> dict[str, Any]:
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
    validate_sealed_preview_invariants(canonical, expected_workspace_identity, promotion=promotion)
    semantic = canonical.get("semantic_payload")
    operations = canonical.get("operation_intents")
    if not isinstance(semantic, Mapping) or not isinstance(operations, list):
        raise ValueError("sealed_preview_incomplete")
    if digest(semantic) != plan_digest or canonical.get("plan_digest") != plan_digest:
        raise ValueError("plan_digest_mismatch")
    operation_semantics = operation_set_digest_payload(operations)
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
        if record.get("source_kind") not in {"declared", "driver"}:
            raise ValueError("controlled_evidence_source")
        parsed = EvidenceRecord.from_dict(record)
        if (parsed.workspace_identity != expected_workspace_identity or
                parsed.preview_id != preview_id or parsed.revision != revision):
            raise ValueError("evidence_scope_mismatch")
        if record.get("source_kind") == "driver":
            if promotion is None or parsed.evidence_id != promotion.evidence_record.evidence_id:
                raise ValueError("repository_aware_promotion_required")
            if parsed.source_identity != promotion.trust_context.trusted_driver_identity:
                raise ValueError("driver_trust_context_mismatch")
            if parsed.payload is None or digest(parsed.payload) != promotion.remote_content_digest:
                raise ValueError("remote_content_digest_mismatch")
    unsigned = {key: value for key, value in canonical.items() if key != "sealed_preview_digest"}
    if canonical.get("sealed_preview_digest") != digest(unsigned):
        raise ValueError("sealed_preview_digest_mismatch")
    return normalized


def _runtime_preview_level(canonical: Mapping[str, Any]) -> PreviewLevel:
    remote = canonical.get("remote_snapshot")
    if not isinstance(remote, Mapping) or canonical.get("remote_snapshot_digest") is None:
        return PreviewLevel.CONCEPTUAL
    if remote.get("query_complete") is True and remote.get("pagination_complete") is True:
        try:
            evaluation = evaluate_write_operations(
                canonical.get("operation_intents", []),
                canonical.get("items", []),
                canonical.get("semantic_payload", {}),
            )
        except (TypeError, ValueError):
            return PreviewLevel.REPOSITORY_AWARE
        if evaluation.eligible and not canonical.get("blockers"):
            return PreviewLevel.WRITE_ELIGIBLE
        return PreviewLevel.REPOSITORY_AWARE
    return PreviewLevel.CONCEPTUAL


def validate_sealed_preview_invariants(canonical: Mapping[str, Any], expected_workspace_identity: str,
                                       *, promotion: RuntimePromotion | None = None) -> None:
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
    if promotion is None:
        raise ValueError("preview_level_unverified")
    if canonical.get("remote_authority") != promotion.trust_context.remote_authority:
        raise ValueError("driver_trust_context_mismatch")
    if canonical.get("remote_snapshot_digest") != promotion.remote_snapshot_digest:
        raise ValueError("remote_snapshot_digest_mismatch")
