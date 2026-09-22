"""Pure sealed-preview validation below Runtime orchestration."""

from __future__ import annotations

from typing import Any, Mapping

from delivery_system.canonical import digest
from delivery_system.evidence import EvidenceRecord
from delivery_system.formal_preview import PreviewLevel, SealedPreview
from delivery_system.remote_snapshot import TypedRemoteSnapshot, TypedRemoteSnapshotV2
from delivery_system.runtime_authority import RuntimePromotion
from delivery_system.write_operations import evaluate_write_operations, evaluate_write_operations_v2, operation_set_digest_payload, operation_set_digest_payload_v2
from delivery_system.existing_endpoints import semantic_digest, identity_digest, write_address_digest


def _validate_v2_endpoint_authority(canonical: Mapping[str, Any]) -> None:
    """Validate the persisted declaration-to-binding authority relationship.

    Declarations in the semantic payload are the only source of executable
    endpoint authority.  Bindings are Runtime-sealed resolutions of those
    declarations and therefore must be unique, declared, and (once the
    Preview is repository-aware) complete.
    """
    if canonical.get("canonical_version") != "2":
        return
    semantic = canonical.get("semantic_payload")
    if not isinstance(semantic, Mapping):
        raise ValueError("sealed_preview_endpoint_declarations_invalid")
    declarations = semantic.get("existing_issue_endpoints")
    if not isinstance(declarations, list):
        raise ValueError("sealed_preview_endpoint_declarations_invalid")
    declared_refs: list[str] = []
    for declaration in declarations:
        if not isinstance(declaration, Mapping):
            raise ValueError("sealed_preview_endpoint_declaration_invalid")
        endpoint_ref = declaration.get("endpoint_ref")
        if not isinstance(endpoint_ref, str) or not endpoint_ref.strip():
            raise ValueError("sealed_preview_endpoint_declaration_invalid")
        declared_refs.append(endpoint_ref)
    if len(declared_refs) != len(set(declared_refs)):
        raise ValueError("sealed_preview_endpoint_declaration_duplicate")

    bindings = canonical.get("existing_endpoint_bindings")
    if not isinstance(bindings, list):
        raise ValueError("sealed_preview_endpoint_bindings_invalid")
    binding_refs: list[str] = []
    for binding in bindings:
        if not isinstance(binding, Mapping):
            raise ValueError("sealed_preview_endpoint_binding_invalid")
        endpoint_ref = binding.get("endpoint_ref")
        if not isinstance(endpoint_ref, str) or not endpoint_ref.strip():
            raise ValueError("sealed_preview_endpoint_binding_invalid")
        binding_refs.append(endpoint_ref)
    if len(binding_refs) != len(set(binding_refs)):
        raise ValueError("sealed_preview_endpoint_binding_duplicate")
    if any(endpoint_ref not in set(declared_refs) for endpoint_ref in binding_refs):
        raise ValueError("sealed_preview_endpoint_binding_undeclared")

    level = canonical.get("preview_level")
    if level in {PreviewLevel.REPOSITORY_AWARE.value, PreviewLevel.WRITE_ELIGIBLE.value}:
        if set(declared_refs) != set(binding_refs):
            raise ValueError("sealed_preview_endpoint_binding_coverage_invalid")


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
    _validate_v2_endpoint_authority(canonical)
    semantic = canonical.get("semantic_payload")
    operations = canonical.get("operation_intents")
    if not isinstance(semantic, Mapping) or not isinstance(operations, list):
        raise ValueError("sealed_preview_incomplete")
    is_v2 = canonical.get("canonical_version") == "2"
    expected_plan_digest = digest({"canonical_version": "2", "semantic_payload": semantic}) if is_v2 else digest(semantic)
    if expected_plan_digest != plan_digest or canonical.get("plan_digest") != plan_digest:
        raise ValueError("plan_digest_mismatch")
    operation_semantics = operation_set_digest_payload_v2(operations) if is_v2 else operation_set_digest_payload(operations)
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
        snapshot_type = TypedRemoteSnapshotV2 if remote_payload.get("schema_version") == "remote-snapshot-v2" else TypedRemoteSnapshot
        snapshot = snapshot_type.from_records(
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
        if is_v2:
            bindings = canonical.get("existing_endpoint_bindings")
            if not isinstance(bindings, list):
                raise ValueError("sealed_preview_endpoint_bindings_invalid")
            records = {record.get("issue_id"): record for record in remote_payload.get("issue_records", []) if isinstance(record, Mapping)}
            for binding in bindings:
                if not isinstance(binding, Mapping) or set(binding) != {"endpoint_ref", "selector_digest", "issue_id", "remote_record_digest", "identity_digest", "write_address_digest", "semantic_digest"}:
                    raise ValueError("sealed_preview_endpoint_binding_invalid")
                record = records.get(binding.get("issue_id"))
                if not isinstance(record, Mapping) or digest(dict(record)) != binding.get("remote_record_digest"):
                    raise ValueError("sealed_preview_endpoint_binding_invalid")
                if identity_digest(record) != binding.get("identity_digest") or write_address_digest(record) != binding.get("write_address_digest") or semantic_digest(record) != binding.get("semantic_digest"):
                    raise ValueError("sealed_preview_endpoint_binding_invalid")
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
            if canonical.get("canonical_version") == "2":
                remote = canonical.get("remote_snapshot") or {}
                evaluation = evaluate_write_operations_v2(canonical.get("operation_intents", []), canonical.get("items", []), canonical.get("semantic_payload", {}), canonical.get("existing_endpoint_bindings", []), remote.get("relationship_records", []))
            else:
                evaluation = evaluate_write_operations(canonical.get("operation_intents", []), canonical.get("items", []), canonical.get("semantic_payload", {}))
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
