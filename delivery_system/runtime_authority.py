"""Runtime promotion authority and repository-aware promotion reconstruction."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from delivery_system.canonical import digest
from delivery_system.evidence import EvidenceRecord
from delivery_system.formal_preview import PreviewLevel
from delivery_system.remote_snapshot import TypedRemoteSnapshot


_PROMOTION_MARKER = object()


class RuntimePromotion:
    """Opaque, single-use Runtime capability; public construction is rejected."""
    __slots__ = ("trust_context", "evidence_record", "snapshot", "remote_content_digest", "remote_snapshot_digest", "_marker", "_used")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if kwargs.pop("_marker", None) is not _PROMOTION_MARKER or kwargs:
            raise TypeError("runtime_promotion_internal_only")
        if len(args) != 5:
            raise TypeError("runtime_promotion_internal_only")
        self.trust_context, self.evidence_record, self.snapshot, self.remote_content_digest, self.remote_snapshot_digest = args
        self._marker = _PROMOTION_MARKER
        self._used = False

    @classmethod
    def _create(cls, trust_context: Any, evidence_record: EvidenceRecord, snapshot: TypedRemoteSnapshot,
                remote_content_digest: str, remote_snapshot_digest: str) -> "RuntimePromotion":
        return cls(trust_context, evidence_record, snapshot, remote_content_digest, remote_snapshot_digest, _marker=_PROMOTION_MARKER)

    def consume(self) -> None:
        if self._used:
            raise ValueError("repository_aware_promotion_reused")
        self._used = True


def _reload_promotion(store: Any, canonical: Mapping[str, Any], evidence: Sequence[Mapping[str, Any]]) -> RuntimePromotion | None:
    if canonical.get("preview_level") not in {PreviewLevel.REPOSITORY_AWARE.value, PreviewLevel.WRITE_ELIGIBLE.value}:
        return None
    trust = getattr(store, "trust_context", None)
    if trust is None:
        raise ValueError("driver_trust_context_required")
    driver_records = [record for record in evidence if record.get("source_kind") == "driver"]
    if len(driver_records) != 1:
        raise ValueError("repository_aware_promotion_required")
    record = EvidenceRecord.from_dict(driver_records[0])
    if record.source_identity != trust.trusted_driver_identity:
        raise ValueError("driver_trust_context_mismatch")
    remote = canonical.get("remote_snapshot")
    if not isinstance(remote, Mapping):
        raise ValueError("remote_snapshot_invalid")
    snapshot = TypedRemoteSnapshot.from_records(
        str(remote.get("repository_identity")), remote.get("query_scope", {}),
        remote.get("query_complete"), remote.get("pagination_complete"),
        remote.get("issue_records", []), remote.get("permissions", {}),
        remote.get("capabilities", []), remote.get("relationship_records", []),
        remote.get("evidence_ids", []), remote.get("observed_at"),
    )
    if tuple(sorted(snapshot.evidence_ids)) != (record.evidence_id,):
        raise ValueError("snapshot_evidence_mismatch")
    if record.evidence_id not in set(canonical.get("evidence_ids", [])):
        raise ValueError("evidence_reference_mismatch")
    promotion = RuntimePromotion._create(trust, record, snapshot, digest(record.payload), snapshot.digest())
    if canonical.get("remote_authority") != trust.remote_authority or canonical.get("remote_snapshot_digest") != promotion.remote_snapshot_digest:
        raise ValueError("driver_trust_context_mismatch")
    return promotion
