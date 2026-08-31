"""Runtime-owned context, provenance, lineage, and local preview storage."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import sqlite3
import threading
from contextlib import closing
import subprocess
from typing import Any, Callable, Mapping, Protocol, Sequence
from copy import deepcopy
from datetime import datetime, timezone

from delivery_system import sqlite_schema
from delivery_system.audit_state import AuditRecord, ApprovalRecord, AuditResult, AuditStatus
from delivery_system.canonical import canonical_payload, digest, normalize
from delivery_system.evidence import DeclaredSource, EvidenceRecord, SourcedValue
from delivery_system.formal_preview import PreviewLevel, SealedPreview
from delivery_system.remote_snapshot import (
    RemoteCapabilitySet,
    RemoteIssueRecord,
    RemotePermissionSet,
    RemoteQueryScope,
    RemoteRelationshipRecord,
    TypedRemoteSnapshot,
    _is_timezone_aware_timestamp,
)

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
    def _bind_and_save_repository_aware_preview(self, promotion: RuntimePromotion, **kwargs: Any) -> None: ...
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


def _preview_is_approval_eligible(preview: Mapping[str, Any]) -> bool:
    canonical = preview.get("canonical_payload")
    if not isinstance(canonical, Mapping):
        return False
    # OperationIntent is intentionally not an approved operation contract yet.
    # Until that contract exists, no product preview may become WriteEligible.
    return False


def _reload_promotion(store: Any, canonical: Mapping[str, Any], evidence: Sequence[Mapping[str, Any]]) -> RuntimePromotion | None:
    if canonical.get("preview_level") != PreviewLevel.REPOSITORY_AWARE.value:
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

    def __init__(self, workspace_identity: str | None = None, trust_context: Any = None) -> None:
        self.workspace_identity = workspace_identity
        self.trust_context = trust_context
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

    def _bind_and_save_repository_aware_preview(self, promotion: RuntimePromotion, **kwargs: Any) -> None:
        with self._lock:
            if self.trust_context is None:
                raise ValueError("driver_trust_context_required")
            if self.trust_context != promotion.trust_context:
                raise ValueError("driver_trust_context_mismatch")
            self._validate_promotion(promotion, kwargs)
            promotion.consume()
            try:
                self._save_preview_revision(**kwargs, promotion=promotion)
            finally:
                promotion._used = True

    def _validate_promotion(self, promotion: RuntimePromotion, kwargs: Mapping[str, Any]) -> None:
        if not isinstance(promotion, RuntimePromotion) or promotion._marker is not _PROMOTION_MARKER:
            raise ValueError("repository_aware_promotion_required")
        if kwargs.get("workspace_identity") != self.workspace_identity:
            raise ValueError("workspace_identity_mismatch")
        if kwargs.get("preview_id") != promotion.evidence_record.preview_id or kwargs.get("revision") != promotion.evidence_record.revision:
            raise ValueError("repository_aware_promotion_required")
        if kwargs.get("remote_snapshot_digest") != promotion.remote_snapshot_digest:
            raise ValueError("remote_snapshot_digest_mismatch")
        canonical = kwargs.get("canonical_payload")
        if not isinstance(canonical, Mapping) or canonical.get("remote_authority") != promotion.trust_context.remote_authority:
            raise ValueError("driver_trust_context_mismatch")

    def _save_preview_revision(self, request_id: str, preview_id: str, revision: int,
                              plan_digest: str, remote_snapshot_digest: str | None,
                              operation_set_digest: str, repository_identity: str | None,
                              items: list[dict[str, object]], workspace_identity: str | None = None,
                              canonical_payload: dict[str, object] | None = None,
                              preview_level: str | None = None,
                               evidence_records: list[dict[str, object]] | None = None,
                               promotion: RuntimePromotion | None = None) -> None:
        if workspace_identity is not None and self.workspace_identity is not None and workspace_identity != self.workspace_identity:
            raise ValueError("workspace_identity_mismatch")
        scope = workspace_identity or self.workspace_identity or ""
        if canonical_payload is None:
            raise ValueError("sealed_preview_required")
        if preview_level is not None:
            raise ValueError("preview_level_runtime_owned")
        normalized_canonical = _validate_preview_payload(canonical_payload, request_id, preview_id, revision,
                                  plan_digest, operation_set_digest,
                                  remote_snapshot_digest, repository_identity, evidence_records, scope, promotion)
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
            raise ValueError("preview_revision_conflict")
        key = (scope, preview_id)
        prior = self._previews.get(key)
        payload = {"request_id": request_id, "preview_id": preview_id, "revision": revision,
                   "canonical_payload": deepcopy(normalized_canonical)}
        if prior is not None and prior == payload:
            return
        prior_revision = prior.get("revision") if prior is not None else None
        if prior is not None and (not isinstance(prior_revision, int) or isinstance(prior_revision, bool) or prior_revision >= revision):
            raise ValueError("preview_revision_conflict")
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
            result = deepcopy(self._previews[(workspace_identity, preview_id)])
            self._validate_loaded_trust(result)
            return result
        except KeyError as exc:
            raise ValueError("preview_not_found") from exc

    def get_preview_revision(self, workspace_identity: str, preview_id: str, revision: int | None = None) -> dict[str, object]:
        if workspace_identity != (self.workspace_identity or workspace_identity):
            raise ValueError("preview crosses Workspace boundary")
        if revision is None:
            return self.get_preview(workspace_identity, preview_id)
        try:
            result = deepcopy(self._preview_history[(workspace_identity, preview_id, revision)])
            self._validate_loaded_trust(result)
            return result
        except KeyError as exc:
            raise ValueError("preview_not_found") from exc

    def _validate_loaded_trust(self, preview: Mapping[str, Any]) -> None:
        canonical = preview.get("canonical_payload")
        if isinstance(canonical, Mapping) and canonical.get("preview_level") == PreviewLevel.REPOSITORY_AWARE.value:
            if self.trust_context is None:
                raise ValueError("driver_trust_context_required")
            evidence = [record.to_dict() for record in self._evidence.values() if record.preview_id == canonical.get("preview_id") and record.revision == canonical.get("revision")]
            _reload_promotion(self, canonical, evidence)

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
            promotion = _reload_promotion(self, canonical_payload, evidence)
            validate_current_commit_context(audit, preview, evidence, build_registry_v1(), self.workspace_identity or audit.workspace_identity, promotion)
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

    SCHEMA_VERSION = 4

    def __init__(
        self,
        context: RuntimeContext,
        ignore_checker: Callable[[Path], bool] | None = None,
        tracked_checker: Callable[[Path], bool] | None = None,
        trust_context: Any = None,
    ):
        context.ensure_store_ready(ignore_checker=ignore_checker, tracked_checker=tracked_checker)
        self.context = context
        self.trust_context = trust_context
        self.path = Path(context.state_path)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        try:
            return sqlite_schema._open_connection(self.path)
        except sqlite_schema.SchemaOwnerError as exc:
            raise StorePreflightError("store_initialization_failed") from exc

    def _validate_promotion(self, promotion: RuntimePromotion, kwargs: Mapping[str, Any]) -> None:
        if not isinstance(promotion, RuntimePromotion) or promotion._marker is not _PROMOTION_MARKER:
            raise ValueError("repository_aware_promotion_required")
        if kwargs.get("workspace_identity") != self.context.workspace_identity:
            raise ValueError("workspace_identity_mismatch")
        if kwargs.get("preview_id") != promotion.evidence_record.preview_id or kwargs.get("revision") != promotion.evidence_record.revision:
            raise ValueError("repository_aware_promotion_required")
        if kwargs.get("remote_snapshot_digest") != promotion.remote_snapshot_digest:
            raise ValueError("remote_snapshot_digest_mismatch")
        canonical = kwargs.get("canonical_payload")
        if not isinstance(canonical, Mapping) or canonical.get("remote_authority") != promotion.trust_context.remote_authority:
            raise ValueError("driver_trust_context_mismatch")

    def save_preview_revision(self, *args: Any, **kwargs: Any) -> None:
        if "promotion" in kwargs:
            raise ValueError("repository_aware_promotion_required")
        self._save_preview_revision_impl(*args, promotion=None, **kwargs)

    def _bind_and_save_repository_aware_preview(self, promotion: RuntimePromotion, **kwargs: Any) -> None:
        if self.trust_context is None:
            raise ValueError("driver_trust_context_required")
        if self.trust_context != promotion.trust_context:
            raise ValueError("driver_trust_context_mismatch")
        self._validate_promotion(promotion, kwargs)
        promotion.consume()
        self._save_preview_revision_impl(**kwargs, promotion=promotion)

    def _initialize(self) -> None:
        try:
            with closing(self._connect()) as connection:
                sqlite_schema.ensure_schema_v4(
                    connection,
                    expected_workspace_identity=self.context.workspace_identity,
                )
        except sqlite_schema.SchemaOwnerError as exc:
            if exc.code in {
                "attestation_persistence_schema_version_unsupported",
                "attestation_persistence_schema_metadata_corrupt",
                "attestation_persistence_schema_shape_mismatch",
                "attestation_persistence_workspace_mismatch",
            }:
                raise StorePreflightError("store_corrupt") from exc
            raise StorePreflightError("store_initialization_failed") from exc

    def _save_preview_revision_impl(self, request_id: str, preview_id: str, revision: int,
                              plan_digest: str, remote_snapshot_digest: str | None,
                              operation_set_digest: str, repository_identity: str | None,
                              items: list[dict[str, object]], workspace_identity: str | None = None,
                              canonical_payload: dict[str, object] | None = None,
                              preview_level: str | None = None,
                               evidence_records: list[dict[str, object]] | None = None,
                               promotion: RuntimePromotion | None = None) -> None:
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
                                    self.context.workspace_identity, promotion)
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
                    raise ValueError("preview_revision_conflict")
                latest = connection.execute(
                    "SELECT MAX(revision) FROM records WHERE workspace_identity=? AND record_type='preview' AND record_id=?",
                    (self.context.workspace_identity, preview_id),
                ).fetchone()[0]
                if latest is not None and revision <= latest:
                    raise ValueError("preview_revision_conflict")
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
        canonical = result.get("canonical_payload")
        if isinstance(canonical, Mapping) and canonical.get("preview_level") == PreviewLevel.REPOSITORY_AWARE.value:
            if self.trust_context is None:
                raise ValueError("driver_trust_context_required")
            evidence = self.get_evidence_records(workspace_identity, list(canonical.get("evidence_ids", [])))
            _reload_promotion(self, canonical, evidence)
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
                promotion = _reload_promotion(self, canonical, evidence)
                from delivery_system.auditor import validate_current_commit_context
                from delivery_system.rules import build_registry_v1
                validate_current_commit_context(audit, preview_payload, evidence, build_registry_v1(), self.context.workspace_identity, promotion)
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

    def __init__(self, context: RuntimeContext, store: Any, driver: Any = None, trust_context: Any = None):
        self.context = context
        self.store = store
        self.driver = driver
        self.trust_context = trust_context
        if driver is not None and not hasattr(driver, "read_repository"):
            raise TypeError("untrusted_driver_adapter")
        if driver is not None and self.trust_context is None:
            raise ValueError("driver_trust_context_required")
        if driver is None and trust_context is not None:
            raise ValueError("driver_trust_context_mismatch")
        if driver is not None and getattr(store, "trust_context", None) not in {None, self.trust_context}:
            raise ValueError("driver_trust_context_mismatch")
        if driver is not None and getattr(store, "trust_context", None) is None:
            raise ValueError("driver_trust_context_required")

    @staticmethod
    def _id(prefix: str) -> str:
        import uuid
        return f"{prefix}-{uuid.uuid4().hex}"

    @staticmethod
    def _sourced(value: Mapping[str, Any]) -> dict[str, Any]:
        return SourcedValue(value["value"], DeclaredSource(value["declared_source"])).to_dict()

    def _state_fingerprint(self, canonical: Mapping[str, Any], evidence_records: Sequence[Mapping[str, Any]]) -> tuple[Any, ...]:
        driver = [record for record in evidence_records if record.get("source_kind") == "driver"]
        remote_digest = digest(driver[0]["payload"]) if len(driver) == 1 else None
        fallback = next((item.get("failure_fingerprint") for item in canonical.get("planner_observations", []) if item.get("kind") == "driver_preflight_failure"), None)
        return (canonical.get("plan_digest"), canonical.get("operation_set_digest"), remote_digest, fallback)

    def _return_existing_candidate(self, preview: Mapping[str, Any]) -> dict[str, Any]:
        canonical = dict(preview["canonical_payload"])
        evidence = self.store.get_evidence_records(self.context.workspace_identity, list(canonical.get("evidence_ids", [])))
        audit_digest = compute_audit_context_digest(
            self.context.workspace_identity, canonical["preview_id"], canonical["revision"],
            canonical["sealed_preview_digest"], evidence,
        )
        result = dict(canonical)
        result.update({"remote_snapshot": None, "findings": [], "stale": False, "write_eligible": False, "audit_context_digest": audit_digest})
        return result

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
        repository_claim = plan.get("repository_claim")
        repository_name = None
        if isinstance(repository_claim, Mapping):
            owner, name = repository_claim.get("owner"), repository_claim.get("name")
            if isinstance(owner, str) and isinstance(name, str) and owner.strip() and name.strip():
                repository_name = f"{owner.strip()}/{name.strip()}"
        validated_facts = None
        preflight_failures: tuple[Any, ...] = ()
        promotion = None
        query_scope = {
            "api_origin": getattr(self.trust_context, "origin", "offline://driver"),
            "api_version": "2026-03-10",
            "issue_state": "all", "pull_request_filter": "pull_request_field_excluded",
            "relationships": ["sub_issues", "parent", "blocked_by", "blocking"],
            "pagination_protocol": "link-header", "budget_profile": "github-rest-offline-v1",
        }
        if repository_name is not None and self.driver is not None:
            from delivery_system.drivers.preflight import validate_driver_facts
            validated_facts, preflight_failures = validate_driver_facts(
                self.driver, repository_name, query_scope, self.trust_context.trusted_driver_identity,
            )
        current_remote_content_digest = validated_facts.remote_content_digest if validated_facts is not None else None
        current_failure_codes = tuple(sorted({failure.code for failure in preflight_failures}))
        current_failure_fingerprint = digest({
            "domain": "delivery-system:driver-preflight-failure:v1",
            "repository": repository_name,
            "query_scope": query_scope,
            "failure_codes": list(current_failure_codes),
        }) if current_failure_codes else None
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
            prior_remote = None
            prior_observations = prior.get("canonical_payload", {}).get("planner_observations", [])
            prior_fallback = next((observation.get("failure_fingerprint") for observation in prior_observations if observation.get("kind") == "driver_preflight_failure"), None)
            prior_evidence_ids = list(prior.get("canonical_payload", {}).get("evidence_ids", []))
            if prior_evidence_ids:
                prior_evidence = self.store.get_evidence_records(self.context.workspace_identity, prior_evidence_ids)
                driver_evidence = [record for record in prior_evidence if record.get("source_kind") == "driver"]
                if len(driver_evidence) == 1:
                    prior_remote = digest(driver_evidence[0].get("payload"))
            if _preview_binding_value(prior, "plan_digest") == plan_digest and _preview_binding_value(prior, "operation_set_digest") == operation_set_digest and (prior_remote != current_remote_content_digest or prior_fallback != current_failure_fingerprint):
                revision = prior_revision + 1
        prior_items = {
            item["client_ref"]: item for item in (
                prior.get("canonical_payload", {}).get("items", ())
                if previous_preview_id is not None else ()
            )
        }
        sealed_items = []
        for item in work_items:
            previous_ref = item.get("previous_client_ref")
            if previous_preview_id is not None and item["client_ref"] in prior_items:
                item_id = prior_items[item["client_ref"]]["item_id"]
            elif previous_ref is not None:
                item_id = self.store.resolve_item_id(
                    self.context.workspace_identity, previous_preview_id or "", previous_ref,
                    prior_revision if previous_preview_id is not None else None,
                )
            else:
                item_id = self._id("item")
            sealed_items.append({"client_ref": item["client_ref"], "previous_client_ref": previous_ref, "item_id": item_id})
        blockers = []
        preview_level = PreviewLevel.CONCEPTUAL
        repository_identity = None
        remote_authority = None
        remote_snapshot = None
        remote_snapshot_digest = None
        if repository_name is not None:
            if validated_facts is not None:
                from delivery_system.drivers.preflight import bind_validated_facts
                from delivery_system.drivers.contract import RuntimeEvidenceBinding
                bound = bind_validated_facts(
                    validated_facts, RuntimeEvidenceBinding(self.context.workspace_identity, preview_id, revision), self.trust_context,
                )
                promotion = bound.promotion
                repository_identity = validated_facts.response.canonical_repository
                remote_authority = self.trust_context.remote_authority
                remote_snapshot = bound.snapshot.to_dict()
                remote_snapshot_digest = bound.remote_snapshot_digest
                preview_level = PreviewLevel.REPOSITORY_AWARE
            else:
                blockers = list(current_failure_codes)
                if self.driver is None and not blockers:
                    blockers = ["driver_unavailable"]
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
            "repository_identity": repository_identity,
            "remote_authority": remote_authority,
            "remote_snapshot": remote_snapshot,
            "remote_snapshot_digest": remote_snapshot_digest,
            "blockers": blockers,
            "planner_observations": ([{
                "kind": "driver_preflight_failure", "failure_codes": list(current_failure_codes),
                "failure_fingerprint": current_failure_fingerprint,
            }] if current_failure_codes else []),
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
        if promotion is not None:
            evidence.append(promotion.evidence_record)
            canonical["evidence_ids"] = [record.evidence_id for record in evidence]
        canonical["sealed_preview_digest"] = digest({
            key: value for key, value in canonical.items()
            if key != "sealed_preview_digest"
        })
        sealed_preview = SealedPreview.from_dict(canonical)
        canonical = sealed_preview.to_dict()
        save_args = dict(request_id=request_id, preview_id=preview_id, revision=revision,
            plan_digest=plan_digest, remote_snapshot_digest=remote_snapshot_digest,
            operation_set_digest=operation_set_digest, repository_identity=repository_identity,
            items=sealed_items, workspace_identity=self.context.workspace_identity,
            canonical_payload=canonical, evidence_records=[record.to_dict() for record in evidence])
        try:
            if promotion is not None:
                if not hasattr(self.store, "_bind_and_save_repository_aware_preview"):
                    raise ValueError("repository_aware_promotion_required")
                self.store._bind_and_save_repository_aware_preview(promotion, **save_args)
            else:
                self.store.save_preview_revision(**save_args)
        except ValueError as exc:
            if str(exc) != "preview_revision_conflict":
                raise
            winner = self.store.get_preview(self.context.workspace_identity, preview_id)
            winner_canonical = winner.get("canonical_payload")
            if not isinstance(winner_canonical, Mapping):
                raise
            winner_evidence = self.store.get_evidence_records(self.context.workspace_identity, list(winner_canonical.get("evidence_ids", [])))
            if self._state_fingerprint(canonical, [record.to_dict() for record in evidence]) != self._state_fingerprint(winner_canonical, winner_evidence):
                raise
            return self._return_existing_candidate(winner)
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

    def __init__(self, context: RuntimeContext, store: PreviewStore, trust_context: Any = None):
        self.context = context
        self.store = store
        self.trust_context = trust_context if trust_context is not None else getattr(store, "trust_context", None)
        if trust_context is not None and getattr(store, "trust_context", None) != trust_context:
            raise ValueError("driver_trust_context_mismatch")

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
        promotion = _reload_promotion(self.store, canonical, evidence)
        if promotion is not None and self.trust_context != promotion.trust_context:
            raise ValueError("driver_trust_context_mismatch")
        try:
            _validate_preview_payload(
                canonical, str(preview["request_id"]), preview_id, revision,
                str(_preview_binding_value(preview, "plan_digest")), str(_preview_binding_value(preview, "operation_set_digest")),
                _preview_binding_value(preview, "remote_snapshot_digest"), _preview_binding_value(preview, "repository_identity"), evidence,
                self.context.workspace_identity, promotion,
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
