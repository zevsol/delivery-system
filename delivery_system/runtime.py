"""Runtime-owned context, provenance, lineage, and local preview storage."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import re
from pathlib import Path
import sqlite3
import threading
import uuid
from contextlib import closing
import subprocess
from typing import Any, Callable, Mapping, Protocol, Sequence
from copy import deepcopy
from datetime import datetime, timezone
from types import MappingProxyType

from delivery_system import sqlite_schema
from delivery_system.audit_state import AuditRecord, ApprovalRecord, AuditResult, AuditStatus
from delivery_system.audit_commit_authority import (
    AuditCommitAuthority, _verify_authority_identity, _verify_candidate,
)
from delivery_system.application_identity import LogicalApplicationIdentity, operation_identity, request_identity
from delivery_system.canonical import canonical_payload, digest, normalize
from delivery_system.evidence import DeclaredSource, EvidenceRecord, SourcedValue
from delivery_system.formal_preview import PreviewLevel, SealedPreview
from delivery_system.preview_validation import (
    _runtime_preview_level,
    _validate_preview_payload,
    validate_sealed_preview_invariants,
)
from delivery_system.write_operations import (
    WriteOperationEvaluation, evaluate_write_operations, normalize_write_operations,
    operation_set_digest_payload, evaluate_write_operations_v2, normalize_write_operations_v2,
    operation_set_digest_payload_v2,
)
from delivery_system.existing_endpoints import (
    SealedExistingEndpoint, selector_digest, semantic_digest, identity_digest,
    validate_issue_selector_url, write_address_digest,
)
from delivery_system.rules import RuleRegistry, build_registry_v1
from delivery_system.remote_snapshot import (
    RemoteCapabilitySet,
    RemoteIssueRecord,
    RemotePermissionSet,
    RemoteQueryScope,
    RemoteRelationshipRecord,
    TypedRemoteSnapshot,
    TypedRemoteSnapshotV2,
    _is_timezone_aware_timestamp,
)
from delivery_system.drivers.contract import (
    DriverTrustContext,
    RuntimeEvidenceBinding,
    normalize_repository_identity,
)
from delivery_system.drivers.preflight import bind_validated_facts, validate_driver_facts
from delivery_system.runtime_authority import _PROMOTION_MARKER, RuntimePromotion, _reload_promotion as _reload_promotion_v1
from delivery_system.attestation_github_app import (
    github_app_installation_principal,
    github_app_installation_source_verification_digest,
)
from delivery_system.github_app_credential import GitHubAppInstallationCredentialLease
from delivery_system.store_reads import (
    StoreReadMiss,
    read_inmemory_evidence_records,
    read_inmemory_preview_latest,
    read_inmemory_preview_revision,
    read_sqlite_evidence_records,
    read_sqlite_latest_preview_revision,
    read_sqlite_preview_latest,
    read_sqlite_preview_revision,
)


def _normalize_canonical_operations(canonical: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    if canonical.get("canonical_version") == "2":
        return tuple(normalize_write_operations_v2(canonical.get("operation_intents", [])))
    return tuple(normalize_write_operations(canonical.get("operation_intents", [])))


def _execution_operations(canonical: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    """Encode V2 operands into the legacy receipt-safe operation envelope.

    The public Preview remains typed V2; durable execution artifacts retain the
    existing operation schema and use tagged refs so old receipt validators stay
    unchanged while preserving endpoint provenance in operation identities.
    """
    operations = _normalize_canonical_operations(canonical)
    if canonical.get("canonical_version") != "2":
        return operations
    encoded = []
    for operation in operations:
        if operation["operation_kind"] == "create_issue":
            encoded.append({"operation_kind": "create_issue", "client_refs": [operation["endpoint"]["client_ref"]], "depends_on": []})
        else:
            refs = []
            for operand in operation["operands"]:
                prefix = "work_item:" if operand["endpoint_type"] == "work_item" else "existing_issue:"
                key = "client_ref" if operand["endpoint_type"] == "work_item" else "endpoint_ref"
                refs.append(prefix + operand[key])
            encoded.append({"operation_kind": operation["operation_kind"], "client_refs": refs, "depends_on": []})
    return tuple(encoded)


def _reload_promotion(store: Any, canonical: Mapping[str, Any], evidence: Sequence[Mapping[str, Any]]) -> RuntimePromotion | None:
    if canonical.get("canonical_version") != "2":
        return _reload_promotion_v1(store, canonical, evidence)
    if canonical.get("preview_level") not in {PreviewLevel.REPOSITORY_AWARE.value, PreviewLevel.WRITE_ELIGIBLE.value}:
        return None
    trust = getattr(store, "trust_context", None)
    driver_records = [record for record in evidence if record.get("source_kind") == "driver"]
    if trust is None or len(driver_records) != 1:
        raise ValueError("repository_aware_promotion_required")
    record = EvidenceRecord.from_dict(driver_records[0])
    if record.source_identity != trust.trusted_driver_identity:
        raise ValueError("driver_trust_context_mismatch")
    remote = canonical.get("remote_snapshot")
    if not isinstance(remote, Mapping):
        raise ValueError("remote_snapshot_invalid")
    snapshot = TypedRemoteSnapshotV2.from_records(
        str(remote.get("repository_identity")), remote.get("query_scope", {}), remote.get("query_complete"), remote.get("pagination_complete"),
        remote.get("issue_records", []), remote.get("permissions", {}), remote.get("capabilities", []), remote.get("relationship_records", []),
        remote.get("evidence_ids", []), remote.get("observed_at"),
    )
    if tuple(sorted(snapshot.evidence_ids)) != (record.evidence_id,):
        raise ValueError("snapshot_evidence_mismatch")
    promotion = RuntimePromotion._create(trust, record, snapshot, digest(record.payload), snapshot.digest())
    if canonical.get("remote_authority") != trust.remote_authority or canonical.get("remote_snapshot_digest") != promotion.remote_snapshot_digest:
        raise ValueError("driver_trust_context_mismatch")
    return promotion


class StorePreflightError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _normalize_windows_drive_namespace(path: Path) -> Path:
    """Normalize supported extended drive paths without broadening device support."""
    if os.name != "nt":
        return path
    value = os.fspath(path)
    if (
        isinstance(value, str)
        and value.startswith("\\\\?\\")
        and len(value) >= 7
        and value[4].isalpha()
        and value[5] == ":"
        and value[6] in "\\/"
    ):
        return Path(value[4:])
    return path


def _canonical_path_identity(path: Path, *, strict: bool) -> Path:
    return _normalize_windows_drive_namespace(Path(path).resolve(strict=strict))


def _canonical_workspace_relative_path(path: Path, workspace_root: Path) -> str:
    try:
        candidate = _canonical_path_identity(path, strict=False)
        root = _canonical_path_identity(workspace_root, strict=False)
        return candidate.relative_to(root).as_posix()
    except (OSError, RuntimeError, ValueError) as exc:
        raise StorePreflightError("store_not_ignored_or_tracked") from exc


def _default_ignored(path: Path, workspace_root: Path) -> bool:
    relative = _canonical_workspace_relative_path(path, workspace_root)
    result = subprocess.run(
        ["git", "check-ignore", "--quiet", "--no-index", "--", relative],
        cwd=_canonical_path_identity(workspace_root, strict=False),
        capture_output=True,
        check=False,
        text=True,
    )
    return result.returncode == 0


def _default_tracked(path: Path, workspace_root: Path) -> bool:
    relative = _canonical_workspace_relative_path(path, workspace_root)
    result = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "--", relative],
        cwd=_canonical_path_identity(workspace_root, strict=False),
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
        root = _canonical_path_identity(Path(self.normalized_workspace_root), strict=True)
        paths = (state.parent, state, *(Path(f"{state}-{suffix}") for suffix in ("wal", "shm", "journal")))
        if any(_is_reparse_or_symlink(path) for path in paths):
            raise StorePreflightError("store_not_ignored_or_tracked")
        try:
            for path in (state, *paths[2:]):
                if path.exists() and _canonical_path_identity(path, strict=True).parent.parent != root:
                    raise StorePreflightError("store_not_ignored_or_tracked")
            if (
                state.parent.exists()
                and _canonical_path_identity(state.parent, strict=True)
                != _canonical_path_identity(root / ".delivery-system", strict=False)
            ):
                raise StorePreflightError("store_not_ignored_or_tracked")
        except (OSError, RuntimeError) as exc:
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
        if _canonical_path_identity(state.parent, strict=True) != _canonical_path_identity(root / ".delivery-system", strict=False):
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
    def _read_preview_revision_for_status(self, workspace_identity: str, preview_id: str, revision: int) -> dict[str, object]: ...
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
def _preview_is_approval_eligible(preview: Mapping[str, Any]) -> bool:
    canonical = preview.get("canonical_payload")
    if not isinstance(canonical, Mapping) or canonical.get("preview_level") != PreviewLevel.WRITE_ELIGIBLE.value:
        return False
    if (not isinstance(canonical.get("workspace_identity"), str) or
            not isinstance(canonical.get("repository_identity"), str) or
            not isinstance(canonical.get("remote_snapshot_digest"), str) or
            canonical.get("blockers") != []):
        return False
    try:
        if canonical.get("canonical_version") == "2":
            remote = canonical.get("remote_snapshot") or {}
            evaluation = evaluate_write_operations_v2(canonical["operation_intents"], canonical["items"], canonical["semantic_payload"], canonical.get("existing_endpoint_bindings", []), remote.get("relationship_records", []))
            operation_digest = digest(operation_set_digest_payload_v2(evaluation.operations))
            plan_digest = digest({"canonical_version": "2", "semantic_payload": canonical["semantic_payload"]})
        else:
            evaluation = evaluate_write_operations(canonical["operation_intents"], canonical["items"], canonical["semantic_payload"])
            operation_digest = digest(operation_set_digest_payload(evaluation.operations))
            plan_digest = digest(canonical["semantic_payload"])
        return (
            evaluation.eligible
            and canonical.get("operation_set_digest") == operation_digest
            and canonical.get("plan_digest") == plan_digest
            and canonical.get("sealed_preview_digest") == digest({
                key: value for key, value in canonical.items() if key != "sealed_preview_digest"
            })
        )
    except (KeyError, TypeError, ValueError):
        return False


def _validate_approval_against_current_preview(
    approval: ApprovalRecord,
    audit: AuditRecord,
    preview: Mapping[str, Any],
    expected_workspace_identity: str,
) -> bool:
    """Validate the complete Approval -> Audit -> current Preview authority chain."""
    canonical = preview.get("canonical_payload")
    if not isinstance(canonical, Mapping):
        return False
    return (
        approval.validate_against(audit)
        and audit.verify_digest()
        and audit.approval_eligible
        and audit.status is AuditStatus.ACTIVE
        and audit.result is AuditResult.PASSED
        and audit.audit_scope == PreviewLevel.WRITE_ELIGIBLE.value
        and audit.workspace_identity == expected_workspace_identity
        and canonical.get("workspace_identity") == expected_workspace_identity
        and audit.preview_id == canonical.get("preview_id")
        and audit.revision == canonical.get("revision")
        and audit.sealed_preview_digest == canonical.get("sealed_preview_digest")
        and audit.plan_digest == canonical.get("plan_digest")
        and audit.operation_set_digest == canonical.get("operation_set_digest")
        and audit.remote_snapshot_digest == canonical.get("remote_snapshot_digest")
        and approval.repository_identity == canonical.get("repository_identity")
        and _preview_is_approval_eligible(preview)
    )


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


def _validate_current_audit_context(
    audit: AuditRecord,
    authority: AuditCommitAuthority,
    preview: Mapping[str, Any],
    evidence: list[dict[str, object]],
    promotion: RuntimePromotion | None,
    expected_workspace_identity: str,
) -> Mapping[str, Any]:
    authority = _verify_authority_identity(authority)
    if not isinstance(preview, Mapping):
        raise ValueError("sealed_preview_unavailable")
    request_id = preview.get("request_id")
    if (preview.get("preview_id") != audit.preview_id or
            preview.get("revision") != audit.revision):
        raise ValueError("preview_identity_mismatch")
    canonical = preview.get("canonical_payload")
    if not isinstance(canonical, Mapping):
        raise ValueError("sealed_preview_unavailable")
    if (canonical.get("preview_id") != audit.preview_id or
            canonical.get("revision") != audit.revision or
            canonical.get("workspace_identity") != expected_workspace_identity):
        raise ValueError("preview_identity_mismatch")
    normalized = _validate_preview_payload(
        canonical,
        request_id,
        audit.preview_id,
        audit.revision,
        audit.plan_digest,
        audit.operation_set_digest,
        audit.remote_snapshot_digest,
        canonical.get("repository_identity"),
        evidence,
        expected_workspace_identity,
        promotion,
    )
    current_context_digest = compute_audit_context_digest(
        expected_workspace_identity,
        audit.preview_id,
        audit.revision,
        normalized["sealed_preview_digest"],
        evidence,
        audit.rule_registry_version,
        audit.rule_registry_digest,
        normalized.get("preview_level"),
    )
    if (current_context_digest != audit.audit_context_digest or
            current_context_digest != getattr(authority, "audit_context_digest", None)):
        raise ValueError("audit_context_stale")
    return normalized


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


@dataclass(frozen=True)
class _ItemRecord:
    workspace_identity: str
    preview_id: str
    client_ref: str
    item_id: str
    tombstone: bool = False
    revision: int = 1


@dataclass(frozen=True, slots=True)
class _RestartAuthorityValidationProvenance:
    """In-memory proof that an authority passed the I4 activation boundary."""

    authority_id: str
    authority_issuance_id: str
    credential_binding_id: str
    credential_instance_id: str
    credential_class: str
    credential_principal_identity: str
    github_subject_identity: str
    repository_identity: str
    driver_identity: str
    remote_authority: str
    evidence_digest: str
    challenge_digest: str
    source_verification_digest: str
    workspace_identity: str
    application_id: str
    preview_id: str
    revision: int
    required_capabilities: tuple[str, ...]
    granted_capabilities: tuple[str, ...]
    expires_at: str
    authority_semantics_digest: str

    @classmethod
    def from_authority(cls, authority: Any, issuance_id: str, *, claims: Any) -> "_RestartAuthorityValidationProvenance":
        values = authority.to_dict()
        identity = LogicalApplicationIdentity.from_authority(values)
        return cls(
            authority_id=values["authority_id"],
            authority_issuance_id=issuance_id,
            credential_binding_id=values["credential_binding_id"],
            credential_instance_id=claims.credential_instance_id,
            credential_class=claims.credential_class,
            credential_principal_identity=claims.credential_principal_identity,
            github_subject_identity=claims.github_subject_identity,
            repository_identity=claims.repository_identity,
            driver_identity=claims.driver_identity,
            remote_authority=claims.remote_authority,
            evidence_digest=claims.evidence_digest,
            challenge_digest=claims.challenge_digest,
            source_verification_digest=claims.source_verification_digest,
            workspace_identity=values["workspace_identity"],
            application_id=identity.application_id,
            preview_id=values["preview_id"],
            revision=values["revision"],
            required_capabilities=tuple(values["required_capabilities"]),
            granted_capabilities=tuple(values["granted_capabilities"]),
            expires_at=values["expires_at"],
            authority_semantics_digest=digest(values),
        )

    def matches_authority(self, authority: Any, issuance_id: str) -> bool:
        try:
            values = authority.to_dict()
            return (
                self.authority_id == values["authority_id"]
                and self.authority_issuance_id == issuance_id
                and self.credential_binding_id == values["credential_binding_id"]
                and self.credential_instance_id == values["credential_instance_id"]
                and self.credential_principal_identity == values["credential_principal_identity"]
                and self.github_subject_identity == values["github_subject_identity"]
                and self.repository_identity == values["repository_identity"]
                and self.driver_identity == values["driver_identity"]
                and self.remote_authority == values["remote_authority"]
                and self.workspace_identity == values["workspace_identity"]
                and self.application_id == LogicalApplicationIdentity.from_authority(values).application_id
                and self.preview_id == values["preview_id"]
                and self.revision == values["revision"]
                and self.required_capabilities == tuple(values["required_capabilities"])
                and self.granted_capabilities == tuple(values["granted_capabilities"])
                and self.expires_at == values["expires_at"]
                and self.authority_semantics_digest == digest(values)
            )
        except Exception:
            return False


class InMemoryPreviewStore:
    """Deterministic test store; production state is owned by a SQLite adapter."""

    def __init__(self, workspace_identity: str | None = None, trust_context: Any = None) -> None:
        self.workspace_identity = workspace_identity
        self.trust_context = trust_context
        self.audit_backend_scope = "inmemory:" + uuid.uuid4().hex
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
            result = read_inmemory_preview_latest(self._previews, workspace_identity, preview_id)
            self._validate_loaded_trust(result)
            return result
        except StoreReadMiss as exc:
            raise ValueError("preview_not_found") from exc

    def get_preview_revision(self, workspace_identity: str, preview_id: str, revision: int | None = None) -> dict[str, object]:
        if workspace_identity != (self.workspace_identity or workspace_identity):
            raise ValueError("preview crosses Workspace boundary")
        if revision is None:
            return self.get_preview(workspace_identity, preview_id)
        try:
            result = read_inmemory_preview_revision(self._preview_history, workspace_identity, preview_id, revision)
            self._validate_loaded_trust(result)
            return result
        except StoreReadMiss as exc:
            raise ValueError("preview_not_found") from exc

    def _read_preview_revision_for_status(self, workspace_identity: str, preview_id: str, revision: int) -> dict[str, object]:
        if workspace_identity != (self.workspace_identity or workspace_identity):
            raise ValueError("preview crosses Workspace boundary")
        try:
            result = read_inmemory_preview_revision(self._preview_history, workspace_identity, preview_id, revision)
            result["revision"] = revision
            return result
        except StoreReadMiss as exc:
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
        try:
            return read_inmemory_evidence_records(self._evidence, workspace_identity, evidence_ids)
        except StoreReadMiss as exc:
            raise ValueError("evidence_not_found") from exc

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
        del audit
        raise ValueError("audit_commit_boundary_required")

    def _apply_audit_commit_atomic(self, audit: AuditRecord, authority: AuditCommitAuthority) -> AuditRecord:
        with self._lock:
            try:
                preview = read_inmemory_preview_revision(
                    self._preview_history, audit.workspace_identity, audit.preview_id, audit.revision,
                )
            except StoreReadMiss as exc:
                raise ValueError("preview_not_found") from exc
            self._validate_loaded_trust(preview)
            try:
                latest = read_inmemory_preview_latest(
                    self._previews, audit.workspace_identity, audit.preview_id,
                )
            except StoreReadMiss as exc:
                raise ValueError("preview_not_found") from exc
            self._validate_loaded_trust(latest)
            latest_revision = latest.get("revision")
            if (not isinstance(latest_revision, int) or isinstance(latest_revision, bool) or
                    latest_revision != audit.revision):
                raise ValueError("audit_context_stale")
            canonical_payload = preview.get("canonical_payload")
            if not isinstance(canonical_payload, Mapping):
                raise ValueError("sealed_preview_unavailable")
            try:
                evidence = read_inmemory_evidence_records(
                    self._evidence,
                    audit.workspace_identity,
                    [str(value) for value in canonical_payload.get("evidence_ids", [])],
                )
            except StoreReadMiss as exc:
                raise ValueError("evidence_not_found") from exc
            promotion = _reload_promotion(self, canonical_payload, evidence)
            _validate_current_audit_context(
                audit, authority, preview, evidence, promotion,
                self.workspace_identity or audit.workspace_identity,
            )
            _verify_candidate(audit, authority, canonical_payload, evidence, self.audit_backend_scope)
            if promotion is not None:
                if canonical_payload.get("remote_authority") != promotion.trust_context.remote_authority:
                    raise ValueError("audit_commit_boundary_required")
            elif canonical_payload.get("remote_authority") is not None:
                raise ValueError("audit_commit_boundary_required")
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
        existing = self._approvals.get((scope, approval.approval_id))
        if existing is not None:
            if existing.to_dict() == approval.to_dict():
                return
            raise ValueError("approval_binding_conflict")
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
        return _validate_approval_against_current_preview(
            approval, audit, preview, scope
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
        normalized_state = os.path.normcase(os.path.abspath(str(self.path)))
        self.audit_backend_scope = digest({"backend": "sqlite", "workspace_identity": context.workspace_identity, "state": normalized_state})
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
        if workspace_identity != self.context.workspace_identity:
            raise ValueError("preview crosses Workspace boundary")
        try:
            with closing(self._connect()) as connection:
                if revision is None:
                    result = read_sqlite_preview_latest(connection, workspace_identity, preview_id)
                else:
                    result = read_sqlite_preview_revision(connection, workspace_identity, preview_id, revision)
        except StoreReadMiss as exc:
            raise ValueError("preview_not_found") from exc
        if revision is not None:
            result["revision"] = revision
        canonical = result.get("canonical_payload")
        if isinstance(canonical, Mapping) and canonical.get("preview_level") == PreviewLevel.REPOSITORY_AWARE.value:
            if self.trust_context is None:
                raise ValueError("driver_trust_context_required")
            evidence = self.get_evidence_records(workspace_identity, list(canonical.get("evidence_ids", [])))
            _reload_promotion(self, canonical, evidence)
        return result

    def _read_preview_revision_for_status(self, workspace_identity: str, preview_id: str, revision: int) -> dict[str, object]:
        if workspace_identity != self.context.workspace_identity:
            raise ValueError("preview crosses Workspace boundary")
        try:
            with closing(self._connect()) as connection:
                result = read_sqlite_preview_revision(connection, workspace_identity, preview_id, revision)
        except StoreReadMiss as exc:
            raise ValueError("preview_not_found") from exc
        result["revision"] = revision
        return result

    def get_evidence_records(self, workspace_identity: str, evidence_ids: list[str]) -> list[dict[str, object]]:
        if workspace_identity != self.context.workspace_identity:
            raise ValueError("evidence_workspace_mismatch")
        try:
            with closing(self._connect()) as connection:
                return read_sqlite_evidence_records(connection, workspace_identity, evidence_ids)
        except StoreReadMiss as exc:
            raise ValueError("evidence_not_found") from exc

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
        del audit
        raise ValueError("audit_commit_boundary_required")

    def _apply_audit_commit_atomic(self, audit: AuditRecord, authority: AuditCommitAuthority) -> AuditRecord:
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                latest_revision = read_sqlite_latest_preview_revision(
                    connection, self.context.workspace_identity, audit.preview_id,
                )
                if latest_revision is None:
                    raise ValueError("preview_not_found")
                if int(latest_revision) != audit.revision:
                    raise ValueError("audit_context_stale")
                try:
                    preview_payload = read_sqlite_preview_revision(
                        connection, self.context.workspace_identity, audit.preview_id, audit.revision,
                    )
                except StoreReadMiss as exc:
                    raise ValueError("preview_not_found") from exc
                canonical = preview_payload.get("canonical_payload")
                if not isinstance(canonical, dict):
                    raise ValueError("sealed_preview_unavailable")
                try:
                    evidence = read_sqlite_evidence_records(
                        connection,
                        self.context.workspace_identity,
                        [str(value) for value in canonical.get("evidence_ids", [])],
                        audit.revision,
                    )
                except StoreReadMiss as exc:
                    raise ValueError("evidence_not_found") from exc
                promotion = _reload_promotion(self, canonical, evidence)
                _validate_current_audit_context(
                    audit, authority, preview_payload, evidence, promotion,
                    self.context.workspace_identity,
                )
                _verify_candidate(audit, authority, canonical, evidence, self.audit_backend_scope)
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
        import json
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT payload FROM audit_history WHERE workspace_identity=? AND audit_id=? ORDER BY event_no DESC LIMIT 1",
                    (self.context.workspace_identity, audit_id),
                ).fetchone()
                if row is None:
                    raise ValueError("audit_not_found")
                current = AuditRecord.from_dict(json.loads(row[0]))
                updated = current.transition(status, reason)
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
            except Exception:
                connection.rollback()
                raise

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
                audit = AuditRecord.from_dict(audit_data)
                if not audit.verify_digest() or audit.status is not AuditStatus.ACTIVE:
                    raise ValueError("approval_stale")
                preview_row = connection.execute(
                    "SELECT revision, payload FROM records WHERE workspace_identity=? AND record_type='preview' AND record_id=? AND revision=?",
                    (self.context.workspace_identity, approval.preview_id, approval.revision),
                ).fetchone()
                if preview_row is None:
                    raise ValueError("preview_not_found")
                preview = json.loads(preview_row[1])
                if not _validate_approval_against_current_preview(
                    approval, audit, preview, self.context.workspace_identity
                ):
                    raise ValueError("approval_binding_mismatch")
                latest = connection.execute(
                    "SELECT MAX(revision) FROM records WHERE workspace_identity=? AND record_type='preview' AND record_id=?",
                    (self.context.workspace_identity, approval.preview_id),
                ).fetchone()[0]
                if latest != approval.revision:
                    raise ValueError("approval_stale")
                existing_row = connection.execute(
                    "SELECT payload FROM records WHERE workspace_identity=? AND record_type='approval' AND record_id=? ORDER BY revision DESC LIMIT 1",
                    (self.context.workspace_identity, approval.approval_id),
                ).fetchone()
                if existing_row is not None:
                    existing = ApprovalRecord.from_dict(json.loads(existing_row[0]))
                    if existing.to_dict() == approval.to_dict():
                        connection.commit()
                        return
                    raise ValueError("approval_binding_conflict")
                try:
                    connection.execute(
                        "INSERT INTO records(workspace_identity, record_type, record_id, revision, payload) VALUES (?, 'approval', ?, ?, ?)",
                        (self.context.workspace_identity, approval.approval_id, approval.revision,
                         json.dumps(approval.to_dict(), sort_keys=True)),
                    )
                except sqlite3.IntegrityError as exc:
                    raced_row = connection.execute(
                        "SELECT payload FROM records WHERE workspace_identity=? AND record_type='approval' AND record_id=? ORDER BY revision DESC LIMIT 1",
                        (self.context.workspace_identity, approval.approval_id),
                    ).fetchone()
                    if raced_row is None:
                        raise ValueError("approval_invalid") from exc
                    try:
                        raced = ApprovalRecord.from_dict(json.loads(raced_row[0]))
                    except ValueError as parse_error:
                        raise ValueError("approval_invalid") from parse_error
                    if raced.to_dict() != approval.to_dict():
                        raise ValueError("approval_binding_conflict") from exc
                    if (not _validate_approval_against_current_preview(
                            raced, audit, preview, self.context.workspace_identity
                        ) or latest != approval.revision):
                        raise ValueError("approval_stale") from exc
                    connection.commit()
                    return
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
        return ApprovalRecord.from_dict(data)

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
            return _validate_approval_against_current_preview(
                approval, audit, preview, self.context.workspace_identity
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
        result.update({
            "remote_snapshot": None,
            "findings": [],
            "stale": False,
            "write_eligible": _preview_is_approval_eligible(preview),
            "audit_context_digest": audit_digest,
        })
        return result

    @staticmethod
    def _is_v2_plan(plan: Mapping[str, Any]) -> bool:
        return bool(plan.get("existing_issue_endpoints")) or any(
            isinstance(rel, Mapping) and (rel.get("from_endpoint") is not None or rel.get("to_endpoint") is not None)
            for rel in plan.get("planned_relationships", ())
        )

    def _preview_v2(self, plan: Mapping[str, Any], previous_preview_id: str | None = None) -> dict[str, Any]:
        """Plan the explicit mixed-endpoint V2 contract without changing V1 code paths."""
        work_items = list(plan.get("work_items", ()))
        item_refs = [item.get("client_ref") for item in work_items]
        if not item_refs or any(not isinstance(ref, str) or not ref for ref in item_refs) or len(item_refs) != len(set(item_refs)):
            raise ValueError("client_ref must be unique within a Draft")
        endpoint_declarations = list(plan.get("existing_issue_endpoints", ()))
        endpoint_refs = [entry.get("endpoint_ref") for entry in endpoint_declarations if isinstance(entry, Mapping)]
        if (len(endpoint_refs) != len(endpoint_declarations) or any(not isinstance(ref, str) or not ref for ref in endpoint_refs)
                or len(endpoint_refs) != len(set(endpoint_refs))):
            raise ValueError("existing_endpoint_ref_invalid")
        if set(item_refs) & set(endpoint_refs):
            raise ValueError("write_operation_reference_namespace_collision")
        semantic = {
            "repository_claim": plan.get("repository_claim"),
            "existing_issue_claims": list(plan.get("existing_issue_claims", ())),
            "existing_issue_endpoints": endpoint_declarations,
            "work_items": [{
                "client_ref": item["client_ref"],
                "previous_client_ref": item.get("previous_client_ref"),
                **{field: self._sourced(item[field]) for field in (
                    "role", "title", "context_problem", "outcome", "scope", "non_goals",
                    "acceptance_criteria", "verification", "required_capabilities", "write_metadata",
                )},
            } for item in work_items],
            "planned_relationships": list(plan.get("planned_relationships", ())),
        }
        operation_intents = [dict(operation) for operation in plan.get("operation_intents", ())]
        repository_claim = plan.get("repository_claim")
        repository_name = None
        if isinstance(repository_claim, Mapping):
            owner, name = repository_claim.get("owner"), repository_claim.get("name")
            if isinstance(owner, str) and isinstance(name, str) and owner.strip() and name.strip():
                repository_name = f"{owner.strip()}/{name.strip()}"
        plan_digest = digest({"canonical_version": "2", "semantic_payload": semantic})
        operation_set_digest = digest(operation_set_digest_payload_v2(operation_intents))
        request_id = self._id("request"); preview_id = self._id("preview"); revision = 1
        validated_facts = None; failures: tuple[Any, ...] = (); promotion = None
        query_scope = {
            "api_origin": getattr(self.trust_context, "origin", "offline://driver"), "api_version": "2026-03-10",
            "issue_state": "all", "pull_request_filter": "pull_request_field_excluded",
            "relationships": ["sub_issues", "parent", "blocked_by", "blocking"],
            "pagination_protocol": "link-header", "budget_profile": "github-rest-offline-v1",
        }
        if repository_name is not None and self.driver is not None:
            validated_facts, failures = validate_driver_facts(self.driver, repository_name, query_scope, self.trust_context.trusted_driver_identity)
        blockers = [failure.code for failure in failures]
        sealed_items = [{"client_ref": item["client_ref"], "previous_client_ref": item.get("previous_client_ref"), "item_id": self._id("item")} for item in work_items]
        snapshot_payload = None; snapshot_digest = None; repository_identity = None; remote_authority = None
        endpoint_bindings: list[dict[str, Any]] = []
        if validated_facts is not None:
            bound = bind_validated_facts(
                validated_facts, RuntimeEvidenceBinding(self.context.workspace_identity, preview_id, revision), self.trust_context,
                snapshot_schema_version="remote-snapshot-v2",
            )
            promotion = bound.promotion; snapshot_payload = bound.snapshot.to_dict(); snapshot_digest = bound.remote_snapshot_digest
            repository_identity = validated_facts.response.canonical_repository; remote_authority = self.trust_context.remote_authority
            records = list(snapshot_payload.get("issue_records", []))
            for declaration in endpoint_declarations:
                selector = {key: declaration.get(key) for key in ("number", "url") if declaration.get(key) is not None}
                if not selector:
                    blockers.append("existing_endpoint_selector_invalid"); continue
                matches = []
                for record in records:
                    number_match = selector.get("number") is None or record.get("issue_number") == selector.get("number")
                    url = selector.get("url")
                    url_match = True
                    if url is not None:
                        try:
                            url_number = validate_issue_selector_url(url, repository_name)
                            url_match = url_number == record.get("issue_number")
                        except ValueError as exc:
                            if str(exc) == "existing_endpoint_repository_mismatch":
                                blockers.append(str(exc))
                            url_match = False
                    if number_match and url_match:
                        matches.append(record)
                if len(matches) != 1:
                    blockers.append("existing_endpoint_not_found" if not matches else "existing_endpoint_selector_mismatch"); continue
                record = matches[0]
                binding = SealedExistingEndpoint(
                    declaration["endpoint_ref"], selector_digest(selector), record["issue_id"], digest(record),
                    identity_digest(record), write_address_digest(record), semantic_digest(record),
                ).to_dict()
                endpoint_bindings.append(binding)
        elif repository_name is not None:
            blockers.append("driver_unavailable" if self.driver is None else "remote_observation_unavailable")
        try:
            operation_evaluation = evaluate_write_operations_v2(
                operation_intents, sealed_items, semantic, endpoint_bindings,
                (snapshot_payload or {}).get("relationship_records", []),
            )
        except (TypeError, ValueError):
            operation_evaluation = WriteOperationEvaluation((), False, ("write_operation_contract_invalid",))
        blockers.extend(operation_evaluation.blockers)
        preview_level = PreviewLevel.WRITE_ELIGIBLE if snapshot_payload is not None and operation_evaluation.eligible and not blockers else (PreviewLevel.REPOSITORY_AWARE if snapshot_payload is not None else PreviewLevel.CONCEPTUAL)
        canonical = {
            "workspace_identity": self.context.workspace_identity, "request_id": request_id, "preview_id": preview_id, "revision": revision,
            "preview_level": preview_level.value, "provenance_status": "declared_unverified", "repository_identity": repository_identity,
            "remote_authority": remote_authority, "semantic_payload": semantic, "operation_intents": list(operation_evaluation.operations or operation_intents),
            "plan_digest": plan_digest, "operation_set_digest": operation_set_digest, "remote_snapshot": snapshot_payload,
            "remote_snapshot_digest": snapshot_digest, "items": sealed_items, "evidence_ids": [], "blockers": sorted(set(blockers)),
            "planner_observations": [], "canonical_version": "2", "existing_endpoint_bindings": endpoint_bindings,
        }
        evidence = []
        for sealed_item in semantic["work_items"]:
            for field in ("role", "title", "context_problem", "outcome", "scope", "non_goals", "acceptance_criteria", "verification", "required_capabilities", "write_metadata"):
                sourced = sealed_item[field]
                evidence.append(EvidenceRecord._create_controlled(self.context.workspace_identity, preview_id, revision, "declared_field", "declared", DeclaredSource(sourced["declared_source"]), f"{sealed_item['client_ref']}.{field}", sourced, None, "runtime-planner", None, None, "evidence-v1"))
        if promotion is not None:
            evidence.append(promotion.evidence_record)
        canonical["evidence_ids"] = [record.evidence_id for record in evidence]
        canonical["sealed_preview_digest"] = digest({key: value for key, value in canonical.items() if key != "sealed_preview_digest"})
        canonical = SealedPreview.from_dict(canonical).to_dict()
        save_args = dict(request_id=request_id, preview_id=preview_id, revision=revision, plan_digest=plan_digest, remote_snapshot_digest=snapshot_digest, operation_set_digest=operation_set_digest, repository_identity=repository_identity, items=sealed_items, workspace_identity=self.context.workspace_identity, canonical_payload=canonical, evidence_records=[record.to_dict() for record in evidence])
        if promotion is not None:
            self.store._bind_and_save_repository_aware_preview(promotion, **save_args)
        else:
            self.store.save_preview_revision(**save_args)
        result = dict(canonical)
        result.update({"remote_snapshot": None, "findings": [], "stale": False, "write_eligible": preview_level == PreviewLevel.WRITE_ELIGIBLE, "audit_context_digest": compute_audit_context_digest(self.context.workspace_identity, preview_id, revision, canonical["sealed_preview_digest"], [record.to_dict() for record in evidence])})
        return result

    def preview(self, plan: Mapping[str, Any], previous_preview_id: str | None = None) -> dict[str, Any]:
        if self._is_v2_plan(plan):
            return self._preview_v2(plan, previous_preview_id)
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
        operation_set_digest = digest(operation_set_digest_payload(operation_intents))
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
        try:
            operation_evaluation = evaluate_write_operations(operation_intents, sealed_items, semantic)
        except (TypeError, ValueError):
            operation_evaluation = WriteOperationEvaluation((), False, ("write_operation_contract_invalid",))
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
                preview_level = (PreviewLevel.WRITE_ELIGIBLE if operation_evaluation.eligible
                                 else PreviewLevel.REPOSITORY_AWARE)
            else:
                blockers = list(current_failure_codes)
                if self.driver is None and not blockers:
                    blockers = ["driver_unavailable"]
        if validated_facts is not None and not operation_evaluation.eligible:
            blockers.extend(operation_evaluation.blockers)
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
            "write_eligible": canonical["preview_level"] == PreviewLevel.WRITE_ELIGIBLE.value,
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


def _freeze_runtime_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_runtime_value(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_runtime_value(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze_runtime_value(item) for item in value)
    return value


def _thaw_runtime_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_runtime_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_runtime_value(item) for item in value]
    if isinstance(value, frozenset):
        return {_thaw_runtime_value(item) for item in value}
    return value


class _ApplierCapability:
    __slots__ = ("_service", "_store", "_dispatch")

    def __init__(self, service: Any, store: Any, dispatch: Callable[[str, Any], Any]) -> None:
        self._service = service
        self._store = store
        self._dispatch = dispatch

    def validate(self, service: Any, store: Any) -> None:
        if self._service is not service or self._store is not store:
            raise ValueError("applier_orchestration_required")

    def dispatch(self, context: Any, kind: str, command: Any) -> Any:
        if kind not in {"create_issue", "add_sub_issue", "add_dependency"}:
            raise ValueError("write_operation_kind_invalid")
        self._service._validate_live_credential_dispatch(context, self._store)
        return self._dispatch(kind, command)


class _LeaseBoundTokenProvider:
    __slots__ = ("_lease",)

    def __init__(self, lease: GitHubAppInstallationCredentialLease) -> None:
        if type(lease) is not GitHubAppInstallationCredentialLease:
            raise ValueError("host_credential_capability_invalid")
        lease._validate_integrity()
        self._lease = lease

    def get_token(self) -> str:
        return self._lease._dispatch_token()


def _compose_production_write_executor(token_provider: Any) -> Any:
    """Compose the only production write executor at the Runtime boundary."""
    from .drivers.github_write import GitHubRestWriteDriver, HttpsWriteTransport
    return GitHubRestWriteDriver(HttpsWriteTransport(), token_provider)


class RuntimeApprovalAuthorityService:
    """Runtime-owned bridge from explicit approval to immutable authority."""

    def __init__(self, context: RuntimeContext, store: PreviewStore, attestation_service: Any,
                 *, clock: Callable[[], datetime], host_credential_lease: Any = None,
                 artifact_link_adapter: Any = None, authority_binding_signer: Any = None,
                 authority_binding_store: Any = None, authority_binding_verifier: Any = None,
                 attestation_persistence_store: Any = None,
                 restart_credential_verifier: Any = None,
                 existing_endpoint_revalidator: Any = None,
                 rule_registry: RuleRegistry | None = None) -> None:
        if not isinstance(context, RuntimeContext) or not callable(clock):
            raise TypeError("approval_runtime_boundary_invalid")
        if rule_registry is None:
            rule_registry = build_registry_v1()
        if not isinstance(rule_registry, RuleRegistry):
            raise ValueError("approval_runtime_boundary_invalid")
        self.context = context
        self.store = store
        self.attestation_service = attestation_service
        self._rule_registry = rule_registry
        self.clock = clock
        self._lock = threading.RLock()
        self._authorities: dict[str, Any] = {}
        self._authority_issuance_ids: dict[str, str] = {}
        self._restart_authority_provenance: dict[str, _RestartAuthorityValidationProvenance] = {}
        self._live_credential_contexts: dict[tuple[str, int], Any] = {}
        self._execution_context_registry: dict[int, tuple[Any, tuple[Any, ...]]] = {}
        self._live_artifact_registry: dict[int, tuple[Any, str, Any, Any]] = {}
        self._artifact_link_adapter = artifact_link_adapter
        self._authority_binding_signer = authority_binding_signer
        self._authority_binding_store = authority_binding_store
        self._authority_binding_verifier = authority_binding_verifier
        self._attestation_persistence_store = attestation_persistence_store
        self._restart_credential_verifier = restart_credential_verifier
        if existing_endpoint_revalidator is not None and not callable(existing_endpoint_revalidator):
            raise ValueError("existing_endpoint_revalidator_invalid")
        self._existing_endpoint_revalidator = existing_endpoint_revalidator
        if host_credential_lease is not None:
            if type(host_credential_lease) is not GitHubAppInstallationCredentialLease:
                raise ValueError("host_credential_capability_invalid")
            host_credential_lease._validate_integrity()
        self._host_credential_lease = host_credential_lease
        self._host_credential_snapshot = (
            host_credential_lease._snapshot() if host_credential_lease is not None else None
        )
        self._write_orchestration_enabled = host_credential_lease is not None
        if host_credential_lease is not None:
            write_executor = _compose_production_write_executor(_LeaseBoundTokenProvider(host_credential_lease))
            if not all(callable(getattr(write_executor, name, None)) for name in
                       ("create_issue", "add_sub_issue", "add_dependency")):
                raise ValueError("write_executor_invalid")
            if getattr(write_executor, "executor_identity", None) != "delivery-system:github-rest-write-v1":
                raise ValueError("write_executor_invalid")
            def dispatch(kind: str, command: Any) -> Any:
                if kind == "create_issue":
                    return write_executor.create_issue(command)
                if kind == "add_sub_issue":
                    return write_executor.add_sub_issue(command)
                if kind == "add_dependency":
                    return write_executor.add_dependency(command)
                raise ValueError("write_operation_kind_invalid")
            self._write_executor_factory = lambda execution_store: _ApplierCapability(self, execution_store, dispatch)
        else:
            self._write_executor_factory = None

    def _validate_live_credential_dispatch(self, context: Any, store: Any) -> None:
        if type(context) is not RuntimeApplicationExecutionContext or store is None:
            raise ValueError("credential_currentness_mismatch")
        if self._host_credential_lease is None or self._host_credential_snapshot is None:
            raise ValueError("credential_capability_unregistered")
        if type(self._host_credential_lease) is not GitHubAppInstallationCredentialLease:
            raise ValueError("credential_capability_unregistered")
        context._require_current()
        authority = context._authority
        lease = self._host_credential_lease
        restart_provenance = self._restart_authority_provenance.get(authority.authority_id)
        if restart_provenance is not None:
            issuance_id = self._authority_issuance_ids.get(authority.authority_id)
            if not isinstance(issuance_id, str) or not restart_provenance.matches_authority(authority, issuance_id):
                raise ValueError("credential_currentness_mismatch")
            try:
                lease._validate_integrity()
                evidence = lease._snapshot()
                if evidence is not self._host_credential_snapshot:
                    raise ValueError("credential_currentness_mismatch")
                if lease._credential_class() != restart_provenance.credential_class:
                    raise ValueError("credential_instance_mismatch")
                if evidence.credential_instance_id != restart_provenance.credential_instance_id:
                    raise ValueError("credential_instance_mismatch")
                if github_app_installation_principal(evidence.app_id, evidence.installation_id) != restart_provenance.credential_principal_identity:
                    raise ValueError("credential_principal_mismatch")
                if evidence.repository_identity != restart_provenance.repository_identity:
                    raise ValueError("credential_repository_mismatch")
                if evidence.repository_scope != (restart_provenance.repository_identity,):
                    raise ValueError("credential_scope_mismatch")
                if dict(evidence.effective_permissions).get("issues") != "write":
                    raise ValueError("credential_capability_mismatch")
                if evidence.expires_at != restart_provenance.expires_at:
                    raise ValueError("credential_currentness_mismatch")
                if "issues:write" not in restart_provenance.required_capabilities:
                    raise ValueError("credential_capability_mismatch")
                now = self.clock().astimezone(timezone.utc)
                expires = datetime.fromisoformat(evidence.expires_at.replace("Z", "+00:00"))
                if expires <= now:
                    raise ValueError("credential_expired")
                request = {
                    "repository_identity": restart_provenance.repository_identity,
                    "required_capabilities": restart_provenance.required_capabilities,
                    "github_subject_identity": restart_provenance.github_subject_identity,
                    "driver_identity": restart_provenance.driver_identity,
                    "remote_authority": restart_provenance.remote_authority,
                    "preview_id": authority.preview_id,
                    "revision": authority.revision,
                    "operation_set_digest": authority.operation_set_digest,
                    "remote_snapshot_digest": authority.remote_snapshot_digest,
                    "evidence_digest": restart_provenance.evidence_digest,
                    "challenge_digest": restart_provenance.challenge_digest,
                }
                if github_app_installation_source_verification_digest(evidence, request) != restart_provenance.source_verification_digest:
                    raise ValueError("credential_currentness_mismatch")
            except ValueError:
                raise
            except (AttributeError, TypeError, ValueError):
                raise ValueError("credential_currentness_mismatch") from None
            return
        binding = self.attestation_service.resolve_registered_binding(authority.credential_binding_id)
        try:
            lease._validate_integrity()
        except ValueError:
            raise ValueError("credential_capability_unregistered") from None
        evidence = lease._snapshot()
        if evidence is not self._host_credential_snapshot:
            raise ValueError("credential_currentness_mismatch")
        if binding.credential_class != lease._credential_class():
            raise ValueError("credential_instance_mismatch")
        if (authority.credential_instance_id != binding.credential_instance_id or
                authority.credential_principal_identity != binding.credential_principal_identity or
                authority.repository_identity != binding.repository_identity or
                tuple(authority.required_capabilities) != tuple(binding.required_capabilities) or
                tuple(authority.granted_capabilities) != tuple(binding.granted_capabilities) or
                authority.expires_at != binding.expires_at):
            raise ValueError("credential_currentness_mismatch")
        if evidence.credential_instance_id != binding.credential_instance_id:
            raise ValueError("credential_instance_mismatch")
        if github_app_installation_principal(evidence.app_id, evidence.installation_id) != binding.credential_principal_identity:
            raise ValueError("credential_principal_mismatch")
        if evidence.repository_identity != binding.repository_identity:
            raise ValueError("credential_repository_mismatch")
        if evidence.repository_scope != (binding.repository_identity,):
            raise ValueError("credential_scope_mismatch")
        if dict(evidence.effective_permissions).get("issues") != "write":
            raise ValueError("credential_capability_mismatch")
        if evidence.expires_at != binding.expires_at:
            raise ValueError("credential_currentness_mismatch")
        if "issues:write" not in tuple(binding.required_capabilities) or "issues:write" not in tuple(binding.granted_capabilities):
            raise ValueError("credential_capability_mismatch")
        now = self.clock().astimezone(timezone.utc)
        try:
            expires = datetime.fromisoformat(evidence.expires_at.replace("Z", "+00:00"))
        except (AttributeError, TypeError, ValueError):
            raise ValueError("credential_currentness_mismatch") from None
        if expires <= now:
            raise ValueError("credential_expired")
        request = {
            "repository_identity": binding.repository_identity,
            "required_capabilities": tuple(binding.required_capabilities),
            "github_subject_identity": binding.github_subject_identity,
            "driver_identity": binding.driver_identity,
            "remote_authority": binding.remote_authority,
            "preview_id": binding.preview_id,
            "revision": binding.revision,
            "operation_set_digest": binding.operation_set_digest,
            "remote_snapshot_digest": binding.remote_snapshot_digest,
            "evidence_digest": binding.evidence_digest,
            "challenge_digest": binding.challenge_digest,
        }
        if github_app_installation_source_verification_digest(evidence, request) != binding.source_verification_digest:
            raise ValueError("credential_currentness_mismatch")

    def _has_registered_live_binding(self, binding_id: str) -> bool:
        try:
            return self.attestation_service.resolve_registered_binding(binding_id) is not None
        except Exception:
            return False

    @staticmethod
    def _approval_id(audit: AuditRecord) -> str:
        return "approval-" + hashlib.sha256(canonical_payload({
            "domain": "delivery-system:human-approval:v1",
            "workspace_identity": audit.workspace_identity,
            "audit_id": audit.audit_id,
            "audit_digest": audit.audit_digest,
            "preview_id": audit.preview_id,
            "revision": audit.revision,
        }).encode("utf-8")).hexdigest()

    @staticmethod
    def _approval_digest(approval: ApprovalRecord) -> str:
        return digest({"domain": "delivery-system:approval-binding:v1", "approval": approval.to_dict()})

    @staticmethod
    def _utc(value: datetime) -> str:
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("approval_invalid")
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    def _resolve_audit(self, preview_id: str, revision: int) -> tuple[dict[str, Any], AuditRecord]:
        try:
            preview = self.store.get_preview(self.context.workspace_identity, preview_id)
        except ValueError as exc:
            raise ValueError("preview_not_found") from exc
        if preview.get("revision") != revision:
            raise ValueError("preview_stale")
        audits = self.store.list_active_audits(self.context.workspace_identity, preview_id, revision)
        if not audits:
            raise ValueError("audit_not_found")
        if len(audits) != 1:
            raise ValueError("approval_audit_ambiguous")
        audit = audits[0]
        if not audit.verify_digest() or not audit.approval_eligible:
            raise ValueError("audit_stale")
        return preview, audit

    def record_approval(self, preview_id: str, revision: int, approval_command: str,
                        approver_claim: str) -> ApprovalRecord:
        if (not isinstance(preview_id, str) or not preview_id or
                not isinstance(revision, int) or isinstance(revision, bool) or revision < 1 or
                not isinstance(approval_command, str) or not isinstance(approver_claim, str) or
                not approver_claim.strip()):
            raise ValueError("approval_invalid")
        claim = approver_claim.strip()
        with self._lock:
            preview, audit = self._resolve_audit(preview_id, revision)
            if approval_command != f"批准写入 {preview_id} {revision}":
                raise ValueError("approval_command_invalid")
            canonical = preview.get("canonical_payload")
            repository_identity = canonical.get("repository_identity") if isinstance(canonical, Mapping) else None
            if not isinstance(repository_identity, str) or not repository_identity:
                raise ValueError("approval_binding_mismatch")
            candidate = ApprovalRecord.create(
                self._approval_id(audit), audit, repository_identity, claim,
                self._utc(self.clock()), approval_command,
            )
            try:
                existing = self.store.get_approval(self.context.workspace_identity, candidate.approval_id)
            except ValueError as exc:
                if str(exc) != "approval_not_found":
                    raise
                if (audit.rule_registry_version != self._rule_registry.registry_version or
                        audit.rule_registry_digest != self._rule_registry.registry_digest):
                    raise ValueError("audit_stale")
                self.store.record_approval(candidate)
                return self.store.get_approval(self.context.workspace_identity, candidate.approval_id)
            if not self.store.validate_approval_current(existing):
                raise ValueError("approval_stale")
            existing_data = existing.to_dict()
            candidate_data = candidate.to_dict()
            existing_data.pop("approved_at")
            candidate_data.pop("approved_at")
            if existing_data != candidate_data:
                raise ValueError("approval_binding_conflict")
            return existing

    def issue_application_authority(self, preview_id: str, revision: int, approval_id: str) -> Any:
        from delivery_system.application_authority import ApplicationAuthority, _AUTHORITY_MARKER
        from delivery_system.application_identity import LogicalApplicationIdentity, operation_identity
        from delivery_system.authority_binding import AuthorityBindingRecord, create_signed_authority_binding
        from delivery_system.authority_binding_persistence import PersistedAuthorityBinding
        from delivery_system.attestation_runtime import VerifiedRuntimeCredentialContext
        from delivery_system.verified_attestation_artifact import VerifiedCredentialArtifactLink
        if not isinstance(approval_id, str) or not approval_id:
            raise ValueError("application_authority_rejected")
        with self._lock:
            if not all((self._artifact_link_adapter is not None,
                        callable(getattr(self._artifact_link_adapter, "persist_verified_attestation", None)),
                        self._authority_binding_signer is not None,
                        self._authority_binding_store is not None,
                        callable(getattr(self._authority_binding_store, "save_authority_binding", None)),
                        callable(getattr(self._authority_binding_store, "resolve_authority_binding_for_operation", None)),
                        callable(getattr(self._authority_binding_store, "load_authority_binding", None)))):
                raise ValueError("authority_issuance_dependencies_required")
            preview, audit = self._resolve_audit(preview_id, revision)
            if approval_id != self._approval_id(audit):
                raise ValueError("approval_binding_mismatch")
            try:
                approval = self.store.get_approval(self.context.workspace_identity, approval_id)
            except ValueError as exc:
                raise ValueError("approval_not_found") from exc
            if not self.store.validate_approval_current(approval):
                raise ValueError("approval_stale")
            if not _validate_approval_against_current_preview(
                approval, audit, preview, self.context.workspace_identity,
            ):
                raise ValueError("approval_stale")
            context_key = (preview_id, revision)
            verified_context = self._live_credential_contexts.get(context_key)
            if (not isinstance(verified_context, VerifiedRuntimeCredentialContext) or
                    not VerifiedRuntimeCredentialContext.is_source_owned(verified_context)):
                result = self.attestation_service.orchestrate(preview_id, revision)
                if (not result.success or result.binding is None or
                        not isinstance(result.verified_context, VerifiedRuntimeCredentialContext)):
                    code = result.failures[0].code if result.failures else "credential_binding_mismatch"
                    raise ValueError(code)
                verified_context = result.verified_context
                self._live_credential_contexts[context_key] = verified_context
            if not VerifiedRuntimeCredentialContext.is_source_owned(verified_context):
                raise ValueError("credential_binding_mismatch")
            binding = verified_context.binding
            registered_binding = self.attestation_service.resolve_registered_binding(binding.binding_id)
            if registered_binding is not binding:
                raise ValueError("credential_binding_mismatch")
            link = self._artifact_link_adapter.persist_verified_attestation(verified_context)
            if type(link) is not VerifiedCredentialArtifactLink or link.credential_binding_id != binding.binding_id:
                raise ValueError("verified_attestation_artifact_link_invalid")
            artifact = link.artifact
            if (artifact.attestation_id != verified_context.claims.attestation_id or
                    artifact.claims_payload.to_payload() != verified_context.claims.to_payload() or
                    artifact.claims_digest != verified_context.claims.claims_digest() or
                    artifact.detached_proof != verified_context.envelope.proof or
                    artifact.original_verified_at != verified_context.verified_at):
                raise ValueError("verified_attestation_artifact_link_invalid")
            canonical = preview.get("canonical_payload")
            if not isinstance(canonical, Mapping):
                raise ValueError("application_authority_rejected")
            try:
                operations = _execution_operations(canonical)
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError("operation_set_mismatch") from exc
            if not operations:
                raise ValueError("operation_set_mismatch")
            required = tuple(binding.required_capabilities)
            granted = tuple(binding.granted_capabilities)
            if "issues:write" not in required or not set(required).issubset(granted) or "issues:write" not in granted:
                raise ValueError("credential_capability_insufficient")
            values = {
                "authority_id": "",
                "workspace_identity": self.context.workspace_identity,
                "repository_identity": canonical.get("repository_identity"),
                "preview_id": preview_id, "revision": revision,
                "sealed_preview_digest": canonical.get("sealed_preview_digest"),
                "plan_digest": canonical.get("plan_digest"),
                "operation_set_digest": canonical.get("operation_set_digest"),
                "remote_snapshot_digest": canonical.get("remote_snapshot_digest"),
                "audit_id": audit.audit_id, "audit_digest": audit.audit_digest,
                "approval_id": approval.approval_id, "approval_digest": self._approval_digest(approval),
                "credential_binding_id": binding.binding_id,
                "credential_instance_id": binding.credential_instance_id, "issuer_id": binding.issuer_id,
                "credential_principal_identity": binding.credential_principal_identity,
                "github_subject_identity": binding.github_subject_identity,
                "driver_identity": binding.driver_identity, "remote_authority": binding.remote_authority,
                "required_capabilities": required, "granted_capabilities": granted,
                "issued_at": "", "expires_at": binding.expires_at,
            }
            for field in ("workspace_identity", "repository_identity", "preview_id", "revision", "plan_digest",
                          "sealed_preview_digest", "operation_set_digest", "remote_snapshot_digest"):
                if getattr(binding, field, None) != values[field]:
                    raise ValueError("credential_binding_mismatch")
            for field in ("audit_id", "audit_digest"):
                if getattr(binding, field, None) != values[field]:
                    raise ValueError("credential_binding_mismatch")
            if (binding.remote_authority != values["remote_authority"] or
                    binding.driver_identity != values["driver_identity"] or
                    binding.credential_instance_id != values["credential_instance_id"] or
                    binding.issuer_id != values["issuer_id"] or
                    binding.credential_principal_identity != values["credential_principal_identity"] or
                    binding.github_subject_identity != values["github_subject_identity"] or
                    tuple(binding.granted_capabilities) != granted):
                raise ValueError("credential_binding_mismatch")
            if not _preview_is_approval_eligible(preview):
                raise ValueError("approval_stale")
            identity = LogicalApplicationIdentity.from_authority(values)
            operation_ids = tuple(
                operation_identity(identity.application_id, index, operation)
                for index, operation in enumerate(operations)
            )
            for operation_id in operation_ids:
                if self._authority_binding_store.resolve_authority_binding_for_operation(
                    self.context.workspace_identity, operation_id,
                ) is not None:
                    raise ValueError("authority_issuance_requires_recovery")
            values["authority_id"] = ApplicationAuthority.expected_id(values)
            if values["authority_id"] in self._authorities:
                raise ValueError("application_authority_registry_conflict")
            issued_at = self._utc(self.clock())
            try:
                if datetime.fromisoformat(binding.expires_at.replace("Z", "+00:00")) <= datetime.fromisoformat(issued_at.replace("Z", "+00:00")):
                    raise ValueError("credential_binding_mismatch")
            except (AttributeError, TypeError, ValueError) as exc:
                if str(exc) == "credential_binding_mismatch":
                    raise
                raise ValueError("credential_binding_mismatch") from exc
            values["issued_at"] = issued_at
            existing = self._authorities.get(values["authority_id"])
            if existing is not None:
                raise ValueError("application_authority_registry_conflict")
            authority = ApplicationAuthority._create(values, _marker=_AUTHORITY_MARKER)
            authority_binding = AuthorityBindingRecord.create(
                workspace_identity=self.context.workspace_identity,
                application_id=identity.application_id,
                credential_binding_id=binding.binding_id,
                required_capabilities=required,
                authority_issued_at=issued_at,
                attestation_artifact_id=link.artifact_id,
                attestation_artifact_digest=link.artifact_digest,
                authorized_operation_identities=operation_ids,
            )
            signed_binding = create_signed_authority_binding(
                authority_binding, self._authority_binding_signer,
            )
            persisted = self._authority_binding_store.save_authority_binding(signed_binding)
            if (type(persisted) is not PersistedAuthorityBinding or
                    persisted.signed != signed_binding or
                    persisted.canonical_payload != signed_binding.payload.canonical_bytes() or
                    persisted.authority_issuance_id != signed_binding.payload.authority_issuance_id):
                raise ValueError("authority_binding_persistence_conflict")
            issuance_id = persisted.authority_issuance_id
            associated = self._authority_issuance_ids.get(authority.authority_id)
            if associated is not None and associated != issuance_id:
                raise ValueError("application_authority_registry_conflict")
            if self._authorities.get(authority.authority_id) is not None:
                raise ValueError("application_authority_registry_conflict")
            self._authority_issuance_ids[authority.authority_id] = issuance_id
            self._authorities[authority.authority_id] = authority
            return authority

    def recover_application_authority(self, preview_id: str, revision: int, approval_id: str) -> Any:
        """Recover one already-durable authority issuance using live Runtime evidence."""
        from delivery_system.application_authority import ApplicationAuthority, _AUTHORITY_MARKER
        from delivery_system.application_identity import LogicalApplicationIdentity, operation_identity
        from delivery_system.authority_binding_persistence import PersistedAuthorityBinding
        from delivery_system.attestation_runtime import VerifiedRuntimeCredentialContext
        from delivery_system.verified_attestation_artifact import VerifiedCredentialArtifactLink

        if not isinstance(approval_id, str) or not approval_id:
            raise ValueError("application_authority_rejected")
        with self._lock:
            store = self._authority_binding_store
            verifier = self._authority_binding_verifier
            if not all((self._artifact_link_adapter is not None,
                        callable(getattr(self._artifact_link_adapter, "resolve_verified_attestation", None)),
                        store is not None,
                        callable(getattr(store, "resolve_authority_binding_for_operation", None)),
                        callable(getattr(store, "load_authority_binding", None)),
                        verifier is not None,
                        callable(getattr(verifier, "verify", None)))):
                raise ValueError("authority_recovery_dependencies_required")
            preview, audit = self._resolve_audit(preview_id, revision)
            if approval_id != self._approval_id(audit):
                raise ValueError("approval_binding_mismatch")
            try:
                approval = self.store.get_approval(self.context.workspace_identity, approval_id)
            except ValueError as exc:
                raise ValueError("approval_not_found") from exc
            if not self.store.validate_approval_current(approval):
                raise ValueError("approval_stale")
            if not _validate_approval_against_current_preview(
                approval, audit, preview, self.context.workspace_identity,
            ):
                raise ValueError("approval_stale")
            context = self._live_credential_contexts.get((preview_id, revision))
            if (not isinstance(context, VerifiedRuntimeCredentialContext) or
                    not VerifiedRuntimeCredentialContext.is_source_owned(context)):
                raise ValueError("authority_recovery_live_context_required")
            binding = context.binding
            if self.attestation_service.resolve_registered_binding(binding.binding_id) is not binding:
                raise ValueError("credential_binding_mismatch")
            canonical = preview.get("canonical_payload")
            if not isinstance(canonical, Mapping):
                raise ValueError("application_authority_rejected")
            try:
                operations = _execution_operations(canonical)
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError("operation_set_mismatch") from exc
            if not operations:
                raise ValueError("operation_set_mismatch")
            required = tuple(binding.required_capabilities)
            granted = tuple(binding.granted_capabilities)
            if ("issues:write" not in required or not set(required).issubset(granted) or
                    "issues:write" not in granted):
                raise ValueError("credential_capability_insufficient")
            values = {
                "authority_id": "",
                "workspace_identity": self.context.workspace_identity,
                "repository_identity": canonical.get("repository_identity"),
                "preview_id": preview_id, "revision": revision,
                "sealed_preview_digest": canonical.get("sealed_preview_digest"),
                "plan_digest": canonical.get("plan_digest"),
                "operation_set_digest": canonical.get("operation_set_digest"),
                "remote_snapshot_digest": canonical.get("remote_snapshot_digest"),
                "audit_id": audit.audit_id, "audit_digest": audit.audit_digest,
                "approval_id": approval.approval_id, "approval_digest": self._approval_digest(approval),
                "credential_binding_id": binding.binding_id,
                "credential_instance_id": binding.credential_instance_id, "issuer_id": binding.issuer_id,
                "credential_principal_identity": binding.credential_principal_identity,
                "github_subject_identity": binding.github_subject_identity,
                "driver_identity": binding.driver_identity, "remote_authority": binding.remote_authority,
                "required_capabilities": required, "granted_capabilities": granted,
                "issued_at": "", "expires_at": binding.expires_at,
            }
            for field in ("workspace_identity", "repository_identity", "preview_id", "revision", "plan_digest",
                          "sealed_preview_digest", "operation_set_digest", "remote_snapshot_digest"):
                if getattr(binding, field, None) != values[field]:
                    raise ValueError("credential_binding_mismatch")
            for field in ("audit_id", "audit_digest"):
                if getattr(binding, field, None) != values[field]:
                    raise ValueError("credential_binding_mismatch")
            if (binding.remote_authority != values["remote_authority"] or
                    binding.driver_identity != values["driver_identity"] or
                    binding.credential_instance_id != values["credential_instance_id"] or
                    binding.issuer_id != values["issuer_id"] or
                    binding.credential_principal_identity != values["credential_principal_identity"] or
                    binding.github_subject_identity != values["github_subject_identity"] or
                    tuple(binding.granted_capabilities) != granted):
                raise ValueError("credential_binding_mismatch")
            if not _preview_is_approval_eligible(preview):
                raise ValueError("approval_stale")
            identity = LogicalApplicationIdentity.from_authority(values)
            operation_ids = tuple(
                operation_identity(identity.application_id, index, operation)
                for index, operation in enumerate(operations)
            )
            assignments = []
            for operation_id in operation_ids:
                try:
                    assigned = store.resolve_authority_binding_for_operation(
                        self.context.workspace_identity, operation_id,
                    )
                except Exception as exc:
                    raise ValueError("restart_reconstruction_persistence_error") from exc
                if assigned is None:
                    raise ValueError("authority_recovery_partial_or_missing")
                if not isinstance(assigned, PersistedAuthorityBinding):
                    raise ValueError("authority_binding_persistence_corrupt")
                assignments.append(assigned.authority_issuance_id)
            if not assignments or len(set(assignments)) != 1:
                raise ValueError("authority_recovery_assignment_conflict")
            issuance_id = assignments[0]
            try:
                persisted = store.load_authority_binding(
                    self.context.workspace_identity, issuance_id,
                )
            except Exception as exc:
                raise ValueError("restart_reconstruction_persistence_error") from exc
            if (not isinstance(persisted, PersistedAuthorityBinding) or
                    persisted.authority_issuance_id != issuance_id):
                raise ValueError("authority_binding_persistence_corrupt")
            try:
                verified = verifier.verify(persisted.signed)
            except Exception as exc:
                raise ValueError("authority_binding_proof_invalid") from exc
            if verified is not True:
                raise ValueError("authority_binding_proof_invalid")
            link = self._artifact_link_adapter.resolve_verified_attestation(context)
            if type(link) is not VerifiedCredentialArtifactLink or link.credential_binding_id != binding.binding_id:
                raise ValueError("verified_attestation_artifact_link_invalid")
            payload = persisted.payload
            expected_operations = tuple(sorted(operation_ids))
            if (payload.workspace_identity != self.context.workspace_identity or
                    payload.application_id != identity.application_id or
                    payload.credential_binding_id != binding.binding_id or
                    payload.required_capabilities != required or
                    payload.attestation_artifact_id != link.artifact_id or
                    payload.attestation_artifact_digest != link.artifact_digest or
                    payload.authorized_operation_identities != expected_operations):
                raise ValueError("authority_recovery_binding_mismatch")
            values["issued_at"] = payload.authority_issued_at
            values["authority_id"] = ApplicationAuthority.expected_id(values)
            try:
                now = self.clock().astimezone(timezone.utc)
                expires = datetime.fromisoformat(binding.expires_at.replace("Z", "+00:00"))
            except (AttributeError, TypeError, ValueError) as exc:
                raise ValueError("credential_currentness_mismatch") from exc
            if expires <= now:
                raise ValueError("credential_expired")
            recovered = ApplicationAuthority._create(values, _marker=_AUTHORITY_MARKER)
            associated = self._authority_issuance_ids.get(recovered.authority_id)
            if associated is not None and associated != issuance_id:
                raise ValueError("application_authority_registry_conflict")
            existing = self._authorities.get(recovered.authority_id)
            if existing is not None:
                if type(existing) is not ApplicationAuthority or existing.to_dict() != recovered.to_dict():
                    raise ValueError("application_authority_registry_conflict")
                if associated is None:
                    self._authority_issuance_ids[recovered.authority_id] = issuance_id
                return existing
            self._authority_issuance_ids[recovered.authority_id] = issuance_id
            self._authorities[recovered.authority_id] = recovered
            return recovered

    def reconstruct_application_authority_after_restart(
        self, preview_id: str, revision: int, approval_id: str,
    ) -> Any:
        """Reconstruct one historical authority without live credential context."""
        from delivery_system.application_authority import ApplicationAuthority, _AUTHORITY_MARKER
        from delivery_system.application_identity import LogicalApplicationIdentity, operation_identity
        from delivery_system.attestation_persistence_store import AttestationArtifactAggregate
        from delivery_system.authority_binding_persistence import PersistedAuthorityBinding
        from delivery_system.restart_credential_verification import (
            RestartVerifiedCredentialEvidence,
            derive_restart_binding_id,
        )

        if not isinstance(approval_id, str) or not approval_id:
            raise ValueError("restart_reconstruction_invalid")
        with self._lock:
            store = self._authority_binding_store
            artifact_store = self._attestation_persistence_store
            verifier = self._authority_binding_verifier
            credential_verifier = self._restart_credential_verifier
            if not all((store is not None,
                        callable(getattr(store, "resolve_authority_binding_for_operation", None)),
                        callable(getattr(store, "load_authority_binding", None)),
                        verifier is not None,
                        callable(getattr(verifier, "verify", None)),
                        artifact_store is not None,
                        callable(getattr(artifact_store, "get_artifact_aggregate", None)),
                        credential_verifier is not None,
                        callable(getattr(credential_verifier, "verify", None)))):
                raise ValueError("restart_reconstruction_dependencies_required")
            preview, audit = self._resolve_audit(preview_id, revision)
            if approval_id != self._approval_id(audit):
                raise ValueError("restart_reconstruction_application_mismatch")
            try:
                approval = self.store.get_approval(self.context.workspace_identity, approval_id)
            except ValueError as exc:
                raise ValueError("restart_reconstruction_approval_missing") from exc
            if not self.store.validate_approval_current(approval):
                raise ValueError("restart_reconstruction_approval_invalid")
            if not _validate_approval_against_current_preview(
                approval, audit, preview, self.context.workspace_identity,
            ):
                raise ValueError("restart_reconstruction_approval_invalid")

            state = self.attestation_service._load_runtime_state(preview_id, revision)
            if not isinstance(state, tuple) or len(state) != 4:
                failures = getattr(state, "failures", ())
                first_failure = failures[0] if failures else None
                raise ValueError(getattr(first_failure, "code", "restart_reconstruction_current_state_invalid"))
            _sealed_context, state_audit, evidence, state_details = state
            if state_audit != audit or not isinstance(state_details, Mapping):
                raise ValueError("restart_reconstruction_current_state_invalid")
            subject = state_details.get("subject")
            if not isinstance(subject, str) or not subject:
                raise ValueError("restart_reconstruction_current_state_invalid")
            canonical = preview.get("canonical_payload")
            if not isinstance(canonical, Mapping):
                raise ValueError("restart_reconstruction_current_state_invalid")
            try:
                operations = _execution_operations(canonical)
                resolver = getattr(self.attestation_service, "_RuntimeAttestationOrchestrationService__resolver")
                required = tuple(sorted(resolver.resolve(tuple(dict(item) for item in operations))))
            except Exception as exc:
                raise ValueError("restart_reconstruction_capability_mismatch") from exc
            if not operations or not required:
                raise ValueError("restart_reconstruction_operation_mismatch")
            try:
                identity_values = {
                    "authority_id": "",
                    "workspace_identity": self.context.workspace_identity,
                    "repository_identity": canonical.get("repository_identity"),
                    "preview_id": preview_id,
                    "revision": revision,
                    "sealed_preview_digest": canonical.get("sealed_preview_digest"),
                    "plan_digest": canonical.get("plan_digest"),
                    "operation_set_digest": canonical.get("operation_set_digest"),
                    "remote_snapshot_digest": canonical.get("remote_snapshot_digest"),
                    "audit_id": audit.audit_id,
                    "audit_digest": audit.audit_digest,
                    "approval_id": approval.approval_id,
                    "approval_digest": self._approval_digest(approval),
                    "credential_binding_id": "binding-" + "0" * 64,
                    "credential_instance_id": "credential-instance-placeholder",
                    "issuer_id": "issuer-placeholder",
                    "credential_principal_identity": "principal-placeholder",
                    "github_subject_identity": subject,
                    "driver_identity": evidence.source_identity,
                    "remote_authority": canonical.get("remote_authority"),
                    "required_capabilities": required,
                }
                identity = LogicalApplicationIdentity.from_authority(identity_values)
                operation_ids = tuple(sorted(
                    operation_identity(identity.application_id, index, operation)
                    for index, operation in enumerate(operations)
                ))
            except Exception as exc:
                raise ValueError("restart_reconstruction_application_mismatch") from exc
            assignments = []
            for operation_id in operation_ids:
                try:
                    assigned = store.resolve_authority_binding_for_operation(
                        self.context.workspace_identity, operation_id,
                    )
                except Exception as exc:
                    raise ValueError("restart_reconstruction_persistence_error") from exc
                if assigned is None:
                    raise ValueError("restart_reconstruction_no_historical_issuance")
                if not isinstance(assigned, PersistedAuthorityBinding):
                    raise ValueError("restart_reconstruction_persistence_corrupt")
                assignments.append(assigned.authority_issuance_id)
            if not assignments:
                raise ValueError("restart_reconstruction_no_historical_issuance")
            if len(set(assignments)) != 1:
                raise ValueError("restart_reconstruction_assignment_conflict")
            issuance_id = assignments[0]
            try:
                persisted = store.load_authority_binding(
                    self.context.workspace_identity, issuance_id,
                )
            except Exception as exc:
                raise ValueError("restart_reconstruction_persistence_error") from exc
            if (not isinstance(persisted, PersistedAuthorityBinding) or
                    persisted.authority_issuance_id != issuance_id):
                raise ValueError("restart_reconstruction_persistence_corrupt")
            try:
                binding_valid = verifier.verify(persisted.signed)
            except Exception as exc:
                raise ValueError("restart_reconstruction_authority_binding_invalid") from exc
            if binding_valid is not True:
                raise ValueError("restart_reconstruction_authority_binding_invalid")
            payload = persisted.payload
            if payload.application_id != identity.application_id:
                raise ValueError("restart_reconstruction_application_mismatch")
            if payload.authorized_operation_identities != operation_ids:
                raise ValueError("restart_reconstruction_operation_mismatch")
            if payload.required_capabilities != required:
                raise ValueError("restart_reconstruction_capability_mismatch")
            try:
                aggregate = artifact_store.get_artifact_aggregate(
                    self.context.workspace_identity, payload.attestation_artifact_id,
                )
            except Exception as exc:
                raise ValueError("restart_reconstruction_artifact_unavailable") from exc
            if aggregate is None:
                raise ValueError("restart_reconstruction_artifact_missing")
            if type(aggregate) is not AttestationArtifactAggregate:
                raise ValueError("restart_reconstruction_artifact_invalid")
            if (aggregate.artifact.artifact_digest != payload.attestation_artifact_digest or
                    aggregate.binding_reference.artifact_id != aggregate.artifact.artifact_id or
                    aggregate.binding_reference.artifact_digest != aggregate.artifact.artifact_digest):
                raise ValueError("restart_reconstruction_artifact_mismatch")
            try:
                now = self.clock().astimezone(timezone.utc)
            except (AttributeError, TypeError, ValueError) as exc:
                raise ValueError("restart_reconstruction_clock_invalid") from exc
            try:
                verified_evidence = credential_verifier.verify(
                    aggregate.artifact, current_time=now,
                )
            except ValueError:
                raise
            except Exception as exc:
                raise ValueError("restart_reconstruction_credential_proof_invalid") from exc
            if type(verified_evidence) is not RestartVerifiedCredentialEvidence:
                raise ValueError("restart_reconstruction_credential_evidence_invalid")
            if (verified_evidence.workspace_identity != self.context.workspace_identity or
                    verified_evidence.artifact_id != payload.attestation_artifact_id or
                    verified_evidence.artifact_digest != payload.attestation_artifact_digest):
                raise ValueError("restart_reconstruction_artifact_mismatch")
            claims = verified_evidence.claims
            reference = aggregate.binding_reference
            if (claims.repository_identity != canonical.get("repository_identity") or
                    claims.github_subject_identity != subject or
                    claims.driver_identity != evidence.source_identity or
                    claims.remote_authority != canonical.get("remote_authority") or
                    claims.preview_id != preview_id or claims.revision != revision or
                    claims.operation_set_digest != canonical.get("operation_set_digest") or
                    claims.remote_snapshot_digest != canonical.get("remote_snapshot_digest") or
                    claims.evidence_digest != evidence.evidence_digest or
                    claims.evidence_digest != canonical.get("evidence_digest", claims.evidence_digest)):
                raise ValueError("restart_reconstruction_binding_mismatch")
            if ("issues:write" not in required or
                    not set(required).issubset(set(claims.granted_capabilities)) or
                    "issues:write" not in claims.granted_capabilities):
                raise ValueError("restart_reconstruction_capability_mismatch")
            if (
                reference.workspace_identity != self.context.workspace_identity
                or reference.artifact_id != payload.attestation_artifact_id
                or reference.artifact_digest != payload.attestation_artifact_digest
                or reference.repository_identity != claims.repository_identity
                or reference.github_subject_identity != claims.github_subject_identity
                or reference.driver_identity != claims.driver_identity
                or reference.remote_authority != claims.remote_authority
                or reference.preview_id != preview_id
                or reference.revision != revision
                or reference.plan_digest != canonical.get("plan_digest")
                or reference.sealed_preview_digest != canonical.get("sealed_preview_digest")
                or reference.operation_set_digest != claims.operation_set_digest
                or reference.remote_snapshot_digest != claims.remote_snapshot_digest
                or reference.audit_id != audit.audit_id
                or reference.audit_digest != audit.audit_digest
                or reference.evidence_id != evidence.evidence_id
                or reference.evidence_digest != claims.evidence_digest
                or reference.original_verified_at != aggregate.artifact.original_verified_at
                or (
                    reference.credential_principal_identity
                    and reference.credential_principal_identity != claims.credential_principal_identity
                )
                or (
                    reference.challenge_digest
                    and reference.challenge_digest != claims.challenge_digest
                )
            ):
                raise ValueError("restart_reconstruction_artifact_mismatch")
            binding_values = {
                "binding_id": payload.credential_binding_id,
                "workspace_identity": self.context.workspace_identity,
                "attestation_version": claims.attestation_version,
                "attestation_id": claims.attestation_id,
                "claims_digest": claims.claims_digest(),
                "credential_instance_id": claims.credential_instance_id,
                "issuer_id": claims.issuer_id,
                "key_id": claims.key_id,
                "algorithm": claims.signature_algorithm,
                "credential_class": claims.credential_class,
                "credential_principal_identity": claims.credential_principal_identity,
                "challenge_digest": claims.challenge_digest,
                "repository_identity": claims.repository_identity,
                "github_subject_identity": claims.github_subject_identity,
                "required_capabilities": required,
                "granted_capabilities": claims.granted_capabilities,
                "driver_identity": claims.driver_identity,
                "remote_authority": claims.remote_authority,
                "preview_id": claims.preview_id,
                "revision": claims.revision,
                "plan_digest": canonical.get("plan_digest"),
                "sealed_preview_digest": canonical.get("sealed_preview_digest"),
                "operation_set_digest": claims.operation_set_digest,
                "remote_snapshot_digest": claims.remote_snapshot_digest,
                "evidence_id": evidence.evidence_id,
                "evidence_digest": claims.evidence_digest,
                "audit_id": audit.audit_id,
                "audit_digest": audit.audit_digest,
                "source_verification_digest": claims.source_verification_digest,
                "issued_at": claims.issued_at,
                "expires_at": claims.expires_at,
                "verified_at": "",
            }
            if derive_restart_binding_id(binding_values) != payload.credential_binding_id:
                raise ValueError("restart_reconstruction_binding_mismatch")
            if (reference.binding_id != payload.credential_binding_id or
                    reference.artifact_id != payload.attestation_artifact_id or
                    reference.artifact_digest != payload.attestation_artifact_digest):
                raise ValueError("restart_reconstruction_artifact_mismatch")
            if (payload.workspace_identity != self.context.workspace_identity or
                    payload.credential_binding_id != derive_restart_binding_id(binding_values)):
                raise ValueError("restart_reconstruction_binding_mismatch")
            values = dict(identity_values)
            values.update({
                "credential_binding_id": payload.credential_binding_id,
                "credential_instance_id": claims.credential_instance_id,
                "issuer_id": claims.issuer_id,
                "credential_principal_identity": claims.credential_principal_identity,
                "github_subject_identity": claims.github_subject_identity,
                "driver_identity": claims.driver_identity,
                "remote_authority": claims.remote_authority,
                "granted_capabilities": claims.granted_capabilities,
                "issued_at": payload.authority_issued_at,
                "expires_at": claims.expires_at,
            })
            values["authority_id"] = ApplicationAuthority.expected_id(values)
            recovered = ApplicationAuthority._create(values, _marker=_AUTHORITY_MARKER)
            associated = self._authority_issuance_ids.get(recovered.authority_id)
            if associated is not None and associated != issuance_id:
                raise ValueError("restart_reconstruction_registry_conflict")
            existing = self._authorities.get(recovered.authority_id)
            provenance = _RestartAuthorityValidationProvenance.from_authority(
                recovered, issuance_id, claims=claims,
            )
            if existing is not None:
                if type(existing) is not ApplicationAuthority or existing.to_dict() != recovered.to_dict():
                    raise ValueError("restart_reconstruction_registry_conflict")
                if (self._live_credential_contexts.get((recovered.preview_id, recovered.revision)) is not None or
                        self._has_registered_live_binding(recovered.credential_binding_id)):
                    raise ValueError("restart_reconstruction_registry_conflict")
                existing_provenance = self._restart_authority_provenance.get(recovered.authority_id)
                if existing_provenance is not None and existing_provenance != provenance:
                    raise ValueError("restart_reconstruction_registry_conflict")
                if associated is None:
                    self._authority_issuance_ids[recovered.authority_id] = issuance_id
                self._restart_authority_provenance[recovered.authority_id] = provenance
                return existing
            if (self._live_credential_contexts.get((recovered.preview_id, recovered.revision)) is not None or
                    self._has_registered_live_binding(recovered.credential_binding_id)):
                raise ValueError("restart_reconstruction_registry_conflict")
            self._authority_issuance_ids[recovered.authority_id] = issuance_id
            self._restart_authority_provenance[recovered.authority_id] = provenance
            self._authorities[recovered.authority_id] = recovered
            return recovered

    def validate_application_authority(self, authority: Any) -> bool:
        from delivery_system.application_authority import ApplicationAuthority
        with self._lock:
            if type(authority) is not ApplicationAuthority:
                return False
            try:
                values = authority.to_dict()
                if ApplicationAuthority.expected_id(values) != values["authority_id"]:
                    return False
                if self._authorities.get(values["authority_id"]) is not authority:
                    return False
                issuance_id = self._authority_issuance_ids.get(values["authority_id"])
                if not isinstance(issuance_id, str):
                    return False
                restart_provenance = self._restart_authority_provenance.get(values["authority_id"])
                if restart_provenance is not None:
                    if (self._live_credential_contexts.get((values["preview_id"], values["revision"])) is not None or
                            self._has_registered_live_binding(values["credential_binding_id"])):
                        return False
                    if not restart_provenance.matches_authority(authority, issuance_id):
                        return False
                    persisted = None
                else:
                    persisted = self._authority_binding_store.load_authority_binding(
                        self.context.workspace_identity, issuance_id,
                    ) if self._authority_binding_store is not None else None
                    if persisted is None or persisted.authority_issuance_id != issuance_id:
                        return False
                preview, audit = self._resolve_audit(values["preview_id"], values["revision"])
                approval = self.store.get_approval(self.context.workspace_identity, values["approval_id"])
                if not self.store.validate_approval_current(approval):
                    return False
                if values["approval_digest"] != self._approval_digest(approval):
                    return False
                if values["audit_id"] != audit.audit_id or values["audit_digest"] != audit.audit_digest:
                    return False
                if restart_provenance is not None:
                    if (values["required_capabilities"] != restart_provenance.required_capabilities or
                            values["granted_capabilities"] != restart_provenance.granted_capabilities or
                            values["credential_binding_id"] != restart_provenance.credential_binding_id):
                        return False
                    granted_capabilities = restart_provenance.granted_capabilities
                else:
                    binding = self.attestation_service.resolve_registered_binding(values["credential_binding_id"])
                    if values["required_capabilities"] != tuple(binding.required_capabilities):
                        return False
                    if values["granted_capabilities"] != tuple(binding.granted_capabilities):
                        return False
                    granted_capabilities = tuple(binding.granted_capabilities)
                if not set(values["required_capabilities"]).issubset(granted_capabilities):
                    return False
                if "issues:write" not in values["required_capabilities"]:
                    return False
                expiry = datetime.fromisoformat(values["expires_at"].replace("Z", "+00:00"))
                if expiry <= self.clock().astimezone(timezone.utc):
                    return False
                canonical = preview["canonical_payload"]
                if restart_provenance is None:
                    if any(values[field] != getattr(binding, field, None) for field in (
                        "workspace_identity", "repository_identity", "preview_id", "revision", "plan_digest",
                        "sealed_preview_digest", "operation_set_digest", "remote_snapshot_digest",
                        "audit_id", "audit_digest", "credential_instance_id", "issuer_id",
                        "credential_principal_identity", "github_subject_identity", "driver_identity",
                        "remote_authority", "expires_at",
                    )):
                        return False
                identity = LogicalApplicationIdentity.from_authority(values)
                canonical_operations = _execution_operations(canonical)
                expected_operations = tuple(
                    operation_identity(identity.application_id, index, operation)
                    for index, operation in enumerate(canonical_operations)
                )
                expected_operations = tuple(sorted(expected_operations))
                if restart_provenance is None:
                    payload = persisted.payload
                    if (payload.workspace_identity != self.context.workspace_identity or
                            payload.application_id != identity.application_id or
                            payload.credential_binding_id != values["credential_binding_id"] or
                            payload.required_capabilities != tuple(values["required_capabilities"]) or
                            payload.authority_issued_at != values["issued_at"] or
                            payload.authorized_operation_identities != expected_operations):
                        return False
                return all(values[field] == canonical.get(field) for field in (
                    "workspace_identity", "repository_identity", "preview_id", "revision",
                    "sealed_preview_digest", "plan_digest", "operation_set_digest", "remote_snapshot_digest",
                ))
            except Exception:
                return False

    def resolve_application_authority(self, authority_id: str) -> Any:
        """Resolve and validate only the protected authority registered by this Runtime."""
        if not isinstance(authority_id, str) or not authority_id.strip():
            raise ValueError("application_authority_rejected")
        with self._lock:
            authority = self._authorities.get(authority_id)
            if authority is None:
                raise ValueError("application_authority_not_found")
            if not self.validate_application_authority(authority):
                raise ValueError("application_authority_rejected")
            return authority

    def resolve_application_provenance(self, authority_id: str) -> Any:
        return self.create_execution_context(authority_id).provenance

    def resolve_credential_continuity(self, authority_id: str) -> Any:
        from .application_identity import CredentialContinuityAnchor
        return CredentialContinuityAnchor.from_authority(self.resolve_application_authority(authority_id))

    def create_applier(self, execution_store: Any) -> Any:
        if not self._write_orchestration_enabled or self._write_executor_factory is None:
            raise ValueError("write_executor_required")
        if getattr(execution_store, "runtime_service", None) is not self:
            raise ValueError("applier_store_binding_invalid")
        from .applier import Applier
        capability = self._write_executor_factory(execution_store)
        return Applier._from_runtime(self, execution_store, capability)

    def validate_execution_context(self, context: Any) -> None:
        from .application_identity import CredentialContinuityAnchor, LogicalApplicationIdentity
        from .write_operations import normalize_write_operations
        if type(context) is not RuntimeApplicationExecutionContext:
            raise ValueError("runtime_context_owner_mismatch")
        with self._lock:
            entry = self._execution_context_registry.get(id(context))
            if entry is None or entry[0] is not context or context._service is not self:
                raise ValueError("runtime_context_owner_mismatch")
            authority, identity, anchor, operations, operation_digest, items, canonical_version, endpoint_bindings, remote_snapshot = entry[1]
            current = self._authorities.get(authority.authority_id)
            if current is None or not self.validate_application_authority(current):
                raise ValueError("runtime_authority_invalid")
            if current is not authority or context._authority is not authority:
                raise ValueError("runtime_context_owner_mismatch")
            if (context.identity.to_dict() != identity or context.continuity_anchor.to_dict() != anchor or
                context._expected_operations != operations or context.operation_set_digest != operation_digest or
                context._items != items or context._canonical_version != canonical_version or
                context._existing_endpoint_bindings != endpoint_bindings or context._remote_snapshot != remote_snapshot):
                raise ValueError("runtime_context_owner_mismatch")
            if (LogicalApplicationIdentity.from_authority(authority).to_dict() != identity or
                    CredentialContinuityAnchor.from_authority(authority).to_dict() != anchor or
                    tuple(normalize_write_operations(context._expected_operations)) != operations or
                    operation_digest != identity["application"]["operation_set_digest"]):
                raise ValueError("runtime_context_owner_mismatch")

    def validate_live_artifact(self, artifact: Any, context: Any, expected_kind: str) -> None:
        self.validate_execution_context(context)
        entry = self._live_artifact_registry.get(id(artifact))
        if (entry is None or entry[0] is not artifact or entry[1] != expected_kind or
                entry[2] is not context or artifact._live_context is not context or artifact.payload() != entry[3]):
            raise ValueError("runtime_authority_required")

    def create_execution_context(self, authority_id: str) -> Any:
        """Create the service-owned live foundation for new execution evidence."""
        from .application_identity import CredentialContinuityAnchor, LogicalApplicationIdentity
        from .receipts import AuthorityProvenance
        from .write_operations import normalize_write_operations
        authority = self.resolve_application_authority(authority_id)
        preview, _audit = self._resolve_audit(authority.preview_id, authority.revision)
        canonical_preview = preview.get("canonical_payload")
        if not isinstance(canonical_preview, Mapping):
            raise ValueError("operation_set_mismatch")
        operations = _execution_operations(canonical_preview)
        identity = LogicalApplicationIdentity.from_authority(authority)
        if canonical_preview.get("operation_set_digest") != identity.values()["operation_set_digest"]:
            raise ValueError("operation_set_mismatch")
        context = object.__new__(RuntimeApplicationExecutionContext)
        object.__setattr__(context, "_service", self)
        object.__setattr__(context, "_authority", authority)
        object.__setattr__(context, "identity", identity)
        object.__setattr__(context, "continuity_anchor", CredentialContinuityAnchor.from_authority(authority))
        object.__setattr__(context, "_expected_operations", operations)
        object.__setattr__(context, "_canonical_version", canonical_preview.get("canonical_version"))
        object.__setattr__(context, "_existing_endpoint_bindings", tuple(deepcopy(canonical_preview.get("existing_endpoint_bindings", []))))
        object.__setattr__(context, "_remote_snapshot", deepcopy(canonical_preview.get("remote_snapshot")))
        object.__setattr__(context, "operation_set_digest", identity.values()["operation_set_digest"])
        # ``items`` in the sealed payload is only the stable reference/index
        # projection.  Execution needs the approved sourced fields as well;
        # those live in the semantic payload and are snapshotted here so the
        # Applier never accepts a caller-provided item map.
        semantic_payload = canonical_preview.get("semantic_payload")
        items = semantic_payload.get("work_items", []) if isinstance(semantic_payload, Mapping) else []
        if not isinstance(items, list) or any(not isinstance(item, Mapping) for item in items):
            raise ValueError("sealed_item_projection_invalid")
        frozen_items = tuple(_freeze_runtime_value(item) for item in items)
        refs = [item.get("client_ref") for item in items]
        if any(type(ref) is not str or not ref for ref in refs) or len(set(refs)) != len(refs):
            raise ValueError("sealed_item_projection_invalid")
        sealed_refs = canonical_preview.get("items", [])
        if (not isinstance(sealed_refs, list) or
                [entry.get("client_ref") for entry in sealed_refs] != refs or
                any(not isinstance(entry, Mapping) or type(entry.get("item_id")) is not str or not entry["item_id"]
                    for entry in sealed_refs)):
            raise ValueError("sealed_item_projection_invalid")
        object.__setattr__(context, "_items", frozen_items)
        snapshot = (authority, identity.to_dict(), context.continuity_anchor.to_dict(), operations,
                    context.operation_set_digest, frozen_items, context._canonical_version,
                    context._existing_endpoint_bindings, context._remote_snapshot)
        self._execution_context_registry[id(context)] = (context, snapshot)
        object.__setattr__(context, "_provenance", AuthorityProvenance._from_live_authority(authority, context))
        return context

class RuntimeApplicationExecutionContext:
    """Ephemeral service-owned boundary for constructing new PC2-A evidence."""

    __slots__ = ("_service", "_authority", "identity", "continuity_anchor", "_expected_operations",
                 "operation_set_digest", "_provenance", "_items", "_canonical_version",
                 "_existing_endpoint_bindings", "_remote_snapshot")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise ValueError("runtime_context_internal_only")

    @property
    def _execution_context(self) -> "RuntimeApplicationExecutionContext":
        return self

    @property
    def provenance(self) -> Any:
        return self._provenance

    @property
    def expected_operations(self) -> tuple[dict[str, Any], ...]:
        return tuple({key: list(value) if isinstance(value, list) else value for key, value in operation.items()}
                     for operation in self._expected_operations)

    @property
    def canonical_items(self) -> tuple[dict[str, Any], ...]:
        return tuple(_thaw_runtime_value(item) for item in self._items)

    @property
    def service(self) -> Any:
        return self._service

    def to_dict(self) -> dict[str, Any]:
        return self._authority.to_dict()

    def __getattr__(self, name: str) -> Any:
        if name in {"authority_id", "workspace_identity", "repository_identity", "preview_id", "revision",
                    "sealed_preview_digest", "plan_digest", "operation_set_digest", "remote_snapshot_digest",
                    "audit_id", "audit_digest", "approval_id", "approval_digest", "credential_binding_id",
                    "credential_instance_id", "issuer_id", "credential_principal_identity", "github_subject_identity",
                    "driver_identity", "remote_authority", "required_capabilities", "granted_capabilities", "issued_at", "expires_at"}:
            return getattr(self._authority, name)
        raise AttributeError(name)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("runtime_execution_context_immutable")

    def revalidate_existing_endpoint(
        self,
        endpoint_ref: str,
        operation_kind: str | None = None,
        references: tuple[Any, ...] | list[Any] | None = None,
    ) -> None:
        """Invoke the composed read-only pre-mutation boundary when present.

        The default service has no live read adapter during offline execution;
        in that case the sealed V2 binding remains the only trusted source and
        the caller must still fail closed on any binding mismatch.
        """
        verifier = getattr(self._service, "_existing_endpoint_revalidator", None)
        if verifier is None:
            return
        if not callable(verifier):
            raise ValueError("existing_endpoint_revalidator_invalid")
        result = verifier(self, endpoint_ref, operation_kind, references)
        if result is False:
            raise ValueError("existing_endpoint_semantic_stale")

    def _require_current(self) -> None:
        self._service.validate_execution_context(self)

    def new_execution_state(self, **values: Any) -> Any:
        from .execution_state import ApplicationExecutionState
        self._require_current()
        state = ApplicationExecutionState(values.pop("application_id", self.identity.application_id), self.identity, continuity_anchor=self.continuity_anchor, _live_context=self, **values)
        self._service._live_artifact_registry[id(state)] = (state, "execution", self, state.payload())
        return state

    def continue_execution_state(self, historical: Any, **changes: Any) -> Any:
        from .execution_state import ApplicationExecutionState
        self._require_current()
        if type(historical) is not ApplicationExecutionState or not historical.verify_integrity():
            raise ValueError("historical_execution_invalid")
        if (historical.identity.to_dict() != self.identity.to_dict() or
                historical.application_id != self.identity.application_id or
                historical.continuity_anchor != self.continuity_anchor):
            raise ValueError("credential_continuity_mismatch")
        allowed = {"state", "next_operation_index", "owner_id", "current_attempt_id", "recovery_code",
                   "operation_receipt_refs", "updated_at", "completed_at"}
        if set(changes) - allowed:
            raise ValueError("application_binding_conflict")
        values = {name: getattr(historical, name) for name in allowed}
        values.update(changes)
        state = ApplicationExecutionState(historical.application_id, self.identity, continuity_anchor=self.continuity_anchor,
                                          _live_context=self, state=values["state"], next_operation_index=values["next_operation_index"],
                                          owner_id=values["owner_id"], current_attempt_id=values["current_attempt_id"],
                                          recovery_code=values["recovery_code"], operation_receipt_refs=values["operation_receipt_refs"],
                                          started_at=historical.started_at, updated_at=values["updated_at"], completed_at=values["completed_at"],
                                          orchestration_policy=historical.orchestration_policy)
        self._service._live_artifact_registry[id(state)] = (state, "execution", self, state.payload())
        return state

    def new_attempt(self, operation_index: int, **values: Any) -> Any:
        from .application_identity import operation_identity, request_identity
        from .execution_state import OperationAttemptState
        self._require_current()
        operation = self._expected_operations[operation_index]
        op_id = operation_identity(self.identity.application_id, operation_index, operation)
        attempt = OperationAttemptState(self.identity.application_id, op_id, operation_index, operation, self._provenance,
                                     self._authority.driver_identity, self._authority.remote_authority, request_identity(op_id),
                                     _live_context=self, identity=self.identity, **values)
        self._service._live_artifact_registry[id(attempt)] = (attempt, "attempt", self, attempt.payload())
        return attempt

    def continue_attempt(self, historical: Any, **changes: Any) -> Any:
        from .execution_state import OperationAttemptState
        from .application_identity import CredentialContinuityAnchor, operation_identity, request_identity
        self._require_current()
        if type(historical) is not OperationAttemptState or not historical.verify_integrity():
            raise ValueError("historical_attempt_invalid")
        expected = self._expected_operations[historical.operation_index] if historical.operation_index < len(self._expected_operations) else None
        if (historical.identity.to_dict() != self.identity.to_dict() or historical.application_id != self.identity.application_id or
                expected is None or historical.payload()["operation"] != expected or
                historical.operation_identity != operation_identity(self.identity.application_id, historical.operation_index, expected) or
                historical.request_identity != request_identity(historical.operation_identity)):
            raise ValueError("operation_attempt_binding_invalid")
        old = historical.authority_binding
        old_anchor = (CredentialContinuityAnchor("PRINCIPAL", (old.credential_principal_identity,))
                      if old.credential_principal_identity else CredentialContinuityAnchor("LEGACY_INSTANCE", (old.issuer_id, old.credential_instance_id)))
        if old_anchor != self.continuity_anchor or historical.driver_identity != self._authority.driver_identity or historical.remote_authority != self._authority.remote_authority:
            raise ValueError("credential_continuity_mismatch")
        allowed = {"state", "updated_at", "failure_code"}
        if set(changes) - allowed:
            raise ValueError("operation_attempt_binding_invalid")
        values = {name: getattr(historical, name) for name in allowed}; values.update(changes)
        attempt = OperationAttemptState(historical.application_id, historical.operation_identity, historical.operation_index,
                                        historical.operation, historical.authority_binding, historical.driver_identity,
                                        historical.remote_authority, historical.request_identity, values["state"],
                                        historical.started_at, values["updated_at"], self.identity, values["failure_code"], _live_context=self)
        self._service._live_artifact_registry[id(attempt)] = (attempt, "attempt", self, attempt.payload())
        return attempt

    def new_receipt(self, operation_index: int, remote_result: Mapping[str, Any], started_at: str, completed_at: str) -> Any:
        from .receipts import OperationReceipt
        self._require_current()
        receipt = OperationReceipt.create(self.identity, operation_index, self._expected_operations[operation_index], self, remote_result, started_at, completed_at)
        self._service._live_artifact_registry[id(receipt)] = (receipt, "operation_receipt", self, receipt.payload())
        return receipt

    def finalize_application_receipt(self, receipts: Any, started_at: str, completed_at: str) -> Any:
        from .receipts import ApplicationReceipt
        self._require_current()
        receipt = ApplicationReceipt.create(self.identity, self.operation_set_digest, self._expected_operations, receipts, started_at, completed_at)
        self._service._live_artifact_registry[id(receipt)] = (receipt, "application_receipt", self, receipt.payload())
        return receipt

    def new_application_receipt_from_refs(self, refs: Any, started_at: str, completed_at: str) -> Any:
        """Create a new live finalization candidate from already validated durable refs."""
        from .receipts import ApplicationReceipt
        self._require_current()
        receipt_id = "application-receipt-" + digest({
            "domain": "delivery-system:application-receipt-id:v1",
            "application_id": self.identity.application_id,
        }).split(":", 1)[1]
        receipt = ApplicationReceipt(receipt_id, self.identity.application_id, self.identity,
                                     self.operation_set_digest, tuple(refs), "Applied",
                                     started_at, completed_at, _live_context=self).with_digest()
        self._service._live_artifact_registry[id(receipt)] = (receipt, "application_receipt", self, receipt.payload())
        return receipt

    def _with_live_digest(self, artifact: Any, kind: str) -> Any:
        """Internal composition helper for digest-bearing CAS candidates."""
        candidate = artifact.with_digest()
        self._service._live_artifact_registry[id(candidate)] = (candidate, kind, self, candidate.payload())
        return candidate


class RuntimeApplicationStatusService:
    """Runtime-owned, read-only projection of durable application evidence."""

    _APPLICATION_ID = re.compile(r"\Aapplication-[0-9a-f]{64}\Z")
    _PREVIEW_BINDINGS = (
        "workspace_identity", "repository_identity", "preview_id", "revision",
        "sealed_preview_digest", "plan_digest", "operation_set_digest",
        "remote_snapshot_digest",
    )
    _PREVIEW_DIGEST_ERRORS = frozenset({
        "preview_identity_mismatch", "plan_digest_mismatch", "operation_set_digest_mismatch",
        "sealed_preview_digest_mismatch", "remote_snapshot_digest_mismatch",
        "repository_identity_mismatch", "sealed_preview_not_canonical", "sealed_preview_incomplete",
    })

    def __init__(self, context: RuntimeContext, store: Any, execution_store: Any) -> None:
        if (not isinstance(context, RuntimeContext) or store is None or execution_store is None or
                getattr(execution_store, "workspace_identity", None) != context.workspace_identity or
                not callable(getattr(execution_store, "get_execution_bootstrap", None)) or
                not callable(getattr(store, "_read_preview_revision_for_status", None))):
            raise ValueError("application_status_boundary_unavailable")
        self.context = context
        self.store = store
        self.execution_store = execution_store

    @classmethod
    def _validate_application_id(cls, application_id: Any) -> None:
        if type(application_id) is not str or cls._APPLICATION_ID.fullmatch(application_id) is None:
            raise ValueError("application_id_invalid")

    @staticmethod
    def _raise_state_error(exc: BaseException) -> None:
        code = str(exc)
        if code in {
            "application_not_found", "application_binding_conflict", "state_integrity_invalid",
            "application_replay_validation_required", "application_receipt_not_found",
        }:
            raise ValueError(code) from None
        raise ValueError("state_integrity_invalid") from None

    def _load_initial_records(self, application_id: str) -> Any:
        try:
            return self.execution_store.get_execution_bootstrap(application_id)
        except ValueError as exc:
            self._raise_state_error(exc)
        except (TypeError, KeyError, json.JSONDecodeError) as exc:
            self._raise_state_error(exc)

    @classmethod
    def _validate_preview_envelope(cls, preview: Any, values: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
        if not isinstance(preview, Mapping):
            raise ValueError("preview_digest_mismatch")
        canonical = preview.get("canonical_payload")
        request_id = preview.get("request_id")
        try:
            sealed = SealedPreview.from_dict(canonical)
            normalized = sealed.to_dict()
            if normalized != dict(canonical):
                raise ValueError("preview_digest_mismatch")
            if (preview.get("revision") != values["revision"] or
                    request_id != normalized["request_id"] or
                    type(request_id) is not str or not request_id):
                raise ValueError("preview_digest_mismatch")
            for field in cls._PREVIEW_BINDINGS:
                if normalized.get(field) != values[field]:
                    if field == "workspace_identity":
                        raise ValueError("application_binding_conflict")
                    raise ValueError("preview_digest_mismatch")
            unsigned = {key: value for key, value in normalized.items() if key != "sealed_preview_digest"}
            if normalized["sealed_preview_digest"] != digest(unsigned):
                raise ValueError("preview_digest_mismatch")
        except ValueError:
            raise
        except (TypeError, KeyError, json.JSONDecodeError):
            raise ValueError("preview_digest_mismatch") from None
        return normalized, request_id

    def _load_preview_operations(self, identity: Any) -> tuple[dict[str, Any], ...]:
        values = identity.values()
        try:
            preview = self.store._read_preview_revision_for_status(
                self.context.workspace_identity,
                values["preview_id"],
                values["revision"],
            )
        except ValueError as exc:
            if str(exc) == "preview crosses Workspace boundary":
                raise ValueError("application_binding_conflict") from None
            raise
        except (TypeError, KeyError, json.JSONDecodeError):
            raise ValueError("preview_digest_mismatch") from None

        canonical, request_id = self._validate_preview_envelope(preview, values)

        evidence_records: list[dict[str, object]] = []
        promotion = None
        if canonical.get("preview_level") in {PreviewLevel.REPOSITORY_AWARE.value, PreviewLevel.WRITE_ELIGIBLE.value}:
            try:
                evidence_records = self.store.get_evidence_records(
                    self.context.workspace_identity,
                    list(canonical["evidence_ids"]),
                )
                promotion = _reload_promotion(self.store, canonical, evidence_records)
            except ValueError:
                raise
            except (TypeError, KeyError, json.JSONDecodeError):
                raise ValueError("preview_digest_mismatch") from None

        try:
            normalized = _validate_preview_payload(
                canonical,
                request_id,
                values["preview_id"],
                values["revision"],
                values["plan_digest"],
                values["operation_set_digest"],
                values["remote_snapshot_digest"],
                values["repository_identity"],
                evidence_records,
                self.context.workspace_identity,
                promotion,
            )
        except ValueError as exc:
            code = str(exc)
            if code == "workspace_identity_mismatch":
                raise ValueError("application_binding_conflict") from None
            if code in self._PREVIEW_DIGEST_ERRORS:
                raise ValueError("preview_digest_mismatch") from None
            raise
        except (TypeError, KeyError, json.JSONDecodeError):
            raise ValueError("preview_digest_mismatch") from None

        for field in self._PREVIEW_BINDINGS:
            if normalized.get(field) != values[field]:
                if field == "workspace_identity":
                    raise ValueError("application_binding_conflict")
                raise ValueError("preview_digest_mismatch")
        try:
            # Preview digests cover canonical operations; execution envelopes
            # are a separate projection used for receipt identities.
            canonical_operations = normalized.get("operation_intents", [])
            op_digest = (
                digest(operation_set_digest_payload_v2(canonical_operations))
                if normalized.get("canonical_version") == "2"
                else digest(operation_set_digest_payload(canonical_operations))
            )
            if op_digest != values["operation_set_digest"]:
                raise ValueError("preview_digest_mismatch")
            operations = _execution_operations(normalized)
        except ValueError:
            raise
        except (TypeError, KeyError):
            raise ValueError("preview_digest_mismatch") from None
        return operations

    def _load_execution(self, application_id: str, operations: tuple[dict[str, Any], ...]) -> Any:
        try:
            return self.execution_store.get_execution(application_id, expected_operations=operations)
        except ValueError as exc:
            code = str(exc)
            if code == "application_replay_binding_invalid":
                raise ValueError("application_receipt_integrity_invalid") from None
            if code in {
                "application_not_found", "application_binding_conflict", "state_integrity_invalid",
                "application_replay_validation_required", "receipt_integrity_invalid",
                "application_receipt_integrity_invalid", "application_receipt_not_found",
                "operation_receipt_not_found", "receipt_binding_conflict", "workspace_mismatch",
            }:
                raise ValueError(code) from None
            raise
        except (TypeError, KeyError, json.JSONDecodeError):
            raise ValueError("state_integrity_invalid") from None

    @staticmethod
    def _plain(value: Any) -> Any:
        if isinstance(value, Mapping):
            return {key: RuntimeApplicationStatusService._plain(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [RuntimeApplicationStatusService._plain(item) for item in value]
        return value

    @staticmethod
    def _authority_binding_matches_execution(binding: Any, identity: Any,
                                             continuity_anchor: Any, application_id: str) -> bool:
        """Validate the authority semantics retained by the execution record."""
        try:
            values = identity.values()
            if (
                binding.application_id != application_id
                or binding.github_subject_identity != values["github_subject_identity"]
                or binding.driver_identity != values["driver_identity"]
                or binding.remote_authority != values["remote_authority"]
            ):
                return False
            if continuity_anchor.mode == "PRINCIPAL":
                return binding.credential_principal_identity == continuity_anchor.values[0]
            if continuity_anchor.mode == "LEGACY_INSTANCE":
                return (
                    binding.issuer_id == continuity_anchor.values[0]
                    and binding.credential_instance_id == continuity_anchor.values[1]
                )
            return False
        except (AttributeError, IndexError, KeyError, TypeError):
            return False

    @staticmethod
    def _validate_execution_state_invariants(state: Any, operations: tuple[dict[str, Any], ...]) -> None:
        try:
            from delivery_system.execution_store import _execution_timestamp

            started = _execution_timestamp(state.started_at)
            updated = _execution_timestamp(state.updated_at)
            if updated < started:
                raise ValueError("state_integrity_invalid")
            if state.completed_at is not None:
                completed_at = _execution_timestamp(state.completed_at)
                if completed_at < updated:
                    raise ValueError("state_integrity_invalid")
            completed = state.next_operation_index
            total = len(operations)
            if completed < 0 or completed > total or len(state.operation_receipt_refs) != completed:
                raise ValueError("state_integrity_invalid")

            if state.state == "Pending":
                valid = (completed == 0 and state.owner_id is None and state.current_attempt_id is None and
                         state.recovery_code is None and state.completed_at is None)
            elif state.state == "Applying":
                valid = (completed < total and type(state.owner_id) is str and bool(state.owner_id) and
                         type(state.current_attempt_id) is str and bool(state.current_attempt_id) and
                         state.recovery_code is None and state.completed_at is None)
            elif state.state == "PartiallyApplied":
                valid = (completed > 0 and state.owner_id is None and state.current_attempt_id is None and
                         state.recovery_code is None and state.completed_at is None)
            elif state.state in {"Failed", "Blocked", "OutcomeUnknown"}:
                valid = (completed < total and state.owner_id is None and
                         type(state.current_attempt_id) is str and bool(state.current_attempt_id) and
                         type(state.recovery_code) is str and bool(state.recovery_code) and
                         state.completed_at is None)
            elif state.state == "Applied":
                valid = (completed == total and state.owner_id is None and state.current_attempt_id is None and
                         state.recovery_code is None and state.completed_at is not None)
            else:
                valid = False
            if not valid:
                raise ValueError("state_integrity_invalid")
        except ValueError:
            raise ValueError("state_integrity_invalid") from None
        except (TypeError, AttributeError, OverflowError):
            raise ValueError("state_integrity_invalid") from None

    def _load_application_receipt(self, application_id: str) -> Any | None:
        try:
            return self.execution_store.get_application_receipt(application_id)
        except ValueError as exc:
            code = str(exc)
            if code == "application_receipt_not_found":
                return None
            if code == "application_binding_conflict":
                raise
            if code in {"application_receipt_integrity_invalid", "receipt_integrity_invalid", "receipt_binding_conflict", "workspace_mismatch"}:
                raise ValueError("application_receipt_integrity_invalid" if code != "application_binding_conflict" else code) from None
            raise ValueError("application_receipt_integrity_invalid") from None
        except (TypeError, KeyError, json.JSONDecodeError):
            raise ValueError("application_receipt_integrity_invalid") from None

    def _project_attempts(self, application_id: str, state: Any,
                          operations: tuple[dict[str, Any], ...]) -> list[dict[str, Any]]:
        completed = state.next_operation_index
        total = len(operations)
        if completed < 0 or completed > total or len(state.operation_receipt_refs) != completed:
            raise ValueError("state_integrity_invalid")
        if state.state in {"Applying", "Failed", "Blocked", "OutcomeUnknown"} and completed >= total:
            raise ValueError("state_integrity_invalid")
        if state.state in {"Pending", "PartiallyApplied", "Applied"} and state.current_attempt_id is not None:
            raise ValueError("state_integrity_invalid")

        attempts: list[dict[str, Any]] = []
        for index, operation in enumerate(operations):
            operation_id = operation_identity(application_id, index, operation)
            try:
                attempt = self.execution_store.get_attempt(application_id, operation_id)
            except ValueError as exc:
                code = str(exc)
                if code in {"operation_attempt_invalid", "operation_attempt_binding_invalid", "operation_attempt_binding_conflict", "attempt_integrity_invalid"}:
                    raise ValueError("attempt_integrity_invalid") from None
                if code != "operation_attempt_not_found":
                    raise
                if index < completed or (
                        index == completed and state.state in {"Applying", "Failed", "Blocked", "OutcomeUnknown"}):
                    raise
                continue
            if (index > completed or attempt.application_id != application_id or
                    attempt.identity.to_dict() != state.identity.to_dict() or
                    attempt.operation_identity != operation_id or
                    self._plain(attempt.operation) != self._plain(operation) or
                    attempt.request_identity != request_identity(operation_id) or
                    attempt.driver_identity != state.identity.values()["driver_identity"] or
                    attempt.remote_authority != state.identity.values()["remote_authority"] or
                    not self._authority_binding_matches_execution(
                        attempt.authority_binding, state.identity, state.continuity_anchor, application_id,
                    )):
                raise ValueError("attempt_integrity_invalid")
            if state.state == "Pending":
                raise ValueError("state_integrity_invalid")
            if index > completed:
                raise ValueError("state_integrity_invalid")
            expected_state = "Applied" if index < completed else state.state
            if attempt.state != expected_state or attempt.operation_index != index:
                raise ValueError("state_integrity_invalid")
            if index == completed and state.state in {"Applying", "Failed", "Blocked", "OutcomeUnknown"} and state.current_attempt_id != operation_id:
                raise ValueError("state_integrity_invalid")
            try:
                from delivery_system.execution_store import _execution_timestamp
                attempt_started = _execution_timestamp(attempt.started_at)
                attempt_updated = _execution_timestamp(attempt.updated_at)
                if attempt_updated < attempt_started or attempt_started < _execution_timestamp(state.started_at) or attempt_updated > _execution_timestamp(state.updated_at):
                    raise ValueError("attempt_integrity_invalid")
            except ValueError:
                raise ValueError("attempt_integrity_invalid") from None
            except (TypeError, AttributeError, OverflowError):
                raise ValueError("attempt_integrity_invalid") from None
            if attempt.state in {"Failed", "Blocked", "OutcomeUnknown"}:
                if type(attempt.failure_code) is not str or not attempt.failure_code:
                    raise ValueError("attempt_integrity_invalid")
            elif attempt.failure_code is not None:
                raise ValueError("attempt_integrity_invalid")
            attempts.append({
                "operation_identity": attempt.operation_identity,
                "operation_index": attempt.operation_index,
                "state": attempt.state,
                "attempt_digest": attempt.attempt_digest,
                "started_at": attempt.started_at,
                "updated_at": attempt.updated_at,
                "failure_code": attempt.failure_code,
            })
        return attempts

    def _project_operation_receipts(self, application_id: str, state: Any,
                                    operations: tuple[dict[str, Any], ...]) -> list[dict[str, Any]]:
        receipts: list[dict[str, Any]] = []
        for index in range(state.next_operation_index):
            operation_id = operation_identity(application_id, index, operations[index])
            try:
                receipt = self.execution_store.get_operation_receipt(application_id, operation_id)
            except ValueError as exc:
                if str(exc) in {"operation_receipt_invalid", "operation_receipt_binding_invalid", "receipt_binding_conflict", "workspace_mismatch"}:
                    raise ValueError("receipt_integrity_invalid") from None
                raise
            if (receipt.application_id != application_id or
                    receipt.identity.to_dict() != state.identity.to_dict() or
                    receipt.operation_identity != operation_id or
                    self._plain(receipt.canonical_operation) != self._plain(operations[index]) or
                    receipt.operation_index != index or
                    receipt.operation_receipt_id != state.operation_receipt_refs[index] or
                    receipt.request_identity != request_identity(operation_id) or
                    not self._authority_binding_matches_execution(
                        receipt.authority_binding, state.identity, state.continuity_anchor, application_id,
                    )):
                raise ValueError("receipt_integrity_invalid")
            try:
                from delivery_system.execution_store import _execution_timestamp
                receipt_started = _execution_timestamp(receipt.started_at)
                receipt_completed = _execution_timestamp(receipt.completed_at)
                if receipt_completed < receipt_started or receipt_started < _execution_timestamp(state.started_at) or receipt_completed > _execution_timestamp(state.updated_at):
                    raise ValueError("receipt_integrity_invalid")
            except ValueError:
                raise ValueError("receipt_integrity_invalid") from None
            except (TypeError, AttributeError, OverflowError):
                raise ValueError("receipt_integrity_invalid") from None
            receipts.append({
                "operation_receipt_id": receipt.operation_receipt_id,
                "receipt_digest": receipt.receipt_digest,
                "operation_index": receipt.operation_index,
                "started_at": receipt.started_at,
                "completed_at": receipt.completed_at,
            })
        for index in range(state.next_operation_index, len(operations)):
            operation_id = operation_identity(application_id, index, operations[index])
            try:
                self.execution_store.get_operation_receipt(application_id, operation_id)
            except ValueError as exc:
                code = str(exc)
                if code == "operation_receipt_not_found":
                    continue
                if code in {"operation_receipt_invalid", "operation_receipt_binding_invalid",
                            "receipt_binding_conflict", "workspace_mismatch", "receipt_integrity_invalid"}:
                    raise ValueError("receipt_integrity_invalid") from None
                raise ValueError("receipt_integrity_invalid") from None
            raise ValueError("receipt_integrity_invalid")
        return receipts

    @staticmethod
    def _project_application_receipt(receipt: Any, state: Any) -> dict[str, Any]:
        try:
            from delivery_system.execution_store import _execution_timestamp

            receipt_started = _execution_timestamp(receipt.started_at)
            receipt_completed = _execution_timestamp(receipt.completed_at)
            execution_started = _execution_timestamp(state.started_at)
            execution_completed = _execution_timestamp(state.completed_at)
            if (receipt_completed < receipt_started or receipt_started < execution_started or
                    receipt_completed > execution_completed):
                raise ValueError("application_receipt_integrity_invalid")
        except ValueError:
            raise ValueError("application_receipt_integrity_invalid") from None
        except (TypeError, AttributeError, OverflowError):
            raise ValueError("application_receipt_integrity_invalid") from None
        return {
            "application_receipt_id": receipt.application_receipt_id,
            "receipt_digest": receipt.receipt_digest,
            "status": receipt.status,
            "operation_receipt_count": len(receipt.operation_receipt_refs),
            "started_at": receipt.started_at,
            "completed_at": receipt.completed_at,
        }

    def get_status(self, application_id: str) -> dict[str, Any]:
        self._validate_application_id(application_id)
        identity = self._load_initial_records(application_id)
        values = identity.values()
        if identity.application_id != application_id:
            raise ValueError("application_binding_conflict")
        operations = self._load_preview_operations(identity)
        state = self._load_execution(application_id, operations)
        if state.application_id != application_id or state.identity.to_dict() != identity.to_dict():
            raise ValueError("application_binding_conflict")
        self._validate_execution_state_invariants(state, operations)
        application_receipt = self._load_application_receipt(application_id)

        operation_receipts = self._project_operation_receipts(application_id, state, operations)
        attempts = self._project_attempts(application_id, state, operations)
        receipt_projection = None
        if state.state == "Applied":
            if application_receipt is None:
                raise ValueError("application_receipt_not_found")
            receipt_projection = self._project_application_receipt(application_receipt, state)
        elif application_receipt is not None:
            raise ValueError("application_receipt_integrity_invalid")

        return {
            "application_id": application_id,
            "preview_id": values["preview_id"],
            "revision": values["revision"],
            "operation_set_digest": values["operation_set_digest"],
            "state": state.state,
            "next_operation_index": state.next_operation_index,
            "completed_operation_count": len(operation_receipts),
            "total_operation_count": len(operations),
            "attempt_count": len(attempts),
            "recovery_code": state.recovery_code,
            "application_receipt": receipt_projection,
            "operation_receipts": operation_receipts,
            "attempts": attempts,
            "started_at": state.started_at,
            "updated_at": state.updated_at,
            "completed_at": state.completed_at,
            "integrity_status": "verified",
        }


class ApplicationPostconditionObservation:
    """Runtime-owned, read-only observation of an OutcomeUnknown relationship."""

    _RELATIONSHIP_KINDS = {
        "add_sub_issue": "existing_parent",
        "add_dependency": "existing_dependency",
    }
    _DEFAULT_QUERY_SCOPE = {
        "api_origin": "https://api.github.com",
        "api_version": "2026-03-10",
        "issue_state": "all",
        "pull_request_filter": "pull_request_field_excluded",
        "relationships": ["sub_issues", "parent", "blocked_by", "blocking"],
        "pagination_protocol": "link-header",
        "budget_profile": "github-rest-offline-v1",
    }
    _REPOSITORY_FAILURES = frozenset({
        "repository_identity_mismatch", "requested_repository_mismatch", "remote_identity_unknown",
    })

    def __init__(self, context: RuntimeContext, store: Any, execution_store: Any,
                 driver: Any, trust_context: DriverTrustContext) -> None:
        if (
            not isinstance(context, RuntimeContext)
            or store is None
            or execution_store is None
            or driver is None
            or not isinstance(trust_context, DriverTrustContext)
            or getattr(execution_store, "workspace_identity", None) != context.workspace_identity
            or not callable(getattr(execution_store, "get_execution_bootstrap", None))
            or not callable(getattr(execution_store, "get_execution", None))
            or not callable(getattr(execution_store, "get_attempt", None))
            or not callable(getattr(execution_store, "get_operation_receipt", None))
            or not callable(getattr(execution_store, "get_application_receipt", None))
            or not callable(getattr(store, "_read_preview_revision_for_status", None))
            or not callable(getattr(driver, "read_repository", None))
        ):
            raise ValueError("application_reconciliation_boundary_unavailable")
        store_trust = getattr(store, "trust_context", None)
        if store_trust is not None and store_trust != trust_context:
            raise ValueError("application_reconciliation_boundary_unavailable")
        self.context = context
        self.store = store
        self.execution_store = execution_store
        self.driver = driver
        self.trust_context = trust_context
        self._status = RuntimeApplicationStatusService(context, store, execution_store)

    @staticmethod
    def _raise_remote_failure(failures: Sequence[Any]) -> None:
        if any(getattr(failure, "code", None) in ApplicationPostconditionObservation._REPOSITORY_FAILURES
               for failure in failures):
            raise ValueError("repository_identity_mismatch")
        raise ValueError("remote_observation_unavailable")

    def _query_scope(self) -> dict[str, object]:
        candidate = getattr(self.driver, "fixed_query_scope", None)
        if candidate is None:
            candidate = self._DEFAULT_QUERY_SCOPE
        if not isinstance(candidate, Mapping) or not candidate:
            raise ValueError("application_reconciliation_boundary_unavailable")
        try:
            return deepcopy(dict(candidate))
        except (TypeError, ValueError):
            raise ValueError("application_reconciliation_boundary_unavailable") from None

    @staticmethod
    def _load_operation_receipt(execution_store: Any, application_id: str, operation_id: str) -> Any:
        try:
            return execution_store.get_operation_receipt(application_id, operation_id)
        except ValueError as exc:
            code = str(exc)
            if code == "operation_receipt_not_found":
                raise ValueError("operation_receipt_not_found") from None
            if code in {
                "receipt_integrity_invalid", "operation_receipt_invalid",
                "operation_receipt_binding_invalid", "workspace_mismatch",
            }:
                raise ValueError("receipt_integrity_invalid") from None
            if code in {"receipt_binding_conflict", "application_binding_conflict"}:
                raise ValueError("reconciliation_correlation_invalid") from None
            raise ValueError("receipt_integrity_invalid") from None
        except (TypeError, KeyError, json.JSONDecodeError):
            raise ValueError("receipt_integrity_invalid") from None

    @staticmethod
    def _receipt_operand(receipt: Any, application_id: str, identity: Any,
                         operation_id: str, operation_index: int,
                         operation: Mapping[str, Any], repository: str) -> Any:
        if (
            receipt.application_id != application_id
            or receipt.identity.to_dict() != identity.to_dict()
            or receipt.operation_identity != operation_id
            or receipt.operation_index != operation_index
            or RuntimeApplicationStatusService._plain(receipt.canonical_operation) != dict(operation)
            or receipt.authority_binding.application_id != application_id
            or receipt.authority_binding.driver_identity != identity.values()["driver_identity"]
            or receipt.authority_binding.remote_authority != identity.values()["remote_authority"]
        ):
            raise ValueError("reconciliation_correlation_invalid")
        remote = receipt.remote_result
        if not isinstance(remote, Mapping) or set(remote) != {"result_kind", "result_identity", "result_digest", "result_payload"}:
            raise ValueError("receipt_integrity_invalid")
        payload = remote.get("result_payload")
        if isinstance(payload, Mapping) and payload.get("repository_identity") != repository:
            raise ValueError("repository_identity_mismatch")
        if remote.get("result_kind") != "github.create_issue.v1":
            raise ValueError("reconciliation_correlation_invalid")
        if (
            not isinstance(payload, Mapping)
            or set(payload) != {
                "repository_identity", "issue_number", "numeric_issue_id", "node_id",
                "executor_identity", "contract_version", "response_status",
            }
            or type(payload.get("issue_number")) is not int
            or payload["issue_number"] < 1
            or type(payload.get("numeric_issue_id")) is not str
            or not re.fullmatch(r"[1-9][0-9]{0,19}", payload["numeric_issue_id"])
            or type(payload.get("node_id")) is not str
            or not payload["node_id"].strip()
            or payload.get("executor_identity") != "delivery-system:github-rest-write-v1"
            or type(payload.get("contract_version")) is not str
            or payload.get("response_status") != 201
            or remote.get("result_identity") != "github-issue:" + payload["node_id"]
            or remote.get("result_digest") != digest(dict(payload))
        ):
            raise ValueError("receipt_integrity_invalid")
        from delivery_system.drivers.write_contract import RemoteIssueReference
        try:
            return RemoteIssueReference(
                payload["repository_identity"], payload["issue_number"],
                payload["numeric_issue_id"], payload["node_id"],
            )
        except (TypeError, ValueError, KeyError):
            raise ValueError("receipt_integrity_invalid") from None

    def _resolve_operands(self, identity: Any, operations: tuple[dict[str, Any], ...],
                          operation_index: int, operation: Mapping[str, Any]) -> tuple[Any, Any]:
        operands = operation.get("operands")
        if isinstance(operands, list) or any(isinstance(ref, str) and (ref.startswith("existing_issue:") or ref.startswith("work_item:")) for ref in operation.get("client_refs", [])):
            if operands is None:
                operands = []
                for ref in operation.get("client_refs", []):
                    if isinstance(ref, str) and ref.startswith("work_item:"):
                        operands.append({"endpoint_type": "work_item", "client_ref": ref.split(":", 1)[1]})
                    elif isinstance(ref, str) and ref.startswith("existing_issue:"):
                        operands.append({"endpoint_type": "existing_issue", "endpoint_ref": ref.split(":", 1)[1]})
            if operation.get("operation_kind") not in self._RELATIONSHIP_KINDS or len(operands) != 2:
                raise ValueError("reconciliation_correlation_invalid")
            try:
                preview = self.store._read_preview_revision_for_status(identity.values()["workspace_identity"], identity.values()["preview_id"], identity.values()["revision"])
                canonical = preview.get("canonical_payload", {})
                bindings = canonical.get("existing_endpoint_bindings", [])
                snapshot = canonical.get("remote_snapshot", {})
            except (TypeError, KeyError, ValueError):
                raise ValueError("reconciliation_correlation_invalid") from None
            resolved = []
            for operand in operands:
                if not isinstance(operand, Mapping):
                    raise ValueError("reconciliation_correlation_invalid")
                if operand.get("endpoint_type") == "work_item":
                    client_ref = operand.get("client_ref")
                    matches = [(index, candidate) for index, candidate in enumerate(operations[:operation_index]) if candidate.get("operation_kind") == "create_issue" and (candidate.get("endpoint", {}).get("client_ref") == client_ref or candidate.get("client_refs") == [client_ref])]
                    if len(matches) != 1:
                        raise ValueError("operation_receipt_not_found")
                    create_index, create_operation = matches[0]
                    create_id = operation_identity(identity.application_id, create_index, create_operation)
                    receipt = self._load_operation_receipt(self.execution_store, identity.application_id, create_id)
                    resolved.append(self._receipt_operand(receipt, identity.application_id, identity, create_id, create_index, create_operation, identity.values()["repository_identity"]))
                elif operand.get("endpoint_type") == "existing_issue":
                    binding = next((value for value in bindings if value.get("endpoint_ref") == operand.get("endpoint_ref")), None)
                    record = next((value for value in snapshot.get("issue_records", []) if isinstance(binding, Mapping) and value.get("issue_id") == binding.get("issue_id")), None)
                    if not isinstance(binding, Mapping) or not isinstance(record, Mapping) or digest(dict(record)) != binding.get("remote_record_digest"):
                        raise ValueError("reconciliation_correlation_invalid")
                    from delivery_system.drivers.write_contract import RemoteIssueReference
                    resolved.append(RemoteIssueReference(identity.values()["repository_identity"], record["issue_number"], str(record["numeric_issue_id"]), record["issue_id"]))
                else:
                    raise ValueError("reconciliation_correlation_invalid")
            if resolved[0] == resolved[1]:
                raise ValueError("reconciliation_correlation_invalid")
            return resolved[0], resolved[1]
        refs = operation.get("client_refs")
        if (
            operation.get("operation_kind") not in self._RELATIONSHIP_KINDS
            or not isinstance(refs, list)
            or len(refs) != 2
            or refs[0] == refs[1]
        ):
            raise ValueError("reconciliation_correlation_invalid")
        resolved = []
        for client_ref in refs:
            matches = [
                (index, candidate)
                for index, candidate in enumerate(operations[:operation_index])
                if candidate.get("operation_kind") == "create_issue"
                and candidate.get("client_refs") == [client_ref]
            ]
            if not matches:
                raise ValueError("operation_receipt_not_found")
            if len(matches) != 1:
                raise ValueError("reconciliation_correlation_invalid")
            create_index, create_operation = matches[0]
            create_id = operation_identity(identity.application_id, create_index, create_operation)
            receipt = self._load_operation_receipt(self.execution_store, identity.application_id, create_id)
            resolved.append(self._receipt_operand(
                receipt, identity.application_id, identity, create_id, create_index,
                create_operation, identity.values()["repository_identity"],
            ))
        if resolved[0] == resolved[1]:
            raise ValueError("reconciliation_correlation_invalid")
        return resolved[0], resolved[1]

    def _read_observation(self, repository: str, binding: RuntimeEvidenceBinding) -> Any:
        query_scope = self._query_scope()
        try:
            facts, failures = validate_driver_facts(
                self.driver, repository, query_scope,
                self.trust_context.trusted_driver_identity,
            )
        except Exception:
            raise ValueError("remote_observation_unavailable") from None
        if failures or facts is None:
            self._raise_remote_failure(failures)
        response = facts.response
        try:
            canonical = normalize_repository_identity(response.canonical_repository)
        except (TypeError, ValueError):
            raise ValueError("repository_identity_mismatch") from None
        if canonical != repository:
            raise ValueError("repository_identity_mismatch")
        for record in response.issue_records:
            if not isinstance(record, Mapping):
                raise ValueError("remote_observation_unavailable")
            try:
                if normalize_repository_identity(record.get("repository_identity")) != repository:
                    raise ValueError("repository_identity_mismatch")
            except (TypeError, ValueError) as exc:
                if str(exc) == "repository_identity_mismatch":
                    raise
                raise ValueError("repository_identity_mismatch") from None
        try:
            bound = bind_validated_facts(facts, binding, self.trust_context)
        except ValueError as exc:
            if str(exc) in {"remote_issue_repository_identity_mismatch", "repository_identity_mismatch"}:
                raise ValueError("repository_identity_mismatch") from None
            raise ValueError("remote_observation_unavailable") from None
        except (TypeError, KeyError):
            raise ValueError("remote_observation_unavailable") from None
        return bound.snapshot

    def _observe(self, application_id: str) -> dict[str, Any]:
        self._status._validate_application_id(application_id)
        identity = self._status._load_initial_records(application_id)
        if identity.application_id != application_id:
            raise ValueError("application_binding_conflict")
        values = identity.values()
        if values.get("remote_authority") != self.trust_context.remote_authority:
            raise ValueError("application_reconciliation_boundary_unavailable")
        operations = self._status._load_preview_operations(identity)
        state = self._status._load_execution(application_id, operations)
        if state.application_id != application_id or state.identity.to_dict() != identity.to_dict():
            raise ValueError("application_binding_conflict")
        self._status._validate_execution_state_invariants(state, operations)
        if state.state != "OutcomeUnknown":
            raise ValueError("application_reconciliation_state_invalid")
        if self._status._load_application_receipt(application_id) is not None:
            raise ValueError("application_receipt_integrity_invalid")
        self._status._project_attempts(application_id, state, operations)

        index = state.next_operation_index
        operation = operations[index]
        operation_id = operation_identity(application_id, index, operation)
        if state.current_attempt_id != operation_id:
            raise ValueError("attempt_integrity_invalid")
        try:
            attempt = self.execution_store.get_attempt(application_id, state.current_attempt_id)
        except ValueError as exc:
            code = str(exc)
            if code == "operation_attempt_not_found":
                raise ValueError("operation_attempt_not_found") from None
            raise ValueError("attempt_integrity_invalid") from None
        except (TypeError, KeyError, json.JSONDecodeError):
            raise ValueError("attempt_integrity_invalid") from None
        if (
            attempt.application_id != application_id
            or attempt.identity.to_dict() != identity.to_dict()
            or attempt.operation_index != index
            or attempt.operation_identity != operation_id
            or RuntimeApplicationStatusService._plain(attempt.operation) != operation
            or attempt.request_identity != request_identity(operation_id)
            or attempt.state != "OutcomeUnknown"
            or attempt.authority_binding.application_id != application_id
            or attempt.authority_binding.driver_identity != values["driver_identity"]
            or attempt.authority_binding.remote_authority != values["remote_authority"]
        ):
            raise ValueError("attempt_integrity_invalid")
        if operation["operation_kind"] == "create_issue":
            raise ValueError("reconciliation_operation_unsupported")
        self._status._project_operation_receipts(application_id, state, operations)
        first, second = self._resolve_operands(identity, operations, index, operation)
        repository = normalize_repository_identity(values["repository_identity"])
        snapshot = self._read_observation(
            repository,
            RuntimeEvidenceBinding(values["workspace_identity"], values["preview_id"], values["revision"]),
        )
        expected_kind = self._RELATIONSHIP_KINDS[operation["operation_kind"]]
        relationships = [
            (record.relationship_type, record.source_issue_id, record.target_issue_id)
            for record in snapshot.relationship_records
        ]
        if len(relationships) != len(set(relationships)):
            raise ValueError("remote_evidence_contradictory")
        expected = (expected_kind, first.node_id, second.node_id)
        relevant = [
            record for record in relationships
            if {record[1], record[2]} == {first.node_id, second.node_id}
        ]
        if any(record != expected for record in relevant):
            raise ValueError("remote_evidence_contradictory")
        issue_ids = {issue.issue_id for issue in snapshot.issue_records if issue.item_type == "issue"}
        if first.node_id not in issue_ids or second.node_id not in issue_ids:
            postcondition = "inconclusive"
        else:
            postcondition = "postcondition_confirmed" if expected in relevant else "postcondition_absent"
        observed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        return {
            "application_id": application_id,
            "operation_index": index,
            "operation_identity": operation_id,
            "operation_kind": operation["operation_kind"],
            "postcondition": postcondition,
            "causal_attribution": "not_established",
            "observed_at": observed_at,
            "state": "OutcomeUnknown",
            "integrity_status": "verified",
        }

    def observe(self, application_id: str) -> dict[str, Any]:
        try:
            return self._observe(application_id)
        except ValueError:
            raise
        except Exception:
            raise ValueError("state_integrity_invalid") from None
