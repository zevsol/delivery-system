"""Audit and approval state records owned below Runtime orchestration."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime
from enum import Enum
from typing import Any, Mapping

from delivery_system.canonical import digest
from delivery_system.formal_preview import PreviewLevel


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
