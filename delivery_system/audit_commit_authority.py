"""Ephemeral authority for semantically validated audit persistence."""

from __future__ import annotations

import weakref
from typing import Any, Mapping, Sequence

from delivery_system.canonical import digest


_AUTHORITY_DOMAIN = "audit-commit-authority-v1"
_MINT_KEY = object()
_authorities: dict[int, weakref.ReferenceType[AuditCommitAuthority]] = {}


def _remove_authority(object_id: int, reference: weakref.ReferenceType["AuditCommitAuthority"]) -> None:
    if _authorities.get(object_id) is reference:
        _authorities.pop(object_id, None)


class AuditCommitAuthority:
    """Opaque, process-local proof of completed semantic audit validation."""

    __slots__ = (
        "authority_domain", "audit_backend_scope", "workspace_identity", "audit_id",
        "audit_payload_digest", "preview_id", "revision", "audit_scope",
        "sealed_preview_digest", "plan_digest", "operation_set_digest",
        "remote_snapshot_digest", "audit_context_digest", "rule_registry_version",
        "rule_registry_digest", "evidence_bindings", "repository_identity",
        "remote_authority", "_sealed", "__weakref__",
    )

    def __new__(cls, *args: Any, **kwargs: Any) -> "AuditCommitAuthority":
        raise TypeError("AuditCommitAuthority must be minted by the Auditor")

    @classmethod
    def _mint(cls, key: object, **bindings: Any) -> "AuditCommitAuthority":
        if key is not _MINT_KEY:
            raise TypeError("AuditCommitAuthority must be minted by the Auditor")
        self = object.__new__(cls)
        for name in cls.__slots__:
            if name not in {"_sealed", "__weakref__"}:
                object.__setattr__(self, name, bindings[name])
        object.__setattr__(self, "_sealed", True)
        object_id = id(self)
        reference = weakref.ref(self, lambda ref, oid=object_id: _remove_authority(oid, ref))
        _authorities[object_id] = reference
        return self

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("AuditCommitAuthority is immutable")
        object.__setattr__(self, name, value)

    def __repr__(self) -> str:
        return (
            "AuditCommitAuthority(domain={!r}, workspace={!r}, preview={!r}, "
            "revision={!r}, audit={!r})"
        ).format(self.authority_domain, self.workspace_identity, self.preview_id, self.revision, self.audit_id)

    def __copy__(self) -> "AuditCommitAuthority":
        raise TypeError("AuditCommitAuthority cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> "AuditCommitAuthority":
        raise TypeError("AuditCommitAuthority cannot be copied")


def _audit_projection(audit: Any) -> dict[str, Any]:
    return {
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


def _evidence_bindings(records: Sequence[Mapping[str, Any]]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((str(record["evidence_id"]), str(record["evidence_digest"])) for record in records))


def _mint_audit_commit_authority(audit: Any, canonical: Mapping[str, Any], evidence: Sequence[Mapping[str, Any]], backend_scope: str) -> AuditCommitAuthority:
    return AuditCommitAuthority._mint(
        _MINT_KEY,
        authority_domain=_AUTHORITY_DOMAIN,
        audit_backend_scope=backend_scope,
        workspace_identity=audit.workspace_identity,
        audit_id=audit.audit_id,
        audit_payload_digest=audit.audit_payload_digest,
        preview_id=audit.preview_id,
        revision=audit.revision,
        audit_scope=audit.audit_scope,
        sealed_preview_digest=audit.sealed_preview_digest,
        plan_digest=audit.plan_digest,
        operation_set_digest=audit.operation_set_digest,
        remote_snapshot_digest=audit.remote_snapshot_digest,
        audit_context_digest=audit.audit_context_digest,
        rule_registry_version=audit.rule_registry_version,
        rule_registry_digest=audit.rule_registry_digest,
        evidence_bindings=_evidence_bindings(evidence),
        repository_identity=canonical.get("repository_identity"),
        remote_authority=canonical.get("remote_authority"),
    )


def _verify_authority_identity(authority: Any) -> AuditCommitAuthority:
    if not isinstance(authority, AuditCommitAuthority):
        raise ValueError("audit_commit_boundary_required")
    reference = _authorities.get(id(authority))
    if reference is None or reference() is not authority:
        raise ValueError("audit_commit_boundary_required")
    return authority


def _verify_candidate(audit: Any, authority: Any, canonical: Mapping[str, Any], evidence: Sequence[Mapping[str, Any]], backend_scope: str) -> None:
    authority = _verify_authority_identity(authority)
    if authority.authority_domain != _AUTHORITY_DOMAIN:
        raise ValueError("audit_commit_boundary_required")
    if getattr(audit.status, "value", None) != "Active":
        raise ValueError("audit_commit_boundary_required")
    if audit.audit_payload_digest != digest(_audit_projection(audit)) or not audit.verify_digest():
        raise ValueError("audit_commit_boundary_required")
    expected = {
        "audit_backend_scope": backend_scope,
        "workspace_identity": audit.workspace_identity,
        "audit_id": audit.audit_id,
        "audit_payload_digest": audit.audit_payload_digest,
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
        "evidence_bindings": _evidence_bindings(evidence),
        "repository_identity": canonical.get("repository_identity"),
        "remote_authority": canonical.get("remote_authority"),
    }
    for name, value in expected.items():
        if getattr(authority, name) != value:
            raise ValueError("audit_commit_boundary_required")
    canonical_bindings = {
        "workspace_identity": canonical.get("workspace_identity"),
        "preview_id": canonical.get("preview_id"),
        "revision": canonical.get("revision"),
        "audit_scope": canonical.get("preview_level"),
        "sealed_preview_digest": canonical.get("sealed_preview_digest"),
        "plan_digest": canonical.get("plan_digest"),
        "operation_set_digest": canonical.get("operation_set_digest"),
        "remote_snapshot_digest": canonical.get("remote_snapshot_digest"),
        "repository_identity": canonical.get("repository_identity"),
        "remote_authority": canonical.get("remote_authority"),
    }
    for name, value in canonical_bindings.items():
        if getattr(authority, name) != value:
            raise ValueError("audit_commit_boundary_required")
        if hasattr(audit, name) and getattr(audit, name) != value:
            raise ValueError("audit_commit_boundary_required")
