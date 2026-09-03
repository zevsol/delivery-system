"""Runtime-owned immutable authority for a single approved application state."""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

from delivery_system.canonical import canonical_payload


_AUTHORITY_MARKER = object()
_FIELDS = (
    "authority_id", "workspace_identity", "repository_identity", "preview_id", "revision",
    "sealed_preview_digest", "plan_digest", "operation_set_digest", "remote_snapshot_digest",
    "audit_id", "audit_digest", "approval_id", "approval_digest", "credential_binding_id",
    "credential_instance_id", "issuer_id", "credential_principal_identity", "github_subject_identity",
    "driver_identity", "remote_authority", "required_capabilities", "granted_capabilities",
    "issued_at", "expires_at",
)


class ApplicationAuthority:
    """Protected, Runtime-created authority; it is not an execution operation."""

    __slots__ = (*_FIELDS, "__weakref__")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise ValueError("application_authority_internal_only")

    def __setattr__(self, name: str, value: Any) -> None:
        raise ValueError("application_authority_immutable")

    def __copy__(self) -> "ApplicationAuthority":
        raise ValueError("application_authority_copy_forbidden")

    def __deepcopy__(self, memo: dict[int, Any]) -> "ApplicationAuthority":
        raise ValueError("application_authority_copy_forbidden")

    @classmethod
    def _create(cls, values: Mapping[str, Any], *, _marker: object | None = None) -> "ApplicationAuthority":
        if _marker is not _AUTHORITY_MARKER or set(values) != set(_FIELDS):
            raise ValueError("application_authority_internal_only")
        authority = object.__new__(cls)
        for field in _FIELDS:
            object.__setattr__(authority, field, values[field])
        return authority

    @classmethod
    def _identity_payload(cls, values: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "domain": "delivery-system:application-authority:v1",
            "authority": {key: values[key] for key in _FIELDS if key not in {"authority_id", "issued_at"}},
        }

    @classmethod
    def expected_id(cls, values: Mapping[str, Any]) -> str:
        payload = canonical_payload(cls._identity_payload(values)).encode("utf-8")
        return "application-authority-" + hashlib.sha256(payload).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {field: getattr(self, field) for field in _FIELDS}

    def __repr__(self) -> str:
        return "<ApplicationAuthority protected>"
