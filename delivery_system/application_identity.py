"""Strict Runtime-owned identities for approved applications and operations."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from .canonical import digest
from .write_operations import normalize_write_operations

APPLICATION_ID_DOMAIN = "delivery-system:application:v1"
APPLICATION_BINDING_FIELDS = (
    "workspace_identity", "repository_identity", "preview_id", "revision",
    "sealed_preview_digest", "plan_digest", "operation_set_digest",
    "remote_snapshot_digest", "audit_id", "audit_digest", "approval_id",
    "approval_digest", "github_subject_identity", "driver_identity",
    "remote_authority", "required_capabilities",
)
ISSUANCE_FIELDS = ("authority_id", "issued_at", "expires_at")
CREDENTIAL_INSTANCE_FIELDS = ("credential_binding_id", "credential_instance_id", "issuer_id")


def _snapshot(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _snapshot(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_snapshot(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_snapshot(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    if isinstance(value, frozenset):
        return [_thaw(item) for item in sorted(value, key=repr)]
    return value


def _logical_values(source: Any) -> dict[str, Any]:
    values = source.to_dict() if hasattr(source, "to_dict") else source
    if not isinstance(values, Mapping) or not (set(APPLICATION_BINDING_FIELDS) <= set(values)):
        raise ValueError("application_binding_invalid")
    result: dict[str, Any] = {}
    for field in APPLICATION_BINDING_FIELDS:
        value = values[field]
        if field == "revision":
            if type(value) is not int or value < 1:
                raise ValueError("application_binding_invalid")
        elif field == "required_capabilities":
            if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple, set, frozenset)):
                raise ValueError("application_binding_invalid")
            capabilities = list(value)
            if any(type(item) is not str or not item for item in capabilities) or len(capabilities) != len(set(capabilities)):
                raise ValueError("application_binding_invalid")
            result[field] = tuple(sorted(capabilities))
            continue
        elif type(value) is not str or not value:
            raise ValueError("application_binding_invalid")
        result[field] = _snapshot(value)
    return result


class LogicalApplicationIdentity:
    """Validated, immutable logical application identity envelope."""

    __slots__ = ("_values", "_application_id")

    def __init__(self, values: Mapping[str, Any]) -> None:
        if set(values) != set(APPLICATION_BINDING_FIELDS):
            raise ValueError("application_identity_invalid")
        normalized = _logical_values(values)
        object.__setattr__(self, "_values", MappingProxyType({key: _snapshot(value) for key, value in normalized.items()}))
        object.__setattr__(self, "_application_id", "application-" + digest(self.to_dict()).split(":", 1)[1])

    @classmethod
    def from_authority(cls, authority: Any) -> "LogicalApplicationIdentity":
        return cls(_logical_values(authority))

    @classmethod
    def from_dict(cls, value: Any) -> "LogicalApplicationIdentity":
        if not isinstance(value, Mapping) or set(value) != {"domain", "application"}:
            raise ValueError("application_identity_invalid")
        if value["domain"] != APPLICATION_ID_DOMAIN or not isinstance(value["application"], Mapping):
            raise ValueError("application_identity_invalid")
        return cls(value["application"])

    @property
    def application_id(self) -> str:
        return self._application_id

    def values(self) -> dict[str, Any]:
        return _thaw(self._values)

    def to_dict(self) -> dict[str, Any]:
        return {"domain": APPLICATION_ID_DOMAIN, "application": self.values()}

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("application_identity_immutable")


class CredentialContinuityAnchor:
    """Runtime-derived continuity binding kept separate from application identity."""

    __slots__ = ("mode", "values")
    DOMAIN = "delivery-system:credential-continuity:v1"

    def __init__(self, mode: str, values: tuple[str, ...]) -> None:
        if mode not in {"PRINCIPAL", "LEGACY_INSTANCE"} or not values or any(type(value) is not str or not value for value in values):
            raise ValueError("credential_continuity_invalid")
        if (mode == "PRINCIPAL" and len(values) != 1) or (mode == "LEGACY_INSTANCE" and len(values) != 2):
            raise ValueError("credential_continuity_invalid")
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "values", tuple(values))

    @classmethod
    def from_authority(cls, authority: Any) -> "CredentialContinuityAnchor":
        from .application_authority import ApplicationAuthority
        if type(authority) is not ApplicationAuthority:
            raise ValueError("credential_continuity_invalid")
        if authority.credential_principal_identity:
            return cls("PRINCIPAL", (authority.credential_principal_identity,))
        return cls("LEGACY_INSTANCE", (authority.issuer_id, authority.credential_instance_id))

    @classmethod
    def from_dict(cls, value: Any) -> "CredentialContinuityAnchor":
        if not isinstance(value, Mapping) or set(value) != {"domain", "mode", "values"} or value["domain"] != cls.DOMAIN:
            raise ValueError("credential_continuity_invalid")
        values = value["values"]
        if not isinstance(values, (list, tuple)):
            raise ValueError("credential_continuity_invalid")
        return cls(value["mode"], tuple(values))

    def to_dict(self) -> dict[str, Any]:
        return {"domain": self.DOMAIN, "mode": self.mode, "values": list(self.values)}

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, CredentialContinuityAnchor) and self.mode == other.mode and self.values == other.values

    def __hash__(self) -> int:
        return hash((self.mode, self.values))


def application_identity_payload(authority: Any) -> dict[str, Any]:
    identity = authority if isinstance(authority, LogicalApplicationIdentity) else LogicalApplicationIdentity.from_authority(authority)
    return identity.to_dict()


def application_id(authority: Any) -> str:
    identity = authority if isinstance(authority, LogicalApplicationIdentity) else LogicalApplicationIdentity.from_authority(authority)
    return identity.application_id


def authority_is_compatible(authority: Any, identity: Any, continuity_anchor: Any = None) -> bool:
    try:
        if continuity_anchor is None:
            return False
        context = getattr(authority, "_execution_context", None)
        if context is None:
            return False
        context._require_current()
        authority = context._authority
        candidate = LogicalApplicationIdentity.from_authority(authority)
        expected = identity if isinstance(identity, LogicalApplicationIdentity) else LogicalApplicationIdentity.from_dict(identity)
        if candidate.application_id != expected.application_id or candidate.values() != expected.values():
            return False
        expected_anchor = continuity_anchor if isinstance(continuity_anchor, CredentialContinuityAnchor) else CredentialContinuityAnchor.from_dict(continuity_anchor)
        return CredentialContinuityAnchor.from_authority(authority) == expected_anchor
    except (KeyError, TypeError, ValueError):
        return False


def operation_identity(application_identifier: str, index: int, operation: Mapping[str, Any]) -> str:
    if type(index) is not int or index < 0 or type(application_identifier) is not str or not application_identifier:
        raise ValueError("operation_identity_invalid")
    try:
        canonical = normalize_write_operations([operation])[0]
    except (TypeError, ValueError, KeyError) as exc:
        raise ValueError("operation_identity_invalid") from exc
    return "operation-" + digest({
        "domain": "delivery-system:operation:v1",
        "application_id": application_identifier,
        "operation_index": index,
        "operation": canonical,
    }).split(":", 1)[1]


def request_identity(operation_identifier: str) -> str:
    if type(operation_identifier) is not str or not operation_identifier:
        raise ValueError("request_identity_invalid")
    return "application-request-" + digest({
        "domain": "delivery-system:application-request:v1",
        "operation_identity": operation_identifier,
    }).split(":", 1)[1]
