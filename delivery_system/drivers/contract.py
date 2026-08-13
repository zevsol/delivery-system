"""Typed, read-only boundary for repository Driver implementations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final
from delivery_system.protocol import digest
from typing import Mapping, Protocol, Sequence


PermissionValue = bool | None


class DriverError(RuntimeError):
    """Stable, secret-free error from any Driver transport or adapter."""
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail if isinstance(detail, str) and len(detail) < 160 else ""


def normalize_repository_identity(repository: str) -> str:
    if not isinstance(repository, str):
        raise ValueError("repository_identity_invalid")
    parts = [part.strip() for part in repository.split("/")]
    if len(parts) != 2 or not all(parts):
        raise ValueError("repository_identity_invalid")
    return "/".join(part.lower() for part in parts)


@dataclass(frozen=True)
class RuntimeEvidenceBinding:
    """Runtime-owned identity supplied separately from Driver facts."""

    workspace_identity: str
    preview_id: str
    revision: int


@dataclass(frozen=True)
class DriverTrustContext:
    """Runtime-owned identity for a concrete Driver implementation."""

    trusted_driver_identity: str
    origin: str
    contract_version: str

    @property
    def remote_authority(self) -> str:
        return digest({
            "domain": "delivery-system:remote-authority:v1",
            "trusted_driver_identity": self.trusted_driver_identity,
            "origin": self.origin,
            "contract_version": self.contract_version,
        })

    def to_dict(self) -> dict[str, str]:
        return {
            "trusted_driver_identity": self.trusted_driver_identity,
            "origin": self.origin,
            "contract_version": self.contract_version,
            "remote_authority": self.remote_authority,
        }


class ValidatedRemoteFacts:
    """Immutable phase-one facts; only the validator can mint a binding ticket."""

    __slots__ = ("response", "canonical_remote_content_payload", "remote_content_digest", "_validation_ticket", "_sealed", "__weakref__")

    def __init__(self, response: "DriverReadResponse", canonical_remote_content_payload: Mapping[str, Any],
                 remote_content_digest: str, *, _validation_ticket: object | None = None) -> None:
        object.__setattr__(self, "response", response)
        object.__setattr__(self, "canonical_remote_content_payload", canonical_remote_content_payload)
        object.__setattr__(self, "remote_content_digest", remote_content_digest)
        object.__setattr__(self, "_validation_ticket", _validation_ticket)
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("validated_remote_facts_immutable")
        object.__setattr__(self, name, value)

    @property
    def validated(self) -> bool:
        return self._validation_ticket is not None


@dataclass(frozen=True)
class RuntimeEvidenceBindingResult:
    binding: RuntimeEvidenceBinding
    trust_context: DriverTrustContext
    evidence_record: Any
    snapshot: Any
    remote_snapshot_digest: str
    promotion: object


@dataclass(frozen=True)
class DriverReadResponse:
    """Untrusted remote facts; it contains no Runtime identity or Evidence ID."""

    requested_repository: str
    canonical_repository: str
    remote_repository_id: str
    authenticated_subject: str | None
    visibility: str | None
    permissions: Mapping[str, PermissionValue]
    capabilities: Mapping[str, PermissionValue]
    query_scope: Mapping[str, object]
    query_complete: bool
    pagination_complete: bool
    issue_records: Sequence[Mapping[str, object]]
    relationship_records: Sequence[Mapping[str, object]]
    evidence_material: Sequence[Mapping[str, object]]
    source_identity: str | None
    remote_content_digest: str
    remote_repository_node_id: str | None = None
    authenticated_user_id: str | None = None
    authenticated_user_node_id: str | None = None
    authenticated_login: str | None = None


class ReadOnlyDriver(Protocol):
    """Minimum logical Driver contract consumed by offline Preflight."""

    def read_repository(
        self, repository: str, query_scope: Mapping[str, object]
    ) -> DriverReadResponse:
        """Read repository identity, capabilities, and scoped work-item facts."""
