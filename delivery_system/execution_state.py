"""Durable, binding-checked execution coordination records for PC2-A."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from .application_identity import CredentialContinuityAnchor, LogicalApplicationIdentity, operation_identity, request_identity
from .canonical import digest
from .receipts import AuthorityProvenance
from .write_operations import normalize_write_operations

APPLICATION_STATES = frozenset({"Pending", "Applying", "PartiallyApplied", "Failed", "Blocked", "OutcomeUnknown", "Applied"})
ATTEMPT_STATES = frozenset({"Pending", "Applying", "Failed", "Blocked", "OutcomeUnknown", "Applied"})

_ATTEMPT_TRANSITIONS = {
    "Pending": frozenset({"Applying", "Failed", "Blocked"}),
    "Applying": frozenset({"Applied", "Failed", "Blocked", "OutcomeUnknown"}),
    "Failed": frozenset(), "Blocked": frozenset(), "OutcomeUnknown": frozenset(), "Applied": frozenset(),
}
_APPLICATION_TRANSITIONS = {
    "Pending": frozenset({"Applying", "Failed", "Blocked"}),
    "Applying": frozenset({"PartiallyApplied", "Failed", "Blocked", "OutcomeUnknown"}),
    "PartiallyApplied": frozenset({"Applying", "Failed", "Blocked"}),
    "Failed": frozenset(), "Blocked": frozenset(), "OutcomeUnknown": frozenset(), "Applied": frozenset(),
}


def validate_attempt_transition(previous: "OperationAttemptState", candidate: "OperationAttemptState") -> None:
    if candidate.state not in _ATTEMPT_TRANSITIONS.get(previous.state, frozenset()):
        raise ValueError("attempt_state_transition_invalid")


def validate_application_transition(previous: "ApplicationExecutionState", candidate: "ApplicationExecutionState") -> None:
    if candidate.state not in _APPLICATION_TRANSITIONS.get(previous.state, frozenset()):
        raise ValueError("application_state_transition_invalid")
    if (previous.application_id != candidate.application_id or
            previous.identity.to_dict() != candidate.identity.to_dict() or
            previous.continuity_anchor != candidate.continuity_anchor or
            previous.started_at != candidate.started_at):
        raise ValueError("application_binding_conflict")
    if previous.completed_at is not None and candidate.completed_at != previous.completed_at:
        raise ValueError("application_coordination_invalid")
    if (previous.next_operation_index != len(previous.operation_receipt_refs) or
            candidate.next_operation_index != len(candidate.operation_receipt_refs)):
        raise ValueError("application_progress_invalid")
    progress_delta = candidate.next_operation_index - previous.next_operation_index
    if progress_delta not in (0, 1):
        raise ValueError("application_progress_invalid")
    if previous.state != "Applying" or candidate.state != "PartiallyApplied":
        if progress_delta != 0 or candidate.operation_receipt_refs != previous.operation_receipt_refs:
            raise ValueError("application_progress_invalid")
    if progress_delta == 0 and candidate.operation_receipt_refs != previous.operation_receipt_refs:
        raise ValueError("application_progress_invalid")
    if progress_delta == 1 and candidate.operation_receipt_refs[:-1] != previous.operation_receipt_refs:
        raise ValueError("application_progress_invalid")

    if previous.state in {"Pending", "PartiallyApplied"}:
        if previous.owner_id is not None or previous.current_attempt_id is not None:
            raise ValueError("application_coordination_invalid")
        if candidate.state == "Applying" and (not candidate.owner_id or not candidate.current_attempt_id):
            raise ValueError("application_coordination_invalid")
        if candidate.state in {"Failed", "Blocked"} and (candidate.owner_id is not None or candidate.current_attempt_id is not None):
            raise ValueError("application_coordination_invalid")
    elif previous.state == "Applying":
        if candidate.state == "PartiallyApplied":
            if progress_delta != 1 or candidate.owner_id is not None or candidate.current_attempt_id is not None:
                raise ValueError("application_coordination_invalid")
        elif candidate.state in {"Failed", "Blocked", "OutcomeUnknown"}:
            if (progress_delta != 0 or candidate.operation_receipt_refs != previous.operation_receipt_refs or
                    candidate.current_attempt_id != previous.current_attempt_id or
                    candidate.owner_id not in {None, previous.owner_id}):
                raise ValueError("application_coordination_invalid")


def _text(value: Any, code: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(code)
    return value


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    if isinstance(value, frozenset):
        return {_thaw(item) for item in value}
    return value


@dataclass(frozen=True)
class ApplicationExecutionState:
    application_id: str
    identity: Mapping[str, Any]
    state: str
    next_operation_index: int
    owner_id: str | None
    current_attempt_id: str | None
    recovery_code: str | None
    operation_receipt_refs: tuple[str, ...] = field(default_factory=tuple)
    started_at: str = ""
    updated_at: str = ""
    completed_at: str | None = None
    continuity_anchor: CredentialContinuityAnchor | Mapping[str, Any] | None = None
    state_digest: str = ""
    _live_context: Any = None

    def __post_init__(self) -> None:
        identity = self.identity if isinstance(self.identity, LogicalApplicationIdentity) else LogicalApplicationIdentity.from_dict(self.identity)
        anchor = self.continuity_anchor if isinstance(self.continuity_anchor, CredentialContinuityAnchor) else CredentialContinuityAnchor.from_dict(self.continuity_anchor)
        if self.application_id != identity.application_id or self.state not in APPLICATION_STATES or type(self.next_operation_index) is not int or self.next_operation_index < 0:
            raise ValueError("application_state_invalid")
        if type(self.operation_receipt_refs) not in (tuple, list) or any(type(ref) is not str or not ref for ref in self.operation_receipt_refs) or len(set(self.operation_receipt_refs)) != len(self.operation_receipt_refs):
            raise ValueError("application_state_invalid")
        if not self.started_at or not self.updated_at:
            raise ValueError("application_state_invalid")
        if self.state in {"Pending", "PartiallyApplied"} and (self.owner_id is not None or self.current_attempt_id is not None):
            raise ValueError("application_coordination_invalid")
        object.__setattr__(self, "identity", identity)
        object.__setattr__(self, "operation_receipt_refs", tuple(self.operation_receipt_refs))
        object.__setattr__(self, "continuity_anchor", anchor)

    def payload(self) -> dict[str, Any]:
        return {"application_id": self.application_id, "identity": self.identity.to_dict(), "state": self.state,
                "next_operation_index": self.next_operation_index, "owner_id": self.owner_id,
                "current_attempt_id": self.current_attempt_id, "recovery_code": self.recovery_code,
                "operation_receipt_refs": list(self.operation_receipt_refs), "started_at": self.started_at,
                "updated_at": self.updated_at, "completed_at": self.completed_at,
                "continuity_anchor": self.continuity_anchor.to_dict()}

    def with_digest(self) -> "ApplicationExecutionState":
        return ApplicationExecutionState(**{**self.__dict__, "state_digest": digest(self.payload())})

    def verify_integrity(self) -> bool:
        return bool(self.state_digest) and self.state_digest == digest(self.payload())


@dataclass(frozen=True)
class OperationAttemptState:
    application_id: str
    operation_identity: str
    operation_index: int
    operation: Mapping[str, Any]
    authority_binding: AuthorityProvenance
    driver_identity: str
    remote_authority: str
    request_identity: str
    state: str
    started_at: str
    updated_at: str
    identity: Mapping[str, Any]
    failure_code: str | None = None
    attempt_digest: str = ""
    _live_context: Any = None

    def __post_init__(self) -> None:
        identity = self.identity if isinstance(self.identity, LogicalApplicationIdentity) else LogicalApplicationIdentity.from_dict(self.identity)
        operation = normalize_write_operations([_thaw(self.operation)])[0]
        provenance = AuthorityProvenance.from_value(self.authority_binding)
        if self.application_id != identity.application_id or type(self.operation_index) is not int or self.operation_index < 0 or self.operation_identity != operation_identity(self.application_id, self.operation_index, operation) or self.request_identity != request_identity(self.operation_identity):
            raise ValueError("operation_attempt_binding_invalid")
        if self.driver_identity != provenance.driver_identity or self.remote_authority != provenance.remote_authority:
            raise ValueError("operation_attempt_binding_invalid")
        if self.state not in ATTEMPT_STATES or not self.started_at or not self.updated_at:
            raise ValueError("operation_attempt_invalid")
        object.__setattr__(self, "identity", identity)
        object.__setattr__(self, "operation", _freeze(operation))
        object.__setattr__(self, "authority_binding", provenance)

    def payload(self) -> dict[str, Any]:
        return {"application_id": self.application_id, "operation_identity": self.operation_identity,
                "operation_index": self.operation_index, "operation": _thaw(self.operation),
                "authority_binding": self.authority_binding.to_dict(), "driver_identity": self.driver_identity,
                "remote_authority": self.remote_authority, "request_identity": self.request_identity,
                "state": self.state, "started_at": self.started_at, "updated_at": self.updated_at,
                "identity": self.identity.to_dict(), "failure_code": self.failure_code}

    def with_digest(self) -> "OperationAttemptState":
        return OperationAttemptState(**{**self.__dict__, "attempt_digest": digest(self.payload())})

    def verify_integrity(self) -> bool:
        return bool(self.attempt_digest) and self.attempt_digest == digest(self.payload())
