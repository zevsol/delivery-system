"""Call-local offline credential capability decision projection."""

from dataclasses import dataclass as _dataclass
from enum import Enum as _Enum
from typing import TYPE_CHECKING as _TYPE_CHECKING, Literal as _Literal

if _TYPE_CHECKING:
    from delivery_system.attestation import (
        AttestationBindingReference as _AttestationBindingReference,
        CredentialCapabilityRequest as _CredentialCapabilityRequest,
    )
    from delivery_system.attestation_restart import (
        RestartRevalidationService as _RestartRevalidationService,
    )


__all__ = (
    "OfflineCapabilityDecision",
    "OfflineCredentialCapabilityDecisionResult",
    "OfflineCredentialCapabilityDecisionService",
)

_PAIRING_ERROR = "offline_capability_decision_reason_pair_invalid"
_VALID_PAIRS = frozenset(
    {
        ("satisfied", "offline_capability_satisfied"),
        ("not_satisfied", "attestation_revalidation_expired"),
        ("not_satisfied", "attestation_revalidation_revoked"),
    }
)


class OfflineCapabilityDecision(str, _Enum):
    SATISFIED = "satisfied"
    NOT_SATISFIED = "not_satisfied"


@_dataclass(frozen=True, slots=True, kw_only=True)
class OfflineCredentialCapabilityDecisionResult:
    decision: OfflineCapabilityDecision
    reason_code: _Literal[
        "offline_capability_satisfied",
        "attestation_revalidation_expired",
        "attestation_revalidation_revoked",
    ]
    workspace_identity: str
    artifact_id: str
    requested_capabilities: tuple[str, ...]
    revalidation_attempt_id: str
    event_sequence: int
    revalidation_context_digest: str
    revalidated_at: str

    def __post_init__(self) -> None:
        decision = self.decision.value if isinstance(self.decision, OfflineCapabilityDecision) else None
        reason = self.reason_code if type(self.reason_code) is str else None
        if (decision, reason) not in _VALID_PAIRS:
            raise ValueError(_PAIRING_ERROR)

    def __str__(self) -> str:
        return (
            "OfflineCredentialCapabilityDecisionResult("
            f"decision={self.decision.value!r}, reason_code={self.reason_code!r})"
        )

    def __repr__(self) -> str:
        return self.__str__()


class OfflineCredentialCapabilityDecisionService:
    def __init__(self, *, revalidation_service: "_RestartRevalidationService") -> None:
        if revalidation_service is None or not callable(
            getattr(revalidation_service, "revalidate", None)
        ):
            raise TypeError("revalidation_service_required")
        self.__revalidation_service = revalidation_service

    def decide(
        self,
        *,
        workspace_identity: str,
        artifact_id: str,
        reference: "_AttestationBindingReference",
        request: "_CredentialCapabilityRequest",
    ) -> OfflineCredentialCapabilityDecisionResult:
        restart_result = self.__revalidation_service.revalidate(
            workspace_identity=workspace_identity,
            artifact_id=artifact_id,
            reference=reference,
            request=request,
        )
        sequenced_event = restart_result.event
        event = sequenced_event.event

        if event.outcome == "Successful" and event.failure_code is None:
            decision = OfflineCapabilityDecision.SATISFIED
            reason_code = "offline_capability_satisfied"
        elif event.outcome == "Failed" and event.failure_code == "attestation_revalidation_expired":
            decision = OfflineCapabilityDecision.NOT_SATISFIED
            reason_code = "attestation_revalidation_expired"
        elif event.outcome == "Failed" and event.failure_code == "attestation_revalidation_revoked":
            decision = OfflineCapabilityDecision.NOT_SATISFIED
            reason_code = "attestation_revalidation_revoked"

        return OfflineCredentialCapabilityDecisionResult(
            decision=decision,
            reason_code=reason_code,
            workspace_identity=event.workspace_identity,
            artifact_id=event.artifact_id,
            requested_capabilities=tuple(request.required_capabilities),
            revalidation_attempt_id=event.revalidation_attempt_id,
            event_sequence=sequenced_event.event_sequence,
            revalidation_context_digest=event.revalidation_context_digest,
            revalidated_at=event.revalidated_at,
        )
