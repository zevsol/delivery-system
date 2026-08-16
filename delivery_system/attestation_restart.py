"""Offline restart revalidation orchestration for persisted attestations."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, fields
from datetime import datetime, timezone
import calendar
import re
import threading
import unicodedata
from typing import Any, Literal

from delivery_system.attestation import (
    AttestationContractError,
    CredentialCapabilityAttestationClaims,
    CredentialCapabilityRequest,
    RevocationReader,
    RevocationStatus,
)
from delivery_system.attestation_persistence import (
    AttestationBindingReference,
    AttestationRevalidationEvent,
    PersistedAttestationArtifact,
    RevalidationAttempt,
    RevalidationAttemptBoundary,
)
from delivery_system.attestation_persistence_store import (
    AttestationArtifactAggregate,
    AttestationPersistenceStore,
    SequencedAttestationRevalidationEvent,
    StoreContractError,
)
from delivery_system.protocol import digest


_SERVICE_CODES = frozenset({
    "attestation_restart_identity_mismatch",
    "attestation_restart_attempt_invalid",
    "attestation_restart_context_invalid",
    "attestation_restart_revocation_unknown",
    "attestation_restart_revocation_unavailable",
    "attestation_restart_revocation_invalid",
    "attestation_restart_clock_invalid",
})
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ARTIFACT_ID_RE = re.compile(r"^artifact-[0-9a-f]{64}$")
_REFERENCE_ID_RE = re.compile(r"^binding-reference-[0-9a-f]{64}$")
_BINDING_ID_RE = re.compile(r"^binding-[0-9a-f]{64}$")
_TIMESTAMP_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?Z$"
)

_CONTEXT_DOMAIN = "delivery-system:attestation-revalidation-context:v1"
_PAYLOAD_VERSION = "1"
_CLAIMS_DOMAIN = "delivery-system:credential-capability-attestation:v1"
_ARTIFACT_CONTRACT_VERSION = "offline-attestation-artifact-v1"
_REFERENCE_CONTRACT_VERSION = "attestation-binding-reference-v1"
_ARTIFACT_CONTENT_DOMAIN = "delivery-system:attestation-artifact-content:v1"
_REFERENCE_CONTENT_DOMAIN = "delivery-system:attestation-binding-reference-content:v1"
_CLAIMS_FIELDS = frozenset({
    "attestation_version", "attestation_id", "issuer_id", "key_id",
    "signature_algorithm", "credential_class", "credential_instance_id",
    "github_subject_identity", "repository_identity", "granted_capabilities",
    "driver_identity", "remote_authority", "preview_id", "revision",
    "operation_set_digest", "remote_snapshot_digest", "evidence_digest",
    "issued_at", "expires_at", "nonce", "source_verification_digest",
})
_ARTIFACT_FIELDS = frozenset({
    "artifact_contract_version", "artifact_id", "workspace_identity",
    "attestation_id", "claims_payload", "detached_proof", "claims_digest",
    "artifact_digest", "original_verified_at", "created_at",
})
_REFERENCE_FIELDS = frozenset({field.name for field in fields(AttestationBindingReference)})
_CONTEXT_ARTIFACT_FIELDS = frozenset({
    "artifact_contract_version", "artifact_digest", "artifact_id",
    "attestation_id", "claims_digest", "claims_payload", "created_at",
    "original_verified_at", "workspace_identity",
})
_CONTEXT_ROOT_FIELDS = frozenset({
    "domain", "payload_version", "workspace_identity", "artifact", "binding_reference",
})
_REQUEST_CROSSWALK = (
    "repository_identity", "github_subject_identity", "driver_identity",
    "remote_authority", "preview_id", "revision", "operation_set_digest",
    "remote_snapshot_digest", "evidence_digest",
)
_REFERENCE_CROSSWALK = (
    "repository_identity", "github_subject_identity", "driver_identity",
    "remote_authority", "preview_id", "revision", "operation_set_digest",
    "remote_snapshot_digest", "evidence_digest",
)


class RestartRevalidationError(Exception):
    """Safe, stable error for the future Slice D Service boundary."""

    _SUPPORTED_CODES = _SERVICE_CODES

    def __init__(
        self,
        code: Literal[
            "attestation_restart_identity_mismatch",
            "attestation_restart_attempt_invalid",
            "attestation_restart_context_invalid",
            "attestation_restart_revocation_unknown",
            "attestation_restart_revocation_unavailable",
            "attestation_restart_revocation_invalid",
            "attestation_restart_clock_invalid",
        ],
    ) -> None:
        if type(code) is not str or code not in self._SUPPORTED_CODES:
            raise ValueError("unsupported Restart Revalidation Service error code")
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return f"<RestartRevalidationError code={self.code!r}>"


@dataclass(frozen=True, slots=True)
class RestartRevalidationResult:
    outcome: Literal["Successful", "Failed"]
    failure_code: str | None
    result_digest: str | None
    event: SequencedAttestationRevalidationEvent


def _service_error(code: str) -> RestartRevalidationError:
    return RestartRevalidationError(code=code)


def _has_fields(value: Any, expected: frozenset[str]) -> bool:
    declared = getattr(type(value), "__dataclass_fields__", None)
    if type(declared) is not dict or frozenset(declared) != expected:
        return False
    return all(hasattr(value, name) for name in expected)


def _canonical_timestamp(value: Any) -> bool:
    if type(value) is not str:
        return False
    match = _TIMESTAMP_RE.fullmatch(value)
    if match is None:
        return False
    year, month, day, hour, minute, second, fraction = match.groups()
    year_i, month_i, day_i = int(year), int(month), int(day)
    hour_i, minute_i, second_i = int(hour), int(minute), int(second)
    if not 1 <= year_i <= 9999 or not 1 <= month_i <= 12:
        return False
    if not 1 <= day_i <= calendar.monthrange(year_i, month_i)[1]:
        return False
    if not 0 <= hour_i <= 23 or not 0 <= minute_i <= 59 or not 0 <= second_i <= 59:
        return False
    microsecond = int((fraction or "").ljust(6, "0")) if fraction else 0
    parsed = datetime(year_i, month_i, day_i, hour_i, minute_i, second_i, microsecond, tzinfo=timezone.utc)
    timespec = "microseconds" if fraction is not None else "seconds"
    return parsed.isoformat(timespec=timespec).replace("+00:00", "Z") == value


def _valid_text(value: Any) -> bool:
    if type(value) is not str or not value:
        return False
    normalized = unicodedata.normalize("NFC", value).strip()
    return bool(normalized) and value == normalized and not any(
        ord(char) < 0x20 or ord(char) == 0x7F for char in value
    )


def _valid_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST_RE.fullmatch(value) is not None


def _valid_id(value: Any, pattern: re.Pattern[str]) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _json_compatible(value: Any) -> bool:
    if type(value) is str or type(value) is int or type(value) is bool or value is None:
        return True
    if type(value) is list:
        return all(_json_compatible(item) for item in value)
    if type(value) is dict:
        normalized_keys: set[str] = set()
        for key, item in value.items():
            if type(key) is not str:
                return False
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized_keys or not _json_compatible(item):
                return False
            normalized_keys.add(normalized_key)
        return True
    return False


def _claims_shape_is_valid(claims: Any) -> bool:
    if type(claims) is not CredentialCapabilityAttestationClaims:
        return False
    if not _has_fields(claims, _CLAIMS_FIELDS):
        return False
    for field in _CLAIMS_FIELDS - {"granted_capabilities", "revision"}:
        if not _valid_text(getattr(claims, field)):
            return False
    if claims.attestation_version != "1" or not _valid_id(claims.attestation_id, re.compile(r"^attestation-[0-9a-f]{64}$")):
        return False
    if type(claims.revision) is not int or claims.revision < 1:
        return False
    if type(claims.granted_capabilities) is not tuple or not claims.granted_capabilities:
        return False
    if any(not _valid_text(capability) for capability in claims.granted_capabilities):
        return False
    if len(set(claims.granted_capabilities)) != len(claims.granted_capabilities):
        return False
    if tuple(sorted(claims.granted_capabilities)) != claims.granted_capabilities:
        return False
    if not all(_valid_digest(getattr(claims, field)) for field in (
        "remote_authority", "operation_set_digest", "remote_snapshot_digest",
        "evidence_digest", "source_verification_digest",
    )):
        return False
    return _canonical_timestamp(claims.issued_at) and _canonical_timestamp(claims.expires_at)


def _artifact_shape_is_valid(artifact: Any) -> bool:
    if type(artifact) is not PersistedAttestationArtifact or not _has_fields(artifact, _ARTIFACT_FIELDS):
        return False
    if artifact.artifact_contract_version != _ARTIFACT_CONTRACT_VERSION:
        return False
    if not _valid_id(artifact.artifact_id, _ARTIFACT_ID_RE):
        return False
    if not _valid_text(artifact.workspace_identity) or not _valid_text(artifact.attestation_id):
        return False
    if not _claims_shape_is_valid(artifact.claims_payload):
        return False
    if artifact.attestation_id != artifact.claims_payload.attestation_id:
        return False
    if not _valid_text(artifact.detached_proof):
        return False
    if not _valid_digest(artifact.claims_digest) or not _valid_digest(artifact.artifact_digest):
        return False
    if not _canonical_timestamp(artifact.original_verified_at) or not _canonical_timestamp(artifact.created_at):
        return False
    if artifact.claims_digest != artifact.claims_payload.claims_digest():
        return False
    content = {
        "domain": _ARTIFACT_CONTENT_DOMAIN,
        "artifact_contract_version": artifact.artifact_contract_version,
        "workspace_identity": artifact.workspace_identity,
        "attestation_id": artifact.attestation_id,
        "claims_payload": artifact.claims_payload.to_payload(),
        "detached_proof": artifact.detached_proof,
        "claims_digest": artifact.claims_digest,
        "original_verified_at": artifact.original_verified_at,
        "created_at": artifact.created_at,
    }
    return artifact.artifact_digest == digest(content)


def _reference_shape_is_valid(reference: Any) -> bool:
    if type(reference) is not AttestationBindingReference or not _has_fields(reference, _REFERENCE_FIELDS):
        return False
    if reference.reference_contract_version != _REFERENCE_CONTRACT_VERSION:
        return False
    if not _valid_id(reference.reference_id, _REFERENCE_ID_RE) or not _valid_id(reference.binding_id, _BINDING_ID_RE):
        return False
    for field in _REFERENCE_FIELDS - {"revision", "reference_contract_version", "reference_id", "binding_id", "artifact_digest", "remote_authority", "plan_digest", "sealed_preview_digest", "operation_set_digest", "remote_snapshot_digest", "audit_digest", "evidence_digest", "binding_reference_digest", "original_verified_at"}:
        if not _valid_text(getattr(reference, field)):
            return False
    if type(reference.revision) is not int or reference.revision < 1:
        return False
    for field in (
        "artifact_digest", "remote_authority", "plan_digest", "sealed_preview_digest",
        "operation_set_digest", "remote_snapshot_digest", "audit_digest", "evidence_digest",
        "binding_reference_digest",
    ):
        if not _valid_digest(getattr(reference, field)):
            return False
    if not _canonical_timestamp(reference.original_verified_at):
        return False
    content = {
        "domain": _REFERENCE_CONTENT_DOMAIN,
        "reference_contract_version": reference.reference_contract_version,
        **{
            field: getattr(reference, field)
            for field in (
                "workspace_identity", "artifact_id", "artifact_digest", "binding_id",
                "repository_identity", "github_subject_identity", "driver_identity",
                "remote_authority", "preview_id", "revision", "plan_digest",
                "sealed_preview_digest", "operation_set_digest", "remote_snapshot_digest",
                "audit_id", "audit_digest", "evidence_id", "evidence_digest",
                "original_verified_at",
            )
        },
    }
    return reference.binding_reference_digest == digest(content)


def _request_shape_is_valid(request: Any) -> bool:
    if type(request) is not CredentialCapabilityRequest:
        return False
    expected = frozenset(CredentialCapabilityRequest.__slots__) - {"__boundary_provenance", "__weakref__"}
    if not all(hasattr(request, field) for field in expected):
        return False
    if not all(_valid_text(getattr(request, field)) for field in (
        "repository_identity", "github_subject_identity", "driver_identity", "preview_id",
    )):
        return False
    if not _valid_digest(request.remote_authority):
        return False
    if type(request.revision) is not int or request.revision < 1:
        return False
    if type(request.required_capabilities) is not tuple or not request.required_capabilities:
        return False
    if len(set(request.required_capabilities)) != len(request.required_capabilities):
        return False
    if tuple(sorted(request.required_capabilities)) != request.required_capabilities:
        return False
    if any(not _valid_text(capability) for capability in request.required_capabilities):
        return False
    return all(_valid_digest(getattr(request, field)) for field in (
        "operation_set_digest", "remote_snapshot_digest", "evidence_digest",
    ))


def _payload_keysets_are_valid(artifact: Any, reference: Any) -> bool:
    claims_payload = artifact.claims_payload.to_payload()
    artifact_payload = {
        "artifact_contract_version": artifact.artifact_contract_version,
        "artifact_digest": artifact.artifact_digest,
        "artifact_id": artifact.artifact_id,
        "attestation_id": artifact.attestation_id,
        "claims_digest": artifact.claims_digest,
        "claims_payload": claims_payload,
        "created_at": artifact.created_at,
        "original_verified_at": artifact.original_verified_at,
        "workspace_identity": artifact.workspace_identity,
    }
    context_payload = {
        "domain": _CONTEXT_DOMAIN,
        "payload_version": _PAYLOAD_VERSION,
        "workspace_identity": artifact.workspace_identity,
        "artifact": artifact_payload,
        "binding_reference": reference.to_payload(),
    }
    return (
        frozenset(claims_payload) == frozenset({"domain", "claims"})
        and frozenset(claims_payload["claims"]) == _CLAIMS_FIELDS
        and frozenset(artifact_payload) == _CONTEXT_ARTIFACT_FIELDS
        and frozenset(context_payload) == _CONTEXT_ROOT_FIELDS
        and _json_compatible(context_payload)
    )


def _validate_restart_revalidation_context_aggregate(
    aggregate: Any,
    workspace_identity: Any,
    artifact_id: Any,
    expected_reference: Any,
    expected_request: Any,
) -> tuple[PersistedAttestationArtifact, AttestationBindingReference]:
    """Validate the persisted projection without exception-driven conversion."""
    if type(aggregate) is not AttestationArtifactAggregate:
        raise _service_error("attestation_restart_context_invalid")
    if not hasattr(aggregate, "artifact") or not hasattr(aggregate, "binding_reference"):
        raise _service_error("attestation_restart_context_invalid")
    artifact = aggregate.artifact
    reference = aggregate.binding_reference
    if not _artifact_shape_is_valid(artifact) or not _reference_shape_is_valid(reference):
        raise _service_error("attestation_restart_context_invalid")
    if type(workspace_identity) is not str or type(artifact_id) is not str:
        raise _service_error("attestation_restart_context_invalid")
    if artifact.workspace_identity != workspace_identity or artifact.artifact_id != artifact_id:
        raise _service_error("attestation_restart_context_invalid")
    if not _request_shape_is_valid(expected_request) or type(expected_reference) is not AttestationBindingReference:
        raise _service_error("attestation_restart_identity_mismatch")
    if not _reference_shape_is_valid(expected_reference):
        raise _service_error("attestation_restart_identity_mismatch")
    for field in _REFERENCE_FIELDS:
        if getattr(expected_reference, field) != getattr(reference, field):
            raise _service_error("attestation_restart_identity_mismatch")
    claims = artifact.claims_payload
    if claims.derived_attestation_id() != claims.attestation_id:
        raise _service_error("attestation_restart_context_invalid")
    if artifact.claims_digest != claims.claims_digest():
        raise _service_error("attestation_restart_context_invalid")
    for field in _REFERENCE_CROSSWALK:
        if getattr(reference, field) != getattr(claims, field):
            raise _service_error("attestation_restart_context_invalid")
    if reference.workspace_identity != artifact.workspace_identity or reference.artifact_id != artifact.artifact_id:
        raise _service_error("attestation_restart_context_invalid")
    if reference.artifact_digest != artifact.artifact_digest:
        raise _service_error("attestation_restart_context_invalid")
    if reference.original_verified_at != artifact.original_verified_at:
        raise _service_error("attestation_restart_context_invalid")
    if claims.attestation_id != artifact.attestation_id:
        raise _service_error("attestation_restart_context_invalid")
    request = expected_request
    if request.repository_identity != claims.repository_identity or request.github_subject_identity != claims.github_subject_identity:
        raise _service_error("attestation_restart_identity_mismatch")
    for field in _REQUEST_CROSSWALK[2:]:
        if getattr(request, field) != getattr(claims, field):
            raise _service_error("attestation_restart_identity_mismatch")
    if not set(request.required_capabilities).issubset(set(claims.granted_capabilities)):
        raise _service_error("attestation_restart_identity_mismatch")
    if not _payload_keysets_are_valid(artifact, reference):
        raise _service_error("attestation_restart_context_invalid")
    return artifact, reference


def _build_restart_revalidation_context_payload(
    validated_aggregate: tuple[PersistedAttestationArtifact, AttestationBindingReference],
) -> dict[str, Any]:
    """Build the exact five-key logical context payload."""
    artifact, reference = validated_aggregate
    claims_payload = artifact.claims_payload.to_payload()
    artifact_payload = {
        "artifact_contract_version": artifact.artifact_contract_version,
        "artifact_digest": artifact.artifact_digest,
        "artifact_id": artifact.artifact_id,
        "attestation_id": artifact.attestation_id,
        "claims_digest": artifact.claims_digest,
        "claims_payload": claims_payload,
        "created_at": artifact.created_at,
        "original_verified_at": artifact.original_verified_at,
        "workspace_identity": artifact.workspace_identity,
    }
    return {
        "domain": _CONTEXT_DOMAIN,
        "payload_version": _PAYLOAD_VERSION,
        "workspace_identity": artifact.workspace_identity,
        "artifact": artifact_payload,
        "binding_reference": reference.to_payload(),
    }


def _derive_restart_revalidation_context_digest(raw_payload: dict[str, Any]) -> str:
    """Derive the context digest through the existing Protocol path exactly once."""
    return digest(raw_payload)


def _result_digest(context_digest: str, reference_digest: str) -> str:
    return digest({
        "domain": "delivery-system:attestation-revalidation-result:v1",
        "outcome": "Successful",
        "revalidation_context_digest": context_digest,
        "binding_reference_digest": reference_digest,
    })


class RestartRevalidationService:
    """Directly injected, offline restart revalidation service."""

    def __init__(
        self,
        *,
        store: AttestationPersistenceStore,
        revocation_reader: RevocationReader,
        attempt_boundary: RevalidationAttemptBoundary,
        clock: Callable[[], datetime],
    ) -> None:
        if store is None or not callable(getattr(store, "get_artifact_aggregate", None)):
            raise ValueError("store dependency is required")
        if revocation_reader is None or not callable(getattr(revocation_reader, "read_status", None)):
            raise RestartRevalidationError(code="attestation_restart_revocation_unavailable")
        if attempt_boundary is None or not callable(getattr(attempt_boundary, "create_attempt", None)):
            raise ValueError("attempt boundary dependency is required")
        if not callable(clock):
            raise ValueError("clock dependency is required")
        self.__store = store
        self.__revocation_reader = revocation_reader
        self.__attempt_boundary = attempt_boundary
        self.__clock = clock
        self.__lock = threading.RLock()

    def revalidate(
        self,
        *,
        workspace_identity: str,
        artifact_id: str,
        reference: AttestationBindingReference,
        request: CredentialCapabilityRequest,
    ) -> RestartRevalidationResult:
        with self.__lock:
            if type(workspace_identity) is not str or not _valid_text(workspace_identity):
                raise _service_error("attestation_restart_identity_mismatch")
            if not _valid_id(artifact_id, _ARTIFACT_ID_RE):
                raise _service_error("attestation_restart_identity_mismatch")
            aggregate = self.__store.get_artifact_aggregate(workspace_identity, artifact_id)
            if aggregate is None:
                raise StoreContractError("attestation_artifact_not_found")
            validated_aggregate = _validate_restart_revalidation_context_aggregate(
                aggregate, workspace_identity, artifact_id, reference, request,
            )
            raw_payload = _build_restart_revalidation_context_payload(validated_aggregate)
            context_digest = _derive_restart_revalidation_context_digest(raw_payload)
            attempt = self.__attempt_boundary.create_attempt(workspace_identity, artifact_id)
            now = self._read_clock()
            artifact, persisted_reference = validated_aggregate
            claims = artifact.claims_payload
            if now >= self._timestamp_value(claims.expires_at):
                return self._append_outcome(
                    attempt, artifact, persisted_reference, context_digest, now,
                    outcome="Failed", failure_code="attestation_revalidation_expired", result_digest=None,
                )
            status = self._read_revocation_status(claims)
            try:
                status.validate(now)
            except AttestationContractError:
                raise _service_error("attestation_restart_revocation_invalid")
            if status.attestation_revoked or status.credential_instance_revoked:
                return self._append_outcome(
                    attempt, artifact, persisted_reference, context_digest, now,
                    outcome="Failed", failure_code="attestation_revalidation_revoked", result_digest=None,
                )
            result_digest = _result_digest(context_digest, persisted_reference.binding_reference_digest)
            return self._append_outcome(
                attempt, artifact, persisted_reference, context_digest, now,
                outcome="Successful", failure_code=None, result_digest=result_digest,
            )

    def _read_clock(self) -> datetime:
        try:
            value = self.__clock()
        except Exception:
            raise _service_error("attestation_restart_clock_invalid")
        if type(value) is not datetime or value.tzinfo is None or value.utcoffset() != timezone.utc.utcoffset(value):
            raise _service_error("attestation_restart_clock_invalid")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _timestamp_value(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    def _read_revocation_status(self, claims: CredentialCapabilityAttestationClaims) -> RevocationStatus:
        try:
            status = self.__revocation_reader.read_status(
                claims.attestation_id,
                claims.credential_instance_id,
                claims.issuer_id,
                claims.key_id,
                "1",
            )
        except Exception:
            raise _service_error("attestation_restart_revocation_unavailable")
        if status is None:
            raise _service_error("attestation_restart_revocation_unknown")
        if type(status) is not RevocationStatus:
            raise _service_error("attestation_restart_revocation_invalid")
        return status

    def _append_outcome(
        self,
        attempt: RevalidationAttempt,
        artifact: PersistedAttestationArtifact,
        reference: AttestationBindingReference,
        context_digest: str,
        now: datetime,
        *,
        outcome: Literal["Successful", "Failed"],
        failure_code: str | None,
        result_digest: str | None,
    ) -> RestartRevalidationResult:
        event = AttestationRevalidationEvent.create(
            workspace_identity=artifact.workspace_identity,
            artifact_id=artifact.artifact_id,
            artifact_digest=artifact.artifact_digest,
            revalidation_attempt_id=attempt.revalidation_attempt_id,
            revalidation_context_digest=context_digest,
            binding_reference_digest=reference.binding_reference_digest,
            outcome=outcome,
            revalidated_at=now.isoformat().replace("+00:00", "Z"),
            failure_code=failure_code,
            result_digest=result_digest,
        )
        finalized = self.__attempt_boundary.finalize(attempt, event)
        stored = self.__store.append_revalidation_event(finalized)
        return RestartRevalidationResult(outcome, failure_code, result_digest, stored)


__all__ = [
    "RestartRevalidationError",
    "RestartRevalidationResult",
    "RestartRevalidationService",
]
