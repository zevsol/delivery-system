"""Bridge verified credential attestations to durable historical evidence.

This module deliberately stops at attestation-artifact persistence.  It does
not issue or persist ApplicationAuthority or AuthorityBindingRecord objects.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any, Callable

from delivery_system.attestation import (
    CredentialCapabilityAttestationClaims,
)
from delivery_system.attestation_persistence import (
    AttestationBindingReference,
    PersistedAttestationArtifact,
)
from delivery_system.attestation_persistence_store import (
    AttestationArtifactAggregate,
    AttestationPersistenceStore,
    StoreContractError,
)
from delivery_system.attestation_runtime import (
    RuntimeCredentialCapabilityBinding,
    VerifiedRuntimeCredentialContext,
)


_BINDING_ID_RE = re.compile(r"^binding-[0-9a-f]{64}$")


class VerifiedAttestationArtifactError(ValueError):
    """Stable adapter-boundary failure without exposing credential material."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _error(code: str) -> None:
    raise VerifiedAttestationArtifactError(code)


def _timestamp(value: Any, field: str) -> str:
    if type(value) is not str:
        _error(f"verified_attestation_{field}_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError, OverflowError):
        _error(f"verified_attestation_{field}_invalid")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _error(f"verified_attestation_{field}_invalid")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _clock_timestamp(value: Any) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        _error("verified_attestation_created_at_invalid")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _binding_id(value: Any) -> str:
    if type(value) is not str or _BINDING_ID_RE.fullmatch(value) is None:
        _error("verified_attestation_binding_invalid")
    return value


def _claims_match_binding(
    claims: CredentialCapabilityAttestationClaims,
    binding: RuntimeCredentialCapabilityBinding,
) -> None:
    checks = {
        "attestation_id": claims.attestation_id,
        "claims_digest": claims.claims_digest(),
        "credential_instance_id": claims.credential_instance_id,
        "issuer_id": claims.issuer_id,
        "key_id": claims.key_id,
        "algorithm": claims.signature_algorithm,
        "credential_class": claims.credential_class,
        "credential_principal_identity": claims.credential_principal_identity,
        "challenge_digest": claims.challenge_digest,
        "github_subject_identity": claims.github_subject_identity,
        "repository_identity": claims.repository_identity,
        "granted_capabilities": claims.granted_capabilities,
        "driver_identity": claims.driver_identity,
        "remote_authority": claims.remote_authority,
        "preview_id": claims.preview_id,
        "revision": claims.revision,
        "operation_set_digest": claims.operation_set_digest,
        "remote_snapshot_digest": claims.remote_snapshot_digest,
        "evidence_digest": claims.evidence_digest,
        "issued_at": claims.issued_at,
        "expires_at": claims.expires_at,
        "source_verification_digest": claims.source_verification_digest,
    }
    try:
        for field, expected in checks.items():
            if getattr(binding, field) != expected:
                _error("verified_attestation_binding_mismatch")
        _binding_id(binding.binding_id)
        if type(binding.workspace_identity) is not str or not binding.workspace_identity:
            _error("verified_attestation_binding_mismatch")
        _timestamp(binding.verified_at, "verified_at")
    except VerifiedAttestationArtifactError:
        raise
    except Exception as exc:
        raise VerifiedAttestationArtifactError("verified_attestation_binding_mismatch") from exc


def _build_artifact(
    context: VerifiedRuntimeCredentialContext,
    created_at: str,
) -> PersistedAttestationArtifact:
    return PersistedAttestationArtifact.create(
        workspace_identity=context.binding.workspace_identity,
        claims_payload=context.claims,
        detached_proof=context.envelope.proof,
        original_verified_at=context.verified_at,
        created_at=created_at,
    )


def _build_reference(
    artifact: PersistedAttestationArtifact,
    binding: RuntimeCredentialCapabilityBinding,
) -> AttestationBindingReference:
    return AttestationBindingReference.create(
        artifact=artifact,
        binding_values=binding.to_dict(),
    )


def _validate_existing(
    aggregate: AttestationArtifactAggregate,
    context: VerifiedRuntimeCredentialContext,
) -> None:
    artifact = aggregate.artifact
    expected = _build_artifact(context, artifact.created_at)
    expected_reference = _build_reference(artifact, context.binding)
    if artifact != expected or aggregate.binding_reference != expected_reference:
        _error("verified_attestation_artifact_conflict")


@dataclass(frozen=True, slots=True)
class VerifiedCredentialArtifactLink:
    """Immutable linkage to durable evidence; it is not itself a trust anchor."""

    credential_binding_id: str
    aggregate: AttestationArtifactAggregate

    def __post_init__(self) -> None:
        _binding_id(self.credential_binding_id)
        if type(self.aggregate) is not AttestationArtifactAggregate:
            _error("verified_attestation_artifact_link_invalid")
        if self.aggregate.binding_reference.binding_id != self.credential_binding_id:
            _error("verified_attestation_artifact_link_invalid")

    @property
    def artifact_id(self) -> str:
        return self.aggregate.artifact.artifact_id

    @property
    def artifact_digest(self) -> str:
        return self.aggregate.artifact.artifact_digest

    @property
    def artifact(self) -> PersistedAttestationArtifact:
        return self.aggregate.artifact

    @property
    def binding_reference(self) -> AttestationBindingReference:
        return self.aggregate.binding_reference


class VerifiedAttestationArtifactAdapter:
    """Persist one exact, successfully verified credential-attestation envelope."""

    def __init__(self, store: AttestationPersistenceStore, *, clock: Callable[[], datetime]) -> None:
        if not callable(getattr(store, "persist_artifact", None)) or not callable(getattr(store, "get_artifact_aggregate", None)):
            _error("verified_attestation_store_invalid")
        if not callable(clock):
            _error("verified_attestation_clock_invalid")
        self._store = store
        self._clock = clock

    @staticmethod
    def _validated_context(
        context: VerifiedRuntimeCredentialContext,
    ) -> tuple[RuntimeCredentialCapabilityBinding, CredentialCapabilityAttestationClaims, str]:
        if not VerifiedRuntimeCredentialContext.is_source_owned(context):
            _error("verified_attestation_context_unverified")
        binding = context.binding
        if context.binding.verified_at != context.verified_at:
            _error("verified_attestation_binding_mismatch")
        claims = context.claims
        _claims_match_binding(claims, binding)
        artifact_id = PersistedAttestationArtifact.artifact_id_for(
            binding.workspace_identity,
            claims.attestation_id,
        )
        return binding, claims, artifact_id

    def resolve_verified_attestation(
        self,
        context: VerifiedRuntimeCredentialContext,
    ) -> VerifiedCredentialArtifactLink:
        """Resolve existing verified evidence without creating or persisting anything."""
        binding, _claims, artifact_id = self._validated_context(context)
        existing = self._store.get_artifact_aggregate(binding.workspace_identity, artifact_id)
        if existing is None:
            _error("verified_attestation_artifact_not_found")
        try:
            _validate_existing(existing, context)
        except VerifiedAttestationArtifactError:
            raise
        except Exception as exc:
            raise VerifiedAttestationArtifactError(
                "verified_attestation_artifact_conflict"
            ) from exc
        return VerifiedCredentialArtifactLink(binding.binding_id, existing)

    def persist_verified_attestation(
        self,
        context: VerifiedRuntimeCredentialContext,
    ) -> VerifiedCredentialArtifactLink:
        binding, claims, artifact_id = self._validated_context(context)
        envelope = context.envelope
        existing = self._store.get_artifact_aggregate(binding.workspace_identity, artifact_id)
        if existing is not None:
            _validate_existing(existing, context)
            return VerifiedCredentialArtifactLink(binding.binding_id, existing)
        created_at = _clock_timestamp(self._clock())
        artifact = _build_artifact(context, created_at)
        reference = _build_reference(artifact, binding)
        try:
            aggregate = self._store.persist_artifact(artifact, reference)
        except StoreContractError as exc:
            if exc.code != "attestation_artifact_conflict":
                raise
            winner = self._store.get_artifact_aggregate(binding.workspace_identity, artifact_id)
            if winner is None:
                raise
            _validate_existing(winner, context)
            aggregate = winner
        _validate_existing(aggregate, context)
        return VerifiedCredentialArtifactLink(binding.binding_id, aggregate)


__all__ = [
    "VerifiedAttestationArtifactError",
    "VerifiedCredentialArtifactLink",
    "VerifiedAttestationArtifactAdapter",
]
