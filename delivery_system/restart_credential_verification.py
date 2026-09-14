"""Restart-time verification of persisted credential attestations.

This module verifies historical credential evidence without creating a live
attestation request, challenge, ticket, or Runtime-owned credential context.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from typing import Any, Protocol

from delivery_system.attestation import (
    ATTESTATION_VERSION_V1,
    ATTESTATION_VERSION_V2,
    CredentialCapabilityAttestationClaims,
    CredentialCapabilityPolicy,
    CredentialCapabilityProofVerifier,
    IssuerTrustDecision,
    REVOCATION_CONTRACT_VERSION,
    RevocationReader,
    RevocationStatus,
    SUPPORTED_SIGNATURE_ALGORITHMS,
    TrustedIssuerPolicy,
)
from delivery_system.attestation_persistence import PersistedAttestationArtifact
from delivery_system.attestation_runtime import RuntimeAttestationOrchestrationService
from delivery_system.protocol import canonical_payload


class RestartCredentialAttestationVerifier(Protocol):
    """Verify one persisted credential artifact under current policy."""

    def verify(
        self,
        artifact: PersistedAttestationArtifact,
        *,
        current_time: datetime,
    ) -> "RestartVerifiedCredentialEvidence": ...


@dataclass(frozen=True, slots=True)
class RestartVerifiedCredentialEvidence:
    """Immutable historical credential evidence verified after restart."""

    workspace_identity: str
    artifact_id: str
    artifact_digest: str
    claims: CredentialCapabilityAttestationClaims
    claims_digest: str
    original_verified_at: str

    def __post_init__(self) -> None:
        if type(self.workspace_identity) is not str or not self.workspace_identity:
            raise ValueError("restart_reconstruction_credential_evidence_invalid")
        if type(self.artifact_id) is not str or not self.artifact_id:
            raise ValueError("restart_reconstruction_credential_evidence_invalid")
        if type(self.artifact_digest) is not str or not self.artifact_digest:
            raise ValueError("restart_reconstruction_credential_evidence_invalid")
        if type(self.claims) is not CredentialCapabilityAttestationClaims:
            raise ValueError("restart_reconstruction_credential_evidence_invalid")
        if self.claims_digest != self.claims.claims_digest():
            raise ValueError("restart_reconstruction_credential_evidence_invalid")
        if type(self.original_verified_at) is not str or not self.original_verified_at:
            raise ValueError("restart_reconstruction_credential_evidence_invalid")

    @property
    def attestation_id(self) -> str:
        return self.claims.attestation_id

    @property
    def issuer_id(self) -> str:
        return self.claims.issuer_id

    @property
    def key_id(self) -> str:
        return self.claims.key_id

    @property
    def signature_algorithm(self) -> str:
        return self.claims.signature_algorithm

    @property
    def credential_class(self) -> str:
        return self.claims.credential_class

    @property
    def credential_instance_id(self) -> str:
        return self.claims.credential_instance_id

    @property
    def credential_principal_identity(self) -> str:
        return self.claims.credential_principal_identity

    @property
    def challenge_digest(self) -> str:
        return self.claims.challenge_digest

    @property
    def repository_identity(self) -> str:
        return self.claims.repository_identity

    @property
    def github_subject_identity(self) -> str:
        return self.claims.github_subject_identity

    @property
    def granted_capabilities(self) -> tuple[str, ...]:
        return self.claims.granted_capabilities

    @property
    def driver_identity(self) -> str:
        return self.claims.driver_identity

    @property
    def remote_authority(self) -> str:
        return self.claims.remote_authority

    @property
    def expires_at(self) -> str:
        return self.claims.expires_at

    @property
    def issued_at(self) -> str:
        return self.claims.issued_at


def derive_restart_binding_id(values: dict[str, Any]) -> str:
    """Derive the existing binding identity without creating a live binding."""
    try:
        projection = dict(values)
        projection.pop("binding_id", None)
        projection = RuntimeAttestationOrchestrationService._binding_payload(projection)
        material = canonical_payload({
            "domain": "delivery-system:runtime-attestation-binding:v1",
            "binding": projection,
        }).encode("utf-8")
    except Exception as exc:
        raise ValueError("restart_reconstruction_binding_mismatch") from exc
    return "binding-" + hashlib.sha256(material).hexdigest()


def _current_time(value: datetime) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("restart_reconstruction_clock_invalid")
    return value.astimezone(timezone.utc)


class DefaultRestartCredentialAttestationVerifier:
    """Restart verifier composed from Runtime-injected trust dependencies."""

    def __init__(
        self,
        *,
        issuer_policy: TrustedIssuerPolicy,
        proof_verifier: CredentialCapabilityProofVerifier,
        revocation_reader: RevocationReader,
        capability_policy: CredentialCapabilityPolicy,
    ) -> None:
        for dependency in (issuer_policy, proof_verifier, revocation_reader, capability_policy):
            if dependency is None:
                raise ValueError("restart_credential_verifier_invalid")
        if not callable(getattr(issuer_policy, "evaluate", None)):
            raise ValueError("restart_credential_verifier_invalid")
        if not callable(getattr(proof_verifier, "verify", None)):
            raise ValueError("restart_credential_verifier_invalid")
        if not callable(getattr(revocation_reader, "read_status", None)):
            raise ValueError("restart_credential_verifier_invalid")
        if not callable(getattr(capability_policy, "is_supported", None)):
            raise ValueError("restart_credential_verifier_invalid")
        self._issuer_policy = issuer_policy
        self._proof_verifier = proof_verifier
        self._revocation_reader = revocation_reader
        self._capability_policy = capability_policy

    def verify(
        self,
        artifact: PersistedAttestationArtifact,
        *,
        current_time: datetime,
    ) -> RestartVerifiedCredentialEvidence:
        try:
            normalized = PersistedAttestationArtifact.from_untrusted(artifact)
        except Exception as exc:
            raise ValueError("restart_reconstruction_credential_evidence_invalid") from exc
        now = _current_time(current_time)
        claims = normalized.claims_payload
        if claims.attestation_version not in {ATTESTATION_VERSION_V1, ATTESTATION_VERSION_V2}:
            raise ValueError("restart_reconstruction_credential_untrusted")
        if claims.signature_algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
            raise ValueError("restart_reconstruction_credential_untrusted")
        try:
            decision = self._issuer_policy.evaluate(
                claims.issuer_id,
                claims.key_id,
                claims.signature_algorithm,
                claims.attestation_version,
                claims.credential_class,
            )
        except Exception as exc:
            raise ValueError("restart_reconstruction_credential_untrusted") from exc
        if type(decision) is not IssuerTrustDecision or decision.accepted is not True:
            raise ValueError("restart_reconstruction_credential_untrusted")
        try:
            signed_payload = canonical_payload(claims.to_payload()).encode("utf-8")
            valid = self._proof_verifier.verify(
                signed_payload,
                normalized.detached_proof,
                claims.issuer_id,
                claims.key_id,
                claims.signature_algorithm,
            )
        except Exception as exc:
            raise ValueError("restart_reconstruction_credential_proof_invalid") from exc
        if valid is not True:
            raise ValueError("restart_reconstruction_credential_proof_invalid")
        try:
            for capability in claims.granted_capabilities:
                if self._capability_policy.is_supported(capability) is not True:
                    raise ValueError("restart_reconstruction_capability_rejected")
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError("restart_reconstruction_capability_rejected") from exc
        try:
            issued = datetime.fromisoformat(claims.issued_at.replace("Z", "+00:00"))
            expires = datetime.fromisoformat(claims.expires_at.replace("Z", "+00:00"))
        except (TypeError, ValueError) as exc:
            raise ValueError("restart_reconstruction_credential_evidence_invalid") from exc
        if now < issued:
            raise ValueError("restart_reconstruction_credential_not_yet_valid")
        if now >= expires:
            raise ValueError("restart_reconstruction_credential_expired")
        try:
            status = self._revocation_reader.read_status(
                claims.attestation_id,
                claims.credential_instance_id,
                claims.issuer_id,
                claims.key_id,
                REVOCATION_CONTRACT_VERSION,
            )
        except Exception as exc:
            raise ValueError("restart_reconstruction_revocation_unavailable") from exc
        if type(status) is not RevocationStatus:
            raise ValueError("restart_reconstruction_revocation_unknown")
        try:
            status.validate(now)
        except Exception as exc:
            raise ValueError("restart_reconstruction_revocation_invalid") from exc
        if status.attestation_revoked or status.credential_instance_revoked:
            raise ValueError("restart_reconstruction_credential_revoked")
        return RestartVerifiedCredentialEvidence(
            workspace_identity=normalized.workspace_identity,
            artifact_id=normalized.artifact_id,
            artifact_digest=normalized.artifact_digest,
            claims=claims,
            claims_digest=claims.claims_digest(),
            original_verified_at=normalized.original_verified_at,
        )


__all__ = [
    "DefaultRestartCredentialAttestationVerifier",
    "RestartCredentialAttestationVerifier",
    "RestartVerifiedCredentialEvidence",
    "derive_restart_binding_id",
]
