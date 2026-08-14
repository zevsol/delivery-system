"""Test-only provider and capability resolver for offline orchestration tests."""

from __future__ import annotations

from datetime import datetime, timezone
import base64
import hashlib
from typing import Any, Mapping, Sequence

from delivery_system.attestation import (
    CredentialCapabilityRequest,
    CredentialCapabilityProvider,
    CredentialCapabilityAttestationClaims,
    SignedCredentialCapabilityAttestation,
)
from delivery_system.protocol import canonical_payload


class FakeCapabilityResolver:
    def __init__(self, capabilities: Sequence[str] = ("issues:write",)) -> None:
        self.capabilities = tuple(capabilities)
        self.calls = 0

    def resolve(self, operation_intents: Sequence[Mapping[str, Any]]) -> Sequence[str]:
        self.calls += 1
        return tuple(sorted(self.capabilities))


class FakeCredentialCapabilityProvider(CredentialCapabilityProvider):
    def __init__(self, *, issued_at: str = "2026-08-14T11:00:00Z", expires_at: str = "2026-08-14T13:00:00Z") -> None:
        self.issued_at = issued_at
        self.expires_at = expires_at
        self.calls = 0
        self.last_request: CredentialCapabilityRequest | None = None
        self.fail = False
        self.malformed: Any = None
        self.credential_instance_id = "fake-instance-1"
        self.repository_identity_override: str | None = None

    def attest(self, request: CredentialCapabilityRequest) -> SignedCredentialCapabilityAttestation | Any:
        self.calls += 1
        self.last_request = request
        if self.fail:
            raise RuntimeError("fake-provider-internal-detail")
        if self.malformed is not None:
            return self.malformed
        claims = CredentialCapabilityAttestationClaims(
            attestation_version="1", attestation_id="", issuer_id="host-issuer", key_id="key-1",
            signature_algorithm="ed25519", credential_class="github-app-installation-token",
            credential_instance_id=self.credential_instance_id,
            github_subject_identity=request.github_subject_identity,
            repository_identity=self.repository_identity_override or request.repository_identity,
            granted_capabilities=request.required_capabilities,
            driver_identity=request.driver_identity,
            remote_authority=request.remote_authority,
            preview_id=request.preview_id,
            revision=request.revision,
            operation_set_digest=request.operation_set_digest,
            remote_snapshot_digest=request.remote_snapshot_digest,
            evidence_digest=request.evidence_digest,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            nonce="fake-nonce-1",
            source_verification_digest=request.evidence_digest,
        )
        payload = canonical_payload(claims.to_payload()).encode("utf-8")
        proof = base64.urlsafe_b64encode(hashlib.sha512(payload).digest()).decode("ascii").rstrip("=")
        return SignedCredentialCapabilityAttestation(claims, proof)
