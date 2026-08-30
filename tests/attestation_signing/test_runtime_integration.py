from __future__ import annotations

from base64 import urlsafe_b64encode
from dataclasses import replace
from datetime import datetime, timezone
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from delivery_system.attestation import (
    AttestationRuntimeBoundary,
    SignedCredentialCapabilityAttestation,
    verify_credential_capability_attestation,
)
from delivery_system.attestation_github_app import GitHubAppCredentialCapabilityProvider
from delivery_system.attestation_signing import (
    Ed25519HostSigner,
    Ed25519ProofVerifier,
    TrustedEd25519IssuerKeyRegistry,
    TrustedEd25519Key,
)
from delivery_system.protocol import canonical_payload
from tests.attestation_contract.test_attestation_contract import FakeIssuer
from tests.attestation_github_app.test_provider import (
    CapabilityPolicy,
    NOW,
    Source,
    raw_evidence,
    request,
)


# TEST ONLY / NON-PRODUCTION deterministic key material.
TEST_ONLY_PRIVATE_BYTES = bytes(range(32))
ALTERNATE_TEST_ONLY_PRIVATE_BYTES = bytes(range(32, 64))


class RuntimeIntegrationTests(unittest.TestCase):
    def make_components(self, private_bytes=TEST_ONLY_PRIVATE_BYTES, key_id="host-key"):
        private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
        signer = Ed25519HostSigner("host-issuer", key_id, private_key)
        registry = TrustedEd25519IssuerKeyRegistry((TrustedEd25519Key(
            "host-issuer", key_id, private_key.public_key()
        ),))
        verifier = Ed25519ProofVerifier(registry)
        boundary = AttestationRuntimeBoundary(
            registry, verifier, FakeIssuer(), CapabilityPolicy()
        )
        source = Source(raw_evidence())
        provider = GitHubAppCredentialCapabilityProvider(
            source,
            signer,
            clock=lambda: NOW,
            credential_instance_id_factory=lambda: "credential-instance-" + "a" * 32,
            nonce_factory=lambda: "nonce-" + "a" * 32,
        )
        return boundary, provider

    def test_real_signer_registry_and_verifier_complete_offline_v2_path(self):
        boundary, provider = self.make_components()
        issued_request = request(boundary)
        signed = provider.attest(issued_request)

        result = verify_credential_capability_attestation(
            signed, issued_request, boundary, NOW
        )

        self.assertTrue(result.success)
        self.assertIsNotNone(result.verified)
        self.assertEqual(signed.claims.attestation_version, "2")
        self.assertEqual(
            signed.claims.credential_principal_identity,
            "github-app-installation-12345-67890",
        )

    def test_wrong_key_and_tampered_claims_or_proof_fail_closed(self):
        boundary, provider = self.make_components()
        issued_request = request(boundary)
        signed = provider.attest(issued_request)

        wrong_boundary, _ = self.make_components(ALTERNATE_TEST_ONLY_PRIVATE_BYTES)
        wrong_request = request(wrong_boundary)
        wrong_key_result = verify_credential_capability_attestation(
            signed, wrong_request, wrong_boundary, NOW
        )
        self.assertFalse(wrong_key_result.success)
        self.assertEqual(wrong_key_result.failures[0].code, "attestation_signature_invalid")

        tampered_claims = replace(
            signed.claims, repository_identity="other/repo", attestation_id=""
        )
        tampered_claims_result = verify_credential_capability_attestation(
            SignedCredentialCapabilityAttestation(tampered_claims, signed.proof),
            issued_request,
            boundary,
            NOW,
        )
        self.assertFalse(tampered_claims_result.success)
        self.assertEqual(
            tampered_claims_result.failures[0].code,
            "attestation_signature_invalid",
        )

        alternate_signer = Ed25519HostSigner(
            "host-issuer",
            "host-key",
            Ed25519PrivateKey.from_private_bytes(ALTERNATE_TEST_ONLY_PRIVATE_BYTES),
        )
        alternate_proof = alternate_signer.sign(
            canonical_payload(signed.claims.to_payload()).encode("utf-8")
        )
        tampered_proof_result = verify_credential_capability_attestation(
            SignedCredentialCapabilityAttestation(signed.claims, alternate_proof),
            issued_request,
            boundary,
            NOW,
        )
        self.assertFalse(tampered_proof_result.success)
        self.assertEqual(
            tampered_proof_result.failures[0].code,
            "attestation_signature_invalid",
        )

    def test_unknown_key_id_is_rejected_by_issuer_policy(self):
        boundary, provider = self.make_components()
        issued_request = request(boundary)
        signed = provider.attest(issued_request)
        claims_data = dict(signed.claims.to_payload()["claims"])
        claims_data["key_id"] = "unknown-key"
        claims_data["attestation_id"] = ""
        unknown_claims = signed.claims.__class__(**claims_data)
        arbitrary_proof = urlsafe_b64encode(bytes(range(64))).decode("ascii").rstrip("=")

        result = verify_credential_capability_attestation(
            SignedCredentialCapabilityAttestation(unknown_claims, arbitrary_proof),
            issued_request,
            boundary,
            NOW,
        )

        self.assertFalse(result.success)
        self.assertEqual(result.failures[0].code, "attestation_issuer_untrusted")


if __name__ == "__main__":
    unittest.main()
