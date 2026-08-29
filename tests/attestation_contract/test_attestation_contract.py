from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import copy
from datetime import datetime, timezone
import base64
import gc
import hashlib
import unittest
import weakref
from unittest.mock import patch

from delivery_system.attestation import (
    ATTESTATION_DOMAIN,
    AttestationRuntimeBoundary,
    CredentialCapabilityAttestationClaims,
    CredentialCapabilityRequest,
    CredentialCapabilityProofVerifier,
    CredentialCapabilityPolicy,
    RevocationReader,
    RevocationStatus,
    SignedCredentialCapabilityAttestation,
    TrustedIssuerPolicy,
    IssuerTrustDecision,
    VerifiedCredentialCapabilityAttestation,
    verify_credential_capability_attestation,
)
import delivery_system.attestation as attestation_module
from delivery_system.protocol import canonical_payload, digest


NOW = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)
SENTINEL = "sentinel-proof-and-provider-error-must-not-leak"


class FakeIssuer(TrustedIssuerPolicy, CredentialCapabilityProofVerifier, RevocationReader):
    def __init__(self) -> None:
        self.trusted = True
        self.algorithm = "ed25519"
        self.revocation = RevocationStatus()
        self.raise_verifier = False
        self.calls = 0
        self.proofs: list[str] = []
        self.payloads: list[bytes] = []

    def evaluate(self, issuer_id: str, key_id: str, signature_algorithm: str, attestation_version: str, credential_class: str) -> IssuerTrustDecision:
        if not self.trusted or issuer_id != "host-issuer" or key_id != "key-1":
            return IssuerTrustDecision(False, "attestation_issuer_untrusted")
        if attestation_version != "1":
            return IssuerTrustDecision(False, "attestation_version_unsupported")
        if signature_algorithm != self.algorithm:
            return IssuerTrustDecision(False, "attestation_algorithm_unsupported")
        if credential_class != "github-app-installation-token":
            return IssuerTrustDecision(False, "attestation_credential_class_unsupported")
        return IssuerTrustDecision(True)

    def verify(self, payload: bytes, proof: str, issuer_id: str, key_id: str, signature_algorithm: str) -> bool:
        if self.raise_verifier:
            raise RuntimeError(SENTINEL)
        self.proofs.append(proof)
        self.payloads.append(payload)
        expected = base64.urlsafe_b64encode(hashlib.sha512(payload).digest()).decode("ascii").rstrip("=")
        return proof == expected

    def read_status(self, attestation_id: str, credential_instance_id: str, issuer_id: str, key_id: str, version: str) -> RevocationStatus:
        self.calls += 1
        return self.revocation


class FakeCapabilityPolicy(CredentialCapabilityPolicy):
    def __init__(self) -> None:
        self.supported = {"issues:read", "issues:write"}
        self.raise_error = False
        self.non_bool = False

    def is_supported(self, capability: str) -> bool | object:
        if self.raise_error:
            raise RuntimeError(SENTINEL)
        if self.non_bool:
            return "yes"
        return capability in self.supported


def request(boundary: AttestationRuntimeBoundary) -> CredentialCapabilityRequest:
    return boundary.create_request(
        repository_identity="owner/repository",
        github_subject_identity="subject-1",
        required_capabilities=("issues:write", "issues:read"),
        driver_identity="github-rest-driver-v1",
        remote_authority="sha256:" + "a" * 64,
        preview_id="preview-1",
        revision=2,
        operation_set_digest="sha256:" + "b" * 64,
        remote_snapshot_digest="sha256:" + "c" * 64,
        evidence_digest="sha256:" + "d" * 64,
    )


def claims(**changes: object) -> CredentialCapabilityAttestationClaims:
    values: dict[str, object] = {
        "attestation_version": "1",
        "attestation_id": "",
        "issuer_id": "host-issuer",
        "key_id": "key-1",
        "signature_algorithm": "ed25519",
        "credential_class": "github-app-installation-token",
        "credential_instance_id": "instance-opaque-1",
        "github_subject_identity": "subject-1",
        "repository_identity": "owner/repository",
        "granted_capabilities": ("issues:read", "issues:write"),
        "driver_identity": "github-rest-driver-v1",
        "remote_authority": "sha256:" + "a" * 64,
        "preview_id": "preview-1",
        "revision": 2,
        "operation_set_digest": "sha256:" + "b" * 64,
        "remote_snapshot_digest": "sha256:" + "c" * 64,
        "evidence_digest": "sha256:" + "d" * 64,
        "issued_at": "2026-08-14T11:00:00Z",
        "expires_at": "2026-08-14T13:00:00Z",
        "nonce": "nonce-1",
        "source_verification_digest": "sha256:" + "e" * 64,
    }
    values.update(changes)
    return CredentialCapabilityAttestationClaims(**values)  # type: ignore[arg-type]


def signed(fake: FakeIssuer, claim: CredentialCapabilityAttestationClaims | None = None) -> SignedCredentialCapabilityAttestation:
    claim = claim or claims()
    payload = canonical_payload(claim.to_payload()).encode("utf-8")
    return SignedCredentialCapabilityAttestation(
        claim, base64.urlsafe_b64encode(hashlib.sha512(payload).digest()).decode("ascii").rstrip("=")
    )


def verify(fake: FakeIssuer, envelope: SignedCredentialCapabilityAttestation | None = None):
    boundary = AttestationRuntimeBoundary(fake, fake, fake, FakeCapabilityPolicy())
    return verify_credential_capability_attestation(envelope or signed(fake), request(boundary), boundary, NOW)


class AttestationContractTests(unittest.TestCase):
    def test_canonical_claims_id_and_capability_order_are_deterministic(self):
        first = claims(granted_capabilities=("issues:write", "issues:read"))
        second = claims(granted_capabilities=("issues:read", "issues:write"))
        self.assertEqual(first, second)
        self.assertEqual(first.attestation_id, second.attestation_id)
        self.assertEqual(first.claims_digest(), second.claims_digest())
        self.assertTrue(first.to_payload()["domain"].startswith(ATTESTATION_DOMAIN))

    def test_duplicate_capability_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "^granted_capabilities_duplicate$"):
            claims(granted_capabilities=("issues:write", "issues:write"))

    def test_valid_fake_issuer_verifier_succeeds(self):
        result = verify(FakeIssuer())
        self.assertTrue(result.success)
        self.assertIsNotNone(result.verified)
        self.assertTrue(result.to_dict()["verified"])

    def test_untrusted_issuer_wrong_key_and_algorithm_fail_closed(self):
        fake = FakeIssuer()
        fake.trusted = False
        self.assertEqual(verify(fake).failures[0].code, "attestation_issuer_untrusted")
        fake.trusted = True
        self.assertEqual(verify(fake, signed(fake, claims(key_id="wrong-key"))).failures[0].code, "attestation_issuer_untrusted")
        unsupported = claims(signature_algorithm="rsa-sha256")
        envelope = object.__new__(SignedCredentialCapabilityAttestation)
        object.__setattr__(envelope, "claims", unsupported)
        object.__setattr__(envelope, "proof", base64.urlsafe_b64encode(b"X" * 64).decode("ascii").rstrip("="))
        self.assertEqual(verify(fake, envelope).failures[0].code, "attestation_algorithm_unsupported")

    def test_tampered_proof_and_claims_fail(self):
        fake = FakeIssuer()
        envelope = signed(fake)
        tampered_proof = SignedCredentialCapabilityAttestation(
            envelope.claims, base64.urlsafe_b64encode(b"X" * 64).decode("ascii").rstrip("=")
        )
        self.assertEqual(verify(fake, tampered_proof).failures[0].code, "attestation_signature_invalid")
        payload = envelope.claims.to_payload()
        payload["claims"]["repository_identity"] = "other/repository"
        boundary = AttestationRuntimeBoundary(fake, fake, fake, FakeCapabilityPolicy())
        result = verify_credential_capability_attestation(
            {"claims": payload["claims"], "proof": envelope.proof}, request(boundary), boundary, NOW,
        )
        self.assertEqual(result.failures[0].code, "attestation_id_mismatch")

    def test_time_boundaries_fail_closed(self):
        fake = FakeIssuer()
        future = signed(fake, claims(issued_at="2026-08-14T13:00:00Z", expires_at="2026-08-14T14:00:00Z"))
        self.assertEqual(verify(fake, future).failures[0].code, "attestation_not_yet_valid")
        expired = signed(fake, claims(issued_at="2026-08-14T10:00:00Z", expires_at="2026-08-14T12:00:00Z"))
        self.assertEqual(verify(fake, expired).failures[0].code, "attestation_expired")

    def test_attestation_and_credential_instance_revocation(self):
        fake = FakeIssuer()
        fake.revocation = RevocationStatus(attestation_revoked=True, revoked_at="2026-08-14T11:30:00Z", reason="operator")
        self.assertEqual(verify(fake).failures[0].code, "attestation_revoked")
        fake.revocation = RevocationStatus(credential_instance_revoked=True, revoked_at="2026-08-14T11:30:00Z", reason="rotation")
        self.assertEqual(verify(fake).failures[0].code, "credential_instance_revoked")

    def test_each_runtime_binding_mismatch_is_rejected(self):
        fields = (
            "repository_identity", "github_subject_identity", "driver_identity", "remote_authority",
            "preview_id", "revision", "operation_set_digest", "remote_snapshot_digest", "evidence_digest",
        )
        values: dict[str, object] = {
            "repository_identity": "other/repository", "github_subject_identity": "subject-2",
            "driver_identity": "other-driver", "remote_authority": "sha256:" + "f" * 64,
            "preview_id": "preview-2", "revision": 3, "operation_set_digest": "sha256:" + "f" * 64,
            "remote_snapshot_digest": "sha256:" + "f" * 64, "evidence_digest": "sha256:" + "f" * 64,
        }
        fake = FakeIssuer()
        for field in fields:
            with self.subTest(field=field):
                result = verify(fake, signed(fake, claims(**{field: values[field]})))
                self.assertEqual(result.failures[0].code, "attestation_binding_mismatch")

    def test_capability_insufficient_and_malformed_values(self):
        fake = FakeIssuer()
        self.assertEqual(
            verify(fake, signed(fake, claims(granted_capabilities=("issues:read",)))).failures[0].code,
            "credential_capability_insufficient",
        )
        raw = {"claims": {"unexpected": True}, "proof": "secret-proof"}
        boundary = AttestationRuntimeBoundary(fake, fake, fake, FakeCapabilityPolicy())
        result = verify_credential_capability_attestation(raw, request(boundary), boundary, NOW)
        self.assertEqual(result.failures[0].code, "attestation_invalid")
        self.assertNotIn("secret-proof", repr(result.to_dict()))

    def test_invalid_digest_revision_time_nonce_and_id_fail(self):
        for field, value in (
            ("operation_set_digest", "sha256:bad"),
            ("revision", True),
            ("issued_at", "2026-08-14T11:00:00"),
            ("expires_at", "2026-08-14T10:00:00Z"),
            ("nonce", "\n"),
        ):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    claims(**{field: value})

    def test_verifier_exception_is_stable_and_secret_free(self):
        fake = FakeIssuer()
        fake.raise_verifier = True
        result = verify(fake, signed(fake))
        self.assertEqual(result.failures[0].code, "attestation_verifier_unavailable")
        output = repr(result.to_dict())
        self.assertNotIn(SENTINEL, output)

    def test_verified_result_cannot_be_ordinary_constructed_or_copied(self):
        fake = FakeIssuer()
        verified = verify(fake).verified
        assert verified is not None
        valid_claims = claims()
        with self.assertRaisesRegex(ValueError, "^verified_attestation_required$"):
            VerifiedCredentialCapabilityAttestation(valid_claims, verified.claims_digest)
        with self.assertRaisesRegex(ValueError, "^attestation_copy_forbidden$"):
            copy(verified)

    def test_verified_ticket_is_single_use_and_concurrent(self):
        fake = FakeIssuer()
        boundary = AttestationRuntimeBoundary(fake, fake, fake, FakeCapabilityPolicy())
        verified = verify_credential_capability_attestation(signed(fake), request(boundary), boundary, NOW).verified
        assert verified is not None
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(lambda _: self._consume(boundary, verified), range(8)))
        self.assertEqual(sum(results), 1)
        self.assertFalse(hasattr(verified, "claims"))

    @staticmethod
    def _consume(boundary: AttestationRuntimeBoundary, verified: VerifiedCredentialCapabilityAttestation) -> int:
        try:
            boundary.consume_ticket(verified)
            return 1
        except ValueError as exc:
            if str(exc) == "attestation_replayed":
                return 0
            raise

    def test_missing_verifier_revocation_reader_and_attestation(self):
        fake = FakeIssuer()
        boundary = AttestationRuntimeBoundary(fake, fake, fake, FakeCapabilityPolicy())
        self.assertEqual(verify_credential_capability_attestation(None, request(boundary), boundary, NOW).failures[0].code, "attestation_missing")
        unavailable = AttestationRuntimeBoundary(None, fake, fake, FakeCapabilityPolicy())
        self.assertEqual(verify_credential_capability_attestation(signed(fake), request(unavailable), unavailable, NOW).failures[0].code, "attestation_verifier_unavailable")
        unavailable = AttestationRuntimeBoundary(fake, fake, None, FakeCapabilityPolicy())
        self.assertEqual(verify_credential_capability_attestation(signed(fake), request(unavailable), unavailable, NOW).failures[0].code, "attestation_revocation_unavailable")

    def test_request_is_runtime_owned(self):
        with self.assertRaisesRegex(ValueError, "^runtime_request_required$"):
            CredentialCapabilityRequest(
                "owner/repository", "subject-1", ("issues:write",), "driver", "authority",
                "preview-1", 1, "sha256:" + "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64,
            )

    def test_old_factories_are_absent_and_boundary_owns_request_and_ticket(self):
        self.assertFalse(hasattr(CredentialCapabilityRequest, "_create"))
        self.assertFalse(hasattr(VerifiedCredentialCapabilityAttestation, "_create"))
        fake = FakeIssuer()
        boundary_a = AttestationRuntimeBoundary(fake, fake, fake, FakeCapabilityPolicy())
        boundary_b = AttestationRuntimeBoundary(fake, fake, fake, FakeCapabilityPolicy())
        request_a = request(boundary_a)
        result = verify_credential_capability_attestation(signed(fake), request_a, boundary_a, NOW)
        self.assertTrue(result.success)
        assert result.verified is not None
        self.assertEqual(
            verify_credential_capability_attestation(signed(fake), request_a, boundary_b, NOW).failures[0].code,
            "attestation_request_unavailable",
        )
        with self.assertRaisesRegex(ValueError, "^attestation_boundary_mismatch$"):
            boundary_b.consume_ticket(result.verified)

    def test_fake_boundary_ticket_is_not_accepted_by_another_boundary(self):
        fake = FakeIssuer()
        boundary_a = AttestationRuntimeBoundary(fake, fake, fake, FakeCapabilityPolicy())
        boundary_b = AttestationRuntimeBoundary(fake, fake, fake, FakeCapabilityPolicy())
        ticket = verify_credential_capability_attestation(signed(fake), request(boundary_a), boundary_a, NOW).verified
        assert ticket is not None
        with self.assertRaisesRegex(ValueError, "^attestation_boundary_mismatch$"):
            boundary_b.consume_ticket(ticket)
        self.assertFalse(hasattr(ticket, "claims"))

    def test_fractional_and_equal_expiry_are_compared_as_datetimes(self):
        with self.assertRaisesRegex(ValueError, "^attestation_expiry_invalid$"):
            claims(issued_at="2026-08-14T12:00:00.100000Z", expires_at="2026-08-14T12:00:00Z")
        with self.assertRaisesRegex(ValueError, "^attestation_expiry_invalid$"):
            claims(issued_at="2026-08-14T12:00:00Z", expires_at="2026-08-14T12:00:00.000000+00:00")
        later = claims(issued_at="2026-08-14T12:00:00.100000Z", expires_at="2026-08-14T12:00:00.100001+00:00")
        self.assertEqual(later.issued_at, "2026-08-14T12:00:00.100000Z")
        self.assertEqual(later.expires_at, "2026-08-14T12:00:00.100001Z")

    def test_policy_closes_credential_class_and_empty_or_invalid_capabilities(self):
        fake = FakeIssuer()
        self.assertEqual(verify(fake, signed(fake, claims(credential_class="unknown-class"))).failures[0].code, "attestation_credential_class_unsupported")
        boundary = AttestationRuntimeBoundary(fake, fake, fake, FakeCapabilityPolicy())
        with self.assertRaisesRegex(ValueError, "^required_capabilities_missing$"):
            boundary.create_request(
                repository_identity="owner/repository", github_subject_identity="subject-1", required_capabilities=(),
                driver_identity="github-rest-driver-v1", remote_authority="sha256:" + "a" * 64,
                preview_id="preview-1", revision=1, operation_set_digest="sha256:" + "b" * 64,
                remote_snapshot_digest="sha256:" + "c" * 64, evidence_digest="sha256:" + "d" * 64,
            )
        with self.assertRaisesRegex(ValueError, "^granted_capabilities_invalid$"):
            claims(granted_capabilities=("Issues:Write",))

    def test_revocation_contract_version_malformed_and_future_status_fail_closed(self):
        fake = FakeIssuer()
        fake.revocation = RevocationStatus(version="2")
        self.assertEqual(verify(fake).failures[0].code, "attestation_revocation_version_unsupported")
        fake.revocation = RevocationStatus(attestation_revoked=True, revoked_at="2026-08-14T13:00:00Z", reason="operator")
        self.assertEqual(verify(fake).failures[0].code, "attestation_revocation_invalid")

        class MalformedReader:
            def read_status(self, *args: object) -> object:
                return object()

        boundary = AttestationRuntimeBoundary(fake, fake, MalformedReader(), FakeCapabilityPolicy())
        self.assertEqual(
            verify_credential_capability_attestation(signed(fake), request(boundary), boundary, NOW).failures[0].code,
            "attestation_revocation_invalid",
        )

    def test_revocation_reader_exception_has_distinct_stable_code(self):
        fake = FakeIssuer()

        class BrokenReader:
            def read_status(self, *args: object) -> RevocationStatus:
                raise RuntimeError(SENTINEL)

        boundary = AttestationRuntimeBoundary(fake, fake, BrokenReader(), FakeCapabilityPolicy())
        result = verify_credential_capability_attestation(signed(fake), request(boundary), boundary, NOW)
        self.assertEqual(result.failures[0].code, "attestation_revocation_unavailable")
        self.assertNotIn(SENTINEL, repr(result.to_dict()))

    def test_proof_is_exact_base64url_without_text_normalization(self):
        fake = FakeIssuer()
        envelope = signed(fake)
        noncanonical = envelope.proof[:-1] + ("B" if envelope.proof[-1] != "B" else "C")
        for bad in (
            " " + envelope.proof, envelope.proof + " ", envelope.proof + "\n", "é" + envelope.proof,
            envelope.proof + "=", noncanonical,
            base64.urlsafe_b64encode(b"X" * 63).decode("ascii").rstrip("="),
            base64.urlsafe_b64encode(b"X" * 65).decode("ascii").rstrip("="),
            "A" * 4097,
        ):
            with self.subTest(bad=repr(bad[:12])):
                with self.assertRaisesRegex(ValueError, "^proof_invalid$"):
                    SignedCredentialCapabilityAttestation(envelope.claims, bad)

    def test_cr_at2_private_bypass_names_are_absent_and_unregistered_objects_fail(self):
        self.assertFalse(hasattr(AttestationRuntimeBoundary, "_issue_ticket"))
        self.assertFalse(hasattr(CredentialCapabilityRequest, "_initialize"))
        self.assertFalse(hasattr(VerifiedCredentialCapabilityAttestation, "_initialize"))
        self.assertFalse(hasattr(VerifiedCredentialCapabilityAttestation, "_consume_for"))
        self.assertFalse(hasattr(CredentialCapabilityRequest, "_create"))
        self.assertFalse(hasattr(VerifiedCredentialCapabilityAttestation, "_create"))
        fake = FakeIssuer()
        boundary = AttestationRuntimeBoundary(fake, fake, fake, FakeCapabilityPolicy())
        fake_ticket = object.__new__(VerifiedCredentialCapabilityAttestation)
        with self.assertRaisesRegex(ValueError, "^attestation_boundary_mismatch$"):
            boundary.consume_ticket(fake_ticket)
        fake_request = object.__new__(CredentialCapabilityRequest)
        result = verify_credential_capability_attestation(signed(fake), fake_request, boundary, NOW)
        self.assertEqual(result.failures[0].code, "attestation_request_unavailable")

    def test_request_is_read_only_and_snapshot_rejects_provider_mutation(self):
        fake = FakeIssuer()
        boundary = AttestationRuntimeBoundary(fake, fake, fake, FakeCapabilityPolicy())
        candidate = request(boundary)
        fields = (
            "repository_identity", "github_subject_identity", "required_capabilities", "driver_identity",
            "remote_authority", "preview_id", "revision", "operation_set_digest",
            "remote_snapshot_digest", "evidence_digest",
        )
        for field in fields:
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "^runtime_request_immutable$"):
                    setattr(candidate, field, "issues:read" if field == "required_capabilities" else "changed")
        object.__setattr__(candidate, "required_capabilities", ("issues:read",))
        result = verify_credential_capability_attestation(signed(fake), candidate, boundary, NOW)
        self.assertEqual(result.failures[0].code, "attestation_request_tampered")

    def test_capability_policy_is_closed_and_failures_are_distinct(self):
        fake = FakeIssuer()
        policy = FakeCapabilityPolicy()
        policy.supported.remove("issues:write")
        boundary = AttestationRuntimeBoundary(fake, fake, fake, policy)
        with self.assertRaisesRegex(ValueError, "^credential_capability_unknown$"):
            request(boundary)
        missing = AttestationRuntimeBoundary(fake, fake, fake, None)
        with self.assertRaisesRegex(ValueError, "^attestation_capability_policy_unavailable$"):
            request(missing)
        broken = FakeCapabilityPolicy()
        broken.raise_error = True
        boundary = AttestationRuntimeBoundary(fake, fake, fake, broken)
        with self.assertRaisesRegex(ValueError, "^attestation_capability_policy_unavailable$"):
            request(boundary)
        broken = FakeCapabilityPolicy()
        broken.non_bool = True
        boundary = AttestationRuntimeBoundary(fake, fake, fake, broken)
        with self.assertRaisesRegex(ValueError, "^attestation_capability_policy_unavailable$"):
            request(boundary)

    def test_revocation_reader_receives_independent_contract_version(self):
        fake = FakeIssuer()
        seen: list[str] = []

        class Reader:
            def read_status(self, attestation_id: str, credential_instance_id: str, issuer_id: str, key_id: str, version: str) -> RevocationStatus:
                seen.append(version)
                return RevocationStatus()

        boundary = AttestationRuntimeBoundary(fake, fake, Reader(), FakeCapabilityPolicy())
        self.assertTrue(verify_credential_capability_attestation(signed(fake), request(boundary), boundary, NOW).success)
        self.assertEqual(seen, ["1"])

    def test_weak_registries_release_request_and_ticket_entries(self):
        fake = FakeIssuer()
        boundary = AttestationRuntimeBoundary(fake, fake, fake, FakeCapabilityPolicy())
        candidate = request(boundary)
        request_ref = weakref.ref(candidate)
        del candidate
        gc.collect()
        self.assertIsNone(request_ref())
        self.assertEqual(len(boundary._AttestationRuntimeBoundary__requests), 0)
        candidate = verify_credential_capability_attestation(signed(fake), request(boundary), boundary, NOW).verified
        assert candidate is not None
        ticket_ref = weakref.ref(candidate)
        del candidate
        gc.collect()
        self.assertIsNone(ticket_ref())
        self.assertEqual(len(boundary._AttestationRuntimeBoundary__tickets), 0)

    def test_typed_envelopes_are_reparsed_and_match_mapping_payload(self):
        fake = FakeIssuer()
        boundary = AttestationRuntimeBoundary(fake, fake, fake, FakeCapabilityPolicy())
        envelope = signed(fake)
        typed_result = verify_credential_capability_attestation(envelope, request(boundary), boundary, NOW)
        mapping_result = verify_credential_capability_attestation(
            {"claims": envelope.claims.to_payload()["claims"], "proof": envelope.proof},
            request(boundary), boundary, NOW,
        )
        self.assertTrue(typed_result.success)
        self.assertTrue(mapping_result.success)
        self.assertEqual(fake.payloads[-2], fake.payloads[-1])

    def test_typed_envelope_alias_and_object_new_bypass_fail_before_verifier(self):
        fake = FakeIssuer()
        boundary = AttestationRuntimeBoundary(fake, fake, fake, FakeCapabilityPolicy())
        envelope = signed(fake)
        decoded = base64.urlsafe_b64decode(envelope.proof + "==")
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        alias = next(
            candidate for candidate in (
                envelope.proof[:-1] + char for char in alphabet
            ) if candidate != envelope.proof and base64.urlsafe_b64decode(candidate + "==") == decoded
        )
        self.assertEqual(base64.urlsafe_b64decode(envelope.proof + "=="), base64.urlsafe_b64decode(alias + "=="))
        self.assertNotEqual(envelope.proof, alias)
        forged = object.__new__(SignedCredentialCapabilityAttestation)
        object.__setattr__(forged, "claims", envelope.claims)
        object.__setattr__(forged, "proof", alias)
        result = verify_credential_capability_attestation(forged, request(boundary), boundary, NOW)
        self.assertEqual(result.failures[0].code, "proof_invalid")
        self.assertEqual(fake.proofs, [])

        class ClaimsChild(CredentialCapabilityAttestationClaims):
            pass

        child = ClaimsChild(**envelope.claims.to_payload()["claims"])
        child_envelope = object.__new__(SignedCredentialCapabilityAttestation)
        object.__setattr__(child_envelope, "claims", child)
        object.__setattr__(child_envelope, "proof", envelope.proof)
        self.assertTrue(verify_credential_capability_attestation(child_envelope, request(boundary), boundary, NOW).success)

        malformed = object.__new__(SignedCredentialCapabilityAttestation)
        result = verify_credential_capability_attestation(malformed, request(boundary), boundary, NOW)
        self.assertEqual(result.failures[0].code, "attestation_invalid")

    def test_proof_length_is_rejected_before_decoder(self):
        fake = FakeIssuer()
        envelope = signed(fake)
        self.assertEqual(len(envelope.proof), 86)
        for bad in (envelope.proof[:-1], envelope.proof + "A", "A" * 4097):
            with self.subTest(length=len(bad)):
                with patch.object(attestation_module.base64, "urlsafe_b64decode", side_effect=AssertionError("decoder-called")):
                    with self.assertRaisesRegex(ValueError, "^proof_invalid$"):
                        SignedCredentialCapabilityAttestation(envelope.claims, bad)

    def test_malformed_typed_revocation_is_revalidated(self):
        fake = FakeIssuer()

        class Reader:
            def __init__(self, status: RevocationStatus) -> None:
                self.status = status

            def read_status(self, *args: object) -> RevocationStatus:
                return self.status

        cases: list[tuple[str, dict[str, object]]] = [
            ("invalid", {"attestation_revoked": False, "credential_instance_revoked": False, "revoked_at": "2026-08-14T11:00:00Z", "reason": None, "version": "1"}),
            ("missing", {"attestation_revoked": True, "credential_instance_revoked": False, "revoked_at": None, "reason": None, "version": "1"}),
            ("future", {"attestation_revoked": True, "credential_instance_revoked": False, "revoked_at": "2026-08-14T13:00:00Z", "reason": "operator", "version": "1"}),
        ]
        for _, fields in cases:
            with self.subTest(fields=fields):
                status = object.__new__(RevocationStatus)
                for field, value in fields.items():
                    object.__setattr__(status, field, value)
                boundary = AttestationRuntimeBoundary(fake, fake, Reader(status), FakeCapabilityPolicy())
                result = verify_credential_capability_attestation(signed(fake), request(boundary), boundary, NOW)
                self.assertEqual(result.failures[0].code, "attestation_revocation_invalid")

        status = object.__new__(RevocationStatus)
        for field, value in {
            "attestation_revoked": False, "credential_instance_revoked": False,
            "revoked_at": None, "reason": None, "version": "2",
        }.items():
            object.__setattr__(status, field, value)
        boundary = AttestationRuntimeBoundary(fake, fake, Reader(status), FakeCapabilityPolicy())
        result = verify_credential_capability_attestation(signed(fake), request(boundary), boundary, NOW)
        self.assertEqual(result.failures[0].code, "attestation_revocation_version_unsupported")

    def test_malformed_typed_issuer_decision_is_unavailable(self):
        fake = FakeIssuer()

        class Policy:
            def evaluate(self, *args: object) -> object:
                decision = object.__new__(IssuerTrustDecision)
                object.__setattr__(decision, "accepted", "yes")
                return decision

        boundary = AttestationRuntimeBoundary(Policy(), fake, fake, FakeCapabilityPolicy())
        result = verify_credential_capability_attestation(signed(fake), request(boundary), boundary, NOW)
        self.assertEqual(result.failures[0].code, "attestation_verifier_unavailable")


if __name__ == "__main__":
    unittest.main()
