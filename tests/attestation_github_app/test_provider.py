from __future__ import annotations

from datetime import datetime, timezone, tzinfo
import base64
import hashlib
import json
import unittest
from collections.abc import Mapping

from delivery_system.attestation import AttestationRuntimeBoundary, CredentialCapabilityRequest, IssuerTrustDecision
from delivery_system.attestation_github_app import (
    GitHubAppCapabilityProviderError,
    GitHubAppCredentialCapabilityProvider,
    GitHubAppInstallationCapabilityEvidence,
    GitHubAppInstallationEvidenceRequest,
)
from delivery_system.protocol import canonical_payload, digest


NOW = datetime(2026, 8, 14, 12, tzinfo=timezone.utc)
HEX = "a" * 32


def raw_evidence(instance="credential-instance-" + HEX, **changes):
    value = {
        "app_id": 12345, "installation_id": 67890, "installation_account_identity": "installation-account",
        "repository_id": 42, "repository_identity": "owner/repo", "repository_scope": ("owner/repo",),
        "effective_permissions": {"issues": "write"}, "expires_at": "2026-08-14T13:00:00Z",
        "observed_at": "2026-08-14T11:00:00Z", "credential_instance_id": instance,
    }
    value.update(changes)
    return value


class Source:
    def __init__(self, value=None, error=None):
        self.value, self.error, self.requests = value, error, []

    def obtain(self, request):
        self.requests.append(request)
        if self.error:
            raise self.error
        return self.value


class PassiveMapping(Mapping):
    def __init__(self, value):
        self.value = dict(value)

    def __getitem__(self, key):
        return self.value[key]

    def __iter__(self):
        return iter(self.value)

    def __len__(self):
        return len(self.value)


class RaisingMapping(Mapping):
    def __init__(self, error):
        self.error = error

    def __getitem__(self, key):
        raise self.error

    def __iter__(self):
        raise self.error

    def __len__(self):
        return 1


class AdversarialEvidence(GitHubAppInstallationCapabilityEvidence):
    def __getattribute__(self, name):
        if name == "repository_identity":
            raise GitHubAppCapabilityProviderError("RAW_TOKEN_SENTINEL")
        return super().__getattribute__(name)


class EvilInt(int):
    def __lt__(self, other):
        raise GitHubAppCapabilityProviderError("RAW_TOKEN_SENTINEL")


class EvilStr(str):
    def strip(self, *args, **kwargs):
        raise GitHubAppCapabilityProviderError("RAW_TOKEN_SENTINEL")


class EvilDateTime(datetime):
    def utcoffset(self):
        raise GitHubAppCapabilityProviderError("RAW_TOKEN_SENTINEL")


class EvilTZ(tzinfo):
    def __init__(self, error):
        self.error = error

    def utcoffset(self, dt):
        raise self.error


class EvilList(list):
    def __len__(self):
        raise GitHubAppCapabilityProviderError("RAW_TOKEN_SENTINEL")

    def __getitem__(self, key):
        raise GitHubAppCapabilityProviderError("RAW_TOKEN_SENTINEL")


class EvilTuple(tuple):
    def __len__(self):
        raise GitHubAppCapabilityProviderError("RAW_TOKEN_SENTINEL")

    def __iter__(self):
        raise GitHubAppCapabilityProviderError("RAW_TOKEN_SENTINEL")


class EvilMapping(Mapping):
    def __getitem__(self, key):
        raise GitHubAppCapabilityProviderError("RAW_TOKEN_SENTINEL")

    def __iter__(self):
        raise GitHubAppCapabilityProviderError("RAW_TOKEN_SENTINEL")

    def __len__(self):
        raise GitHubAppCapabilityProviderError("RAW_TOKEN_SENTINEL")


class Signer:
    issuer_id = "host-issuer"
    key_id = "host-key"
    signature_algorithm = "ed25519"

    def __init__(self, error=None):
        self.error, self.payloads = error, []

    def sign(self, payload):
        self.payloads.append(payload)
        if self.error:
            raise self.error
        return base64.urlsafe_b64encode(hashlib.sha512(payload).digest()).decode().rstrip("=")


class EvilMetadataSigner(Signer):
    @property
    def issuer_id(self):
        return EvilStr("host-issuer")


class EvilProofSigner(Signer):
    def sign(self, payload):
        return EvilStr("proof")


class RaisingSigner(Signer):
    @property
    def issuer_id(self):
        raise RuntimeError("RAW_TOKEN_SENTINEL")


class CapabilityPolicy:
    def is_supported(self, capability):
        return capability in {"issues:write", "issues:read"}


def request(boundary, required=("issues:write",), subject="human-subject", driver="driver"):
    return boundary.create_request(
        repository_identity="owner/repo", github_subject_identity=subject,
        required_capabilities=required, driver_identity=driver,
        remote_authority=digest({"authority": "remote"}), preview_id="preview-" + HEX,
        revision=1, operation_set_digest=digest({"operations": 1}),
        remote_snapshot_digest=digest({"snapshot": 1}), evidence_digest=digest({"evidence": 1}),
    )


class ProviderTests(unittest.TestCase):
    def make(self, value=None, signer=None, instance="credential-instance-" + HEX):
        source = Source(value if value is not None else raw_evidence(instance))
        signer = signer or Signer()
        provider = GitHubAppCredentialCapabilityProvider(
            source, signer, clock=lambda: NOW,
            credential_instance_id_factory=lambda: instance,
            nonce_factory=lambda: "nonce-" + HEX,
        )
        return provider, source, signer

    def setUp(self):
        self.boundary = AttestationRuntimeBoundary(None, None, None, CapabilityPolicy())
        self.boundary.create_request  # establish the Runtime-owned factory boundary

    def test_write_read_and_missing_permissions(self):
        for permissions, expected in (({"issues": "write"}, ("issues:write",)), ({"issues": "read"}, ()), ({}, ())):
            with self.subTest(permissions=permissions):
                provider, _, _ = self.make(raw_evidence(effective_permissions=permissions))
                result = provider.attest(request(self.boundary))
                self.assertEqual(result.claims.granted_capabilities, expected)

    def test_unsupported_requirement_and_scope_or_expiry_fail_closed(self):
        provider, _, _ = self.make(raw_evidence())
        with self.assertRaises(GitHubAppCapabilityProviderError):
            provider.attest(request(self.boundary, ("issues:read",)))
        for change in ({"repository_scope": ("other/repo",)}, {"repository_identity": "other/repo"}, {"expires_at": "2026-08-14T12:00:00Z"}, {"observed_at": "2026-08-14T12:01:00Z"}):
            with self.subTest(change=change):
                provider, _, _ = self.make(raw_evidence(**change))
                with self.assertRaises(GitHubAppCapabilityProviderError):
                    provider.attest(request(self.boundary))

    def test_identity_instance_challenge_and_source_digest(self):
        provider, source, _ = self.make(raw_evidence())
        issued_request = request(self.boundary, subject="acting-human")
        result = provider.attest(issued_request)
        claims = result.claims
        self.assertEqual(claims.github_subject_identity, "acting-human")
        self.assertEqual(claims.credential_principal_identity, "github-app-installation-12345-67890")
        self.assertEqual(claims.credential_instance_id, "credential-instance-" + HEX)
        self.assertEqual(claims.challenge_digest, issued_request.challenge_digest)
        self.assertIsInstance(source.requests[0], GitHubAppInstallationEvidenceRequest)
        self.assertFalse(hasattr(source.requests[0], "challenge_value"))

        provider2, _, _ = self.make(raw_evidence(installation_id=67891))
        self.assertNotEqual(claims.source_verification_digest, provider2.attest(request(self.boundary)).claims.source_verification_digest)
        provider3, _, _ = self.make(raw_evidence())
        repeat_a = provider3.attest(issued_request).claims.source_verification_digest
        repeat_b = provider3.attest(issued_request).claims.source_verification_digest
        self.assertEqual(repeat_a, repeat_b)
        provider4, _, _ = self.make(raw_evidence())
        changed_binding = provider4.attest(request(self.boundary, driver="other-driver"))
        self.assertNotEqual(claims.source_verification_digest, changed_binding.claims.source_verification_digest)

    def test_provider_accepts_normalized_evidence_object(self):
        provider, source, _ = self.make()
        source.value = __import__("delivery_system.attestation_github_app", fromlist=["_normalize_evidence"])._normalize_evidence(source.value)
        result = provider.attest(request(self.boundary))
        self.assertEqual(result.claims.granted_capabilities, ("issues:write",))

    def test_provider_snapshots_non_dict_mapping(self):
        provider, source, _ = self.make(PassiveMapping(raw_evidence()))
        result = provider.attest(request(self.boundary))
        self.assertEqual(result.claims.granted_capabilities, ("issues:write",))

    def test_mapping_behavior_failure_is_redacted_for_both_exception_types(self):
        sentinel = "RAW_TOKEN_SENTINEL"
        for error in (
            GitHubAppCapabilityProviderError(sentinel),
            RuntimeError(sentinel),
        ):
            with self.subTest(error=type(error).__name__):
                provider, source, _ = self.make(RaisingMapping(error))
                with self.assertRaises(GitHubAppCapabilityProviderError) as ctx:
                    provider.attest(request(self.boundary))
                self.assertEqual(str(ctx.exception), "github_app_capability_provider_failed")
                self.assertNotIn(sentinel, str(ctx.exception))
                self.assertNotIn(sentinel, repr(ctx.exception))
                self.assertNotIn(sentinel, repr(provider))

    def test_evidence_subclass_is_rejected_without_field_access(self):
        base = raw_evidence()
        subclass = AdversarialEvidence(**base)
        provider, source, _ = self.make(subclass)
        with self.assertRaises(GitHubAppCapabilityProviderError) as ctx:
            provider.attest(request(self.boundary))
        self.assertEqual(str(ctx.exception), "evidence_shape_invalid")
        self.assertNotIn("RAW_TOKEN_SENTINEL", str(ctx.exception))
        self.assertNotIn("RAW_TOKEN_SENTINEL", repr(ctx.exception))
        self.assertNotIn("RAW_TOKEN_SENTINEL", repr(provider))

    def test_evidence_primitive_and_nested_container_subclasses_are_rejected(self):
        cases = (
            {"app_id": EvilInt(12345)},
            {"installation_account_identity": EvilStr("installation-account")},
            {"repository_scope": EvilList(["owner/repo"])},
            {"repository_scope": EvilTuple(("owner/repo",))},
            {"effective_permissions": EvilMapping()},
            {"effective_permissions": EvilTuple((("issues", "write"),))},
        )
        for change in cases:
            with self.subTest(change=change):
                provider, _, _ = self.make(raw_evidence(**change))
                with self.assertRaises(GitHubAppCapabilityProviderError) as ctx:
                    provider.attest(request(self.boundary))
                self.assertNotIn("RAW_TOKEN_SENTINEL", str(ctx.exception))
                self.assertNotIn("RAW_TOKEN_SENTINEL", repr(ctx.exception))
                self.assertNotIn("RAW_TOKEN_SENTINEL", repr(provider))

    def test_exact_dataclass_with_behavioral_field_is_rejected(self):
        values = raw_evidence()
        values["app_id"] = EvilInt(12345)
        evidence = GitHubAppInstallationCapabilityEvidence(**values)
        provider, _, _ = self.make(evidence)
        with self.assertRaises(GitHubAppCapabilityProviderError) as ctx:
            provider.attest(request(self.boundary))
        self.assertEqual(str(ctx.exception), "app_id_invalid")
        self.assertNotIn("RAW_TOKEN_SENTINEL", repr(ctx.exception))
        self.assertNotIn("RAW_TOKEN_SENTINEL", repr(provider))

    def test_injected_outputs_use_exact_type_validation(self):
        provider, _, _ = self.make()
        provider = GitHubAppCredentialCapabilityProvider(
            Source(raw_evidence()), Signer(),
            clock=lambda: EvilDateTime(2026, 8, 14, 12, tzinfo=timezone.utc),
            credential_instance_id_factory=lambda: EvilStr("credential-instance-" + HEX),
            nonce_factory=lambda: "nonce-" + HEX,
        )
        with self.assertRaises(GitHubAppCapabilityProviderError) as ctx:
            provider.attest(request(self.boundary))
        self.assertEqual(str(ctx.exception), "credential_instance_id_invalid")
        self.assertNotIn("RAW_TOKEN_SENTINEL", repr(ctx.exception))

        provider = GitHubAppCredentialCapabilityProvider(
            Source(raw_evidence()), Signer(),
            clock=lambda: EvilDateTime(2026, 8, 14, 12, tzinfo=timezone.utc),
            credential_instance_id_factory=lambda: "credential-instance-" + HEX,
            nonce_factory=lambda: "nonce-" + HEX,
        )
        with self.assertRaises(GitHubAppCapabilityProviderError) as ctx:
            provider.attest(request(self.boundary))
        self.assertEqual(str(ctx.exception), "provider_clock_invalid")
        self.assertNotIn("RAW_TOKEN_SENTINEL", repr(ctx.exception))

    def test_exact_datetime_requires_provider_trusted_utc_tzinfo(self):
        for error in (
            GitHubAppCapabilityProviderError("RAW_TOKEN_SENTINEL"),
            RuntimeError("RAW_TOKEN_SENTINEL"),
        ):
            with self.subTest(error=type(error).__name__):
                clock_value = datetime(2026, 8, 14, 12, tzinfo=EvilTZ(error))
                self.assertIs(type(clock_value), datetime)
                provider = GitHubAppCredentialCapabilityProvider(
                    Source(raw_evidence()), Signer(), clock=lambda: clock_value,
                    credential_instance_id_factory=lambda: "credential-instance-" + HEX,
                    nonce_factory=lambda: "nonce-" + HEX,
                )
                with self.assertRaises(GitHubAppCapabilityProviderError) as ctx:
                    provider.attest(request(self.boundary))
                self.assertEqual(str(ctx.exception), "provider_clock_invalid")
                self.assertNotIn("RAW_TOKEN_SENTINEL", str(ctx.exception))
                self.assertNotIn("RAW_TOKEN_SENTINEL", repr(ctx.exception))
                self.assertNotIn("RAW_TOKEN_SENTINEL", repr(provider))

    def test_exact_utc_datetime_clock_still_succeeds(self):
        provider = GitHubAppCredentialCapabilityProvider(
            Source(raw_evidence()), Signer(), clock=lambda: NOW,
            credential_instance_id_factory=lambda: "credential-instance-" + HEX,
            nonce_factory=lambda: "nonce-" + HEX,
        )
        result = provider.attest(request(self.boundary))
        self.assertEqual(result.claims.issued_at, "2026-08-14T12:00:00Z")

    def test_signer_metadata_and_proof_require_exact_strings(self):
        provider = GitHubAppCredentialCapabilityProvider(
            Source(raw_evidence()), EvilMetadataSigner(), clock=lambda: NOW,
            credential_instance_id_factory=lambda: "credential-instance-" + HEX,
            nonce_factory=lambda: "nonce-" + HEX,
        )
        with self.assertRaises(GitHubAppCapabilityProviderError) as ctx:
            provider.attest(request(self.boundary))
        self.assertEqual(str(ctx.exception), "issuer_id_invalid")
        self.assertNotIn("RAW_TOKEN_SENTINEL", repr(ctx.exception))

        provider = GitHubAppCredentialCapabilityProvider(
            Source(raw_evidence()), EvilProofSigner(), clock=lambda: NOW,
            credential_instance_id_factory=lambda: "credential-instance-" + HEX,
            nonce_factory=lambda: "nonce-" + HEX,
        )
        with self.assertRaises(GitHubAppCapabilityProviderError) as ctx:
            provider.attest(request(self.boundary))
        self.assertEqual(str(ctx.exception), "github_app_capability_provider_failed")
        self.assertNotIn("RAW_TOKEN_SENTINEL", repr(ctx.exception))

    def test_instance_mismatch_and_source_or_signer_details_are_redacted(self):
        sentinel = "RAW_TOKEN_SENTINEL"
        provider, _, _ = self.make(raw_evidence(instance="credential-instance-" + "b" * 32))
        with self.assertRaises(GitHubAppCapabilityProviderError) as ctx:
            provider.attest(request(self.boundary))
        self.assertNotIn(sentinel, repr(ctx.exception))
        for source_error, signer in (
            (RuntimeError(sentinel), Signer()),
            (GitHubAppCapabilityProviderError(sentinel), Signer()),
            (None, Signer(RuntimeError(sentinel))),
            (None, Signer(GitHubAppCapabilityProviderError(sentinel))),
            (None, RaisingSigner()),
        ):
            source = Source(raw_evidence(), source_error)
            provider = GitHubAppCredentialCapabilityProvider(source, signer, clock=lambda: NOW,
                credential_instance_id_factory=lambda: "credential-instance-" + HEX,
                nonce_factory=lambda: "nonce-" + HEX)
            with self.assertRaises(GitHubAppCapabilityProviderError) as ctx:
                provider.attest(request(self.boundary))
            self.assertNotIn(sentinel, str(ctx.exception) + repr(ctx.exception) + repr(provider))

    def test_injected_clock_failure_is_redacted(self):
        source = Source(raw_evidence())
        provider = GitHubAppCredentialCapabilityProvider(
            source, Signer(), clock=lambda: (_ for _ in ()).throw(RuntimeError("RAW_TOKEN_SENTINEL")),
            credential_instance_id_factory=lambda: "credential-instance-" + HEX,
            nonce_factory=lambda: "nonce-" + HEX,
        )
        with self.assertRaises(GitHubAppCapabilityProviderError) as ctx:
            provider.attest(request(self.boundary))
        self.assertNotIn("RAW_TOKEN_SENTINEL", str(ctx.exception))
        self.assertNotIn("RAW_TOKEN_SENTINEL", repr(ctx.exception))
        self.assertNotIn("RAW_TOKEN_SENTINEL", repr(provider))

    def test_serialized_attestation_has_no_secret_sentinel_and_v2_claims(self):
        sentinel = "RAW_TOKEN_SENTINEL"
        provider, _, _ = self.make(raw_evidence(access_token=sentinel))
        with self.assertRaises(GitHubAppCapabilityProviderError) as ctx:
            provider.attest(request(self.boundary))
        self.assertNotIn(sentinel, str(ctx.exception) + repr(ctx.exception) + repr(provider))
        provider, _, _ = self.make(raw_evidence())
        result = provider.attest(request(self.boundary))
        serialized = json.dumps({"claims": result.claims.to_payload(), "proof": result.proof})
        self.assertNotIn("access_token", serialized)
        self.assertNotIn(sentinel, result.proof)
        self.assertEqual(result.claims.attestation_version, "2")


if __name__ == "__main__":
    unittest.main()
