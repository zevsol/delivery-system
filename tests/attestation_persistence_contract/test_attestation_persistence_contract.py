from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import copy, deepcopy
from datetime import datetime, timezone
import base64
import gc
import hashlib
import unittest

from delivery_system.attestation import CredentialCapabilityAttestationClaims
from delivery_system.attestation_persistence import (
    ARTIFACT_CONTENT_DOMAIN,
    ARTIFACT_ID_DOMAIN,
    ATTESTATION_REVALIDATION_FAILURE_CODES,
    EVENT_ID_DOMAIN,
    FUTURE_STORE_ERROR_CODES,
    REFERENCE_CONTENT_DOMAIN,
    REFERENCE_ID_DOMAIN,
    AttestationBindingReference,
    AttestationRevalidationEvent,
    PersistenceContractError,
    PersistedAttestationArtifact,
    RevalidationAttemptBoundary,
    validate_artifact_aggregate,
)
from delivery_system.protocol import _text as canonical_text
from delivery_system.protocol import canonical_payload, digest


DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
DIGEST_D = "sha256:" + "d" * 64
DIGEST_E = "sha256:" + "e" * 64
PROOF = base64.urlsafe_b64encode(b"p" * 64).decode("ascii").rstrip("=")


def expect_code(test: unittest.TestCase, code: str, callback) -> None:
    with test.assertRaises(PersistenceContractError) as raised:
        callback()
    test.assertEqual(raised.exception.code, code)


def make_claims(**changes: object) -> CredentialCapabilityAttestationClaims:
    values: dict[str, object] = {
        "attestation_version": "1",
        "attestation_id": "",
        "issuer_id": "issuer-1",
        "key_id": "key-1",
        "signature_algorithm": "ed25519",
        "credential_class": "github-app-installation-token",
        "credential_instance_id": "credential-instance-1",
        "github_subject_identity": "subject-node-1",
        "repository_identity": "owner/repository",
        "granted_capabilities": ("issues:read", "issues:write"),
        "driver_identity": "github-rest-driver-v1",
        "remote_authority": DIGEST_A,
        "preview_id": "preview-1",
        "revision": 1,
        "operation_set_digest": DIGEST_B,
        "remote_snapshot_digest": DIGEST_C,
        "evidence_digest": DIGEST_D,
        "issued_at": "2026-08-14T11:00:00Z",
        "expires_at": "2026-08-14T13:00:00Z",
        "nonce": "nonce-1",
        "source_verification_digest": DIGEST_E,
    }
    values.update(changes)
    return CredentialCapabilityAttestationClaims(**values)  # type: ignore[arg-type]


def artifact_for(claims: CredentialCapabilityAttestationClaims | None = None, *, workspace: str = "workspace-1") -> PersistedAttestationArtifact:
    claims = claims or make_claims()
    workspace = canonical_text(workspace)
    claims_payload = claims.to_payload()
    original = "2026-08-14T11:30:00.000000Z"
    created = "2026-08-14T11:31:00.000000Z"
    content = {
        "domain": ARTIFACT_CONTENT_DOMAIN,
        "artifact_contract_version": "offline-attestation-artifact-v1",
        "workspace_identity": workspace,
        "attestation_id": claims.attestation_id,
        "claims_payload": claims_payload,
        "detached_proof": PROOF,
        "claims_digest": claims.claims_digest(),
        "original_verified_at": original,
        "created_at": created,
    }
    artifact_digest = digest(content)
    identity = {
        "domain": ARTIFACT_ID_DOMAIN,
        "payload": {"identity_version": "1", "workspace_identity": workspace, "attestation_id": claims.attestation_id},
    }
    artifact_id = "artifact-" + hashlib.sha256(canonical_payload(identity).encode("utf-8")).hexdigest()
    return PersistedAttestationArtifact(
        "offline-attestation-artifact-v1", artifact_id, workspace, claims.attestation_id,
        claims, PROOF, claims.claims_digest(), artifact_digest, original, created,
    )


def reference_for(artifact: PersistedAttestationArtifact, **changes: object) -> AttestationBindingReference:
    values: dict[str, object] = {
        "reference_contract_version": "attestation-binding-reference-v1",
        "reference_id": "",
        "workspace_identity": artifact.workspace_identity,
        "artifact_id": artifact.artifact_id,
        "artifact_digest": artifact.artifact_digest,
        "binding_id": "binding-" + "1" * 64,
        "repository_identity": "owner/repository",
        "github_subject_identity": "subject-node-1",
        "driver_identity": "github-rest-driver-v1",
        "remote_authority": DIGEST_A,
        "preview_id": "preview-1",
        "revision": 1,
        "plan_digest": DIGEST_B,
        "sealed_preview_digest": DIGEST_C,
        "operation_set_digest": artifact.claims_payload.operation_set_digest,
        "remote_snapshot_digest": artifact.claims_payload.remote_snapshot_digest,
        "audit_id": "audit-1",
        "audit_digest": DIGEST_A,
        "evidence_id": "evidence-1",
        "evidence_digest": artifact.claims_payload.evidence_digest,
        "original_verified_at": artifact.original_verified_at,
        "binding_reference_digest": "",
    }
    values.update(changes)
    for field in ("workspace_identity", "repository_identity", "github_subject_identity", "driver_identity", "preview_id", "audit_id", "evidence_id"):
        values[field] = canonical_text(values[field])
    content = {
        "domain": REFERENCE_CONTENT_DOMAIN,
        "reference_contract_version": "attestation-binding-reference-v1",
        **{key: values[key] for key in (
            "workspace_identity", "artifact_id", "artifact_digest", "binding_id",
            "repository_identity", "github_subject_identity", "driver_identity",
            "remote_authority", "preview_id", "revision", "plan_digest",
            "sealed_preview_digest", "operation_set_digest", "remote_snapshot_digest",
            "audit_id", "audit_digest", "evidence_id", "evidence_digest", "original_verified_at",
        )},
    }
    values["binding_reference_digest"] = digest(content)
    identity = {
        "domain": REFERENCE_ID_DOMAIN,
        "payload": {"reference_version": "1", "workspace_identity": values["workspace_identity"],
                    "artifact_id": values["artifact_id"], "binding_id": values["binding_id"]},
    }
    values["reference_id"] = "binding-reference-" + hashlib.sha256(canonical_payload(identity).encode("utf-8")).hexdigest()
    return AttestationBindingReference(**values)  # type: ignore[arg-type]


def event_for(artifact: PersistedAttestationArtifact, reference: AttestationBindingReference,
              attempt_id: str = "attempt-" + "1" * 32, **changes: object) -> AttestationRevalidationEvent:
    values: dict[str, object] = {
        "workspace_identity": artifact.workspace_identity,
        "artifact_id": artifact.artifact_id,
        "artifact_digest": artifact.artifact_digest,
        "revalidation_attempt_id": attempt_id,
        "revalidation_context_digest": DIGEST_C,
        "binding_reference_digest": reference.binding_reference_digest,
        "outcome": "Successful",
        "revalidated_at": "2026-08-14T12:00:00.000000Z",
        "failure_code": None,
        "result_digest": DIGEST_D,
    }
    values.update(changes)
    return AttestationRevalidationEvent.create(**values)  # type: ignore[arg-type]


class Entropy:
    def __init__(self, *values: bytes) -> None:
        self.values = list(values)

    def __call__(self, size: int) -> bytes:
        self.last_size = size
        return self.values.pop(0)


class FalseyEntropy:
    def __init__(self, value: bytes) -> None:
        self.value = value
        self.calls = 0

    def __bool__(self) -> bool:
        return False

    def __call__(self, size: int) -> bytes:
        self.calls += 1
        return self.value


class PersistenceDomainTests(unittest.TestCase):
    def test_artifact_reference_and_event_round_trip(self):
        artifact = artifact_for()
        reference = reference_for(artifact)
        event = event_for(artifact, reference)
        self.assertEqual(PersistedAttestationArtifact.from_untrusted(artifact.to_payload()), artifact)
        self.assertEqual(AttestationBindingReference.from_untrusted(reference.to_payload()), reference)
        self.assertEqual(AttestationRevalidationEvent.from_untrusted(event.to_payload()), event)
        validate_artifact_aggregate(artifact, reference)

    def test_artifact_and_reference_have_independent_digests(self):
        artifact = artifact_for()
        reference = reference_for(artifact)
        changed = reference_for(artifact, binding_id="binding-" + "2" * 64)
        self.assertEqual(artifact.artifact_digest, artifact_for().artifact_digest)
        self.assertNotEqual(reference.binding_reference_digest, changed.binding_reference_digest)
        self.assertEqual(artifact.artifact_digest, artifact_for().artifact_digest)

    def test_exact_keysets_and_subclasses_fail(self):
        artifact = artifact_for()
        payload = artifact.to_payload()
        payload["extra"] = 1
        expect_code(self, "attestation_persistence_keyset_invalid", lambda: PersistedAttestationArtifact.from_untrusted(payload))
        payload = artifact.to_payload()
        payload["artifact_id"] = True
        expect_code(self, "attestation_persistence_payload_invalid", lambda: PersistedAttestationArtifact.from_untrusted(payload))

        class DictSubclass(dict):
            pass
        expect_code(self, "attestation_persistence_type_invalid", lambda: PersistedAttestationArtifact.from_untrusted(DictSubclass(artifact.to_payload())))

    def test_claims_json_list_converts_only_to_internal_tuple(self):
        artifact = artifact_for()
        payload = artifact.to_payload()
        self.assertIs(type(payload["claims_payload"]["claims"]["granted_capabilities"]), list)
        restored = PersistedAttestationArtifact.from_untrusted(payload)
        self.assertIs(type(restored.claims_payload.granted_capabilities), tuple)
        payload["claims_payload"]["claims"]["granted_capabilities"] = tuple(payload["claims_payload"]["claims"]["granted_capabilities"])
        expect_code(self, "attestation_persistence_type_invalid", lambda: PersistedAttestationArtifact.from_untrusted(payload))

    def test_object_new_and_field_tampering_are_revalidated(self):
        artifact = artifact_for()
        forged = object.__new__(PersistedAttestationArtifact)
        expect_code(self, "attestation_persistence_payload_invalid", lambda: PersistedAttestationArtifact.from_untrusted(forged))
        object.__setattr__(artifact, "artifact_digest", DIGEST_A)
        expect_code(self, "attestation_persistence_payload_invalid", lambda: PersistedAttestationArtifact.from_untrusted(artifact))

    def test_reference_and_event_typed_tampering_is_revalidated(self):
        artifact = artifact_for()
        reference = reference_for(artifact)
        event = event_for(artifact, reference)
        object.__setattr__(reference, "artifact_digest", DIGEST_E)
        object.__setattr__(event, "event_payload_digest", DIGEST_E)
        expect_code(self, "attestation_persistence_payload_invalid", lambda: AttestationBindingReference.from_untrusted(reference))
        expect_code(self, "attestation_persistence_payload_invalid", lambda: AttestationRevalidationEvent.from_untrusted(event))
        forged_reference = object.__new__(AttestationBindingReference)
        forged_event = object.__new__(AttestationRevalidationEvent)
        expect_code(self, "attestation_persistence_payload_invalid", lambda: AttestationBindingReference.from_untrusted(forged_reference))
        expect_code(self, "attestation_persistence_payload_invalid", lambda: AttestationRevalidationEvent.from_untrusted(forged_event))

    def test_subclasses_and_noncanonical_proof_fail(self):
        artifact = artifact_for()

        class TextSubclass(str):
            pass

        class IntegerSubclass(int):
            pass

        payload = artifact.to_payload()
        payload["workspace_identity"] = TextSubclass("workspace-1")
        expect_code(self, "attestation_persistence_type_invalid", lambda: PersistedAttestationArtifact.from_untrusted(payload))
        payload = artifact.to_payload()
        payload["claims_payload"]["claims"]["revision"] = IntegerSubclass(1)
        expect_code(self, "attestation_persistence_type_invalid", lambda: PersistedAttestationArtifact.from_untrusted(payload))
        payload = artifact.to_payload()
        payload["detached_proof"] = " " + PROOF[:-1]
        expect_code(self, "attestation_persistence_payload_invalid", lambda: PersistedAttestationArtifact.from_untrusted(payload))
        payload = artifact.to_payload()
        payload["detached_proof"] = PROOF + "A"
        expect_code(self, "attestation_persistence_payload_invalid", lambda: PersistedAttestationArtifact.from_untrusted(payload))

    def test_reference_aggregate_mismatch_fails(self):
        artifact = artifact_for()
        reference = reference_for(artifact, workspace_identity="workspace-2")
        expect_code(self, "attestation_persistence_payload_invalid", lambda: validate_artifact_aggregate(artifact, reference))

    def test_aggregate_checks_every_shared_fact(self):
        artifact = artifact_for()
        shared = (
            "repository_identity", "github_subject_identity", "driver_identity", "remote_authority",
            "preview_id", "revision", "operation_set_digest", "remote_snapshot_digest",
            "evidence_digest", "original_verified_at",
        )
        changes = {
            "repository_identity": "other/repository",
            "github_subject_identity": "subject-node-2",
            "driver_identity": "other-driver",
            "remote_authority": DIGEST_E,
            "preview_id": "preview-2",
            "revision": 2,
            "operation_set_digest": DIGEST_E,
            "remote_snapshot_digest": DIGEST_E,
            "evidence_digest": DIGEST_E,
            "original_verified_at": "2026-08-14T11:31:00Z",
        }
        for field in shared:
            with self.subTest(field=field):
                reference = reference_for(artifact)
                object.__setattr__(reference, field, changes[field])
                expect_code(self, "attestation_persistence_payload_invalid", lambda: validate_artifact_aggregate(artifact, reference))

    def test_claims_envelope_domain_version_and_algorithm_are_closed(self):
        artifact = artifact_for()
        for field, value in (("domain", "evil-domain"), ("attestation_version", "2"), ("signature_algorithm", "rsa-sha256")):
            payload = artifact.to_payload()
            if field == "domain":
                payload["claims_payload"]["domain"] = value
            else:
                payload["claims_payload"]["claims"][field] = value
            with self.subTest(field=field):
                expect_code(self, "attestation_persistence_payload_invalid", lambda: PersistedAttestationArtifact.from_untrusted(payload))

    def test_artifact_historical_time_order_is_failure_closed(self):
        for changes in (
            {"issued_at": "2026-08-14T12:00:00Z"},
            {"expires_at": "2026-08-14T11:30:00Z"},
        ):
            with self.subTest(changes=changes):
                expect_code(self, "attestation_persistence_payload_invalid", lambda: artifact_for(make_claims(**changes)))
        artifact = artifact_for()
        object.__setattr__(artifact, "original_verified_at", "2026-08-14T10:30:00Z")
        expect_code(self, "attestation_persistence_payload_invalid", lambda: PersistedAttestationArtifact.from_untrusted(artifact))
        artifact = artifact_for()
        object.__setattr__(artifact, "created_at", "2026-08-14T11:00:00Z")
        expect_code(self, "attestation_persistence_payload_invalid", lambda: PersistedAttestationArtifact.from_untrusted(artifact))

    def test_derived_ids_and_digests_reject_string_subclasses(self):
        class TextSubclass(str):
            pass
        artifact = artifact_for()
        reference = reference_for(artifact)
        event = event_for(artifact, reference)
        for value, callback in (
            (TextSubclass(artifact.artifact_id), lambda: PersistedAttestationArtifact.from_untrusted(artifact)),
            (TextSubclass(artifact.artifact_digest), lambda: PersistedAttestationArtifact.from_untrusted(artifact)),
            (TextSubclass(reference.reference_id), lambda: AttestationBindingReference.from_untrusted(reference)),
            (TextSubclass(reference.binding_reference_digest), lambda: AttestationBindingReference.from_untrusted(reference)),
            (TextSubclass(event.event_id), lambda: AttestationRevalidationEvent.from_untrusted(event)),
            (TextSubclass(event.event_payload_digest), lambda: AttestationRevalidationEvent.from_untrusted(event)),
        ):
            with self.subTest(value=value):
                field = None
                if value == artifact.artifact_id:
                    field = "artifact_id"
                    target = artifact
                elif value == artifact.artifact_digest:
                    field = "artifact_digest"
                    target = artifact
                elif value == reference.reference_id:
                    field = "reference_id"
                    target = reference
                elif value == reference.binding_reference_digest:
                    field = "binding_reference_digest"
                    target = reference
                elif value == event.event_id:
                    field = "event_id"
                    target = event
                else:
                    field = "event_payload_digest"
                    target = event
                object.__setattr__(target, field, value)
                expect_code(self, "attestation_persistence_payload_invalid", callback)

    def test_canonical_text_is_stored_before_identity_and_digest(self):
        artifact = artifact_for(workspace="  workspace-1  ")
        self.assertEqual(artifact.workspace_identity, "workspace-1")
        self.assertEqual(artifact.artifact_id, artifact_for().artifact_id)
        self.assertEqual(artifact.artifact_digest, artifact_for().artifact_digest)
        nfc = artifact_for(workspace="e\u0301")
        composed = artifact_for(workspace="\u00e9")
        self.assertEqual(nfc.workspace_identity, composed.workspace_identity)
        self.assertEqual(nfc.artifact_id, composed.artifact_id)
        self.assertEqual(nfc.artifact_digest, composed.artifact_digest)

        reference = reference_for(artifact, repository_identity="  owner/repository  ",
                                 github_subject_identity="  subject-node-1  ",
                                 driver_identity="  github-rest-driver-v1  ",
                                 preview_id="  preview-1  ", audit_id="  audit-1  ", evidence_id="  evidence-1  ")
        self.assertEqual(reference.repository_identity, "owner/repository")
        self.assertEqual(reference.github_subject_identity, "subject-node-1")
        self.assertEqual(reference.driver_identity, "github-rest-driver-v1")
        self.assertEqual(reference.preview_id, "preview-1")
        self.assertEqual(reference.audit_id, "audit-1")
        self.assertEqual(reference.evidence_id, "evidence-1")
        event = event_for(artifact, reference, **{"revalidated_at": "2026-08-14T12:00:00Z"})
        self.assertEqual(event.workspace_identity, "workspace-1")
        boundary = RevalidationAttemptBoundary(Entropy(b"j" * 16))
        attempt = boundary.create_attempt("  workspace-1  ", artifact.artifact_id)
        self.assertEqual(attempt.workspace_identity, "workspace-1")

    def test_whitespace_only_text_is_rejected(self):
        artifact = artifact_for()
        expect_code(self, "attestation_persistence_payload_invalid", lambda: AttestationRevalidationEvent.create(
            workspace_identity="   ", artifact_id=artifact.artifact_id, artifact_digest=artifact.artifact_digest,
            revalidation_attempt_id="attempt-" + "1" * 32, revalidation_context_digest=DIGEST_A,
            binding_reference_digest=DIGEST_B, outcome="Successful", revalidated_at="2026-08-14T12:00:00Z",
            result_digest=DIGEST_C,
        ))
        expect_code(self, "attestation_persistence_payload_invalid", lambda: RevalidationAttemptBoundary(Entropy(b"k" * 16)).create_attempt("   ", artifact.artifact_id))

    def test_reference_remote_authority_is_strict_digest(self):
        artifact = artifact_for()
        invalid = ("api.github.com", "SHA256:" + "a" * 64, " " + DIGEST_A,
                   DIGEST_A + " ", "sha256:" + "a" * 63, "sha256:" + "A" * 64)
        for value in invalid:
            with self.subTest(value=value):
                expect_code(self, "attestation_persistence_payload_invalid", lambda: reference_for(artifact, remote_authority=value))
        class TextSubclass(str):
            pass
        expect_code(self, "attestation_persistence_payload_invalid", lambda: reference_for(artifact, remote_authority=TextSubclass(DIGEST_A)))
        self.assertEqual(reference_for(artifact, remote_authority=DIGEST_A).remote_authority, DIGEST_A)

    def test_event_success_and_all_failed_codes(self):
        artifact = artifact_for()
        reference = reference_for(artifact)
        successful = event_for(artifact, reference)
        self.assertEqual(successful.outcome, "Successful")
        for code in sorted(ATTESTATION_REVALIDATION_FAILURE_CODES):
            failed = event_for(artifact, reference, attempt_id="attempt-" + (str(len(code)) * 32)[:32],
                               outcome="Failed", failure_code=code, result_digest=None)
            self.assertEqual(failed.outcome, "Failed")
            self.assertIsNone(failed.result_digest)
        expect_code(self, "attestation_persistence_payload_invalid", lambda: event_for(artifact, reference, outcome="Failed", failure_code="attestation_artifact_aggregate_corrupt", result_digest=None))
        expect_code(self, "attestation_persistence_payload_invalid", lambda: event_for(artifact, reference, outcome="Failed", failure_code="attestation_attempt_replayed", result_digest=None))
        expect_code(self, "attestation_persistence_payload_invalid", lambda: event_for(artifact, reference, failure_code="unknown", result_digest=DIGEST_D))
        expect_code(self, "attestation_persistence_payload_invalid", lambda: event_for(artifact, reference, outcome="Successful", failure_code="attestation_signature_invalid"))
        expect_code(self, "attestation_persistence_payload_invalid", lambda: event_for(artifact, reference, outcome="Failed", failure_code="attestation_signature_invalid", result_digest=DIGEST_D))

    def test_event_id_is_attempt_scoped_and_payload_digest_is_not(self):
        artifact = artifact_for()
        reference = reference_for(artifact)
        first = event_for(artifact, reference, attempt_id="attempt-" + "1" * 32)
        changed = event_for(artifact, reference, attempt_id="attempt-" + "1" * 32, revalidated_at="2026-08-14T12:01:00Z")
        other = event_for(artifact, reference, attempt_id="attempt-" + "2" * 32)
        self.assertEqual(first.event_id, changed.event_id)
        self.assertNotEqual(first.event_payload_digest, changed.event_payload_digest)
        self.assertNotEqual(first.event_id, other.event_id)
        self.assertNotIn("event_sequence", first.to_payload())

    def test_public_projections_revalidate_forged_and_tampered_objects(self):
        artifact = artifact_for()
        reference = reference_for(artifact)
        event = event_for(artifact, reference)
        for model, method in ((PersistedAttestationArtifact, "to_payload"),
                              (AttestationBindingReference, "content_payload"),
                              (AttestationRevalidationEvent, "to_payload")):
            forged = object.__new__(model)
            with self.subTest(model=model.__name__):
                expect_code(self, "attestation_persistence_payload_invalid", lambda: getattr(forged, method)())
        forged_attempt = object.__new__(type(RevalidationAttemptBoundary(Entropy(b"z" * 16)).create_attempt("workspace-1", artifact.artifact_id)))
        expect_code(self, "attestation_attempt_tampered", lambda: forged_attempt.to_payload())
        object.__setattr__(artifact, "artifact_id", "artifact-" + "f" * 64)
        expect_code(self, "attestation_persistence_payload_invalid", lambda: artifact.to_payload())
        object.__setattr__(reference, "binding_reference_digest", DIGEST_E)
        expect_code(self, "attestation_persistence_payload_invalid", lambda: reference.content_payload())
        object.__setattr__(event, "outcome", "Failed")
        expect_code(self, "attestation_persistence_payload_invalid", lambda: event.to_payload())

    def test_attempt_boundary_creation_collision_and_finalization(self):
        entropy = Entropy(b"1" * 16, b"1" * 16, b"2" * 16)
        boundary = RevalidationAttemptBoundary(entropy)
        artifact = artifact_for()
        reference = reference_for(artifact)
        first = boundary.create_attempt("workspace-1", artifact.artifact_id)
        expect_code(self, "attestation_attempt_id_collision", lambda: boundary.create_attempt("workspace-1", artifact.artifact_id))
        event = event_for(artifact, reference, attempt_id=first.revalidation_attempt_id)
        self.assertIs(boundary.finalize(first, event), boundary.finalize(first, event))
        changed = event_for(artifact, reference, attempt_id=first.revalidation_attempt_id, revalidated_at="2026-08-14T12:01:00Z")
        expect_code(self, "attestation_revalidation_event_conflict", lambda: boundary.finalize(first, changed))
        second = boundary.create_attempt("workspace-1", artifact.artifact_id)
        self.assertNotEqual(first.revalidation_attempt_id, second.revalidation_attempt_id)
        expect_code(self, "attestation_attempt_boundary_mismatch", lambda: RevalidationAttemptBoundary(Entropy(b"3" * 16)).finalize(first, event))

    def test_attempt_entropy_and_copy_failures(self):
        expect_code(self, "attestation_attempt_entropy_unavailable", lambda: RevalidationAttemptBoundary(Entropy(b"x" * 15)).create_attempt("workspace-1", artifact_for().artifact_id))
        expect_code(self, "attestation_attempt_entropy_unavailable", lambda: RevalidationAttemptBoundary(lambda size: (_ for _ in ()).throw(RuntimeError("hidden"))).create_attempt("workspace-1", artifact_for().artifact_id))
        boundary = RevalidationAttemptBoundary(Entropy(b"4" * 16))
        attempt = boundary.create_attempt("workspace-1", artifact_for().artifact_id)
        expect_code(self, "attestation_attempt_tampered", lambda: setattr(attempt, "artifact_id", "artifact-" + "0" * 64))
        expect_code(self, "attestation_attempt_tampered", lambda: copy(attempt))
        expect_code(self, "attestation_attempt_tampered", lambda: deepcopy(attempt))
        forged = object.__new__(type(attempt))
        self.assertFalse(boundary.owns(forged))

    def test_attempt_gc_tombstone_and_falsey_entropy(self):
        entropy = FalseyEntropy(b"g" * 16)
        boundary = RevalidationAttemptBoundary(entropy)
        attempt = boundary.create_attempt("workspace-1", artifact_for().artifact_id)
        self.assertEqual(entropy.calls, 1)
        del attempt
        gc.collect()
        expect_code(self, "attestation_attempt_id_collision", lambda: boundary.create_attempt("workspace-1", artifact_for().artifact_id))
        self.assertEqual(entropy.calls, 2)

    def test_finalized_event_registry_integrity_is_revalidated(self):
        artifact = artifact_for()
        reference = reference_for(artifact)
        boundary = RevalidationAttemptBoundary(Entropy(b"h" * 16))
        attempt = boundary.create_attempt("workspace-1", artifact.artifact_id)
        event = event_for(artifact, reference, attempt_id=attempt.revalidation_attempt_id)
        finalized = boundary.finalize(attempt, event)
        mutations = {
            "outcome": "Failed",
            "failure_code": "attestation_signature_invalid",
            "result_digest": DIGEST_E,
            "event_id": "revalidation-event-" + "f" * 64,
            "event_payload_digest": DIGEST_E,
            "artifact_digest": DIGEST_E,
            "revalidation_context_digest": DIGEST_E,
            "binding_reference_digest": DIGEST_E,
            "revalidated_at": "2026-08-14T12:01:00Z",
        }
        original = {field: getattr(finalized, field) for field in mutations}
        for field, value in mutations.items():
            with self.subTest(field=field):
                object.__setattr__(finalized, field, value)
                expect_code(self, "attestation_persistence_payload_invalid", lambda: boundary.finalize(attempt, event_for(artifact, reference, attempt_id=attempt.revalidation_attempt_id)))
                object.__setattr__(finalized, field, original[field])
        self.assertIs(boundary.finalize(attempt, event), finalized)

    def test_concurrent_attempt_collision_has_one_winner(self):
        class SameEntropy:
            def __call__(self, size: int) -> bytes:
                return b"i" * 16
        boundary = RevalidationAttemptBoundary(SameEntropy())
        artifact = artifact_for()
        def create(_: int) -> str:
            try:
                return "ok:" + boundary.create_attempt("workspace-1", artifact.artifact_id).revalidation_attempt_id
            except PersistenceContractError as exc:
                return "error:" + exc.code
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(create, range(8)))
        self.assertEqual(sum(result.startswith("ok:") for result in results), 1)
        self.assertEqual(sum(result == "error:attestation_attempt_id_collision" for result in results), 7)

    def test_concurrent_same_attempt_finalization_converges(self):
        artifact = artifact_for()
        reference = reference_for(artifact)
        boundary = RevalidationAttemptBoundary(Entropy(b"5" * 16))
        attempt = boundary.create_attempt("workspace-1", artifact.artifact_id)
        event = event_for(artifact, reference, attempt_id=attempt.revalidation_attempt_id)
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: boundary.finalize(attempt, event), range(8)))
        self.assertTrue(all(result is results[0] for result in results))

    def test_concurrent_different_payloads_have_one_winner(self):
        artifact = artifact_for()
        reference = reference_for(artifact)
        boundary = RevalidationAttemptBoundary(Entropy(b"6" * 16))
        attempt = boundary.create_attempt("workspace-1", artifact.artifact_id)
        events = [
            event_for(artifact, reference, attempt_id=attempt.revalidation_attempt_id,
                      revalidated_at="2026-08-14T12:00:00Z"),
            event_for(artifact, reference, attempt_id=attempt.revalidation_attempt_id,
                      revalidated_at="2026-08-14T12:01:00Z"),
        ]
        def finalize(event: AttestationRevalidationEvent) -> str:
            try:
                return "ok:" + boundary.finalize(attempt, event).event_payload_digest
            except PersistenceContractError as exc:
                return "error:" + exc.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(finalize, events))
        self.assertEqual(sum(result.startswith("ok:") for result in results), 1)
        self.assertEqual(sum(result == "error:attestation_revalidation_event_conflict" for result in results), 1)

    def test_forbidden_persisted_fields_and_future_store_codes_are_not_event_codes(self):
        self.assertNotIn("attestation_artifact_aggregate_corrupt", ATTESTATION_REVALIDATION_FAILURE_CODES)
        self.assertNotIn("attestation_attempt_replayed", ATTESTATION_REVALIDATION_FAILURE_CODES)
        self.assertEqual(FUTURE_STORE_ERROR_CODES, frozenset({
            "attestation_artifact_aggregate_corrupt",
            "attestation_artifact_conflict",
            "attestation_binding_reference_conflict",
        }))


if __name__ == "__main__":
    unittest.main()
