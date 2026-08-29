from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import base64
import hashlib
import json
import unittest

from delivery_system.attestation import CredentialCapabilityAttestationClaims
from delivery_system.attestation_persistence import (
    ARTIFACT_CONTENT_DOMAIN,
    ARTIFACT_ID_DOMAIN,
    ATTESTATION_REVALIDATION_FAILURE_CODES,
    EVENT_CONTENT_DOMAIN,
    AttestationBindingReference,
    AttestationRevalidationEvent,
    PersistenceContractError,
    PersistedAttestationArtifact,
)
from delivery_system.attestation_persistence_store import (
    AttestationArtifactAggregate,
)
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
        "attestation_version": "1", "attestation_id": "", "issuer_id": "issuer-1",
        "key_id": "key-1", "signature_algorithm": "ed25519",
        "credential_class": "github-app-installation-token",
        "credential_instance_id": "credential-instance-1",
        "github_subject_identity": "subject-node-1", "repository_identity": "owner/repository",
        "granted_capabilities": ("issues:read", "issues:write"),
        "driver_identity": "github-rest-driver-v1", "remote_authority": DIGEST_A,
        "preview_id": "preview-1", "revision": 1, "operation_set_digest": DIGEST_B,
        "remote_snapshot_digest": DIGEST_C, "evidence_digest": DIGEST_D,
        "issued_at": "2026-08-14T11:00:00Z", "expires_at": "2026-08-14T13:00:00Z",
        "nonce": "nonce-1", "source_verification_digest": DIGEST_E,
    }
    values.update(changes)
    return CredentialCapabilityAttestationClaims(**values)  # type: ignore[arg-type]


def artifact_for(
    claims: CredentialCapabilityAttestationClaims | None = None,
    *, workspace: str = "workspace-1", proof: str = PROOF,
) -> PersistedAttestationArtifact:
    claims = claims or make_claims()
    original = "2026-08-14T11:30:00.000000Z"
    created = "2026-08-14T11:31:00.000000Z"
    content = {
        "domain": ARTIFACT_CONTENT_DOMAIN,
        "artifact_contract_version": "offline-attestation-artifact-v1",
        "workspace_identity": workspace,
        "attestation_id": claims.attestation_id,
        "claims_payload": claims.to_payload(),
        "detached_proof": proof,
        "claims_digest": claims.claims_digest(),
        "original_verified_at": original,
        "created_at": created,
    }
    artifact_digest = digest(content)
    identity = {
        "domain": ARTIFACT_ID_DOMAIN,
        "payload": {"identity_version": "1", "workspace_identity": workspace,
                    "attestation_id": claims.attestation_id},
    }
    artifact_id = "artifact-" + hashlib.sha256(
        canonical_payload(identity).encode("utf-8")
    ).hexdigest()
    return PersistedAttestationArtifact(
        "offline-attestation-artifact-v1", artifact_id, workspace, claims.attestation_id,
        claims, proof, claims.claims_digest(), artifact_digest, original, created,
    )


def reference_for(artifact: PersistedAttestationArtifact, **changes: object) -> AttestationBindingReference:
    values: dict[str, object] = {
        "reference_contract_version": "attestation-binding-reference-v1", "reference_id": "",
        "workspace_identity": artifact.workspace_identity, "artifact_id": artifact.artifact_id,
        "artifact_digest": artifact.artifact_digest, "binding_id": "binding-" + "1" * 64,
        "repository_identity": "owner/repository", "github_subject_identity": "subject-node-1",
        "driver_identity": "github-rest-driver-v1", "remote_authority": DIGEST_A,
        "preview_id": "preview-1", "revision": 1, "plan_digest": DIGEST_B,
        "sealed_preview_digest": DIGEST_C,
        "operation_set_digest": artifact.claims_payload.operation_set_digest,
        "remote_snapshot_digest": artifact.claims_payload.remote_snapshot_digest,
        "audit_id": "audit-1", "audit_digest": DIGEST_A, "evidence_id": "evidence-1",
        "evidence_digest": artifact.claims_payload.evidence_digest,
        "original_verified_at": artifact.original_verified_at, "binding_reference_digest": "",
    }
    values.update(changes)
    content = {
        "domain": "delivery-system:attestation-binding-reference-content:v1",
        "reference_contract_version": "attestation-binding-reference-v1",
        **{key: values[key] for key in (
            "workspace_identity", "artifact_id", "artifact_digest", "binding_id",
            "repository_identity", "github_subject_identity", "driver_identity",
            "remote_authority", "preview_id", "revision", "plan_digest",
            "sealed_preview_digest", "operation_set_digest", "remote_snapshot_digest",
            "audit_id", "audit_digest", "evidence_id", "evidence_digest",
            "original_verified_at",
        )},
    }
    values["binding_reference_digest"] = digest(content)
    identity = {
        "domain": "delivery-system:attestation-binding-reference-identity:v1",
        "payload": {"reference_version": "1", "workspace_identity": values["workspace_identity"],
                    "artifact_id": values["artifact_id"], "binding_id": values["binding_id"]},
    }
    values["reference_id"] = "binding-reference-" + hashlib.sha256(
        canonical_payload(identity).encode("utf-8")
    ).hexdigest()
    return AttestationBindingReference(**values)  # type: ignore[arg-type]


def event_for(
    artifact: PersistedAttestationArtifact,
    reference: AttestationBindingReference,
    *, attempt_id: str = "attempt-" + "1" * 32,
    **changes: object,
) -> AttestationRevalidationEvent:
    values: dict[str, object] = {
        "workspace_identity": artifact.workspace_identity, "artifact_id": artifact.artifact_id,
        "artifact_digest": artifact.artifact_digest, "revalidation_attempt_id": attempt_id,
        "revalidation_context_digest": DIGEST_C,
        "binding_reference_digest": reference.binding_reference_digest,
        "outcome": "Successful", "revalidated_at": "2026-08-14T12:00:00.000000Z",
        "failure_code": None, "result_digest": DIGEST_D,
    }
    values.update(changes)
    return AttestationRevalidationEvent.create(**values)  # type: ignore[arg-type]


def run_shared_store_contract(
    test: unittest.TestCase,
    store_factory,
    corruptor=None,
) -> None:
    artifact = artifact_for()
    reference = reference_for(artifact)
    store = store_factory()

    first = store.persist_artifact(artifact, reference)
    test.assertIsInstance(first, AttestationArtifactAggregate)
    replay = store.persist_artifact(artifact, reference)
    test.assertEqual(replay.artifact.artifact_digest, artifact.artifact_digest)
    test.assertIsNot(first, replay)

    alternate_artifact = artifact_for(proof=base64.urlsafe_b64encode(b"q" * 64).decode("ascii").rstrip("="))
    expect_code(test, "attestation_artifact_conflict", lambda: store.persist_artifact(alternate_artifact, reference_for(alternate_artifact)))
    alternate_reference = reference_for(artifact, binding_id="binding-" + "2" * 64)
    expect_code(test, "attestation_binding_reference_conflict", lambda: store.persist_artifact(artifact, alternate_reference))

    loaded = store.get_artifact_aggregate(artifact.workspace_identity, artifact.artifact_id)
    test.assertIsNotNone(loaded)
    object.__setattr__(loaded, "artifact", alternate_artifact)
    clean = store.get_artifact_aggregate(artifact.workspace_identity, artifact.artifact_id)
    test.assertEqual(clean.artifact.artifact_digest, artifact.artifact_digest)

    event = event_for(artifact, reference)
    sequence_one = store.append_revalidation_event(event)
    test.assertEqual(sequence_one.event_sequence, 1)
    event_replay = store.append_revalidation_event(event)
    test.assertEqual(event_replay.event_sequence, 1)
    test.assertIsNot(sequence_one, event_replay)
    changed = event_for(artifact, reference, revalidated_at="2026-08-14T12:01:00Z")
    expect_code(test, "attestation_revalidation_event_conflict", lambda: store.append_revalidation_event(changed))
    mismatch = event_for(artifact, reference, attempt_id="attempt-" + "2" * 32, artifact_digest=DIGEST_E)
    expect_code(test, "attestation_revalidation_event_binding_mismatch", lambda: store.append_revalidation_event(mismatch))

    for index, code in enumerate(sorted(ATTESTATION_REVALIDATION_FAILURE_CODES), start=3):
        failed = event_for(artifact, reference, attempt_id=f"attempt-{index:032x}", outcome="Failed",
                           failure_code=code, result_digest=None)
        result = store.append_revalidation_event(failed)
        test.assertEqual(result.event_sequence, index - 1)
    latest = store.get_latest_revalidation_event(artifact.workspace_identity, artifact.artifact_id)
    test.assertEqual(latest.event_sequence, 10)

    backdated = event_for(artifact, reference, attempt_id="attempt-" + "f" * 32,
                          revalidated_at="2026-08-14T10:00:00Z")
    backdated_result = store.append_revalidation_event(backdated)
    test.assertEqual(backdated_result.event_sequence, 11)
    test.assertEqual(store.get_latest_revalidation_event(artifact.workspace_identity, artifact.artifact_id).event_sequence, 11)
    empty_artifact = artifact_for(workspace="workspace-empty")
    store.persist_artifact(empty_artifact, reference_for(empty_artifact))
    test.assertIsNone(store.get_latest_revalidation_event("workspace-empty", empty_artifact.artifact_id))

    empty = store_factory()
    expect_code(test, "attestation_artifact_not_found", lambda: empty.get_latest_revalidation_event(artifact.workspace_identity, artifact.artifact_id))
    expect_code(test, "attestation_artifact_not_found", lambda: empty.append_revalidation_event(event))
    isolated = store_factory()
    other_workspace = artifact_for(workspace="workspace-2")
    isolated.persist_artifact(other_workspace, reference_for(other_workspace))
    test.assertIsNone(isolated.get_artifact_aggregate("workspace-1", artifact.artifact_id))

    if corruptor is not None:
        corruptor(store, "aggregate")
        expect_code(test, "attestation_artifact_aggregate_corrupt", lambda: store.get_artifact_aggregate(artifact.workspace_identity, artifact.artifact_id))


class SharedStoreContractTests(unittest.TestCase):
    """Shared suite is callable by each backend; direct execution is optional."""

    def test_contract_runner_is_available(self) -> None:
        self.assertTrue(callable(run_shared_store_contract))


__all__ = [
    "DIGEST_A", "DIGEST_B", "DIGEST_C", "DIGEST_D", "DIGEST_E", "PROOF",
    "artifact_for", "reference_for", "event_for", "expect_code",
    "run_shared_store_contract",
]
