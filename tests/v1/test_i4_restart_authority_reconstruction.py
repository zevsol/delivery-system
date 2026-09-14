from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
from dataclasses import replace
from datetime import timedelta
from copy import deepcopy
import threading
import unittest
from unittest.mock import Mock

from dataclasses import FrozenInstanceError

from delivery_system.attestation import (
    CredentialCapabilityAttestationClaims,
    IssuerTrustDecision,
    RevocationStatus,
)
from delivery_system.attestation_persistence_store import InMemoryAttestationPersistenceStore
from delivery_system.attestation_persistence import PersistedAttestationArtifact
from delivery_system.authority_binding import SignedAuthorityBinding
from delivery_system.authority_binding_persistence import PersistedAuthorityBinding
from delivery_system.protocol import canonical_payload
from delivery_system.restart_credential_verification import (
    DefaultRestartCredentialAttestationVerifier,
    RestartVerifiedCredentialEvidence,
)
from tests.attestation_contract.test_attestation_contract import FakeCapabilityPolicy, FakeIssuer
from tests.v1 import test_operational_approval_authority as approval_fixture


NOW = approval_fixture.NOW


class AuthorityVerifier:
    def __init__(self, accepted: bool = True) -> None:
        self.accepted = accepted
        self.calls: list[object] = []

    def verify(self, value: object) -> bool:
        self.calls.append(value)
        return self.accepted


class CredentialVerifier:
    def __init__(self, delegate) -> None:
        self.delegate = delegate
        self.calls: list[object] = []

    def verify(self, artifact, *, current_time):
        self.calls.append(artifact)
        return self.delegate.verify(artifact, current_time=current_time)


class ReadOnlyBindingStore:
    def __init__(self, delegate) -> None:
        self.delegate = delegate
        self.save_calls = 0

    def save_authority_binding(self, binding):
        self.save_calls += 1
        raise AssertionError("restart_must_not_save_binding")

    def load_authority_binding(self, workspace_identity, authority_issuance_id):
        return self.delegate.load_authority_binding(workspace_identity, authority_issuance_id)

    def resolve_authority_binding_for_operation(self, workspace_identity, operation_identity):
        return self.delegate.resolve_authority_binding_for_operation(workspace_identity, operation_identity)


class ReadOnlyArtifactStore:
    def __init__(self, delegate) -> None:
        self.delegate = delegate
        self.get_calls = 0
        self.persist_calls = 0

    def get_artifact_aggregate(self, workspace_identity, artifact_id):
        self.get_calls += 1
        return self.delegate.get_artifact_aggregate(workspace_identity, artifact_id)

    def persist_artifact(self, artifact, reference):
        self.persist_calls += 1
        raise AssertionError("restart_must_not_persist_artifact")


class I4RestartAuthorityReconstructionTests(unittest.TestCase):
    def _setup(self, *, two_operations=False):
        harness = approval_fixture.OperationalApprovalAuthorityTests()
        if not two_operations:
            directory, context, store, preview, audit, service = harness._setup("memory")
        else:
            directory = __import__("tempfile").TemporaryDirectory()
            from delivery_system.runtime import InMemoryPreviewStore, RuntimeContext, RuntimePlanner
            from tests.v1.test_operational_approval_authority import TRUST
            from tests.attestation_orchestration.test_attestation_orchestration import FakeReadOnlyDriver
            from delivery_system.auditor import RuleEvaluationDraft, RuntimeAuditor
            from delivery_system.rules import SemanticOutcome, build_registry_v1
            from delivery_system.attestation_runtime import RuntimeAttestationOrchestrationService
            from delivery_system.attestation import AttestationRuntimeBoundary
            from tests.fakes.attestation_provider import FakeCredentialCapabilityProvider, FakeCapabilityResolver
            context = RuntimeContext.from_workspace_root(directory.name)
            store = InMemoryPreviewStore(context.workspace_identity, TRUST)
            fixture_plan = approval_fixture.plan()
            fixture_plan["work_items"].append(deepcopy(fixture_plan["work_items"][0]))
            fixture_plan["work_items"][1]["client_ref"] = "item-2"
            fixture_plan["operation_intents"] = [
                {"operation_kind": "create_issue", "client_refs": ["item"], "depends_on": []},
                {"operation_kind": "create_issue", "client_refs": ["item-2"], "depends_on": []},
            ]
            trust = TRUST
            preview = RuntimePlanner(context, store, FakeReadOnlyDriver(node_id="node-1"), trust).preview(fixture_plan)
            auditor = RuntimeAuditor(context, store, build_registry_v1(), trust)
            audit_context = auditor.get_context(preview["preview_id"], 1)
            evaluations = [
                RuleEvaluationDraft(rule["rule_id"], rule["rule_version"], SemanticOutcome.PASSED, "verified")
                for rule in audit_context["semantic_rule_contexts"] if rule["applicability"] == "Applicable"
            ]
            audit = auditor.record_audit(preview["preview_id"], 1, audit_context["audit_context_digest"], evaluations, [])
            issuer = FakeIssuer()
            attestation = RuntimeAttestationOrchestrationService(
                context, store, TRUST,
                AttestationRuntimeBoundary(issuer, issuer, issuer, FakeCapabilityPolicy()),
                FakeCredentialCapabilityProvider(), FakeCapabilityResolver(), clock=lambda: NOW,
            )
            artifact_adapter, signer, binding_store = approval_fixture.i3b_dependencies(context.workspace_identity)
            from delivery_system.runtime import RuntimeApprovalAuthorityService
            service = RuntimeApprovalAuthorityService(
                context, store, attestation, clock=lambda: NOW,
                artifact_link_adapter=artifact_adapter,
                authority_binding_signer=signer,
                authority_binding_store=binding_store,
            )
        command = f"批准写入 {preview['preview_id']} 1"
        approval = service.record_approval(preview["preview_id"], 1, command, "human")
        original = service.issue_application_authority(preview["preview_id"], 1, approval.approval_id)
        issuance_id = service._authority_issuance_ids[original.authority_id]
        persisted = service._authority_binding_store.load_authority_binding(
            context.workspace_identity, issuance_id,
        )
        artifact_store = service._artifact_link_adapter._store
        issuer = FakeIssuer()
        credential_verifier = CredentialVerifier(DefaultRestartCredentialAttestationVerifier(
            issuer_policy=issuer,
            proof_verifier=issuer,
            revocation_reader=issuer,
            capability_policy=FakeCapabilityPolicy(),
        ))
        authority_verifier = AuthorityVerifier()
        service._attestation_persistence_store = artifact_store
        service._restart_credential_verifier = credential_verifier
        service._authority_binding_verifier = authority_verifier
        service._live_credential_contexts.clear()
        for field in (
            "_RuntimeAttestationOrchestrationService__contexts_by_binding",
            "_RuntimeAttestationOrchestrationService__bindings_by_state",
            "_RuntimeAttestationOrchestrationService__bindings_by_id",
            "_RuntimeAttestationOrchestrationService__binding_registry",
            "_RuntimeAttestationOrchestrationService__binding_events",
        ):
            getattr(service.attestation_service, field).clear()
        service._authority_issuance_ids.clear()
        service._authorities.clear()
        return (directory, context, store, preview, approval, service, original,
                persisted, artifact_store, authority_verifier, credential_verifier, issuer)

    @staticmethod
    def _reconstruct(service, preview, approval):
        return service.reconstruct_application_authority_after_restart(
            preview["preview_id"], 1, approval.approval_id,
        )

    def test_valid_restart_reconstructs_historical_authority_without_live_context(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            recovered = self._reconstruct(service, preview, approval)
            self.assertEqual(recovered.to_dict(), original.to_dict())
            self.assertEqual(recovered.issued_at, persisted.payload.authority_issued_at)
            self.assertEqual(recovered.expires_at, original.expires_at)
            self.assertEqual(len(authority_verifier.calls), 1)
            self.assertEqual(len(credential_verifier.calls), 1)
            self.assertEqual(service._live_credential_contexts, {})
            self.assertEqual(artifact_store.get_artifact_aggregate(
                context.workspace_identity, persisted.payload.attestation_artifact_id
            ).artifact.artifact_digest, persisted.payload.attestation_artifact_digest)
        finally:
            directory.cleanup()

    def test_restart_verifier_returns_distinct_immutable_evidence(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            artifact = artifact_store.get_artifact_aggregate(
                context.workspace_identity, persisted.payload.attestation_artifact_id,
            ).artifact
            evidence = credential_verifier.delegate.verify(artifact, current_time=NOW)
            self.assertIs(type(evidence), RestartVerifiedCredentialEvidence)
            self.assertEqual(evidence.artifact_id, artifact.artifact_id)
            self.assertEqual(evidence.claims_digest, artifact.claims_digest)
            with self.assertRaises(FrozenInstanceError):
                evidence.artifact_id = "other"  # type: ignore[misc]
        finally:
            directory.cleanup()

    def test_historical_signature_message_is_canonical_claims_payload(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            self._reconstruct(service, preview, approval)
            artifact = credential_verifier.calls[0]
            self.assertEqual(issuer.payloads[0], canonical_payload(artifact.claims_payload.to_payload()).encode("utf-8"))
        finally:
            directory.cleanup()

    def test_invalid_credential_proof_blocks_publication(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            issuer.verify = lambda *args: False
            with self.assertRaisesRegex(ValueError, "^restart_reconstruction_credential_proof_invalid$"):
                self._reconstruct(service, preview, approval)
            self.assertEqual(service._authorities, {})
            self.assertEqual(service._authority_issuance_ids, {})
        finally:
            directory.cleanup()

    def test_untrusted_issuer_blocks_publication(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            issuer.trusted = False
            with self.assertRaisesRegex(ValueError, "^restart_reconstruction_credential_untrusted$"):
                self._reconstruct(service, preview, approval)
            self.assertEqual(service._authorities, {})
        finally:
            directory.cleanup()

    def test_wrong_key_and_algorithm_are_rejected_by_restart_verifier(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            artifact = artifact_store.get_artifact_aggregate(
                context.workspace_identity, persisted.payload.attestation_artifact_id,
            ).artifact
            variant = self._artifact_variant(artifact, key_id="wrong-key")
            with self.assertRaisesRegex(ValueError, "^restart_reconstruction_credential_untrusted$"):
                credential_verifier.delegate.verify(variant, current_time=NOW)
            issuer.algorithm = "rsa-sha256"
            with self.assertRaisesRegex(ValueError, "^restart_reconstruction_credential_untrusted$"):
                credential_verifier.delegate.verify(artifact, current_time=NOW)
        finally:
            directory.cleanup()

    def test_current_capability_policy_rejects_historical_grant(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            credential_verifier.delegate._capability_policy.supported = {"issues:read"}
            with self.assertRaisesRegex(ValueError, "^restart_reconstruction_capability_rejected$"):
                self._reconstruct(service, preview, approval)
            self.assertEqual(service._authorities, {})
        finally:
            directory.cleanup()

    def test_revoked_and_unavailable_credentials_fail_closed(self):
        for mode in ("revoked", "unavailable", "unknown"):
            data = self._setup()
            directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
            try:
                if mode == "revoked":
                    issuer.revocation = RevocationStatus(
                        attestation_revoked=True,
                        revoked_at="2026-08-14T11:30:00Z",
                        reason="test-revocation",
                    )
                    expected = "restart_reconstruction_credential_revoked"
                elif mode == "unknown":
                    issuer.read_status = lambda *args: None
                    expected = "restart_reconstruction_revocation_unknown"
                else:
                    issuer.read_status = Mock(side_effect=RuntimeError("unavailable"))
                    expected = "restart_reconstruction_revocation_unavailable"
                with self.assertRaisesRegex(ValueError, f"^{expected}$"):
                    self._reconstruct(service, preview, approval)
                self.assertEqual(service._authorities, {})
            finally:
                directory.cleanup()

    def test_expired_credential_fails_without_refreshing_issued_at(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            service.clock = lambda: NOW + timedelta(hours=2)
            with self.assertRaisesRegex(ValueError, "^restart_reconstruction_credential_expired$"):
                self._reconstruct(service, preview, approval)
            self.assertEqual(service._authorities, {})
        finally:
            directory.cleanup()

    def test_artifact_id_and_digest_mismatch_fail_closed(self):
        for field, value, expected in (
            ("attestation_artifact_id", "artifact-" + "a" * 64, "restart_reconstruction_artifact_missing"),
            ("attestation_artifact_digest", "sha256:" + "b" * 64, "restart_reconstruction_artifact_mismatch"),
        ):
            data = self._setup()
            directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
            try:
                self._replace_persisted(service, persisted, **{field: value})
                with self.assertRaisesRegex(ValueError, f"^{expected}$"):
                    self._reconstruct(service, preview, approval)
                self.assertEqual(service._authorities, {})
            finally:
                directory.cleanup()

    def test_missing_partial_and_split_assignments_fail_closed(self):
        for mode in ("missing", "partial", "split"):
            data = self._setup(two_operations=(mode != "missing"))
            directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
            try:
                assignments = service._authority_binding_store
                operation_ids = persisted.payload.authorized_operation_identities
                if mode == "missing":
                    service._authority_binding_store = ReadOnlyBindingStore(
                        _EmptyAssignmentDelegate(assignments)
                    )
                elif mode == "partial":
                    service._authority_binding_store = _PartialAssignmentStore(assignments, operation_ids)
                else:
                    service._authority_binding_store = _SplitAssignmentStore(assignments, persisted)
                expected = (
                    "restart_reconstruction_no_historical_issuance"
                    if mode in {"missing", "partial"}
                    else "restart_reconstruction_assignment_conflict"
                )
                with self.assertRaisesRegex(ValueError, f"^{expected}$"):
                    self._reconstruct(service, preview, approval)
            finally:
                directory.cleanup()

    def test_authority_binding_proof_is_required_before_artifact_verification(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            service._authority_binding_verifier = AuthorityVerifier(False)
            with self.assertRaisesRegex(ValueError, "^restart_reconstruction_authority_binding_invalid$"):
                self._reconstruct(service, preview, approval)
            self.assertEqual(credential_verifier.calls, [])
            self.assertEqual(service._authorities, {})
        finally:
            directory.cleanup()

    def test_extra_and_missing_signed_operations_fail_closed(self):
        for mode in ("missing", "extra"):
            data = self._setup(two_operations=True)
            directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
            try:
                operation_ids = persisted.payload.authorized_operation_identities
                changed = operation_ids[:1] if mode == "missing" else operation_ids + ("operation-" + "c" * 64,)
                self._replace_persisted(service, persisted, authorized_operation_identities=changed)
                with self.assertRaisesRegex(ValueError, "^restart_reconstruction_operation_mismatch$"):
                    self._reconstruct(service, preview, approval)
            finally:
                directory.cleanup()

    def test_artifact_store_is_read_only_and_reference_mismatch_fails(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            read_only = ReadOnlyArtifactStore(artifact_store)
            service._attestation_persistence_store = read_only
            aggregate = artifact_store.get_artifact_aggregate(
                context.workspace_identity, persisted.payload.attestation_artifact_id,
            )
            artifact_store._reference_snapshots[(context.workspace_identity, aggregate.artifact.artifact_id)] = "{}"
            with self.assertRaisesRegex(ValueError, "^restart_reconstruction_artifact_unavailable$"):
                self._reconstruct(service, preview, approval)
            self.assertEqual(read_only.persist_calls, 0)
        finally:
            directory.cleanup()

    def test_current_relationship_claims_must_match_reloadable_state(self):
        fields = (
            ("workspace_identity", "other-workspace", "restart_reconstruction_artifact_mismatch"),
            ("repository_identity", "other/repository", "restart_reconstruction_binding_mismatch"),
            ("driver_identity", "other-driver", "restart_reconstruction_binding_mismatch"),
            ("remote_authority", "sha256:" + "f" * 64, "restart_reconstruction_binding_mismatch"),
            ("evidence_digest", "sha256:" + "e" * 64, "restart_reconstruction_binding_mismatch"),
        )
        for field, value, expected in fields:
            data = self._setup()
            directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
            try:
                artifact = artifact_store.get_artifact_aggregate(
                    context.workspace_identity, persisted.payload.attestation_artifact_id,
                ).artifact
                evidence = credential_verifier.delegate.verify(artifact, current_time=NOW)
                if field == "workspace_identity":
                    altered = replace(evidence, workspace_identity=value)
                else:
                    claims = self._claims_variant(evidence.claims, **{field: value})
                    altered = replace(evidence, claims=claims, claims_digest=claims.claims_digest())
                credential_verifier.verify = lambda artifact, *, current_time, altered=altered: altered
                with self.assertRaisesRegex(ValueError, f"^{expected}$"):
                    self._reconstruct(service, preview, approval)
                self.assertEqual(service._authorities, {})
            finally:
                directory.cleanup()

    def test_current_capability_and_application_identity_must_match(self):
        for field, value, expected in (
            ("application_id", "application-" + "a" * 64, "restart_reconstruction_application_mismatch"),
            ("required_capabilities", ("issues:read",), "restart_reconstruction_capability_mismatch"),
        ):
            data = self._setup()
            directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
            try:
                self._replace_persisted(service, persisted, **{field: value})
                with self.assertRaisesRegex(ValueError, f"^{expected}$"):
                    self._reconstruct(service, preview, approval)
            finally:
                directory.cleanup()

    def test_binding_mismatch_and_operation_mismatch_fail_closed(self):
        for field, expected in (
            ("credential_binding_id", "restart_reconstruction_binding_mismatch"),
            ("authorized_operation_identities", "restart_reconstruction_operation_mismatch"),
        ):
            data = self._setup()
            directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
            try:
                changed = ("binding-" + "f" * 64 if field == "credential_binding_id"
                           else ("operation-" + "f" * 64,))
                altered = replace(persisted.payload, **{field: changed})
                signed = SignedAuthorityBinding(
                    altered, persisted.signed.issuer_id, persisted.signed.key_id,
                    persisted.signed.signature_algorithm, persisted.signed.proof,
                )
                service._authority_binding_store = _StaticBindingStore(
                    PersistedAuthorityBinding(signed, altered.canonical_bytes(), altered.authority_issuance_id)
                )
                with self.assertRaisesRegex(ValueError, f"^{expected}$"):
                    self._reconstruct(service, preview, approval)
            finally:
                directory.cleanup()

    def test_zero_signer_and_zero_durable_writes(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            signer = service._authority_binding_signer
            before = signer.calls
            binding_store = ReadOnlyBindingStore(service._authority_binding_store)
            service._authority_binding_store = binding_store
            artifact = ReadOnlyArtifactStore(artifact_store)
            service._attestation_persistence_store = artifact
            self._reconstruct(service, preview, approval)
            self.assertEqual(signer.calls, before)
            self.assertEqual(binding_store.save_calls, 0)
            self.assertEqual(artifact.persist_calls, 0)
            self.assertGreater(artifact.get_calls, 0)
        finally:
            directory.cleanup()

    def test_registry_reconstruction_is_idempotent_and_concurrent(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            binding_store = ReadOnlyBindingStore(service._authority_binding_store)
            service._authority_binding_store = binding_store
            read_only_artifact = ReadOnlyArtifactStore(artifact_store)
            service._attestation_persistence_store = read_only_artifact
            signer_calls_before = service._authority_binding_signer.calls
            durable_parent_before = binding_store.delegate.load_authority_binding(
                context.workspace_identity, persisted.authority_issuance_id,
            )
            durable_assignments_before = tuple(
                binding_store.delegate.resolve_authority_binding_for_operation(
                    context.workspace_identity, operation_id,
                )
                for operation_id in persisted.payload.authorized_operation_identities
            )
            barrier = threading.Barrier(2)

            def invoke():
                barrier.wait(timeout=5)
                return self._reconstruct(service, preview, approval)

            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(invoke) for _ in range(2)]
                results = [future.result(timeout=10) for future in futures]
            self.assertEqual([result.authority_id for result in results], [original.authority_id] * 2)
            self.assertIs(results[0], results[1])
            self.assertEqual(service._authority_issuance_ids, {original.authority_id: persisted.authority_issuance_id})
            self.assertEqual(tuple(service._authorities), (original.authority_id,))
            self.assertEqual(results[0].issued_at, persisted.payload.authority_issued_at)
            self.assertEqual(len(authority_verifier.calls), 2)
            self.assertEqual(len(credential_verifier.calls), 2)
            self.assertEqual(service._authority_binding_signer.calls, signer_calls_before)
            self.assertEqual(binding_store.save_calls, 0)
            self.assertEqual(read_only_artifact.persist_calls, 0)
            self.assertGreaterEqual(read_only_artifact.get_calls, 2)
            self.assertEqual(
                binding_store.delegate.load_authority_binding(
                    context.workspace_identity, persisted.authority_issuance_id,
                ),
                durable_parent_before,
            )
            self.assertEqual(
                tuple(
                    binding_store.delegate.resolve_authority_binding_for_operation(
                        context.workspace_identity, operation_id,
                    )
                    for operation_id in persisted.payload.authorized_operation_identities
                ),
                durable_assignments_before,
            )
        finally:
            directory.cleanup()

    def test_existing_incompatible_registry_state_is_not_overwritten(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            incompatible = object()
            service._authorities[original.authority_id] = incompatible
            with self.assertRaisesRegex(ValueError, "^restart_reconstruction_registry_conflict$"):
                self._reconstruct(service, preview, approval)
            self.assertIs(service._authorities[original.authority_id], incompatible)
        finally:
            directory.cleanup()

    def test_matching_association_without_authority_publishes_after_validation(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            service._authority_issuance_ids[original.authority_id] = persisted.authority_issuance_id
            recovered = self._reconstruct(service, preview, approval)
            self.assertEqual(recovered.to_dict(), original.to_dict())
            self.assertIs(service._authorities[original.authority_id], recovered)
        finally:
            directory.cleanup()

    def test_existing_authority_without_association_installs_matching_association(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            service._authorities[original.authority_id] = original
            recovered = self._reconstruct(service, preview, approval)
            self.assertIs(recovered, original)
            self.assertEqual(service._authority_issuance_ids, {original.authority_id: persisted.authority_issuance_id})
        finally:
            directory.cleanup()

    def test_incompatible_association_is_not_overwritten(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            incompatible = "authority-issuance-" + "d" * 64
            service._authority_issuance_ids[original.authority_id] = incompatible
            with self.assertRaisesRegex(ValueError, "^restart_reconstruction_registry_conflict$"):
                self._reconstruct(service, preview, approval)
            self.assertEqual(service._authority_issuance_ids[original.authority_id], incompatible)
            self.assertEqual(service._authorities, {})
        finally:
            directory.cleanup()

    def test_issue_and_resolve_do_not_implicitly_reconstruct(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            with self.assertRaisesRegex(ValueError, "^authority_issuance_requires_recovery$"):
                service.issue_application_authority(preview["preview_id"], 1, approval.approval_id)
            with self.assertRaisesRegex(ValueError, "^application_authority_not_found$"):
                service.resolve_application_authority(original.authority_id)
            self.assertEqual(authority_verifier.calls, [])
            self.assertEqual(credential_verifier.calls, [])
        finally:
            directory.cleanup()

    def test_unsupported_legacy_evidence_requires_reauthorization(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            artifact = artifact_store.get_artifact_aggregate(
                context.workspace_identity, persisted.payload.attestation_artifact_id,
            ).artifact
            with self.assertRaisesRegex(ValueError, "^restart_reconstruction_credential_evidence_invalid$"):
                credential_verifier.delegate.verify(object(), current_time=NOW)
        finally:
            directory.cleanup()

    def test_missing_live_context_is_an_i4_boundary_for_i3c(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            with self.assertRaisesRegex(ValueError, "^authority_recovery_live_context_required$"):
                service.recover_application_authority(preview["preview_id"], 1, approval.approval_id)
            self.assertEqual(authority_verifier.calls, [])
        finally:
            directory.cleanup()

    def test_authority_binding_verifier_exception_blocks_all_publication(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            authority_verifier.verify = Mock(side_effect=RuntimeError("invalid-proof"))
            with self.assertRaisesRegex(ValueError, "^restart_reconstruction_authority_binding_invalid$"):
                self._reconstruct(service, preview, approval)
            self.assertEqual(service._authorities, {})
            self.assertEqual(service._authority_issuance_ids, {})
            self.assertEqual(credential_verifier.calls, [])
        finally:
            directory.cleanup()

    def test_credential_verifier_exception_blocks_all_publication(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            credential_verifier.verify = Mock(side_effect=RuntimeError("credential-proof"))
            with self.assertRaisesRegex(ValueError, "^restart_reconstruction_credential_proof_invalid$"):
                self._reconstruct(service, preview, approval)
            self.assertEqual(service._authorities, {})
            self.assertEqual(service._authority_issuance_ids, {})
        finally:
            directory.cleanup()

    def test_missing_parent_binding_fails_closed(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            service._authority_binding_store = _MissingParentStore(service._authority_binding_store)
            with self.assertRaisesRegex(ValueError, "^restart_reconstruction_persistence_corrupt$"):
                self._reconstruct(service, preview, approval)
            self.assertEqual(service._authorities, {})
        finally:
            directory.cleanup()

    def test_assignment_store_error_does_not_mean_no_issuance(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            service._authority_binding_store = _AssignmentErrorStore(service._authority_binding_store)
            with self.assertRaisesRegex(ValueError, "^restart_reconstruction_persistence_error$"):
                self._reconstruct(service, preview, approval)
            self.assertEqual(service._authorities, {})
        finally:
            directory.cleanup()

    def test_artifact_store_error_does_not_mean_no_issuance(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            service._attestation_persistence_store = _ArtifactErrorStore()
            with self.assertRaisesRegex(ValueError, "^restart_reconstruction_artifact_unavailable$"):
                self._reconstruct(service, preview, approval)
            self.assertEqual(service._authorities, {})
        finally:
            directory.cleanup()

    def test_reference_relationship_is_checked_beyond_artifact_identity(self):
        for field, value in (
            ("repository_identity", "other/repository"),
            ("preview_id", "other-preview"),
            ("audit_id", "other-audit"),
            ("binding_id", "binding-" + "e" * 64),
        ):
            data = self._setup()
            directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
            try:
                service._attestation_persistence_store = _MutatedReferenceStore(artifact_store, field, value)
                with self.assertRaisesRegex(ValueError, "^restart_reconstruction_artifact_mismatch$"):
                    self._reconstruct(service, preview, approval)
            finally:
                directory.cleanup()

    def test_current_time_only_validates_eligibility_not_historical_issuance(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            service.clock = lambda: NOW + timedelta(minutes=30)
            recovered = self._reconstruct(service, preview, approval)
            self.assertEqual(recovered.issued_at, persisted.payload.authority_issued_at)
            self.assertNotEqual(recovered.issued_at, service._utc(service.clock()))
        finally:
            directory.cleanup()

    def test_public_resolver_exposes_only_reconstructed_authority(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            recovered = self._reconstruct(service, preview, approval)
            self.assertIsNone(service.attestation_service.lookup_binding(recovered.credential_binding_id))
            self.assertEqual(service._live_credential_contexts, {})
            self.assertIs(service.resolve_application_authority(recovered.authority_id), recovered)
        finally:
            directory.cleanup()

    def test_restart_authority_requires_restart_provenance_for_resolution(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            recovered = self._reconstruct(service, preview, approval)
            service._restart_authority_provenance.pop(recovered.authority_id)
            self.assertFalse(service.validate_application_authority(recovered))
            with self.assertRaisesRegex(ValueError, "^application_authority_rejected$"):
                service.resolve_application_authority(recovered.authority_id)
        finally:
            directory.cleanup()

    def test_conflicting_restart_provenance_is_not_accepted_or_repaired(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            recovered = self._reconstruct(service, preview, approval)
            provenance = service._restart_authority_provenance[recovered.authority_id]
            service._restart_authority_provenance[recovered.authority_id] = replace(
                provenance, authority_id="application-authority-" + "f" * 64,
            )
            self.assertFalse(service.validate_application_authority(recovered))
            with self.assertRaisesRegex(ValueError, "^application_authority_rejected$"):
                service.resolve_application_authority(recovered.authority_id)
            self.assertEqual(
                service._restart_authority_provenance[recovered.authority_id].authority_id,
                "application-authority-" + "f" * 64,
            )
        finally:
            directory.cleanup()

    def test_incomplete_restart_registry_states_do_not_resolve(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            recovered = self._reconstruct(service, preview, approval)
            provenance = service._restart_authority_provenance[recovered.authority_id]
            service._authorities.clear()
            service._authority_issuance_ids.clear()
            with self.assertRaisesRegex(ValueError, "^application_authority_not_found$"):
                service.resolve_application_authority(recovered.authority_id)
            service._restart_authority_provenance[recovered.authority_id] = provenance
            service._authorities[recovered.authority_id] = recovered
            with self.assertRaisesRegex(ValueError, "^application_authority_rejected$"):
                service.resolve_application_authority(recovered.authority_id)
            service._authority_issuance_ids[recovered.authority_id] = persisted.authority_issuance_id
            self.assertIs(service.resolve_application_authority(recovered.authority_id), recovered)
            service._restart_authority_provenance.clear()
            with self.assertRaisesRegex(ValueError, "^application_authority_rejected$"):
                service.resolve_application_authority(recovered.authority_id)
        finally:
            directory.cleanup()

    def test_restart_execution_context_validates_without_live_binding(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            recovered = self._reconstruct(service, preview, approval)
            execution = service.create_execution_context(recovered.authority_id)
            self.assertIsNone(service.attestation_service.lookup_binding(recovered.credential_binding_id))
            service.validate_execution_context(execution)
        finally:
            directory.cleanup()

    def test_restart_reconstruction_does_not_call_live_orchestration(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            service.attestation_service.orchestrate = Mock(side_effect=AssertionError("no-live-attestation"))
            before = len(service.attestation_service._RuntimeAttestationOrchestrationService__contexts_by_binding)
            self._reconstruct(service, preview, approval)
            after = len(service.attestation_service._RuntimeAttestationOrchestrationService__contexts_by_binding)
            self.assertEqual(before, after)
        finally:
            directory.cleanup()

    def test_reconstructed_authority_uses_canonical_identity(self):
        data = self._setup()
        directory, context, store, preview, approval, service, original, persisted, artifact_store, authority_verifier, credential_verifier, issuer = data
        try:
            recovered = self._reconstruct(service, preview, approval)
            from delivery_system.application_authority import ApplicationAuthority
            self.assertEqual(recovered.authority_id, ApplicationAuthority.expected_id(recovered.to_dict()))
            self.assertEqual(recovered.to_dict(), original.to_dict())
        finally:
            directory.cleanup()

    @staticmethod
    def _artifact_variant(artifact, **changes):
        claims = I4RestartAuthorityReconstructionTests._claims_variant(
            artifact.claims_payload, **changes,
        )
        payload = canonical_payload(claims.to_payload()).encode("utf-8")
        proof = base64.urlsafe_b64encode(hashlib.sha512(payload).digest()).decode("ascii").rstrip("=")
        return PersistedAttestationArtifact.create(
            workspace_identity=artifact.workspace_identity,
            claims_payload=claims,
            detached_proof=proof,
            original_verified_at=artifact.original_verified_at,
            created_at=artifact.created_at,
        )

    @staticmethod
    def _claims_variant(claims, **changes):
        values = {
            field: getattr(claims, field)
            for field in CredentialCapabilityAttestationClaims.__dataclass_fields__
        }
        values.update(changes)
        values["attestation_id"] = ""
        return CredentialCapabilityAttestationClaims(**values)

    @staticmethod
    def _replace_persisted(service, persisted, **changes):
        altered = replace(persisted.payload, **changes)
        signed = SignedAuthorityBinding(
            altered, persisted.signed.issuer_id, persisted.signed.key_id,
            persisted.signed.signature_algorithm, persisted.signed.proof,
        )
        service._authority_binding_store = _StaticBindingStore(
            PersistedAuthorityBinding(signed, altered.canonical_bytes(), altered.authority_issuance_id)
        )


class _EmptyAssignmentDelegate:
    def __init__(self, delegate):
        self.delegate = delegate

    def resolve_authority_binding_for_operation(self, workspace_identity, operation_identity):
        return None

    def load_authority_binding(self, workspace_identity, authority_issuance_id):
        return self.delegate.load_authority_binding(workspace_identity, authority_issuance_id)


class _MissingParentStore(_EmptyAssignmentDelegate):
    def resolve_authority_binding_for_operation(self, workspace_identity, operation_identity):
        return self.delegate.resolve_authority_binding_for_operation(workspace_identity, operation_identity)

    def load_authority_binding(self, workspace_identity, authority_issuance_id):
        return None


class _AssignmentErrorStore(_EmptyAssignmentDelegate):
    def resolve_authority_binding_for_operation(self, workspace_identity, operation_identity):
        raise RuntimeError("assignment-store-error")


class _ArtifactErrorStore:
    def get_artifact_aggregate(self, workspace_identity, artifact_id):
        raise RuntimeError("artifact-store-error")


class _MutatedReferenceStore:
    def __init__(self, delegate, field, value):
        self.delegate = delegate
        self.field = field
        self.value = value

    def get_artifact_aggregate(self, workspace_identity, artifact_id):
        aggregate = self.delegate.get_artifact_aggregate(workspace_identity, artifact_id)
        object.__setattr__(aggregate.binding_reference, self.field, self.value)
        return aggregate


class _PartialAssignmentStore(_EmptyAssignmentDelegate):
    def __init__(self, delegate, operation_ids):
        super().__init__(delegate)
        self.operation_ids = operation_ids

    def resolve_authority_binding_for_operation(self, workspace_identity, operation_identity):
        if operation_identity == self.operation_ids[0]:
            return self.delegate.resolve_authority_binding_for_operation(workspace_identity, operation_identity)
        return None


class _SplitAssignmentStore(_EmptyAssignmentDelegate):
    def __init__(self, delegate, persisted):
        super().__init__(delegate)
        self.persisted = persisted
        self.calls = 0

    def resolve_authority_binding_for_operation(self, workspace_identity, operation_identity):
        self.calls += 1
        if self.calls == 1:
            return self.persisted
        alternate = replace(self.persisted.payload, authority_issued_at="2026-08-14T11:01:00Z")
        signed = SignedAuthorityBinding(
            alternate, self.persisted.signed.issuer_id, self.persisted.signed.key_id,
            self.persisted.signed.signature_algorithm, self.persisted.signed.proof,
        )
        return PersistedAuthorityBinding(signed, alternate.canonical_bytes(), alternate.authority_issuance_id)


class _StaticBindingStore:
    def __init__(self, persisted):
        self.persisted = persisted

    def resolve_authority_binding_for_operation(self, workspace_identity, operation_identity):
        return self.persisted

    def load_authority_binding(self, workspace_identity, authority_issuance_id):
        return self.persisted
