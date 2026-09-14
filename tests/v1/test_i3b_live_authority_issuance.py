from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
import threading
import unittest

from delivery_system.application_identity import LogicalApplicationIdentity, operation_identity
from delivery_system.authority_binding import SignedAuthorityBinding
from delivery_system.authority_binding_persistence import (
    AuthorityBindingPersistenceError,
    PersistedAuthorityBinding,
)
from delivery_system.runtime import RuntimeApprovalAuthorityService
from tests.v1 import test_operational_approval_authority as approval_fixture

NOW = approval_fixture.NOW


class CountingClock:
    def __init__(self, value: datetime) -> None:
        self.value = value
        self.calls = 0

    def __call__(self) -> datetime:
        self.calls += 1
        return self.value


class CountingStore:
    def __init__(self, delegate) -> None:
        self.delegate = delegate
        self.save_calls = 0

    def save_authority_binding(self, binding):
        self.save_calls += 1
        return self.delegate.save_authority_binding(binding)

    def load_authority_binding(self, workspace_identity, authority_issuance_id):
        return self.delegate.load_authority_binding(workspace_identity, authority_issuance_id)

    def resolve_authority_binding_for_operation(self, workspace_identity, operation_identity):
        return self.delegate.resolve_authority_binding_for_operation(workspace_identity, operation_identity)


class ExistingAssignmentStore:
    def __init__(self, value=object()) -> None:
        self.value = value
        self.save_calls = 0

    def save_authority_binding(self, binding):
        self.save_calls += 1
        raise AssertionError("save_must_not_be_reached")

    def load_authority_binding(self, workspace_identity, authority_issuance_id):
        return None

    def resolve_authority_binding_for_operation(self, workspace_identity, operation_identity):
        return self.value


class BlockingStore(CountingStore):
    def __init__(self, delegate) -> None:
        super().__init__(delegate)
        self.entered = threading.Event()
        self.release = threading.Event()

    def save_authority_binding(self, binding):
        self.save_calls += 1
        self.entered.set()
        if not self.release.wait(5):
            raise AssertionError("blocking_store_timeout")
        return self.delegate.save_authority_binding(binding)


class FailingArtifactAdapter:
    def persist_verified_attestation(self, context):
        raise ValueError("artifact_link_unavailable")


class FailingSigner:
    issuer_id = "test-authority-issuer"
    key_id = "test-authority-key"
    signature_algorithm = "ed25519"

    def __init__(self) -> None:
        self.calls = 0

    def sign_authority_binding(self, canonical_payload_bytes: bytes) -> str:
        self.calls += 1
        raise RuntimeError("signer_failure")


class FailingPersistenceStore(CountingStore):
    def save_authority_binding(self, binding):
        self.save_calls += 1
        raise AuthorityBindingPersistenceError("authority_binding_persistence_sqlite_operational")


class RecordingArtifactAdapter:
    def __init__(self, delegate) -> None:
        self.delegate = delegate
        self.context = None

    def persist_verified_attestation(self, context):
        self.context = context
        return self.delegate.persist_verified_attestation(context)


class DifferentResultStore(CountingStore):
    def __init__(self, delegate, proof: str) -> None:
        super().__init__(delegate)
        self.proof = proof

    def save_authority_binding(self, binding):
        self.save_calls += 1
        persisted = self.delegate.save_authority_binding(binding)
        alternate = SignedAuthorityBinding(
            persisted.signed.payload,
            persisted.signed.issuer_id,
            persisted.signed.key_id,
            persisted.signed.signature_algorithm,
            self.proof,
        )
        return PersistedAuthorityBinding(
            alternate,
            alternate.payload.canonical_bytes(),
            alternate.payload.authority_issuance_id,
        )


class I3BLiveAuthorityIssuanceTests(unittest.TestCase):
    def _setup(self):
        harness = approval_fixture.OperationalApprovalAuthorityTests()
        directory, context, store, preview, audit, service = harness._setup("memory")
        command = f"批准写入 {preview['preview_id']} 1"
        approval = service.record_approval(preview["preview_id"], 1, command, "human")
        return directory, context, store, preview, approval, service

    def _issue(self, service, preview, approval):
        return service.issue_application_authority(
            preview["preview_id"], 1, approval.approval_id,
        )

    def test_missing_i3b_dependencies_fails_closed_without_legacy_fallback(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            service._artifact_link_adapter = None
            service._authority_binding_signer = None
            service._authority_binding_store = None
            with self.assertRaisesRegex(ValueError, "^authority_issuance_dependencies_required$"):
                self._issue(service, preview, approval)
            self.assertEqual(service._authorities, {})
        finally:
            directory.cleanup()

    def test_artifact_adapter_receives_the_verified_context_as_one_input(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            recording = RecordingArtifactAdapter(service._artifact_link_adapter)
            service._artifact_link_adapter = recording
            self._issue(service, preview, approval)
            result = service.attestation_service.orchestrate(preview["preview_id"], 1)
            self.assertIs(recording.context, result.verified_context)
        finally:
            directory.cleanup()

    def test_repeated_issue_does_not_reask_provider_for_attestation(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            provider = service.attestation_service._RuntimeAttestationOrchestrationService__provider
            original = provider.attest
            calls = []
            provider.attest = lambda request: (calls.append(request), original(request))[1]
            self._issue(service, preview, approval)
            with self.assertRaisesRegex(ValueError, "^authority_issuance_requires_recovery$"):
                self._issue(service, preview, approval)
            self.assertEqual(len(calls), 1)
        finally:
            directory.cleanup()

    def test_binding_record_uses_the_complete_required_operation_assignment(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            authority = self._issue(service, preview, approval)
            issuance = service._authority_binding_store.load_authority_binding(
                context.workspace_identity, service._authority_issuance_ids[authority.authority_id],
            )
            self.assertTrue(issuance.payload.authorized_operation_identities)
            self.assertEqual(issuance.payload.credential_binding_id, authority.credential_binding_id)
        finally:
            directory.cleanup()

    def test_successful_new_issuance_publishes_after_durable_binding(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            authority = self._issue(service, preview, approval)
            self.assertTrue(service.validate_application_authority(authority))
            self.assertIn(authority.authority_id, service._authorities)
            self.assertIn(authority.authority_id, service._authority_issuance_ids)
        finally:
            directory.cleanup()

    def test_exact_artifact_link_and_binding_fields_are_used(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            authority = self._issue(service, preview, approval)
            result = service.attestation_service.orchestrate(preview["preview_id"], 1)
            link = service._artifact_link_adapter.persist_verified_attestation(result.verified_context)
            issuance = service._authority_binding_store.load_authority_binding(
                context.workspace_identity,
                service._authority_issuance_ids[authority.authority_id],
            )
            self.assertEqual(issuance.payload.credential_binding_id, result.binding.binding_id)
            self.assertEqual(issuance.payload.attestation_artifact_id, link.artifact_id)
            self.assertEqual(issuance.payload.attestation_artifact_digest, link.artifact_digest)
        finally:
            directory.cleanup()

    def test_application_and_operation_identities_are_canonical_and_complete(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            authority = self._issue(service, preview, approval)
            identity = LogicalApplicationIdentity.from_authority(authority)
            canonical = store.get_preview(context.workspace_identity, preview["preview_id"])["canonical_payload"]
            from delivery_system.write_operations import normalize_write_operations
            operations = tuple(normalize_write_operations(canonical["operation_intents"]))
            expected = tuple(operation_identity(identity.application_id, i, operation) for i, operation in enumerate(operations))
            persisted = service._authority_binding_store.load_authority_binding(
                context.workspace_identity, service._authority_issuance_ids[authority.authority_id],
            )
            self.assertEqual(identity.application_id, persisted.payload.application_id)
            self.assertEqual(expected, persisted.payload.authorized_operation_identities)
        finally:
            directory.cleanup()

    def test_capabilities_and_expiry_are_copied_exactly(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            authority = self._issue(service, preview, approval)
            binding = service.attestation_service.resolve_registered_binding(authority.credential_binding_id)
            self.assertEqual(authority.required_capabilities, binding.required_capabilities)
            self.assertEqual(authority.granted_capabilities, binding.granted_capabilities)
            self.assertEqual(authority.expires_at, binding.expires_at)
        finally:
            directory.cleanup()

    def test_one_issued_at_is_shared_by_authority_and_binding(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            authority = self._issue(service, preview, approval)
            persisted = service._authority_binding_store.load_authority_binding(
                context.workspace_identity, service._authority_issuance_ids[authority.authority_id],
            )
            self.assertEqual(authority.issued_at, persisted.payload.authority_issued_at)
        finally:
            directory.cleanup()

    def test_signer_runs_only_after_assignment_precheck(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            signer = service._authority_binding_signer
            binding_store = ExistingAssignmentStore()
            service._authority_binding_store = binding_store
            with self.assertRaisesRegex(ValueError, "^authority_issuance_requires_recovery$"):
                self._issue(service, preview, approval)
            self.assertEqual(signer.calls, 0)
            self.assertEqual(binding_store.save_calls, 0)
        finally:
            directory.cleanup()

    def test_persistence_is_before_publication_and_authority_is_hidden_while_blocked(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            blocking = BlockingStore(service._authority_binding_store)
            service._authority_binding_store = blocking
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(self._issue, service, preview, approval)
                self.assertTrue(blocking.entered.wait(5))
                self.assertEqual(service._authorities, {})
                self.assertEqual(service._authority_issuance_ids, {})
                blocking.release.set()
                authority = future.result(timeout=5)
            self.assertTrue(service.validate_application_authority(authority))
        finally:
            directory.cleanup()

    def test_artifact_link_failure_prevents_signing_and_persistence(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            service._artifact_link_adapter = FailingArtifactAdapter()
            binding_store = CountingStore(service._authority_binding_store)
            service._authority_binding_store = binding_store
            with self.assertRaisesRegex(ValueError, "^artifact_link_unavailable$"):
                self._issue(service, preview, approval)
            self.assertEqual(service._authority_binding_signer.calls, 0)
            self.assertEqual(binding_store.save_calls, 0)
            self.assertEqual(service._authorities, {})
        finally:
            directory.cleanup()

    def test_signer_failure_prevents_persistence_and_publication(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            signer = FailingSigner()
            service._authority_binding_signer = signer
            binding_store = CountingStore(service._authority_binding_store)
            service._authority_binding_store = binding_store
            with self.assertRaisesRegex(RuntimeError, "^signer_failure$"):
                self._issue(service, preview, approval)
            self.assertEqual(signer.calls, 1)
            self.assertEqual(binding_store.save_calls, 0)
            self.assertEqual(service._authorities, {})
        finally:
            directory.cleanup()

    def test_persistence_failure_prevents_publication(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            binding_store = FailingPersistenceStore(service._authority_binding_store)
            service._authority_binding_store = binding_store
            with self.assertRaisesRegex(AuthorityBindingPersistenceError, "^authority_binding_persistence_sqlite_operational$"):
                self._issue(service, preview, approval)
            self.assertEqual(binding_store.save_calls, 1)
            self.assertEqual(service._authorities, {})
            self.assertEqual(service._authority_issuance_ids, {})
        finally:
            directory.cleanup()

    def test_complete_existing_assignment_blocks_clock_and_signing(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            first = self._issue(service, preview, approval)
            signer_calls = service._authority_binding_signer.calls
            clock = CountingClock(NOW + timedelta(minutes=1))
            service.clock = clock
            with self.assertRaisesRegex(ValueError, "^authority_issuance_requires_recovery$"):
                self._issue(service, preview, approval)
            self.assertEqual(clock.calls, 0)
            self.assertEqual(service._authority_binding_signer.calls, signer_calls)
            self.assertTrue(service.validate_application_authority(first))
        finally:
            directory.cleanup()

    def test_partial_assignment_path_is_fail_closed_before_clock(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            service._authority_binding_store = ExistingAssignmentStore()
            clock = CountingClock(NOW + timedelta(minutes=1))
            service.clock = clock
            with self.assertRaisesRegex(ValueError, "^authority_issuance_requires_recovery$"):
                self._issue(service, preview, approval)
            self.assertEqual(clock.calls, 0)
        finally:
            directory.cleanup()

    def test_exact_durable_return_is_used_for_established_authority(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            authority = self._issue(service, preview, approval)
            issuance = service._authority_binding_store.load_authority_binding(
                context.workspace_identity, service._authority_issuance_ids[authority.authority_id],
            )
            self.assertEqual(issuance.payload.authority_issuance_id, service._authority_issuance_ids[authority.authority_id])
            self.assertTrue(service.validate_application_authority(authority))
        finally:
            directory.cleanup()

    def test_different_durable_return_is_rejected(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            alternate = base64.urlsafe_b64encode(bytes([255]) + bytes(63)).decode("ascii").rstrip("=")
            service._authority_binding_store = DifferentResultStore(
                service._authority_binding_store, alternate,
            )
            with self.assertRaisesRegex(ValueError, "^authority_binding_persistence_conflict$"):
                self._issue(service, preview, approval)
            self.assertEqual(service._authorities, {})
        finally:
            directory.cleanup()

    def test_incompatible_authority_registry_is_not_overwritten(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            established = self._issue(service, preview, approval)
            artifact_adapter, signer, binding_store = approval_fixture.i3b_dependencies(context.workspace_identity)
            shadow = RuntimeApprovalAuthorityService(
                context, store, service.attestation_service, clock=lambda: NOW,
                artifact_link_adapter=artifact_adapter,
                authority_binding_signer=signer,
                authority_binding_store=binding_store,
            )
            shadow._authorities[established.authority_id] = object()
            with self.assertRaisesRegex(ValueError, "^application_authority_registry_conflict$"):
                self._issue(shadow, preview, approval)
            self.assertIsNotNone(shadow._authorities[established.authority_id])
        finally:
            directory.cleanup()

    def test_incompatible_issuance_association_is_not_overwritten(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            established = self._issue(service, preview, approval)
            artifact_adapter, signer, binding_store = approval_fixture.i3b_dependencies(context.workspace_identity)
            shadow = RuntimeApprovalAuthorityService(
                context, store, service.attestation_service, clock=lambda: NOW,
                artifact_link_adapter=artifact_adapter,
                authority_binding_signer=signer,
                authority_binding_store=binding_store,
            )
            shadow._authority_issuance_ids[established.authority_id] = "authority-issuance-" + "a" * 64
            with self.assertRaisesRegex(ValueError, "^application_authority_registry_conflict$"):
                self._issue(shadow, preview, approval)
            self.assertEqual(shadow._authority_issuance_ids[established.authority_id], "authority-issuance-" + "a" * 64)
        finally:
            directory.cleanup()

    def test_publication_failure_leaves_durable_orphan(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            class FailingRegistry(dict):
                def __setitem__(self, key, value):
                    raise RuntimeError("publication_failure")
            service._authorities = FailingRegistry()
            with self.assertRaisesRegex(RuntimeError, "^publication_failure$"):
                self._issue(service, preview, approval)
            self.assertEqual(len(service._authority_issuance_ids), 1)
            issuance_id = next(iter(service._authority_issuance_ids.values()))
            self.assertIsNotNone(service._authority_binding_store.load_authority_binding(
                context.workspace_identity, issuance_id,
            ))
        finally:
            directory.cleanup()

    def test_unassociated_authority_cannot_resolve_as_execution_usable(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            authority = self._issue(service, preview, approval)
            service._authority_issuance_ids.pop(authority.authority_id)
            with self.assertRaisesRegex(ValueError, "^application_authority_rejected$"):
                service.resolve_application_authority(authority.authority_id)
        finally:
            directory.cleanup()

    def test_established_authority_creates_execution_context(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            authority = self._issue(service, preview, approval)
            execution = service.create_execution_context(authority.authority_id)
            self.assertEqual(execution.identity.application_id, LogicalApplicationIdentity.from_authority(authority).application_id)
        finally:
            directory.cleanup()

    def test_repeated_issuance_does_not_mint_second_issuance(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            first = self._issue(service, preview, approval)
            signer_calls = service._authority_binding_signer.calls
            with self.assertRaisesRegex(ValueError, "^authority_issuance_requires_recovery$"):
                self._issue(service, preview, approval)
            self.assertEqual(service._authority_binding_signer.calls, signer_calls)
            self.assertEqual(len(service._authority_binding_store._bindings), 1)
            self.assertIs(service.resolve_application_authority(first.authority_id), first)
        finally:
            directory.cleanup()

    def test_concurrent_new_calls_publish_at_most_one_authority(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(self._issue, service, preview, approval) for _ in range(2)]
                results = []
                failures = []
                for future in futures:
                    try:
                        results.append(future.result(timeout=5))
                    except ValueError as exc:
                        failures.append(str(exc))
            self.assertEqual(len(results), 1)
            self.assertEqual(failures, ["authority_issuance_requires_recovery"])
            self.assertEqual(len(service._authorities), 1)
        finally:
            directory.cleanup()

    def test_no_issuance_failure_reaches_execution_creation(self):
        directory, context, store, preview, approval, service = self._setup()
        try:
            service._authority_binding_signer = FailingSigner()
            with self.assertRaises(RuntimeError):
                self._issue(service, preview, approval)
            with self.assertRaisesRegex(ValueError, "^application_authority_not_found$"):
                service.create_execution_context("application-authority-" + "0" * 64)
        finally:
            directory.cleanup()


if __name__ == "__main__":
    unittest.main()
