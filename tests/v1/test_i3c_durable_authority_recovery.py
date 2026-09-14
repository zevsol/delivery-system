from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
import threading
import unittest

from delivery_system.authority_binding import SignedAuthorityBinding
from delivery_system.authority_binding_persistence import PersistedAuthorityBinding
from delivery_system.runtime import RuntimeApprovalAuthorityService
from delivery_system.verified_attestation_artifact import VerifiedCredentialArtifactLink
from tests.v1 import test_operational_approval_authority as approval_fixture


NOW = approval_fixture.NOW


class CountingClock:
    def __init__(self, value):
        self.value = value
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return self.value


class RecordingVerifier:
    def __init__(self, accepted=True, callback=None):
        self.accepted = accepted
        self.callback = callback
        self.calls = []

    def verify(self, value):
        self.calls.append(value)
        if self.callback is not None:
            self.callback(value)
        return self.accepted


class ReadOnlyBindingStore:
    def __init__(self, delegate):
        self.delegate = delegate
        self.save_calls = 0

    def save_authority_binding(self, binding):
        self.save_calls += 1
        raise AssertionError("recovery_must_not_save_binding")

    def load_authority_binding(self, workspace_identity, authority_issuance_id):
        return self.delegate.load_authority_binding(workspace_identity, authority_issuance_id)

    def resolve_authority_binding_for_operation(self, workspace_identity, operation_identity):
        return self.delegate.resolve_authority_binding_for_operation(workspace_identity, operation_identity)


class ReadOnlyArtifactAdapter:
    def __init__(self, delegate):
        self.delegate = delegate
        self.resolve_calls = 0
        self.persist_calls = 0

    def resolve_verified_attestation(self, context):
        self.resolve_calls += 1
        return self.delegate.resolve_verified_attestation(context)

    def persist_verified_attestation(self, context):
        self.persist_calls += 1
        raise AssertionError("recovery_must_not_write_artifact")


class StaticBindingStore:
    def __init__(self, persisted):
        self.persisted = persisted
        self.save_calls = 0

    def save_authority_binding(self, binding):
        self.save_calls += 1
        raise AssertionError("recovery_must_not_save_binding")

    def load_authority_binding(self, workspace_identity, authority_issuance_id):
        return self.persisted

    def resolve_authority_binding_for_operation(self, workspace_identity, operation_identity):
        return self.persisted


class I3CDurableAuthorityRecoveryTests(unittest.TestCase):
    def _setup_issued(self):
        harness = approval_fixture.OperationalApprovalAuthorityTests()
        directory, context, store, preview, audit, service = harness._setup("memory")
        command = f"批准写入 {preview['preview_id']} 1"
        approval = service.record_approval(preview["preview_id"], 1, command, "human")
        authority = service.issue_application_authority(
            preview["preview_id"], 1, approval.approval_id,
        )
        service._authority_binding_verifier = RecordingVerifier()
        issuance_id = service._authority_issuance_ids[authority.authority_id]
        persisted = service._authority_binding_store.load_authority_binding(
            context.workspace_identity, issuance_id,
        )
        return directory, context, store, preview, approval, service, authority, persisted

    @staticmethod
    def _orphan(service, authority, *, association=False, authority_entry=False):
        if not association:
            service._authority_issuance_ids.pop(authority.authority_id, None)
        if not authority_entry:
            service._authorities.pop(authority.authority_id, None)

    @staticmethod
    def _alternate(persisted, **changes):
        payload = replace(persisted.payload, **changes)
        signed = SignedAuthorityBinding(
            payload,
            persisted.signed.issuer_id,
            persisted.signed.key_id,
            persisted.signed.signature_algorithm,
            persisted.signed.proof,
        )
        return PersistedAuthorityBinding(signed, payload.canonical_bytes(), payload.authority_issuance_id)

    def _recover(self, service, preview, approval):
        return service.recover_application_authority(
            preview["preview_id"], 1, approval.approval_id,
        )

    def test_orphan_durable_binding_recovers_same_authority(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original)
            recovered = self._recover(service, preview, approval)
            self.assertEqual(recovered.to_dict(), original.to_dict())
            self.assertEqual(recovered.issued_at, persisted.payload.authority_issued_at)
            self.assertTrue(service.validate_application_authority(recovered))
        finally:
            directory.cleanup()

    def test_recovery_uses_historical_issued_at_without_new_issuance_timestamp(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original)
            clock = CountingClock(NOW + timedelta(minutes=30))
            service.clock = clock
            recovered = self._recover(service, preview, approval)
            self.assertEqual(recovered.issued_at, persisted.payload.authority_issued_at)
            self.assertEqual(clock.calls, 1)
        finally:
            directory.cleanup()

    def test_recovery_never_calls_signer(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original)
            signer = service._authority_binding_signer
            calls = signer.calls
            self._recover(service, preview, approval)
            self.assertEqual(signer.calls, calls)
        finally:
            directory.cleanup()

    def test_recovery_never_saves_authority_binding(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original)
            read_store = ReadOnlyBindingStore(service._authority_binding_store)
            service._authority_binding_store = read_store
            self._recover(service, preview, approval)
            self.assertEqual(read_store.save_calls, 0)
        finally:
            directory.cleanup()

    def test_recovery_uses_read_only_artifact_resolver(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original)
            adapter = ReadOnlyArtifactAdapter(service._artifact_link_adapter)
            service._artifact_link_adapter = adapter
            recovered = self._recover(service, preview, approval)
            self.assertEqual(adapter.resolve_calls, 1)
            self.assertEqual(adapter.persist_calls, 0)
            self.assertEqual(recovered.authority_id, original.authority_id)
        finally:
            directory.cleanup()

    def test_verifier_runs_before_publication(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original)
            observations = []
            service._authority_binding_verifier = RecordingVerifier(
                callback=lambda value: observations.append((dict(service._authorities), dict(service._authority_issuance_ids)))
            )
            self._recover(service, preview, approval)
            self.assertEqual(len(observations), 1)
            self.assertEqual(observations[0], ({}, {}))
        finally:
            directory.cleanup()

    def test_invalid_authority_binding_proof_fails_closed(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original)
            service._authority_binding_verifier = RecordingVerifier(False)
            with self.assertRaisesRegex(ValueError, "^authority_binding_proof_invalid$"):
                self._recover(service, preview, approval)
            self.assertEqual(service._authorities, {})
            self.assertEqual(service._authority_issuance_ids, {})
        finally:
            directory.cleanup()

    def test_verifier_receives_complete_signed_binding_envelope(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original)
            verifier = RecordingVerifier()
            service._authority_binding_verifier = verifier
            self._recover(service, preview, approval)
            self.assertEqual(verifier.calls[0], persisted.signed)
            self.assertEqual(verifier.calls[0].proof, persisted.signed.proof)
            self.assertEqual(verifier.calls[0].issuer_id, persisted.signed.issuer_id)
            self.assertEqual(verifier.calls[0].key_id, persisted.signed.key_id)
        finally:
            directory.cleanup()

    def test_application_id_mismatch_fails_closed(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original)
            alternate = self._alternate(persisted, application_id="application-" + "a" * 64)
            service._authority_binding_store = StaticBindingStore(alternate)
            with self.assertRaisesRegex(ValueError, "^authority_recovery_binding_mismatch$"):
                self._recover(service, preview, approval)
            self.assertEqual(service._authorities, {})
        finally:
            directory.cleanup()

    def test_credential_binding_id_mismatch_fails_closed(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original)
            alternate = self._alternate(persisted, credential_binding_id="binding-" + "b" * 64)
            service._authority_binding_store = StaticBindingStore(alternate)
            with self.assertRaisesRegex(ValueError, "^authority_recovery_binding_mismatch$"):
                self._recover(service, preview, approval)
        finally:
            directory.cleanup()

    def test_required_capabilities_mismatch_fails_closed(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original)
            alternate = self._alternate(persisted, required_capabilities=("issues:read",))
            service._authority_binding_store = StaticBindingStore(alternate)
            with self.assertRaisesRegex(ValueError, "^authority_recovery_binding_mismatch$"):
                self._recover(service, preview, approval)
        finally:
            directory.cleanup()

    def test_artifact_id_mismatch_fails_closed(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original)
            alternate = self._alternate(persisted, attestation_artifact_id="artifact-" + "c" * 64)
            service._authority_binding_store = StaticBindingStore(alternate)
            with self.assertRaisesRegex(ValueError, "^authority_recovery_binding_mismatch$"):
                self._recover(service, preview, approval)
        finally:
            directory.cleanup()

    def test_artifact_digest_mismatch_fails_closed(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original)
            alternate = self._alternate(persisted, attestation_artifact_digest="sha256:" + "d" * 64)
            service._authority_binding_store = StaticBindingStore(alternate)
            with self.assertRaisesRegex(ValueError, "^authority_recovery_binding_mismatch$"):
                self._recover(service, preview, approval)
        finally:
            directory.cleanup()

    def test_operation_assignment_mismatch_fails_closed(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original)
            alternate = self._alternate(persisted, authorized_operation_identities=("operation-" + "e" * 64,))
            service._authority_binding_store = StaticBindingStore(alternate)
            with self.assertRaisesRegex(ValueError, "^authority_recovery_binding_mismatch$"):
                self._recover(service, preview, approval)
        finally:
            directory.cleanup()

    def test_missing_assignment_is_not_treated_as_new_issuance(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original)
            service._authority_binding_store = approval_fixture.i3b_dependencies(
                context.workspace_identity,
            )[2]
            with self.assertRaisesRegex(ValueError, "^authority_recovery_partial_or_missing$"):
                self._recover(service, preview, approval)
            self.assertEqual(service._authorities, {})
        finally:
            directory.cleanup()

    def test_partial_assignment_is_fail_closed(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original)
            class PartialStore(StaticBindingStore):
                def resolve_authority_binding_for_operation(self, workspace_identity, operation_identity):
                    return None
            service._authority_binding_store = PartialStore(persisted)
            with self.assertRaisesRegex(ValueError, "^authority_recovery_partial_or_missing$"):
                self._recover(service, preview, approval)
        finally:
            directory.cleanup()

    def test_no_live_context_stays_at_i4_boundary(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original)
            service._live_credential_contexts.clear()
            with self.assertRaisesRegex(ValueError, "^authority_recovery_live_context_required$"):
                self._recover(service, preview, approval)
        finally:
            directory.cleanup()

    def test_expired_live_credential_cannot_be_recovered(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original)
            service.clock = lambda: NOW + timedelta(hours=2)
            with self.assertRaisesRegex(ValueError, "^credential_expired$"):
                self._recover(service, preview, approval)
            self.assertEqual(service._authorities, {})
        finally:
            directory.cleanup()

    def test_association_missing_and_authority_missing_are_repaired(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original)
            recovered = self._recover(service, preview, approval)
            self.assertIs(service._authorities[recovered.authority_id], recovered)
            self.assertEqual(service._authority_issuance_ids[recovered.authority_id], persisted.authority_issuance_id)
        finally:
            directory.cleanup()

    def test_association_present_and_authority_missing_publishes_recovered(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original, association=True)
            recovered = self._recover(service, preview, approval)
            self.assertEqual(recovered.authority_id, original.authority_id)
        finally:
            directory.cleanup()

    def test_authority_present_and_association_missing_restores_exact_association(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original, authority_entry=True)
            recovered = self._recover(service, preview, approval)
            self.assertIs(recovered, original)
            self.assertEqual(service._authority_issuance_ids[original.authority_id], persisted.authority_issuance_id)
        finally:
            directory.cleanup()

    def test_already_established_recovery_is_idempotent(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            recovered = self._recover(service, preview, approval)
            self.assertIs(recovered, original)
            self.assertEqual(service._authority_issuance_ids[original.authority_id], persisted.authority_issuance_id)
        finally:
            directory.cleanup()

    def test_incompatible_authority_is_not_overwritten(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            service._authorities[original.authority_id] = object()
            service._authority_issuance_ids.pop(original.authority_id, None)
            with self.assertRaisesRegex(ValueError, "^application_authority_registry_conflict$"):
                self._recover(service, preview, approval)
            self.assertNotIsInstance(service._authorities[original.authority_id], type(original))
        finally:
            directory.cleanup()

    def test_incompatible_association_is_not_overwritten(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            service._authority_issuance_ids[original.authority_id] = "authority-issuance-" + "f" * 64
            service._authorities.pop(original.authority_id, None)
            with self.assertRaisesRegex(ValueError, "^application_authority_registry_conflict$"):
                self._recover(service, preview, approval)
            self.assertEqual(service._authority_issuance_ids[original.authority_id], "authority-issuance-" + "f" * 64)
        finally:
            directory.cleanup()

    def test_repeated_new_issue_remains_recovery_required(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            with self.assertRaisesRegex(ValueError, "^authority_issuance_requires_recovery$"):
                service.issue_application_authority(preview["preview_id"], 1, approval.approval_id)
        finally:
            directory.cleanup()

    def test_resolution_does_not_automatically_recover(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original)
            with self.assertRaisesRegex(ValueError, "^application_authority_not_found$"):
                service.resolve_application_authority(original.authority_id)
        finally:
            directory.cleanup()

    def test_recovery_does_not_require_signer_or_verifier_for_new_issue(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            service._authority_binding_verifier = None
            next_authority = service._authority_binding_signer
            self.assertIsNotNone(next_authority)
            self.assertTrue(service.validate_application_authority(original))
        finally:
            directory.cleanup()

    def test_recovery_preserves_complete_durable_payload(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original)
            recovered = self._recover(service, preview, approval)
            self.assertEqual(recovered.credential_binding_id, persisted.payload.credential_binding_id)
            self.assertEqual(recovered.required_capabilities, persisted.payload.required_capabilities)
            self.assertEqual(recovered.issued_at, persisted.payload.authority_issued_at)
        finally:
            directory.cleanup()

    def test_recovery_uses_current_artifact_link_without_writing(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original)
            adapter = ReadOnlyArtifactAdapter(service._artifact_link_adapter)
            service._artifact_link_adapter = adapter
            self._recover(service, preview, approval)
            self.assertEqual(adapter.persist_calls, 0)
            self.assertGreater(adapter.resolve_calls, 0)
        finally:
            directory.cleanup()

    def test_recovery_requires_verifier_dependency(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original)
            service._authority_binding_verifier = None
            with self.assertRaisesRegex(ValueError, "^authority_recovery_dependencies_required$"):
                self._recover(service, preview, approval)
        finally:
            directory.cleanup()

    def test_recovery_requires_complete_assignment_to_one_issuance(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original)
            class SplitStore(StaticBindingStore):
                def __init__(self, first, second):
                    super().__init__(first)
                    self.second = second
                    self.calls = 0

                def resolve_authority_binding_for_operation(self, workspace_identity, operation_identity):
                    self.calls += 1
                    return self.persisted if self.calls == 1 else self.second

            alternate = self._alternate(persisted, authority_issued_at="2026-08-14T12:00:01Z")
            service._authority_binding_store = SplitStore(persisted, alternate)
            from unittest.mock import patch
            operations = (
                {"operation_kind": "create_issue", "client_refs": ["item"], "depends_on": []},
                {"operation_kind": "create_issue", "client_refs": ["item-2"], "depends_on": []},
            )
            with patch("delivery_system.runtime.normalize_write_operations", return_value=operations):
                with self.assertRaisesRegex(ValueError, "^authority_recovery_assignment_conflict$"):
                    self._recover(service, preview, approval)
            self.assertEqual(service._authorities, {})
        finally:
            directory.cleanup()

    def test_concurrent_recovery_calls_converge_on_one_established_authority(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self._orphan(service, original)
            durable_store = service._authority_binding_store
            assignment_before = tuple(
                durable_store.resolve_authority_binding_for_operation(
                    context.workspace_identity, operation_id,
                )
                for operation_id in persisted.payload.authorized_operation_identities
            )
            persisted_before = durable_store.load_authority_binding(
                context.workspace_identity, persisted.authority_issuance_id,
            )

            from unittest.mock import Mock
            signer = Mock(wraps=service._authority_binding_signer)
            service._authority_binding_signer = signer
            read_only_store = ReadOnlyBindingStore(durable_store)
            service._authority_binding_store = read_only_store
            artifact = ReadOnlyArtifactAdapter(service._artifact_link_adapter)
            service._artifact_link_adapter = artifact
            verifier = RecordingVerifier()
            service._authority_binding_verifier = verifier
            validation_clock = CountingClock(NOW + timedelta(minutes=30))
            service.clock = validation_clock

            callers_ready = threading.Barrier(2)

            def recover():
                callers_ready.wait(timeout=5)
                return self._recover(service, preview, approval)

            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(recover) for _ in range(2)]
                results = [future.result(timeout=10) for future in futures]

            self.assertEqual(
                [result.authority_id for result in results],
                [original.authority_id, original.authority_id],
            )
            self.assertEqual(
                [result.issued_at for result in results],
                [persisted.payload.authority_issued_at] * 2,
            )
            self.assertEqual(validation_clock.calls, 2)
            self.assertEqual(signer.sign_authority_binding.call_count, 0)
            self.assertEqual(read_only_store.save_calls, 0)
            self.assertEqual(artifact.persist_calls, 0)
            self.assertEqual(artifact.resolve_calls, 2)
            self.assertEqual(len(verifier.calls), 2)

            self.assertEqual(
                service._authority_issuance_ids,
                {original.authority_id: persisted.authority_issuance_id},
            )
            self.assertEqual(tuple(service._authorities), (original.authority_id,))
            self.assertTrue(all(
                result is service._authorities[original.authority_id]
                for result in results
            ))
            self.assertEqual(
                durable_store.load_authority_binding(
                    context.workspace_identity, persisted.authority_issuance_id,
                ),
                persisted_before,
            )
            assignment_after = tuple(
                durable_store.resolve_authority_binding_for_operation(
                    context.workspace_identity, operation_id,
                )
                for operation_id in persisted.payload.authorized_operation_identities
            )
            self.assertEqual(assignment_after, assignment_before)
        finally:
            directory.cleanup()

    def test_recovery_keeps_i3b_new_issuance_green(self):
        data = self._setup_issued()
        directory, context, store, preview, approval, service, original, persisted = data
        try:
            self.assertTrue(service.validate_application_authority(original))
            self.assertIsNotNone(service._authority_binding_signer)
            self.assertIsNotNone(service._authority_binding_store)
        finally:
            directory.cleanup()


if __name__ == "__main__":
    unittest.main()
