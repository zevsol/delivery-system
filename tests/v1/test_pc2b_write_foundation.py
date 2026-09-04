"""Deterministic PC2-B write-boundary and coordination tests."""

from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from delivery_system.application_identity import operation_identity, request_identity
from delivery_system.canonical import digest
from delivery_system.drivers.write_contract import (
    CreateIssueCommand,
    RelationshipCommand,
    RemoteIssueReference,
    WriteDriver,
    WriteObservation,
    WriteObservationKind,
    WRITE_EXECUTOR_IDENTITY,
    correlation_marker_for_request,
)
from delivery_system.execution_state import (ApplicationExecutionState, OperationAttemptState,
                                              validate_application_transition)
from delivery_system.execution_store import SQLiteExecutionStore
from delivery_system.receipts import ApplicationReceipt, AuthorityProvenance, OperationReceipt
from tests.fakes.fake_write_driver import FakeWriteDriver
class PC2BWriteFoundationTests(unittest.TestCase):
    def _context(self, version="1"):
        from tests.v1.test_pc2a_foundation import PC2AFoundationTests
        return PC2AFoundationTests()._live_authority(version)

    def test_write_driver_is_narrow_and_observations_are_transport_facts(self):
        methods = ({name for name in WriteDriver.__dict__ if not name.startswith("_")} |
                   set(WriteDriver.__dict__.get("__annotations__", {})))
        self.assertEqual(methods, {"executor_identity", "create_issue", "add_sub_issue", "add_dependency"})
        self.assertNotIn("write", methods)
        self.assertNotIn("verify_relationship", methods)
        self.assertEqual({item.value for item in WriteObservationKind}, {"DefinitiveSuccess", "DefinitiveRejected", "Ambiguous"})

    def test_direction_marker_and_deterministic_fake_trace(self):
        repository = "owner/repo"
        child = RemoteIssueReference(repository, 2, "202", "I_child")
        parent = RemoteIssueReference(repository, 1, "101", "I_parent")
        relationship = RelationshipCommand(repository, child, parent)
        marker = correlation_marker_for_request("request-1")
        command = CreateIssueCommand(repository, "client-1", "Title", "Body", "request-1")
        observations = (WriteObservation(WriteObservationKind.DEFINITIVE_SUCCESS, result_identity="202"),)
        first = FakeWriteDriver(observations)
        second = FakeWriteDriver(observations)
        first.create_issue(command)
        first.add_sub_issue(relationship)
        first.add_dependency(RelationshipCommand(repository, parent, child))
        second.create_issue(command)
        second.add_sub_issue(relationship)
        second.add_dependency(RelationshipCommand(repository, parent, child))
        self.assertEqual(first.trace, second.trace)
        self.assertEqual(first.trace[1].command.first, child)
        self.assertEqual(first.trace[1].command.second, parent)
        self.assertEqual(first.trace[2].command.first, parent)
        self.assertEqual(first.trace[2].command.second, child)
        self.assertEqual(command.correlation_marker, marker)
        self.assertNotIn("credential", marker)
        self.assertNotIn("authority", marker)
        self.assertEqual(first.executor_identity, WRITE_EXECUTOR_IDENTITY)

    def test_marker_has_one_source_of_truth_and_fake_payload_is_deeply_frozen(self):
        marker = correlation_marker_for_request("request-a")
        command = CreateIssueCommand("owner/repo", "client-a", "Title", "Body", "request-a")
        self.assertEqual(command.correlation_marker, marker)
        self.assertNotEqual(command.correlation_marker, correlation_marker_for_request("request-b"))
        with self.assertRaises(TypeError):
            CreateIssueCommand("owner/repo", "client-a", "Title", "Body", correlation_marker=marker)
        nested = {"items": [{"value": 1}]}
        observation = WriteObservation(WriteObservationKind.DEFINITIVE_SUCCESS, result_payload=nested)
        fake = FakeWriteDriver((observation,))
        fake.create_issue(command)
        nested["items"][0]["value"] = 99
        self.assertEqual(fake.trace[0].observation.result_payload["items"][0]["value"], 1)
        with self.assertRaises(TypeError):
            fake.trace[0].observation.result_payload["items"][0]["value"] = 2

    def test_atomic_attempt_claim_and_no_fake_idempotency(self):
        directory, context = self._context()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                store = SQLiteExecutionStore(Path(temporary) / "state.sqlite3", context.workspace_identity,
                                             runtime_service=context.service)
                attempt = context.new_attempt(0, state="Applying", started_at="2026-09-04T00:00:00Z",
                                              updated_at="2026-09-04T00:00:00Z")
                stored = store.create_attempt_if_absent(attempt)
                self.assertTrue(stored.verify_integrity())
                with self.assertRaisesRegex(ValueError, "operation_attempt_already_exists"):
                    store.create_attempt_if_absent(attempt)
                self.assertEqual(len(FakeWriteDriver().trace), 0)
        finally:
            directory.cleanup()

    def test_claim_requires_applying_and_two_connections_have_one_winner(self):
        directory, context = self._context()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "state.sqlite3"
                stores = [SQLiteExecutionStore(path, context.workspace_identity, runtime_service=context.service) for _ in range(2)]
                for state in ("Pending", "Applied", "Failed", "Blocked", "OutcomeUnknown"):
                    attempt = context.new_attempt(0, state=state, started_at="2026-09-04T00:00:00Z",
                                                  updated_at="2026-09-04T00:00:00Z")
                    with self.assertRaisesRegex(ValueError, "operation_attempt_claim_state_invalid"):
                        stores[0].create_attempt_if_absent(attempt)
                attempt = context.new_attempt(0, state="Applying", started_at="2026-09-04T00:00:00Z",
                                              updated_at="2026-09-04T00:00:00Z")
                barrier = threading.Barrier(2)
                results = []

                def claim(store):
                    barrier.wait()
                    try:
                        store.create_attempt_if_absent(attempt)
                        results.append("winner")
                    except ValueError as exc:
                        results.append(str(exc))

                threads = [threading.Thread(target=claim, args=(store,)) for store in stores]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
                self.assertEqual(sorted(results), ["operation_attempt_already_exists", "winner"])
                self.assertTrue(stores[0].get_attempt(context.identity.application_id, attempt.operation_identity).verify_integrity())
        finally:
            directory.cleanup()

    def test_cas_transitions_are_atomic_and_policy_rejects_unknown_retry(self):
        directory, context = self._context()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                store = SQLiteExecutionStore(Path(temporary) / "state.sqlite3", context.workspace_identity,
                                             runtime_service=context.service)
                attempt = context.new_attempt(0, state="Applying", started_at="2026-09-04T00:00:00Z",
                                              updated_at="2026-09-04T00:00:00Z")
                stored_attempt = store.create_attempt_if_absent(attempt)
                historical_attempt = store.get_attempt(context.identity.application_id, stored_attempt.operation_identity)
                applied = context.continue_attempt(historical_attempt, state="Applied", updated_at="2026-09-04T00:00:01Z")
                transitioned = store.transition_attempt(stored_attempt.attempt_digest, applied)
                self.assertEqual(transitioned.state, "Applied")
                changed_start = context.new_attempt(0, state="Failed", started_at="2026-09-04T00:00:09Z",
                                                    updated_at="2026-09-04T00:00:01Z")
                with tempfile.TemporaryDirectory() as attempt_temporary:
                    claim_store = SQLiteExecutionStore(Path(attempt_temporary) / "state.sqlite3",
                                                        context.workspace_identity, runtime_service=context.service)
                    claim_store.create_attempt_if_absent(attempt)
                    with self.assertRaisesRegex(ValueError, "operation_attempt_binding_conflict"):
                        claim_store.transition_attempt(stored_attempt.attempt_digest, changed_start)
                stale = context.continue_attempt(historical_attempt, state="Failed", updated_at="2026-09-04T00:00:02Z")
                with self.assertRaisesRegex(ValueError, "attempt_state_stale"):
                    store.transition_attempt(stored_attempt.attempt_digest, stale)
                unknown = context.continue_attempt(transitioned, state="OutcomeUnknown", updated_at="2026-09-04T00:00:03Z")
                with self.assertRaisesRegex(ValueError, "attempt_state_transition_invalid"):
                    store.transition_attempt(transitioned.attempt_digest, unknown)

                state = context.new_execution_state(state="Pending", next_operation_index=0, owner_id=None,
                                                    current_attempt_id=None, recovery_code=None,
                                                    operation_receipt_refs=(), started_at="2026-09-04T00:00:00Z",
                                                    updated_at="2026-09-04T00:00:00Z")
                stored_state = store.save_execution(state)
                applying = context.continue_execution_state(store.get_execution(context.identity.application_id),
                                                            state="Applying", owner_id="worker-1", current_attempt_id="attempt-1",
                                                            updated_at="2026-09-04T00:00:01Z")
                self.assertEqual(store.transition_execution(stored_state.state_digest, applying).state, "Applying")
                stale_state = context.continue_execution_state(store.get_execution(context.identity.application_id),
                                                               state="Applying", updated_at="2026-09-04T00:00:02Z")
                with self.assertRaisesRegex(ValueError, "application_state_stale"):
                    store.transition_execution(stored_state.state_digest, stale_state)

                with self.assertRaisesRegex(ValueError, "application_finalization_required"):
                    applied_state = context.continue_execution_state(store.get_execution(context.identity.application_id),
                                                                     state="Applied", updated_at="2026-09-04T00:00:03Z")
                    store.transition_execution(store.get_execution(context.identity.application_id).state_digest, applied_state)
        finally:
            directory.cleanup()

    def test_generic_application_cas_rejects_applied_from_every_prior_state(self):
        directory, context = self._context()
        try:
            for state_name in ("Pending", "Applying", "PartiallyApplied", "Failed", "Blocked", "OutcomeUnknown", "Applied"):
                with self.subTest(state=state_name), tempfile.TemporaryDirectory() as temporary:
                    store = SQLiteExecutionStore(Path(temporary) / "state.sqlite3", context.workspace_identity,
                                                 runtime_service=context.service)
                    owner = "worker-1" if state_name == "Applying" else None
                    current_attempt = "attempt-1" if state_name == "Applying" else None
                    state = context.new_execution_state(state=state_name, next_operation_index=0, owner_id=owner,
                                                        current_attempt_id=current_attempt, recovery_code=None,
                                                        operation_receipt_refs=(), started_at="2026-09-04T00:00:00Z",
                                                        updated_at="2026-09-04T00:00:00Z")
                    stored = store.save_execution(state)
                    candidate = context.continue_execution_state(stored, state="Applied", updated_at="2026-09-04T00:00:01Z")
                    with self.assertRaisesRegex(ValueError, "application_finalization_required"):
                        store.transition_execution(stored.state_digest, candidate)
        finally:
            directory.cleanup()

    def test_application_progress_requires_receipts_and_preserves_claim_rules(self):
        directory, context = self._context()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                store = SQLiteExecutionStore(Path(temporary) / "state.sqlite3", context.workspace_identity,
                                             runtime_service=context.service)
                initial = context.new_execution_state(state="Pending", next_operation_index=0, owner_id=None,
                                                      current_attempt_id=None, recovery_code=None,
                                                      operation_receipt_refs=(), started_at="2026-09-04T00:00:00Z",
                                                      updated_at="2026-09-04T00:00:00Z")
                store.save_execution(initial)
                applying = context.continue_execution_state(store.get_execution(context.identity.application_id), state="Applying", owner_id="worker-1",
                                                            current_attempt_id="attempt-1", updated_at="2026-09-04T00:00:01Z")
                store.transition_execution(initial.with_digest().state_digest, applying)
                missing = context.continue_execution_state(store.get_execution(context.identity.application_id),
                                                           state="PartiallyApplied", next_operation_index=1,
                                                           operation_receipt_refs=("missing-receipt",), owner_id=None,
                                                           current_attempt_id=None, updated_at="2026-09-04T00:00:02Z")
                with self.assertRaisesRegex(ValueError, "application_progress_invalid"):
                    store.transition_execution(store.get_execution(context.identity.application_id).state_digest, missing)
                receipt_payload = {"repository_identity": context.repository_identity, "issue_number": 1}
                receipt = context.new_receipt(0, {"result_kind": "issue", "result_identity": "issue-1",
                                                  "result_digest": digest(receipt_payload), "result_payload": receipt_payload},
                                              "2026-09-04T00:00:02Z", "2026-09-04T00:00:03Z")
                store.record_operation_receipt(receipt)
                progressed = context.continue_execution_state(store.get_execution(context.identity.application_id),
                                                              state="PartiallyApplied", next_operation_index=1,
                                                              operation_receipt_refs=(receipt.operation_receipt_id,),
                                                              owner_id=None, current_attempt_id=None,
                                                              updated_at="2026-09-04T00:00:03Z")
                self.assertEqual(store.transition_execution(store.get_execution(context.identity.application_id).state_digest,
                                                            progressed).state, "PartiallyApplied")
                replacement = context.continue_execution_state(store.get_execution(context.identity.application_id),
                                                               state="Applying", next_operation_index=1,
                                                               operation_receipt_refs=("different",), owner_id="worker-2",
                                                               current_attempt_id="attempt-2", updated_at="2026-09-04T00:00:04Z")
                with self.assertRaisesRegex(ValueError, "application_progress_invalid"):
                    store.transition_execution(store.get_execution(context.identity.application_id).state_digest, replacement)
        finally:
            directory.cleanup()

    def test_only_applying_to_partial_can_advance_application_progress(self):
        directory, context = self._context()
        try:
            def state(name, index=0, refs=(), owner=None, attempt=None):
                return context.new_execution_state(state=name, next_operation_index=index,
                    owner_id=owner, current_attempt_id=attempt, recovery_code=None,
                    operation_receipt_refs=refs, started_at="2026-09-04T00:00:00Z",
                    updated_at="2026-09-04T00:00:00Z")

            for old_name, old_owner, old_attempt in (
                ("Pending", None, None), ("PartiallyApplied", None, None),
                ("Applying", "worker-1", "attempt-1")):
                old = state(old_name, owner=old_owner, attempt=old_attempt)
                targets = ("Applying", "Failed", "Blocked") if old_name != "Applying" else ("Failed", "Blocked", "OutcomeUnknown")
                for target in targets:
                    with self.subTest(old=old_name, target=target):
                        candidate = state(target, 1, ("receipt-1",),
                                          owner="worker-1" if target == "Applying" else None,
                                          attempt="attempt-1" if target == "Applying" else (old_attempt if old_name == "Applying" else None))
                        with self.assertRaisesRegex(ValueError, "application_progress_invalid"):
                            validate_application_transition(old, candidate)

            old = state("Applying", owner="worker-1", attempt="attempt-1")
            unchanged = state("PartiallyApplied", 0, (), None, None)
            with self.assertRaisesRegex(ValueError, "application_(progress|coordination)_invalid"):
                validate_application_transition(old, unchanged)
            for candidate in (state("PartiallyApplied", 2, ("r1", "r2"), None, None),):
                with self.assertRaisesRegex(ValueError, "application_progress_invalid"):
                    validate_application_transition(old, candidate)
            old_with_ref = state("Applying", 1, ("original",), "worker-1", "attempt-1")
            for candidate in (state("PartiallyApplied", 2, ("replacement", "new"), None, None),):
                with self.assertRaisesRegex(ValueError, "application_progress_invalid"):
                    validate_application_transition(old_with_ref, candidate)
            with self.assertRaisesRegex(ValueError, "application_state_invalid"):
                state("PartiallyApplied", 2, ("original", "original"), None, None)
        finally:
            directory.cleanup()

    def test_idle_coordination_and_completed_looking_applied_are_rejected(self):
        directory, context = self._context()
        try:
            for idle in ("Pending", "PartiallyApplied"):
                for owner, current in (("worker-1", None), (None, "attempt-1"), ("worker-1", "attempt-1")):
                    with self.subTest(idle=idle, owner=owner, current=current), self.assertRaisesRegex(ValueError, "application_coordination_invalid"):
                        context.new_execution_state(state=idle, next_operation_index=0, owner_id=owner,
                            current_attempt_id=current, recovery_code=None, operation_receipt_refs=(),
                            started_at="2026-09-04T00:00:00Z", updated_at="2026-09-04T00:00:00Z")

            pending = context.new_execution_state(state="Pending", next_operation_index=0, owner_id=None,
                current_attempt_id=None, recovery_code=None, operation_receipt_refs=(),
                started_at="2026-09-04T00:00:00Z", updated_at="2026-09-04T00:00:00Z").with_digest()
            for owner, current in ((None, None), ("worker-1", None), (None, "attempt-1")):
                with self.subTest(entering_applying=(owner, current)), self.assertRaisesRegex(ValueError, "application_coordination_invalid"):
                    validate_application_transition(pending, context.continue_execution_state(pending, state="Applying",
                        owner_id=owner, current_attempt_id=current))
            valid_applying = context.continue_execution_state(pending, state="Applying", owner_id="worker-1",
                current_attempt_id="attempt-1")
            validate_application_transition(pending, valid_applying)

            applying = context.new_execution_state(state="Applying", next_operation_index=0, owner_id="worker-1",
                current_attempt_id="attempt-1", recovery_code=None, operation_receipt_refs=(),
                started_at="2026-09-04T00:00:00Z", updated_at="2026-09-04T00:00:00Z").with_digest()
            for target in ("Failed", "Blocked", "OutcomeUnknown"):
                for owner, current in (("worker-2", "attempt-1"), ("worker-1", "attempt-2"), ("worker-1", None)):
                    with self.subTest(target=target, owner=owner, current=current), self.assertRaisesRegex(ValueError, "application_coordination_invalid"):
                        validate_application_transition(applying, context.continue_execution_state(applying, state=target,
                            owner_id=owner, current_attempt_id=current))
                validate_application_transition(applying, context.continue_execution_state(applying, state=target,
                    owner_id="worker-1", current_attempt_id="attempt-1"))
                validate_application_transition(applying, context.continue_execution_state(applying, state=target,
                    owner_id=None, current_attempt_id="attempt-1"))

            with tempfile.TemporaryDirectory() as temporary:
                store = SQLiteExecutionStore(Path(temporary) / "state.sqlite3", context.workspace_identity,
                                             runtime_service=context.service)
                initial = context.new_execution_state(state="Pending", next_operation_index=0, owner_id=None,
                    current_attempt_id=None, recovery_code=None, operation_receipt_refs=(),
                    started_at="2026-09-04T00:00:00Z", updated_at="2026-09-04T00:00:00Z")
                stored = store.save_execution(initial)
                applied = context.continue_execution_state(stored, state="Applied", next_operation_index=1,
                    operation_receipt_refs=("plausible-receipt",), updated_at="2026-09-04T00:00:01Z")
                with self.assertRaisesRegex(ValueError, "application_finalization_required"):
                    store.transition_execution(stored.state_digest, applied)
        finally:
            directory.cleanup()

    def test_runtime_continuation_credential_matrix_preserves_historical_provenance(self):
        directory, principal = self._context("2")
        legacy_directory, legacy = self._context("1")
        try:
            def historical(context, provenance):
                operation = context.expected_operations[0]
                op_id = operation_identity(context.identity.application_id, 0, operation)
                return OperationAttemptState(context.identity.application_id, op_id, 0, operation, provenance,
                    context.driver_identity, context.remote_authority, request_identity(op_id), "Applying",
                    "2026-09-04T00:00:00Z", "2026-09-04T00:00:00Z", context.identity).with_digest()

            def altered(provenance, **changes):
                return AuthorityProvenance.from_dict({**provenance.to_dict(), **changes})

            principal_base = principal.provenance
            principal_historical = historical(principal, altered(principal_base, credential_instance_id="X"))
            principal_same = principal.continue_attempt(principal_historical, state="Failed",
                                                         updated_at="2026-09-04T00:00:01Z")
            self.assertIsNot(principal_same, principal_historical)
            self.assertEqual(principal_same.authority_binding.to_dict(), principal_historical.authority_binding.to_dict())
            self.assertEqual(principal_same.started_at, principal_historical.started_at)
            self.assertEqual(principal_same.operation_identity, principal_historical.operation_identity)
            self.assertEqual(principal_same.request_identity, principal_historical.request_identity)
            principal.service.validate_live_artifact(principal_same, principal, "attempt")
            with self.assertRaisesRegex(ValueError, "runtime_authority_required"):
                principal.service.validate_live_artifact(principal_historical, principal, "attempt")
            with self.assertRaisesRegex(ValueError, "credential_continuity_mismatch"):
                principal.continue_attempt(historical(principal, altered(principal_base,
                    credential_principal_identity="different-principal")), state="Failed",
                    updated_at="2026-09-04T00:00:01Z")

            legacy_base = legacy.provenance
            legacy_historical = historical(legacy, legacy_base)
            legacy_same = legacy.continue_attempt(legacy_historical, state="Failed",
                                                  updated_at="2026-09-04T00:00:01Z")
            self.assertIsNot(legacy_same, legacy_historical)
            self.assertEqual(legacy_same.authority_binding.to_dict(), legacy_historical.authority_binding.to_dict())
            legacy.service.validate_live_artifact(legacy_same, legacy, "attempt")
            with self.assertRaisesRegex(ValueError, "runtime_authority_required"):
                legacy.service.validate_live_artifact(legacy_historical, legacy, "attempt")
            for changes in ({"credential_instance_id": "different-instance"},
                            {"issuer_id": "different-issuer"}):
                with self.subTest(legacy_changes=changes), self.assertRaisesRegex(ValueError, "credential_continuity_mismatch"):
                    legacy.continue_attempt(historical(legacy, altered(legacy_base, **changes)), state="Failed",
                                            updated_at="2026-09-04T00:00:01Z")

            with self.assertRaisesRegex(ValueError, "credential_continuity_mismatch"):
                principal.continue_attempt(historical(principal, altered(principal_base,
                    credential_principal_identity="", issuer_id="issuer", credential_instance_id="instance")),
                    state="Failed", updated_at="2026-09-04T00:00:01Z")
            with self.assertRaisesRegex(ValueError, "credential_continuity_mismatch"):
                legacy.continue_attempt(historical(legacy, altered(legacy_base,
                    credential_principal_identity="principal")), state="Failed",
                    updated_at="2026-09-04T00:00:01Z")
        finally:
            directory.cleanup()
            legacy_directory.cleanup()

    def test_caller_created_artifacts_cannot_first_insert(self):
        directory, context = self._context()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                store = SQLiteExecutionStore(Path(temporary) / "state.sqlite3", context.workspace_identity,
                                             runtime_service=context.service)
                state = ApplicationExecutionState(context.identity.application_id, context.identity, "Pending", 0, None, None,
                                                  None, (), "2026-09-04T00:00:00Z", "2026-09-04T00:00:00Z", None,
                                                  context.continuity_anchor, _live_context=context)
                with self.assertRaisesRegex(ValueError, "runtime_context_invalid|runtime_authority_required"):
                    store.save_execution(state)
                operation = context.expected_operations[0]
                op_id = operation_identity(context.identity.application_id, 0, operation)
                attempt = OperationAttemptState(context.identity.application_id, op_id, 0, operation, context.provenance,
                                                context.driver_identity, context.remote_authority, request_identity(op_id),
                                                "Applying", "2026-09-04T00:00:00Z", "2026-09-04T00:00:00Z",
                                                context.identity, _live_context=context)
                with self.assertRaisesRegex(ValueError, "runtime_context_invalid|runtime_authority_required"):
                    store.create_attempt_if_absent(attempt)
                result_payload = {"repository_identity": context.repository_identity, "issue_number": 1}
                result = {"result_kind": "issue", "result_identity": "issue-1", "result_digest": digest(result_payload),
                          "result_payload": result_payload}
                receipt = OperationReceipt.create(context.identity, 0, operation, context, result,
                                                  "2026-09-04T00:00:00Z", "2026-09-04T00:00:01Z")
                with self.assertRaisesRegex(ValueError, "runtime_context_invalid|runtime_authority_required"):
                    store.record_operation_receipt(receipt)
                final = ApplicationReceipt.create(context.identity, context.operation_set_digest,
                                                  context.expected_operations, (receipt,), "2026-09-04T00:00:00Z",
                                                  "2026-09-04T00:00:01Z")
                with self.assertRaisesRegex(ValueError, "runtime_context_invalid|runtime_authority_required"):
                    store.record_application_receipt(final)
        finally:
            directory.cleanup()

    def test_historical_attempt_does_not_become_live_and_provenance_is_preserved(self):
        directory, context = self._context()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                store = SQLiteExecutionStore(Path(temporary) / "state.sqlite3", context.workspace_identity,
                                             runtime_service=context.service)
                attempt = context.new_attempt(0, state="Applying", started_at="2026-09-04T00:00:00Z",
                                              updated_at="2026-09-04T00:00:00Z")
                store.create_attempt_if_absent(attempt)
                historical = store.get_attempt(context.identity.application_id, attempt.operation_identity)
                continued = context.continue_attempt(historical, state="Failed", updated_at="2026-09-04T00:00:01Z")
                self.assertEqual(continued.authority_binding.to_dict(), historical.authority_binding.to_dict())
                self.assertEqual(continued.started_at, historical.started_at)
                self.assertIsNot(historical._live_context, context)
                untrusted_candidate = OperationAttemptState(
                    historical.application_id, historical.operation_identity, historical.operation_index,
                    historical.operation, historical.authority_binding, historical.driver_identity,
                    historical.remote_authority, historical.request_identity, "Failed", historical.started_at,
                    "2026-09-04T00:00:02Z", historical.identity)
                with self.assertRaisesRegex(ValueError, "runtime_authority_required|runtime_context_invalid"):
                    store.transition_attempt(historical.attempt_digest, untrusted_candidate)
        finally:
            directory.cleanup()


if __name__ == "__main__":
    unittest.main()
