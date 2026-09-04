from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from tempfile import TemporaryDirectory
import threading
import unittest

from delivery_system.application_identity import operation_identity
from delivery_system.drivers.write_contract import (
    WRITE_CONTRACT_VERSION,
    WRITE_EXECUTOR_IDENTITY,
    WriteObservation,
    WriteObservationKind,
)
from delivery_system.execution_store import SQLiteExecutionStore
from delivery_system.canonical import digest
from delivery_system.applier import ApplyResult, render_create_issue
from delivery_system.applier import _materialize, _trusted_success_result
from delivery_system.execution_state import APPLIER_ORCHESTRATION_POLICY
from delivery_system.runtime import RuntimeApprovalAuthorityService
import delivery_system.runtime as runtime_module
from tests.fakes.fake_write_driver import FakeWriteDriver
from tests.v1 import test_operational_approval_authority as approval_fixture
from unittest.mock import patch


class _CrashingWriteDriver:
    executor_identity = WRITE_EXECUTOR_IDENTITY

    def __init__(self, message: str = "dispatch-crash") -> None:
        self.message = message
        self.calls = 0

    def _crash(self, command: object) -> WriteObservation:
        self.calls += 1
        raise RuntimeError(self.message)

    create_issue = _crash
    add_sub_issue = _crash
    add_dependency = _crash


class _BlockingWriteDriver:
    executor_identity = WRITE_EXECUTOR_IDENTITY

    def __init__(self, observation: WriteObservation) -> None:
        self.observation = observation
        self.entered = threading.Event()
        self.release = threading.Event()
        self.calls = 0

    def create_issue(self, command: object) -> WriteObservation:
        self.calls += 1
        self.entered.set()
        self.release.wait(5)
        return self.observation

    def add_sub_issue(self, command: object) -> WriteObservation:
        return self.create_issue(command)

    def add_dependency(self, command: object) -> WriteObservation:
        return self.create_issue(command)


class _ClockChangingWriteDriver:
    executor_identity = WRITE_EXECUTOR_IDENTITY

    def __init__(self, observation: WriteObservation, change_clock) -> None:
        self.observation = observation
        self.change_clock = change_clock
        self.calls = 0

    def create_issue(self, command: object) -> WriteObservation:
        self.calls += 1
        self.change_clock()
        return self.observation

    add_sub_issue = create_issue
    add_dependency = create_issue


class _FailingCommitConnection:
    def __init__(self, connection) -> None:
        self._connection = connection
        self._failed = False

    def execute(self, *args, **kwargs):
        return self._connection.execute(*args, **kwargs)

    def commit(self):
        if not self._failed:
            self._failed = True
            raise RuntimeError("finalization_commit_abort")
        return self._connection.commit()

    def rollback(self):
        return self._connection.rollback()

    def close(self):
        return self._connection.close()


class ApplierOrchestrationTests(unittest.TestCase):
    def _compose(self, observations=(), driver=None):
        harness = approval_fixture.OperationalApprovalAuthorityTests()
        directory, context, preview_store, preview, audit, foundation = harness._setup("memory")
        driver = driver or FakeWriteDriver(observations)
        with patch.object(runtime_module, "_compose_production_write_executor", return_value=driver):
            service = RuntimeApprovalAuthorityService(
                context, preview_store, foundation.attestation_service,
                clock=foundation.clock, write_token_provider=object(),
            )
        approval = service.record_approval(
            preview["preview_id"], 1,
            f"批准写入 {preview['preview_id']} 1", "human",
        )
        authority = service.issue_application_authority(
            preview["preview_id"], 1, approval.approval_id,
        )
        return directory, context, preview, service, authority, driver

    def _store(self, context, service, directory):
        return SQLiteExecutionStore(
            directory.name + "\\execution.sqlite3", context.workspace_identity,
            runtime_service=service,
        )

    @staticmethod
    def _success(repository="owner/repo", number=1, numeric_id="1"):
        return WriteObservation(
            WriteObservationKind.DEFINITIVE_SUCCESS,
            "github-issue:node-1",
            {
                "repository_identity": repository,
                "issue_number": number,
                "numeric_issue_id": numeric_id,
                "node_id": "node-1",
                "executor_identity": WRITE_EXECUTOR_IDENTITY,
                "contract_version": WRITE_CONTRACT_VERSION,
                "response_status": 201,
            },
        )

    @staticmethod
    def _relationship_success(repository="owner/repo", identity="relationship"):
        return WriteObservation(
            WriteObservationKind.DEFINITIVE_SUCCESS,
            "github-write-result-" + identity,
            {"repository_identity": repository,
             "executor_identity": WRITE_EXECUTOR_IDENTITY,
             "contract_version": WRITE_CONTRACT_VERSION,
             "response_status": 201},
        )

    def _compose_operations(self, refs, operations, observations):
        plan = deepcopy(approval_fixture.base_plan())
        item = deepcopy(plan["work_items"][0])
        plan["work_items"] = []
        for ref in refs:
            copy_item = deepcopy(item)
            copy_item["client_ref"] = ref
            plan["work_items"].append(copy_item)
        plan["operation_intents"] = operations
        plan["planned_relationships"] = [
            {"kind": "planned_parent" if op["operation_kind"] == "add_sub_issue" else "planned_dependency",
             "from_client_ref": op["client_refs"][0], "to_client_ref": op["client_refs"][1]}
            for op in operations if op["operation_kind"] in {"add_sub_issue", "add_dependency"}
        ]
        with patch.object(approval_fixture, "plan", return_value=plan):
            return self._compose(observations)

    def test_public_applier_surface_is_executor_bound(self):
        directory, context, preview, service, authority, driver = self._compose((self._success(),))
        try:
            store = self._store(context, service, directory)
            applier = service.create_applier(store)
            self.assertEqual(applier.apply(authority.authority_id).state, "Applied")
            self.assertEqual(applier.__slots__, ("_apply_fn",))
            self.assertFalse(hasattr(applier, "executor"))
            self.assertFalse(hasattr(applier, "store"))
            with self.assertRaisesRegex(TypeError, "unexpected keyword argument"):
                applier.apply(authority.authority_id, executor=driver)  # type: ignore[call-arg]
        finally:
            directory.cleanup()

    def test_runtime_without_executor_requires_orchestration_executor(self):
        directory, context, preview, service, authority, driver = self._compose((self._success(),))
        try:
            foundation = approval_fixture.OperationalApprovalAuthorityTests()._setup("memory")
            try:
                with self.assertRaisesRegex(ValueError, "^write_executor_required$"):
                    foundation[-1].create_applier(self._store(context, foundation[-1], directory))
            finally:
                foundation[0].cleanup()
        finally:
            directory.cleanup()

    def test_legacy_and_managed_policy_digest_contracts(self):
        directory, context, preview, service, authority, driver = self._compose((self._success(),))
        try:
            live = service.create_execution_context(authority.authority_id)
            legacy = live.new_execution_state(
                state="Pending", next_operation_index=0, owner_id=None,
                current_attempt_id=None, recovery_code=None, operation_receipt_refs=(),
                started_at="2026-08-14T12:00:00Z", updated_at="2026-08-14T12:00:00Z",
                completed_at=None,
            ).with_digest()
            self.assertNotIn("orchestration_policy", legacy.payload())
            self.assertEqual(legacy.state_digest, digest(legacy.payload()))
            managed = live.new_execution_state(
                state="Pending", next_operation_index=0, owner_id=None,
                current_attempt_id=None, recovery_code=None, operation_receipt_refs=(),
                started_at="2026-08-14T12:00:00Z", updated_at="2026-08-14T12:00:00Z",
                completed_at=None, orchestration_policy=APPLIER_ORCHESTRATION_POLICY,
            ).with_digest()
            self.assertEqual(managed.payload()["orchestration_policy"], APPLIER_ORCHESTRATION_POLICY)
            self.assertNotEqual(managed.state_digest, legacy.state_digest)
        finally:
            directory.cleanup()

    def test_shadow_store_cannot_mutate_durable_managed_application(self):
        directory, context, preview, service, authority, driver = self._compose((self._success(),))
        try:
            path = directory.name + "\\execution.sqlite3"
            store = self._store(context, service, directory)
            service.create_applier(store).apply(authority.authority_id)
            shadow = RuntimeApprovalAuthorityService(
                context, service.store, service.attestation_service, clock=service.clock,
            )
            approval = shadow.record_approval(
                preview["preview_id"], 1,
                f"批准写入 {preview['preview_id']} 1", "human",
            )
            shadow_authority = shadow.issue_application_authority(
                preview["preview_id"], 1, approval.approval_id,
            )
            shadow_context = shadow.create_execution_context(shadow_authority.authority_id)
            shadow_store = SQLiteExecutionStore(path, context.workspace_identity, runtime_service=shadow)
            state = shadow_store.get_execution(
                shadow_context.identity.application_id,
                expected_operations=shadow_context.expected_operations,
            )
            candidate = shadow_context.continue_execution_state(
                state, state="Applied", completed_at="2026-08-14T12:00:00Z",
                updated_at="2026-08-14T12:00:00Z",
            )
            with self.assertRaisesRegex(ValueError, "^applier_orchestration_required$"):
                shadow_store.save_execution(candidate)
        finally:
            directory.cleanup()

    def test_crash_b_after_remote_success_never_redispatches(self):
        directory, context, preview, service, authority, driver = self._compose((self._success(),))
        try:
            store = self._store(context, service, directory)
            applier = service.create_applier(store)
            original_complete = store.complete_operation_success

            def abort_completion(*args, **kwargs):
                raise RuntimeError("simulated_local_commit_abort")

            with patch.object(store, "complete_operation_success", side_effect=abort_completion):
                with self.assertRaisesRegex(RuntimeError, "simulated_local_commit_abort"):
                    applier.apply(authority.authority_id)
            self.assertEqual(len(driver.trace), 1)
            runtime_context = service.create_execution_context(authority.authority_id)
            state = store.get_execution(runtime_context.identity.application_id)
            self.assertEqual((state.state, state.next_operation_index), ("Applying", 0))
            with self.assertRaisesRegex(ValueError, "^operation_receipt_not_found$"):
                store.get_operation_receipt(runtime_context.identity.application_id, "missing")
            self.assertEqual(applier.apply(authority.authority_id).recovery_code,
                             "application_recovery_required")
            self.assertEqual(len(driver.trace), 1)
        finally:
            directory.cleanup()

    def test_crash_c_final_success_can_only_finalize_locally_after_restart(self):
        directory, context, preview, service, authority, driver = self._compose((self._success(),))
        try:
            store = self._store(context, service, directory)
            applier = service.create_applier(store)
            with patch.object(store, "finalize_application", side_effect=RuntimeError("simulated_finalize_abort")):
                with self.assertRaisesRegex(RuntimeError, "simulated_finalize_abort"):
                    applier.apply(authority.authority_id)
            self.assertEqual(len(driver.trace), 1)
            runtime_context = service.create_execution_context(authority.authority_id)
            partial = store.get_execution(runtime_context.identity.application_id)
            self.assertEqual((partial.state, partial.next_operation_index), ("PartiallyApplied", 1))
            second = applier.apply(authority.authority_id)
            self.assertEqual(second.state, "Applied")
            self.assertEqual(len(driver.trace), 1)
            replay = applier.apply(authority.authority_id)
            self.assertEqual(replay.application_receipt_id, second.application_receipt_id)
            self.assertEqual(len(driver.trace), 1)
        finally:
            directory.cleanup()

    def test_claim_clock_regression_is_rejected_before_attempt_insert(self):
        directory, context, preview, service, authority, driver = self._compose((self._success(),))
        try:
            store = self._store(context, service, directory)
            live = service.create_execution_context(authority.authority_id)
            initial = live.new_execution_state(
                state="Pending", next_operation_index=0, owner_id=None,
                current_attempt_id=None, recovery_code=None, operation_receipt_refs=(),
                started_at="2026-08-14T12:00:00Z", updated_at="2026-08-14T12:00:00Z",
                completed_at=None, orchestration_policy=APPLIER_ORCHESTRATION_POLICY,
            )
            capability = service._write_executor_factory(store)
            store.create_execution_if_absent(capability, initial)
            service.clock = lambda: __import__("datetime").datetime(2026, 8, 14, 11, 0,
                                                                        tzinfo=__import__("datetime").timezone.utc)
            with self.assertRaisesRegex(ValueError, "^execution_clock_invalid$"):
                service.create_applier(store).apply(authority.authority_id)
            self.assertEqual(len(driver.trace), 0)
        finally:
            directory.cleanup()

    def test_arbitrary_executor_constructor_argument_is_not_supported(self):
        directory, context, preview, service, authority, driver = self._compose((self._success(),))
        try:
            with self.assertRaises(TypeError):
                RuntimeApprovalAuthorityService(
                    context, service.store, service.attestation_service,
                    clock=service.clock, write_executor=driver,  # type: ignore[call-arg]
                )
        finally:
            directory.cleanup()

    def test_initialization_and_success_are_atomic_bounded_results(self):
        directory, context, preview, service, authority, driver = self._compose((self._success(),))
        try:
            store = self._store(context, service, directory)
            result = service.create_applier(store).apply(authority.authority_id)
            self.assertEqual((result.state, result.next_operation_index), ("Applied", 1))
            self.assertIsNotNone(result.application_receipt_id)
            self.assertEqual(len(driver.trace), 1)
            replay = service.create_applier(store).apply(authority.authority_id)
            self.assertEqual(replay, result)
            self.assertEqual(len(driver.trace), 1)
        finally:
            directory.cleanup()

    def test_generic_mutation_lockdown_rejects_fabricated_receipt_and_state(self):
        directory, context, preview, service, authority, driver = self._compose((self._success(),))
        try:
            store = self._store(context, service, directory)
            runtime_context = service.create_execution_context(authority.authority_id)
            state = runtime_context.new_execution_state(
                state="Pending", next_operation_index=0, owner_id=None,
                current_attempt_id=None, recovery_code=None,
                operation_receipt_refs=(), started_at="2026-08-14T12:00:00Z",
                updated_at="2026-08-14T12:00:00Z", completed_at=None,
            )
            with self.assertRaisesRegex(ValueError, "^applier_orchestration_required$"):
                store.save_execution(state)
            fabricated_payload = {"status": 201}
            receipt = runtime_context.new_receipt(
                0, {"result_kind": "github.create_issue.v1", "result_identity": "x",
                    "result_digest": digest(fabricated_payload), "result_payload": fabricated_payload},
                "2026-08-14T12:00:00Z", "2026-08-14T12:00:00Z",
            )
            with self.assertRaisesRegex(ValueError, "^applier_orchestration_required$"):
                store.record_operation_receipt(receipt)
        finally:
            directory.cleanup()

    def test_rendered_item_snapshot_is_runtime_owned_and_bounded(self):
        directory, context, preview, service, authority, driver = self._compose((self._success(),))
        try:
            runtime_context = service.create_execution_context(authority.authority_id)
            item = runtime_context.canonical_items[0]
            self.assertEqual(item["title"]["value"], "Existing bug")
            item["title"]["value"] = "caller mutation"
            self.assertEqual(runtime_context.canonical_items[0]["title"]["value"], "Existing bug")
        finally:
            directory.cleanup()

    def test_render_contract_is_fixed_and_write_metadata_is_informational(self):
        directory, context, preview, service, authority, driver = self._compose((self._success(),))
        try:
            item = service.create_execution_context(authority.authority_id).canonical_items[0]
            title, body = render_create_issue(item)
            self.assertEqual(title, "Existing bug")
            headings = [
                "Client reference", "Role", "Context / Problem", "Outcome", "Scope",
                "Non-goals", "Acceptance criteria", "Verification", "Required capabilities",
                "Write metadata (informational only)",
            ]
            self.assertEqual([line[3:] for line in body.splitlines() if line.startswith("## ")],
                             [f"## {heading}"[3:] for heading in headings])
            self.assertIn('    ["issues"]', body)
            self.assertNotIn("labels", body)
        finally:
            directory.cleanup()

    def test_every_legacy_mutator_is_locked_in_executor_mode(self):
        directory, context, preview, service, authority, driver = self._compose((self._success(),))
        try:
            store = self._store(context, service, directory)
            calls = [
                lambda: store.save_execution(None),
                lambda: store.save_attempt(None),
                lambda: store.create_attempt_if_absent(None),
                lambda: store.transition_execution(None, None),
                lambda: store.transition_attempt(None, None),
                lambda: store.record_operation_receipt(None),
                lambda: store.record_application_receipt(None),
            ]
            for call in calls:
                with self.subTest(mutator=call):
                    with self.assertRaisesRegex(ValueError, "^applier_orchestration_required$"):
                        call()
        finally:
            directory.cleanup()

    def test_persisted_applying_is_recovery_only_after_dispatch_crash(self):
        crashing = _CrashingWriteDriver()
        directory, context, preview, service, authority, driver = self._compose(driver=crashing)
        try:
            store = self._store(context, service, directory)
            applier = service.create_applier(store)
            with self.assertRaisesRegex(RuntimeError, "dispatch-crash"):
                applier.apply(authority.authority_id)
            self.assertEqual(crashing.calls, 1)
            result = applier.apply(authority.authority_id)
            self.assertEqual((result.state, result.recovery_code), ("Applying", "application_recovery_required"))
            self.assertEqual(crashing.calls, 1)
        finally:
            directory.cleanup()

    def test_ambiguous_is_terminal_recovery_without_retry(self):
        directory, context, preview, service, authority, driver = self._compose((WriteObservation(
            WriteObservationKind.AMBIGUOUS, "", None, "github_write_transport_ambiguous",
        ),))
        try:
            store = self._store(context, service, directory)
            result = service.create_applier(store).apply(authority.authority_id)
            self.assertEqual((result.state, result.recovery_code), ("OutcomeUnknown", "github_write_transport_ambiguous"))
            self.assertEqual(len(driver.trace), 1)
            replay = service.create_applier(store).apply(authority.authority_id)
            self.assertEqual(replay.state, "OutcomeUnknown")
            self.assertEqual(len(driver.trace), 1)
        finally:
            directory.cleanup()

    def test_rejected_write_creates_no_success_receipt(self):
        directory, context, preview, service, authority, driver = self._compose((WriteObservation(
            WriteObservationKind.DEFINITIVE_REJECTED, "", {"status": 422}, "github_write_rejected",
        ),))
        try:
            store = self._store(context, service, directory)
            result = service.create_applier(store).apply(authority.authority_id)
            self.assertEqual((result.state, result.recovery_code), ("Failed", "github_write_rejected"))
            self.assertEqual(len(driver.trace), 1)
            with self.assertRaisesRegex(ValueError, "^operation_receipt_not_found$"):
                store.get_operation_receipt(result.application_id, "missing")
        finally:
            directory.cleanup()

    def test_runtime_capability_is_service_and_store_local(self):
        d1, c1, p1, s1, a1, driver1 = self._compose((self._success(),))
        d2, c2, p2, s2, a2, driver2 = self._compose((self._success(),))
        try:
            st1 = self._store(c1, s1, d1)
            st2 = self._store(c2, s2, d2)
            applier = s1.create_applier(st1)
            self.assertEqual(applier.apply(a1.authority_id).state, "Applied")
            with self.assertRaisesRegex(ValueError, "^applier_store_binding_invalid$"):
                s1.create_applier(st2)
            self.assertFalse(hasattr(s1, "write_executor"))
            self.assertFalse(hasattr(applier, "_executor"))
        finally:
            d1.cleanup(); d2.cleanup()

    def test_two_appliers_have_one_claim_and_one_dispatch(self):
        blocking = _BlockingWriteDriver(self._success())
        directory, context, preview, service, authority, driver = self._compose(driver=blocking)
        second_store = None
        try:
            first_store = self._store(context, service, directory)
            second_store = SQLiteExecutionStore(
                directory.name + "\\execution.sqlite3", context.workspace_identity,
                runtime_service=service,
            )
            first = service.create_applier(first_store)
            second = service.create_applier(second_store)
            results = []
            errors = []

            def run(applier):
                try:
                    results.append(applier.apply(authority.authority_id))
                except Exception as exc:  # pragma: no cover - assertion below reports it
                    errors.append(exc)

            thread = threading.Thread(target=run, args=(first,))
            thread.start()
            self.assertTrue(blocking.entered.wait(2))
            loser = second.apply(authority.authority_id)
            self.assertEqual((loser.state, loser.recovery_code),
                             ("Applying", "application_recovery_required"))
            blocking.release.set()
            thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].state, "Applied")
            self.assertEqual(blocking.calls, 1)
        finally:
            if second_store is not None:
                pass
            directory.cleanup()

    def test_claim_updated_at_regression_is_rejected_before_attempt_insert(self):
        directory, context, preview, service, authority, driver = self._compose((self._success(),))
        try:
            store = self._store(context, service, directory)
            live = service.create_execution_context(authority.authority_id)
            initial = live.new_execution_state(
                state="Pending", next_operation_index=0, owner_id=None,
                current_attempt_id=None, recovery_code=None, operation_receipt_refs=(),
                started_at="2026-08-14T10:00:00Z", updated_at="2026-08-14T12:00:00Z",
                completed_at=None, orchestration_policy=APPLIER_ORCHESTRATION_POLICY,
            )
            capability = service._write_executor_factory(store)
            store.create_execution_if_absent(capability, initial)
            service.clock = lambda: datetime(2026, 8, 14, 11, 0, tzinfo=timezone.utc)
            with self.assertRaisesRegex(ValueError, "^execution_clock_invalid$"):
                service.create_applier(store).apply(authority.authority_id)
            persisted = store.get_execution(initial.application_id)
            self.assertEqual((persisted.state, persisted.next_operation_index, persisted.owner_id, persisted.current_attempt_id),
                             ("Pending", 0, None, None))
            with self.assertRaisesRegex(ValueError, "^operation_attempt_not_found$"):
                store.get_attempt(initial.application_id, "missing")
            self.assertEqual(len(driver.trace), 0)
        finally:
            directory.cleanup()

    def test_equal_claim_clock_is_allowed(self):
        directory, context, preview, service, authority, driver = self._compose((self._success(),))
        try:
            store = self._store(context, service, directory)
            service.clock = lambda: datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)
            result = service.create_applier(store).apply(authority.authority_id)
            self.assertEqual(result.state, "Applied")
            self.assertEqual(len(driver.trace), 1)
        finally:
            directory.cleanup()

    def test_completion_clock_regression_rolls_back_and_never_redispatches(self):
        changed = []
        driver = _ClockChangingWriteDriver(self._success(), lambda: changed.append(True))
        directory, context, preview, service, authority, _ = self._compose(driver=driver)
        try:
            service.clock = lambda: datetime(2026, 8, 14, 12 if not changed else 11, 0, tzinfo=timezone.utc)
            driver.change_clock = lambda: changed.append(True) or setattr(service, "clock", lambda: datetime(2026, 8, 14, 11, 0, tzinfo=timezone.utc))
            store = self._store(context, service, directory)
            with self.assertRaisesRegex(ValueError, "^execution_clock_invalid$"):
                service.create_applier(store).apply(authority.authority_id)
            self.assertEqual(driver.calls, 1)
            runtime_context = service.create_execution_context(authority.authority_id)
            state = store.get_execution(runtime_context.identity.application_id)
            self.assertEqual((state.state, state.next_operation_index), ("Applying", 0))
            with self.assertRaisesRegex(ValueError, "^operation_receipt_not_found$"):
                store.get_operation_receipt(runtime_context.identity.application_id, "missing")
            result = service.create_applier(store).apply(authority.authority_id)
            self.assertEqual((result.state, result.recovery_code), ("Applying", "application_recovery_required"))
            self.assertEqual(driver.calls, 1)
        finally:
            directory.cleanup()

    def test_finalization_clock_regression_rolls_back(self):
        directory, context, preview, service, authority, driver = self._compose((self._success(),))
        try:
            store = self._store(context, service, directory)
            original = store.finalize_application
            def regress(*args, **kwargs):
                return original(*args[:-1], "2026-08-14T11:00:00Z", **kwargs)
            with patch.object(store, "finalize_application", side_effect=regress):
                with self.assertRaisesRegex(ValueError, "^execution_clock_invalid$"):
                    service.clock = lambda: datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)
                    service.create_applier(store).apply(authority.authority_id)
            runtime_context = service.create_execution_context(authority.authority_id)
            state = store.get_execution(runtime_context.identity.application_id)
            self.assertEqual(state.state, "PartiallyApplied")
            with self.assertRaisesRegex(ValueError, "^application_receipt_not_found$"):
                store.get_application_receipt(runtime_context.identity.application_id)
            self.assertEqual(len(driver.trace), 1)
        finally:
            directory.cleanup()

    def test_equal_finalization_clock_is_allowed(self):
        directory, context, preview, service, authority, driver = self._compose((self._success(),))
        try:
            service.clock = lambda: datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)
            result = service.create_applier(self._store(context, service, directory)).apply(authority.authority_id)
            self.assertEqual(result.state, "Applied")
            self.assertEqual(len(driver.trace), 1)
        finally:
            directory.cleanup()

    def test_relationship_sub_issue_uses_child_parent_receipts(self):
        operations = [
            {"operation_kind": "create_issue", "client_refs": ["child"], "depends_on": []},
            {"operation_kind": "create_issue", "client_refs": ["parent"], "depends_on": []},
            {"operation_kind": "add_sub_issue", "client_refs": ["child", "parent"], "depends_on": []},
        ]
        observations = (self._success(number=11, numeric_id="101"),
                        self._success(number=12, numeric_id="102"),
                        self._relationship_success(identity="sub"))
        directory, context, preview, service, authority, driver = self._compose_operations(("child", "parent"), operations, observations)
        try:
            result = service.create_applier(self._store(context, service, directory)).apply(authority.authority_id)
            self.assertEqual(result.state, "Applied")
            self.assertEqual(len(driver.trace), 3)
            command = driver.trace[2].command
            self.assertEqual((command.first.issue_number, command.second.issue_number), (11, 12))
        finally:
            directory.cleanup()

    def test_relationship_dependency_uses_dependent_prerequisite_receipts(self):
        operations = [
            {"operation_kind": "create_issue", "client_refs": ["dependent"], "depends_on": []},
            {"operation_kind": "create_issue", "client_refs": ["prerequisite"], "depends_on": []},
            {"operation_kind": "add_dependency", "client_refs": ["dependent", "prerequisite"], "depends_on": []},
        ]
        observations = (self._success(number=21, numeric_id="201"),
                        self._success(number=22, numeric_id="202"),
                        self._relationship_success(identity="dependency"))
        directory, context, preview, service, authority, driver = self._compose_operations(("dependent", "prerequisite"), operations, observations)
        try:
            result = service.create_applier(self._store(context, service, directory)).apply(authority.authority_id)
            self.assertEqual(result.state, "Applied")
            self.assertEqual(len(driver.trace), 3)
            command = driver.trace[2].command
            self.assertEqual((command.first.issue_number, command.second.issue_number), (21, 22))
        finally:
            directory.cleanup()

    def test_authority_expiry_before_dispatch_blocks_driver(self):
        directory, context, preview, service, authority, driver = self._compose((self._success(),))
        try:
            store = self._store(context, service, directory)
            original_validate = store.validate_claim
            def expire_after_revalidation(*args, **kwargs):
                result = original_validate(*args, **kwargs)
                service.clock = lambda: datetime(2030, 1, 1, 0, 0, tzinfo=timezone.utc)
                return result
            with patch.object(store, "validate_claim", side_effect=expire_after_revalidation):
                try:
                    service.create_applier(store).apply(authority.authority_id)
                except ValueError:
                    pass
            self.assertEqual(len(driver.trace), 0)
        finally:
            directory.cleanup()

    def test_relationship_authority_expiry_after_materialization_blocks_dispatch(self):
        operations = [
            {"operation_kind": "create_issue", "client_refs": ["child"], "depends_on": []},
            {"operation_kind": "create_issue", "client_refs": ["parent"], "depends_on": []},
            {"operation_kind": "add_sub_issue", "client_refs": ["child", "parent"], "depends_on": []},
        ]
        observations = (self._success(number=31, numeric_id="301"),
                        self._success(number=32, numeric_id="302"),
                        self._relationship_success(identity="guard"))
        directory, context, preview, service, authority, driver = self._compose_operations(("child", "parent"), operations, observations)
        try:
            store = self._store(context, service, directory)
            original = store.validate_claim
            calls = [0]
            def expire_on_relationship(*args, **kwargs):
                result = original(*args, **kwargs)
                calls[0] += 1
                if calls[0] == 3:
                    service.clock = lambda: datetime(2030, 1, 1, 0, 0, tzinfo=timezone.utc)
                return result
            with patch.object(store, "validate_claim", side_effect=expire_on_relationship):
                result = service.create_applier(store).apply(authority.authority_id)
            self.assertEqual((result.state, result.recovery_code), ("Applying", "application_recovery_required"))
            self.assertEqual([entry.operation for entry in driver.trace], ["create_issue", "create_issue"])
        finally:
            directory.cleanup()

    def test_authority_expiry_after_success_has_one_dispatch_and_no_receipt(self):
        driver = _ClockChangingWriteDriver(self._success(), lambda: None)
        directory, context, preview, service, authority, _ = self._compose(driver=driver)
        try:
            store = self._store(context, service, directory)
            application_id = service.create_execution_context(authority.authority_id).identity.application_id
            driver.change_clock = lambda: setattr(service, "clock", lambda: datetime(2030, 1, 1, 0, 0, tzinfo=timezone.utc))
            result = service.create_applier(store).apply(authority.authority_id)
            self.assertEqual((result.state, result.recovery_code), ("Applying", "application_recovery_required"))
            self.assertEqual(driver.calls, 1)
            state = store.get_execution(application_id)
            self.assertEqual((state.state, state.next_operation_index), ("Applying", 0))
            service.clock = lambda: datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)
            replay = service.create_applier(store).apply(authority.authority_id)
            self.assertEqual((replay.state, replay.recovery_code), ("Applying", "application_recovery_required"))
            self.assertEqual(driver.calls, 1)
        finally:
            directory.cleanup()

    def test_authority_expiry_after_rejection_returns_recovery(self):
        observation = WriteObservation(WriteObservationKind.DEFINITIVE_REJECTED, "", {"status": 422}, "github_write_rejected")
        driver = _ClockChangingWriteDriver(observation, lambda: None)
        directory, context, preview, service, authority, _ = self._compose(driver=driver)
        try:
            store = self._store(context, service, directory)
            application_id = service.create_execution_context(authority.authority_id).identity.application_id
            driver.change_clock = lambda: setattr(service, "clock", lambda: datetime(2030, 1, 1, 0, 0, tzinfo=timezone.utc))
            result = service.create_applier(store).apply(authority.authority_id)
            self.assertEqual((result.state, result.recovery_code), ("Applying", "application_recovery_required"))
            self.assertEqual(driver.calls, 1)
            self.assertEqual(store.get_execution(application_id).state, "Applying")
        finally:
            directory.cleanup()

    def test_authority_expiry_after_ambiguous_returns_recovery(self):
        observation = WriteObservation(WriteObservationKind.AMBIGUOUS, "", {}, "github_write_transport_ambiguous")
        driver = _ClockChangingWriteDriver(observation, lambda: None)
        directory, context, preview, service, authority, _ = self._compose(driver=driver)
        try:
            store = self._store(context, service, directory)
            driver.change_clock = lambda: setattr(service, "clock", lambda: datetime(2030, 1, 1, 0, 0, tzinfo=timezone.utc))
            result = service.create_applier(store).apply(authority.authority_id)
            self.assertEqual((result.state, result.recovery_code), ("Applying", "application_recovery_required"))
            self.assertEqual(driver.calls, 1)
        finally:
            directory.cleanup()

    def test_non_authority_value_error_is_not_swallowed_after_dispatch(self):
        directory, context, preview, service, authority, driver = self._compose((self._success(),))
        try:
            store = self._store(context, service, directory)
            with patch("delivery_system.applier._trusted_success_result", side_effect=ValueError("remote_result_invalid")):
                with self.assertRaisesRegex(ValueError, "^remote_result_invalid$"):
                    service.create_applier(store).apply(authority.authority_id)
            self.assertEqual(len(driver.trace), 1)
        finally:
            directory.cleanup()

    def test_missing_relationship_receipt_blocks_without_dispatch(self):
        operations = [
            {"operation_kind": "create_issue", "client_refs": ["child"], "depends_on": []},
            {"operation_kind": "create_issue", "client_refs": ["parent"], "depends_on": []},
            {"operation_kind": "add_sub_issue", "client_refs": ["child", "parent"], "depends_on": []},
        ]
        observations = (self._success(number=41, numeric_id="401"),
                        self._success(number=42, numeric_id="402"),
                        self._relationship_success(identity="missing"))
        directory, context, preview, service, authority, driver = self._compose_operations(("child", "parent"), operations, observations)
        try:
            store = self._store(context, service, directory)
            original = store.get_operation_receipt
            def unavailable(*args, **kwargs):
                raise ValueError("operation_receipt_not_found")
            with patch.object(store, "get_operation_receipt", side_effect=unavailable):
                result = service.create_applier(store).apply(authority.authority_id)
            self.assertEqual((result.state, result.recovery_code), ("Failed", "operation_receipt_not_found"))
            self.assertEqual([entry.operation for entry in driver.trace], ["create_issue", "create_issue"])
            self.assertEqual(store.get_execution(service.create_execution_context(authority.authority_id).identity.application_id).next_operation_index, 2)
        finally:
            directory.cleanup()

    def test_partially_applied_workers_claim_next_operation_once(self):
        operations = [
            {"operation_kind": "create_issue", "client_refs": ["first"], "depends_on": []},
            {"operation_kind": "create_issue", "client_refs": ["second"], "depends_on": []},
        ]
        observations = (self._success(number=51, numeric_id="501"), self._success(number=52, numeric_id="502"))
        directory, context, preview, service, authority, driver = self._compose_operations(("first", "second"), operations, observations)
        try:
            store = self._store(context, service, directory)
            runtime_context = service.create_execution_context(authority.authority_id)
            now = service._utc(service.clock())
            initial = runtime_context.new_execution_state(state="Pending", next_operation_index=0, owner_id=None,
                current_attempt_id=None, recovery_code=None, operation_receipt_refs=(), started_at=now, updated_at=now,
                completed_at=None, orchestration_policy=APPLIER_ORCHESTRATION_POLICY)
            capability = service._write_executor_factory(store)
            persisted = store.create_execution_if_absent(capability, initial)
            owner = "execution-owner-" + "a" * 32
            state, attempt = store.claim_next_operation(capability, persisted.application_id, persisted.state_digest, runtime_context, owner, now)
            command = _materialize(runtime_context, attempt, store)
            observation = capability.dispatch("create_issue", command)
            receipt = runtime_context.new_receipt(attempt.operation_index, _trusted_success_result(runtime_context, attempt, observation), attempt.started_at, now)
            store.complete_operation_success(capability, initial.application_id, state.state_digest, attempt.operation_identity,
                attempt.attempt_digest, owner, runtime_context, receipt, now)
            store2 = SQLiteExecutionStore(store.path, context.workspace_identity, runtime_service=service)
            barrier = threading.Barrier(2)
            original1, original2 = store.claim_next_operation, store2.claim_next_operation
            store.claim_next_operation = lambda *a, **k: (barrier.wait(5), original1(*a, **k))[1]
            store2.claim_next_operation = lambda *a, **k: (barrier.wait(5), original2(*a, **k))[1]
            results, errors = [], []
            def run(applier):
                try: results.append(applier.apply(authority.authority_id))
                except Exception as exc: errors.append(exc)
            t1 = threading.Thread(target=run, args=(service.create_applier(store),)); t2 = threading.Thread(target=run, args=(service.create_applier(store2),))
            t1.start(); t2.start(); t1.join(5); t2.join(5)
            self.assertEqual(errors, [])
            self.assertEqual(len(driver.trace), 2)
            self.assertEqual([entry.operation for entry in driver.trace], ["create_issue", "create_issue"])
            self.assertEqual(len(results), 2)
            self.assertTrue(all(isinstance(result, ApplyResult) for result in results))
            self.assertTrue(all(result.state in {"Applying", "PartiallyApplied", "Applied"} for result in results))
            self.assertTrue(any(result.state == "Applied" for result in results))
        finally:
            directory.cleanup()

    def test_claim_refresh_replay_integrity_error_is_not_suppressed(self):
        directory, context, preview, service, authority, driver = self._compose((self._success(),))
        try:
            store = self._store(context, service, directory)
            original_get = store.get_execution
            def corrupt_refresh(*args, **kwargs):
                if kwargs.get("expected_operations") is not None:
                    raise ValueError("application_replay_validation_required")
                return original_get(*args, **kwargs)
            with patch.object(store, "claim_next_operation", side_effect=ValueError("application_state_stale")):
                with patch.object(store, "get_execution", side_effect=corrupt_refresh):
                    with self.assertRaisesRegex(ValueError, "^application_replay_validation_required$"):
                        service.create_applier(store).apply(authority.authority_id)
            self.assertEqual(len(driver.trace), 0)
        finally:
            directory.cleanup()

    def test_finalization_insert_before_commit_rolls_back_and_retries_locally(self):
        directory, context, preview, service, authority, driver = self._compose((self._success(),))
        try:
            store = self._store(context, service, directory)
            original = store.finalize_application
            with patch.object(store, "finalize_application", side_effect=RuntimeError("prepare_only")):
                with self.assertRaisesRegex(RuntimeError, "^prepare_only$"):
                    service.create_applier(store).apply(authority.authority_id)
            real_connection = SQLiteExecutionStore._connection(store)
            real_connection.close()
            def failing_connection():
                return _FailingCommitConnection(SQLiteExecutionStore._connection(store))
            with patch.object(store, "_connection", side_effect=failing_connection):
                with self.assertRaisesRegex(RuntimeError, "^finalization_commit_abort$"):
                    original(capability := service._write_executor_factory(store),
                             service.create_execution_context(authority.authority_id).identity.application_id,
                             store.get_execution(service.create_execution_context(authority.authority_id).identity.application_id).state_digest,
                             service.create_execution_context(authority.authority_id), service._utc(service.clock()))
            runtime_context = service.create_execution_context(authority.authority_id)
            partial = store.get_execution(runtime_context.identity.application_id)
            self.assertEqual(partial.state, "PartiallyApplied")
            with self.assertRaisesRegex(ValueError, "^application_receipt_not_found$"):
                store.get_application_receipt(runtime_context.identity.application_id)
            result = service.create_applier(store).apply(authority.authority_id)
            self.assertEqual(result.state, "Applied")
            self.assertEqual(len(driver.trace), 1)
        finally:
            directory.cleanup()


if __name__ == "__main__":
    unittest.main()
