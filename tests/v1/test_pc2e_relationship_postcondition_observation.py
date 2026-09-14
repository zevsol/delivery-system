from __future__ import annotations

import unittest
from concurrent.futures import ThreadPoolExecutor
import threading
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mcp import Client

from delivery_system.application_identity import operation_identity
from delivery_system.canonical import digest
from delivery_system.drivers.contract import DriverError, DriverReadResponse
from delivery_system.drivers.write_contract import WriteObservation, WriteObservationKind
from delivery_system.runtime import ApplicationPostconditionObservation
from mcp_server.server import create_server
from tests.v1 import test_operational_approval_authority as approval_fixture
from tests.v1 import test_pc2b_applier_orchestration as applier_fixture
from tests.v1 import test_pc2d_application_status as status_fixture


TRUST = approval_fixture.TRUST
QUERY_SCOPE = {
    "api_origin": TRUST.origin,
    "api_version": "2026-03-10",
    "issue_state": "all",
    "pull_request_filter": "pull_request_field_excluded",
    "relationships": ["sub_issues", "parent", "blocked_by", "blocking"],
    "pagination_protocol": "link-header",
    "budget_profile": "github-rest-offline-v1",
}


class ObservationDriver:
    fixed_query_scope = QUERY_SCOPE

    def __init__(self, issue_ids: tuple[str, ...], relationships=(), *, error: Exception | None = None,
                 repository: str = "owner/repo", query_complete: bool = True,
                 pagination_complete: bool = True):
        self.issue_ids = issue_ids
        self.relationships = tuple(relationships)
        self.error = error
        self.repository = repository
        self.query_complete = query_complete
        self.pagination_complete = pagination_complete
        self.calls = 0
        self.methods: list[str] = []

    def _response(self, repository: str, query_scope) -> DriverReadResponse:
        issues = [
            {"issue_id": issue_id, "item_type": "issue", "title": issue_id,
             "updated_at": "2026-08-13T00:00:00+00:00", "repository_identity": self.repository}
            for issue_id in self.issue_ids
        ]
        relationships = [{"kind": kind, "from": source, "to": target}
                         for kind, source, target in self.relationships]
        material = {
            "source_identity": TRUST.trusted_driver_identity,
            "repository_identity": self.repository,
            "query_scope": dict(query_scope),
            "payload": {"issue_records": issues, "relationship_records": relationships},
        }
        payload = {
            "requested_repository": repository,
            "canonical_repository": self.repository,
            "remote_repository_id": "R1",
            "authenticated_subject": "U1",
            "visibility": "private",
            "permissions": {"read": True, "write": False},
            "capabilities": {"issues": True, "relationships": True},
            "query_scope": dict(query_scope),
            "query_complete": self.query_complete,
            "pagination_complete": self.pagination_complete,
            "issue_records": issues,
            "relationship_records": relationships,
            "evidence_material": [material],
            "source_identity": TRUST.trusted_driver_identity,
        }
        return DriverReadResponse(**payload, remote_content_digest=digest(payload))

    def read_repository(self, repository: str, query_scope):
        self.calls += 1
        self.methods.append("GET")
        if self.error is not None:
            raise self.error
        return self._response(repository, query_scope)


class BarrierObservationDriver(ObservationDriver):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.barrier = threading.Barrier(2)

    def read_repository(self, repository: str, query_scope):
        self.barrier.wait(timeout=5)
        return super().read_repository(repository, query_scope)


class ApplicationObservationTests(unittest.TestCase):
    operations = [
        {"operation_kind": "create_issue", "client_refs": ["child"], "depends_on": []},
        {"operation_kind": "create_issue", "client_refs": ["parent"], "depends_on": []},
        {"operation_kind": "add_sub_issue", "client_refs": ["child", "parent"], "depends_on": []},
    ]

    @staticmethod
    def _create_success(number: int, numeric_id: str, node_id: str) -> WriteObservation:
        return WriteObservation(
            WriteObservationKind.DEFINITIVE_SUCCESS,
            "github-issue:" + node_id,
            {
                "repository_identity": "owner/repo", "issue_number": number,
                "numeric_issue_id": numeric_id, "node_id": node_id,
                "executor_identity": "delivery-system:github-rest-write-v1",
                "contract_version": "github-rest-write-v1", "response_status": 201,
            },
        )

    @staticmethod
    def _ambiguous() -> WriteObservation:
        return WriteObservation(WriteObservationKind.AMBIGUOUS, code="github_write_transport_ambiguous")

    def _configured(self, *, kind: str = "add_sub_issue", relationships=(), issue_ids=("child-node", "parent-node"),
                    driver: ObservationDriver | None = None, operations_override=None, refs=("child", "parent")):
        operations = [dict(operation) for operation in (operations_override or self.operations)]
        if kind == "add_dependency":
            operations[-1] = {**operations[-1], "operation_kind": "add_dependency"}
        harness = applier_fixture.ApplierOrchestrationTests()
        observations = (
            self._create_success(11, "101", "child-node"),
            self._create_success(12, "102", "parent-node"),
            self._ambiguous(),
        )
        directory, context, preview, service, authority, write_driver = harness._compose_operations(
            refs, operations, observations,
        )
        execution_store = harness._store(context, service, directory)
        service.create_applier(execution_store).apply(authority.authority_id)
        observation_driver = driver or ObservationDriver(issue_ids, relationships)
        server = create_server(
            context, service.store, driver=observation_driver, trust_context=TRUST,
            approval_authority_service=service, execution_store=execution_store,
        )
        return directory, context, service, authority, execution_store, observation_driver, server

    @staticmethod
    def _call(server, application_id: str):
        async def exercise():
            async with Client(server, raise_exceptions=False) as client:
                return await client.call_tool(
                    "delivery_observe_application_postcondition",
                    {"payload": {"application_id": application_id}},
                )
        import asyncio
        return asyncio.run(exercise())

    def test_add_sub_issue_and_dependency_confirmed(self):
        expected = {
            "application_id", "operation_index", "operation_identity", "operation_kind",
            "postcondition", "causal_attribution", "observed_at", "state", "integrity_status",
        }
        for kind, relation_kind in (("add_sub_issue", "existing_parent"), ("add_dependency", "existing_dependency")):
            directory, context, service, authority, execution_store, driver, server = self._configured(
                kind=kind,
                relationships=((relation_kind, "child-node", "parent-node"),),
            )
            try:
                application_id = service.create_execution_context(authority.authority_id).identity.application_id
                result = self._call(server, application_id)
                self.assertFalse(result.is_error, result.content)
                self.assertEqual(set(result.structured_content), expected)
                self.assertEqual(
                    (result.structured_content["operation_kind"], result.structured_content["postcondition"],
                     result.structured_content["causal_attribution"], result.structured_content["state"],
                     result.structured_content["integrity_status"]),
                    (kind, "postcondition_confirmed", "not_established", "OutcomeUnknown", "verified"),
                )
                self.assertEqual(driver.calls, 1)
            finally:
                directory.cleanup()

    def test_complete_snapshot_absent_and_missing_issue_is_inconclusive(self):
        for issue_ids, expected in ((
            ("child-node", "parent-node"), "postcondition_absent"),
            (("child-node",), "inconclusive"),
        ):
            directory, context, service, authority, execution_store, driver, server = self._configured(issue_ids=issue_ids)
            try:
                application_id = service.create_execution_context(authority.authority_id).identity.application_id
                result = self._call(server, application_id)
                self.assertFalse(result.is_error, result.content)
                self.assertEqual(result.structured_content["postcondition"], expected)
            finally:
                directory.cleanup()

    def test_create_issue_and_non_unknown_states_are_rejected_without_read(self):
        operations = [
            {"operation_kind": "create_issue", "client_refs": ["child"], "depends_on": []},
            {"operation_kind": "create_issue", "client_refs": ["parent"], "depends_on": []},
            {"operation_kind": "create_issue", "client_refs": ["orphan"], "depends_on": []},
        ]
        directory, context, service, authority, execution_store, driver, server = self._configured(
            operations_override=operations, refs=("child", "parent", "orphan"),
        )
        try:
            application_id = service.create_execution_context(authority.authority_id).identity.application_id
            result = self._call(server, application_id)
            self.assertTrue(result.is_error)
            self.assertIn("reconciliation_operation_unsupported", str(result.content))
            self.assertEqual(driver.calls, 0)
        finally:
            directory.cleanup()

    def test_all_non_unknown_states_are_rejected_without_read(self):
        directory, context, service, authority, execution_store, driver, server = self._configured()
        try:
            application_id = service.create_execution_context(authority.authority_id).identity.application_id
            live = service.create_execution_context(authority.authority_id)
            original = execution_store.get_execution(application_id, expected_operations=live.expected_operations)
            candidates = {
                "Pending": live.continue_execution_state(
                    original, state="Pending", next_operation_index=0, owner_id=None,
                    current_attempt_id=None, recovery_code=None, operation_receipt_refs=(),
                    updated_at=original.started_at, completed_at=None,
                ),
                "Applying": live.continue_execution_state(
                    original, state="Applying", owner_id="worker", recovery_code=None,
                ),
                "PartiallyApplied": live.continue_execution_state(
                    original, state="PartiallyApplied", owner_id=None,
                    current_attempt_id=None, recovery_code=None,
                ),
                "Failed": live.continue_execution_state(original, state="Failed"),
                "Blocked": live.continue_execution_state(original, state="Blocked"),
                "Applied": live.continue_execution_state(
                    original, state="Applied", next_operation_index=3, owner_id=None,
                    current_attempt_id=None, recovery_code=None,
                    operation_receipt_refs=original.operation_receipt_refs + ("unused",),
                    completed_at=original.updated_at,
                ),
            }
            for state_name, candidate in candidates.items():
                with self.subTest(state=state_name), patch.object(execution_store, "get_execution", return_value=candidate):
                    result = self._call(server, application_id)
                    self.assertTrue(result.is_error)
                    self.assertIn("application_reconciliation_state_invalid", str(result.content))
            self.assertEqual(driver.calls, 0)
        finally:
            directory.cleanup()

    def test_identity_and_integrity_failures_are_stable_and_private(self):
        application_id = "application-" + "a" * 64
        result = self._call(create_server(), application_id + " ")
        self.assertTrue(result.is_error)
        self.assertIn("application_id_invalid", str(result.content))

        directory, context, service, authority, execution_store, driver, server = self._configured()
        try:
            application_id = service.create_execution_context(authority.authority_id).identity.application_id
            with patch.object(execution_store, "get_execution", side_effect=ValueError("state_integrity_invalid")):
                result = self._call(server, application_id)
            self.assertTrue(result.is_error)
            self.assertIn("state_integrity_invalid", str(result.content))

        finally:
            directory.cleanup()

    def test_preview_receipt_and_attempt_integrity_fail_closed(self):
        directory, context, service, authority, execution_store, driver, server = self._configured()
        try:
            application_id = service.create_execution_context(authority.authority_id).identity.application_id
            with patch.object(
                service.store, "_read_preview_revision_for_status",
                side_effect=lambda *args: {"canonical_payload": {}, "revision": 1, "request_id": "forged"},
            ):
                result = self._call(server, application_id)
            self.assertTrue(result.is_error)
            self.assertIn("sealed_preview_schema_invalid", str(result.content))
            self.assertEqual(driver.calls, 0)

            with patch.object(execution_store, "get_operation_receipt", side_effect=ValueError("operation_receipt_not_found")):
                result = self._call(server, application_id)
            self.assertTrue(result.is_error)
            self.assertIn("operation_receipt_not_found", str(result.content))

            live = service.create_execution_context(authority.authority_id)
            state = execution_store.get_execution(application_id, expected_operations=live.expected_operations)
            attempt = execution_store.get_attempt(application_id, state.current_attempt_id)
            tampered_attempt = Mock(wraps=attempt)
            tampered_attempt.request_identity = "request-forged"
            with patch.object(execution_store, "get_attempt", return_value=tampered_attempt):
                result = self._call(server, application_id)
            self.assertTrue(result.is_error)
            self.assertIn("attempt_integrity_invalid", str(result.content))

            for field, value in (("operation_identity", "operation-forged"), ("operation_index", 99),
                                 ("request_identity", "request-forged")):
                tampered = Mock(wraps=attempt)
                setattr(tampered, field, value)
                with self.subTest(attempt_field=field), patch.object(execution_store, "get_attempt", return_value=tampered):
                    result = self._call(server, application_id)
                    self.assertTrue(result.is_error)
                    self.assertIn("attempt_integrity_invalid", str(result.content))

            live_operation = live.expected_operations[0]
            receipt = execution_store.get_operation_receipt(
                application_id, operation_identity(application_id, 0, live_operation),
            )
            forged_remote_result = dict(receipt.remote_result)
            forged_remote_result["result_digest"] = "sha256:" + "0" * 64
            tampered_receipt = SimpleNamespace(
                application_id=receipt.application_id, identity=receipt.identity,
                operation_identity=receipt.operation_identity, operation_index=receipt.operation_index,
                canonical_operation=receipt.canonical_operation,
                request_identity=receipt.request_identity, authority_binding=receipt.authority_binding,
                remote_result=forged_remote_result, operation_receipt_id=receipt.operation_receipt_id,
                started_at=receipt.started_at, completed_at=receipt.completed_at,
                receipt_digest=receipt.receipt_digest,
            )
            with patch.object(execution_store, "get_operation_receipt", return_value=tampered_receipt):
                result = self._call(server, application_id)
            self.assertTrue(result.is_error)
            self.assertIn("receipt_integrity_invalid", str(result.content))
        finally:
            directory.cleanup()

    def test_remote_failures_map_to_one_stable_failure_and_do_not_retry(self):
        failures = (
            DriverError("remote_timeout"), DriverError("remote_transient_failure"),
            DriverError("permission_denied"), DriverError("rate_limited"),
            DriverError("driver_response_invalid"), DriverError("request_budget_exhausted"),
            DriverError("pagination_incomplete"),
        )
        for failure in failures:
            directory, context, service, authority, execution_store, driver, server = self._configured(
                driver=ObservationDriver(("child-node", "parent-node"), error=failure),
            )
            try:
                application_id = service.create_execution_context(authority.authority_id).identity.application_id
                result = self._call(server, application_id)
                self.assertTrue(result.is_error)
                self.assertIn("remote_observation_unavailable", str(result.content))
                self.assertEqual(driver.calls, 1)
            finally:
                directory.cleanup()

    def test_repository_mismatch_and_contradictory_facts_fail_closed(self):
        cases = (
            (ObservationDriver(("child-node", "parent-node"), repository="other/repo"), "repository_identity_mismatch"),
            (ObservationDriver(("child-node", "parent-node"), query_complete=False), "remote_observation_unavailable"),
            (ObservationDriver(("child-node", "parent-node"), pagination_complete=False), "remote_observation_unavailable"),
            (ObservationDriver(
                ("child-node", "parent-node"),
                (("existing_parent", "child-node", "parent-node"),
                 ("existing_parent", "parent-node", "child-node")),
            ), "remote_evidence_contradictory"),
        )
        for driver, code in cases:
            directory, context, service, authority, execution_store, actual_driver, server = self._configured(driver=driver)
            try:
                application_id = service.create_execution_context(authority.authority_id).identity.application_id
                result = self._call(server, application_id)
                self.assertTrue(result.is_error)
                self.assertIn(code, str(result.content))
            finally:
                directory.cleanup()

    def test_projection_never_contains_remote_or_trust_payload(self):
        directory, context, service, authority, execution_store, driver, server = self._configured(
            relationships=(("existing_parent", "child-node", "parent-node"),),
        )
        try:
            application_id = service.create_execution_context(authority.authority_id).identity.application_id
            result = self._call(server, application_id)
            rendered = str(result.structured_content)
            for forbidden in (
                "issue_records", "remote_result", "result_payload", "canonical_operation",
                "authority_binding", "credential", "token", "header", "body",
            ):
                self.assertNotIn(forbidden, rendered)
        finally:
            directory.cleanup()

    def test_repetition_has_no_persistence_or_write_side_effects(self):
        directory, context, service, authority, execution_store, driver, server = self._configured(
            relationships=(("existing_parent", "child-node", "parent-node"),),
        )
        try:
            application_id = service.create_execution_context(authority.authority_id).identity.application_id
            before_bytes = execution_store.path.read_bytes()
            with patch.object(service, "issue_application_authority", side_effect=AssertionError("issuance")), \
                    patch.object(service, "create_applier", side_effect=AssertionError("apply")), \
                    patch.object(execution_store, "save_execution", side_effect=AssertionError("write")), \
                    patch.object(execution_store, "save_attempt", side_effect=AssertionError("write")), \
                    patch.object(execution_store, "complete_operation_success", side_effect=AssertionError("write")), \
                    patch.object(execution_store, "finalize_application", side_effect=AssertionError("write")):
                first = self._call(server, application_id)
                second = self._call(server, application_id)
            self.assertFalse(first.is_error, first.content)
            self.assertFalse(second.is_error, second.content)
            self.assertEqual(
                {key: value for key, value in first.structured_content.items() if key != "observed_at"},
                {key: value for key, value in second.structured_content.items() if key != "observed_at"},
            )
            self.assertEqual(execution_store.path.read_bytes(), before_bytes)
            self.assertEqual(driver.calls, 2)
        finally:
            directory.cleanup()

    def test_digest_valid_historical_attempt_substitutions_fail_before_read(self):
        mutations = (
            ("request_identity", lambda payload: payload.update(request_identity="request-forged")),
            ("driver_identity", lambda payload: (payload.update(driver_identity="forged-driver"),
                                                  payload["authority_binding"].update(driver_identity="forged-driver"))),
            ("remote_authority", lambda payload: (payload.update(remote_authority="sha256:" + "0" * 64),
                                                   payload["authority_binding"].update(remote_authority="sha256:" + "0" * 64))),
            ("authority_binding", lambda payload: payload["authority_binding"].update(github_subject_identity="forged-subject")),
        )
        for field, mutate in mutations:
            directory, context, service, authority, execution_store, driver, server = self._configured(
                relationships=(("existing_parent", "child-node", "parent-node"),),
            )
            try:
                application_id = service.create_execution_context(authority.authority_id).identity.application_id
                live = service.create_execution_context(authority.authority_id)
                state = execution_store.get_execution(application_id, expected_operations=live.expected_operations)
                operation_id = operation_identity(application_id, 0, live.expected_operations[0])
                payload = status_fixture.ApplicationStatusSurfaceTests._row_payload(
                    execution_store.path, "operation_attempts", application_id, operation_id,
                )
                mutate(payload)
                status_fixture.ApplicationStatusSurfaceTests._replace_payload(
                    execution_store.path, "operation_attempts", application_id,
                    status_fixture.ApplicationStatusSurfaceTests._redigest(payload, "attempt_digest"), operation_id,
                )
                with self.subTest(field=field):
                    result = self._call(server, application_id)
                    self.assertTrue(result.is_error)
                    self.assertIn("attempt_integrity_invalid", str(result.content))
                    self.assertEqual(driver.calls, 0)
            finally:
                directory.cleanup()

    def test_digest_valid_historical_receipt_substitutions_fail_before_read(self):
        mutations = (
            ("authority_binding", lambda payload: payload["authority_binding"].update(driver_identity="forged-driver")),
            ("remote_result", lambda payload: payload["remote_result"].update(result_identity="github-issue:forged")),
            ("repository", lambda payload: payload["remote_result"]["result_payload"].update(repository_identity="other/repo")),
            ("client_reference", lambda payload: payload["canonical_operation"].update(client_refs=["parent"])),
        )
        for field, mutate in mutations:
            directory, context, service, authority, execution_store, driver, server = self._configured(
                relationships=(("existing_parent", "child-node", "parent-node"),),
            )
            try:
                application_id = service.create_execution_context(authority.authority_id).identity.application_id
                live = service.create_execution_context(authority.authority_id)
                operation_id = operation_identity(application_id, 0, live.expected_operations[0])
                payload = status_fixture.ApplicationStatusSurfaceTests._row_payload(
                    execution_store.path, "operation_receipts", application_id, operation_id,
                )
                mutate(payload)
                if field in {"remote_result", "repository"}:
                    payload["remote_result"]["result_digest"] = digest(payload["remote_result"]["result_payload"])
                if field == "client_reference":
                    alternate = operation_identity(application_id, 0, payload["canonical_operation"])
                    payload["operation_identity"] = alternate
                    payload["request_identity"] = "application-request-" + digest({
                        "domain": "delivery-system:application-request:v1", "operation_identity": alternate,
                    }).split(":", 1)[1]
                status_fixture.ApplicationStatusSurfaceTests._replace_payload(
                    execution_store.path, "operation_receipts", application_id,
                    status_fixture.ApplicationStatusSurfaceTests._redigest(payload, "receipt_digest"), operation_id,
                )
                with self.subTest(field=field):
                    result = self._call(server, application_id)
                    self.assertTrue(result.is_error)
                    expected = "repository_identity_mismatch" if field == "repository" else "receipt_integrity_invalid"
                    self.assertIn(expected, str(result.content))
                    self.assertEqual(driver.calls, 0)
            finally:
                directory.cleanup()

    def test_historical_attempt_and_receipt_from_other_execution_fail_closed(self):
        directory, context, service, authority, execution_store, driver, server = self._configured(
            relationships=(("existing_parent", "child-node", "parent-node"),),
        )
        other_directory, other_context, other_service, other_authority, other_store, other_driver, other_server = self._configured(
            relationships=(("existing_parent", "child-node", "parent-node"),),
        )
        try:
            application_id = service.create_execution_context(authority.authority_id).identity.application_id
            other_id = other_service.create_execution_context(other_authority.authority_id).identity.application_id
            live = service.create_execution_context(authority.authority_id)
            other_live = other_service.create_execution_context(other_authority.authority_id)
            operation_id = operation_identity(application_id, 0, live.expected_operations[0])
            other_operation_id = operation_identity(other_id, 0, other_live.expected_operations[0])
            for table, expected in (("operation_attempts", "attempt_integrity_invalid"),
                                    ("operation_receipts", "receipt_integrity_invalid")):
                trusted_payload = status_fixture.ApplicationStatusSurfaceTests._row_payload(
                    execution_store.path, table, application_id, operation_id,
                )
                payload = status_fixture.ApplicationStatusSurfaceTests._row_payload(
                    other_store.path, table, other_id, other_operation_id,
                )
                status_fixture.ApplicationStatusSurfaceTests._replace_payload(
                    execution_store.path, table, application_id, payload, operation_id,
                )
                with self.subTest(table=table):
                    result = self._call(server, application_id)
                    self.assertTrue(result.is_error)
                    self.assertIn(expected, str(result.content))
                    self.assertEqual(driver.calls, 0)
                # Restore the trusted row before testing the other artifact.
                status_fixture.ApplicationStatusSurfaceTests._replace_payload(
                    execution_store.path, table, application_id, trusted_payload, operation_id,
                )
        finally:
            directory.cleanup()
            other_directory.cleanup()

    def test_concurrent_observations_are_read_only_and_deterministic(self):
        driver = BarrierObservationDriver(("child-node", "parent-node"),
                                           (("existing_parent", "child-node", "parent-node"),))
        directory, context, service, authority, execution_store, _, server = self._configured(driver=driver)
        try:
            application_id = service.create_execution_context(authority.authority_id).identity.application_id
            before_bytes = execution_store.path.read_bytes()
            observer = ApplicationPostconditionObservation(context, service.store, execution_store, driver, TRUST)
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(observer.observe, (application_id, application_id)))
            self.assertEqual([result["postcondition"] for result in results], ["postcondition_confirmed"] * 2)
            self.assertEqual(results[0].keys(), results[1].keys())
            self.assertEqual(execution_store.path.read_bytes(), before_bytes)
            self.assertEqual(driver.calls, 2)
        finally:
            directory.cleanup()

    def test_global_boundary_is_fail_closed(self):
        application_id = "application-" + "a" * 64
        result = self._call(create_server(), application_id)
        self.assertTrue(result.is_error)
        self.assertIn("application_reconciliation_boundary_unavailable", str(result.content))


if __name__ == "__main__":
    unittest.main()
