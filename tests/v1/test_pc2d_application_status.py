from __future__ import annotations

import asyncio
from inspect import getsource
import json
import sqlite3
import unittest
from contextlib import closing
from copy import deepcopy
from unittest.mock import patch

from pydantic import ValidationError
from mcp import Client

from delivery_system.application_identity import operation_identity, request_identity
from delivery_system.canonical import digest
from delivery_system.drivers.write_contract import WriteObservation, WriteObservationKind
from delivery_system.execution_state import APPLIER_ORCHESTRATION_POLICY
from mcp_server.server import create_server, mcp
import tests.v1.test_pc2c_mcp_write_surface as mcp_surface


class ApplicationStatusSurfaceTests(unittest.TestCase):
    @staticmethod
    def _configured(observations=()):
        return mcp_surface.McpWriteSurfaceTests()._configured(observations)

    @staticmethod
    def _call(server, payload):
        return mcp_surface.McpWriteSurfaceTests._call(server, "delivery_get_application_status", payload)

    @staticmethod
    def _server(context, service, execution_store):
        return create_server(
            context,
            service.store,
            approval_authority_service=service,
            execution_store=execution_store,
        )

    @staticmethod
    def _pending(context, service, authority, execution_store):
        runtime_context = service.create_execution_context(authority.authority_id)
        now = service._utc(service.clock())
        state = runtime_context.new_execution_state(
            state="Pending", next_operation_index=0, owner_id=None,
            current_attempt_id=None, recovery_code=None, operation_receipt_refs=(),
            started_at=now, updated_at=now, completed_at=None,
            orchestration_policy=APPLIER_ORCHESTRATION_POLICY,
        )
        capability = service._write_executor_factory(execution_store)
        persisted = execution_store.create_execution_if_absent(capability, state)
        return runtime_context, capability, persisted, now

    @staticmethod
    def _app_id(result):
        return result.structured_content["application_id"]

    @staticmethod
    def _row_payload(path, table, application_id, operation_identity=None):
        with closing(sqlite3.connect(path)) as connection:
            if operation_identity is None:
                row = connection.execute(
                    f"SELECT payload FROM {table} WHERE application_id=?", (application_id,)
                ).fetchone()
            else:
                row = connection.execute(
                    f"SELECT payload FROM {table} WHERE application_id=? AND operation_identity=?",
                    (application_id, operation_identity),
                ).fetchone()
        if row is None:
            raise AssertionError(f"missing {table} row")
        return json.loads(row[0])

    @staticmethod
    def _replace_payload(path, table, application_id, payload, operation_identity=None):
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        with closing(sqlite3.connect(path)) as connection:
            if operation_identity is None:
                connection.execute(
                    f"UPDATE {table} SET payload=? WHERE application_id=?",
                    (encoded, application_id),
                )
            else:
                connection.execute(
                    f"UPDATE {table} SET payload=? WHERE application_id=? AND operation_identity=?",
                    (encoded, application_id, operation_identity),
                )
            connection.commit()

    @staticmethod
    def _redigest(payload, digest_field):
        payload[digest_field] = digest({key: value for key, value in payload.items() if key != digest_field})
        return payload

    @staticmethod
    def _run_async(coro):
        return asyncio.run(coro)

    def test_applied_projection_uses_preview_operations_and_excludes_secrets(self):
        directory, context, preview, service, authority, driver, execution_store = self._configured(
            (mcp_surface.McpWriteSurfaceTests._success(),)
        )
        try:
            server = self._server(context, service, execution_store)
            applied = mcp_surface.McpWriteSurfaceTests._call(
                server, "delivery_apply_approved_work_items",
                {"application_authority_id": authority.authority_id},
            )
            application_id = self._app_id(applied)
            expected_operations = service.create_execution_context(authority.authority_id).expected_operations
            original_get_execution = execution_store.get_execution
            with patch.object(execution_store, "get_execution", wraps=original_get_execution) as get_execution:
                result = self._call(server, {"application_id": application_id})
            self.assertFalse(result.is_error, result.content)
            status = result.structured_content
            self.assertEqual(status["state"], "Applied")
            self.assertEqual(status["integrity_status"], "verified")
            self.assertEqual(status["completed_operation_count"], status["total_operation_count"])
            self.assertEqual(status["attempt_count"], status["total_operation_count"])
            self.assertIsNotNone(status["application_receipt"])
            self.assertEqual(status["application_receipt"]["status"], "Applied")
            self.assertEqual(len(status["operation_receipts"]), status["total_operation_count"])
            self.assertEqual(len(status["attempts"]), status["total_operation_count"])
            self.assertEqual(
                set(status), {
                    "application_id", "preview_id", "revision", "operation_set_digest", "state",
                    "next_operation_index", "completed_operation_count", "total_operation_count",
                    "attempt_count", "recovery_code", "application_receipt", "operation_receipts",
                    "attempts", "started_at", "updated_at", "completed_at", "integrity_status",
                },
            )
            rendered = str(status)
            for forbidden in ("remote_result", "result_payload", "authority_binding", "owner_id", "canonical_operation"):
                self.assertNotIn(forbidden, rendered)
            replay_calls = [call for call in get_execution.call_args_list if call.kwargs.get("expected_operations") is not None]
            self.assertTrue(replay_calls)
            self.assertEqual(replay_calls[-1].kwargs["expected_operations"], expected_operations)
            self.assertEqual(len(driver.trace), 1)
        finally:
            directory.cleanup()

    def test_pending_and_applying_projection(self):
        directory, context, preview, service, authority, driver, execution_store = self._configured()
        try:
            runtime_context, capability, initial, now = self._pending(context, service, authority, execution_store)
            server = self._server(context, service, execution_store)
            pending = self._call(server, {"application_id": initial.application_id})
            self.assertFalse(pending.is_error, pending.content)
            self.assertEqual((pending.structured_content["state"], pending.structured_content["completed_operation_count"], pending.structured_content["attempt_count"]), ("Pending", 0, 0))
            self.assertIsNone(pending.structured_content["application_receipt"])

            attempt_owner = "execution-owner-" + "a" * 32
            claimed, attempt = execution_store.claim_next_operation(
                capability, initial.application_id, initial.state_digest,
                runtime_context, attempt_owner, now,
            )
            applying = self._call(server, {"application_id": initial.application_id})
            self.assertFalse(applying.is_error, applying.content)
            self.assertEqual(applying.structured_content["state"], "Applying")
            self.assertEqual(applying.structured_content["attempt_count"], 1)
            self.assertEqual(applying.structured_content["attempts"][0]["state"], "Applying")
            self.assertEqual(applying.structured_content["attempts"][0]["operation_identity"], attempt.operation_identity)
            self.assertEqual(claimed.current_attempt_id, attempt.operation_identity)
            self.assertEqual(len(driver.trace), 0)
        finally:
            directory.cleanup()

    def test_partially_applied_failed_blocked_and_outcome_unknown_states(self):
        cases = (
            ("PartiallyApplied", (mcp_surface.McpWriteSurfaceTests._success(),), "partial"),
            ("Failed", (mcp_surface.McpWriteSurfaceTests._success(),), "failed"),
            ("Blocked", (), "blocked"),
            ("OutcomeUnknown", (), "unknown"),
        )
        for expected_state, observations, mode in cases:
            if mode == "failed":
                observations = (WriteObservation(
                    WriteObservationKind.DEFINITIVE_REJECTED,
                    "",
                    {"status": 422},
                    "github_write_rejected",
                ),)
            directory, context, preview, service, authority, driver, execution_store = self._configured(observations)
            try:
                if mode == "partial":
                    with patch.object(execution_store, "finalize_application", side_effect=RuntimeError("test_finalize_abort")):
                        with self.assertRaisesRegex(RuntimeError, "test_finalize_abort"):
                            service.create_applier(execution_store).apply(authority.authority_id)
                elif mode == "failed":
                    service.create_applier(execution_store).apply(authority.authority_id)
                else:
                    runtime_context, capability, initial, now = self._pending(context, service, authority, execution_store)
                    claimed, attempt = execution_store.claim_next_operation(
                        capability, initial.application_id, initial.state_digest,
                        runtime_context, "execution-owner-" + "b" * 32, now,
                    )
                    execution_store.settle_operation(
                        capability, initial.application_id, claimed.state_digest,
                        attempt.operation_identity, attempt.attempt_digest, claimed.owner_id,
                        runtime_context, expected_state, "test_" + mode, now,
                    )
                server = self._server(context, service, execution_store)
                application_id = service.create_execution_context(authority.authority_id).identity.application_id
                result = self._call(server, {"application_id": application_id})
                self.assertFalse(result.is_error, result.content)
                status = result.structured_content
                self.assertEqual(status["state"], expected_state)
                self.assertEqual(status["integrity_status"], "verified")
                self.assertIsNone(status["application_receipt"])
                if expected_state in {"Failed", "Blocked", "OutcomeUnknown"}:
                    self.assertTrue(status["recovery_code"])
                    self.assertTrue(any(attempt["state"] == expected_state for attempt in status["attempts"]))
                if expected_state == "PartiallyApplied":
                    self.assertEqual(status["completed_operation_count"], 1)
            finally:
                directory.cleanup()

    def test_input_and_workspace_boundaries(self):
        directory, context, preview, service, authority, driver, execution_store = self._configured()
        try:
            server = self._server(context, service, execution_store)
            for application_id in (
                "application-" + "A" * 64,
                "application-" + "a" * 63,
                "application-" + "a" * 65,
                " application-" + "a" * 64,
                "application-" + "a" * 64 + " ",
            ):
                result = self._call(server, {"application_id": application_id})
                self.assertTrue(result.is_error)
                self.assertIn("application_id_invalid", str(result.content))
            with self.assertRaises(ValidationError):
                server_payload = {"application_id": "application-" + "a" * 64, "workspace": "other"}
                from mcp_server.server import GetApplicationStatusInput
                GetApplicationStatusInput.model_validate(server_payload)

            missing = self._call(server, {"application_id": "application-" + "a" * 64})
            self.assertTrue(missing.is_error)
            self.assertIn("application_not_found", str(missing.content))

            applied = mcp_surface.McpWriteSurfaceTests._call(
                server, "delivery_apply_approved_work_items",
                {"application_authority_id": authority.authority_id},
            )
            application_id = self._app_id(applied)
            other_directory, other_context, other_preview, other_service, other_authority, other_driver, other_store = self._configured()
            try:
                other_server = self._server(other_context, other_service, other_store)
                result = self._call(other_server, {"application_id": application_id})
                self.assertTrue(result.is_error)
                self.assertIn("application_not_found", str(result.content))
            finally:
                other_directory.cleanup()
        finally:
            directory.cleanup()

    def test_tampered_execution_and_receipt_records_fail_closed(self):
        directory, context, preview, service, authority, driver, execution_store = self._configured(
            (mcp_surface.McpWriteSurfaceTests._success(),)
        )
        try:
            server = self._server(context, service, execution_store)
            applied = mcp_surface.McpWriteSurfaceTests._call(
                server, "delivery_apply_approved_work_items",
                {"application_authority_id": authority.authority_id},
            )
            application_id = self._app_id(applied)
            state = self._row_payload(execution_store.path, "application_execution", application_id)
            state["state"] = "Failed"
            self._replace_payload(execution_store.path, "application_execution", application_id, state)
            result = self._call(server, {"application_id": application_id})
            self.assertTrue(result.is_error)
            self.assertIn("state_integrity_invalid", str(result.content))
        finally:
            directory.cleanup()

        directory, context, preview, service, authority, driver, execution_store = self._configured(
            (mcp_surface.McpWriteSurfaceTests._success(),)
        )
        try:
            server = self._server(context, service, execution_store)
            applied = mcp_surface.McpWriteSurfaceTests._call(
                server, "delivery_apply_approved_work_items",
                {"application_authority_id": authority.authority_id},
            )
            application_id = self._app_id(applied)
            attempt = self._row_payload(execution_store.path, "operation_attempts", application_id)
            attempt["updated_at"] = "2026-01-01T00:00:00Z"
            self._replace_payload(execution_store.path, "operation_attempts", application_id, attempt, attempt["operation_identity"])
            result = self._call(server, {"application_id": application_id})
            self.assertTrue(result.is_error)
            self.assertIn("attempt_integrity_invalid", str(result.content))
        finally:
            directory.cleanup()

    def test_historical_attempt_and_receipt_authority_bindings_are_verified(self):
        directory, context, preview, service, authority, driver, execution_store = self._configured(
            (mcp_surface.McpWriteSurfaceTests._success(),)
        )
        try:
            server = self._server(context, service, execution_store)
            applied = mcp_surface.McpWriteSurfaceTests._call(
                server, "delivery_apply_approved_work_items",
                {"application_authority_id": authority.authority_id},
            )
            application_id = self._app_id(applied)
            attempt = self._row_payload(execution_store.path, "operation_attempts", application_id)
            attempt["request_identity"] = "application-request-forged"
            self._replace_payload(
                execution_store.path, "operation_attempts", application_id,
                self._redigest(attempt, "attempt_digest"), attempt["operation_identity"],
            )
            result = self._call(server, {"application_id": application_id})
            self.assertTrue(result.is_error)
            self.assertIn("attempt_integrity_invalid", str(result.content))
        finally:
            directory.cleanup()

        directory, context, preview, service, authority, driver, execution_store = self._configured(
            (mcp_surface.McpWriteSurfaceTests._success(),)
        )
        try:
            server = self._server(context, service, execution_store)
            applied = mcp_surface.McpWriteSurfaceTests._call(
                server, "delivery_apply_approved_work_items",
                {"application_authority_id": authority.authority_id},
            )
            application_id = self._app_id(applied)
            receipt = self._row_payload(execution_store.path, "operation_receipts", application_id)
            receipt["authority_binding"]["remote_authority"] = "sha256:" + "0" * 64
            self._replace_payload(
                execution_store.path, "operation_receipts", application_id,
                self._redigest(receipt, "receipt_digest"), receipt["operation_identity"],
            )
            result = self._call(server, {"application_id": application_id})
            self.assertTrue(result.is_error)
            self.assertIn("receipt_integrity_invalid", str(result.content))
        finally:
            directory.cleanup()

    def test_missing_receipts_and_side_effect_boundary(self):
        directory, context, preview, service, authority, driver, execution_store = self._configured(
            (mcp_surface.McpWriteSurfaceTests._success(),)
        )
        try:
            server = self._server(context, service, execution_store)
            applied = mcp_surface.McpWriteSurfaceTests._call(
                server, "delivery_apply_approved_work_items",
                {"application_authority_id": authority.authority_id},
            )
            application_id = self._app_id(applied)
            with closing(sqlite3.connect(execution_store.path)) as connection:
                connection.execute("DELETE FROM application_receipts WHERE application_id=?", (application_id,))
                connection.commit()
            result = self._call(server, {"application_id": application_id})
            self.assertTrue(result.is_error)
            self.assertIn("application_receipt_not_found", str(result.content))
            self.assertEqual(len(driver.trace), 1)
        finally:
            directory.cleanup()

    def test_tampered_operation_and_application_receipts_fail_closed(self):
        directory, context, preview, service, authority, driver, execution_store = self._configured(
            (mcp_surface.McpWriteSurfaceTests._success(),)
        )
        try:
            server = self._server(context, service, execution_store)
            applied = mcp_surface.McpWriteSurfaceTests._call(
                server, "delivery_apply_approved_work_items",
                {"application_authority_id": authority.authority_id},
            )
            application_id = self._app_id(applied)
            operation = self._row_payload(execution_store.path, "operation_receipts", application_id)
            operation["completed_at"] = "2026-01-01T00:00:00Z"
            self._replace_payload(
                execution_store.path, "operation_receipts", application_id,
                operation, operation["operation_identity"],
            )
            result = self._call(server, {"application_id": application_id})
            self.assertTrue(result.is_error)
            self.assertIn("receipt_integrity_invalid", str(result.content))
        finally:
            directory.cleanup()

        directory, context, preview, service, authority, driver, execution_store = self._configured(
            (mcp_surface.McpWriteSurfaceTests._success(),)
        )
        try:
            server = self._server(context, service, execution_store)
            applied = mcp_surface.McpWriteSurfaceTests._call(
                server, "delivery_apply_approved_work_items",
                {"application_authority_id": authority.authority_id},
            )
            application_id = self._app_id(applied)
            application = self._row_payload(execution_store.path, "application_receipts", application_id)
            application["completed_at"] = "2026-01-01T00:00:00Z"
            self._replace_payload(execution_store.path, "application_receipts", application_id, application)
            result = self._call(server, {"application_id": application_id})
            self.assertTrue(result.is_error)
            self.assertIn("application_receipt_integrity_invalid", str(result.content))
        finally:
            directory.cleanup()

    def test_missing_operation_receipt_and_preview_binding_fail_closed(self):
        directory, context, preview, service, authority, driver, execution_store = self._configured(
            (mcp_surface.McpWriteSurfaceTests._success(),)
        )
        try:
            server = self._server(context, service, execution_store)
            applied = mcp_surface.McpWriteSurfaceTests._call(
                server, "delivery_apply_approved_work_items",
                {"application_authority_id": authority.authority_id},
            )
            application_id = self._app_id(applied)
            with closing(sqlite3.connect(execution_store.path)) as connection:
                connection.execute("DELETE FROM operation_receipts WHERE application_id=?", (application_id,))
                connection.commit()
            result = self._call(server, {"application_id": application_id})
            self.assertTrue(result.is_error)
            self.assertIn("operation_receipt_not_found", str(result.content))
        finally:
            directory.cleanup()

        directory, context, preview, service, authority, driver, execution_store = self._configured()
        try:
            server = self._server(context, service, execution_store)
            original = service.store._read_preview_revision_for_status

            def altered(workspace_identity, preview_id, revision=None):
                result = deepcopy(original(workspace_identity, preview_id, revision))
                result["canonical_payload"]["plan_digest"] = "sha256:" + "0" * 64
                return result

            with patch.object(service.store, "_read_preview_revision_for_status", side_effect=altered):
                runtime_context, capability, initial, now = self._pending(context, service, authority, execution_store)
                result = self._call(server, {"application_id": initial.application_id})
            self.assertTrue(result.is_error)
            self.assertIn("preview_digest_mismatch", str(result.content))
        finally:
            directory.cleanup()

    def test_execution_and_application_receipt_row_keys_bind_payload_identity(self):
        directory_a, context_a, preview_a, service_a, authority_a, driver_a, store_a = self._configured()
        directory_b, context_b, preview_b, service_b, authority_b, driver_b, store_b = self._configured()
        try:
            runtime_a, capability_a, state_a, now_a = self._pending(context_a, service_a, authority_a, store_a)
            runtime_b, capability_b, state_b, now_b = self._pending(context_b, service_b, authority_b, store_b)
            server_a = self._server(context_a, service_a, store_a)
            state_b_payload = self._row_payload(store_b.path, "application_execution", state_b.application_id)
            self._replace_payload(store_a.path, "application_execution", state_a.application_id, state_b_payload)
            result = self._call(server_a, {"application_id": state_a.application_id})
            self.assertTrue(result.is_error)
            self.assertIn("application_binding_conflict", str(result.content))
            self.assertNotIn(state_b.application_id, str(result.content))
        finally:
            directory_a.cleanup()
            directory_b.cleanup()

        directory_a, context_a, preview_a, service_a, authority_a, driver_a, store_a = self._configured(
            (mcp_surface.McpWriteSurfaceTests._success(),)
        )
        directory_b, context_b, preview_b, service_b, authority_b, driver_b, store_b = self._configured(
            (mcp_surface.McpWriteSurfaceTests._success(),)
        )
        try:
            server_a = self._server(context_a, service_a, store_a)
            applied_a = mcp_surface.McpWriteSurfaceTests._call(
                server_a, "delivery_apply_approved_work_items",
                {"application_authority_id": authority_a.authority_id},
            )
            server_b = self._server(context_b, service_b, store_b)
            applied_b = mcp_surface.McpWriteSurfaceTests._call(
                server_b, "delivery_apply_approved_work_items",
                {"application_authority_id": authority_b.authority_id},
            )
            application_a = self._app_id(applied_a)
            application_b = self._app_id(applied_b)
            receipt_b = self._row_payload(store_b.path, "application_receipts", application_b)
            self._replace_payload(store_a.path, "application_receipts", application_a, receipt_b)
            result = self._call(server_a, {"application_id": application_a})
            self.assertTrue(result.is_error)
            self.assertIn("application_binding_conflict", str(result.content))
            self.assertNotIn(application_b, str(result.content))
        finally:
            directory_a.cleanup()
            directory_b.cleanup()

    def test_attempt_and_operation_receipt_bind_to_preview_operation_and_row_key(self):
        directory, context, preview, service, authority, driver, execution_store = self._configured()
        try:
            runtime_context, capability, initial, now = self._pending(context, service, authority, execution_store)
            claimed, attempt = execution_store.claim_next_operation(
                capability, initial.application_id, initial.state_digest,
                runtime_context, "execution-owner-" + "c" * 32, now,
            )
            server = self._server(context, service, execution_store)
            attempt_payload = self._row_payload(execution_store.path, "operation_attempts", initial.application_id)
            alternate_operation = deepcopy(attempt_payload["operation"])
            alternate_operation["client_refs"] = ["wrong-operation"]
            alternate_identity = operation_identity(initial.application_id, 0, alternate_operation)
            attempt_payload["operation"] = alternate_operation
            attempt_payload["operation_identity"] = alternate_identity
            attempt_payload["request_identity"] = request_identity(alternate_identity)
            self._replace_payload(
                execution_store.path, "operation_attempts", initial.application_id,
                self._redigest(attempt_payload, "attempt_digest"), attempt.operation_identity,
            )
            result = self._call(server, {"application_id": initial.application_id})
            self.assertTrue(result.is_error)
            self.assertIn("attempt_integrity_invalid", str(result.content))
        finally:
            directory.cleanup()

        directory, context, preview, service, authority, driver, execution_store = self._configured(
            (mcp_surface.McpWriteSurfaceTests._success(),)
        )
        try:
            server = self._server(context, service, execution_store)
            applied = mcp_surface.McpWriteSurfaceTests._call(
                server, "delivery_apply_approved_work_items",
                {"application_authority_id": authority.authority_id},
            )
            application_id = self._app_id(applied)
            receipt_payload = self._row_payload(execution_store.path, "operation_receipts", application_id)
            stored_operation_identity = receipt_payload["operation_identity"]
            alternate_operation = deepcopy(receipt_payload["canonical_operation"])
            alternate_operation["client_refs"] = ["wrong-receipt-operation"]
            alternate_identity = operation_identity(application_id, 0, alternate_operation)
            receipt_payload["canonical_operation"] = alternate_operation
            receipt_payload["operation_identity"] = alternate_identity
            receipt_payload["request_identity"] = request_identity(alternate_identity)
            receipt_payload["operation_receipt_id"] = "operation-receipt-" + digest({
                "domain": "delivery-system:operation-receipt-id:v1",
                "operation_identity": alternate_identity,
            }).split(":", 1)[1]
            self._replace_payload(
                execution_store.path, "operation_receipts", application_id,
                self._redigest(receipt_payload, "receipt_digest"), stored_operation_identity,
            )
            result = self._call(server, {"application_id": application_id})
            self.assertTrue(result.is_error)
            self.assertIn("receipt_integrity_invalid", str(result.content))
        finally:
            directory.cleanup()

    def test_state_invariants_and_malformed_persistence_fail_closed(self):
        mutations = (
            ("Pending", lambda payload: payload.update(recovery_code="illegal")),
            ("Applying", lambda payload: payload.update(owner_id=None)),
            ("PartiallyApplied", lambda payload: payload.update(
                state="PartiallyApplied", owner_id=None, current_attempt_id=None,
                recovery_code="illegal",
            )),
            ("Failed", lambda payload: payload.update(recovery_code=None)),
            ("Blocked", lambda payload: payload.update(owner_id="illegal-owner")),
            ("OutcomeUnknown", lambda payload: payload.update(current_attempt_id=None)),
            ("Applied", lambda payload: payload.update(completed_at=None)),
        )
        for expected_state, mutate in mutations:
            directory, context, preview, service, authority, driver, execution_store = self._configured(
                (mcp_surface.McpWriteSurfaceTests._success(),) if expected_state == "Applied" else ()
            )
            try:
                if expected_state == "Pending":
                    _, _, state, _ = self._pending(context, service, authority, execution_store)
                    state_id = state.application_id
                elif expected_state == "Applied":
                    server = self._server(context, service, execution_store)
                    applied = mcp_surface.McpWriteSurfaceTests._call(
                        server, "delivery_apply_approved_work_items",
                        {"application_authority_id": authority.authority_id},
                    )
                    state_id = self._app_id(applied)
                else:
                    runtime_context, capability, initial, now = self._pending(context, service, authority, execution_store)
                    claimed, attempt = execution_store.claim_next_operation(
                        capability, initial.application_id, initial.state_digest,
                        runtime_context, "execution-owner-" + expected_state.lower()[:1] * 32, now,
                    )
                    if expected_state in {"Applying", "PartiallyApplied"}:
                        state_id = initial.application_id
                    else:
                        execution_store.settle_operation(
                            capability, initial.application_id, claimed.state_digest,
                            attempt.operation_identity, attempt.attempt_digest, claimed.owner_id,
                            runtime_context, expected_state, "recovery", now,
                        )
                    state_id = initial.application_id
                state_payload = self._row_payload(execution_store.path, "application_execution", state_id)
                mutate(state_payload)
                self._replace_payload(
                    execution_store.path, "application_execution", state_id,
                    self._redigest(state_payload, "state_digest"),
                )
                result = self._call(self._server(context, service, execution_store), {"application_id": state_id})
                self.assertTrue(result.is_error)
                self.assertIn("state_integrity_invalid", str(result.content))
            finally:
                directory.cleanup()

        malformed_cases = (
            ("application_execution", "state_integrity_invalid"),
            ("operation_attempts", "attempt_integrity_invalid"),
            ("operation_receipts", "receipt_integrity_invalid"),
            ("application_receipts", "application_receipt_integrity_invalid"),
        )
        for table, expected_code in malformed_cases:
            directory, context, preview, service, authority, driver, execution_store = self._configured(
                (mcp_surface.McpWriteSurfaceTests._success(),)
            )
            try:
                server = self._server(context, service, execution_store)
                applied = mcp_surface.McpWriteSurfaceTests._call(
                    server, "delivery_apply_approved_work_items",
                    {"application_authority_id": authority.authority_id},
                )
                application_id = self._app_id(applied)
                with closing(sqlite3.connect(execution_store.path)) as connection:
                    connection.execute(f"UPDATE {table} SET payload=? WHERE application_id=?", ("{malformed", application_id))
                    connection.commit()
                result = self._call(server, {"application_id": application_id})
                self.assertTrue(result.is_error)
                self.assertIn(expected_code, str(result.content))
                for raw in ("JSONDecodeError", "KeyError", "IndexError", "sqlite3"):
                    self.assertNotIn(raw, str(result.content))
            finally:
                directory.cleanup()

    def test_progress_bounds_and_applied_receipt_lookup_are_bounded(self):
        directory, context, preview, service, authority, driver, execution_store = self._configured(
            (mcp_surface.McpWriteSurfaceTests._success(),)
        )
        try:
            server = self._server(context, service, execution_store)
            applied = mcp_surface.McpWriteSurfaceTests._call(
                server, "delivery_apply_approved_work_items",
                {"application_authority_id": authority.authority_id},
            )
            application_id = self._app_id(applied)
            operation_payload = self._row_payload(execution_store.path, "operation_receipts", application_id)
            with closing(sqlite3.connect(execution_store.path)) as connection:
                for index in range(50):
                    connection.execute(
                        "INSERT INTO operation_receipts(workspace_identity, application_id, operation_identity, payload) VALUES (?, ?, ?, ?)",
                        (execution_store.workspace_identity, application_id, f"orphan-operation-{index}", json.dumps(operation_payload, sort_keys=True)),
                    )
                connection.commit()
            stable = self._call(server, {"application_id": application_id})
            self.assertFalse(stable.is_error, stable.content)
            self.assertEqual(len(stable.structured_content["operation_receipts"]), 1)
            state = self._row_payload(execution_store.path, "application_execution", application_id)
            state["next_operation_index"] = 10**9
            self._replace_payload(
                execution_store.path, "application_execution", application_id,
                self._redigest(state, "state_digest"),
            )
            result = self._call(server, {"application_id": application_id})
            self.assertTrue(result.is_error)
            self.assertIn("state_integrity_invalid", str(result.content))
        finally:
            directory.cleanup()

        source = getsource(type(execution_store).get_execution)
        self.assertNotIn("_get_operation_receipt_by_id", source)
        self.assertIn("get_operation_receipt(application_id, operation_id)", source)
        self.assertNotIn("fetchall", source)

    def test_status_bootstrap_validates_preview_before_evidence_read(self):
        directory, context, preview, service, authority, driver, execution_store = self._configured()
        try:
            runtime_context, capability, initial, now = self._pending(context, service, authority, execution_store)
            events = []
            original_bootstrap = execution_store.get_execution_bootstrap
            original_reader = service.store._read_preview_revision_for_status
            public_reader = service.store.get_preview_revision
            with patch.object(execution_store, "get_execution_bootstrap", side_effect=lambda application_id: (events.append("execution"), original_bootstrap(application_id))[1]), \
                 patch.object(service.store, "get_preview_revision", side_effect=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("public Preview reader used"))), \
                 patch.object(service.store, "_read_preview_revision_for_status", side_effect=lambda workspace, preview_id, revision: (events.append("preview"), original_reader(workspace, preview_id, revision))[1]):
                result = self._call(self._server(context, service, execution_store), {"application_id": initial.application_id})
            self.assertFalse(result.is_error, result.content)
            self.assertEqual(events[:2], ["execution", "preview"])

            original_reader = service.store._read_preview_revision_for_status
            def altered(workspace, preview_id, revision):
                value = deepcopy(original_reader(workspace, preview_id, revision))
                value["canonical_payload"]["sealed_preview_digest"] = "sha256:" + "0" * 64
                return value
            with patch.object(service.store, "_read_preview_revision_for_status", side_effect=altered), \
                 patch.object(service.store, "get_evidence_records", side_effect=AssertionError("evidence read before envelope validation")):
                result = self._call(self._server(context, service, execution_store), {"application_id": initial.application_id})
            self.assertTrue(result.is_error)
            self.assertIn("preview_digest_mismatch", str(result.content))
        finally:
            directory.cleanup()

    def test_impossible_pending_attempt_fails_before_output_validation(self):
        directory, context, preview, service, authority, driver, execution_store = self._configured()
        try:
            runtime_context, capability, initial, now = self._pending(context, service, authority, execution_store)
            _, attempt = execution_store.claim_next_operation(
                capability, initial.application_id, initial.state_digest,
                runtime_context, "execution-owner-" + "p" * 32, now,
            )
            state = self._row_payload(execution_store.path, "application_execution", initial.application_id)
            attempt_payload = self._row_payload(
                execution_store.path, "operation_attempts", initial.application_id, attempt.operation_identity,
            )
            attempt_payload["state"] = "Pending"
            self._replace_payload(
                execution_store.path, "operation_attempts", initial.application_id,
                self._redigest(attempt_payload, "attempt_digest"), attempt.operation_identity,
            )
            self._replace_payload(
                execution_store.path, "application_execution", initial.application_id,
                self._redigest({**state, "state": "Pending", "owner_id": None, "current_attempt_id": None}, "state_digest"),
            )
            result = self._call(self._server(context, service, execution_store), {"application_id": initial.application_id})
            self.assertTrue(result.is_error)
            self.assertIn("state_integrity_invalid", str(result.content))
            self.assertNotIn("ValidationError", str(result.content))
            self.assertEqual(len(driver.trace), 0)
        finally:
            directory.cleanup()

    def test_zero_progress_partially_applied_fails_closed(self):
        directory, context, preview, service, authority, driver, execution_store = self._configured()
        try:
            _, _, initial, _ = self._pending(context, service, authority, execution_store)
            state = self._row_payload(execution_store.path, "application_execution", initial.application_id)
            state.update({
                "state": "PartiallyApplied",
                "next_operation_index": 0,
                "owner_id": None,
                "current_attempt_id": None,
                "recovery_code": None,
                "operation_receipt_refs": [],
                "completed_at": None,
            })
            self._replace_payload(
                execution_store.path, "application_execution", initial.application_id,
                self._redigest(state, "state_digest"),
            )
            result = self._call(self._server(context, service, execution_store), {"application_id": initial.application_id})
            self.assertTrue(result.is_error)
            self.assertIn("state_integrity_invalid", str(result.content))
            self.assertEqual(len(driver.trace), 0)
        finally:
            directory.cleanup()

    def test_application_receipt_timestamp_corruption_is_stable(self):
        mutations = (
            lambda payload: payload.update(started_at=123),
            lambda payload: payload.update(completed_at="not-a-timestamp"),
            lambda payload: payload.update(
                started_at="9999-12-31T00:00:00Z", completed_at="0001-01-01T00:00:00Z",
            ),
        )
        for mutate in mutations:
            directory, context, preview, service, authority, driver, execution_store = self._configured(
                (mcp_surface.McpWriteSurfaceTests._success(),),
            )
            try:
                server = self._server(context, service, execution_store)
                applied = mcp_surface.McpWriteSurfaceTests._call(
                    server, "delivery_apply_approved_work_items",
                    {"application_authority_id": authority.authority_id},
                )
                application_id = self._app_id(applied)
                receipt = self._row_payload(execution_store.path, "application_receipts", application_id)
                mutate(receipt)
                self._replace_payload(
                    execution_store.path, "application_receipts", application_id,
                    self._redigest(receipt, "receipt_digest"),
                )
                result = self._call(server, {"application_id": application_id})
                self.assertTrue(result.is_error)
                self.assertIn("application_receipt_integrity_invalid", str(result.content))
                for raw in ("ValidationError", "ValueError", "datetime", "JSONDecodeError"):
                    self.assertNotIn(raw, str(result.content))
                self.assertEqual(len(driver.trace), 1)
            finally:
                directory.cleanup()

        directory, context, preview, service, authority, driver, execution_store = self._configured(
            (mcp_surface.McpWriteSurfaceTests._success(),),
        )
        try:
            server = self._server(context, service, execution_store)
            applied = mcp_surface.McpWriteSurfaceTests._call(
                server, "delivery_apply_approved_work_items",
                {"application_authority_id": authority.authority_id},
            )
            application_id = self._app_id(applied)
            receipt = self._row_payload(execution_store.path, "application_receipts", application_id)
            state = self._row_payload(execution_store.path, "application_execution", application_id)
            receipt["started_at"] = state["started_at"]
            receipt["completed_at"] = "9999-12-31T00:00:00Z"
            self._replace_payload(
                execution_store.path, "application_receipts", application_id,
                self._redigest(receipt, "receipt_digest"),
            )
            result = self._call(server, {"application_id": application_id})
            self.assertTrue(result.is_error)
            self.assertIn("application_receipt_integrity_invalid", str(result.content))
            self.assertEqual(len(driver.trace), 1)
        finally:
            directory.cleanup()

    def test_mcp_status_schema_advertises_exact_identifier_pattern(self):
        async def inspect_tools():
            async with Client(mcp, raise_exceptions=True) as client:
                return await client.list_tools()
        tools = self._run_async(inspect_tools()).tools
        status_tool = next(tool for tool in tools if tool.name == "delivery_get_application_status")
        schema = status_tool.input_schema
        payload_schema = schema["$defs"][schema["properties"]["payload"]["$ref"].rsplit("/", 1)[1]]
        properties = payload_schema["properties"]
        self.assertEqual(properties["application_id"]["pattern"], r"^application-[0-9a-f]{64}$")
        self.assertEqual(len(tools), 9)


if __name__ == "__main__":
    unittest.main()
