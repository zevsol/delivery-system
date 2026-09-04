from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from mcp import Client, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import ValidationError

from delivery_system.applier import ApplyResult
from delivery_system.drivers.write_contract import WriteObservation, WriteObservationKind
from delivery_system.execution_store import SQLiteExecutionStore
from delivery_system.runtime import RuntimeApprovalAuthorityService, RuntimeContext
from mcp_server.server import (
    ApplyApprovedWorkItemsInput, ApplyApprovedWorkItemsOutput, create_server, mcp,
)
from tests.fakes.fake_write_driver import FakeWriteDriver
from tests.v1 import test_operational_approval_authority as approval_fixture
from tests.v1.test_pc2b_applier_orchestration import ApplierOrchestrationTests


class McpWriteSurfaceTests(unittest.TestCase):
    @staticmethod
    def run_async(coro):
        return asyncio.run(coro)

    def _configured(self, observations=(), operations=None):
        harness = ApplierOrchestrationTests()
        if operations is None:
            directory, context, preview, service, authority, driver = harness._compose(
                observations,
            )
        else:
            refs = []
            for operation in operations:
                refs.extend(operation["client_refs"])
            directory, context, preview, service, authority, driver = harness._compose_operations(
                tuple(dict.fromkeys(refs)), operations, observations,
            )
        execution_store = harness._store(context, service, directory)
        return directory, context, preview, service, authority, driver, execution_store

    @staticmethod
    def _call(server, name, payload, *, raise_exceptions=True):
        async def exercise():
            async with Client(server, raise_exceptions=raise_exceptions) as client:
                return await client.call_tool(name, {"payload": payload})
        return McpWriteSurfaceTests.run_async(exercise())

    @staticmethod
    def _success(number=1, numeric_id="1"):
        return ApplierOrchestrationTests._success(number=number, numeric_id=numeric_id)

    def test_sixth_tool_and_exact_annotations(self):
        async def exercise():
            async with Client(mcp, raise_exceptions=True) as client:
                return (await client.list_tools()).tools
        tools = self.run_async(exercise())
        self.assertEqual(len(tools), 6)
        apply_tool = next(tool for tool in tools if tool.name == "delivery_apply_approved_work_items")
        self.assertEqual((apply_tool.annotations.read_only_hint,
                          apply_tool.annotations.destructive_hint,
                          apply_tool.annotations.open_world_hint), (False, True, True))

    def test_global_apply_is_unconfigured_and_fails_closed(self):
        result = self._call(mcp, "delivery_apply_approved_work_items",
                            {"application_authority_id": "authority"})
        self.assertTrue(result.is_error)
        self.assertIn("write_execution_boundary_unavailable", str(result.content))

    def test_apply_input_is_strict_and_forbids_injection(self):
        for value in (1, True):
            with self.assertRaises(ValidationError):
                ApplyApprovedWorkItemsInput.model_validate({"application_authority_id": value})
        with self.assertRaises(ValidationError):
            ApplyApprovedWorkItemsInput.model_validate({"application_authority_id": "a", "token": "secret"})
        for value in (" ", " authority", "authority ", "\tauthority"):
            directory, context, preview, service, authority, driver, execution_store = self._configured()
            try:
                result = self._call(create_server(context, service.store, approval_authority_service=service,
                                                  execution_store=execution_store),
                                    "delivery_apply_approved_work_items",
                                    {"application_authority_id": value})
                self.assertTrue(result.is_error)
                self.assertIn("application_authority_id_invalid", str(result.content))
            finally:
                directory.cleanup()

    def test_execution_boundary_composition_is_explicit_and_bounded(self):
        directory, context, preview, service, authority, driver, execution_store = self._configured()
        try:
            server = create_server(context, service.store, approval_authority_service=service,
                                   execution_store=execution_store)
            self.assertIsNotNone(server)
            with self.assertRaisesRegex(ValueError, "^write_execution_boundary_invalid$"):
                create_server(context, service.store, approval_authority_service=service,
                              execution_store=object())
            other = SQLiteExecutionStore(directory.name + "\\other.sqlite3", context.workspace_identity)
            with self.assertRaisesRegex(ValueError, "^write_execution_boundary_invalid$"):
                create_server(context, service.store, approval_authority_service=service,
                              execution_store=other)
        finally:
            directory.cleanup()

    def test_runtime_service_subclasses_cannot_replace_applier_trust_root(self):
        directory, context, preview, service, authority, driver, execution_store = self._configured()
        try:
            calls = []

            class MaliciousService(RuntimeApprovalAuthorityService):
                def create_applier(self, execution_store):
                    calls.append(execution_store)
                    return object()

            class BenignService(RuntimeApprovalAuthorityService):
                pass

            for service_type in (MaliciousService, BenignService):
                candidate = service_type(context, service.store, service.attestation_service,
                                         clock=service.clock)
                candidate_store = SQLiteExecutionStore(
                    directory.name + "\\service-subclass.sqlite3",
                    context.workspace_identity,
                    runtime_service=candidate,
                )
                with self.assertRaisesRegex(ValueError, "^write_execution_boundary_invalid$"):
                    create_server(context, service.store, approval_authority_service=candidate,
                                  execution_store=candidate_store)
            self.assertEqual(calls, [])
        finally:
            directory.cleanup()

    def test_execution_store_subclasses_and_structural_fakes_are_rejected(self):
        directory, context, preview, service, authority, driver, execution_store = self._configured()
        try:
            calls = []

            class MaliciousStore(SQLiteExecutionStore):
                def claim_next_operation(self, *args, **kwargs):
                    calls.append(True)
                    return None

            class BenignStore(SQLiteExecutionStore):
                pass

            for store_type in (MaliciousStore, BenignStore):
                candidate = store_type(directory.name + "\\store-subclass.sqlite3",
                                       context.workspace_identity,
                                       runtime_service=service)
                with self.assertRaisesRegex(ValueError, "^write_execution_boundary_invalid$"):
                    create_server(context, service.store, approval_authority_service=service,
                                  execution_store=candidate)

            class StructuralFake:
                workspace_identity = context.workspace_identity
                runtime_service = service
                path = directory.name + "\\fake.sqlite3"

            with self.assertRaisesRegex(ValueError, "^write_execution_boundary_invalid$"):
                create_server(context, service.store, approval_authority_service=service,
                              execution_store=StructuralFake())
            self.assertEqual(calls, [])
        finally:
            directory.cleanup()

    def test_shadow_runtime_compositions_fail_but_exact_composition_works(self):
        directory, context, preview, service, authority, driver, execution_store = self._configured()
        try:
            self.assertIsNotNone(create_server(context, service.store,
                                               approval_authority_service=service,
                                               execution_store=execution_store))
            shadow = RuntimeApprovalAuthorityService(
                context, service.store, service.attestation_service, clock=service.clock,
            )
            permutations = (
                (context, shadow, execution_store),
                (context, service, SQLiteExecutionStore(
                    directory.name + "\\shadow-store.sqlite3", context.workspace_identity,
                    runtime_service=shadow,
                )),
            )
            for candidate_context, candidate_service, candidate_store in permutations:
                with self.assertRaisesRegex(ValueError, "^write_execution_boundary_invalid$"):
                    create_server(candidate_context, service.store,
                                  approval_authority_service=candidate_service,
                                  execution_store=candidate_store)
        finally:
            directory.cleanup()

    def test_write_disabled_service_preserves_b3_error(self):
        harness = approval_fixture.OperationalApprovalAuthorityTests()
        directory, context, preview_store, preview, audit, foundation = harness._setup("memory")
        try:
            service = RuntimeApprovalAuthorityService(context, preview_store, foundation.attestation_service,
                                                      clock=foundation.clock)
            execution_store = SQLiteExecutionStore(directory.name + "\\execution.sqlite3",
                                                    context.workspace_identity, runtime_service=service)
            server = create_server(context, preview_store, approval_authority_service=service,
                                   execution_store=execution_store)
            result = self._call(server, "delivery_apply_approved_work_items",
                                {"application_authority_id": "authority"})
            self.assertTrue(result.is_error)
            self.assertIn("write_executor_required", str(result.content))
        finally:
            directory.cleanup()

    def test_success_projects_exact_result_and_delegates_once(self):
        directory, context, preview, service, authority, driver, execution_store = self._configured((self._success(),))
        try:
            server = create_server(context, service.store, approval_authority_service=service,
                                   execution_store=execution_store)
            result = self._call(server, "delivery_apply_approved_work_items",
                                {"application_authority_id": authority.authority_id})
            self.assertFalse(result.is_error)
            self.assertEqual(set(result.structured_content), {
                "application_id", "state", "next_operation_index",
                "application_receipt_id", "recovery_code",
            })
            self.assertEqual(result.structured_content["state"], "Applied")
            self.assertEqual(len(driver.trace), 1)
            self.assertEqual(ApplyApprovedWorkItemsOutput.model_validate(result.structured_content).state, "Applied")
        finally:
            directory.cleanup()

    def test_applied_replay_and_bounded_applying_do_not_dispatch(self):
        directory, context, preview, service, authority, driver, execution_store = self._configured((self._success(),))
        try:
            server = create_server(context, service.store, approval_authority_service=service,
                                   execution_store=execution_store)
            first = self._call(server, "delivery_apply_approved_work_items",
                               {"application_authority_id": authority.authority_id})
            second = self._call(server, "delivery_apply_approved_work_items",
                                {"application_authority_id": authority.authority_id})
            self.assertEqual(first.structured_content, second.structured_content)
            self.assertEqual(len(driver.trace), 1)
        finally:
            directory.cleanup()

        directory, context, preview, service, authority, driver, execution_store = self._configured((self._success(),))
        try:
            b3 = ApplierOrchestrationTests()
            runtime_context = service.create_execution_context(authority.authority_id)
            now = service._utc(service.clock())
            initial = runtime_context.new_execution_state(
                state="Pending", next_operation_index=0, owner_id=None, current_attempt_id=None,
                recovery_code=None, operation_receipt_refs=(), started_at=now, updated_at=now,
                completed_at=None, orchestration_policy="delivery-system:applier-orchestration-v1",
            )
            capability = service._write_executor_factory(execution_store)
            persisted = execution_store.create_execution_if_absent(capability, initial)
            execution_store.claim_next_operation(capability, persisted.application_id, persisted.state_digest,
                                                  runtime_context, "execution-owner-" + "a" * 32, now)
            server = create_server(context, service.store, approval_authority_service=service,
                                   execution_store=execution_store)
            result = self._call(server, "delivery_apply_approved_work_items",
                                {"application_authority_id": authority.authority_id})
            self.assertEqual((result.structured_content["state"], result.structured_content["recovery_code"]),
                             ("Applying", "application_recovery_required"))
            self.assertEqual(len(driver.trace), 0)
        finally:
            directory.cleanup()

    def test_failed_blocked_and_ambiguous_results_are_projected_without_retry(self):
        cases = (
            WriteObservation(WriteObservationKind.DEFINITIVE_REJECTED, code="github_write_rejected"),
            WriteObservation(WriteObservationKind.AMBIGUOUS, code="github_write_transport_ambiguous"),
        )
        for observation, expected_state in zip(cases, ("Failed", "OutcomeUnknown")):
            directory, context, preview, service, authority, driver, execution_store = self._configured((observation,))
            try:
                server = create_server(context, service.store, approval_authority_service=service,
                                       execution_store=execution_store)
                result = self._call(server, "delivery_apply_approved_work_items",
                                    {"application_authority_id": authority.authority_id})
                self.assertEqual(result.structured_content["state"], expected_state)
                self.assertEqual(len(driver.trace), 1)
            finally:
                directory.cleanup()

    def test_replay_error_is_not_swallowed_by_adapter(self):
        directory, context, preview, service, authority, driver, execution_store = self._configured((self._success(),))
        try:
            server = create_server(context, service.store, approval_authority_service=service,
                                   execution_store=execution_store)
            self._call(server, "delivery_apply_approved_work_items", {"application_authority_id": authority.authority_id})
            with patch.object(execution_store, "get_execution",
                              side_effect=ValueError("application_replay_validation_required")):
                result = self._call(server, "delivery_apply_approved_work_items",
                                    {"application_authority_id": authority.authority_id})
                self.assertTrue(result.is_error)
                self.assertIn("application_replay_validation_required", str(result.content))
        finally:
            directory.cleanup()

    def test_relationship_flow_is_single_mcp_call_and_fake_only(self):
        operations = [
            {"operation_kind": "create_issue", "client_refs": ["child"], "depends_on": []},
            {"operation_kind": "create_issue", "client_refs": ["parent"], "depends_on": []},
            {"operation_kind": "add_sub_issue", "client_refs": ["child", "parent"], "depends_on": []},
        ]
        observations = (self._success(1, "101"), self._success(2, "102"),
                        ApplierOrchestrationTests._relationship_success())
        directory, context, preview, service, authority, driver, execution_store = self._configured(observations, operations)
        try:
            server = create_server(context, service.store, approval_authority_service=service,
                                   execution_store=execution_store)
            result = self._call(server, "delivery_apply_approved_work_items",
                                {"application_authority_id": authority.authority_id})
            self.assertEqual(result.structured_content["state"], "Applied")
            self.assertEqual(len(driver.trace), 3)
            self.assertEqual(driver.trace[-1].command.first.issue_number, 1)
            self.assertEqual(driver.trace[-1].command.second.issue_number, 2)
        finally:
            directory.cleanup()

    def test_global_stdio_discovers_sixth_tool_but_apply_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory).resolve()
            (workspace / ".gitignore").write_text(".delivery-system/\n", encoding="utf-8")
            subprocess.run(["git", "init", "--quiet"], cwd=workspace, check=True,
                            capture_output=True, text=True)
            async def exercise():
                params = StdioServerParameters(
                    command=sys.executable,
                    args=["-m", "mcp_server.server", "--workspace-root", str(workspace)],
                    cwd=Path(__file__).parents[2].resolve(),
                    env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                )
                async with stdio_client(params) as (read, write):
                    async with Client(stdio_client(params), raise_exceptions=False) as client:
                        tools = await client.list_tools()
                        result = await client.call_tool("delivery_apply_approved_work_items",
                                                        {"payload": {"application_authority_id": "authority"}})
                        return tools, result
            tools, result = self.run_async(exercise())
            self.assertEqual(len(tools.tools), 6)
            self.assertTrue(result.is_error)
            self.assertIn("write_execution_boundary_unavailable", str(result.content))


if __name__ == "__main__":
    unittest.main()
