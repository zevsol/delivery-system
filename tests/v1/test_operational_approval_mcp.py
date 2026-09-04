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

from delivery_system.attestation import AttestationRuntimeBoundary
from delivery_system.attestation_runtime import RuntimeAttestationOrchestrationService
from delivery_system.auditor import RuleEvaluationDraft, RuntimeAuditor
from delivery_system.audit_state import AuditStatus
from delivery_system.drivers.contract import DriverTrustContext
from delivery_system.runtime import (
    InMemoryPreviewStore, RuntimeApprovalAuthorityService, RuntimeContext, RuntimePlanner,
)
from delivery_system.rules import SemanticOutcome, build_registry_v1
from mcp_server.server import (
    IssueApplicationAuthorityInput, RecordApprovalInput, create_server, mcp,
)
from tests.attestation_contract.test_attestation_contract import FakeCapabilityPolicy, FakeIssuer
from tests.attestation_orchestration.test_attestation_orchestration import FakeReadOnlyDriver
from tests.fakes.attestation_provider import FakeCapabilityResolver, FakeCredentialCapabilityProvider
from tests.local_rest_offline.test_repository_aware_runtime import plan as base_plan


TRUST = DriverTrustContext("fixture-driver", "offline://fixture", "fixture-v1")
NOW = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)

APPROVAL_FIELDS = {
    "approval_id", "audit_id", "audit_digest", "audit_result", "preview_id", "revision",
    "plan_digest", "remote_snapshot_digest", "operation_set_digest", "repository_identity",
    "approval_command", "approver_claim", "approved_at", "status",
}
AUTHORITY_FIELDS = {
    "authority_id", "workspace_identity", "repository_identity", "preview_id", "revision",
    "sealed_preview_digest", "plan_digest", "operation_set_digest", "remote_snapshot_digest",
    "audit_id", "audit_digest", "approval_id", "approval_digest", "credential_binding_id",
    "credential_instance_id", "issuer_id", "credential_principal_identity", "github_subject_identity",
    "driver_identity", "remote_authority", "required_capabilities", "granted_capabilities",
    "issued_at", "expires_at",
}


def plan() -> dict[str, object]:
    result = base_plan()
    result["operation_intents"] = [{
        "operation_kind": "create_issue", "client_refs": ["item"], "depends_on": [],
    }]
    return result


class OperationalApprovalMcpTests(unittest.TestCase):
    @staticmethod
    def run_async(coroutine):
        return asyncio.run(coroutine)

    def _setup(self, *, with_attestation: bool):
        directory = tempfile.TemporaryDirectory()
        context = RuntimeContext.from_workspace_root(directory.name)
        store = InMemoryPreviewStore(context.workspace_identity, TRUST)
        preview = RuntimePlanner(context, store, FakeReadOnlyDriver(node_id="node-1"), TRUST).preview(plan())
        auditor = RuntimeAuditor(context, store, build_registry_v1(), TRUST)
        audit_context = auditor.get_context(preview["preview_id"], 1)
        evaluations = [
            RuleEvaluationDraft(rule["rule_id"], rule["rule_version"], SemanticOutcome.PASSED, "verified")
            for rule in audit_context["semantic_rule_contexts"] if rule["applicability"] == "Applicable"
        ]
        audit = auditor.record_audit(
            preview["preview_id"], 1, audit_context["audit_context_digest"], evaluations, [],
        )
        attestation = None
        if with_attestation:
            issuer = FakeIssuer()
            attestation = RuntimeAttestationOrchestrationService(
                context, store, TRUST,
                AttestationRuntimeBoundary(issuer, issuer, issuer, FakeCapabilityPolicy()),
                FakeCredentialCapabilityProvider(), FakeCapabilityResolver(), clock=lambda: NOW,
            )
        service = RuntimeApprovalAuthorityService(context, store, attestation, clock=lambda: NOW)
        return directory, context, store, preview, audit, service

    def _call(self, server, tool_name, payload, *, raise_exceptions=False):
        async def exercise():
            async with Client(server, raise_exceptions=raise_exceptions) as client:
                return await client.call_tool(tool_name, {"payload": payload})
        return self.run_async(exercise())

    def test_discovery_has_exact_six_tools_and_annotations(self):
        async def exercise():
            async with Client(mcp, raise_exceptions=True) as client:
                return await client.list_tools()
        tools = self.run_async(exercise()).tools
        by_name = {tool.name: tool for tool in tools}
        expected = {
            "delivery_plan_preview", "delivery_get_audit_context", "delivery_record_audit",
            "delivery_record_approval", "delivery_issue_application_authority",
            "delivery_apply_approved_work_items",
        }
        self.assertEqual(set(by_name), expected)
        for name, expected_values in {
            "delivery_record_approval": (False, False, False),
            "delivery_issue_application_authority": (False, False, True),
        }.items():
            annotations = by_name[name].annotations
            self.assertIsNotNone(annotations)
            self.assertEqual(
                (annotations.read_only_hint, annotations.destructive_hint, annotations.open_world_hint),
                expected_values,
            )

    def test_new_input_models_are_strict_and_use_strict_int(self):
        valid_approval = {
            "preview_id": "preview", "revision": 1, "approval_command": "command", "approver_claim": "human",
        }
        for field in ("approval_id", "approved_at", "audit_id", "repository_identity", "plan_digest", "status"):
            with self.subTest(model="approval", field=field):
                with self.assertRaises(ValidationError):
                    RecordApprovalInput.model_validate({**valid_approval, field: "forbidden"})
        for revision in (True, "1"):
            with self.assertRaises(ValidationError):
                RecordApprovalInput.model_validate({**valid_approval, "revision": revision})

        valid_authority = {"preview_id": "preview", "revision": 1, "approval_id": "approval-1"}
        for field in ("authority_id", "credential_binding_id", "required_capabilities", "repository_identity", "audit_digest", "expires_at", "provider"):
            with self.subTest(model="authority", field=field):
                with self.assertRaises(ValidationError):
                    IssueApplicationAuthorityInput.model_validate({**valid_authority, field: "forbidden"})
        for revision in (True, "1"):
            with self.assertRaises(ValidationError):
                IssueApplicationAuthorityInput.model_validate({**valid_authority, "revision": revision})

    def test_approval_is_delegated_without_attestation_and_projects_exact_record(self):
        directory, context, store, preview, audit, service = self._setup(with_attestation=False)
        try:
            server = create_server(context, store, approval_authority_service=service)
            command = f"批准写入 {preview['preview_id']} 1"

            async def exercise():
                async with Client(server, raise_exceptions=True) as client:
                    return await client.call_tool("delivery_record_approval", {
                        "payload": {
                            "preview_id": preview["preview_id"], "revision": 1,
                            "approval_command": command, "approver_claim": " human ",
                        },
                    })
            result = self.run_async(exercise())
            approval = store.get_approval(context.workspace_identity, service._approval_id(audit))
            self.assertFalse(result.is_error)
            self.assertEqual(set(result.structured_content), set(approval.to_dict()))
            self.assertEqual(set(result.structured_content), APPROVAL_FIELDS)
            self.assertEqual(result.structured_content, approval.to_dict())
            self.assertEqual(result.structured_content["audit_result"], "Passed")
            self.assertEqual(result.structured_content["status"], "valid")
        finally:
            directory.cleanup()

    def test_authority_delegation_replay_and_projection_use_stable_service(self):
        directory, context, store, preview, audit, service = self._setup(with_attestation=True)
        try:
            server = create_server(context, store, approval_authority_service=service)
            command = f"批准写入 {preview['preview_id']} 1"

            async def exercise():
                async with Client(server, raise_exceptions=True) as client:
                    approval_result = await client.call_tool("delivery_record_approval", {
                        "payload": {
                            "preview_id": preview["preview_id"], "revision": 1,
                            "approval_command": command, "approver_claim": "human",
                        },
                    })
                    approval_id = approval_result.structured_content["approval_id"]
                    first = await client.call_tool("delivery_issue_application_authority", {
                        "payload": {"preview_id": preview["preview_id"], "revision": 1, "approval_id": approval_id},
                    })
                    second = await client.call_tool("delivery_issue_application_authority", {
                        "payload": {"preview_id": preview["preview_id"], "revision": 1, "approval_id": approval_id},
                    })
                    return approval_result, first, second

            approval_result, first, second = self.run_async(exercise())
            self.assertFalse(first.is_error)
            self.assertFalse(second.is_error)
            self.assertEqual(set(first.structured_content), set(second.structured_content))
            self.assertEqual(first.structured_content, second.structured_content)
            self.assertEqual(len(service._authorities), 1)
            self.assertTrue(service.validate_application_authority(next(iter(service._authorities.values()))))
            self.assertEqual(len(first.structured_content["required_capabilities"]), 1)
            self.assertEqual(first.structured_content["required_capabilities"], ["issues:write"])
            self.assertEqual(first.structured_content["granted_capabilities"], ["issues:write"])
        finally:
            directory.cleanup()

    def test_approval_replay_conflict_command_claim_and_stale_through_mcp(self):
        directory, context, store, preview, audit, service = self._setup(with_attestation=False)
        try:
            clock_calls = 0
            def clock():
                nonlocal clock_calls
                clock_calls += 1
                return NOW if clock_calls == 1 else datetime(2026, 8, 14, 12, 1, tzinfo=timezone.utc)
            service.clock = clock
            server = create_server(context, store, approval_authority_service=service)
            command = f"批准写入 {preview['preview_id']} 1"

            with patch.object(service, "record_approval", wraps=service.record_approval) as record_approval:
                async def exercise():
                    async with Client(server, raise_exceptions=False) as client:
                        first = await client.call_tool("delivery_record_approval", {"payload": {
                            "preview_id": preview["preview_id"], "revision": 1,
                            "approval_command": command, "approver_claim": "human",
                        }})
                        replay = await client.call_tool("delivery_record_approval", {"payload": {
                            "preview_id": preview["preview_id"], "revision": 1,
                            "approval_command": command, "approver_claim": "human",
                        }})
                        conflict = await client.call_tool("delivery_record_approval", {"payload": {
                            "preview_id": preview["preview_id"], "revision": 1,
                            "approval_command": command, "approver_claim": "other",
                        }})
                        malformed = await client.call_tool("delivery_record_approval", {"payload": {
                            "preview_id": preview["preview_id"], "revision": 1,
                            "approval_command": f"批准写入 {preview['preview_id']} 1 ", "approver_claim": "human",
                        }})
                        whitespace = await client.call_tool("delivery_record_approval", {"payload": {
                            "preview_id": preview["preview_id"], "revision": 1,
                            "approval_command": command, "approver_claim": "   ",
                        }})
                        return first, replay, conflict, malformed, whitespace

                first, replay, conflict, malformed, whitespace = self.run_async(exercise())
                self.assertEqual(record_approval.call_count, 5)
            self.assertFalse(first.is_error)
            self.assertFalse(replay.is_error)
            self.assertEqual(first.structured_content["approval_id"], replay.structured_content["approval_id"])
            self.assertEqual(first.structured_content["approved_at"], replay.structured_content["approved_at"])
            self.assertEqual(first.structured_content, replay.structured_content)
            self.assertEqual(first.structured_content["approved_at"], "2026-08-14T12:00:00Z")
            self.assertTrue(conflict.is_error)
            self.assertIn("approval_binding_conflict", str(conflict.content))
            self.assertTrue(malformed.is_error)
            self.assertIn("approval_command_invalid", str(malformed.content))
            self.assertTrue(whitespace.is_error)
            self.assertIn("approval_invalid", str(whitespace.content))

            store.transition_audit_status(audit.audit_id, AuditStatus.STALE, "test")
            stale = self._call(server, "delivery_record_approval", {
                "preview_id": preview["preview_id"], "revision": 1,
                "approval_command": command, "approver_claim": "human",
            })
            self.assertTrue(stale.is_error)
            self.assertIn("audit_not_found", str(stale.content))
            self.assertEqual(store.get_approval(context.workspace_identity, first.structured_content["approval_id"]).to_dict(), first.structured_content)
        finally:
            directory.cleanup()

    def test_authority_mcp_projection_and_negative_runtime_codes(self):
        directory, context, store, preview, audit, service = self._setup(with_attestation=True)
        try:
            server = create_server(context, store, approval_authority_service=service)
            command = f"批准写入 {preview['preview_id']} 1"
            approval = self._call(server, "delivery_record_approval", {
                "preview_id": preview["preview_id"], "revision": 1,
                "approval_command": command, "approver_claim": "human",
            })
            authority_payload = {
                "preview_id": preview["preview_id"], "revision": 1,
                "approval_id": approval.structured_content["approval_id"],
            }
            first = self._call(server, "delivery_issue_application_authority", authority_payload)
            second = self._call(server, "delivery_issue_application_authority", authority_payload)
            self.assertFalse(first.is_error)
            self.assertEqual(set(first.structured_content), AUTHORITY_FIELDS)
            self.assertEqual(first.structured_content, second.structured_content)
            for field in ("authority_id", "issued_at", "expires_at", "credential_binding_id"):
                self.assertEqual(first.structured_content[field], second.structured_content[field])
            self.assertEqual(first.structured_content["required_capabilities"], ["issues:write"])
            self.assertEqual(first.structured_content["granted_capabilities"], ["issues:write"])
            self.assertIsInstance(first.structured_content["required_capabilities"], list)
            self.assertIsInstance(first.structured_content["granted_capabilities"], list)
            self.assertEqual(len(service._authorities), 1)

            wrong = self._call(server, "delivery_issue_application_authority", {
                **authority_payload, "approval_id": "approval-wrong",
            })
            self.assertTrue(wrong.is_error)
            self.assertIn("approval_binding_mismatch", str(wrong.content))

        finally:
            directory.cleanup()

    def test_authority_mcp_missing_required_capability_propagates(self):
        directory, context, store, preview, audit, service = self._setup(with_attestation=True)
        try:
            server = create_server(context, store, approval_authority_service=service)
            command = f"批准写入 {preview['preview_id']} 1"
            approval = self._call(server, "delivery_record_approval", {
                "preview_id": preview["preview_id"], "revision": 1,
                "approval_command": command, "approver_claim": "human",
            })
            service.attestation_service._RuntimeAttestationOrchestrationService__resolver = FakeCapabilityResolver(("issues:read",))
            result = self._call(server, "delivery_issue_application_authority", {
                "preview_id": preview["preview_id"], "revision": 1,
                "approval_id": approval.structured_content["approval_id"],
            })
            self.assertTrue(result.is_error)
            self.assertIn("credential_capability_insufficient", str(result.content))
        finally:
            directory.cleanup()

    def test_authority_mcp_granted_capability_and_expiry_fail_closed(self):
        directory, context, store, preview, audit, service = self._setup(with_attestation=True)
        try:
            server = create_server(context, store, approval_authority_service=service)
            command = f"批准写入 {preview['preview_id']} 1"
            approval = self._call(server, "delivery_record_approval", {
                "preview_id": preview["preview_id"], "revision": 1,
                "approval_command": command, "approver_claim": "human",
            })
            payload = {"preview_id": preview["preview_id"], "revision": 1,
                       "approval_id": approval.structured_content["approval_id"]}
            original = service.attestation_service.resolve_registered_binding

            def without_grant(binding_id):
                binding = original(binding_id)
                object.__setattr__(binding, "granted_capabilities", ())
                return binding

            with patch.object(service.attestation_service, "resolve_registered_binding", side_effect=without_grant):
                missing_grant = self._call(server, "delivery_issue_application_authority", payload)
            self.assertTrue(missing_grant.is_error)
            self.assertIn("credential_capability_insufficient", str(missing_grant.content))
        finally:
            directory.cleanup()

        directory, context, store, preview, audit, service = self._setup(with_attestation=True)
        try:
            server = create_server(context, store, approval_authority_service=service)
            command = f"批准写入 {preview['preview_id']} 1"
            approval = self._call(server, "delivery_record_approval", {
                "preview_id": preview["preview_id"], "revision": 1,
                "approval_command": command, "approver_claim": "human",
            })
            service.clock = lambda: datetime(2026, 8, 14, 13, 0, tzinfo=timezone.utc)
            expired = self._call(server, "delivery_issue_application_authority", {
                "preview_id": preview["preview_id"], "revision": 1,
                "approval_id": approval.structured_content["approval_id"],
            })
            self.assertTrue(expired.is_error)
            self.assertIn("credential_binding_mismatch", str(expired.content))
        finally:
            directory.cleanup()

    def test_create_server_injected_service_and_partial_boundaries_fail_closed(self):
        directory, context, store, preview, audit, service = self._setup(with_attestation=False)
        try:
            self.assertIsNotNone(create_server(context, store, approval_authority_service=service))
            other_directory = tempfile.TemporaryDirectory()
            try:
                other_context = RuntimeContext.from_workspace_root(other_directory.name)
                other_store = InMemoryPreviewStore(other_context.workspace_identity, TRUST)
                with self.assertRaisesRegex(ValueError, "^approval_runtime_boundary_invalid$"):
                    create_server(other_context, store, approval_authority_service=service)
                with self.assertRaisesRegex(ValueError, "^approval_runtime_boundary_invalid$"):
                    create_server(context, other_store, approval_authority_service=service)
            finally:
                other_directory.cleanup()
            with self.assertRaisesRegex(ValueError, "^approval_runtime_boundary_invalid$"):
                create_server(context, store, approval_authority_service=object())
        finally:
            directory.cleanup()

        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore(context.workspace_identity, TRUST)
            for server in (create_server(context=context), create_server(store=store), create_server()):
                result = self._call(server, "delivery_record_approval", {
                    "preview_id": "preview", "revision": 1,
                    "approval_command": "command", "approver_claim": "human",
                })
                self.assertTrue(result.is_error)
                self.assertIn("workspace_identity_unavailable", str(result.content))

    def test_authority_without_attestation_fails_closed(self):
        directory, context, store, preview, audit, service = self._setup(with_attestation=False)
        try:
            server = create_server(context, store, approval_authority_service=service)

            async def exercise():
                async with Client(server, raise_exceptions=False) as client:
                    return await client.call_tool("delivery_issue_application_authority", {
                        "payload": {"preview_id": preview["preview_id"], "revision": 1, "approval_id": "approval-missing"},
                    })
            result = self.run_async(exercise())
            self.assertTrue(result.is_error)
            self.assertIn("attestation_service_unavailable", str(result.content))
        finally:
            directory.cleanup()

    def test_stdio_bootstrap_exposes_five_tools_without_credential_fabrication(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory).resolve()
            (workspace / ".gitignore").write_text(".delivery-system/\n", encoding="utf-8")
            subprocess.run(["git", "init", "--quiet"], cwd=workspace, check=True, capture_output=True, text=True)
            params = StdioServerParameters(
                command=os.fspath(Path(sys.executable)),
                args=["-m", "mcp_server.server", "--workspace-root", str(workspace)],
                cwd=Path(__file__).parents[2].resolve(),
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )

            async def exercise():
                async with Client(stdio_client(params), raise_exceptions=False) as client:
                    tools = await client.list_tools()
                    result = await client.call_tool("delivery_issue_application_authority", {
                        "payload": {"preview_id": "preview", "revision": 1, "approval_id": "approval"},
                    })
                    return tools, result

            tools, result = self.run_async(exercise())
            self.assertEqual(len(tools.tools), 6)
            self.assertTrue(result.is_error)
            self.assertIn("attestation_service_unavailable", str(result.content))


if __name__ == "__main__":
    unittest.main()
