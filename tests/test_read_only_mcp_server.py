"""Protocol tests for the dedicated three-tool read-only MCP factory."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp import Client
from mcp.shared.exceptions import MCPError

from delivery_system.public_error_contract import INTERNAL_ERROR_CODE
from delivery_system.read_only_composition import ReadOnlyComposition
from mcp_server import read_only_contracts as contracts
from mcp_server.read_only_server import create_read_only_server
from tests import test_read_only_projections as fixtures


READ_ONLY_TOOLS = {
    "delivery_get_audit_context",
    "delivery_get_approval_status",
    "delivery_get_application_status",
}
LEGACY_TOOLS = {
    "delivery_plan_preview", "delivery_get_audit_context", "delivery_record_audit",
    "delivery_record_approval", "delivery_get_approval_status",
    "delivery_get_application_status", "delivery_issue_application_authority",
    "delivery_apply_approved_work_items", "delivery_observe_application_postcondition",
}


@unittest.skipUnless(os.name == "posix" and Path("/proc/self/fd").is_dir(), "Linux proc fd required")
class ReadOnlyMCPServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = fixtures.ReadOnlyProjectionTests(
            "test_conceptual_audit_context_needs_no_driver_or_policy"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.composition = ReadOnlyComposition.open(
            self.fixture.bundle,
            expected_workspace_identity=self.fixture.context.workspace_identity,
            expected_release_id=fixtures.RELEASE,
        )
        self.addCleanup(self.composition.close)
        self.server = create_read_only_server(self.composition)

    @staticmethod
    def run_async(coroutine):
        return asyncio.run(coroutine)

    def test_discovery_is_exact_and_excluded_calls_are_unavailable(self) -> None:
        async def exercise():
            async with Client(self.server) as client:
                names = {tool.name for tool in (await client.list_tools()).tools}
                excluded = sorted(LEGACY_TOOLS - READ_ONLY_TOOLS)
                unavailable = []
                for name in excluded:
                    try:
                        result = await client.call_tool(name, {})
                    except MCPError:
                        unavailable.append(True)
                    else:
                        unavailable.append(result.is_error)
                return names, unavailable

        names, unavailable = self.run_async(exercise())
        self.assertEqual(names, READ_ONLY_TOOLS)
        self.assertEqual(len(names), 3)
        self.assertTrue(all(unavailable))

    def test_each_tool_delegates_and_preserves_structured_outputs(self) -> None:
        audit = {
            "context_status": "audit_ready", "workspace_identity": "ws-source",
            "preview_id": "preview-1", "revision": 1, "sealed_preview": {},
            "evidence_records": [], "audit_context_digest": "sha256:" + "a" * 64,
            "audit_scope": "Conceptual", "semantic_rule_contexts": [],
        }
        approval = {
            "status": "NO_CURRENT_APPROVAL", "preview_id": "preview-1",
            "revision": 1, "approval": None,
        }
        application = {
            "application_id": "application-" + "1" * 64, "preview_id": "preview-1",
            "revision": 1, "operation_set_digest": "sha256:" + "b" * 64,
            "state": "Pending", "next_operation_index": 0,
            "completed_operation_count": 0, "total_operation_count": 0,
            "attempt_count": 0, "recovery_code": None, "application_receipt": None,
            "operation_receipts": [], "attempts": [], "started_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z", "completed_at": None,
            "integrity_status": "verified",
        }
        with patch.object(self.composition, "get_audit_context", return_value=audit) as get_audit, \
             patch.object(self.composition, "get_approval_status", return_value=approval) as get_approval, \
             patch.object(self.composition, "get_application_status", return_value=application) as get_app, \
             patch.object(self.composition, "get_application_status_by_approved_context",
                          return_value=application) as get_context:
            async def exercise():
                async with Client(self.server, raise_exceptions=True) as client:
                    audit_result = await client.call_tool(
                        "delivery_get_audit_context",
                        {"payload": {"preview_id": "preview-1", "revision": 1}},
                    )
                    approval_result = await client.call_tool(
                        "delivery_get_approval_status",
                        {"payload": {"preview_id": "preview-1", "revision": 1}},
                    )
                    app_by_id = await client.call_tool(
                        "delivery_get_application_status",
                        {"payload": {"application_id": application["application_id"]}},
                    )
                    app_by_context = await client.call_tool(
                        "delivery_get_application_status",
                        {"payload": {"preview_id": "preview-1", "revision": 1,
                                     "approval_id": "approval-1", "approval_digest": "sha256:" + "c" * 64}},
                    )
                    return audit_result, approval_result, app_by_id, app_by_context

            audit_result, approval_result, app_by_id, app_by_context = self.run_async(exercise())

        get_audit.assert_called_once_with("preview-1", 1)
        get_approval.assert_called_once_with("preview-1", 1)
        get_app.assert_called_once_with(application["application_id"])
        get_context.assert_called_once_with("preview-1", 1, "approval-1", "sha256:" + "c" * 64)
        self.assertEqual(audit_result.structured_content["context_status"], "audit_ready")
        self.assertEqual(approval_result.structured_content["status"], "NO_CURRENT_APPROVAL")
        self.assertEqual(app_by_id.structured_content["state"], "Pending")
        self.assertEqual(app_by_context.structured_content["state"], "Pending")

    def test_projection_errors_and_closed_composition_use_safe_mapping(self) -> None:
        with patch.object(self.composition, "get_audit_context",
                          side_effect=ValueError("preview_stale")):
            async def failing_call():
                async with Client(self.server) as client:
                    return await client.call_tool(
                        "delivery_get_audit_context",
                        {"payload": {"preview_id": "preview-1", "revision": 1}},
                    )
            failed = self.run_async(failing_call())
        self.assertTrue(failed.is_error)
        self.assertEqual(failed.meta["com.delivery-system/public-tool-error"]["code"], "preview_stale")
        self.assertIsNone(failed.structured_content)

        self.composition.close()

        async def closed_call():
            async with Client(self.server) as client:
                return await client.call_tool(
                    "delivery_get_audit_context",
                    {"payload": {"preview_id": "preview-1", "revision": 1}},
                )
        closed = self.run_async(closed_call())
        self.assertTrue(closed.is_error)
        self.assertEqual(
            closed.meta["com.delivery-system/public-tool-error"]["code"],
            INTERNAL_ERROR_CODE,
        )

    def test_existing_schema_imports_are_reexported_without_schema_drift(self) -> None:
        from mcp_server import server as legacy

        for name in (
            "AuditContextInput", "AuditContextOutput", "ApprovalStatusInput",
            "ApprovalStatusOutput", "GetApplicationStatusInput", "ApplicationStatusOutput",
        ):
            self.assertIs(getattr(legacy, name), getattr(contracts, name))
        self.assertEqual(
            contracts.GetApplicationStatusInput.model_json_schema(),
            legacy.GetApplicationStatusInput.model_json_schema(),
        )
        self.assertEqual(
            contracts.ApplicationStatusOutput.model_json_schema(),
            legacy.ApplicationStatusOutput.model_json_schema(),
        )

    def test_legacy_factory_keeps_nine_tool_inventory(self) -> None:
        from mcp_server.server import create_server

        legacy = create_server()

        async def exercise():
            async with Client(legacy) as client:
                return {tool.name for tool in (await client.list_tools()).tools}

        self.assertEqual(self.run_async(exercise()), LEGACY_TOOLS)

    def test_read_only_import_does_not_load_legacy_server(self) -> None:
        script = (
            "import sys; import mcp_server.read_only_contracts; "
            "import mcp_server.read_only_server; "
            "assert 'mcp_server.server' not in sys.modules"
        )
        result = subprocess.run(
            [sys.executable, "-B", "-c", script], capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
