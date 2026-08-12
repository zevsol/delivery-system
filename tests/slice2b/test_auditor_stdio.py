from __future__ import annotations

import asyncio
import os
from pathlib import Path
import sys
import tempfile
import unittest

from mcp import Client, StdioServerParameters
from mcp.client.stdio import stdio_client

from delivery_system.runtime import InMemoryPreviewStore, RuntimeContext
from mcp_server.server import create_server
from mcp_server.server import AuditContextInput
from pydantic import ValidationError


def sourced(value, source="user_asserted"):
    return {"value": value, "declared_source": source}


def plan_payload():
    return {"work_items": [{
        "client_ref": "inventory", "role": sourced("product_item", "model_proposed"),
        "title": sourced("Inventory batches"), "context_problem": sourced("Inventory lacks batch tracking"),
        "outcome": sourced("Users can trace batches"), "scope": sourced(["inventory"]),
        "non_goals": sourced(["billing"], "model_assumption"),
        "acceptance_criteria": sourced(["A batch can be recorded"]),
        "verification": sourced(["Unit test"], "model_proposed"),
        "required_capabilities": sourced(["issues"]), "write_metadata": sourced({}, "model_proposed"),
    }], "planned_relationships": [], "operation_intents": []}


class AuditorMcpContractTests(unittest.TestCase):
    def test_strict_revision_and_model_finding_id_inputs(self):
        with self.assertRaises(ValidationError):
            AuditContextInput.model_validate({"preview_id": "p", "revision": True})
        with self.assertRaises(ValidationError):
            AuditContextInput.model_validate({"preview_id": "p", "revision": "1"})
    def test_tool_list_contains_record_audit_and_context_is_structured(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            server = create_server(context, InMemoryPreviewStore())

            async def exercise():
                async with Client(server, raise_exceptions=True) as client:
                    return await client.list_tools()

            tools = asyncio.run(exercise())
            self.assertIn("delivery_record_audit", {tool.name for tool in tools.tools})

    def test_record_audit_uses_structured_sdk_input_and_output(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            server = create_server(context, InMemoryPreviewStore())

            async def exercise():
                async with Client(server, raise_exceptions=True) as client:
                    preview = await client.call_tool("delivery_plan_preview", {"payload": {"plan": plan_payload()}})
                    audit_context = await client.call_tool("delivery_get_audit_context", {"payload": {"preview_id": preview.structured_content["preview_id"], "revision": 1}})
                    evaluations = [
                        {"rule_id": rule["rule_id"], "rule_version": rule["rule_version"], "outcome": "Passed", "rationale": "meets contract"}
                        for rule in audit_context.structured_content["semantic_rule_contexts"]
                        if rule["applicability"] == "Applicable"
                    ]
                    audit = await client.call_tool("delivery_record_audit", {"payload": {
                        "preview_id": preview.structured_content["preview_id"], "revision": 1,
                        "expected_audit_context_digest": audit_context.structured_content["audit_context_digest"],
                        "semantic_evaluations": evaluations, "finding_drafts": [],
                    }})
                    return audit

            result = asyncio.run(exercise())
            self.assertFalse(result.is_error)
            self.assertEqual(result.structured_content["result"], "Passed")
            self.assertFalse(result.structured_content["approval_eligible"])

    def test_real_stdio_process_discovers_and_records_audit(self):
        root = Path(__file__).parents[2].resolve()
        params = StdioServerParameters(
            command=os.fspath(Path(sys.executable)),
            args=["-m", "mcp_server.server", "--workspace-root", str(root)],
            cwd=root,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )

        async def exercise():
            async with Client(stdio_client(params), raise_exceptions=True) as client:
                preview = await client.call_tool("delivery_plan_preview", {"payload": {"plan": plan_payload()}})
                context = await client.call_tool("delivery_get_audit_context", {"payload": {
                    "preview_id": preview.structured_content["preview_id"], "revision": preview.structured_content["revision"],
                }})
                evaluations = [
                    {"rule_id": rule["rule_id"], "rule_version": rule["rule_version"], "outcome": "Passed", "rationale": "stdio contract"}
                    for rule in context.structured_content["semantic_rule_contexts"]
                    if rule["applicability"] == "Applicable"
                ]
                return await client.call_tool("delivery_record_audit", {"payload": {
                    "preview_id": preview.structured_content["preview_id"],
                    "revision": preview.structured_content["revision"],
                    "expected_audit_context_digest": context.structured_content["audit_context_digest"],
                    "semantic_evaluations": evaluations,
                    "finding_drafts": [],
                }})

        result = asyncio.run(exercise())
        self.assertFalse(result.is_error)
        self.assertEqual(result.structured_content["result"], "Passed")
        self.assertFalse(result.structured_content["approval_eligible"])


if __name__ == "__main__":
    unittest.main()
