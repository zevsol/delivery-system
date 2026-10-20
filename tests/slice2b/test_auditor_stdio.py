from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sqlite3
import sys
import subprocess
import tempfile
import unittest

from mcp import Client, StdioServerParameters
from mcp.client.stdio import stdio_client

from delivery_system.runtime import InMemoryPreviewStore, RuntimeContext, RuntimePlanner, SQLitePreviewStore
from mcp_server.server import AuditContextInput, create_server
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
        with tempfile.TemporaryDirectory() as directory:
            root = Path(__file__).parents[2].resolve()
            workspace = Path(directory).resolve()
            (workspace / ".gitignore").write_text(".delivery-system/\n", encoding="utf-8")
            subprocess.run(
                ["git", "init", "--quiet"],
                cwd=workspace,
                check=True,
                capture_output=True,
                text=True,
            )
            params = StdioServerParameters(
                command=os.fspath(Path(sys.executable)),
                args=["-m", "mcp_server.server", "--workspace-root", str(workspace)],
                cwd=root,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )

            async def exercise():
                async with Client(stdio_client(params), raise_exceptions=True) as client:
                    preview = await client.call_tool("delivery_plan_preview", {"payload": {"plan": plan_payload()}})
                    context = await client.call_tool("delivery_get_audit_context", {"payload": {
                        "preview_id": preview.structured_content["preview_id"], "revision": preview.structured_content["revision"],
                    }})
                    self.assertEqual(
                        preview.structured_content["audit_context_digest"],
                        context.structured_content["audit_context_digest"],
                    )
                    evaluations = [
                        {"rule_id": rule["rule_id"], "rule_version": rule["rule_version"], "outcome": "Passed", "rationale": "stdio contract"}
                        for rule in context.structured_content["semantic_rule_contexts"]
                        if rule["applicability"] == "Applicable"
                    ]
                    audit = await client.call_tool("delivery_record_audit", {"payload": {
                        "preview_id": preview.structured_content["preview_id"],
                        "revision": preview.structured_content["revision"],
                        "expected_audit_context_digest": context.structured_content["audit_context_digest"],
                        "semantic_evaluations": evaluations,
                        "finding_drafts": [],
                    }})
                    return audit, context.structured_content["audit_context_digest"]

            result, expected_context_digest = asyncio.run(exercise())
            self.assertFalse(result.is_error)
            self.assertEqual(result.structured_content["result"], "Passed")
            self.assertFalse(result.structured_content["approval_eligible"])

            state_path = workspace / ".delivery-system" / "state.sqlite3"
            self.assertTrue(state_path.is_file())
            self.assertNotEqual(state_path, root / ".delivery-system" / "state.sqlite3")
            workspace_identity = RuntimeContext.from_workspace_root(workspace).workspace_identity
            connection = sqlite3.connect(state_path)
            try:
                persisted_rows = connection.execute(
                    "SELECT payload FROM audit_history WHERE workspace_identity=? AND audit_id=?",
                    (workspace_identity, result.structured_content["audit_id"]),
                ).fetchall()
            finally:
                connection.close()
            self.assertEqual(len(persisted_rows), 1)
            persisted = json.loads(persisted_rows[0][0])
            self.assertEqual(persisted["audit_id"], result.structured_content["audit_id"])
            self.assertEqual(persisted["audit_context_digest"], expected_context_digest)
            self.assertEqual(persisted["audit_payload_digest"], result.structured_content["audit_payload_digest"])

    def test_sqlite_audit_write_failure_rolls_back_and_maps_to_safe_internal_error(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False)
            preview = RuntimePlanner(context, store).preview(plan_payload())
            server = create_server(context, store)

            connection = sqlite3.connect(store.path)
            try:
                connection.execute("""
                    CREATE TRIGGER fail_audit_history_insert
                    BEFORE INSERT ON audit_history
                    BEGIN SELECT RAISE(ABORT, 'sensitive test detail'); END
                """)
                connection.commit()
            finally:
                connection.close()

            async def exercise():
                async with Client(server) as client:
                    audit_context = await client.call_tool("delivery_get_audit_context", {"payload": {
                        "preview_id": preview["preview_id"], "revision": preview["revision"],
                    }})
                    evaluations = [
                        {"rule_id": rule["rule_id"], "rule_version": rule["rule_version"],
                         "outcome": "Passed", "rationale": "meets contract"}
                        for rule in audit_context.structured_content["semantic_rule_contexts"]
                        if rule["applicability"] == "Applicable"
                    ]
                    return await client.call_tool("delivery_record_audit", {"payload": {
                        "preview_id": preview["preview_id"], "revision": preview["revision"],
                        "expected_audit_context_digest": audit_context.structured_content["audit_context_digest"],
                        "semantic_evaluations": evaluations, "finding_drafts": [],
                    }})

            with self.assertLogs("mcp_server.read_only_contracts", level="ERROR") as captured:
                result = asyncio.run(exercise())
            self.assertTrue(result.is_error)
            self.assertEqual(result.meta["com.delivery-system/public-tool-error"]["code"], "internal_error")
            self.assertNotIn("sensitive test detail", result.content[0].text)
            log_output = "\n".join(captured.output)
            self.assertIn("request_id=", log_output)
            self.assertIn("sqlite3.IntegrityError", log_output)
            self.assertIn("audit_persistence_failed", log_output)
            self.assertIn("traceback_frames=", log_output)
            self.assertNotIn("sensitive test detail", log_output)
            self.assertNotIn("sensitive test detail", str(result.meta))

            connection = sqlite3.connect(store.path)
            try:
                persisted = connection.execute(
                    "SELECT COUNT(*) FROM audit_history WHERE workspace_identity=? AND payload LIKE ?",
                    (context.workspace_identity, f"%{preview['preview_id']}%"),
                ).fetchone()[0]
            finally:
                connection.close()
            self.assertEqual(persisted, 0)


if __name__ == "__main__":
    unittest.main()
