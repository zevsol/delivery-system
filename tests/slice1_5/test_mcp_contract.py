import asyncio
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest

from mcp import Client, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import ValidationError

from delivery_system.runtime import InMemoryPreviewStore, RuntimeContext, RuntimePlanner
from mcp_server.server import (
    PlanDraftInput,
    PreviewRequestInput,
    create_server,
    mcp,
)


def sourced(value, source="user_asserted"):
    return {"value": value, "declared_source": source}


def plan_payload(repository_claim=None):
    item = {
        "client_ref": "inventory",
        "role": sourced("product_item", "model_proposed"),
        "title": sourced("Inventory batches"),
        "context_problem": sourced("Inventory lacks batch tracking"),
        "outcome": sourced("Users can trace batches"),
        "scope": sourced(["inventory"]),
        "non_goals": sourced(["billing"], "model_assumption"),
        "acceptance_criteria": sourced(["A batch can be recorded"]),
        "verification": sourced(["Unit test"], "model_proposed"),
        "required_capabilities": sourced(["issues"]),
        "write_metadata": sourced({}, "model_proposed"),
    }
    return {"repository_claim": repository_claim, "work_items": [item]}


class McpSdkContractTests(unittest.TestCase):
    def run_async(self, coroutine):
        return asyncio.run(coroutine)

    def test_input_schema_has_one_canonical_work_item_shape(self):
        parsed = PlanDraftInput.model_validate(plan_payload())
        self.assertEqual(parsed.work_items[0].client_ref, "inventory")
        with self.assertRaises(ValidationError):
            PlanDraftInput.model_validate({**plan_payload(), "title": "duplicate source"})
        with self.assertRaises(ValidationError):
            PlanDraftInput.model_validate({**plan_payload(), "work_items": [{**plan_payload()["work_items"][0], "item_id": "item-fake"}]})

    def test_in_memory_sdk_output_is_sealed_and_local_stateful(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            server = create_server(context, InMemoryPreviewStore())

            async def exercise():
                async with Client(server, raise_exceptions=True) as client:
                    tools = await client.list_tools()
                    result = await client.call_tool("delivery_plan_preview", {"payload": {"plan": plan_payload()}})
                    return tools, result

            tools, result = self.run_async(exercise())
            self.assertEqual({tool.name for tool in tools.tools}, {"delivery_plan_preview", "delivery_get_audit_context", "delivery_record_audit"})
            self.assertFalse(result.is_error)
            self.assertEqual(result.structured_content["provenance_status"], "declared_unverified")
            self.assertFalse(result.structured_content["write_eligible"])

    def test_repository_claim_without_driver_is_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            server = create_server(context, InMemoryPreviewStore())

            async def exercise():
                async with Client(server, raise_exceptions=True) as client:
                    return await client.call_tool("delivery_plan_preview", {"payload": {"plan": plan_payload({"owner": "o", "name": "r"})}})

            result = self.run_async(exercise())
            self.assertIn("driver_unavailable", result.structured_content["blockers"])

    def test_preview_lineage_inherits_request_and_item_id_from_store(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore()
            service = RuntimePlanner(context, store)
            first = service.preview(plan_payload())
            changed = plan_payload()
            changed["work_items"][0]["client_ref"] = "inventory-v2"
            changed["work_items"][0]["previous_client_ref"] = "inventory"
            second = service.preview(changed, first["preview_id"])
            self.assertEqual(second["preview_id"], first["preview_id"])
            self.assertEqual(second["request_id"], first["request_id"])
            self.assertEqual(second["revision"], 2)

    def test_tool_annotation_is_not_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            server = create_server(context, InMemoryPreviewStore())

            async def exercise():
                async with Client(server, raise_exceptions=True) as client:
                    return (await client.list_tools()).tools[0].annotations

            annotations = self.run_async(exercise())
            assert annotations is not None
            self.assertFalse(annotations.read_only_hint)
            self.assertFalse(annotations.destructive_hint)
            self.assertFalse(annotations.open_world_hint)

    def test_stdio_transport_uses_runtime_context_argument(self):
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
                    return await client.call_tool("delivery_plan_preview", {"payload": {"plan": plan_payload()}})

            result = self.run_async(exercise())
            self.assertFalse(result.is_error)
            self.assertTrue(result.structured_content["workspace_identity"].startswith("ws_v1_"))
            state_path = workspace / ".delivery-system" / "state.sqlite3"
            self.assertTrue(state_path.is_file())
            self.assertNotEqual(state_path.parent.parent, root / ".delivery-system")


if __name__ == "__main__":
    unittest.main()
