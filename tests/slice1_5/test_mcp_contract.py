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


def v1_plan_payload(repository_claim=None):
    sourced_fields = {
        "role": sourced("Integration Evidence"),
        "title": sourced("[Integration Evidence] V1-INT1 first live approved write"),
        "context_problem": sourced("The Delivery System V1 GitHub Issue write path has not yet been validated against a real personal repository."),
        "outcome": sourced("Validate one approved production-native create_issue mutation, durable receipts, and an independent remote postcondition."),
        "scope": sourced(["zevsol/delivery-system-integration-test"]),
        "non_goals": sourced([
            "Modify any existing Issue",
            "Create a second Issue",
            "Create sub-issue or dependency relationships",
            "Write to any other repository",
            "Automatic retry",
            "Automatic reconciliation",
            "Automatic cleanup",
        ]),
        "acceptance_criteria": sourced([
            "Exactly one create_issue operation is dispatched.",
            "The application reaches Applied.",
            "One immutable operation receipt and one immutable application receipt are persisted.",
            "An authenticated post-write read observes the returned Issue number with the exact approved title.",
            "No existing Issue or relationship is modified.",
            "The resulting Issue is retained as durable integration evidence.",
        ]),
        "verification": sourced([
            "ApplyResult.state is Applied and next_operation_index is 1.",
            "Operation and application receipt integrity validation succeeds.",
            "The returned Issue identity matches the definitive write observation.",
            "The post-write Issue set equals the pre-write set plus exactly one new Issue.",
        ]),
        "required_capabilities": sourced(["issues"]),
        "write_metadata": sourced({
            "automatic_cleanup": "PROHIBITED",
            "automatic_reconciliation": "PROHIBITED",
            "automatic_retry": "PROHIBITED",
            "delivery_system_source_head": "114e5e6d1a17b8000f406ba7b1677b9fcc076178",
            "maximum_github_mutations": 1,
            "operation": "create_issue",
            "relationship_operations": 0,
            "retention": "Retain the resulting Issue as durable integration evidence.",
            "target_repository": "zevsol/delivery-system-integration-test",
            "target_repository_id": "1333027111",
        }),
    }
    return {
        "repository_claim": repository_claim,
        "work_items": [{"client_ref": "h9-first-live-issue", **sourced_fields}],
        "planned_relationships": [],
        "operation_intents": [{
            "operation_kind": "create_issue",
            "client_refs": ["h9-first-live-issue"],
            "depends_on": [],
        }],
    }


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
            self.assertEqual({tool.name for tool in tools.tools}, {
                "delivery_plan_preview", "delivery_get_audit_context", "delivery_record_audit",
                "delivery_record_approval", "delivery_issue_application_authority",
                "delivery_apply_approved_work_items",
                "delivery_get_application_status",
                "delivery_observe_application_postcondition",
            })
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

    def _preview_via_mcp(self, repository_claim, payload_factory=plan_payload):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            server = create_server(context, InMemoryPreviewStore())

            async def exercise():
                async with Client(server, raise_exceptions=True) as client:
                    return await client.call_tool(
                        "delivery_plan_preview",
                        {"payload": {"plan": payload_factory(repository_claim)}},
                    )

            result = self.run_async(exercise())
            self.assertFalse(result.is_error)
            return result.structured_content

    def test_repository_claim_optional_url_matches_direct_runtime_semantics(self):
        repository_claim = {"owner": "o", "name": "r"}
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            direct = RuntimePlanner(context, InMemoryPreviewStore()).preview(plan_payload(repository_claim))
        mcp_preview = self._preview_via_mcp(repository_claim)
        self.assertEqual(mcp_preview["plan_digest"], direct["plan_digest"])
        self.assertEqual(mcp_preview["semantic_payload"]["repository_claim"], repository_claim)
        self.assertNotIn("url", mcp_preview["semantic_payload"]["repository_claim"])

    def test_omitted_and_explicit_null_repository_url_are_semantically_equal(self):
        omitted = self._preview_via_mcp({"owner": "o", "name": "r"})
        explicit_null = self._preview_via_mcp({"owner": "o", "name": "r", "url": None})
        self.assertEqual(
            omitted["semantic_payload"]["repository_claim"],
            explicit_null["semantic_payload"]["repository_claim"],
        )
        self.assertEqual(omitted["plan_digest"], explicit_null["plan_digest"])
        self.assertEqual(omitted["operation_set_digest"], explicit_null["operation_set_digest"])

    def test_non_null_repository_url_is_preserved_in_runtime_semantics(self):
        url = "https://example.test/repository"
        preview = self._preview_via_mcp({"owner": "o", "name": "r", "url": url})
        self.assertEqual(preview["semantic_payload"]["repository_claim"]["url"], url)

    def test_historical_v1_plan_digest_excludes_omitted_repository_url(self):
        repository_claim = {"owner": "zevsol", "name": "delivery-system-integration-test"}
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            direct = RuntimePlanner(context, InMemoryPreviewStore()).preview(v1_plan_payload(repository_claim))
            legacy_mcp_shape = PreviewRequestInput.model_validate({"plan": v1_plan_payload(repository_claim)}).plan.model_dump()
            legacy = RuntimePlanner(context, InMemoryPreviewStore()).preview(legacy_mcp_shape)
        mcp_preview = self._preview_via_mcp(repository_claim, v1_plan_payload)
        self.assertEqual(direct["plan_digest"], "sha256:b41bb0da51873a284e61457c6eb3233bd57bed269095b8167b9bb58713f4bf80")
        self.assertEqual(mcp_preview["plan_digest"], direct["plan_digest"])
        self.assertEqual(legacy["plan_digest"], "sha256:d45f3d7ffa43625441faf863862d17c53f5bc1d97adffff54f301125643dba1f")
        self.assertEqual(direct["operation_set_digest"], "sha256:7fe09348ecc9d2f3354cb0ce8af48714d47e30a031d83b2ba3c8cc41127f815a")
        self.assertEqual(mcp_preview["operation_set_digest"], direct["operation_set_digest"])
        self.assertEqual(legacy["operation_set_digest"], direct["operation_set_digest"])

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
