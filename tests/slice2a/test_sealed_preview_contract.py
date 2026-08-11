import asyncio
import json
import sqlite3
from contextlib import closing
import tempfile
import unittest
from pathlib import Path

from mcp import Client

from delivery_system.protocol import canonical_payload, digest
from delivery_system.runtime import (
    ApprovalRecord,
    AuditRecord,
    AuditResult,
    DeclaredSource,
    EvidenceRecord,
    InMemoryPreviewStore,
    PreviewLevel,
    RuntimeContext,
    RuntimePlanner,
    TypedRemoteSnapshot,
    SQLitePreviewStore,
    AuditContextService,
    compute_audit_context_digest,
)
from mcp_server.server import create_server


def sourced(value, source="user_asserted"):
    return {"value": value, "declared_source": source}


def plan_payload(repository_claim=None):
    return {
        "repository_claim": repository_claim,
        "work_items": [{
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
        }],
        "planned_relationships": [],
        "operation_intents": [],
    }


class Slice2ASealedPreviewTests(unittest.TestCase):
    def test_planner_and_audit_context_use_identical_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore()
            result = RuntimePlanner(context, store).preview(plan_payload())
            context_result = AuditContextService(context, store).get(result["preview_id"], result["revision"])
            self.assertEqual(result["audit_context_digest"], context_result["audit_context_digest"])

    def test_audit_context_digest_is_order_independent_but_content_sensitive(self):
        records = [
            {"evidence_id": "ev-b", "evidence_digest": "d-b"},
            {"evidence_id": "ev-a", "evidence_digest": "d-a"},
        ]
        first = compute_audit_context_digest("ws", "p", 1, "sealed", records)
        reordered = compute_audit_context_digest("ws", "p", 1, "sealed", list(reversed(records)))
        changed = compute_audit_context_digest("ws", "p", 1, "sealed", [{**records[0], "evidence_digest": "changed"}, records[1]])
        self.assertEqual(first, reordered)
        self.assertNotEqual(first, changed)

    def test_operation_only_revision_increments_and_retry_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore()
            first_plan = plan_payload()
            first_plan["operation_intents"] = [{"operation_kind": "create_issue", "client_refs": ["inventory"], "depends_on": []}]
            second_plan = plan_payload()
            second_plan["operation_intents"] = [{"operation_kind": "verify_relationship", "client_refs": ["inventory"], "depends_on": []}]
            first = RuntimePlanner(context, store).preview(first_plan)
            second = RuntimePlanner(context, store).preview(second_plan, first["preview_id"])
            retry = RuntimePlanner(context, store).preview(second_plan, first["preview_id"])
            self.assertEqual(first["preview_id"], second["preview_id"])
            self.assertEqual(second["revision"], 2)
            self.assertEqual(retry["revision"], second["revision"])
            self.assertEqual(retry["operation_set_digest"], second["operation_set_digest"])
            self.assertEqual(store.get_preview_revision(context.workspace_identity, first["preview_id"], 1)["revision"], 1)

    def test_operation_order_is_canonical_semantics_not_display_noise(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore()
            first_plan = plan_payload()
            first_plan["operation_intents"] = [
                {"operation_kind": "create_issue", "client_refs": ["inventory"], "depends_on": []},
                {"operation_kind": "verify_relationship", "client_refs": ["inventory"], "depends_on": []},
            ]
            reordered_plan = plan_payload()
            reordered_plan["operation_intents"] = list(reversed(first_plan["operation_intents"]))
            first = RuntimePlanner(context, store).preview(first_plan)
            reordered = RuntimePlanner(context, store).preview(reordered_plan, first["preview_id"])
            self.assertEqual(reordered["preview_id"], first["preview_id"])
            self.assertEqual(reordered["revision"], 2)
            self.assertEqual(reordered["plan_digest"], first["plan_digest"])
            self.assertNotEqual(reordered["operation_set_digest"], first["operation_set_digest"])

    def test_sealed_preview_rejects_untrusted_provenance_and_invalid_types(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore()
            result = RuntimePlanner(context, store).preview(plan_payload())
            tampered = dict(store.get_preview(context.workspace_identity, result["preview_id"])["canonical_payload"])
            tampered["revision"] = 2
            tampered["provenance_status"] = "driver_verified"
            tampered["sealed_preview_digest"] = digest({key: value for key, value in tampered.items() if key != "sealed_preview_digest"})
            with self.assertRaisesRegex(ValueError, "^preview_provenance_invalid$"):
                store.save_preview_revision(result["request_id"], result["preview_id"], 2, result["plan_digest"], None, result["operation_set_digest"], None, tampered["items"], workspace_identity=context.workspace_identity, canonical_payload=tampered, evidence_records=[])
    def test_missing_canonical_payload_cannot_create_preview(self):
        store = InMemoryPreviewStore()
        with self.assertRaisesRegex(ValueError, "^sealed_preview_required$"):
            store.save_preview_revision("r", "p", 1, "plan", None, "ops", None, [], workspace_identity="ws")
        with self.assertRaises(ValueError):
            store.get_preview("ws", "p")
        with self.assertRaises(ValueError):
            store.get_evidence_records("ws", ["missing"])

    def test_legacy_default_cannot_pass_approval(self):
        store = InMemoryPreviewStore()
        legacy = {"workspace_identity": "ws", "request_id": "r", "preview_id": "p", "revision": 1}
        with self.assertRaisesRegex(ValueError, "^sealed_preview_schema_invalid$"):
            store.save_preview_revision("r", "p", 1, "plan", "remote", "ops", "repo", [], workspace_identity="ws", canonical_payload=legacy)

    def test_operation_change_does_not_change_plan_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            first_plan = plan_payload()
            first_plan["operation_intents"] = [{"operation_kind": "create_issue", "client_refs": ["inventory"], "depends_on": []}]
            second_plan = plan_payload()
            second_plan["operation_intents"] = [{"operation_kind": "verify_relationship", "client_refs": ["inventory"], "depends_on": []}]
            first = RuntimePlanner(context, InMemoryPreviewStore()).preview(first_plan)
            second = RuntimePlanner(context, InMemoryPreviewStore()).preview(second_plan)
            self.assertEqual(first["plan_digest"], second["plan_digest"])
            self.assertNotEqual(first["operation_set_digest"], second["operation_set_digest"])
            self.assertNotEqual(first["sealed_preview_digest"], second["sealed_preview_digest"])

    def test_public_evidence_factory_rejects_runtime_and_driver_sources(self):
        for source_kind in ("runtime", "driver"):
            with self.subTest(source_kind=source_kind):
                with self.assertRaisesRegex(ValueError, "^controlled_evidence_source$"):
                    EvidenceRecord.create("ws", "p", 1, "x", source_kind, None, "s", {})

    def test_declared_provenance_is_not_collapsed_to_user_asserted(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            plan = plan_payload()
            plan["work_items"][0]["title"] = sourced("system title", "model_proposed")
            plan["work_items"][0]["non_goals"] = sourced(["unknown"], "model_assumption")
            result = RuntimePlanner(context, InMemoryPreviewStore()).preview(plan)
            sources = {field: result["semantic_payload"]["work_items"][0][field]["declared_source"] for field in ("title", "non_goals")}
            self.assertEqual(sources, {"title": "model_proposed", "non_goals": "model_assumption"})

    def test_inmemory_read_isolation(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore()
            result = RuntimePlanner(context, store).preview(plan_payload())
            returned = store.get_preview(context.workspace_identity, result["preview_id"])
            returned["canonical_payload"]["semantic_payload"]["work_items"][0]["client_ref"] = "tampered"
            fresh = store.get_preview(context.workspace_identity, result["preview_id"])
            self.assertEqual(fresh["canonical_payload"]["semantic_payload"]["work_items"][0]["client_ref"], "inventory")
    def test_runtime_owns_one_sealed_preview_and_store_persists_full_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore()
            result = RuntimePlanner(context, store).preview(plan_payload())
            stored = store.get_preview(context.workspace_identity, result["preview_id"])
            self.assertEqual(result["preview_level"], PreviewLevel.CONCEPTUAL.value)
            self.assertIn("canonical_payload", stored)
            self.assertEqual(stored["canonical_payload"]["semantic_payload"], result["semantic_payload"])
            self.assertIn("planned_relationships", stored["canonical_payload"]["semantic_payload"])
            self.assertIn("operation_intents", stored["canonical_payload"])
            self.assertIn("sealed_preview_digest", result)

    def test_protocol_preview_is_only_runtime_compatibility_alias(self):
        from delivery_system.protocol import Preview
        from delivery_system.runtime import SealedPreview
        self.assertIs(Preview, SealedPreview)

    def test_plan_digest_excludes_record_identity_and_operation_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            first = RuntimePlanner(context, InMemoryPreviewStore()).preview(plan_payload())
            second = RuntimePlanner(context, InMemoryPreviewStore()).preview(plan_payload())
            self.assertEqual(first["plan_digest"], second["plan_digest"])
            self.assertEqual(first["operation_set_digest"], second["operation_set_digest"])

    def test_evidence_conditions_and_canonical_id_are_enforced(self):
        declared = EvidenceRecord.create(
            workspace_identity="ws", preview_id="p", revision=1,
            evidence_type="claim", source_kind="declared",
            declared_source=DeclaredSource.USER_ASSERTED,
            subject_ref="title", payload={"value": "Inventory"},
        )
        self.assertEqual(declared.verification_status, "declared_unverified")
        self.assertEqual(declared.evidence_id, EvidenceRecord.create(
            workspace_identity="ws", preview_id="p", revision=1,
            evidence_type="claim", source_kind="declared",
            declared_source=DeclaredSource.USER_ASSERTED,
            subject_ref="title", payload={"value": "Inventory"},
        ).evidence_id)
        with self.assertRaises(ValueError):
            EvidenceRecord.create("ws", "p", 1, "machine", "runtime", DeclaredSource.USER_ASSERTED, "x", {})
        with self.assertRaises(ValueError):
            EvidenceRecord.create("ws", "p", 1, "claim", "declared", None, "x", {})

    def test_typed_remote_snapshot_rejects_pull_request_as_issue(self):
        with self.assertRaises(ValueError):
            TypedRemoteSnapshot.from_records(
                repository_identity="owner/repo",
                query_scope={"state": "open"},
                query_complete=True,
                pagination_complete=True,
                issue_records=[{"issue_id": "1", "item_type": "pull_request", "title": "PR", "updated_at": "2026-01-01T00:00:00+00:00", "repository_identity": "owner/repo"}],
                permissions={"issues:write": True},
                capabilities=["issues"],
                relationship_records=[],
            )

    def test_remote_snapshot_digest_ignores_observed_at_but_binds_complete_fields(self):
        kwargs = dict(
            repository_identity="owner/repo", query_scope={"state": "open"},
            query_complete=True, pagination_complete=True,
            issue_records=[{"issue_id": "1", "item_type": "issue", "title": "Issue", "updated_at": "2026-01-01T00:00:00+00:00", "repository_identity": "owner/repo"}, {"issue_id": "2", "item_type": "issue", "title": "Other", "updated_at": "2026-01-01T00:00:00+00:00", "repository_identity": "owner/repo"}],
            permissions={"issues:read": True}, capabilities=["issues"],
            relationship_records=[{"kind": "existing_dependency", "from": "1", "to": "2"}],
        )
        first = TypedRemoteSnapshot.from_records(**kwargs, observed_at="2026-01-01T00:00:00+00:00")
        second = TypedRemoteSnapshot.from_records(**kwargs, observed_at="2026-01-02T00:00:00+00:00")
        self.assertEqual(first.digest(), second.digest())
        changed = TypedRemoteSnapshot.from_records(**{**kwargs, "permissions": {"issues:read": False}}, observed_at="2026-01-02T00:00:00+00:00")
        self.assertNotEqual(first.digest(), changed.digest())

    def test_sqlite_persists_canonical_payload_and_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False)
            result = RuntimePlanner(context, store).preview(plan_payload())
            stored = store.get_preview_revision(context.workspace_identity, result["preview_id"], result["revision"])
            self.assertEqual(stored["canonical_payload"]["sealed_preview_digest"], result["sealed_preview_digest"])
            self.assertEqual(store.get_evidence_records(context.workspace_identity, result["evidence_ids"])[0]["evidence_id"], result["evidence_ids"][0])

    def test_store_envelope_has_no_second_semantic_source(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore()
            result = RuntimePlanner(context, store).preview(plan_payload())
            envelope = store.get_preview(context.workspace_identity, result["preview_id"])
            self.assertEqual(set(envelope), {"request_id", "preview_id", "revision", "canonical_payload"})
            self.assertNotIn("plan_digest", envelope)
            self.assertNotIn("operation_set_digest", envelope)
            self.assertNotIn("items", envelope)
            self.assertNotIn("evidence_records", envelope)

    def test_sqlite_payload_tamper_is_detected_by_audit_context(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False)
            result = RuntimePlanner(context, store).preview(plan_payload())
            with closing(sqlite3.connect(context.state_path)) as connection:
                row = connection.execute(
                    "SELECT payload FROM records WHERE record_type='preview' AND record_id=? AND revision=?",
                    (result["preview_id"], result["revision"]),
                ).fetchone()
                envelope = json.loads(row[0])
                envelope["canonical_payload"]["semantic_payload"]["work_items"][0]["title"]["value"] = "tampered"
                connection.execute(
                    "UPDATE records SET payload=? WHERE record_type='preview' AND record_id=? AND revision=?",
                    (json.dumps(envelope, sort_keys=True), result["preview_id"], result["revision"]),
                )
                connection.commit()
            with self.assertRaisesRegex(ValueError, "^preview_digest_mismatch$"):
                from delivery_system.runtime import AuditContextService
                AuditContextService(context, store).get(result["preview_id"], result["revision"])

    def test_missing_evidence_blocks_audit_context(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore()
            result = RuntimePlanner(context, store).preview(plan_payload())
            store._evidence.clear()
            with self.assertRaisesRegex(ValueError, "^evidence_not_found$"):
                from delivery_system.runtime import AuditContextService
                AuditContextService(context, store).get(result["preview_id"], result["revision"])

    def test_evidence_payload_and_source_change_identity_and_digest(self):
        base = EvidenceRecord.create("ws", "p", 1, "claim", "declared", DeclaredSource.USER_ASSERTED, "title", {"value": "A"}, created_at="2026-01-01T00:00:00+00:00")
        later = EvidenceRecord.create("ws", "p", 1, "claim", "declared", DeclaredSource.USER_ASSERTED, "title", {"value": "A"}, created_at="2027-01-01T00:00:00+00:00")
        changed = EvidenceRecord.create("ws", "p", 1, "claim", "declared", DeclaredSource.MODEL_PROPOSED, "title", {"value": "A"})
        self.assertEqual(base.evidence_id, later.evidence_id)
        self.assertEqual(base.evidence_digest, later.evidence_digest)
        self.assertNotEqual(base.evidence_id, changed.evidence_id)
        self.assertNotEqual(base.evidence_digest, changed.evidence_digest)

    def test_legacy_preview_is_not_audit_context(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore()
            legacy = {"legacy": True, "request_id": "r", "preview_id": "legacy", "revision": 1}
            store._previews[(context.workspace_identity, "legacy")] = legacy
            store._preview_history[(context.workspace_identity, "legacy", 1)] = legacy
            self.assertNotIn("sealed_preview_digest", store.get_preview(context.workspace_identity, "legacy").get("canonical_payload", {}))

    def test_conceptual_preview_cannot_be_used_for_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore()
            result = RuntimePlanner(context, store).preview(plan_payload())
            audit = AuditRecord.create("audit", result["preview_id"], result["revision"], result["plan_digest"], "remote", result["operation_set_digest"], AuditResult.PASSED)
            store.record_audit(audit)
            approval = ApprovalRecord.create("approval", audit, "repo", "operator", "2026-08-11T00:00:00+00:00", f"批准写入 {result['preview_id']} {result['revision']}")
            with self.assertRaises(ValueError):
                store.record_approval(approval)

    def test_conceptual_preview_has_no_fake_remote_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            result = RuntimePlanner(context, InMemoryPreviewStore()).preview(
                plan_payload({"owner": "owner", "name": "repo"})
            )
            self.assertEqual(result["preview_level"], "Conceptual")
            self.assertIsNone(result["remote_snapshot"])
            self.assertIsNone(result["remote_snapshot_digest"])
            self.assertIn("driver_unavailable", result["blockers"])

    def test_audit_context_tool_returns_rules_unavailable_and_full_context_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore()
            preview = RuntimePlanner(context, store).preview(plan_payload())
            server = create_server(context, store)

            async def exercise():
                async with Client(server, raise_exceptions=True) as client:
                    tools = await client.list_tools()
                    result = await client.call_tool(
                        "delivery_get_audit_context",
                        {"payload": {"preview_id": preview["preview_id"], "revision": preview["revision"]}},
                    )
                    return tools, result

            tools, result = asyncio.run(exercise())
            self.assertEqual({tool.name for tool in tools.tools}, {"delivery_plan_preview", "delivery_get_audit_context"})
            self.assertFalse(result.is_error)
            self.assertEqual(result.structured_content["context_status"], "preview_ready_rules_unavailable")
            self.assertIsNone(result.structured_content["rule_registry_version"])
            self.assertIsNone(result.structured_content["rule_registry_digest"])
            self.assertIn("audit_context_digest", result.structured_content)


if __name__ == "__main__":
    unittest.main()
