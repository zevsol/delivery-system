from __future__ import annotations

import asyncio
import copy
from contextlib import closing
import json
import sqlite3
import tempfile
import unittest

from mcp import Client

from delivery_system.auditor import FindingDraft, RuleEvaluationDraft, RuntimeAuditor
from delivery_system.audit_state import ApprovalRecord
from delivery_system.drivers.contract import DriverTrustContext
from delivery_system.protocol import digest
from delivery_system.rules import ResultClass, SemanticOutcome, build_registry_v1
from delivery_system.runtime import (
    AuditResult,
    InMemoryPreviewStore,
    RuntimeContext,
    RuntimePlanner,
    SQLitePreviewStore,
    _preview_is_approval_eligible,
)
from delivery_system.write_operations import (
    evaluate_write_operations,
    normalize_write_operations,
    operation_set_digest_payload,
)
from mcp_server.server import create_server
from tests.local_rest_offline.test_repository_aware_runtime import FixtureDriver, plan


TRUST = DriverTrustContext("fixture-driver", "offline://fixture", "fixture-v1")


def operation(kind: str, refs: list[str], depends_on: list[str] | None = None) -> dict[str, object]:
    return {"operation_kind": kind, "client_refs": refs, "depends_on": depends_on or []}


def items(*refs: str) -> list[dict[str, str]]:
    return [{"client_ref": ref, "item_id": f"item-{ref}"} for ref in refs]


class WriteOperationEvaluatorTests(unittest.TestCase):
    def test_valid_graph_is_deterministic_and_ordered(self):
        operations = [operation("create_issue", ["a"]), operation("create_issue", ["b"]), operation("add_dependency", ["a", "b"])]
        result = evaluate_write_operations(
            operations,
            items("a", "b"),
            {"planned_relationships": [{"kind": "planned_dependency", "from_client_ref": "a", "to_client_ref": "b"}]},
        )
        self.assertTrue(result.eligible)
        self.assertEqual(result.operations[0]["operation_kind"], "create_issue")
        self.assertEqual(result.operations[-1]["operation_kind"], "add_dependency")
        self.assertNotEqual(digest({"operation_intents": operations}), digest({"operation_intents": list(reversed(operations))}))

    def test_invalid_or_noneligible_operations_fail_closed(self):
        cases = (
            ([operation("unknown", ["a"])], "write_operation_kind_not_write_eligible"),
            ([operation("create_issue", ["unknown"])], "write_operation_unknown_client_ref"),
            ([operation("create_issue", ["a", "a"])], "write_operation_client_refs_duplicate"),
            ([operation("create_issue", ["a"], ["op-1"])], "write_operation_dependencies_unsupported"),
            ([operation("create_issue", ["a"]), operation("create_issue", ["a"])], "write_operation_duplicate_create_issue"),
            ([operation("verify_relationship", ["a"])], "write_operation_kind_not_write_eligible"),
            ([operation("create_issue", ["a"])], "write_operation_create_issue_incomplete"),
            ([operation("create_issue", ["a"]), operation("add_dependency", ["a", "b"])], "write_operation_relationship_unplanned"),
        )
        for operations, blocker in cases:
            with self.subTest(blocker=blocker):
                if blocker == "write_operation_client_refs_duplicate":
                    with self.assertRaisesRegex(ValueError, "^write_operation_client_refs_duplicate$"):
                        evaluate_write_operations(operations, items("a", "b"), {"planned_relationships": []})
                else:
                    result = evaluate_write_operations(operations, items("a", "b"), {"planned_relationships": []})
                    self.assertFalse(result.eligible)
                    self.assertIn(blocker, result.blockers)

    def test_extra_fields_are_rejected_and_relationship_direction_is_exact(self):
        with self.assertRaisesRegex(ValueError, "^write_operation_shape_invalid$"):
            evaluate_write_operations(
                [{**operation("create_issue", ["a"]), "id": "provider-id"}],
                items("a"), {"planned_relationships": []},
            )
        result = evaluate_write_operations(
            [operation("create_issue", ["a"]), operation("create_issue", ["b"]), operation("add_dependency", ["b", "a"])],
            items("a", "b"),
            {"planned_relationships": [{"kind": "planned_dependency", "from_client_ref": "a", "to_client_ref": "b"}]},
        )
        self.assertFalse(result.eligible)
        self.assertIn("write_operation_relationship_incomplete", result.blockers)

    def test_planning_digest_preserves_only_historical_identity_noise(self):
        base = [operation("create_issue", ["a"])]
        with_ids = [{**base[0], "id": "provider-id", "operation_id": "host-id"}]
        self.assertEqual(
            operation_set_digest_payload(base), operation_set_digest_payload(with_ids)
        )
        with_extra = [{**base[0], "provider_payload": {"title": "unsafe"}}]
        self.assertNotEqual(
            operation_set_digest_payload(base), operation_set_digest_payload(with_extra)
        )
        for candidate in (with_ids, with_extra):
            with self.subTest(candidate=candidate):
                with self.assertRaisesRegex(ValueError, "^write_operation_shape_invalid$"):
                    normalize_write_operations(candidate)

    def test_missing_depends_on_key_never_becomes_write_eligible(self):
        candidate = {"operation_kind": "create_issue", "client_refs": ["a"]}
        with self.assertRaisesRegex(ValueError, "^write_operation_shape_invalid$"):
            evaluate_write_operations([candidate], items("a"), {"planned_relationships": []})

    def test_non_write_planning_kind_is_not_write_eligible(self):
        result = evaluate_write_operations(
            [operation("verify_relationship", ["a"])], items("a"), {"planned_relationships": []}
        )
        self.assertFalse(result.eligible)


class WriteEligibilityRuntimeTests(unittest.TestCase):
    def test_preview_levels_and_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            conceptual = RuntimePlanner(context, InMemoryPreviewStore()).preview(plan())
            self.assertEqual(conceptual["preview_level"], "Conceptual")
            repository_store = InMemoryPreviewStore(context.workspace_identity, TRUST)
            repository_aware = RuntimePlanner(context, repository_store, FixtureDriver(), TRUST).preview(plan())
            self.assertEqual(repository_aware["preview_level"], "RepositoryAware")
            self.assertFalse(repository_aware["write_eligible"])

            valid_plan = copy.deepcopy(plan())
            valid_plan["operation_intents"] = [operation("create_issue", ["item"])]
            store = InMemoryPreviewStore(context.workspace_identity, TRUST)
            eligible = RuntimePlanner(context, store, FixtureDriver(), TRUST).preview(valid_plan)
            self.assertEqual(eligible["preview_level"], "WriteEligible")
            self.assertTrue(eligible["write_eligible"])
            repeated = RuntimePlanner(context, store, FixtureDriver(), TRUST).preview(valid_plan, eligible["preview_id"])
            self.assertTrue(repeated["write_eligible"])

            repository_stored = repository_store.get_preview(context.workspace_identity, repository_aware["preview_id"])
            tampered_level = {**repository_stored, "canonical_payload": {**repository_stored["canonical_payload"], "preview_level": "WriteEligible"}}
            self.assertFalse(_preview_is_approval_eligible(tampered_level))
            stored = store.get_preview(context.workspace_identity, eligible["preview_id"])
            tampered_operations = copy.deepcopy(stored)
            tampered_operations["canonical_payload"]["operation_intents"] = [operation("create_issue", ["other"])]
            self.assertFalse(_preview_is_approval_eligible(tampered_operations))

    def _passed_audit(self, context: RuntimeContext, store, preview):
        auditor = RuntimeAuditor(context, store, build_registry_v1(), TRUST)
        audit_context = auditor.get_context(preview["preview_id"], preview["revision"])
        evaluations = [
            RuleEvaluationDraft(rule["rule_id"], rule["rule_version"], SemanticOutcome.PASSED, "verified")
            for rule in audit_context["semantic_rule_contexts"] if rule["applicability"] == "Applicable"
        ]
        return auditor.record_audit(preview["preview_id"], preview["revision"], audit_context["audit_context_digest"], evaluations, [])

    def test_passed_write_eligible_audit_and_approval_parity(self):
        for kind in ("memory", "sqlite"):
            with self.subTest(store=kind), tempfile.TemporaryDirectory() as directory:
                context = RuntimeContext.from_workspace_root(directory)
                store = (InMemoryPreviewStore(context.workspace_identity, TRUST) if kind == "memory" else
                         SQLitePreviewStore(context, trust_context=TRUST, ignore_checker=lambda _: True, tracked_checker=lambda _: False))
                valid_plan = copy.deepcopy(plan())
                valid_plan["operation_intents"] = [operation("create_issue", ["item"])]
                preview = RuntimePlanner(context, store, FixtureDriver(), TRUST).preview(valid_plan)
                audit = self._passed_audit(context, store, preview)
                self.assertEqual(audit.result, AuditResult.PASSED)
                self.assertTrue(audit.approval_eligible)
                approval = ApprovalRecord.create(
                    "approval-1", audit, "owner/repo", "human-1", "2026-09-01T00:00:00+00:00",
                    f"批准写入 {preview['preview_id']} {preview['revision']}",
                )
                store.record_approval(approval)
                retrieved = store.get_approval(context.workspace_identity, "approval-1")
                self.assertTrue(store.validate_approval_current(retrieved))

    def test_formal_approval_rejects_stale_and_binding_mismatches(self):
        for kind in ("memory", "sqlite"):
            with self.subTest(store=kind), tempfile.TemporaryDirectory() as directory:
                context = RuntimeContext.from_workspace_root(directory)
                store = (InMemoryPreviewStore(context.workspace_identity, TRUST) if kind == "memory" else
                         SQLitePreviewStore(context, trust_context=TRUST, ignore_checker=lambda _: True, tracked_checker=lambda _: False))
                valid_plan = copy.deepcopy(plan())
                valid_plan["operation_intents"] = [operation("create_issue", ["item"])]
                preview = RuntimePlanner(context, store, FixtureDriver(), TRUST).preview(valid_plan)
                audit = self._passed_audit(context, store, preview)
                command = f"批准写入 {preview['preview_id']} {preview['revision']}"

                for field, value in (("audit_digest", "sha256:bad"), ("operation_set_digest", "sha256:bad"), ("repository_identity", "other/repo")):
                    candidate = ApprovalRecord.create("approval-" + field, audit, "owner/repo", "human-1", "2026-09-01T00:00:00+00:00", command)
                    candidate = candidate.__class__(**{**candidate.to_dict(), field: value})
                    with self.subTest(field=field), self.assertRaises(ValueError):
                        store.record_approval(candidate)

                stale = ApprovalRecord.create("approval-stale", audit, "owner/repo", "human-1", "2026-09-01T00:00:00+00:00", command)
                changed_plan = copy.deepcopy(valid_plan)
                changed_plan["operation_intents"] = []
                RuntimePlanner(context, store, FixtureDriver(), TRUST).preview(changed_plan, preview["preview_id"])
                with self.assertRaises(ValueError):
                    store.record_approval(stale)

    def test_approval_rejects_current_preview_with_tampered_sealed_item(self):
        for kind in ("memory", "sqlite"):
            with self.subTest(store=kind), tempfile.TemporaryDirectory() as directory:
                context = RuntimeContext.from_workspace_root(directory)
                store = (InMemoryPreviewStore(context.workspace_identity, TRUST) if kind == "memory" else
                         SQLitePreviewStore(context, trust_context=TRUST, ignore_checker=lambda _: True, tracked_checker=lambda _: False))
                valid_plan = copy.deepcopy(plan())
                valid_plan["operation_intents"] = [operation("create_issue", ["item"])]
                preview = RuntimePlanner(context, store, FixtureDriver(), TRUST).preview(valid_plan)
                audit = self._passed_audit(context, store, preview)
                approval = ApprovalRecord.create(
                    "approval-tamper", audit, "owner/repo", "human-1", "2026-09-01T00:00:00+00:00",
                    f"批准写入 {preview['preview_id']} {preview['revision']}",
                )
                tampered = copy.deepcopy(store.get_preview(context.workspace_identity, preview["preview_id"]))
                tampered["canonical_payload"]["items"][0]["item_id"] = "item-tampered"
                tampered["canonical_payload"]["sealed_preview_digest"] = digest({
                    key: value for key, value in tampered["canonical_payload"].items()
                    if key != "sealed_preview_digest"
                })
                if kind == "memory":
                    store._previews[(context.workspace_identity, preview["preview_id"])] = tampered
                    store._preview_history[(context.workspace_identity, preview["preview_id"], 1)] = tampered
                else:
                    with closing(sqlite3.connect(store.path)) as connection:
                        connection.execute(
                            "UPDATE records SET payload=? WHERE workspace_identity=? AND record_type='preview' AND record_id=? AND revision=1",
                            (json.dumps(tampered, sort_keys=True), context.workspace_identity, preview["preview_id"]),
                        )
                        connection.commit()
                self.assertFalse(store.validate_approval_current(approval))
                with self.assertRaises(ValueError):
                    store.record_approval(approval)

    def test_non_write_eligible_audit_cannot_grant_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore(context.workspace_identity, TRUST)
            preview = RuntimePlanner(context, store, FixtureDriver(), TRUST).preview(plan())
            audit = self._passed_audit(context, store, preview)
            approval = ApprovalRecord.create(
                "approval-nonwrite", audit, "owner/repo", "human-1", "2026-09-01T00:00:00+00:00",
                f"批准写入 {preview['preview_id']} {preview['revision']}",
            )
            self.assertFalse(store.validate_approval_current(approval))

    def test_nonpassed_audit_is_not_approval_eligible(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore(context.workspace_identity, TRUST)
            valid_plan = copy.deepcopy(plan())
            valid_plan["operation_intents"] = [operation("create_issue", ["item"])]
            preview = RuntimePlanner(context, store, FixtureDriver(), TRUST).preview(valid_plan)
            auditor = RuntimeAuditor(context, store, build_registry_v1(), TRUST)
            audit_context = auditor.get_context(preview["preview_id"], preview["revision"])
            evaluations = [
                RuleEvaluationDraft(rule["rule_id"], rule["rule_version"], SemanticOutcome.FAILED, "failed", ("finding-1",))
                if rule["applicability"] == "Applicable" and rule["rule_id"] == "SEM-WORK-ITEM-COMPLETENESS" else
                RuleEvaluationDraft(rule["rule_id"], rule["rule_version"], SemanticOutcome.PASSED, "verified")
                for rule in audit_context["semantic_rule_contexts"] if rule["applicability"] == "Applicable"
            ]
            finding = FindingDraft(
                "finding-1", "SEM-WORK-ITEM-COMPLETENESS", ResultClass.WORK_ITEM_CONTENT_GAP, "High",
                "failed", "failed", (), (preview["items"][0]["item_id"],), "correct", None,
            )
            self.assertEqual(auditor.record_audit(preview["preview_id"], 1, audit_context["audit_context_digest"], evaluations, [finding]).approval_eligible, False)

    def test_existing_mcp_tools_surface_true_booleans_without_new_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore(context.workspace_identity, TRUST)
            valid_plan = copy.deepcopy(plan())
            valid_plan["operation_intents"] = [operation("create_issue", ["item"])]
            server = create_server(context, store, FixtureDriver(), TRUST)

            async def exercise():
                async with Client(server, raise_exceptions=True) as client:
                    preview = await client.call_tool("delivery_plan_preview", {"payload": {"plan": valid_plan}})
                    context_result = await client.call_tool("delivery_get_audit_context", {"payload": {"preview_id": preview.structured_content["preview_id"], "revision": 1}})
                    evaluations = [{"rule_id": rule["rule_id"], "rule_version": rule["rule_version"], "outcome": "Passed", "rationale": "verified"} for rule in context_result.structured_content["semantic_rule_contexts"] if rule["applicability"] == "Applicable"]
                    audit = await client.call_tool("delivery_record_audit", {"payload": {"preview_id": preview.structured_content["preview_id"], "revision": 1, "expected_audit_context_digest": context_result.structured_content["audit_context_digest"], "semantic_evaluations": evaluations, "finding_drafts": []}})
                    return preview, audit, await client.list_tools()

            preview, audit, tools = asyncio.run(exercise())
            self.assertTrue(preview.structured_content["write_eligible"])
            self.assertTrue(audit.structured_content["approval_eligible"])
            self.assertEqual({tool.name for tool in tools.tools}, {
                "delivery_plan_preview", "delivery_get_audit_context", "delivery_record_audit",
                "delivery_record_approval", "delivery_issue_application_authority",
            })


if __name__ == "__main__":
    unittest.main()
