from __future__ import annotations

import tempfile
import unittest
import gc
import asyncio
import threading
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor

from delivery_system.auditor import RuleEvaluationDraft, RuntimeAuditor
from delivery_system.drivers.contract import DriverReadResponse, DriverTrustContext, RuntimeEvidenceBinding, ValidatedRemoteFacts
from delivery_system.drivers.preflight import bind_validated_facts, validate_driver_facts
import delivery_system.drivers.preflight as preflight_module
from delivery_system.protocol import digest
from delivery_system.rules import SemanticOutcome, build_registry_v1
from delivery_system.runtime import AuditResult, InMemoryPreviewStore, RuntimeContext, RuntimePlanner, RuntimePromotion, SQLitePreviewStore
from mcp import Client
from mcp_server.server import create_server


TRUST = DriverTrustContext("fixture-driver", "offline://fixture", "fixture-v1")


def plan():
    def s(value, source="user_asserted"):
        return {"value": value, "declared_source": source}
    return {"repository_claim": {"owner": "Owner", "name": "Repo"}, "work_items": [{
        "client_ref": "item", "role": s("Bug", "model_proposed"), "title": s("Existing bug"),
        "context_problem": s("Problem"), "outcome": s("Outcome", "model_proposed"), "scope": s(["repo"]),
        "non_goals": s([], "model_assumption"), "acceptance_criteria": s(["Works"]),
        "verification": s(["Test"], "model_proposed"), "required_capabilities": s(["issues"]),
        "write_metadata": s({}, "model_proposed"),
    }], "planned_relationships": [], "operation_intents": []}


class FixtureDriver:
    def __init__(self, title="Existing"):
        self.title = title

    def read_repository(self, repository, query_scope):
        issue = {"issue_id": "I1", "item_type": "issue", "title": self.title, "updated_at": "2026-08-13T00:00:00+00:00", "repository_identity": "owner/repo"}
        material = {"source_identity": TRUST.trusted_driver_identity, "repository_identity": "owner/repo", "query_scope": query_scope, "payload": {"issue_records": [issue], "relationship_records": []}}
        payload = {"requested_repository": repository, "canonical_repository": "owner/repo", "remote_repository_id": "R1", "authenticated_subject": "U1", "visibility": "private", "permissions": {"read": True, "write": False}, "capabilities": {"issues": True, "relationships": True}, "query_scope": dict(query_scope), "query_complete": True, "pagination_complete": True, "issue_records": [issue], "relationship_records": [], "evidence_material": [material], "source_identity": TRUST.trusted_driver_identity}
        return DriverReadResponse(**payload, remote_content_digest=digest(payload))


class CandidateReadBarrierStore:
    """Block only the two initial Revision-1 reads; winner reloads pass through."""

    def __init__(self, store, barrier):
        self._store = store
        self._barrier = barrier
        self.trust_context = store.trust_context
        self._candidate_reads = 0
        self._candidate_reads_lock = threading.Lock()

    def get_preview(self, workspace_identity, preview_id):
        preview = self._store.get_preview(workspace_identity, preview_id)
        with self._candidate_reads_lock:
            is_candidate_read = preview["revision"] == 1 and self._candidate_reads < 2
            if is_candidate_read:
                self._candidate_reads += 1
        if is_candidate_read:
            self._barrier.wait()
        return preview

    def __getattr__(self, name):
        return getattr(self._store, name)


class RepositoryAwareRuntimeTests(unittest.TestCase):
    def test_same_remote_facts_are_revision_idempotent_and_audit_commits(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore(context.workspace_identity, TRUST)
            first = RuntimePlanner(context, store, FixtureDriver(), TRUST).preview(plan())
            second = RuntimePlanner(context, store, FixtureDriver(), TRUST).preview(plan(), first["preview_id"])
            self.assertEqual((first["revision"], first["evidence_ids"]), (second["revision"], second["evidence_ids"]))
            auditor = RuntimeAuditor(context, store, build_registry_v1(), TRUST)
            audit_context = auditor.get_context(first["preview_id"], first["revision"])
            evaluations = [RuleEvaluationDraft(rule["rule_id"], rule["rule_version"], SemanticOutcome.PASSED, "verified") for rule in audit_context["semantic_rule_contexts"] if rule["applicability"] == "Applicable"]
            audit = auditor.record_audit(first["preview_id"], first["revision"], audit_context["audit_context_digest"], evaluations, [])
            self.assertEqual(audit.result, AuditResult.PASSED)

    def test_sqlite_reopen_requires_matching_trust_and_can_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            kwargs = {"ignore_checker": lambda path: True, "tracked_checker": lambda path: False}
            store = SQLitePreviewStore(context, trust_context=TRUST, **kwargs)
            preview = RuntimePlanner(context, store, FixtureDriver(), TRUST).preview(plan())
            reopened = SQLitePreviewStore(context, trust_context=TRUST, **kwargs)
            auditor = RuntimeAuditor(context, reopened, build_registry_v1(), TRUST)
            audit_context = auditor.get_context(preview["preview_id"], preview["revision"])
            evaluations = [RuleEvaluationDraft(rule["rule_id"], rule["rule_version"], SemanticOutcome.PASSED, "verified") for rule in audit_context["semantic_rule_contexts"] if rule["applicability"] == "Applicable"]
            self.assertEqual(auditor.record_audit(preview["preview_id"], preview["revision"], audit_context["audit_context_digest"], evaluations, []).result, AuditResult.PASSED)
            with self.assertRaisesRegex(ValueError, "driver_trust_context_mismatch"):
                SQLitePreviewStore(context, trust_context=DriverTrustContext("other", TRUST.origin, TRUST.contract_version), **kwargs).get_preview(context.workspace_identity, preview["preview_id"])

    def test_trust_root_and_promotion_are_not_caller_constructible(self):
        with self.assertRaisesRegex(TypeError, "runtime_promotion_internal_only"):
            RuntimePromotion(object(), object(), object(), "x", "y")
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            with self.assertRaisesRegex(ValueError, "driver_trust_context_required"):
                RuntimePlanner(context, InMemoryPreviewStore(), FixtureDriver())

    def test_unvalidated_facts_and_forged_payloads_cannot_mint_promotion(self):
        driver = FixtureDriver()
        scope = {"api_origin": TRUST.origin, "api_version": "2026-03-10", "issue_state": "all", "pull_request_filter": "pull_request_field_excluded", "relationships": ["sub_issues", "parent", "blocked_by", "blocking"], "pagination_protocol": "link-header", "budget_profile": "github-rest-offline-v1"}
        facts, failures = validate_driver_facts(driver, "Owner/Repo", scope, TRUST.trusted_driver_identity)
        self.assertFalse(failures)
        self.assertIsNotNone(facts)
        forged = ValidatedRemoteFacts(facts.response, {"forged": True}, facts.remote_content_digest)
        with self.assertRaisesRegex(ValueError, "validated_remote_facts_required"):
            bind_validated_facts(forged, __import__("delivery_system.drivers.contract", fromlist=["RuntimeEvidenceBinding"]).RuntimeEvidenceBinding("ws", "preview", 1), TRUST)
        forged_payload = ValidatedRemoteFacts(facts.response, facts.canonical_remote_content_payload, "sha256:" + "0" * 64, _validation_ticket=object())
        with self.assertRaisesRegex(ValueError, "validated_remote_facts_required"):
            bind_validated_facts(forged_payload, __import__("delivery_system.drivers.contract", fromlist=["RuntimeEvidenceBinding"]).RuntimeEvidenceBinding("ws", "preview", 1), TRUST)

    def test_validated_facts_ticket_is_single_use_and_registry_is_weak(self):
        facts, failures = validate_driver_facts(FixtureDriver(), "Owner/Repo", {"api_origin": TRUST.origin, "api_version": "2026-03-10", "issue_state": "all", "pull_request_filter": "pull_request_field_excluded", "relationships": ["sub_issues", "parent", "blocked_by", "blocking"], "pagination_protocol": "link-header", "budget_profile": "github-rest-offline-v1"}, TRUST.trusted_driver_identity)
        self.assertFalse(failures)
        bind_validated_facts(facts, RuntimeEvidenceBinding("ws", "preview", 1), TRUST)
        with self.assertRaisesRegex(ValueError, "validated_remote_facts_required"):
            bind_validated_facts(facts, RuntimeEvidenceBinding("ws", "preview", 1), TRUST)
        for _ in range(100):
            temporary, failures = validate_driver_facts(FixtureDriver(), "Owner/Repo", {"api_origin": TRUST.origin, "api_version": "2026-03-10", "issue_state": "all", "pull_request_filter": "pull_request_field_excluded", "relationships": ["sub_issues", "parent", "blocked_by", "blocking"], "pagination_protocol": "link-header", "budget_profile": "github-rest-offline-v1"}, TRUST.trusted_driver_identity)
            self.assertFalse(failures)
            bind_validated_facts(temporary, RuntimeEvidenceBinding("ws", "preview", 1), TRUST)
        gc.collect()
        self.assertLessEqual(len(preflight_module._VALIDATED_FACTS), 1)

    def test_remote_plan_operation_and_fallback_changes_create_revisions(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore(context.workspace_identity, TRUST)
            first = RuntimePlanner(context, store, FixtureDriver(), TRUST).preview(plan())
            remote = RuntimePlanner(context, store, FixtureDriver("Changed"), TRUST).preview(plan(), first["preview_id"])
            self.assertEqual(remote["revision"], 2)
            operation_plan = plan()
            operation_plan["operation_intents"] = [{"operation_kind": "create_issue", "client_refs": ["item"]}]
            operation = RuntimePlanner(context, store, FixtureDriver("Changed"), TRUST).preview(operation_plan, first["preview_id"])
            self.assertEqual(operation["revision"], 3)
            class FailingDriver(FixtureDriver):
                def read_repository(self, repository, query_scope):
                    raise RuntimeError("offline fixture failure")
            fallback = RuntimePlanner(context, store, FailingDriver(), TRUST).preview(operation_plan, first["preview_id"])
            self.assertEqual(fallback["preview_level"], "Conceptual")
            self.assertEqual(fallback["remote_snapshot"], None)
            stored_evidence = store.get_evidence_records(context.workspace_identity, fallback["evidence_ids"])
            self.assertTrue(all(record["source_kind"] == "declared" for record in stored_evidence))

    def test_mcp_repository_aware_three_tool_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore(context.workspace_identity, TRUST)
            server = create_server(context, store, FixtureDriver(), TRUST)
            async def exercise():
                async with Client(server, raise_exceptions=True) as client:
                    planned = await client.call_tool("delivery_plan_preview", {"payload": {"plan": plan()}})
                    self.assertEqual(planned.structured_content["preview_level"], "RepositoryAware")
                    audit_context = await client.call_tool("delivery_get_audit_context", {"payload": {"preview_id": planned.structured_content["preview_id"], "revision": 1}})
                    evaluations = [{"rule_id": rule["rule_id"], "rule_version": rule["rule_version"], "outcome": "Passed", "rationale": "complete"} for rule in audit_context.structured_content["semantic_rule_contexts"] if rule["applicability"] == "Applicable"]
                    return await client.call_tool("delivery_record_audit", {"payload": {"preview_id": planned.structured_content["preview_id"], "revision": 1, "expected_audit_context_digest": audit_context.structured_content["audit_context_digest"], "semantic_evaluations": evaluations, "finding_drafts": []}})
            result = asyncio.run(exercise())
            self.assertEqual(result.structured_content["result"], "Passed")
            self.assertFalse(result.structured_content["approval_eligible"])

    def test_concurrent_same_candidate_is_idempotent_for_both_stores(self):
        for store_kind in ("memory", "sqlite"):
            with self.subTest(store=store_kind), tempfile.TemporaryDirectory() as directory:
                context = RuntimeContext.from_workspace_root(directory)
                if store_kind == "memory":
                    store = InMemoryPreviewStore(context.workspace_identity, TRUST)
                else:
                    store = SQLitePreviewStore(context, trust_context=TRUST, ignore_checker=lambda path: True, tracked_checker=lambda path: False)
                first = RuntimePlanner(context, store, FixtureDriver(), TRUST).preview(plan())
                def refresh():
                    return RuntimePlanner(context, store, FixtureDriver(), TRUST).preview(plan(), first["preview_id"])
                with ThreadPoolExecutor(max_workers=2) as pool:
                    results = list(pool.map(lambda _: refresh(), (1, 2)))
                self.assertEqual([result["revision"] for result in results], [1, 1])
                self.assertEqual(results[0]["sealed_preview_digest"], results[1]["sealed_preview_digest"])

    def test_concurrent_same_new_revision_merges_random_item_candidates(self):
        for store_kind in ("memory", "sqlite"):
            with self.subTest(store=store_kind), tempfile.TemporaryDirectory() as directory:
                context = RuntimeContext.from_workspace_root(directory)
                store = InMemoryPreviewStore(context.workspace_identity, TRUST) if store_kind == "memory" else SQLitePreviewStore(context, trust_context=TRUST, ignore_checker=lambda path: True, tracked_checker=lambda path: False)
                first = RuntimePlanner(context, store, FixtureDriver(), TRUST).preview(plan())
                candidate = deepcopy(plan())
                extra = deepcopy(candidate["work_items"][0])
                extra["client_ref"] = "new-item"
                candidate["work_items"].append(extra)
                barrier = threading.Barrier(2)
                candidate_store = CandidateReadBarrierStore(store, barrier)
                def refresh():
                    return RuntimePlanner(context, candidate_store, FixtureDriver(), TRUST).preview(candidate, first["preview_id"])
                with ThreadPoolExecutor(max_workers=2) as pool:
                    results = list(pool.map(lambda _: refresh(), (1, 2)))
                self.assertEqual(results[0], results[1])
                self.assertEqual([result["revision"] for result in results], [2, 2])
                self.assertEqual(results[0]["items"], results[1]["items"])
                self.assertEqual(results[0]["evidence_ids"], results[1]["evidence_ids"])
                self.assertEqual(results[0]["sealed_preview_digest"], results[1]["sealed_preview_digest"])
                self.assertIsNone(results[0]["remote_snapshot"])
                self.assertIsNone(results[1]["remote_snapshot"])
                self.assertEqual(results[0]["audit_context_digest"], results[1]["audit_context_digest"])


if __name__ == "__main__":
    unittest.main()
