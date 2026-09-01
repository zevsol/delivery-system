from __future__ import annotations

import tempfile
import unittest
import sqlite3
import threading
from dataclasses import replace
from copy import deepcopy
from typing import Any, cast

from delivery_system.auditor import (
    FindingDraft,
    RuleEvaluationDraft,
    RuntimeAuditor,
    ResultClass,
    SemanticOutcome,
    build_finding_id,
)
from delivery_system.runtime import (
    AuditRecord,
    AuditResult,
    AuditStatus,
    InMemoryPreviewStore,
    RuntimeContext,
    RuntimePlanner,
    SQLitePreviewStore,
)
from delivery_system.protocol import digest
from delivery_system.rules import build_registry_v1
from tests.fakes.store_contract import run_auditor_store_contract


class _BeginGateConnection:
    def __init__(self, connection, acquired=None, release=None, attempting=None, allow_begin=None):
        self._connection = connection
        self._acquired = acquired
        self._release = release
        self._attempting = attempting
        self._allow_begin = allow_begin

    def execute(self, sql, *args):
        if sql == "BEGIN IMMEDIATE" and self._attempting is not None:
            self._attempting.set()
        if sql == "BEGIN IMMEDIATE" and self._allow_begin is not None:
            if not self._allow_begin.wait(5):
                raise AssertionError("timed out waiting to allow BEGIN IMMEDIATE")
        result = self._connection.execute(sql, *args)
        if sql == "BEGIN IMMEDIATE" and self._acquired is not None:
            self._acquired.set()
            if not self._release.wait(5):
                raise AssertionError("timed out waiting to release BEGIN IMMEDIATE")
        return result

    def __getattr__(self, name):
        return getattr(self._connection, name)


def sourced(value, source="user_asserted"):
    return {"value": value, "declared_source": source}


def plan_payload():
    return {
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


class AuditorContractTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.context = RuntimeContext.from_workspace_root(self.directory.name)
        self.store = InMemoryPreviewStore()
        self.preview = RuntimePlanner(self.context, self.store).preview(plan_payload())
        self.registry = build_registry_v1()
        self.auditor = RuntimeAuditor(self.context, self.store, self.registry)

    def tearDown(self):
        self.directory.cleanup()

    def _context(self):
        return self.auditor.get_context(self.preview["preview_id"], self.preview["revision"])

    def _passed_evaluations(self):
        return [
            RuleEvaluationDraft(rule_id=rule.rule_id, rule_version=rule.rule_version,
                                outcome=SemanticOutcome.PASSED, rationale="meets contract")
            for rule in self.registry.semantic_rules
            if rule.applicability == "Applicable"
        ]

    def _audit_candidate(self, auditor, preview, audit_id, rationale):
        context = auditor.get_context(preview["preview_id"], preview["revision"])
        evaluations = [replace(item, rationale=rationale) for item in self._passed_evaluations()]
        evaluation_payload, finding_payload = auditor._validate(context, evaluations, [])
        payload = {
            "workspace_identity": auditor.context.workspace_identity,
            "preview_id": preview["preview_id"],
            "revision": preview["revision"],
            "audit_scope": context["audit_scope"],
            "sealed_preview_digest": context["sealed_preview"]["sealed_preview_digest"],
            "plan_digest": context["sealed_preview"]["plan_digest"],
            "operation_set_digest": context["sealed_preview"]["operation_set_digest"],
            "remote_snapshot_digest": context["sealed_preview"].get("remote_snapshot_digest"),
            "audit_context_digest": context["audit_context_digest"],
            "rule_registry_version": self.registry.registry_version,
            "rule_registry_digest": self.registry.registry_digest,
            "semantic_evaluations": evaluation_payload,
            "findings": finding_payload,
            "result": AuditResult.PASSED.value,
        }
        return AuditRecord.create(
            audit_id, preview["preview_id"], preview["revision"],
            payload["plan_digest"], payload["remote_snapshot_digest"],
            payload["operation_set_digest"], AuditResult.PASSED,
            workspace_identity=auditor.context.workspace_identity,
            audit_scope=context["audit_scope"], audit_payload_digest=digest(payload),
            audit_context_digest=context["audit_context_digest"],
            rule_registry_version=self.registry.registry_version,
            rule_registry_digest=self.registry.registry_digest,
            rule_evaluations=tuple(evaluation_payload), findings=tuple(finding_payload),
            evidence_refs=tuple(sorted(record["evidence_id"] for record in context["evidence_records"])),
            sealed_preview_digest=payload["sealed_preview_digest"],
            created_at="2026-08-11T00:00:00+00:00",
        )

    def test_registry_digest_binds_contract_and_context_exposes_rules(self):
        context = self._context()
        self.assertEqual(context["rule_registry_version"], "1.0")
        self.assertEqual(context["rule_registry_digest"], self.registry.registry_digest)
        self.assertTrue(context["semantic_rule_contexts"])
        self.assertEqual(context["audit_scope"], "Conceptual")

    def test_runtime_gate_failure_does_not_create_audit(self):
        with self.assertRaisesRegex(ValueError, "^invalid_input$"):
            self.auditor.record_audit(self.preview["preview_id"], 1, "wrong", self._passed_evaluations(), [])
        with self.assertRaises(ValueError):
            self.store.get_audit(self.context.workspace_identity, "missing")

    def test_passed_conceptual_audit_is_not_approval_eligible(self):
        context = self._context()
        audit = self.auditor.record_audit(
            self.preview["preview_id"], 1, context["audit_context_digest"],
            self._passed_evaluations(), [],
        )
        self.assertEqual(audit.result, AuditResult.PASSED)
        self.assertEqual(audit.status, AuditStatus.ACTIVE)
        self.assertEqual(audit.audit_scope, "Conceptual")
        self.assertFalse(audit.approval_eligible)

    def test_failed_unknown_and_blocked_aggregate_deterministically(self):
        for outcome, expected, result_class in (
            (SemanticOutcome.FAILED, AuditResult.CHANGES_REQUIRED, ResultClass.WORK_ITEM_CONTENT_GAP),
            (SemanticOutcome.UNKNOWN, AuditResult.NEEDS_INFORMATION, ResultClass.MISSING_INFORMATION),
            (SemanticOutcome.BLOCKED, AuditResult.BLOCKED, ResultClass.SEMANTIC_BLOCKER),
        ):
            with self.subTest(outcome=outcome):
                context = self._context()
                evaluation = RuleEvaluationDraft(
                    "SEM-WORK-ITEM-COMPLETENESS", "1.0", outcome, "insufficient", ("f-1",),
                )
                finding = FindingDraft(
                    "f-1", "SEM-WORK-ITEM-COMPLETENESS", result_class, "High", "gap", "reason", (),
                    (self.preview["items"][0]["item_id"],), "clarify", None,
                )
                audit = self.auditor.record_audit(
                    self.preview["preview_id"], 1, context["audit_context_digest"],
                    [evaluation] + [e for e in self._passed_evaluations() if e.rule_id != evaluation.rule_id],
                    [finding],
                )
                self.assertEqual(audit.result, expected)

    def test_model_cannot_submit_runtime_or_not_applicable_rule(self):
        context = self._context()
        for evaluation, expected in (
            (RuleEvaluationDraft("RT-PREVIEW-SCHEMA", "1.0", SemanticOutcome.PASSED, "fake"), "invalid_runtime_rule_submission"),
            (RuleEvaluationDraft("RT-UNKNOWN", "1.0", SemanticOutcome.PASSED, "fake"), "invalid_input"),
            (RuleEvaluationDraft("SEM-UNKNOWN", "1.0", SemanticOutcome.PASSED, "fake"), "invalid_input"),
            (RuleEvaluationDraft("SEM-DUPLICATE-OVERLAP", "1.0", "NotApplicable", "fake"), "invalid_not_applicable_submission"),
        ):
            with self.subTest(evaluation=evaluation):
                with self.assertRaisesRegex(ValueError, f"^{expected}$"):
                    self.auditor.record_audit(self.preview["preview_id"], 1, context["audit_context_digest"], [evaluation], [])

    def test_finding_result_class_must_match_rule_outcome(self):
        context = self._context()
        evaluation = RuleEvaluationDraft(
            "SEM-WORK-ITEM-COMPLETENESS", "1.0", SemanticOutcome.FAILED, "gap", ("f-1",),
        )
        finding = FindingDraft(
            "f-1", "SEM-WORK-ITEM-COMPLETENESS", ResultClass.DEPENDENCY_RISK, "High", "wrong", "wrong", (),
            (self.preview["items"][0]["item_id"],), "fix", None,
        )
        with self.assertRaisesRegex(ValueError, "^invalid_input$"):
            self.auditor.record_audit(
                self.preview["preview_id"], 1, context["audit_context_digest"],
                [evaluation] + [e for e in self._passed_evaluations() if e.rule_id != evaluation.rule_id],
                [finding],
            )

    def test_identical_payload_is_idempotent_and_new_payload_stales_old(self):
        context = self._context()
        evaluations = self._passed_evaluations()
        first = self.auditor.record_audit(self.preview["preview_id"], 1, context["audit_context_digest"], evaluations, [])
        retry = self.auditor.record_audit(self.preview["preview_id"], 1, context["audit_context_digest"], evaluations, [])
        self.assertEqual(first.audit_id, retry.audit_id)
        changed = list(evaluations)
        changed[0] = RuleEvaluationDraft(changed[0].rule_id, changed[0].rule_version, SemanticOutcome.UNKNOWN, "needs facts", ("f-2",))
        finding = FindingDraft("f-2", changed[0].rule_id, ResultClass.MISSING_INFORMATION, "Medium", "missing", "missing", (), (self.preview["items"][0]["item_id"],), "clarify", None)
        second = self.auditor.record_audit(self.preview["preview_id"], 1, context["audit_context_digest"], changed, [finding])
        self.assertNotEqual(first.audit_id, second.audit_id)
        self.assertEqual(self.store.get_audit(self.context.workspace_identity, first.audit_id).status, AuditStatus.STALE)

    def test_sqlite_store_shares_audit_contract_and_idempotency(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False)
            preview = RuntimePlanner(context, store).preview(plan_payload())
            auditor = RuntimeAuditor(context, store, self.registry)
            context_payload = auditor.get_context(preview["preview_id"], preview["revision"])
            first = auditor.record_audit(preview["preview_id"], 1, context_payload["audit_context_digest"], self._passed_evaluations(), [])
            retry = auditor.record_audit(preview["preview_id"], 1, context_payload["audit_context_digest"], self._passed_evaluations(), [])
            self.assertEqual(store.get_audit(context.workspace_identity, first.audit_id).audit_id, first.audit_id)
            self.assertEqual(retry.audit_id, first.audit_id)

    def test_revision_competition_rejects_old_audit_candidate(self):
        for adapter in ("inmemory", "sqlite"):
            with self.subTest(adapter=adapter), tempfile.TemporaryDirectory() as directory:
                context = RuntimeContext.from_workspace_root(directory)
                if adapter == "sqlite":
                    store_a = SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False)
                    store_b = SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False)
                else:
                    store_a = InMemoryPreviewStore(context.workspace_identity)
                    store_b = store_a
                preview = RuntimePlanner(context, store_a).preview(plan_payload())
                auditor = RuntimeAuditor(context, store_a, self.registry)
                context_payload = auditor.get_context(preview["preview_id"], 1)
                candidate = auditor.record_audit(preview["preview_id"], 1, context_payload["audit_context_digest"], self._passed_evaluations(), [])
                canonical = cast(dict[str, Any], deepcopy(store_b.get_preview_revision(context.workspace_identity, preview["preview_id"], 1)["canonical_payload"]))
                canonical["revision"] = 2
                canonical["evidence_ids"] = []
                canonical["sealed_preview_digest"] = digest({key: value for key, value in canonical.items() if key != "sealed_preview_digest"})
                store_b.save_preview_revision(
                    canonical["request_id"], canonical["preview_id"], 2,
                    canonical["plan_digest"], canonical["remote_snapshot_digest"],
                    canonical["operation_set_digest"], canonical["repository_identity"],
                    canonical["items"], workspace_identity=context.workspace_identity,
                    canonical_payload=canonical, evidence_records=[],
                )
                with self.assertRaisesRegex(ValueError, "^audit_context_stale$"):
                    store_a.commit_audit(candidate)
                self.assertEqual(store_a.get_audit(context.workspace_identity, candidate.audit_id).status, AuditStatus.STALE)
                self.assertEqual(store_a.list_active_audits(context.workspace_identity, preview["preview_id"], 1), [])

    def test_shared_auditor_store_contract_runs_for_inmemory_and_sqlite(self):
        for adapter in ("inmemory", "sqlite"):
            with self.subTest(adapter=adapter), tempfile.TemporaryDirectory() as directory:
                context = RuntimeContext.from_workspace_root(directory)
                store = (InMemoryPreviewStore() if adapter == "inmemory" else
                         SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False))
                preview = RuntimePlanner(context, store).preview(plan_payload())
                run_auditor_store_contract(self, context, store, RuntimeAuditor(context, store, self.registry), preview)

    def test_forged_passed_audit_cannot_use_public_store_write(self):
        for adapter in ("inmemory", "sqlite"):
            with self.subTest(adapter=adapter), tempfile.TemporaryDirectory() as directory:
                context = RuntimeContext.from_workspace_root(directory)
                store = (InMemoryPreviewStore() if adapter == "inmemory" else
                         SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False))
                preview = RuntimePlanner(context, store).preview(plan_payload())
                forged = __import__("delivery_system.runtime", fromlist=["AuditRecord"]).AuditRecord.create(
                    "forged", preview["preview_id"], 1, preview["plan_digest"], None,
                    preview["operation_set_digest"], AuditResult.PASSED,
                    workspace_identity=context.workspace_identity, audit_scope="Conceptual",
                    audit_payload_digest="sha256:forged", audit_context_digest="sha256:forged",
                    sealed_preview_digest=preview["sealed_preview_digest"],
                    rule_registry_version="1.0", rule_registry_digest="sha256:forged",
                    created_at="2026-08-11T00:00:00+00:00",
                )
                with self.assertRaisesRegex(ValueError, "^audit_commit_boundary_required$"):
                    store.record_audit(forged)
                with self.assertRaises(ValueError):
                    store.get_audit(context.workspace_identity, forged.audit_id)

    def test_forged_passed_audit_cannot_use_commit_boundary(self):
        for adapter in ("inmemory", "sqlite"):
            with self.subTest(adapter=adapter), tempfile.TemporaryDirectory() as directory:
                context = RuntimeContext.from_workspace_root(directory)
                store = (InMemoryPreviewStore() if adapter == "inmemory" else
                         SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False))
                preview = RuntimePlanner(context, store).preview(plan_payload())
                auditor = RuntimeAuditor(context, store, self.registry)
                context_payload = auditor.get_context(preview["preview_id"], 1)
                genuine = auditor.record_audit(preview["preview_id"], 1, context_payload["audit_context_digest"], self._passed_evaluations(), [])
                forged_payload = {
                    "workspace_identity": genuine.workspace_identity,
                    "preview_id": genuine.preview_id,
                    "revision": genuine.revision,
                    "audit_scope": genuine.audit_scope,
                    "sealed_preview_digest": genuine.sealed_preview_digest,
                    "plan_digest": genuine.plan_digest,
                    "operation_set_digest": genuine.operation_set_digest,
                    "remote_snapshot_digest": genuine.remote_snapshot_digest,
                    "audit_context_digest": genuine.audit_context_digest,
                    "rule_registry_version": "666",
                    "rule_registry_digest": genuine.rule_registry_digest,
                    "semantic_evaluations": list(genuine.rule_evaluations),
                    "findings": list(genuine.findings),
                    "result": genuine.result.value,
                }
                forged = replace(genuine, audit_id="forged-commit", rule_registry_version="666",
                                 audit_payload_digest=digest(forged_payload))._with_digest()
                with self.assertRaisesRegex(ValueError, "^audit_commit_boundary_required$"):
                    store.commit_audit(forged)
                self.assertEqual(store.get_audit(context.workspace_identity, genuine.audit_id).audit_id, genuine.audit_id)
                with self.assertRaisesRegex(ValueError, "^audit_not_found$"):
                    store.get_audit(context.workspace_identity, forged.audit_id)
                fake_evaluations = ({"rule_id": "SEM-FAKE", "rule_version": "1.0", "outcome": "Passed", "rationale": "forged", "finding_refs": [], "evidence_refs": []},)
                fake_payload = {
                    "workspace_identity": genuine.workspace_identity, "preview_id": genuine.preview_id,
                    "revision": genuine.revision, "audit_scope": genuine.audit_scope,
                    "sealed_preview_digest": genuine.sealed_preview_digest, "plan_digest": genuine.plan_digest,
                    "operation_set_digest": genuine.operation_set_digest, "remote_snapshot_digest": genuine.remote_snapshot_digest,
                    "audit_context_digest": genuine.audit_context_digest, "rule_registry_version": genuine.rule_registry_version,
                    "rule_registry_digest": genuine.rule_registry_digest, "semantic_evaluations": list(fake_evaluations),
                    "findings": [], "result": "Passed",
                }
                fake = replace(genuine, audit_id="forged-rule", rule_evaluations=fake_evaluations,
                               audit_payload_digest=digest(fake_payload))._with_digest()
                with self.assertRaisesRegex(ValueError, "^audit_commit_boundary_required$"):
                    store.commit_audit(fake)
                with self.assertRaisesRegex(ValueError, "^audit_not_found$"):
                    store.get_audit(context.workspace_identity, fake.audit_id)

    def test_commit_rejects_tampered_sqlite_evidence_and_canonical(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False)
            preview = RuntimePlanner(context, store).preview(plan_payload())
            auditor = RuntimeAuditor(context, store, self.registry)
            ctx = auditor.get_context(preview["preview_id"], 1)
            genuine = auditor.record_audit(preview["preview_id"], 1, ctx["audit_context_digest"], self._passed_evaluations(), [])
            candidate = replace(genuine, audit_id="tampered-evidence")._with_digest()
            connection = sqlite3.connect(store.path)
            try:
                evidence_id = preview["evidence_ids"][0]
                connection.execute("UPDATE records SET payload=? WHERE record_type='evidence' AND record_id=?", ('{"tampered":true}', evidence_id))
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(ValueError):
                store.commit_audit(candidate)
            self.assertEqual(store.get_audit(context.workspace_identity, genuine.audit_id).audit_id, genuine.audit_id)

    def test_commit_rejects_tampered_sqlite_canonical_without_staling(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False)
            preview = RuntimePlanner(context, store).preview(plan_payload())
            auditor = RuntimeAuditor(context, store, self.registry)
            ctx = auditor.get_context(preview["preview_id"], 1)
            genuine = auditor.record_audit(preview["preview_id"], 1, ctx["audit_context_digest"], self._passed_evaluations(), [])
            candidate = replace(genuine, audit_id="tampered-canonical")._with_digest()
            connection = sqlite3.connect(store.path)
            try:
                row = connection.execute("SELECT payload FROM records WHERE record_type='preview' AND record_id=? AND revision=1", (preview["preview_id"],)).fetchone()
                payload = __import__("json").loads(row[0])
                payload["canonical_payload"]["semantic_payload"]["tampered"] = True
                connection.execute("UPDATE records SET payload=? WHERE record_type='preview' AND record_id=? AND revision=1", (__import__("json").dumps(payload, sort_keys=True), preview["preview_id"]))
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(ValueError):
                store.commit_audit(candidate)
            self.assertEqual(store.get_audit(context.workspace_identity, genuine.audit_id).status, AuditStatus.ACTIVE)

    def test_commit_rejects_strict_audit_children_and_status(self):
        for adapter in ("inmemory", "sqlite"):
            with self.subTest(adapter=adapter), tempfile.TemporaryDirectory() as directory:
                context = RuntimeContext.from_workspace_root(directory)
                store = InMemoryPreviewStore() if adapter == "inmemory" else SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False)
                preview = RuntimePlanner(context, store).preview(plan_payload())
                auditor = RuntimeAuditor(context, store, self.registry)
                ctx = auditor.get_context(preview["preview_id"], 1)
                genuine = auditor.record_audit(preview["preview_id"], 1, ctx["audit_context_digest"], self._passed_evaluations(), [])
                bad_eval = dict(genuine.rule_evaluations[0]); bad_eval["runtime_gate_passed"] = True
                bad = replace(genuine, audit_id="bad-eval", rule_evaluations=(bad_eval,) + genuine.rule_evaluations[1:])._with_digest()
                with self.assertRaises(ValueError): store.commit_audit(bad)
                bad_status = genuine.transition(AuditStatus.STALE, "test")
                with self.assertRaisesRegex(ValueError, "^audit_commit_boundary_required$"): store.commit_audit(bad_status)

    def test_inmemory_concurrent_different_payloads_leave_one_active(self):
        context = self._context()
        barrier = threading.Barrier(2)
        results = []

        def submit(rationale):
            try:
                barrier.wait()
                evaluations = [replace(item, rationale=rationale) for item in self._passed_evaluations()]
                result = self.auditor.record_audit(self.preview["preview_id"], 1, context["audit_context_digest"], evaluations, [])
                results.append(result)
            except Exception as exc:
                results.append(exc)

        threads = [threading.Thread(target=submit, args=("first",)), threading.Thread(target=submit, args=("second",))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(results), 2)
        self.assertTrue(all(not isinstance(result, Exception) for result in results), results)
        audits = [value for value in self.auditor.store._audits.values() if value.preview_id == self.preview["preview_id"]]
        self.assertEqual(sum(value.status is AuditStatus.ACTIVE for value in audits), 1)
        self.assertEqual(sum(value.status is AuditStatus.STALE for value in audits), 1)

    def test_inmemory_concurrent_identical_payloads_are_idempotent(self):
        context = self._context()
        barrier = threading.Barrier(2)
        results = []

        def submit():
            try:
                barrier.wait()
                results.append(self.auditor.record_audit(self.preview["preview_id"], 1, context["audit_context_digest"], self._passed_evaluations(), []))
            except Exception as exc:
                results.append(exc)

        threads = [threading.Thread(target=submit), threading.Thread(target=submit)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(results), 2)
        self.assertTrue(all(not isinstance(result, Exception) for result in results), results)
        self.assertEqual(results[0].audit_id, results[1].audit_id)
        self.assertEqual(len(self.auditor.store._audits), 1)

    def test_sqlite_concurrent_different_payloads_leave_one_active(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store_a = SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False)
            store_b = SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False)
            preview = RuntimePlanner(context, store_a).preview(plan_payload())
            auditor = RuntimeAuditor(context, store_a, self.registry)
            candidate_a = self._audit_candidate(auditor, preview, "audit-a", "first")
            candidate_b = self._audit_candidate(auditor, preview, "audit-b", "second")
            acquired = threading.Event()
            release = threading.Event()
            attempting = threading.Event()
            allow_begin = threading.Event()
            original_connect = store_a._connect
            store_a._connect = lambda: _BeginGateConnection(original_connect(), acquired, release)
            original_connect_b = store_b._connect
            store_b._connect = lambda: _BeginGateConnection(original_connect_b(), attempting=attempting, allow_begin=allow_begin)
            results = []

            def submit(store, candidate):
                try:
                    results.append(store.commit_audit(candidate))
                except Exception as exc:
                    results.append(exc)

            first = threading.Thread(target=submit, args=(store_a, candidate_a))
            second = threading.Thread(target=submit, args=(store_b, candidate_b))
            first.start()
            self.assertTrue(acquired.wait(5))
            second.start()
            self.assertTrue(attempting.wait(5))
            release.set()
            first.join(5)
            self.assertFalse(first.is_alive())
            allow_begin.set()
            second.join(5)
            self.assertFalse(second.is_alive())
            self.assertEqual(len(results), 2)
            self.assertTrue(all(not isinstance(result, Exception) for result in results), results)
            audits = [store_a.get_audit(context.workspace_identity, audit_id)
                      for audit_id in ("audit-a", "audit-b")]
            self.assertEqual(sum(audit.status is AuditStatus.ACTIVE for audit in audits), 1)
            self.assertEqual(sum(audit.status is AuditStatus.STALE for audit in audits), 1)

    def test_sqlite_concurrent_identical_payloads_are_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store_a = SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False)
            store_b = SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False)
            preview = RuntimePlanner(context, store_a).preview(plan_payload())
            auditor = RuntimeAuditor(context, store_a, self.registry)
            candidate = self._audit_candidate(auditor, preview, "audit-same", "same")
            acquired = threading.Event()
            release = threading.Event()
            attempting = threading.Event()
            allow_begin = threading.Event()
            original_connect = store_a._connect
            store_a._connect = lambda: _BeginGateConnection(original_connect(), acquired, release)
            original_connect_b = store_b._connect
            store_b._connect = lambda: _BeginGateConnection(original_connect_b(), attempting=attempting, allow_begin=allow_begin)
            results = []

            def submit(store):
                try:
                    results.append(store.commit_audit(candidate))
                except Exception as exc:
                    results.append(exc)

            first = threading.Thread(target=submit, args=(store_a,))
            second = threading.Thread(target=submit, args=(store_b,))
            first.start()
            self.assertTrue(acquired.wait(5))
            second.start()
            self.assertTrue(attempting.wait(5))
            release.set()
            first.join(5)
            self.assertFalse(first.is_alive())
            allow_begin.set()
            second.join(5)
            self.assertFalse(second.is_alive())
            self.assertEqual(len(results), 2)
            self.assertTrue(all(not isinstance(result, Exception) for result in results), results)
            self.assertEqual(results[0].audit_id, results[1].audit_id)
            self.assertEqual(len(store_a._current_audits(context.workspace_identity)), 1)

    def test_sqlite_transition_rechecks_current_state(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False)
            preview = RuntimePlanner(context, store).preview(plan_payload())
            auditor = RuntimeAuditor(context, store, self.registry)
            candidate = self._audit_candidate(auditor, preview, "audit-transition", "same")
            store.commit_audit(candidate)
            store_a = SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False)
            store_b = SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False)
            observed = threading.Barrier(2)
            acquired = threading.Event()
            release = threading.Event()
            attempting = threading.Event()
            allow_begin = threading.Event()
            original_get_audit_a = store_a.get_audit
            original_get_audit_b = store_b.get_audit
            def get_then_wait(original, *args):
                current = original(*args)
                observed.wait(5)
                return current

            store_a.get_audit = lambda *args: get_then_wait(original_get_audit_a, *args)
            store_b.get_audit = lambda *args: get_then_wait(original_get_audit_b, *args)
            original_connect_a = store_a._connect
            store_a._connect = lambda: _BeginGateConnection(original_connect_a(), acquired, release)
            original_connect_b = store_b._connect
            store_b._connect = lambda: _BeginGateConnection(original_connect_b(), attempting=attempting, allow_begin=allow_begin)
            results = []

            def transition(store, status):
                try:
                    results.append(store.transition_audit_status("audit-transition", status, "race"))
                except Exception as exc:
                    results.append(exc)

            first = threading.Thread(target=transition, args=(store_a, AuditStatus.INVALID))
            second = threading.Thread(target=transition, args=(store_b, AuditStatus.STALE))
            first.start()
            second.start()
            self.assertTrue(acquired.wait(5))
            self.assertTrue(attempting.wait(5))
            release.set()
            first.join(5)
            self.assertFalse(first.is_alive())
            allow_begin.set()
            second.join(5)
            self.assertFalse(second.is_alive())
            self.assertEqual(len(results), 2)
            self.assertEqual(sum(not isinstance(result, Exception) for result in results), 1, results)
            self.assertEqual(sum(isinstance(result, ValueError) and str(result) == "invalid audit status transition" for result in results), 1, results)
            self.assertEqual(store.get_audit(context.workspace_identity, "audit-transition").status, AuditStatus.INVALID)

    def test_finding_ref_rename_preserves_finding_and_audit_identity(self):
        context = self._context()
        evaluation = RuleEvaluationDraft("SEM-WORK-ITEM-COMPLETENESS", "1.0", SemanticOutcome.FAILED, "gap", ("temporary-a",))
        finding = FindingDraft("temporary-a", "SEM-WORK-ITEM-COMPLETENESS", ResultClass.WORK_ITEM_CONTENT_GAP, "High", "gap", "reason", (), (self.preview["items"][0]["item_id"],), "clarify", None)
        first = self.auditor.record_audit(self.preview["preview_id"], 1, context["audit_context_digest"], [evaluation] + [e for e in self._passed_evaluations() if e.rule_id != evaluation.rule_id], [finding])
        renamed_evaluation = replace(evaluation, finding_refs=("temporary-b",))
        renamed_finding = replace(finding, finding_ref="temporary-b")
        retry = self.auditor.record_audit(self.preview["preview_id"], 1, context["audit_context_digest"], [renamed_evaluation] + [e for e in self._passed_evaluations() if e.rule_id != evaluation.rule_id], [renamed_finding])
        self.assertEqual(first.audit_id, retry.audit_id)
        self.assertEqual(first.audit_payload_digest, retry.audit_payload_digest)
        self.assertEqual(first.findings[0]["finding_id"], retry.findings[0]["finding_id"])
        formal_evaluation = next(item for item in first.rule_evaluations if item["rule_id"] == evaluation.rule_id)
        self.assertEqual(formal_evaluation["finding_refs"], [first.findings[0]["finding_id"]])

    def test_finding_identity_binds_semantics_but_not_input_order(self):
        plan = plan_payload()
        second = dict(plan["work_items"][0])
        second["client_ref"] = "inventory-reports"
        plan["work_items"] = plan["work_items"] + [second]
        with tempfile.TemporaryDirectory() as directory:
            context_runtime = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore()
            preview = RuntimePlanner(context_runtime, store).preview(plan)
            auditor = RuntimeAuditor(context_runtime, store, self.registry)
            context = auditor.get_context(preview["preview_id"], preview["revision"])
            evidence = tuple(record["evidence_id"] for record in context["evidence_records"][:2])
            item_ids = tuple(item["item_id"] for item in preview["items"])
            evaluation = RuleEvaluationDraft("SEM-WORK-ITEM-COMPLETENESS", "1.0", SemanticOutcome.FAILED, "gap", ("f",))
            base = FindingDraft("f", "SEM-WORK-ITEM-COMPLETENESS", ResultClass.WORK_ITEM_CONTENT_GAP, "High", "gap", "reason", evidence, item_ids, "clarify", None)
            passed = [e for e in self._passed_evaluations() if e.rule_id != evaluation.rule_id]
            first = auditor.record_audit(preview["preview_id"], 1, context["audit_context_digest"], [evaluation] + passed, [base])
            reordered = replace(base, finding_ref="renamed", evidence_refs=tuple(reversed(evidence)), affected_item_ids=tuple(reversed(item_ids)))
            retry = auditor.record_audit(preview["preview_id"], 1, context["audit_context_digest"], [replace(evaluation, finding_refs=("renamed",))] + passed, [reordered])
            self.assertEqual(first.findings[0]["finding_id"], retry.findings[0]["finding_id"])
            duplicate = replace(base, evidence_refs=(evidence[0], evidence[0]))
            with self.assertRaisesRegex(ValueError, "^invalid_input$"):
                auditor.record_audit(preview["preview_id"], 1, context["audit_context_digest"], [evaluation] + passed, [duplicate])
            duplicate_items = replace(base, affected_item_ids=(item_ids[0], item_ids[0]))
            with self.assertRaisesRegex(ValueError, "^invalid_input$"):
                auditor.record_audit(preview["preview_id"], 1, context["audit_context_digest"], [evaluation] + passed, [duplicate_items])
            return

    def test_audit_digest_binds_sealed_preview_and_excludes_created_at(self):
        context = self._context()
        audit = self.auditor.record_audit(self.preview["preview_id"], 1, context["audit_context_digest"], self._passed_evaluations(), [])
        self.assertEqual(audit.sealed_preview_digest, self.preview["sealed_preview_digest"])
        later = replace(audit, created_at="2099-01-01T00:00:00+00:00")
        self.assertEqual(audit.audit_digest, later.audit_digest)
        changed_status = audit.transition(AuditStatus.STALE, "test")
        self.assertEqual(audit.audit_payload_digest, changed_status.audit_payload_digest)
        self.assertNotEqual(audit.audit_digest, changed_status.audit_digest)

    def test_planned_dependency_does_not_activate_parent_rule(self):
        plan = plan_payload()
        plan["planned_relationships"] = [{"kind": "planned_dependency", "from_client_ref": "inventory", "to_client_ref": "inventory", "rationale": sourced("blocks", "model_proposed")}]
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore()
            preview = RuntimePlanner(context, store).preview(plan)
            contexts = RuntimeAuditor(context, store, self.registry).get_context(preview["preview_id"], 1)["semantic_rule_contexts"]
            by_id = {item["rule_id"]: item for item in contexts}
            self.assertEqual(by_id["SEM-DEPENDENCY"]["applicability"], "Applicable")
            self.assertEqual(by_id["SEM-PARENT-SUBISSUE"]["applicability"], "NotApplicable")

    def test_f13_commit_rejects_audit_and_envelope_binding_mutations(self):
        mutations = (
            ("plan", {"plan_digest": "sha256:" + "1" * 64}),
            ("operation", {"operation_set_digest": "sha256:" + "2" * 64}),
            ("sealed", {"sealed_preview_digest": "sha256:" + "3" * 64}),
            ("remote", {"remote_snapshot_digest": "sha256:" + "4" * 64}),
            ("scope", {"audit_scope": "RepositoryAware"}),
            ("evidence", {"evidence_refs": ("evidence-not-bound",)}),
        )
        for adapter in ("inmemory", "sqlite"):
            for name, changes in mutations:
                with self.subTest(adapter=adapter, mutation=name), tempfile.TemporaryDirectory() as directory:
                    context = RuntimeContext.from_workspace_root(directory)
                    store = (InMemoryPreviewStore() if adapter == "inmemory" else
                             SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False))
                    preview = RuntimePlanner(context, store).preview(plan_payload())
                    auditor = RuntimeAuditor(context, store, self.registry)
                    audit_context = auditor.get_context(preview["preview_id"], 1)
                    genuine = auditor.record_audit(preview["preview_id"], 1, audit_context["audit_context_digest"], self._passed_evaluations(), [])
                    candidate = replace(genuine, audit_id="f13-" + name, **changes)._with_digest()
                    with self.assertRaisesRegex(ValueError, "^(audit_commit_boundary_required|audit_context_stale)$"):
                        store.commit_audit(candidate)
                    self.assertEqual(store.get_audit(context.workspace_identity, genuine.audit_id).status, AuditStatus.ACTIVE)
                    with self.assertRaisesRegex(ValueError, "^audit_not_found$"):
                        store.get_audit(context.workspace_identity, candidate.audit_id)

    def test_f13_commit_rejects_record_envelope_identity_mismatch(self):
        for adapter in ("inmemory", "sqlite"):
            for field, value in (("request_id", "wrong-request"), ("preview_id", "wrong-preview"), ("revision", 99)):
                with self.subTest(adapter=adapter, field=field), tempfile.TemporaryDirectory() as directory:
                    context = RuntimeContext.from_workspace_root(directory)
                    store = (InMemoryPreviewStore() if adapter == "inmemory" else
                             SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False))
                    preview = RuntimePlanner(context, store).preview(plan_payload())
                    auditor = RuntimeAuditor(context, store, self.registry)
                    audit_context = auditor.get_context(preview["preview_id"], 1)
                    genuine = auditor.record_audit(preview["preview_id"], 1, audit_context["audit_context_digest"], self._passed_evaluations(), [])
                    if adapter == "inmemory":
                        memory_store = cast(InMemoryPreviewStore, store)
                        for envelope in (memory_store._previews[(context.workspace_identity, preview["preview_id"])], memory_store._preview_history[(context.workspace_identity, preview["preview_id"], 1)]):
                            envelope[field] = value
                    else:
                        import json
                        sqlite_store = cast(SQLitePreviewStore, store)
                        connection = sqlite3.connect(sqlite_store.path)
                        try:
                            row = connection.execute("SELECT payload FROM records WHERE record_type='preview' AND record_id=? AND revision=1", (preview["preview_id"],)).fetchone()
                            envelope = json.loads(row[0])
                            envelope[field] = value
                            connection.execute("UPDATE records SET payload=? WHERE record_type='preview' AND record_id=? AND revision=1", (json.dumps(envelope, sort_keys=True), preview["preview_id"]))
                            connection.commit()
                        finally:
                            connection.close()
                    candidate = replace(genuine, audit_id="f13-envelope-" + field)._with_digest()
                    with self.assertRaisesRegex(ValueError, "^(audit_commit_boundary_required|audit_context_stale)$"):
                        store.commit_audit(candidate)
                    self.assertEqual(store.get_audit(context.workspace_identity, genuine.audit_id).status, AuditStatus.ACTIVE)

    def test_f14_store_commit_rejects_finding_cross_field_mutations(self):
        mutations = (
            ("version", {"rule_version": "666"}),
            ("outcome", {"outcome": "Passed"}),
            ("severity", {"severity": "Critical"}),
        )
        for adapter in ("inmemory", "sqlite"):
            for name, changes in mutations:
                with self.subTest(adapter=adapter, mutation=name), tempfile.TemporaryDirectory() as directory:
                    context = RuntimeContext.from_workspace_root(directory)
                    store = (InMemoryPreviewStore() if adapter == "inmemory" else
                             SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False))
                    preview = RuntimePlanner(context, store).preview(plan_payload())
                    auditor = RuntimeAuditor(context, store, self.registry)
                    audit_context = auditor.get_context(preview["preview_id"], 1)
                    evaluation = RuleEvaluationDraft("SEM-WORK-ITEM-COMPLETENESS", "1.0", SemanticOutcome.FAILED, "gap", ("finding-ref",))
                    finding = FindingDraft("finding-ref", "SEM-WORK-ITEM-COMPLETENESS", ResultClass.WORK_ITEM_CONTENT_GAP, "High", "gap", "reason", (), (preview["items"][0]["item_id"],), "clarify", None)
                    evaluations = [evaluation] + [item for item in self._passed_evaluations() if item.rule_id != evaluation.rule_id]
                    genuine = auditor.record_audit(preview["preview_id"], 1, audit_context["audit_context_digest"], evaluations, [finding])
                    changed_finding = dict(genuine.findings[0]); changed_finding.update(changes)
                    payload = {
                        "workspace_identity": genuine.workspace_identity, "preview_id": genuine.preview_id, "revision": genuine.revision,
                        "audit_scope": genuine.audit_scope, "sealed_preview_digest": genuine.sealed_preview_digest,
                        "plan_digest": genuine.plan_digest, "operation_set_digest": genuine.operation_set_digest,
                        "remote_snapshot_digest": genuine.remote_snapshot_digest, "audit_context_digest": genuine.audit_context_digest,
                        "rule_registry_version": genuine.rule_registry_version, "rule_registry_digest": genuine.rule_registry_digest,
                        "semantic_evaluations": list(genuine.rule_evaluations), "findings": [changed_finding], "result": genuine.result.value,
                    }
                    candidate = replace(genuine, audit_id="f14-" + name, findings=(changed_finding,), audit_payload_digest=digest(payload))._with_digest()
                    with self.assertRaisesRegex(ValueError, "^audit_commit_boundary_required$"):
                        store.commit_audit(candidate)
                    self.assertEqual(store.get_audit(context.workspace_identity, genuine.audit_id).status, AuditStatus.ACTIVE)

    def test_f14_build_finding_id_rejects_unapproved_severity(self):
        with self.assertRaisesRegex(ValueError, "^invalid_input$"):
            build_finding_id(
                self.context.workspace_identity, self.preview["preview_id"], 1,
                "SEM-WORK-ITEM-COMPLETENESS", "1.0", SemanticOutcome.FAILED,
                ResultClass.WORK_ITEM_CONTENT_GAP, "Critical", "title", "reason",
                (), (self.preview["items"][0]["item_id"],), "action", None,
            )

    def test_f15_inmemory_revision_save_and_audit_commit_are_serialized(self):
        for commit_first in (True, False):
            with self.subTest(commit_first=commit_first):
                local_context = RuntimeContext.from_workspace_root(self.directory.name)
                store = InMemoryPreviewStore()
                preview = RuntimePlanner(local_context, store).preview(plan_payload())
                auditor = RuntimeAuditor(local_context, store, self.registry)
                audit_context = auditor.get_context(preview["preview_id"], 1)
                candidate = auditor.record_audit(preview["preview_id"], 1, audit_context["audit_context_digest"], self._passed_evaluations(), [])
                original = cast(dict[str, Any], deepcopy(store.get_preview_revision(local_context.workspace_identity, preview["preview_id"], 1)["canonical_payload"]))
                original["revision"] = 2
                original["semantic_payload"] = {"changed": True}
                original["plan_digest"] = digest(original["semantic_payload"])
                original["evidence_ids"] = []
                original["sealed_preview_digest"] = digest({key: value for key, value in original.items() if key != "sealed_preview_digest"})
                commit_done = threading.Event()
                save_done = threading.Event()
                outcomes = []

                def do_commit():
                    if not commit_first:
                        save_done.wait()
                    try:
                        store.commit_audit(candidate)
                        outcomes.append("commit-ok")
                    except ValueError as exc:
                        outcomes.append(str(exc))
                    finally:
                        commit_done.set()

                def do_save():
                    if commit_first:
                        commit_done.wait()
                    try:
                        store.save_preview_revision(
                            original["request_id"], original["preview_id"], 2, original["plan_digest"],
                            original["remote_snapshot_digest"], original["operation_set_digest"], None,
                            original["items"], workspace_identity=local_context.workspace_identity,
                            canonical_payload=original, evidence_records=[],
                        )
                        outcomes.append("save-ok")
                    finally:
                        save_done.set()

                threads = [threading.Thread(target=do_commit), threading.Thread(target=do_save)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
                self.assertIn("save-ok", outcomes)
                if commit_first:
                    self.assertIn("commit-ok", outcomes)
                else:
                    self.assertIn("audit_context_stale", outcomes)
                self.assertEqual(store.list_active_audits(local_context.workspace_identity, preview["preview_id"], 1), [])
                self.assertEqual(store.get_audit(local_context.workspace_identity, candidate.audit_id).status, AuditStatus.STALE)


if __name__ == "__main__":
    unittest.main()
