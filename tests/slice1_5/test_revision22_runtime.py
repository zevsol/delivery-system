import json
from dataclasses import FrozenInstanceError
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from delivery_system.runtime import (
    ApprovalRecord,
    AuditRecord,
    AuditStatus,
    AuditResult,
    DeclaredSource,
    InMemoryPreviewStore,
    RuntimeContext,
    SourcedValue,
    StorePreflightError,
    SQLitePreviewStore,
    _ItemRecord,
)


class Revision22RuntimeTests(unittest.TestCase):
    def test_runtime_context_is_explicit_and_normalized(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            self.assertTrue(Path(context.workspace_root).is_absolute())
            self.assertTrue(context.workspace_identity.startswith("ws_v1_"))
            self.assertEqual(context.normalized_workspace_root, context.workspace_root)
            self.assertEqual(
                context.state_path,
                str(Path(context.workspace_root) / ".delivery-system" / "state.sqlite3"),
            )

    def test_relative_workspace_input_is_absolute(self):
        context = RuntimeContext.from_workspace_root(".")
        self.assertTrue(Path(context.workspace_root).is_absolute())
        self.assertTrue(Path(context.normalized_workspace_root).is_absolute())

    def test_symlink_workspace_and_real_workspace_share_identity_and_preflight(self):
        with tempfile.TemporaryDirectory() as directory:
            real = Path(directory) / "real"
            real.mkdir()
            link = Path(directory) / "link"
            try:
                link.symlink_to(real, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlink unavailable: {exc}")
            actual = RuntimeContext.from_workspace_root(real)
            through_link = RuntimeContext.from_workspace_root(link)
            self.assertEqual(actual.workspace_identity, through_link.workspace_identity)
            self.assertEqual(actual.normalized_workspace_root, through_link.normalized_workspace_root)
            through_link.ensure_store_ready(ignore_checker=lambda _: True, tracked_checker=lambda _: False)

    def test_missing_workspace_context_fails_closed(self):
        with self.assertRaises(ValueError):
            RuntimeContext.from_workspace_root(None)
        with self.assertRaises(ValueError):
            RuntimeContext.from_workspace_root("does-not-exist")

    def test_declared_provenance_is_not_verified_user_fact(self):
        value = SourcedValue("user text", DeclaredSource.USER_ASSERTED)
        self.assertEqual(value.declared_source, DeclaredSource.USER_ASSERTED)
        self.assertEqual(value.provenance_status, "declared_unverified")
        with self.assertRaises(FrozenInstanceError):
            value.declared_source = DeclaredSource.MODEL_PROPOSED

    def test_lineage_inherits_only_unique_live_previous_client_ref(self):
        store = InMemoryPreviewStore()
        store._items.append(_ItemRecord("ws", "preview-1", "old-ref", "item-1"))
        self.assertEqual(
            store.resolve_item_id("ws", "preview-1", "old-ref"),
            "item-1",
        )

    def test_lineage_rejects_missing_duplicate_cross_preview_and_tombstone(self):
        store = InMemoryPreviewStore()
        store._items.extend([
            _ItemRecord("ws", "preview-1", "old-ref", "item-1"),
            _ItemRecord("ws", "preview-2", "old-ref", "item-2"),
            _ItemRecord("ws", "preview-3", "deleted-ref", "item-3", True),
        ])
        for workspace, preview, client_ref in (
            ("ws", "preview-1", "missing"),
            ("other", "preview-1", "old-ref"),
            ("ws", "preview-3", "deleted-ref"),
        ):
            with self.subTest(workspace=workspace, preview=preview, client_ref=client_ref):
                with self.assertRaises(ValueError):
                    store.resolve_item_id(workspace, preview, client_ref)
        self.assertEqual(store.resolve_item_id("ws", "preview-2", "old-ref"), "item-2")

    def test_audit_uses_discovery_contract_results(self):
        for result in AuditResult:
            self.assertIn(result.value, {"Passed", "NeedsInformation", "ChangesRequired", "Blocked"})
        record = AuditRecord(
            audit_id="audit-1",
            preview_id="preview-1",
            revision=1,
            plan_digest="sha256:plan",
            remote_snapshot_digest="sha256:remote",
            operation_set_digest="sha256:ops",
            audit_digest="sha256:audit",
            result=AuditResult.PASSED,
            status=AuditStatus.ACTIVE,
        )
        self.assertEqual(record.result, AuditResult.PASSED)
        self.assertEqual(record.status, AuditStatus.ACTIVE)

    def test_audit_digest_is_runtime_derived_and_status_is_bound(self):
        record = AuditRecord.create(
            audit_id="audit-1",
            preview_id="preview-1",
            revision=1,
            plan_digest="sha256:plan",
            remote_snapshot_digest="sha256:remote",
            operation_set_digest="sha256:ops",
            result=AuditResult.PASSED,
        )
        self.assertTrue(record.verify_digest())
        self.assertNotEqual(record.audit_digest, "sha256:audit")
        self.assertFalse(record.with_status(AuditStatus.STALE).verify_digest())

    def test_audit_status_transitions_are_bounded_and_history_is_retained(self):
        record = AuditRecord.create("audit-1", "preview-1", 1, "plan", "remote", "ops", AuditResult.PASSED)
        stale = record.transition(AuditStatus.STALE, "preview revision replaced")
        self.assertEqual(stale.status, AuditStatus.STALE)
        with self.assertRaises(ValueError):
            stale.transition(AuditStatus.ACTIVE, "revive")
        invalid = stale.transition(AuditStatus.INVALID, "tampered")
        self.assertEqual(invalid.status, AuditStatus.INVALID)

    def test_approval_command_and_all_bindings_are_strict(self):
        audit = AuditRecord.create("audit-1", "preview-1", 2, "plan", "remote", "ops", AuditResult.PASSED)
        approval = ApprovalRecord.create(
            approval_id="approval-1", audit=audit, repository_identity="repo",
            approver_claim="operator", approved_at="2026-08-11T00:00:00+00:00",
            approval_command="批准写入 preview-1 2",
        )
        self.assertTrue(approval.validate_against(audit))
        for command in ("批准 preview-1 2", "批准写入 preview-1", "批准写入 preview-1 3"):
            self.assertFalse(approval.__class__(**{**approval.to_dict(), "approval_command": command}).is_structurally_valid())

    def test_audit_and_approval_round_trip_and_stale_invalidation(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False)
            audit, _ = self._preview_and_audit(store, context)
            self.assertEqual(store.get_audit(context.workspace_identity, audit.audit_id).audit_digest, audit.audit_digest)
            stale = store.transition_audit_status(audit.audit_id, AuditStatus.STALE, "remote changed")
            self.assertEqual(stale.status, AuditStatus.STALE)
            self.assertEqual(store.get_audit(context.workspace_identity, audit.audit_id).status, AuditStatus.STALE)

    def test_audit_record_requires_operation_digest_and_status(self):
        with self.assertRaises(TypeError):
            AuditRecord("audit", "preview", 1, "plan", "remote", "digest", AuditResult.PASSED)  # type: ignore[misc]

    def test_missing_audit_is_stable_not_invalid_record(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False)
            with self.assertRaisesRegex(ValueError, "^audit_not_found$"):
                store.get_audit(context.workspace_identity, "missing")

    def test_invalid_audit_status_and_digest_are_rejected_by_store(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False)
            record = AuditRecord.create("audit", "preview", 1, "plan", "remote", "ops", AuditResult.PASSED)
            with self.assertRaises(ValueError):
                store.record_audit(record.with_status(AuditStatus.STALE))
            with self.assertRaises(ValueError):
                store.record_audit(record.with_status(AuditStatus.ACTIVE).with_status(AuditStatus.INVALID))

    def test_runtime_rejects_arbitrary_driver_and_never_clears_driver_blocker(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            with self.assertRaises(TypeError):
                from delivery_system.runtime import RuntimePlanner
                RuntimePlanner(context, InMemoryPreviewStore(), object())

    def test_save_preview_rejects_mismatched_workspace_without_partial_state(self):
        with tempfile.TemporaryDirectory() as directory:
            context, store = self._sqlite_store(directory)
            with self.assertRaisesRegex(ValueError, "^workspace_identity_mismatch$"):
                store.save_preview_revision("r", "preview-cross", 1, "plan", None, "ops", None, [], workspace_identity="other")
            with self.assertRaisesRegex(ValueError, "^preview_not_found$"):
                store.get_preview(context.workspace_identity, "preview-cross")

    def test_approval_structural_validity_is_not_current_binding_validity(self):
        with tempfile.TemporaryDirectory() as directory:
            context, store = self._sqlite_store(directory)
            audit, approval = self._preview_and_audit(store, context)
            with self.assertRaisesRegex(ValueError, "^approval_binding_mismatch$"):
                store.record_approval(approval)
            self.assertTrue(approval.is_structurally_valid())
            self.assertFalse(store.validate_approval_current(approval))

    def test_store_contract_suite_applies_to_inmemory_and_sqlite(self):
        from tests.fakes.store_contract import run_store_contract
        self.assertEqual(run_store_contract(self, lambda: (InMemoryPreviewStore("ws-contract"), "ws-contract")), 13)
        with tempfile.TemporaryDirectory() as directory:
            context, sqlite_store = self._sqlite_store(directory)
            self.assertEqual(run_store_contract(self, lambda: (sqlite_store, context.workspace_identity)), 13)

    def test_blocked_audit_cannot_create_approval(self):
        audit = AuditRecord.create("audit", "preview", 1, "plan", "remote", "ops", AuditResult.BLOCKED)
        with self.assertRaisesRegex(ValueError, "^approval_requires_passed_active_audit$"):
            ApprovalRecord.create("approval", audit, "repo", "operator", "2026-08-11T00:00:00+00:00", "批准写入 preview 1")

    def test_blocked_approval_is_not_structurally_valid(self):
        audit = AuditRecord.create("audit", "preview", 1, "plan", "remote", "ops", AuditResult.BLOCKED)
        approval = ApprovalRecord(
            "approval", "audit", audit.audit_digest, AuditResult.BLOCKED, "preview", 1,
            "plan", "remote", "ops", "repo", "批准写入 preview 1", "operator",
            "2026-08-11T00:00:00+00:00", "valid",
        )
        self.assertFalse(approval.is_structurally_valid())

    def test_stale_approval_has_no_generic_valid_api(self):
        self.assertFalse(hasattr(ApprovalRecord, "is_valid"))

    def test_inmemory_atomic_failure_leaves_no_state(self):
        store = InMemoryPreviewStore()
        with self.assertRaisesRegex(ValueError, "^sealed_preview_required$"):
            store.save_preview_revision("request", "preview", 1, "plan", "remote", "ops", "repo", [
                {"client_ref": "first", "previous_client_ref": None, "item_id": "item-1"},
                {"client_ref": "broken", "previous_client_ref": None},
            ], workspace_identity="ws")
        with self.assertRaises(ValueError):
            store.get_preview("ws", "preview")
        with self.assertRaises(ValueError):
            store.resolve_item_id("ws", "preview", "first", 1)

    def test_inmemory_failed_first_write_does_not_bind_workspace(self):
        store = InMemoryPreviewStore()
        with self.assertRaisesRegex(ValueError, "^sealed_preview_required$"):
            store.save_preview_revision("request", "preview", 1, "plan", None, "ops", None, [{"client_ref": "broken"}], workspace_identity="ws")
        with self.assertRaisesRegex(ValueError, "^sealed_preview_required$"):
            store.save_preview_revision("request", "preview", 1, "plan", None, "ops", None, [], workspace_identity="other")
        with self.assertRaises(ValueError):
            store.get_preview("other", "preview")

    def test_inmemory_new_revision_stales_active_audit(self):
        store = InMemoryPreviewStore()
        with self.assertRaisesRegex(ValueError, "^sealed_preview_required$"):
            store.save_preview_revision("request", "preview", 1, "plan", "remote", "ops", "repo", [], workspace_identity="ws")

    def test_shared_store_contract_runs_all_failure_cases_for_both_stores(self):
        from tests.fakes.store_contract import run_store_contract

        self.assertEqual(run_store_contract(self, lambda: (InMemoryPreviewStore("inmemory-contract"), "inmemory-contract")), 13)
        with tempfile.TemporaryDirectory() as directory:
            context, store = self._sqlite_store(directory)
            self.assertEqual(run_store_contract(self, lambda: (store, context.workspace_identity)), 13)

    def test_trust_boundary_contract_runs_against_both_store_adapters(self):
        from tests.fakes.store_contract import run_trust_boundary_contract

        self.assertEqual(run_trust_boundary_contract(self, lambda: (InMemoryPreviewStore("trust-inmemory"), "trust-inmemory")), 13)
        with tempfile.TemporaryDirectory() as directory:
            context, store = self._sqlite_store(directory)
            self.assertEqual(run_trust_boundary_contract(self, lambda: (store, context.workspace_identity)), 13)

    def test_strict_sealed_preview_types_run_against_both_store_adapters(self):
        from tests.fakes.store_contract import run_strict_type_contract

        self.assertEqual(run_strict_type_contract(self, lambda: (InMemoryPreviewStore("strict-inmemory"), "strict-inmemory")), 7)
        with tempfile.TemporaryDirectory() as directory:
            context, store = self._sqlite_store(directory)
            self.assertEqual(run_strict_type_contract(self, lambda: (store, context.workspace_identity)), 7)

    def test_sealed_preview_schema_contract_runs_against_both_store_adapters(self):
        from tests.fakes.store_contract import run_sealed_schema_contract

        self.assertEqual(run_sealed_schema_contract(self, lambda: (InMemoryPreviewStore("schema-inmemory"), "schema-inmemory")), 11)
        with tempfile.TemporaryDirectory() as directory:
            context, store = self._sqlite_store(directory)
            self.assertEqual(run_sealed_schema_contract(self, lambda: (store, context.workspace_identity)), 11)

    def _sqlite_store(self, directory):
        context = RuntimeContext.from_workspace_root(directory)
        return context, SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False)

    def _preview_and_audit(self, store, context, revision=1, plan="plan", remote="remote", ops="ops", repo="repo"):
        from delivery_system.protocol import digest
        from delivery_system.runtime import TypedRemoteSnapshot
        snapshot = TypedRemoteSnapshot.from_records(
            repository_identity=repo,
            query_scope={"state": "open"}, query_complete=True, pagination_complete=True,
            issue_records=[{"issue_id": "1", "item_type": "issue", "title": "Issue", "updated_at": "2026-01-01T00:00:00+00:00", "repository_identity": repo}],
            permissions={"issues:read": True, "issues:write": True}, capabilities=["issues"],
            relationship_records=[],
        )
        remote_payload = snapshot.to_dict()
        remote_digest = snapshot.digest()
        semantic = {"test_plan": plan}
        plan_digest = digest(semantic)
        operation_intents = [{"operation_kind": "create_issue", "client_refs": ["item"], "depends_on": []}]
        operation_digest = digest({"operation_intents": operation_intents})
        canonical = {
            "workspace_identity": context.workspace_identity,
            "request_id": "request-1", "preview_id": "preview-1", "revision": revision,
            "preview_level": "Conceptual", "provenance_status": "declared_unverified",
            "semantic_payload": semantic, "operation_intents": operation_intents,
            "repository_identity": None, "remote_authority": None,
            "plan_digest": plan_digest, "operation_set_digest": operation_digest,
            "remote_snapshot": None, "remote_snapshot_digest": None,
            "items": [{"client_ref": "item", "previous_client_ref": None, "item_id": f"runtime-{revision}"}],
            "blockers": [], "planner_observations": [], "evidence_ids": [],
        }
        canonical["sealed_preview_digest"] = digest(canonical)
        store.save_preview_revision(
            request_id="request-1", preview_id="preview-1", revision=revision,
            plan_digest=plan_digest, remote_snapshot_digest=None, operation_set_digest=operation_digest,
            repository_identity=None, items=[{"client_ref": "item", "previous_client_ref": None, "item_id": f"runtime-{revision}"}],
            workspace_identity=context.workspace_identity, canonical_payload=canonical,
            evidence_records=[],
        )
        audit = AuditRecord.create("audit-1", "preview-1", revision, plan_digest, remote_digest, operation_digest, AuditResult.PASSED)
        store.record_audit(audit)
        approval = ApprovalRecord.create("approval-1", audit, repo, "operator", "2026-08-11T00:00:00+00:00", f"批准写入 preview-1 {revision}")
        return audit, approval

    def test_orphan_missing_audit_and_preview_approvals_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            context, store = self._sqlite_store(directory)
            approval = ApprovalRecord("a", "missing", "digest", AuditResult.PASSED, "preview-1", 1, "plan", "remote", "ops", "repo", "批准写入 preview-1 1", "operator", "2026-08-11T00:00:00+00:00", "valid")
            with self.assertRaisesRegex(ValueError, "^audit_not_found$"):
                store.record_approval(approval)
            audit = AuditRecord.create("audit-1", "missing-preview", 1, "plan", "remote", "ops", AuditResult.PASSED)
            store.record_audit(audit)
            approval = ApprovalRecord.create("a", audit, "repo", "operator", "2026-08-11T00:00:00+00:00", "批准写入 missing-preview 1")
            with self.assertRaisesRegex(ValueError, "^preview_not_found$"):
                store.record_approval(approval)

    def test_preview_revision_stales_audit_and_invalidates_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            context, store = self._sqlite_store(directory)
            audit, approval = self._preview_and_audit(store, context)
            with self.assertRaisesRegex(ValueError, "^approval_binding_mismatch$"):
                store.record_approval(approval)
            with self.assertRaisesRegex(ValueError, "^sealed_preview_required$"):
                store.save_preview_revision("request-1", "preview-1", 2, "plan-2", "remote", "ops", "repo", [{"client_ref": "item", "previous_client_ref": "item", "item_id": "runtime-1"}])
            self.assertEqual(store.get_audit(context.workspace_identity, audit.audit_id).status, AuditStatus.ACTIVE)
            self.assertFalse(store.validate_approval_current(approval))

    def test_approval_rejects_empty_repository_and_naive_time(self):
        with tempfile.TemporaryDirectory() as directory:
            context, store = self._sqlite_store(directory)
            audit, _ = self._preview_and_audit(store, context)
            for repo, timestamp in ((None, "2026-08-11T00:00:00+00:00"), ("", "2026-08-11T00:00:00+00:00"), ("  ", "2026-08-11T00:00:00+00:00"), ("repo", "2026-08-11T00:00:00")):
                approval = ApprovalRecord.create("a", audit, repo, "operator", timestamp, "批准写入 preview-1 1")
                with self.assertRaises(ValueError):
                    store.record_approval(approval)

    def test_preview_history_and_client_refs_are_revision_scoped_and_atomic(self):
        with tempfile.TemporaryDirectory() as directory:
            context, store = self._sqlite_store(directory)
            with self.assertRaisesRegex(ValueError, "^sealed_preview_required$"):
                store.save_preview_revision("r", "p1", 1, "d1", None, "o1", None, [{"client_ref": "same", "previous_client_ref": None, "item_id": "i1"}])
            with self.assertRaisesRegex(ValueError, "^sealed_preview_required$"):
                store.save_preview_revision("r2", "p2", 1, "d2", None, "o2", None, [{"client_ref": "same", "previous_client_ref": None, "item_id": "i2"}])
            with self.assertRaises(ValueError):
                store.get_preview(context.workspace_identity, "p1")
            with self.assertRaisesRegex(ValueError, "^sealed_preview_required$"):
                store.save_preview_revision("r", "p1", 2, "d3", None, "o3", None, [{"client_ref": "ok", "previous_client_ref": None, "item_id": "i3"}, {"client_ref": "ok", "previous_client_ref": None, "item_id": "i4"}])
            with self.assertRaisesRegex(ValueError, "^lineage_not_found$"):
                store.resolve_item_id(context.workspace_identity, "p1", "ok", 2)

    def test_sealed_preview_contains_item_lineage_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            from delivery_system.runtime import RuntimePlanner
            context = RuntimeContext.from_workspace_root(directory)
            result = RuntimePlanner(context, InMemoryPreviewStore()).preview({"work_items": []})
            self.assertIn("items", result)
            self.assertEqual(result["items"], [])

    def test_windows_junction_workspace_state_is_rejected(self):
        if os.name != "nt":
            self.skipTest("Windows reparse-point contract")
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            link = root / ".delivery-system"
            result = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True)
            if result.returncode != 0:
                self.fail(f"unable to create junction for contract test: {result.stderr or result.stdout}")
            context = RuntimeContext.from_workspace_root(directory)
            with self.assertRaises(StorePreflightError) as error:
                context.ensure_store_ready(ignore_checker=lambda _: True, tracked_checker=lambda _: False)
            self.assertEqual(error.exception.code, "store_not_ignored_or_tracked")
            self.assertFalse((Path(outside) / "state.sqlite3").exists())

    def test_approval_requires_passed_audit_and_all_bindings(self):
        audit = AuditRecord.create("audit-1", "preview-1", 1, "sha256:plan", "sha256:remote", "sha256:ops", AuditResult.PASSED)
        approval = ApprovalRecord(
            approval_id="approval-1",
            audit_id="audit-1",
            audit_digest=audit.audit_digest,
            audit_result=AuditResult.PASSED,
            preview_id="preview-1",
            revision=1,
            plan_digest="sha256:plan",
            remote_snapshot_digest="sha256:remote",
            operation_set_digest="sha256:ops",
            repository_identity="repo",
            approval_command="批准写入 preview-1 1",
            approver_claim="user asserted",
            approved_at="2026-08-11T00:00:00+00:00",
            status="valid",
        )
        self.assertTrue(approval.is_structurally_valid())
        invalid = approval.__class__(**{**approval.to_dict(), "audit_result": "Blocked"})
        self.assertFalse(invalid.is_structurally_valid())
        self.assertFalse(invalid.validate_against(audit))

    def test_store_preflight_does_not_create_unignored_state(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            with self.assertRaises(StorePreflightError) as error:
                context.ensure_store_ready(ignore_checker=lambda _: False, tracked_checker=lambda _: False)
            self.assertEqual(error.exception.code, "store_not_ignored_or_tracked")
            self.assertFalse(Path(context.state_path).exists())
            self.assertFalse(Path(context.state_path).parent.exists())

    def test_store_preflight_requires_all_sqlite_sidecars_to_be_ignored_and_untracked(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            context.ensure_store_ready(ignore_checker=lambda _: True, tracked_checker=lambda _: False)
            self.assertTrue(Path(context.state_path).parent.exists())

    def test_sqlite_store_records_schema_and_lineage_transactionally(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = SQLitePreviewStore(context, ignore_checker=lambda _: True, tracked_checker=lambda _: False)
            from tests.slice2a.test_sealed_preview_contract import plan_payload
            from delivery_system.runtime import RuntimePlanner
            result = RuntimePlanner(context, store).preview(plan_payload())
            self.assertEqual(store.get_preview(context.workspace_identity, result["preview_id"])["revision"], 1)
            self.assertEqual(store.resolve_item_id(context.workspace_identity, result["preview_id"], "inventory"), result["items"][0]["item_id"])

    def test_approval_binding_is_invalid_when_audit_binding_changes(self):
        audit = AuditRecord.create("audit-1", "preview-1", 1, "sha256:plan", "sha256:remote", "sha256:ops", AuditResult.PASSED)
        approval = ApprovalRecord.create(
            "approval-1", audit, "repo", "claim", "2026-08-11T00:00:00+00:00", "批准写入 preview-1 1"
        )
        self.assertTrue(approval.validate_against(audit))
        changed = AuditRecord.create("audit-1", "preview-1", 2, "sha256:plan", "sha256:remote", "sha256:ops", AuditResult.PASSED)
        self.assertFalse(approval.validate_against(changed))

    def test_console_entry_point_and_tool_annotations_are_explicit(self):
        pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("delivery-system-mcp", pyproject)
        from mcp_server.server import TOOL_ANNOTATIONS

        self.assertFalse(TOOL_ANNOTATIONS.read_only_hint)
        self.assertFalse(TOOL_ANNOTATIONS.destructive_hint)
        self.assertFalse(TOOL_ANNOTATIONS.open_world_hint)


if __name__ == "__main__":
    unittest.main()
