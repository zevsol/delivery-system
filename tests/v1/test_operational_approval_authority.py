from __future__ import annotations

from copy import copy, deepcopy
from datetime import datetime, timezone
import tempfile
import unittest
from dataclasses import replace
from unittest.mock import patch

from delivery_system.application_authority import ApplicationAuthority
from delivery_system.attestation import AttestationRuntimeBoundary
from delivery_system.attestation_runtime import RuntimeAttestationOrchestrationService
from delivery_system.auditor import RuleEvaluationDraft, RuntimeAuditor
from delivery_system.audit_state import AuditResult, AuditStatus
from delivery_system.audit_state import ApprovalRecord
from delivery_system.drivers.contract import DriverTrustContext
from delivery_system.runtime import (
    InMemoryPreviewStore, RuntimeApprovalAuthorityService, RuntimeContext, RuntimePlanner,
    SQLitePreviewStore,
)
from delivery_system.rules import SemanticOutcome, build_registry_v1
from tests.attestation_contract.test_attestation_contract import FakeCapabilityPolicy, FakeIssuer
from tests.attestation_orchestration.test_attestation_orchestration import FakeReadOnlyDriver
from tests.fakes.attestation_provider import FakeCapabilityResolver, FakeCredentialCapabilityProvider
from tests.local_rest_offline.test_repository_aware_runtime import plan as base_plan


TRUST = DriverTrustContext("fixture-driver", "offline://fixture", "fixture-v1")
NOW = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)


def plan() -> dict[str, object]:
    result = base_plan()
    result["operation_intents"] = [{
        "operation_kind": "create_issue", "client_refs": ["item"], "depends_on": [],
    }]
    return result


class OperationalApprovalAuthorityTests(unittest.TestCase):
    def _setup(self, kind: str):
        directory = tempfile.TemporaryDirectory()
        context = RuntimeContext.from_workspace_root(directory.name)
        if kind == "memory":
            store = InMemoryPreviewStore(context.workspace_identity, TRUST)
        else:
            store = SQLitePreviewStore(
                context, ignore_checker=lambda path: True,
                tracked_checker=lambda path: False, trust_context=TRUST,
            )
        preview = RuntimePlanner(context, store, FakeReadOnlyDriver(node_id="node-1"), TRUST).preview(plan())
        auditor = RuntimeAuditor(context, store, build_registry_v1(), TRUST)
        audit_context = auditor.get_context(preview["preview_id"], 1)
        evaluations = [
            RuleEvaluationDraft(rule["rule_id"], rule["rule_version"], SemanticOutcome.PASSED, "verified")
            for rule in audit_context["semantic_rule_contexts"] if rule["applicability"] == "Applicable"
        ]
        audit = auditor.record_audit(preview["preview_id"], 1, audit_context["audit_context_digest"], evaluations, [])
        issuer = FakeIssuer()
        attestation = RuntimeAttestationOrchestrationService(
            context, store, TRUST,
            AttestationRuntimeBoundary(issuer, issuer, issuer, FakeCapabilityPolicy()),
            FakeCredentialCapabilityProvider(), FakeCapabilityResolver(), clock=lambda: NOW,
        )
        service = RuntimeApprovalAuthorityService(context, store, attestation, clock=lambda: NOW)
        return directory, context, store, preview, audit, service

    def test_exact_approval_is_persisted_and_replayed_with_original_time(self):
        for kind in ("memory", "sqlite"):
            with self.subTest(store=kind):
                directory, context, store, preview, audit, service = self._setup(kind)
                try:
                    command = f"批准写入 {preview['preview_id']} 1"
                    first = service.record_approval(preview["preview_id"], 1, command, "  human-1  ")
                    replay = service.record_approval(preview["preview_id"], 1, command, "human-1")
                    self.assertEqual(first, replay)
                    self.assertEqual(first.approved_at, "2026-08-14T12:00:00Z")
                    self.assertTrue(store.validate_approval_current(first))
                    with self.assertRaisesRegex(ValueError, "^approval_binding_conflict$"):
                        service.record_approval(preview["preview_id"], 1, command, "other-human")
                finally:
                    directory.cleanup()

    def test_invalid_command_claim_and_conflict_fail_closed(self):
        directory, context, store, preview, audit, service = self._setup("memory")
        try:
            with self.assertRaisesRegex(ValueError, "^approval_command_invalid$"):
                service.record_approval(preview["preview_id"], 1, f"批准写入 {preview['preview_id']} 1 ", "human")
            with self.assertRaisesRegex(ValueError, "^approval_invalid$"):
                service.record_approval(preview["preview_id"], 1, f"批准写入 {preview['preview_id']} 1", "  ")
            command = f"批准写入 {preview['preview_id']} 1"
            service.record_approval(preview["preview_id"], 1, command, "human")
            with self.assertRaisesRegex(ValueError, "^approval_binding_conflict$"):
                service.record_approval(preview["preview_id"], 1, command, "different")
        finally:
            directory.cleanup()

    def test_approval_requires_unique_passed_active_write_eligible_audit(self):
        directory, context, store, preview, audit, service = self._setup("memory")
        try:
            store._audits[(context.workspace_identity, "extra")] = audit
            with self.assertRaisesRegex(ValueError, "^approval_audit_ambiguous$"):
                service.record_approval(preview["preview_id"], 1, f"批准写入 {preview['preview_id']} 1", "human")
        finally:
            directory.cleanup()

    def test_authority_is_immutable_idempotent_and_current(self):
        directory, context, store, preview, audit, service = self._setup("memory")
        try:
            command = f"批准写入 {preview['preview_id']} 1"
            approval = service.record_approval(preview["preview_id"], 1, command, "human")
            first = service.issue_application_authority(preview["preview_id"], 1, approval.approval_id)
            second = service.issue_application_authority(preview["preview_id"], 1, approval.approval_id)
            self.assertIs(first, second)
            self.assertTrue(service.validate_application_authority(first))
            with self.assertRaisesRegex(ValueError, "^application_authority_internal_only$"):
                ApplicationAuthority()
            with self.assertRaisesRegex(ValueError, "^application_authority_immutable$"):
                first.preview_id = "other"
            with self.assertRaisesRegex(ValueError, "^application_authority_copy_forbidden$"):
                copy(first)
            with self.assertRaisesRegex(ValueError, "^application_authority_copy_forbidden$"):
                deepcopy(first)
        finally:
            directory.cleanup()

    def test_authority_happy_path_is_available_for_both_stores(self):
        for kind in ("memory", "sqlite"):
            with self.subTest(store=kind):
                directory, context, store, preview, audit, service = self._setup(kind)
                try:
                    command = f"批准写入 {preview['preview_id']} 1"
                    approval = service.record_approval(preview["preview_id"], 1, command, "human")
                    authority = service.issue_application_authority(preview["preview_id"], 1, approval.approval_id)
                    self.assertEqual(authority.workspace_identity, context.workspace_identity)
                    self.assertEqual(authority.audit_id, audit.audit_id)
                    self.assertIn("issues:write", authority.required_capabilities)
                    self.assertIn("issues:write", authority.granted_capabilities)
                    self.assertTrue(service.validate_application_authority(authority))
                finally:
                    directory.cleanup()

    def test_authority_rejects_missing_approval_and_stale_preview(self):
        directory, context, store, preview, audit, service = self._setup("memory")
        try:
            with self.assertRaisesRegex(ValueError, "^approval_binding_mismatch$"):
                service.issue_application_authority(preview["preview_id"], 1, "approval-missing")
            command = f"批准写入 {preview['preview_id']} 1"
            approval = service.record_approval(preview["preview_id"], 1, command, "human")
            changed = dict(plan())
            changed["operation_intents"] = []
            RuntimePlanner(context, store, FakeReadOnlyDriver(node_id="node-1"), TRUST).preview(
                changed, preview["preview_id"]
            )
            with self.assertRaisesRegex(ValueError, "^(preview_stale|audit_stale)$"):
                service.issue_application_authority(preview["preview_id"], 1, approval.approval_id)
        finally:
            directory.cleanup()

    def test_forged_or_unregistered_authority_is_rejected(self):
        directory, context, store, preview, audit, service = self._setup("memory")
        try:
            command = f"批准写入 {preview['preview_id']} 1"
            approval = service.record_approval(preview["preview_id"], 1, command, "human")
            authority = service.issue_application_authority(preview["preview_id"], 1, approval.approval_id)
            forged = object.__new__(ApplicationAuthority)
            self.assertFalse(service.validate_application_authority(forged))
            self.assertTrue(service.validate_application_authority(authority))
        finally:
            directory.cleanup()

    def test_binding_and_authority_tampering_fail_closed(self):
        directory, context, store, preview, audit, service = self._setup("memory")
        try:
            command = f"批准写入 {preview['preview_id']} 1"
            approval = service.record_approval(preview["preview_id"], 1, command, "human")
            authority = service.issue_application_authority(preview["preview_id"], 1, approval.approval_id)
            binding = service.attestation_service.resolve_registered_binding(authority.credential_binding_id)
            object.__setattr__(binding, "repository_identity", "other/repository")
            self.assertFalse(service.validate_application_authority(authority))
            object.__setattr__(binding, "repository_identity", "owner/repo")
            object.__setattr__(authority, "operation_set_digest", "sha256:" + "0" * 64)
            self.assertFalse(service.validate_application_authority(authority))
        finally:
            directory.cleanup()

    def test_stale_audit_cannot_issue_authority(self):
        directory, context, store, preview, audit, service = self._setup("memory")
        try:
            command = f"批准写入 {preview['preview_id']} 1"
            approval = service.record_approval(preview["preview_id"], 1, command, "human")
            store.transition_audit_status(audit.audit_id, AuditStatus.STALE, "test")
            with self.assertRaisesRegex(ValueError, "^audit_not_found$"):
                service.issue_application_authority(preview["preview_id"], 1, approval.approval_id)
        finally:
            directory.cleanup()

    def test_wrong_preview_revision_workspace_and_capability_fail_closed(self):
        directory, context, store, preview, audit, service = self._setup("memory")
        try:
            command = f"批准写入 {preview['preview_id']} 1"
            approval = service.record_approval(preview["preview_id"], 1, command, "human")
            with self.assertRaisesRegex(ValueError, "^preview_stale$"):
                service.issue_application_authority(preview["preview_id"], 2, approval.approval_id)
            with self.assertRaisesRegex(ValueError, "^preview_not_found$"):
                service.issue_application_authority("other-preview", 1, approval.approval_id)
            service.attestation_service._RuntimeAttestationOrchestrationService__resolver = FakeCapabilityResolver(("issues:read",))
            with self.assertRaisesRegex(ValueError, "^credential_capability_insufficient$"):
                service.issue_application_authority(preview["preview_id"], 1, approval.approval_id)
        finally:
            directory.cleanup()

    def test_expired_binding_is_rejected(self):
        directory, context, store, preview, audit, service = self._setup("memory")
        try:
            command = f"批准写入 {preview['preview_id']} 1"
            approval = service.record_approval(preview["preview_id"], 1, command, "human")
            service.clock = lambda: datetime(2026, 8, 14, 14, 0, tzinfo=timezone.utc)
            with self.assertRaisesRegex(ValueError, "^credential_binding_mismatch$"):
                service.issue_application_authority(preview["preview_id"], 1, approval.approval_id)
        finally:
            directory.cleanup()

    def test_sqlite_direct_duplicate_is_idempotent_and_conflict_is_normalized(self):
        directory, context, store, preview, audit, service = self._setup("sqlite")
        try:
            command = f"批准写入 {preview['preview_id']} 1"
            approval = service.record_approval(preview["preview_id"], 1, command, "human")
            store.record_approval(approval)
            self.assertEqual(store.get_approval(context.workspace_identity, approval.approval_id).to_dict(), approval.to_dict())
            conflicting = replace(approval, approver_claim="other-human")
            with self.assertRaisesRegex(ValueError, "^approval_binding_conflict$"):
                store.record_approval(conflicting)
            self.assertEqual(store.get_approval(context.workspace_identity, approval.approval_id).to_dict(), approval.to_dict())
        finally:
            directory.cleanup()

    def test_identical_stale_approval_replay_fails_for_both_stores(self):
        for kind in ("memory", "sqlite"):
            with self.subTest(store=kind):
                directory, context, store, preview, audit, service = self._setup(kind)
                try:
                    command = f"批准写入 {preview['preview_id']} 1"
                    approval = service.record_approval(preview["preview_id"], 1, command, "human")
                    changed = plan()
                    changed["operation_intents"] = []
                    RuntimePlanner(context, store, FakeReadOnlyDriver(node_id="node-1"), TRUST).preview(
                        changed, preview["preview_id"]
                    )
                    with self.assertRaisesRegex(ValueError, "^(preview_stale|audit_not_found|approval_stale)$"):
                        service.record_approval(preview["preview_id"], 1, command, "human")
                    self.assertFalse(store.validate_approval_current(approval))
                    self.assertEqual(store.get_approval(context.workspace_identity, approval.approval_id), approval)
                finally:
                    directory.cleanup()

    def test_cross_workspace_approval_is_rejected(self):
        directory, context, store, preview, audit, service = self._setup("memory")
        other_directory = tempfile.TemporaryDirectory()
        try:
            command = f"批准写入 {preview['preview_id']} 1"
            approval = service.record_approval(preview["preview_id"], 1, command, "human")
            other_context = RuntimeContext.from_workspace_root(other_directory.name)
            other_store = InMemoryPreviewStore(other_context.workspace_identity, TRUST)
            with self.assertRaisesRegex(ValueError, "^approval_binding_mismatch$"):
                other_store.record_approval(approval)
        finally:
            directory.cleanup()
            other_directory.cleanup()

    def test_approval_record_round_trip_and_strict_loader(self):
        directory, context, store, preview, audit, service = self._setup("memory")
        try:
            command = f"批准写入 {preview['preview_id']} 1"
            approval = service.record_approval(preview["preview_id"], 1, command, "human")
            self.assertEqual(ApprovalRecord.from_dict(approval.to_dict()).to_dict(), approval.to_dict())
            missing = approval.to_dict()
            del missing["status"]
            with self.assertRaisesRegex(ValueError, "^approval_invalid$"):
                ApprovalRecord.from_dict(missing)
            extra = approval.to_dict()
            extra["unexpected"] = True
            with self.assertRaisesRegex(ValueError, "^approval_invalid$"):
                ApprovalRecord.from_dict(extra)
        finally:
            directory.cleanup()

    def test_authority_rejects_substituted_approval_and_audit(self):
        directory, context, store, preview, audit, service = self._setup("memory")
        try:
            command = f"批准写入 {preview['preview_id']} 1"
            approval = service.record_approval(preview["preview_id"], 1, command, "human")
            authority = service.issue_application_authority(preview["preview_id"], 1, approval.approval_id)
            key = next(key for key in store._approvals if key[1] == approval.approval_id)
            store._approvals[key] = replace(approval, approver_claim="substituted")
            self.assertFalse(service.validate_application_authority(authority))
            store._approvals[key] = approval
            store.transition_audit_status(audit.audit_id, AuditStatus.STALE, "test")
            self.assertFalse(service.validate_application_authority(authority))
        finally:
            directory.cleanup()

    def test_forged_deterministic_looking_authority_is_unregistered(self):
        directory, context, store, preview, audit, service = self._setup("memory")
        try:
            command = f"批准写入 {preview['preview_id']} 1"
            approval = service.record_approval(preview["preview_id"], 1, command, "human")
            authority = service.issue_application_authority(preview["preview_id"], 1, approval.approval_id)
            forged = object.__new__(ApplicationAuthority)
            for field, value in authority.to_dict().items():
                object.__setattr__(forged, field, value)
            self.assertFalse(service.validate_application_authority(forged))
        finally:
            directory.cleanup()

    def test_missing_granted_issue_write_is_insufficient(self):
        directory, context, store, preview, audit, service = self._setup("memory")
        try:
            command = f"批准写入 {preview['preview_id']} 1"
            approval = service.record_approval(preview["preview_id"], 1, command, "human")
            original = service.attestation_service.resolve_registered_binding
            def without_grant(binding_id):
                binding = original(binding_id)
                object.__setattr__(binding, "granted_capabilities", ())
                return binding
            with patch.object(service.attestation_service, "resolve_registered_binding", side_effect=without_grant):
                with self.assertRaisesRegex(ValueError, "^credential_capability_insufficient$"):
                    service.issue_application_authority(preview["preview_id"], 1, approval.approval_id)
        finally:
            directory.cleanup()

    def test_expiry_equality_is_rejected(self):
        directory, context, store, preview, audit, service = self._setup("memory")
        try:
            command = f"批准写入 {preview['preview_id']} 1"
            approval = service.record_approval(preview["preview_id"], 1, command, "human")
            service.clock = lambda: datetime(2026, 8, 14, 13, 0, tzinfo=timezone.utc)
            with self.assertRaisesRegex(ValueError, "^credential_binding_mismatch$"):
                service.issue_application_authority(preview["preview_id"], 1, approval.approval_id)
        finally:
            directory.cleanup()

    def test_authority_rejects_operation_remote_and_binding_substitution(self):
        directory, context, store, preview, audit, service = self._setup("memory")
        try:
            command = f"批准写入 {preview['preview_id']} 1"
            approval = service.record_approval(preview["preview_id"], 1, command, "human")
            authority = service.issue_application_authority(preview["preview_id"], 1, approval.approval_id)
            for field in ("operation_set_digest", "remote_snapshot_digest", "repository_identity"):
                original = getattr(authority, field)
                object.__setattr__(authority, field, "tampered-" + field)
                self.assertFalse(service.validate_application_authority(authority), field)
                object.__setattr__(authority, field, original)
            binding = service.attestation_service.resolve_registered_binding(authority.credential_binding_id)
            replacements = {
                "workspace_identity": "tampered-workspace",
                "repository_identity": "tampered/repository",
                "preview_id": "tampered-preview",
                "revision": 99,
                "plan_digest": "tampered-plan",
                "sealed_preview_digest": "tampered-sealed",
                "operation_set_digest": "tampered-operation",
                "remote_snapshot_digest": "tampered-remote",
                "audit_id": "tampered-audit",
                "audit_digest": "tampered-audit-digest",
            }
            for field, replacement in replacements.items():
                original = getattr(binding, field)
                object.__setattr__(binding, field, replacement)
                self.assertFalse(service.validate_application_authority(authority), field)
                object.__setattr__(binding, field, original)
        finally:
            directory.cleanup()


if __name__ == "__main__":
    unittest.main()
