from __future__ import annotations

from copy import copy, deepcopy
import base64
from contextlib import closing
from datetime import datetime, timezone
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from unittest.mock import patch

from delivery_system.application_authority import ApplicationAuthority
from delivery_system.attestation import AttestationRuntimeBoundary
from delivery_system.attestation_runtime import RuntimeAttestationOrchestrationService
from delivery_system.attestation_persistence_store import InMemoryAttestationPersistenceStore
from delivery_system.authority_binding import AUTHORITY_BINDING_SIGNATURE_ALGORITHM
from delivery_system.authority_binding_persistence import InMemoryAuthorityBindingPersistenceStore
from delivery_system.auditor import RuleEvaluationDraft, RuntimeAuditor
from delivery_system.audit_state import AuditResult, AuditStatus
from delivery_system.audit_state import ApprovalRecord
from delivery_system.drivers.contract import DriverTrustContext
from delivery_system.runtime import (
    InMemoryPreviewStore, RuntimeApprovalAuthorityService, RuntimeContext, RuntimePlanner,
    SQLitePreviewStore,
)
from delivery_system.verified_attestation_artifact import VerifiedAttestationArtifactAdapter
from delivery_system.rules import RuleRegistry, SemanticOutcome, build_registry_v1
from tests.attestation_contract.test_attestation_contract import FakeCapabilityPolicy, FakeIssuer
from tests.attestation_orchestration.test_attestation_orchestration import FakeReadOnlyDriver
from tests.fakes.attestation_provider import FakeCapabilityResolver, FakeCredentialCapabilityProvider
from tests.local_rest_offline.test_repository_aware_runtime import plan as base_plan


TRUST = DriverTrustContext("fixture-driver", "offline://fixture", "fixture-v1")
NOW = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)


class TestAuthorityBindingSigner:
    issuer_id = "test-authority-issuer"
    key_id = "test-authority-key"
    signature_algorithm = AUTHORITY_BINDING_SIGNATURE_ALGORITHM
    proof = base64.urlsafe_b64encode(bytes(range(64))).decode("ascii").rstrip("=")

    def __init__(self) -> None:
        self.calls = 0

    def sign_authority_binding(self, canonical_payload_bytes: bytes) -> str:
        self.calls += 1
        return self.proof


def i3b_dependencies(workspace_identity: str):
    artifact_store = InMemoryAttestationPersistenceStore()
    artifact_adapter = VerifiedAttestationArtifactAdapter(
        artifact_store,
        clock=lambda: NOW.replace(minute=1),
    )
    signer = TestAuthorityBindingSigner()
    binding_store = InMemoryAuthorityBindingPersistenceStore(
        workspace_identity=workspace_identity,
    )
    return artifact_adapter, signer, binding_store


def plan() -> dict[str, object]:
    result = base_plan()
    result["operation_intents"] = [{
        "operation_kind": "create_issue", "client_refs": ["item"], "depends_on": [],
    }]
    return result


def legacy_registry() -> RuleRegistry:
    current = build_registry_v1()
    return RuleRegistry(current.registry_version, tuple(
        replace(rule, rule_version="1.0") if rule.rule_id in {
            "SEM-WORK-ITEM-DECOMPOSITION", "SEM-PARENT-SUBISSUE"
        } else rule for rule in current.rules
    ))


class OperationalApprovalAuthorityTests(unittest.TestCase):
    def _setup(self, kind: str, *, audit_registry=None, service_registry=None):
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
        audit_registry = audit_registry or build_registry_v1()
        service_registry = service_registry or build_registry_v1()
        auditor = RuntimeAuditor(context, store, audit_registry, TRUST)
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
        artifact_adapter, signer, binding_store = i3b_dependencies(context.workspace_identity)
        service = RuntimeApprovalAuthorityService(
            context, store, attestation, clock=lambda: NOW,
            artifact_link_adapter=artifact_adapter,
            authority_binding_signer=signer,
            authority_binding_store=binding_store,
            rule_registry=service_registry,
        )
        return directory, context, store, preview, audit, service

    @staticmethod
    def _with_registry(service, registry):
        return RuntimeApprovalAuthorityService(
            service.context, service.store, service.attestation_service,
            clock=service.clock,
            artifact_link_adapter=service._artifact_link_adapter,
            authority_binding_signer=service._authority_binding_signer,
            authority_binding_store=service._authority_binding_store,
            rule_registry=registry,
        )

    def test_old_policy_audit_is_historical_but_cannot_create_new_approval(self):
        directory, context, store, preview, audit, service = self._setup(
            "memory", audit_registry=legacy_registry(), service_registry=build_registry_v1(),
        )
        try:
            self.assertTrue(audit.verify_digest())
            with self.assertRaisesRegex(ValueError, "^audit_stale$"):
                service.record_approval(
                    preview["preview_id"], 1,
                    f"批准写入 {preview['preview_id']} 1", "human",
                )
            self.assertTrue(audit.verify_digest())
            self.assertEqual(store.list_active_audits(context.workspace_identity, preview["preview_id"], 1)[0], audit)
        finally:
            directory.cleanup()

    def test_existing_old_policy_approval_replays_under_new_registry(self):
        directory, context, store, preview, audit, old_service = self._setup(
            "memory", audit_registry=legacy_registry(), service_registry=legacy_registry(),
        )
        try:
            command = f"批准写入 {preview['preview_id']} 1"
            approval = old_service.record_approval(preview["preview_id"], 1, command, "human")
            new_service = self._with_registry(old_service, build_registry_v1())
            replayed = new_service.record_approval(preview["preview_id"], 1, command, "human")
            self.assertEqual(replayed, approval)
            authority = new_service.issue_application_authority(
                preview["preview_id"], 1, replayed.approval_id,
            )
            self.assertEqual(authority.approval_id, approval.approval_id)
        finally:
            directory.cleanup()

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

    def test_approval_status_returns_current_or_no_current_approval_for_both_stores(self):
        for kind in ("memory", "sqlite"):
            with self.subTest(store=kind):
                directory, context, store, preview, audit, service = self._setup(kind)
                try:
                    missing = service.get_approval_status(preview["preview_id"], 1)
                    self.assertEqual(missing["status"], "NO_CURRENT_APPROVAL")
                    self.assertIsNone(missing["approval"])
                    command = f"批准写入 {preview['preview_id']} 1"
                    approval = service.record_approval(preview["preview_id"], 1, command, "human")
                    current = service.get_approval_status(preview["preview_id"], 1)
                    self.assertEqual(current["status"], "CURRENT")
                    self.assertEqual(current["approval"], approval.to_dict())
                finally:
                    directory.cleanup()

    def test_approval_status_rejects_invalid_inputs_and_preserves_target_errors(self):
        directory, context, store, preview, audit, service = self._setup("memory")
        try:
            for preview_id, revision in (("", 1), (True, 1), (preview["preview_id"], True), (preview["preview_id"], 0)):
                with self.subTest(preview_id=preview_id, revision=revision):
                    with self.assertRaisesRegex(ValueError, "^approval_invalid$"):
                        service.get_approval_status(preview_id, revision)
            with self.assertRaisesRegex(ValueError, "^preview_not_found$"):
                service.get_approval_status("missing-preview", 1)
            with self.assertRaisesRegex(ValueError, "^preview_stale$"):
                service.get_approval_status(preview["preview_id"], 2)
            store._audits[(context.workspace_identity, "extra")] = audit
            with self.assertRaisesRegex(ValueError, "^approval_audit_ambiguous$"):
                service.get_approval_status(preview["preview_id"], 1)
        finally:
            directory.cleanup()

    def test_approval_status_rejects_malformed_or_stale_approval(self):
        directory, context, store, preview, audit, service = self._setup("memory")
        try:
            command = f"批准写入 {preview['preview_id']} 1"
            approval = service.record_approval(preview["preview_id"], 1, command, "human")
            key = next(key for key in store._approvals if key[1] == approval.approval_id)
            store._approvals[key] = replace(approval, status="invalid")
            with self.assertRaisesRegex(ValueError, "^approval_invalid$"):
                service.get_approval_status(preview["preview_id"], 1)
            store._approvals[key] = replace(approval, repository_identity="other/repository")
            with self.assertRaisesRegex(ValueError, "^approval_stale$"):
                service.get_approval_status(preview["preview_id"], 1)
        finally:
            directory.cleanup()

    def test_approval_status_rejects_embedded_approval_id_mismatch(self):
        directory, context, store, preview, audit, service = self._setup("memory")
        try:
            command = f"批准写入 {preview['preview_id']} 1"
            approval = service.record_approval(preview["preview_id"], 1, command, "human")
            key = next(key for key in store._approvals if key[1] == approval.approval_id)
            corrupted = replace(approval, approval_id="approval-corrupted-payload-id")
            self.assertNotEqual(corrupted.approval_id, key[1])
            store._approvals[key] = corrupted
            with self.assertRaisesRegex(ValueError, "^approval_invalid$"):
                service.get_approval_status(preview["preview_id"], 1)
        finally:
            directory.cleanup()

    def test_recreated_empty_inmemory_store_returns_preview_not_found(self):
        directory, context, store, preview, audit, service = self._setup("memory")
        try:
            recreated_store = InMemoryPreviewStore(context.workspace_identity, TRUST)
            recreated_service = RuntimeApprovalAuthorityService(
                context,
                recreated_store,
                None,
                clock=lambda: NOW,
                rule_registry=build_registry_v1(),
            )
            with self.assertRaisesRegex(ValueError, "^preview_not_found$"):
                recreated_service.get_approval_status(preview["preview_id"], 1)
        finally:
            directory.cleanup()

    def test_approval_status_does_not_project_old_audit_approval_for_new_audit(self):
        directory, context, store, preview, audit, service = self._setup("memory")
        try:
            command = f"批准写入 {preview['preview_id']} 1"
            old_approval = service.record_approval(preview["preview_id"], 1, command, "human")
            store.transition_audit_status(audit.audit_id, AuditStatus.STALE, "re-audit")
            auditor = RuntimeAuditor(context, store, build_registry_v1(), TRUST)
            audit_context = auditor.get_context(preview["preview_id"], 1)
            evaluations = [
                RuleEvaluationDraft(
                    rule["rule_id"], rule["rule_version"], SemanticOutcome.PASSED, "re-audited",
                )
                for rule in audit_context["semantic_rule_contexts"] if rule["applicability"] == "Applicable"
            ]
            new_audit = auditor.record_audit(
                preview["preview_id"], 1, audit_context["audit_context_digest"], evaluations, [],
            )
            self.assertNotEqual(service._approval_id(new_audit), old_approval.approval_id)
            status = service.get_approval_status(preview["preview_id"], 1)
            self.assertEqual(status["status"], "NO_CURRENT_APPROVAL")
            self.assertIsNone(status["approval"])
        finally:
            directory.cleanup()

    def test_approval_status_is_read_only_and_sqlite_survives_store_recreation(self):
        for kind in ("memory", "sqlite"):
            with self.subTest(store=kind):
                directory, context, store, preview, audit, service = self._setup(kind)
                try:
                    command = f"批准写入 {preview['preview_id']} 1"
                    approval = service.record_approval(preview["preview_id"], 1, command, "human")
                    authority_state_names = (
                        "_authorities", "_authority_issuance_ids", "_live_credential_contexts",
                        "_restart_authority_provenance",
                    )
                    authority_state_before = {
                        name: deepcopy(getattr(service, name)) for name in authority_state_names
                    }
                    if kind == "memory":
                        store_state_before = {
                            name: deepcopy(getattr(store, name))
                            for name in ("_previews", "_preview_history", "_audits", "_approvals", "_evidence")
                        }
                    else:
                        with closing(sqlite3.connect(store.path)) as connection:
                            sqlite_state_before = (
                                connection.execute(
                                    "SELECT workspace_identity, record_type, record_id, revision, payload "
                                    "FROM records ORDER BY workspace_identity, record_type, record_id, revision"
                                ).fetchall(),
                                connection.execute(
                                    "SELECT workspace_identity, audit_id, event_no, payload, reason, occurred_at "
                                    "FROM audit_history ORDER BY workspace_identity, audit_id, event_no"
                                ).fetchall(),
                            )
                    with patch.object(store, "record_approval", wraps=store.record_approval) as record_approval, \
                            patch.object(store, "record_audit", wraps=store.record_audit) as record_audit, \
                            patch.object(service, "record_approval", wraps=service.record_approval) as service_record, \
                            patch.object(service, "issue_application_authority", wraps=service.issue_application_authority) as issue_authority, \
                            patch.object(service, "recover_application_authority", wraps=service.recover_application_authority) as recover_authority, \
                            patch.object(service, "reconstruct_application_authority_after_restart", wraps=service.reconstruct_application_authority_after_restart) as reconstruct_authority, \
                            patch.object(service, "create_applier", wraps=service.create_applier) as create_applier:
                        first = service.get_approval_status(preview["preview_id"], 1)
                        second = service.get_approval_status(preview["preview_id"], 1)
                    self.assertEqual(first, second)
                    self.assertEqual(first["approval"], approval.to_dict())
                    record_approval.assert_not_called()
                    record_audit.assert_not_called()
                    service_record.assert_not_called()
                    issue_authority.assert_not_called()
                    recover_authority.assert_not_called()
                    reconstruct_authority.assert_not_called()
                    create_applier.assert_not_called()
                    self.assertEqual(
                        authority_state_before,
                        {name: getattr(service, name) for name in authority_state_names},
                    )
                    if kind == "memory":
                        self.assertEqual(
                            store_state_before,
                            {name: getattr(store, name) for name in store_state_before},
                        )
                    else:
                        with closing(sqlite3.connect(store.path)) as connection:
                            sqlite_state_after = (
                                connection.execute(
                                    "SELECT workspace_identity, record_type, record_id, revision, payload "
                                    "FROM records ORDER BY workspace_identity, record_type, record_id, revision"
                                ).fetchall(),
                                connection.execute(
                                    "SELECT workspace_identity, audit_id, event_no, payload, reason, occurred_at "
                                    "FROM audit_history ORDER BY workspace_identity, audit_id, event_no"
                                ).fetchall(),
                            )
                        self.assertEqual(sqlite_state_before, sqlite_state_after)
                    if kind == "sqlite":
                        restarted_store = SQLitePreviewStore(
                            context,
                            ignore_checker=lambda path: True,
                            tracked_checker=lambda path: False,
                            trust_context=TRUST,
                        )
                        restarted_service = RuntimeApprovalAuthorityService(
                            context,
                            restarted_store,
                            None,
                            clock=lambda: NOW,
                            rule_registry=build_registry_v1(),
                        )
                        restarted = restarted_service.get_approval_status(preview["preview_id"], 1)
                        self.assertEqual(restarted, first)
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
            self.assertTrue(service.validate_application_authority(first))
            with self.assertRaisesRegex(ValueError, "^authority_issuance_requires_recovery$"):
                service.issue_application_authority(preview["preview_id"], 1, approval.approval_id)
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
                with self.assertRaisesRegex(ValueError, "^verified_attestation_context_unverified$"):
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
