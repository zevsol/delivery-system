from __future__ import annotations

import tempfile
import unittest
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from delivery_system.attestation import AttestationRuntimeBoundary
from delivery_system.attestation_runtime import RuntimeAttestationOrchestrationService
from delivery_system.canonical import digest
from delivery_system.application_identity import operation_identity
from delivery_system.drivers.contract import DriverReadResponse, DriverTrustContext
from delivery_system.drivers.write_contract import RemoteIssueReference, WriteObservation, WriteObservationKind
from delivery_system.existing_endpoints import (
    ExistingEndpointRevalidator,
    SealedExistingEndpoint,
    identity_digest,
    selector_digest,
    semantic_digest,
    validate_issue_selector_url,
    write_address_digest,
)
from delivery_system.formal_preview import SealedPreview
from delivery_system.remote_snapshot import RemoteIssueRecordV2
from delivery_system.receipts import ApplicationReceipt
from delivery_system.auditor import RuleEvaluationDraft, RuntimeAuditor
from delivery_system.rules import SemanticOutcome, build_registry_v1
from delivery_system.runtime import ApplicationPostconditionObservation, InMemoryPreviewStore, RuntimeApplicationStatusService, RuntimeApprovalAuthorityService, RuntimeContext, RuntimePlanner
from tests.attestation_contract.test_attestation_contract import FakeCapabilityPolicy, FakeIssuer
from tests.fakes.attestation_provider import FakeCapabilityResolver, FakeCredentialCapabilityProvider
from tests.v1 import test_operational_approval_authority as approval_fixture
from tests.v1 import test_pc2b_applier_orchestration as applier_fixture
from tests.v1.test_operational_approval_authority import i3b_dependencies
from delivery_system.write_operations import evaluate_write_operations_v2, operation_set_digest_payload
from delivery_system.preview_validation import _validate_v2_endpoint_authority


TRUST = DriverTrustContext("fixture-driver", "offline://fixture", "fixture-v1")
NOW = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)


def _s(value):
    return {"value": value, "declared_source": "user_asserted"}


def _item(ref="new-item"):
    return {
        "client_ref": ref,
        "role": _s("Bug"), "title": _s("New issue"), "context_problem": _s("Problem"),
        "outcome": _s("Outcome"), "scope": _s([]), "non_goals": _s([]),
        "acceptance_criteria": _s(["Works"]), "verification": _s(["Test"]),
        "required_capabilities": _s(["issues"]), "write_metadata": _s({}),
    }


class _Driver:
    fixed_query_scope = {
        "api_origin": "offline://fixture", "api_version": "2026-03-10", "issue_state": "all",
        "pull_request_filter": "pull_request_field_excluded",
        "relationships": ["sub_issues", "parent", "blocked_by", "blocking"],
        "pagination_protocol": "link-header", "budget_profile": "github-rest-offline-v1",
    }

    def read_repository(self, repository, query_scope):
        issue = {
            "issue_id": "NODE-12", "numeric_id": "12", "number": 12,
            "item_type": "issue", "title": "Existing parent", "body": "Parent body",
            "state": "open", "updated_at": "2026-08-13T00:00:00+00:00",
            "repository_identity": "owner/repo",
        }
        material = {
            "source_identity": TRUST.trusted_driver_identity,
            "repository_identity": "owner/repo", "query_scope": query_scope,
            "payload": {"issue_records": [issue], "relationship_records": []},
        }
        payload = {
            "requested_repository": repository, "canonical_repository": "owner/repo",
            "remote_repository_id": "repo-1", "authenticated_subject": "subject-1",
            "visibility": "private", "permissions": {"read": True, "write": True},
            "capabilities": {"issues": True, "relationships": True},
            "query_scope": dict(query_scope), "query_complete": True,
            "pagination_complete": True, "issue_records": [issue],
            "relationship_records": [], "evidence_material": [material],
            "source_identity": TRUST.trusted_driver_identity,
        }
        return DriverReadResponse(**payload, remote_content_digest=digest(payload))


def _mixed_plan(kind="planned_parent"):
    return {
        "repository_claim": {"owner": "Owner", "name": "Repo"},
        "existing_issue_endpoints": [{"endpoint_ref": "existing-parent", "number": 12}],
        "work_items": [_item("new-child")],
        "planned_relationships": [{
            "kind": kind,
            "from_endpoint": {"endpoint_type": "work_item", "client_ref": "new-child"},
            "to_endpoint": {"endpoint_type": "existing_issue", "endpoint_ref": "existing-parent"},
            "rationale": _s("The existing outcome is the governed parent."),
        }],
        "operation_intents": [
            {"operation_kind": "create_issue", "endpoint": {"endpoint_type": "work_item", "client_ref": "new-child"}, "depends_on": []},
            {"operation_kind": "add_sub_issue" if kind == "planned_parent" else "add_dependency",
             "operands": [
                 {"endpoint_type": "work_item", "client_ref": "new-child"},
                 {"endpoint_type": "existing_issue", "endpoint_ref": "existing-parent"},
             ], "depends_on": []},
        ],
    }


def _mixed_plan_shape(kind, source_type, target_type):
    plan = _mixed_plan(kind)
    source = {"endpoint_type": source_type}
    target = {"endpoint_type": target_type}
    if source_type == "work_item":
        source["client_ref"] = "new-child"
    else:
        source["endpoint_ref"] = "existing-parent"
    if target_type == "work_item":
        target["client_ref"] = "new-child"
    else:
        target["endpoint_ref"] = "existing-parent"
    plan["planned_relationships"][0]["from_endpoint"] = source
    plan["planned_relationships"][0]["to_endpoint"] = target
    plan["operation_intents"][1]["operands"] = [source, target]
    return plan


class ExistingRemoteRelationshipEndpointTests(unittest.TestCase):
    @staticmethod
    def _record(**overrides):
        record = {
            "issue_id": "NODE-12", "numeric_issue_id": "12", "issue_number": 12,
            "item_type": "issue", "title": "Existing parent", "body": "Parent body",
            "state": "open", "updated_at": "2026-08-13T00:00:00+00:00",
            "repository_identity": "owner/repo",
        }
        record.update(overrides)
        return record

    def test_issue_selector_url_requires_canonical_github_authority(self):
        valid = "https://github.com/owner/repo/issues/12"
        self.assertEqual(validate_issue_selector_url(valid, "owner/repo"), 12)
        for invalid in (
            "http://github.com/owner/repo/issues/12",
            "https://evil.example/owner/repo/issues/12",
            "https://github.com.evil.example/owner/repo/issues/12",
            "https://user@github.com/owner/repo/issues/12",
            "https://github.com:444/owner/repo/issues/12",
            "https://github.com/owner/repo/issues/12?x=1",
            "https://github.com/owner/repo/issues/12#fragment",
            "https://github.com/other/repo/issues/12",
        ):
            with self.subTest(url=invalid):
                with self.assertRaises(ValueError):
                    validate_issue_selector_url(invalid, "owner/repo")

    def test_v2_remote_fact_presence_and_identity_validation(self):
        self.assertEqual(RemoteIssueRecordV2.from_dict(self._record(body=None)).body, "")
        for field in ("body", "state"):
            missing = self._record()
            del missing[field]
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    RemoteIssueRecordV2.from_dict(missing)
        for numeric_id in ("", "0", "-1", "+1", "0x12", "1" * 21):
            with self.subTest(numeric_id=numeric_id):
                with self.assertRaises(ValueError):
                    RemoteIssueRecordV2.from_dict(self._record(numeric_issue_id=numeric_id))
        for number in (True, 0, -1):
            with self.subTest(number=number):
                with self.assertRaises(ValueError):
                    RemoteIssueRecordV2.from_dict(self._record(issue_number=number))
        for state in (None, "pending"):
            with self.subTest(state=state):
                with self.assertRaises(ValueError):
                    RemoteIssueRecordV2.from_dict(self._record(state=state))
        with self.assertRaises(ValueError):
            RemoteIssueRecordV2.from_dict(self._record(issue_id=""))

    def test_v2_binding_requires_v2_snapshot(self):
        payload = {
            "workspace_identity": "workspace",
            "request_id": "request",
            "preview_id": "preview",
            "revision": 1,
            "preview_level": "RepositoryAware",
            "provenance_status": "declared_unverified",
            "repository_identity": "owner/repo",
            "remote_authority": "github",
            "semantic_payload": {},
            "operation_intents": [],
            "plan_digest": "plan",
            "operation_set_digest": "operations",
            "remote_snapshot": None,
            "remote_snapshot_digest": None,
            "items": [],
            "evidence_ids": [],
            "blockers": [],
            "planner_observations": [],
            "sealed_preview_digest": "sealed",
            "canonical_version": "2",
            "existing_endpoint_bindings": [{"endpoint_ref": "existing"}],
        }
        with self.assertRaisesRegex(ValueError, "sealed_preview_v2_snapshot_required"):
            SealedPreview.from_dict(payload)
        payload["remote_snapshot"] = {"schema_version": "remote-snapshot-v1"}
        payload["remote_snapshot_digest"] = "snapshot"
        with self.assertRaisesRegex(ValueError, "sealed_preview_v2_snapshot_invalid"):
            SealedPreview.from_dict(payload)

    def test_v2_declaration_binding_authority_is_one_to_one(self):
        base = {
            "canonical_version": "2",
            "preview_level": "RepositoryAware",
            "semantic_payload": {"existing_issue_endpoints": [{"endpoint_ref": "existing-parent", "number": 12}]},
            "existing_endpoint_bindings": [{"endpoint_ref": "existing-parent"}],
        }
        _validate_v2_endpoint_authority(base)
        duplicate_declaration = deepcopy(base)
        duplicate_declaration["semantic_payload"]["existing_issue_endpoints"].append(
            {"endpoint_ref": "existing-parent", "number": 12}
        )
        with self.assertRaisesRegex(ValueError, "sealed_preview_endpoint_declaration_duplicate"):
            _validate_v2_endpoint_authority(duplicate_declaration)
        duplicate_binding = deepcopy(base)
        duplicate_binding["existing_endpoint_bindings"].append({"endpoint_ref": "existing-parent"})
        with self.assertRaisesRegex(ValueError, "sealed_preview_endpoint_binding_duplicate"):
            _validate_v2_endpoint_authority(duplicate_binding)
        undeclared = deepcopy(base)
        undeclared["existing_endpoint_bindings"][0]["endpoint_ref"] = "other"
        with self.assertRaisesRegex(ValueError, "sealed_preview_endpoint_binding_undeclared"):
            _validate_v2_endpoint_authority(undeclared)
        missing_binding = deepcopy(base)
        missing_binding["existing_endpoint_bindings"] = []
        with self.assertRaisesRegex(ValueError, "sealed_preview_endpoint_binding_coverage_invalid"):
            _validate_v2_endpoint_authority(missing_binding)

    def test_v2_conceptual_declarations_without_bindings_remain_valid(self):
        payload = {
            "canonical_version": "2",
            "preview_level": "Conceptual",
            "semantic_payload": {"existing_issue_endpoints": [{"endpoint_ref": "existing-parent", "number": 12}]},
            "existing_endpoint_bindings": [],
        }
        _validate_v2_endpoint_authority(payload)

    def test_new_to_existing_produces_v2_snapshot_and_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore(context.workspace_identity, TRUST)
            preview = RuntimePlanner(context, store, _Driver(), TRUST).preview(_mixed_plan())
            self.assertEqual(preview["canonical_version"], "2")
            self.assertEqual(preview["preview_level"], "WriteEligible")
            self.assertEqual(preview["existing_endpoint_bindings"][0]["endpoint_ref"], "existing-parent")
            stored = store.get_preview(context.workspace_identity, preview["preview_id"])["canonical_payload"]
            self.assertEqual(stored["remote_snapshot"]["schema_version"], "remote-snapshot-v2")

    def test_url_and_number_selector_must_agree(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore(context.workspace_identity, TRUST)
            plan = _mixed_plan()
            plan["existing_issue_endpoints"][0]["url"] = "https://github.com/owner/repo/issues/13"
            with self.assertRaisesRegex(ValueError, "sealed_preview_endpoint_binding_coverage_invalid"):
                RuntimePlanner(context, store, _Driver(), TRUST).preview(plan)

    def test_existing_endpoint_and_work_item_namespaces_are_disjoint(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore(context.workspace_identity, TRUST)
            plan = _mixed_plan()
            plan["work_items"][0]["client_ref"] = "existing-parent"
            with self.assertRaises(ValueError) as error:
                RuntimePlanner(context, store, _Driver(), TRUST).preview(plan)
            self.assertEqual(str(error.exception), "write_operation_reference_namespace_collision")

    def test_v1_payload_rejects_v2_fields_without_discriminator(self):
        with self.assertRaises(ValueError):
            SealedPreview.from_dict({"canonical_version": "2"})

    def test_v2_evaluator_accepts_both_mixed_forms_for_both_relationship_kinds(self):
        for operation_kind, relationship_kind in (("add_sub_issue", "planned_parent"), ("add_dependency", "planned_dependency")):
            for source_type, target_type in (("work_item", "existing_issue"), ("existing_issue", "work_item")):
                source = {"endpoint_type": source_type, "client_ref" if source_type == "work_item" else "endpoint_ref": "new" if source_type == "work_item" else "existing"}
                target = {"endpoint_type": target_type, "client_ref" if target_type == "work_item" else "endpoint_ref": "new" if target_type == "work_item" else "existing"}
                result = evaluate_write_operations_v2(
                    [
                        {"operation_kind": "create_issue", "endpoint": {"endpoint_type": "work_item", "client_ref": "new"}, "depends_on": []},
                        {"operation_kind": operation_kind, "operands": [source, target], "depends_on": []},
                    ],
                    [{"client_ref": "new"}],
                    {"planned_relationships": [{"kind": relationship_kind, "from_endpoint": source, "to_endpoint": target}]},
                    [{"endpoint_ref": "existing"}],
                )
                self.assertTrue(result.eligible, result.blockers)

    def test_v2_evaluator_rejects_relation_only_existing_to_existing(self):
        existing_a = {"endpoint_type": "existing_issue", "endpoint_ref": "a"}
        existing_b = {"endpoint_type": "existing_issue", "endpoint_ref": "b"}
        result = evaluate_write_operations_v2(
            [{"operation_kind": "add_dependency", "operands": [existing_a, existing_b], "depends_on": []}],
            [{"client_ref": "new"}],
            {"planned_relationships": [{"kind": "planned_dependency", "from_endpoint": existing_a, "to_endpoint": existing_b}]},
            [{"endpoint_ref": "a"}, {"endpoint_ref": "b"}],
        )
        self.assertFalse(result.eligible)
        self.assertIn("write_operation_existing_to_existing_unsupported", result.blockers)

    def test_all_supported_mixed_shapes_complete_preview_and_audit(self):
        for kind in ("planned_parent", "planned_dependency"):
            for source_type, target_type in (("work_item", "existing_issue"), ("existing_issue", "work_item")):
                with self.subTest(kind=kind, source_type=source_type, target_type=target_type), tempfile.TemporaryDirectory() as directory:
                    context = RuntimeContext.from_workspace_root(directory)
                    store = InMemoryPreviewStore(context.workspace_identity, TRUST)
                    preview = RuntimePlanner(context, store, _Driver(), TRUST).preview(
                        _mixed_plan_shape(kind, source_type, target_type)
                    )
                    self.assertTrue(preview["write_eligible"], preview["blockers"])
                    auditor = RuntimeAuditor(context, store, build_registry_v1(), TRUST)
                    audit_context = auditor.get_context(preview["preview_id"], preview["revision"])
                    evaluations = [
                        RuleEvaluationDraft(rule["rule_id"], rule["rule_version"], SemanticOutcome.PASSED, "verified")
                        for rule in audit_context["semantic_rule_contexts"]
                        if rule["applicability"] == "Applicable"
                    ]
                    audit = auditor.record_audit(
                        preview["preview_id"], preview["revision"],
                        audit_context["audit_context_digest"], evaluations, [],
                    )
                    self.assertEqual(audit.result.value if hasattr(audit.result, "value") else audit.result, "Passed")

    def test_all_supported_mixed_shapes_reach_approval_and_authority(self):
        for kind in ("planned_parent", "planned_dependency"):
            for source_type, target_type in (("work_item", "existing_issue"), ("existing_issue", "work_item")):
                with self.subTest(kind=kind, source_type=source_type, target_type=target_type), tempfile.TemporaryDirectory() as directory:
                    context = RuntimeContext.from_workspace_root(directory)
                    store = InMemoryPreviewStore(context.workspace_identity, TRUST)
                    preview = RuntimePlanner(context, store, _Driver(), TRUST).preview(
                        _mixed_plan_shape(kind, source_type, target_type)
                    )
                    auditor = RuntimeAuditor(context, store, build_registry_v1(), TRUST)
                    audit_context = auditor.get_context(preview["preview_id"], preview["revision"])
                    evaluations = [
                        RuleEvaluationDraft(rule["rule_id"], rule["rule_version"], SemanticOutcome.PASSED, "verified")
                        for rule in audit_context["semantic_rule_contexts"]
                        if rule["applicability"] == "Applicable"
                    ]
                    audit = auditor.record_audit(
                        preview["preview_id"], preview["revision"],
                        audit_context["audit_context_digest"], evaluations, [],
                    )
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
                    )
                    approval = service.record_approval(
                        preview["preview_id"], preview["revision"],
                        f"批准写入 {preview['preview_id']} {preview['revision']}", "human",
                    )
                    authority = service.issue_application_authority(
                        preview["preview_id"], preview["revision"], approval.approval_id,
                    )
                    self.assertEqual(authority.preview_id, preview["preview_id"])

    def test_all_supported_mixed_shapes_apply_through_existing_executor(self):
        harness = applier_fixture.ApplierOrchestrationTests()
        for kind in ("planned_parent", "planned_dependency"):
            for source_type, target_type in (("work_item", "existing_issue"), ("existing_issue", "work_item")):
                with self.subTest(kind=kind, source_type=source_type, target_type=target_type):
                    directory = None
                    try:
                        with patch.object(approval_fixture, "plan", return_value=_mixed_plan_shape(kind, source_type, target_type)), \
                             patch.object(approval_fixture, "FakeReadOnlyDriver", side_effect=lambda node_id=None: _Driver()):
                            directory, context, preview, service, authority, write_driver = harness._compose(
                                (harness._success(number=21, numeric_id="21"), harness._relationship_success()),
                            )
                        service._existing_endpoint_revalidator = ExistingEndpointRevalidator(_Driver(), TRUST)
                        execution_store = harness._store(context, service, directory)
                        result = service.create_applier(execution_store).apply(authority.authority_id)
                        self.assertEqual(result.state, "Applied")
                        self.assertEqual(len(write_driver.trace), 2)
                        application_id = service.create_execution_context(authority.authority_id).identity.application_id
                        status = RuntimeApplicationStatusService(context, service.store, execution_store).get_status(application_id)
                        self.assertEqual(status["state"], "Applied")
                        self.assertEqual(status["operation_set_digest"], preview["operation_set_digest"])
                        self.assertEqual(status["completed_operation_count"], 2)
                    finally:
                        if directory is not None:
                            directory.cleanup()

    def test_v2_receipt_replay_binds_identity_digest_and_execution_receipts(self):
        harness = applier_fixture.ApplierOrchestrationTests()
        directory = None
        try:
            with patch.object(approval_fixture, "plan", return_value=_mixed_plan_shape("planned_parent", "work_item", "existing_issue")), \
                 patch.object(approval_fixture, "FakeReadOnlyDriver", side_effect=lambda node_id=None: _Driver()):
                directory, context, preview, service, authority, _ = harness._compose(
                    (harness._success(number=21, numeric_id="21"), harness._relationship_success()),
                )
            service._existing_endpoint_revalidator = ExistingEndpointRevalidator(_Driver(), TRUST)
            execution_store = harness._store(context, service, directory)
            result = service.create_applier(execution_store).apply(authority.authority_id)
            self.assertEqual(result.state, "Applied")
            identity = service.create_execution_context(authority.authority_id).identity
            status = RuntimeApplicationStatusService(context, service.store, execution_store)
            operations = status._load_preview_operations(identity)
            receipts = [
                execution_store.get_operation_receipt(
                    identity.application_id,
                    operation_identity(identity.application_id, index, operation),
                )
                for index, operation in enumerate(operations)
            ]
            application_receipt = execution_store.get_application_receipt(identity.application_id)
            legacy_projection_digest = digest(operation_set_digest_payload(operations))
            self.assertNotEqual(identity.values()["operation_set_digest"], legacy_projection_digest)
            self.assertEqual(application_receipt.operation_set_digest, identity.values()["operation_set_digest"])
            self.assertTrue(application_receipt.validate_against(operations, receipts))

            substituted = [dict(operation) for operation in operations]
            substituted[1]["client_refs"] = ["work_item:new-child", "existing_issue:substituted"]
            self.assertFalse(application_receipt.validate_against(substituted, receipts))

            tampered = replace(
                application_receipt,
                operation_set_digest="sha256:" + "0" * 64,
                receipt_digest="",
            ).with_digest()
            self.assertTrue(tampered.verify_integrity())
            self.assertFalse(tampered.validate_against(operations, receipts))
        finally:
            if directory is not None:
                directory.cleanup()

    def test_mixed_outcome_unknown_reconstructs_operands_after_restart(self):
        class ObservationDriver:
            fixed_query_scope = _Driver.fixed_query_scope

            def read_repository(self, repository, query_scope):
                issues = [
                    {"issue_id": "node-1", "item_type": "issue", "title": "Created", "updated_at": "2026-08-13T00:00:00+00:00", "repository_identity": "owner/repo"},
                    {"issue_id": "NODE-12", "item_type": "issue", "title": "Existing", "updated_at": "2026-08-13T00:00:00+00:00", "repository_identity": "owner/repo"},
                ]
                material = {"source_identity": TRUST.trusted_driver_identity, "repository_identity": "owner/repo", "query_scope": query_scope, "payload": {"issue_records": issues, "relationship_records": []}}
                payload = {"requested_repository": repository, "canonical_repository": "owner/repo", "remote_repository_id": "repo-1", "authenticated_subject": "subject-1", "visibility": "private", "permissions": {"read": True, "write": True}, "capabilities": {"issues": True, "relationships": True}, "query_scope": dict(query_scope), "query_complete": True, "pagination_complete": True, "issue_records": issues, "relationship_records": [], "evidence_material": [material], "source_identity": TRUST.trusted_driver_identity}
                return DriverReadResponse(**payload, remote_content_digest=digest(payload))

        harness = applier_fixture.ApplierOrchestrationTests()
        for kind in ("planned_parent", "planned_dependency"):
            with self.subTest(kind=kind):
                directory = None
                try:
                    with patch.object(approval_fixture, "plan", return_value=_mixed_plan_shape(kind, "work_item", "existing_issue")), \
                         patch.object(approval_fixture, "FakeReadOnlyDriver", side_effect=lambda node_id=None: _Driver()):
                        directory, context, preview, service, authority, write_driver = harness._compose(
                            (harness._success(number=21, numeric_id="21"), WriteObservation(WriteObservationKind.AMBIGUOUS, code="github_write_transport_ambiguous")),
                        )
                    service._existing_endpoint_revalidator = ExistingEndpointRevalidator(_Driver(), TRUST)
                    execution_store = harness._store(context, service, directory)
                    result = service.create_applier(execution_store).apply(authority.authority_id)
                    self.assertEqual(result.state, "OutcomeUnknown")
                    dispatch_count = len(write_driver.trace)
                    replay = service.create_applier(execution_store).apply(authority.authority_id)
                    self.assertEqual(replay.state, "OutcomeUnknown")
                    self.assertEqual(len(write_driver.trace), dispatch_count)
                    application_id = service.create_execution_context(authority.authority_id).identity.application_id
                    observer = ApplicationPostconditionObservation(context, service.store, execution_store, ObservationDriver(), TRUST)
                    observed = observer._observe(application_id)
                    self.assertEqual(observed["postcondition"], "postcondition_absent")
                    restarted_observer = ApplicationPostconditionObservation(context, service.store, execution_store, ObservationDriver(), TRUST)
                    self.assertEqual(restarted_observer._observe(application_id)["postcondition"], "postcondition_absent")
                finally:
                    if directory is not None:
                        directory.cleanup()

    def test_status_reload_recomputes_v2_digest_before_execution_projection(self):
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore(context.workspace_identity, TRUST)
            preview = RuntimePlanner(context, store, _Driver(), TRUST).preview(_mixed_plan())

            class _ExecutionStore:
                workspace_identity = context.workspace_identity

                def get_execution_bootstrap(self, application_id):
                    raise AssertionError("bootstrap must not be consulted while loading preview operations")

                def get_execution(self, *args, **kwargs):
                    raise AssertionError("execution must not be consulted while loading preview operations")

                def get_attempt(self, *args, **kwargs):
                    raise AssertionError("attempt must not be consulted while loading preview operations")

                def get_operation_receipt(self, *args, **kwargs):
                    raise AssertionError("receipt must not be consulted while loading preview operations")

                def get_application_receipt(self, *args, **kwargs):
                    raise AssertionError("application receipt must not be consulted while loading preview operations")

            class _Identity:
                application_id = "application-" + "0" * 64

                def values(self):
                    return {
                        "workspace_identity": context.workspace_identity,
                        "repository_identity": preview["repository_identity"],
                        "preview_id": preview["preview_id"],
                        "revision": preview["revision"],
                        "sealed_preview_digest": preview["sealed_preview_digest"],
                        "plan_digest": preview["plan_digest"],
                        "operation_set_digest": preview["operation_set_digest"],
                        "remote_snapshot_digest": preview["remote_snapshot_digest"],
                    }

            status = RuntimeApplicationStatusService(context, store, _ExecutionStore())
            operations = status._load_preview_operations(_Identity())
            self.assertEqual(operations[0]["operation_kind"], "create_issue")
            self.assertEqual(operations[0]["client_refs"], ["new-child"])
            self.assertEqual(operations[1]["operation_kind"], "add_sub_issue")
            self.assertEqual(operations[1]["client_refs"], ["work_item:new-child", "existing_issue:existing-parent"])

    def test_default_revalidator_reads_through_trusted_driver_and_validates_binding(self):
        record = {
            "issue_id": "NODE-12", "numeric_issue_id": "12", "issue_number": 12,
            "item_type": "issue", "title": "Existing parent", "body": "Parent body",
            "state": "open", "updated_at": "2026-08-13T00:00:00+00:00",
            "repository_identity": "owner/repo",
        }
        binding = SealedExistingEndpoint(
            "existing-parent", selector_digest({"number": 12}), record["issue_id"], digest(record),
            identity_digest(record), write_address_digest(record), semantic_digest(record),
        ).to_dict()
        context = SimpleNamespace(
            repository_identity="owner/repo",
            _existing_endpoint_bindings=(binding,),
        )
        self.assertTrue(ExistingEndpointRevalidator(_Driver(), TRUST)(context, "existing-parent"))

    def test_revalidator_blocks_relationship_already_present_for_parent_and_dependency(self):
        class RelationshipDriver:
            fixed_query_scope = _Driver.fixed_query_scope

            def read_repository(self, repository, query_scope):
                issues = [
                    {"issue_id": "NODE-12", "numeric_id": "12", "number": 12, "item_type": "issue", "title": "Existing parent", "body": "Parent body", "state": "open", "updated_at": "2026-08-13T00:00:00+00:00", "repository_identity": "owner/repo"},
                    {"issue_id": "NODE-13", "numeric_id": "13", "number": 13, "item_type": "issue", "title": "New issue", "body": "New body", "state": "open", "updated_at": "2026-08-13T00:00:00+00:00", "repository_identity": "owner/repo"},
                ]
                relationships = [
                    {"kind": "existing_parent", "from": "NODE-13", "to": "NODE-12"},
                    {"kind": "existing_dependency", "from": "NODE-13", "to": "NODE-12"},
                ]
                material = {"source_identity": TRUST.trusted_driver_identity, "repository_identity": "owner/repo", "query_scope": query_scope, "payload": {"issue_records": issues, "relationship_records": relationships}}
                payload = {"requested_repository": repository, "canonical_repository": "owner/repo", "remote_repository_id": "repo-1", "authenticated_subject": "subject-1", "visibility": "private", "permissions": {"read": True, "write": True}, "capabilities": {"issues": True, "relationships": True}, "query_scope": dict(query_scope), "query_complete": True, "pagination_complete": True, "issue_records": issues, "relationship_records": relationships, "evidence_material": [material], "source_identity": TRUST.trusted_driver_identity}
                return DriverReadResponse(**payload, remote_content_digest=digest(payload))

        record = {
            "issue_id": "NODE-12", "numeric_issue_id": "12", "issue_number": 12,
            "item_type": "issue", "title": "Existing parent", "body": "Parent body",
            "state": "open", "updated_at": "2026-08-13T00:00:00+00:00", "repository_identity": "owner/repo",
        }
        binding = SealedExistingEndpoint(
            "existing-parent", selector_digest({"number": 12}), record["issue_id"], digest(record),
            identity_digest(record), write_address_digest(record), semantic_digest(record),
        ).to_dict()
        context = SimpleNamespace(repository_identity="owner/repo", _existing_endpoint_bindings=(binding,))
        references = (
            RemoteIssueReference("owner/repo", 13, "13", "NODE-13"),
            RemoteIssueReference("owner/repo", 12, "12", "NODE-12"),
        )
        for operation_kind in ("add_sub_issue", "add_dependency"):
            with self.subTest(operation_kind=operation_kind):
                with self.assertRaisesRegex(ValueError, "relationship_already_exists"):
                    ExistingEndpointRevalidator(RelationshipDriver(), TRUST)(context, "existing-parent", operation_kind, references)

    def test_preview_blocks_already_existing_parent_before_write_eligibility(self):
        class PreviewDriver(_Driver):
            def read_repository(self, repository, query_scope):
                response = super().read_repository(repository, query_scope)
                issues = [
                    {"issue_id": "NODE-12", "numeric_id": "12", "number": 12,
                     "item_type": "issue", "title": "Existing parent", "body": "Parent body",
                     "state": "open", "updated_at": "2026-08-13T00:00:00+00:00", "repository_identity": "owner/repo"},
                    {"issue_id": "NODE-13", "numeric_id": "13", "number": 13,
                     "item_type": "issue", "title": "New child", "body": "Child body",
                     "state": "open", "updated_at": "2026-08-13T00:00:00+00:00", "repository_identity": "owner/repo"},
                ]
                relationships = [{"kind": "existing_parent", "from": "NODE-13", "to": "NODE-12"}]
                payload = dict(response.__dict__)
                payload["issue_records"] = issues
                payload["relationship_records"] = relationships
                payload["evidence_material"] = [{
                    "source_identity": TRUST.trusted_driver_identity,
                    "repository_identity": "owner/repo", "query_scope": query_scope,
                    "payload": {"issue_records": issues, "relationship_records": relationships},
                }]
                payload.pop("remote_content_digest", None)
                for key in ("remote_repository_node_id", "authenticated_user_id", "authenticated_user_node_id", "authenticated_login"):
                    payload.pop(key, None)
                return DriverReadResponse(**payload, remote_content_digest=digest(payload))

        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore(context.workspace_identity, TRUST)
            plan = _mixed_plan("planned_parent")
            plan["existing_issue_endpoints"] = [
                {"endpoint_ref": "existing-child", "number": 13},
                {"endpoint_ref": "existing-parent", "number": 12},
            ]
            plan["planned_relationships"][0]["from_endpoint"] = {"endpoint_type": "existing_issue", "endpoint_ref": "existing-child"}
            plan["planned_relationships"][0]["to_endpoint"] = {"endpoint_type": "existing_issue", "endpoint_ref": "existing-parent"}
            plan["operation_intents"][1]["operands"] = [
                {"endpoint_type": "existing_issue", "endpoint_ref": "existing-child"},
                {"endpoint_type": "existing_issue", "endpoint_ref": "existing-parent"},
            ]
            preview = RuntimePlanner(context, store, PreviewDriver(), TRUST).preview(plan)
            self.assertFalse(preview["write_eligible"])
            self.assertIn("relationship_already_exists", preview["blockers"])
            self.assertTrue(any(operation.get("operation_kind") == "add_sub_issue" for operation in preview["operation_intents"]))

    def test_preview_blocks_already_existing_dependency_before_write_eligibility(self):
        class PreviewDriver(_Driver):
            def read_repository(self, repository, query_scope):
                response = super().read_repository(repository, query_scope)
                issues = [
                    {"issue_id": "NODE-12", "numeric_id": "12", "number": 12,
                     "item_type": "issue", "title": "Existing prerequisite", "body": "Prerequisite body",
                     "state": "open", "updated_at": "2026-08-13T00:00:00+00:00", "repository_identity": "owner/repo"},
                    {"issue_id": "NODE-13", "numeric_id": "13", "number": 13,
                     "item_type": "issue", "title": "New dependent", "body": "Dependent body",
                     "state": "open", "updated_at": "2026-08-13T00:00:00+00:00", "repository_identity": "owner/repo"},
                ]
                relationships = [{"kind": "existing_dependency", "from": "NODE-13", "to": "NODE-12"}]
                payload = dict(response.__dict__)
                payload["issue_records"] = issues
                payload["relationship_records"] = relationships
                payload["evidence_material"] = [{
                    "source_identity": TRUST.trusted_driver_identity,
                    "repository_identity": "owner/repo", "query_scope": query_scope,
                    "payload": {"issue_records": issues, "relationship_records": relationships},
                }]
                payload.pop("remote_content_digest", None)
                for key in ("remote_repository_node_id", "authenticated_user_id", "authenticated_user_node_id", "authenticated_login"):
                    payload.pop(key, None)
                return DriverReadResponse(**payload, remote_content_digest=digest(payload))

        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore(context.workspace_identity, TRUST)
            plan = _mixed_plan("planned_dependency")
            plan["existing_issue_endpoints"] = [
                {"endpoint_ref": "existing-child", "number": 13},
                {"endpoint_ref": "existing-parent", "number": 12},
            ]
            plan["planned_relationships"][0]["from_endpoint"] = {"endpoint_type": "existing_issue", "endpoint_ref": "existing-child"}
            plan["planned_relationships"][0]["to_endpoint"] = {"endpoint_type": "existing_issue", "endpoint_ref": "existing-parent"}
            plan["operation_intents"][1]["operands"] = [
                {"endpoint_type": "existing_issue", "endpoint_ref": "existing-child"},
                {"endpoint_type": "existing_issue", "endpoint_ref": "existing-parent"},
            ]
            preview = RuntimePlanner(context, store, PreviewDriver(), TRUST).preview(plan)
            self.assertFalse(preview["write_eligible"])
            self.assertIn("relationship_already_exists", preview["blockers"])
            self.assertTrue(any(operation.get("operation_kind") == "add_dependency" for operation in preview["operation_intents"]))

    def test_existing_relationship_matching_requires_exact_direction_and_endpoints(self):
        bindings = [
            {"endpoint_ref": "child", "issue_id": "NODE-13"},
            {"endpoint_ref": "parent", "issue_id": "NODE-12"},
        ]
        for kind, operation_kind, remote_kind in (
            ("planned_parent", "add_sub_issue", "existing_parent"),
            ("planned_dependency", "add_dependency", "existing_dependency"),
        ):
            with self.subTest(kind=kind):
                source = {"endpoint_type": "existing_issue", "endpoint_ref": "child"}
                target = {"endpoint_type": "existing_issue", "endpoint_ref": "parent"}
                operations = [
                    {"operation_kind": "create_issue", "endpoint": {"endpoint_type": "work_item", "client_ref": "unrelated"}, "depends_on": []},
                    {"operation_kind": operation_kind, "operands": [source, target], "depends_on": []},
                ]
                semantic = {"planned_relationships": [{"kind": kind, "from_endpoint": source, "to_endpoint": target}]}
                exact = evaluate_write_operations_v2(
                    operations, [{"client_ref": "unrelated"}], semantic, bindings,
                    [{"kind": remote_kind, "from": "NODE-13", "to": "NODE-12"}],
                )
                self.assertIn("relationship_already_exists", exact.blockers)
                reversed_result = evaluate_write_operations_v2(
                    operations, [{"client_ref": "unrelated"}], semantic, bindings,
                    [{"kind": remote_kind, "from": "NODE-12", "to": "NODE-13"}],
                )
                self.assertNotIn("relationship_already_exists", reversed_result.blockers)
                unrelated = evaluate_write_operations_v2(
                    operations, [{"client_ref": "unrelated"}], semantic, bindings,
                    [{"kind": remote_kind, "from": "NODE-77", "to": "NODE-88"}],
                )
                self.assertNotIn("relationship_already_exists", unrelated.blockers)


if __name__ == "__main__":
    unittest.main()
