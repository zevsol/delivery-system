from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import tempfile
import threading
import unittest

from delivery_system.attestation import AttestationRuntimeBoundary, IssuerTrustDecision
from delivery_system.attestation_runtime import (
    RuntimeAttestationOrchestrationService,
    RuntimeCredentialCapabilityBinding,
    _subject_from_payload,
)
from delivery_system.auditor import RuleEvaluationDraft, RuntimeAuditor
from delivery_system.attestation_persistence import AttestationBindingReference
from delivery_system.attestation_persistence_store import SQLiteAttestationPersistenceStore
from delivery_system.drivers.contract import DriverReadResponse, DriverTrustContext
from delivery_system.protocol import canonical_payload, digest
from delivery_system.rules import SemanticOutcome, build_registry_v1
from delivery_system.runtime import AuditResult, InMemoryPreviewStore, RuntimeContext, RuntimePlanner
from tests.attestation_contract.test_attestation_contract import FakeCapabilityPolicy, FakeIssuer
from tests.fakes.attestation_persistence_store_contract import artifact_for
from tests.fakes.attestation_provider import FakeCapabilityResolver, FakeCredentialCapabilityProvider


TRUST = DriverTrustContext("fixture-driver", "offline://fixture", "fixture-v1")
NOW = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)


def sourced(value: object, source: str = "user_asserted") -> dict[str, object]:
    return {"value": value, "declared_source": source}


def plan() -> dict[str, object]:
    return {
        "repository_claim": {"owner": "Owner", "name": "Repo"},
        "work_items": [{
            "client_ref": "item", "role": sourced("Bug", "model_proposed"), "title": sourced("Existing bug"),
            "context_problem": sourced("Problem"), "outcome": sourced("Outcome", "model_proposed"),
            "scope": sourced(["repo"]), "non_goals": sourced([], "model_assumption"),
            "acceptance_criteria": sourced(["Works"]), "verification": sourced(["Test"], "model_proposed"),
            "required_capabilities": sourced(["issues"]), "write_metadata": sourced({}, "model_proposed"),
        }],
        "planned_relationships": [],
        "operation_intents": [{"operation_kind": "create_issue", "client_refs": ["item"]}],
    }


class FakeReadOnlyDriver:
    def __init__(self, *, subject: str = "subject-1", node_id: str | None = None) -> None:
        self.subject = subject
        self.node_id = node_id

    def read_repository(self, repository: str, query_scope: dict[str, object]) -> DriverReadResponse:
        issue = {
            "issue_id": "I1", "item_type": "issue", "title": "Existing", "updated_at": "2026-08-13T00:00:00+00:00",
            "repository_identity": "owner/repo",
        }
        payload: dict[str, object] = {
            "requested_repository": repository, "canonical_repository": "owner/repo", "remote_repository_id": "R1",
            "authenticated_subject": self.subject, "visibility": "private", "permissions": {"read": True, "write": False},
            "capabilities": {"issues": True, "relationships": True}, "query_scope": dict(query_scope),
            "query_complete": True, "pagination_complete": True, "issue_records": [issue], "relationship_records": [],
            "evidence_material": [{"source_identity": TRUST.trusted_driver_identity, "repository_identity": "owner/repo", "query_scope": dict(query_scope), "payload": {"issue_records": [issue], "relationship_records": []}}],
            "source_identity": TRUST.trusted_driver_identity,
        }
        if self.node_id is not None:
            payload["authenticated_user_node_id"] = self.node_id
        digest_payload = dict(payload)
        if self.node_id is not None:
            digest_payload["schema_version"] = "github-rest-remote-content-v1"
        remote_digest = digest(digest_payload)
        return DriverReadResponse(**payload, remote_content_digest=remote_digest)  # type: ignore[arg-type]


class OrchestrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.context = RuntimeContext.from_workspace_root(self.directory.name)
        self.store = InMemoryPreviewStore(self.context.workspace_identity, TRUST)
        self.preview = RuntimePlanner(self.context, self.store, FakeReadOnlyDriver(node_id="node-1"), TRUST).preview(plan())
        auditor = RuntimeAuditor(self.context, self.store, build_registry_v1(), TRUST)
        audit_context = auditor.get_context(self.preview["preview_id"], self.preview["revision"])
        evaluations = [
            RuleEvaluationDraft(rule["rule_id"], rule["rule_version"], SemanticOutcome.PASSED, "verified")
            for rule in audit_context["semantic_rule_contexts"] if rule["applicability"] == "Applicable"
        ]
        self.audit = auditor.record_audit(
            self.preview["preview_id"], self.preview["revision"], audit_context["audit_context_digest"], evaluations, []
        )
        self.fake_issuer = FakeIssuer()
        self.provider = FakeCredentialCapabilityProvider()
        self.resolver = FakeCapabilityResolver()
        self.service = RuntimeAttestationOrchestrationService(
            self.context, self.store, TRUST,
            AttestationRuntimeBoundary(self.fake_issuer, self.fake_issuer, self.fake_issuer, FakeCapabilityPolicy()),
            self.provider, self.resolver, clock=lambda: NOW,
        )

    def tearDown(self) -> None:
        self.directory.cleanup()

    def run_service(self):
        return self.service.orchestrate(self.preview["preview_id"], self.preview["revision"])

    def test_complete_runtime_chain_consumes_ticket_and_creates_binding(self):
        result = self.run_service()
        self.assertTrue(result.success)
        assert result.binding is not None
        binding = result.binding
        self.assertEqual(binding.repository_identity, "owner/repo")
        self.assertEqual(binding.github_subject_identity, "node-1")
        self.assertEqual(binding.required_capabilities, ("issues:write",))
        self.assertEqual(binding.audit_id, self.audit.audit_id)
        self.assertEqual(binding.preview_id, self.preview["preview_id"])
        self.assertTrue(self.service.accepts_binding(binding))
        self.assertIs(self.service.lookup_binding(binding.binding_id), binding)
        self.assertFalse(self.preview["write_eligible"])

    def test_v2_provider_challenge_and_principal_reach_binding(self):
        self.fake_issuer.evaluate = lambda issuer_id, key_id, signature_algorithm, attestation_version, credential_class: (
            IssuerTrustDecision(False, "attestation_issuer_untrusted")
            if issuer_id != "host-issuer" or key_id != "key-1"
            else IssuerTrustDecision(True)
        )
        self.provider = FakeCredentialCapabilityProvider(attestation_version="2")
        self.service = RuntimeAttestationOrchestrationService(
            self.context, self.store, TRUST,
            AttestationRuntimeBoundary(self.fake_issuer, self.fake_issuer, self.fake_issuer, FakeCapabilityPolicy()),
            self.provider, self.resolver, clock=lambda: NOW,
        )
        result = self.run_service()
        self.assertTrue(result.success)
        assert result.binding is not None
        self.assertEqual(result.binding.attestation_version, "2")
        self.assertEqual(result.binding.credential_principal_identity, "fake-app-installation-1")
        self.assertTrue(result.binding.challenge_digest.startswith("sha256:"))
        self.assertFalse(self.preview["write_eligible"])

    def test_v2_challenge_replay_expiry_and_concurrent_consumption(self):
        self.fake_issuer.evaluate = lambda issuer_id, key_id, signature_algorithm, attestation_version, credential_class: IssuerTrustDecision(True)
        clock = [0.0]
        class SynchronizedBoundary(AttestationRuntimeBoundary):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.consume_barrier = threading.Barrier(2)

            def consume_challenge(self, request):
                self.consume_barrier.wait(timeout=5)
                return super().consume_challenge(request)

        boundary = SynchronizedBoundary(self.fake_issuer, self.fake_issuer, self.fake_issuer, FakeCapabilityPolicy(), monotonic_clock=lambda: clock[0])
        request = boundary.create_request(
            repository_identity="owner/repo", github_subject_identity="node-1", required_capabilities=("issues:write",),
            driver_identity=TRUST.trusted_driver_identity, remote_authority="sha256:" + "a" * 64,
            preview_id="preview-1", revision=1, operation_set_digest="sha256:" + "b" * 64,
            remote_snapshot_digest="sha256:" + "c" * 64, evidence_digest="sha256:" + "d" * 64,
        )
        provider = FakeCredentialCapabilityProvider(attestation_version="2")
        envelope = provider.attest(request)
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: boundary.verify(envelope, request, NOW), (1, 2)))
        self.assertEqual(sorted(result.success for result in results), [False, True])
        self.assertEqual(sum(result.success for result in results), 1)

        before_boundary = AttestationRuntimeBoundary(self.fake_issuer, self.fake_issuer, self.fake_issuer, FakeCapabilityPolicy(), monotonic_clock=lambda: clock[0])
        before_request = before_boundary.create_request(
            repository_identity="owner/repo", github_subject_identity="node-1", required_capabilities=("issues:write",),
            driver_identity=TRUST.trusted_driver_identity, remote_authority="sha256:" + "a" * 64,
            preview_id="preview-1", revision=1, operation_set_digest="sha256:" + "b" * 64,
            remote_snapshot_digest="sha256:" + "c" * 64, evidence_digest="sha256:" + "d" * 64,
        )
        clock[0] = 299.999
        before = before_boundary.verify(provider.attest(before_request), before_request, NOW)
        self.assertTrue(before.success)

        clock[0] = 0.0
        expired_boundary = AttestationRuntimeBoundary(self.fake_issuer, self.fake_issuer, self.fake_issuer, FakeCapabilityPolicy(), monotonic_clock=lambda: clock[0])
        expired_request = expired_boundary.create_request(
            repository_identity="owner/repo", github_subject_identity="node-1", required_capabilities=("issues:write",),
            driver_identity=TRUST.trusted_driver_identity, remote_authority="sha256:" + "a" * 64,
            preview_id="preview-1", revision=1, operation_set_digest="sha256:" + "b" * 64,
            remote_snapshot_digest="sha256:" + "c" * 64, evidence_digest="sha256:" + "d" * 64,
        )
        expired_envelope = provider.attest(expired_request)
        clock[0] = 300.0
        expired = expired_boundary.verify(expired_envelope, expired_request, NOW)
        self.assertFalse(expired.success)
        self.assertEqual(expired.failures[0].code, "attestation_challenge_expired")

        clock[0] = 0.0
        after_boundary = AttestationRuntimeBoundary(self.fake_issuer, self.fake_issuer, self.fake_issuer, FakeCapabilityPolicy(), monotonic_clock=lambda: clock[0])
        after_request = after_boundary.create_request(
            repository_identity="owner/repo", github_subject_identity="node-1", required_capabilities=("issues:write",),
            driver_identity=TRUST.trusted_driver_identity, remote_authority="sha256:" + "a" * 64,
            preview_id="preview-1", revision=1, operation_set_digest="sha256:" + "b" * 64,
            remote_snapshot_digest="sha256:" + "c" * 64, evidence_digest="sha256:" + "d" * 64,
        )
        clock[0] = 301.0
        after = after_boundary.verify(provider.attest(after_request), after_request, NOW)
        self.assertFalse(after.success)
        self.assertEqual(after.failures[0].code, "attestation_challenge_expired")

    def test_v2_rejects_provider_substituted_challenge(self):
        self.fake_issuer.evaluate = lambda *args: IssuerTrustDecision(True)
        self.provider = FakeCredentialCapabilityProvider(attestation_version="2")
        self.provider.challenge_digest_override = "sha256:" + "0" * 64
        self.service = RuntimeAttestationOrchestrationService(
            self.context, self.store, TRUST,
            AttestationRuntimeBoundary(self.fake_issuer, self.fake_issuer, self.fake_issuer, FakeCapabilityPolicy()),
            self.provider, self.resolver, clock=lambda: NOW,
        )
        substituted = self.run_service()
        self.assertFalse(substituted.success)
        self.assertEqual(substituted.failures[0].code, "attestation_challenge_mismatch")

    def test_v2_runtime_restart_requires_fresh_challenge_and_reacquires(self):
        issuer = self.fake_issuer
        issuer.evaluate = lambda *args: IssuerTrustDecision(True)
        values = dict(
            repository_identity="owner/repo", github_subject_identity="node-1", required_capabilities=("issues:write",),
            driver_identity=TRUST.trusted_driver_identity, remote_authority="sha256:" + "a" * 64,
            preview_id="preview-1", revision=1, operation_set_digest="sha256:" + "b" * 64,
            remote_snapshot_digest="sha256:" + "c" * 64, evidence_digest="sha256:" + "d" * 64,
        )
        runtime_a = AttestationRuntimeBoundary(issuer, issuer, issuer, FakeCapabilityPolicy())
        request_a = runtime_a.create_request(**values)
        provider = FakeCredentialCapabilityProvider(attestation_version="2")
        envelope_a = provider.attest(request_a)
        self.assertTrue(runtime_a.verify(envelope_a, request_a, NOW).success)

        runtime_b = AttestationRuntimeBoundary(issuer, issuer, issuer, FakeCapabilityPolicy())
        stale = runtime_b.verify(envelope_a, request_a, NOW)
        self.assertFalse(stale.success)
        request_b = runtime_b.create_request(**values)
        envelope_b = provider.attest(request_b)
        fresh = runtime_b.verify(envelope_b, request_b, NOW)
        self.assertTrue(fresh.success)
        self.assertNotEqual(request_a.challenge_digest, request_b.challenge_digest)

    def test_v2_persisted_lifecycle_requires_fresh_runtime_and_provider_exchange(self):
        self.fake_issuer.evaluate = lambda *args: IssuerTrustDecision(True)
        provider = FakeCredentialCapabilityProvider(attestation_version="2")
        boundary_a = AttestationRuntimeBoundary(
            self.fake_issuer, self.fake_issuer, self.fake_issuer, FakeCapabilityPolicy()
        )
        service_a = RuntimeAttestationOrchestrationService(
            self.context, self.store, TRUST, boundary_a, provider, self.resolver, clock=lambda: NOW
        )

        result_a = service_a.orchestrate(self.preview["preview_id"], self.preview["revision"])
        self.assertTrue(result_a.success)
        assert result_a.binding is not None
        binding_a = result_a.binding
        request_a = provider.last_request
        self.assertIsNotNone(request_a)
        assert request_a is not None
        challenge_a = request_a.challenge_digest

        # Persist the exact envelope returned by the exchange that Runtime A
        # verified; persistence is deliberately exercised as a separate store.
        envelope_a = provider.last_attestation
        self.assertIsNotNone(envelope_a)
        artifact = artifact_for(envelope_a.claims, workspace=self.context.workspace_identity)
        reference_values = {
            "reference_contract_version": "attestation-binding-reference-v2",
            "reference_id": "",
            "workspace_identity": artifact.workspace_identity,
            "artifact_id": artifact.artifact_id,
            "artifact_digest": artifact.artifact_digest,
            "binding_id": binding_a.binding_id,
            "repository_identity": binding_a.repository_identity,
            "github_subject_identity": binding_a.github_subject_identity,
            "driver_identity": binding_a.driver_identity,
            "remote_authority": binding_a.remote_authority,
            "preview_id": binding_a.preview_id,
            "revision": binding_a.revision,
            "plan_digest": binding_a.plan_digest,
            "sealed_preview_digest": binding_a.sealed_preview_digest,
            "operation_set_digest": binding_a.operation_set_digest,
            "remote_snapshot_digest": binding_a.remote_snapshot_digest,
            "audit_id": binding_a.audit_id,
            "audit_digest": binding_a.audit_digest,
            "evidence_id": binding_a.evidence_id,
            "evidence_digest": binding_a.evidence_digest,
            "original_verified_at": artifact.original_verified_at,
            "binding_reference_digest": "",
            "credential_principal_identity": binding_a.credential_principal_identity,
            "challenge_digest": binding_a.challenge_digest,
        }
        reference_values["binding_reference_digest"] = digest(
            AttestationBindingReference._content_payload_for(reference_values)
        )
        reference_values["reference_id"] = "binding-reference-" + hashlib.sha256(
            canonical_payload({
                "domain": "delivery-system:attestation-binding-reference-identity:v1",
                "payload": {
                    "reference_version": "2",
                    "workspace_identity": artifact.workspace_identity,
                    "artifact_id": artifact.artifact_id,
                    "binding_id": binding_a.binding_id,
                },
            }).encode("utf-8")
        ).hexdigest()
        reference = AttestationBindingReference(**reference_values)

        path = self.directory.name + "\\persisted-v2.sqlite3"
        persisted = SQLiteAttestationPersistenceStore(path, workspace_identity=self.context.workspace_identity)
        try:
            persisted.persist_artifact(artifact, reference)
            self.assertTrue(service_a.accepts_binding(binding_a))
            del service_a, boundary_a

            aggregate = persisted.get_artifact_aggregate(self.context.workspace_identity, artifact.artifact_id)
            self.assertIsNotNone(aggregate)
            assert aggregate is not None
            self.assertEqual(aggregate.artifact.artifact_digest, artifact.artifact_digest)
            self.assertEqual(aggregate.artifact.claims_payload.challenge_digest, challenge_a)
            self.assertEqual(aggregate.binding_reference.challenge_digest, challenge_a)

            boundary_b = AttestationRuntimeBoundary(
                self.fake_issuer, self.fake_issuer, self.fake_issuer, FakeCapabilityPolicy()
            )
            service_b = RuntimeAttestationOrchestrationService(
                self.context, self.store, TRUST, boundary_b, provider, self.resolver, clock=lambda: NOW
            )
            self.assertIsNone(service_b.lookup_binding(binding_a.binding_id))
            self.assertFalse(service_b.accepts_binding(binding_a))
            stale = boundary_b.verify(envelope_a, request_a, NOW)
            self.assertFalse(stale.success)
            self.assertEqual(stale.failures[0].code, "attestation_request_unavailable")

            result_b = service_b.orchestrate(self.preview["preview_id"], self.preview["revision"])
            self.assertTrue(result_b.success)
            assert result_b.binding is not None
            binding_b = result_b.binding
            request_b = provider.last_request
            self.assertIsNotNone(request_b)
            assert request_b is not None
            self.assertNotEqual(challenge_a, request_b.challenge_digest)
            self.assertEqual(binding_b.challenge_digest, request_b.challenge_digest)
            self.assertNotEqual(binding_a.binding_id, binding_b.binding_id)
            self.assertIsNone(service_b.lookup_binding(binding_a.binding_id))
            self.assertTrue(service_b.accepts_binding(binding_b))
            self.assertNotEqual(binding_a.attestation_id, binding_b.attestation_id)
        finally:
            persisted.close()

    def test_request_fields_are_runtime_derived_and_not_caller_inputs(self):
        result = self.run_service()
        self.assertTrue(result.success)
        request = self.provider.last_request
        assert request is not None
        canonical = self.preview
        evidence = self.store.get_evidence_records(self.context.workspace_identity, canonical["evidence_ids"])
        self.assertEqual(request.repository_identity, canonical["repository_identity"])
        self.assertEqual(request.preview_id, canonical["preview_id"])
        self.assertEqual(request.revision, canonical["revision"])
        self.assertEqual(request.operation_set_digest, canonical["operation_set_digest"])
        self.assertEqual(request.remote_snapshot_digest, canonical["remote_snapshot_digest"])
        self.assertEqual(request.remote_authority, canonical["remote_authority"])
        self.assertEqual(request.evidence_digest, evidence[-1]["evidence_digest"])
        self.assertEqual(request.driver_identity, TRUST.trusted_driver_identity)
        self.assertEqual(request.github_subject_identity, "node-1")
        self.assertEqual(self.resolver.calls, 1)

    def test_provider_is_called_once_and_failures_leave_no_binding(self):
        self.provider.fail = True
        result = self.run_service()
        self.assertEqual(result.failures[0].code, "attestation_provider_unavailable")
        self.assertEqual(self.provider.calls, 1)
        self.assertIsNone(result.binding)
        self.assertIsNone(self.service.lookup_binding("missing"))

    def test_missing_audit_and_non_repository_preview_fail_closed(self):
        empty = InMemoryPreviewStore(self.context.workspace_identity, TRUST)
        service = RuntimeAttestationOrchestrationService(
            self.context, empty, TRUST,
            AttestationRuntimeBoundary(self.fake_issuer, self.fake_issuer, self.fake_issuer, FakeCapabilityPolicy()),
            self.provider, self.resolver, clock=lambda: NOW,
        )
        self.assertEqual(service.orchestrate(self.preview["preview_id"], 1).failures[0].code, "attestation_preview_not_found")

        conceptual_store = InMemoryPreviewStore(self.context.workspace_identity)
        conceptual = RuntimePlanner(self.context, conceptual_store).preview(plan())
        service = RuntimeAttestationOrchestrationService(
            self.context, conceptual_store, TRUST,
            AttestationRuntimeBoundary(self.fake_issuer, self.fake_issuer, self.fake_issuer, FakeCapabilityPolicy()),
            self.provider, self.resolver, clock=lambda: NOW,
        )
        self.assertEqual(service.orchestrate(conceptual["preview_id"], 1).failures[0].code, "attestation_preview_not_repository_aware")

    def test_ticket_and_binding_cross_service_or_forged_objects_are_rejected(self):
        result = self.run_service()
        assert result.binding is not None
        other = RuntimeAttestationOrchestrationService(
            self.context, self.store, TRUST,
            AttestationRuntimeBoundary(self.fake_issuer, self.fake_issuer, self.fake_issuer, FakeCapabilityPolicy()),
            self.provider, self.resolver, clock=lambda: NOW,
        )
        self.assertFalse(other.accepts_binding(result.binding))
        with self.assertRaisesRegex(ValueError, "^runtime_binding_internal_only$"):
            RuntimeCredentialCapabilityBinding()
        forged = object.__new__(RuntimeCredentialCapabilityBinding)
        object.__setattr__(forged, "binding_id", result.binding.binding_id)
        self.assertFalse(other.accepts_binding(forged))

    def test_same_candidate_is_idempotent_and_different_attestation_conflicts(self):
        first = self.run_service()
        second = self.run_service()
        self.assertTrue(first.success and second.success)
        self.assertIs(first.binding, second.binding)
        self.assertEqual(first.binding.binding_id, second.binding.binding_id)  # type: ignore[union-attr]
        self.provider.credential_instance_id = "fake-instance-2"
        conflict = self.run_service()
        self.assertEqual(conflict.failures[0].code, "attestation_binding_conflict")
        self.assertEqual(len(self.service._RuntimeAttestationOrchestrationService__bindings_by_id), 1)

    def test_concurrent_same_candidate_merges(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.run_service(), range(4)))
        self.assertTrue(all(result.success for result in results))
        self.assertEqual(len({result.binding.binding_id for result in results if result.binding}), 1)
        self.assertEqual(len(self.service._RuntimeAttestationOrchestrationService__bindings_by_id), 1)

    def test_invalid_resolver_output_and_unknown_subject_fail_closed(self):
        bad_resolver = FakeCapabilityResolver(("issues:write", "issues:write"))
        service = RuntimeAttestationOrchestrationService(
            self.context, self.store, TRUST,
            AttestationRuntimeBoundary(self.fake_issuer, self.fake_issuer, self.fake_issuer, FakeCapabilityPolicy()),
            self.provider, bad_resolver, clock=lambda: NOW,
        )
        self.assertEqual(service.orchestrate(self.preview["preview_id"], 1).failures[0].code, "attestation_capability_requirement_invalid")

    def test_binding_does_not_create_approval_operation_or_change_preview(self):
        before = self.store.get_preview(self.context.workspace_identity, self.preview["preview_id"])
        result = self.run_service()
        after = self.store.get_preview(self.context.workspace_identity, self.preview["preview_id"])
        self.assertTrue(result.success)
        self.assertEqual(before, after)
        self.assertEqual(self.store.list_active_audits(self.context.workspace_identity, self.preview["preview_id"], 1), [self.audit])
        self.assertFalse(self.preview["write_eligible"])

    def test_registered_binding_integrity_rejects_each_mutable_slot(self):
        for field, value in (
            ("granted_capabilities", ("issues:read",)),
            ("required_capabilities", ("issues:read",)),
            ("expires_at", "2026-08-14T12:01:00Z"),
            ("credential_instance_id", "tampered-instance"),
            ("audit_digest", "tampered-audit"),
            ("evidence_digest", "tampered-evidence"),
            ("binding_id", "binding-tampered"),
        ):
            with self.subTest(field=field):
                result = self.run_service()
                assert result.binding is not None
                object.__setattr__(result.binding, field, value)
                self.assertFalse(self.service.accepts_binding(result.binding))
                self.assertIsNone(self.service.lookup_binding(result.binding.binding_id))
                self.assertFalse(self.service.accepts_binding(result.binding.to_dict()))
                repeated = self.run_service()
                self.assertFalse(repeated.success)
                self.assertEqual(repeated.failures[0].code, "attestation_binding_integrity_failed")
                self.provider = FakeCredentialCapabilityProvider()
                self.service = RuntimeAttestationOrchestrationService(
                    self.context, self.store, TRUST,
                    AttestationRuntimeBoundary(self.fake_issuer, self.fake_issuer, self.fake_issuer, FakeCapabilityPolicy()),
                    self.provider, self.resolver, clock=lambda: NOW,
                )

    def test_stale_revision_and_preview_integrity_are_distinct(self):
        stale = self.service.orchestrate(self.preview["preview_id"], self.preview["revision"] + 1)
        self.assertEqual(stale.failures[0].code, "attestation_preview_stale")

        class BrokenPreviewStore:
            def __init__(self, wrapped):
                self.wrapped = wrapped
                self.trust_context = wrapped.trust_context

            def get_preview(self, workspace_identity, preview_id):
                value = self.wrapped.get_preview(workspace_identity, preview_id)
                value["canonical_payload"]["plan_digest"] = "broken"
                return value

            def get_preview_revision(self, workspace_identity, preview_id, revision):
                value = self.wrapped.get_preview_revision(workspace_identity, preview_id, revision)
                value["canonical_payload"]["plan_digest"] = "broken"
                return value

            def __getattr__(self, name):
                return getattr(self.wrapped, name)

        broken = RuntimeAttestationOrchestrationService(
            self.context, BrokenPreviewStore(self.store), TRUST,
            AttestationRuntimeBoundary(self.fake_issuer, self.fake_issuer, self.fake_issuer, FakeCapabilityPolicy()),
            self.provider, self.resolver, clock=lambda: NOW,
        )
        result = broken.orchestrate(self.preview["preview_id"], 1)
        self.assertEqual(result.failures[0].code, "attestation_preview_integrity_invalid")

    def test_audit_missing_ambiguity_and_binding_mismatch_fail_closed(self):
        class AuditViewStore:
            def __init__(self, wrapped, audits):
                self.wrapped = wrapped
                self.audits = audits
                self.trust_context = wrapped.trust_context

            def list_active_audits(self, *args):
                return self.audits

            def __getattr__(self, name):
                return getattr(self.wrapped, name)

        for audits, code in (([], "attestation_audit_missing"), ([self.audit, self.audit], "attestation_audit_ambiguous"),
                             ([replace(self.audit, plan_digest="bad")], "attestation_audit_binding_mismatch")):
            with self.subTest(code=code):
                service = RuntimeAttestationOrchestrationService(
                    self.context, AuditViewStore(self.store, audits), TRUST,
                    AttestationRuntimeBoundary(self.fake_issuer, self.fake_issuer, self.fake_issuer, FakeCapabilityPolicy()),
                    self.provider, self.resolver, clock=lambda: NOW,
                )
                self.assertEqual(service.orchestrate(self.preview["preview_id"], 1).failures[0].code, code)

    def test_provider_shape_claim_binding_and_ticket_failures_leave_no_binding(self):
        self.provider.malformed = object()
        malformed = self.run_service()
        self.assertEqual(malformed.failures[0].code, "attestation_provider_response_invalid")
        self.assertEqual(len(self.service._RuntimeAttestationOrchestrationService__bindings_by_id), 0)

        self.provider.malformed = None
        self.provider.repository_identity_override = "other/repo"
        mismatch = self.run_service()
        self.assertEqual(mismatch.failures[0].code, "attestation_binding_mismatch")
        self.assertEqual(len(self.service._RuntimeAttestationOrchestrationService__bindings_by_id), 0)

        class ConsumeFailBoundary(AttestationRuntimeBoundary):
            def consume_ticket(self, ticket):
                raise ValueError("ticket-internal")

        service = RuntimeAttestationOrchestrationService(
            self.context, self.store, TRUST,
            ConsumeFailBoundary(self.fake_issuer, self.fake_issuer, self.fake_issuer, FakeCapabilityPolicy()),
            self.provider, self.resolver, clock=lambda: NOW,
        )
        self.provider.repository_identity_override = None
        consumed = service.orchestrate(self.preview["preview_id"], 1)
        self.assertEqual(consumed.failures[0].code, "attestation_ticket_consume_failed")
        self.assertEqual(len(service._RuntimeAttestationOrchestrationService__bindings_by_id), 0)

    def test_resolver_empty_and_exception_fail_closed(self):
        class EmptyResolver:
            def resolve(self, operation_intents):
                return ()

        class FailingResolver:
            def resolve(self, operation_intents):
                raise RuntimeError("resolver-internal")

        for resolver, code in ((EmptyResolver(), "attestation_capability_requirement_invalid"),
                               (FailingResolver(), "attestation_capability_resolution_unavailable")):
            with self.subTest(code=code):
                service = RuntimeAttestationOrchestrationService(
                    self.context, self.store, TRUST,
                    AttestationRuntimeBoundary(self.fake_issuer, self.fake_issuer, self.fake_issuer, FakeCapabilityPolicy()),
                    self.provider, resolver, clock=lambda: NOW,
                )
                self.assertEqual(service.orchestrate(self.preview["preview_id"], 1).failures[0].code, code)

    def test_evidence_missing_ambiguity_and_binding_mismatch_fail_closed(self):
        class EvidenceViewStore:
            def __init__(self, wrapped, mode):
                self.wrapped = wrapped
                self.mode = mode
                self.trust_context = wrapped.trust_context

            def get_evidence_records(self, workspace_identity, evidence_ids):
                records = self.wrapped.get_evidence_records(workspace_identity, evidence_ids)
                drivers = [record for record in records if record.get("source_kind") == "driver"]
                if self.mode == "missing":
                    return [record for record in records if record.get("source_kind") != "driver"]
                if self.mode == "ambiguous":
                    return records + drivers
                if self.mode == "mismatch":
                    changed = [dict(record) for record in records]
                    for record in changed:
                        if record.get("source_kind") == "driver":
                            record["source_identity"] = "other-driver"
                    return changed
                return records

            def __getattr__(self, name):
                return getattr(self.wrapped, name)

        # AuditContextService validates the complete evidence set before the
        # orchestration selector runs; malformed sets therefore fail at the
        # earlier preview integrity boundary with the current Store contract.
        for mode, expected in (("missing", "attestation_preview_integrity_invalid"),
                               ("ambiguous", "attestation_preview_integrity_invalid"),
                               ("mismatch", "attestation_preview_integrity_invalid")):
            with self.subTest(mode=mode):
                service = RuntimeAttestationOrchestrationService(
                    self.context, EvidenceViewStore(self.store, mode), TRUST,
                    AttestationRuntimeBoundary(self.fake_issuer, self.fake_issuer, self.fake_issuer, FakeCapabilityPolicy()),
                    self.provider, self.resolver, clock=lambda: NOW,
                )
                self.assertEqual(service.orchestrate(self.preview["preview_id"], 1).failures[0].code, expected)

    def test_subject_source_priority_and_login_exclusion(self):
        self.assertEqual(_subject_from_payload({
            "authenticated_user_node_id": "node", "authenticated_user_id": "user",
            "authenticated_subject": "subject", "authenticated_login": "login",
        }), "node")
        self.assertEqual(_subject_from_payload({
            "authenticated_user_id": "user", "authenticated_subject": "subject",
            "authenticated_login": "login",
        }), "user")
        self.assertEqual(_subject_from_payload({
            "authenticated_subject": "subject", "authenticated_login": "login",
        }), "subject")
        self.assertIsNone(_subject_from_payload({"authenticated_login": "login"}))

    def test_typed_binding_snapshot_rejects_equivalent_but_wrong_types(self):
        class TupleSubclass(tuple):
            pass

        class StrSubclass(str):
            pass

        mutations = (
            ("required_capabilities", ["issues:write"]),
            ("granted_capabilities", ["issues:write"]),
            ("required_capabilities", TupleSubclass(("issues:write",))),
            ("granted_capabilities", TupleSubclass(("issues:write",))),
            ("repository_identity", StrSubclass("owner/repo")),
            ("revision", True),
            ("revision", type("IntSubclass", (int,), {})(1)),
        )
        for field, replacement in mutations:
            with self.subTest(field=field, replacement=type(replacement).__name__):
                provider = FakeCredentialCapabilityProvider()
                service = RuntimeAttestationOrchestrationService(
                    self.context, self.store, TRUST,
                    AttestationRuntimeBoundary(self.fake_issuer, self.fake_issuer, self.fake_issuer, FakeCapabilityPolicy()),
                    provider, self.resolver, clock=lambda: NOW,
                )
                result = service.orchestrate(self.preview["preview_id"], 1)
                self.assertTrue(result.success)
                assert result.binding is not None
                object.__setattr__(result.binding, field, replacement)
                self.assertFalse(service.accepts_binding(result.binding))
                self.assertIsNone(service.lookup_binding(result.binding.binding_id))
                repeated = service.orchestrate(self.preview["preview_id"], 1)
                self.assertFalse(repeated.success)
                self.assertEqual(repeated.failures[0].code, "attestation_binding_integrity_failed")
                self.assertEqual(len(service._RuntimeAttestationOrchestrationService__bindings_by_id), 1)
                self.assertFalse(self.preview["write_eligible"])


if __name__ == "__main__":
    unittest.main()
