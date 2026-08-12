"""Shared contract cases for every PreviewStore adapter used by tests."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from typing import Callable

from delivery_system.protocol import digest
from delivery_system.runtime import ApprovalRecord, AuditRecord, AuditResult, AuditStatus, EvidenceRecord, TypedRemoteSnapshot
from delivery_system.auditor import RuleEvaluationDraft
from delivery_system.rules import SemanticOutcome


def run_store_contract(testcase, store_factory: Callable[[], tuple[object, str]]) -> int:
    """Replay the common Store contract against one adapter factory."""
    store, workspace = store_factory()
    def save(sid, rev, plan="plan", items=None):
        items = items or []
        semantic = {"contract_plan": plan}
        operations = [{"operation_kind": "create_issue", "client_refs": [item["client_ref"]], "depends_on": []} for item in items]
        pdigest = digest(semantic)
        odigest = digest({"operation_intents": operations})
        canonical = {
            "workspace_identity": workspace, "request_id": "request", "preview_id": sid, "revision": rev,
            "preview_level": "Conceptual", "provenance_status": "declared_unverified",
            "semantic_payload": semantic, "operation_intents": operations,
            "repository_identity": None, "remote_authority": None,
            "plan_digest": pdigest, "operation_set_digest": odigest,
            "remote_snapshot": None, "remote_snapshot_digest": None,
            "items": items, "blockers": [], "planner_observations": [], "evidence_ids": [],
        }
        canonical["sealed_preview_digest"] = digest(canonical)
        return store.save_preview_revision(
            "request", sid, rev, pdigest, None, odigest, None, items,
            workspace_identity=workspace, canonical_payload=canonical,
            evidence_records=[],
        )

    save("contract-success", 1, items=[])
    testcase.assertEqual(store.get_preview(workspace, "contract-success")["revision"], 1)

    with testcase.assertRaises(ValueError):
        save("contract-cross", 1, items=[])
        store.save_preview_revision("request", "contract-cross", 2, "p", None, "o", None, [], workspace_identity="other")

    orphan = ApprovalRecord(
        "orphan", "missing-audit", "digest", AuditResult.PASSED, "missing-preview", 1,
        "plan", "remote", "ops", "repo", "批准写入 missing-preview 1", "operator",
        "2026-08-11T00:00:00+00:00", "valid",
    )
    with testcase.assertRaises(ValueError):
        store.record_approval(orphan)

    missing_audit = AuditRecord.create("missing-preview-audit", "missing-preview", 1, "plan", "remote", "ops", AuditResult.PASSED)
    store.record_audit(missing_audit)
    missing_approval = ApprovalRecord.create("missing-preview-approval", missing_audit, "repo", "operator", "2026-08-11T00:00:00+00:00", "批准写入 missing-preview 1")
    with testcase.assertRaises(ValueError):
        store.record_approval(missing_approval)

    save("contract-stale", 1, items=[])
    stale_preview = store.get_preview(workspace, "contract-stale")
    stale_canonical = stale_preview["canonical_payload"]
    stale_audit = AuditRecord.create("contract-stale-audit", "contract-stale", 1,
                                     stale_canonical["plan_digest"], "remote",
                                     stale_canonical["operation_set_digest"], AuditResult.PASSED)
    store.record_audit(stale_audit)
    stale_approval = ApprovalRecord.create("contract-stale-approval", stale_audit, "repo", "operator", "2026-08-11T00:00:00+00:00", "批准写入 contract-stale 1")
    with testcase.assertRaises(ValueError):
        store.record_approval(stale_approval)
    testcase.assertFalse(store.validate_approval_current(stale_approval))
    with testcase.assertRaises(ValueError):
        save("contract-stale", 1, plan="changed", items=[])
    save("contract-stale", 2, plan="changed", items=[])
    testcase.assertEqual(store.get_audit(workspace, stale_audit.audit_id).status, AuditStatus.STALE)
    testcase.assertFalse(store.validate_approval_current(stale_approval))

    mismatch_audit = AuditRecord.create("digest-audit", "digest-preview", 1, "plan", "remote", "ops", AuditResult.PASSED)
    save("digest-preview", 1, items=[])
    store.record_audit(mismatch_audit)
    mismatch = ApprovalRecord.create("digest-approval", mismatch_audit, "repo", "operator", "2026-08-11T00:00:00+00:00", "批准写入 digest-preview 1")
    mismatch = mismatch.__class__(**{**mismatch.to_dict(), "plan_digest": "wrong"})
    with testcase.assertRaises(ValueError):
        store.record_approval(mismatch)

    save("contract-retry", 1, items=[])
    save("contract-retry", 1, items=[])
    with testcase.assertRaises(ValueError):
        save("contract-retry", 1, plan="different", items=[])

    with testcase.assertRaises(ValueError):
        save("duplicate-ref", 1, items=[
            {"client_ref": "same", "previous_client_ref": None, "item_id": "a"},
            {"client_ref": "same", "previous_client_ref": None, "item_id": "b"},
        ])
    with testcase.assertRaises((KeyError, ValueError)):
        save("malformed-item", 1, items=[{"client_ref": "missing-item-id"}])
    with testcase.assertRaises((KeyError, ValueError)):
        save("atomic-failure", 1, items=[
            {"client_ref": "first", "previous_client_ref": None, "item_id": "a"},
            {"client_ref": "broken", "previous_client_ref": None},
        ])
    with testcase.assertRaises(ValueError):
        store.get_preview(workspace, "atomic-failure")
    with testcase.assertRaises(ValueError):
        store.resolve_item_id(workspace, "atomic-failure", "first", 1)

    return 13


def run_auditor_store_contract(testcase, context, store, auditor, preview) -> int:
    """Replay the Slice 2B audit persistence contract against one adapter."""
    canonical = store.get_preview_revision(context.workspace_identity, preview["preview_id"], preview["revision"])["canonical_payload"]
    evaluations = [
        RuleEvaluationDraft(rule.rule_id, rule.rule_version, SemanticOutcome.PASSED, "contract pass")
        for rule in auditor.registry.semantic_rules if auditor._applicable(rule, canonical)
    ]
    context_payload = auditor.get_context(preview["preview_id"], preview["revision"])
    # The helper deliberately obtains the digest from the Runtime context service.
    first = auditor.record_audit(preview["preview_id"], preview["revision"], context_payload["audit_context_digest"], evaluations, [])
    retry = auditor.record_audit(preview["preview_id"], preview["revision"], context_payload["audit_context_digest"], evaluations, [])
    testcase.assertEqual(first.audit_id, retry.audit_id)
    testcase.assertEqual(first.audit_payload_digest, retry.audit_payload_digest)
    testcase.assertEqual(store.get_audit(context.workspace_identity, first.audit_id).audit_id, first.audit_id)
    testcase.assertTrue(any(entry["outcome"] == "NotApplicable" for entry in first.rule_evaluations))
    forged_registry = replace(first, audit_id="forged-registry", rule_registry_version="666")._with_digest()
    with testcase.assertRaisesRegex(ValueError, "^audit_commit_boundary_required$"):
        store.commit_audit(forged_registry)
    with testcase.assertRaisesRegex(ValueError, "^audit_not_found$"):
        store.get_audit(context.workspace_identity, "forged-registry")
    malformed_evaluation = dict(first.rule_evaluations[0])
    malformed_evaluation["runtime_gate_passed"] = True
    malformed = replace(
        first,
        audit_id="malformed-evaluation",
        rule_evaluations=(malformed_evaluation,) + first.rule_evaluations[1:],
    )._with_digest()
    with testcase.assertRaisesRegex(ValueError, "^audit_commit_boundary_required$"):
        store.commit_audit(malformed)
    with testcase.assertRaisesRegex(ValueError, "^audit_not_found$"):
        store.get_audit(context.workspace_identity, "malformed-evaluation")
    stale_direct = first.transition(AuditStatus.STALE, "contract")
    with testcase.assertRaisesRegex(ValueError, "^audit_commit_boundary_required$"):
        store.commit_audit(stale_direct)
    changed_evaluations = [replace(item, rationale="changed") for item in evaluations]
    replacement = auditor.record_audit(
        preview["preview_id"], preview["revision"], context_payload["audit_context_digest"], changed_evaluations, []
    )
    testcase.assertNotEqual(replacement.audit_id, first.audit_id)
    testcase.assertEqual(store.get_audit(context.workspace_identity, first.audit_id).status, AuditStatus.STALE)
    testcase.assertEqual(store.list_active_audits(context.workspace_identity, preview["preview_id"], preview["revision"])[0].audit_id, replacement.audit_id)
    with testcase.assertRaisesRegex(ValueError, "^audit_coverage_incomplete$"):
        auditor.record_audit(
            preview["preview_id"], preview["revision"], context_payload["audit_context_digest"],
            evaluations[:-1], [],
        )
    for rule_id, expected in (
        ("RT-PREVIEW-SCHEMA", "invalid_runtime_rule_submission"),
        ("RT-UNKNOWN", "invalid_input"),
        ("SEM-UNKNOWN", "invalid_input"),
        ("SEM-DUPLICATE-OVERLAP", "invalid_not_applicable_submission"),
    ):
        with testcase.assertRaisesRegex(ValueError, f"^{expected}$"):
            auditor.record_audit(
                preview["preview_id"], preview["revision"], context_payload["audit_context_digest"],
                [RuleEvaluationDraft(rule_id, "1.0", "NotApplicable" if rule_id.startswith("SEM-") else SemanticOutcome.PASSED, "invalid")], [],
            )
    with testcase.assertRaisesRegex(ValueError, "^invalid_input$"):
        auditor.record_audit(preview["preview_id"], preview["revision"], "wrong", evaluations, [])
    with testcase.assertRaisesRegex(ValueError, "^audit_not_found$"):
        store.get_audit(context.workspace_identity, "missing-audit")
    return 4


def run_trust_boundary_contract(testcase, store_factory: Callable[[], tuple[object, str]]) -> int:
    """Failure-first trust-boundary cases replayed against each Store adapter."""
    store, workspace = store_factory()
    semantic = {"contract_plan": "trust"}
    operations = [{"operation_kind": "create_issue", "client_refs": ["item"], "depends_on": []}]
    snapshot = TypedRemoteSnapshot.from_records(
        "repo", {"state": "open"}, True, True,
        [{"issue_id": "1", "item_type": "issue", "title": "Issue", "updated_at": "2026-01-01T00:00:00+00:00", "repository_identity": "repo"}],
        {"issues:read": True, "issues:write": True}, ["issues"], [],
    )
    plan_digest = digest(semantic)
    operation_digest = digest({"operation_intents": operations})
    items = [{"client_ref": "item", "previous_client_ref": None, "item_id": "item-1"}]

    def make_canonical(preview_id="trust-preview", **changes):
        value = {
            "workspace_identity": workspace, "request_id": "trust-request", "preview_id": preview_id, "revision": 1,
            "preview_level": "RepositoryAware", "provenance_status": "declared_unverified", "repository_identity": "repo", "remote_authority": "test_fixture",
            "semantic_payload": semantic, "operation_intents": operations,
            "plan_digest": plan_digest, "operation_set_digest": operation_digest,
            "remote_snapshot": snapshot.to_dict(), "remote_snapshot_digest": snapshot.digest(),
            "items": items, "blockers": [], "planner_observations": [], "evidence_ids": [],
        }
        value.update(changes)
        value["sealed_preview_digest"] = digest(value)
        return value

    def save(value, supplied_items=None, supplied_workspace=workspace):
        if supplied_items is None:
            supplied_items = value["items"]
        return store.save_preview_revision(
            value["request_id"], value["preview_id"], value["revision"], value["plan_digest"], value["remote_snapshot_digest"],
            value["operation_set_digest"], value.get("repository_identity"), supplied_items,
            workspace_identity=supplied_workspace, canonical_payload=value,
            evidence_records=[],
        )

    incomplete_snapshot = TypedRemoteSnapshot.from_records(
        "repo", {"state": "open"}, False, False, [], {}, [], [],
        observed_at="2026-01-01T00:00:00+00:00",
    )
    incomplete = make_canonical(
        remote_snapshot=incomplete_snapshot.to_dict(),
        remote_snapshot_digest=incomplete_snapshot.digest(),
        operation_intents=[], operation_set_digest=digest({"operation_intents": []}),
    )
    with testcase.assertRaisesRegex(ValueError, "^preview_level_unverified$"):
        save(incomplete)

    with testcase.assertRaisesRegex(ValueError, "^workspace_identity_mismatch$"):
        save(make_canonical(preview_id="trust-workspace", workspace_identity="other"))

    with testcase.assertRaisesRegex(ValueError, "^canonical_projection_mismatch$"):
        save(make_canonical(preview_id="trust-projection", preview_level="Conceptual", repository_identity=None, remote_snapshot=None, remote_snapshot_digest=None, remote_authority=None), supplied_items=[{"client_ref": "different", "previous_client_ref": None, "item_id": "item-1"}])

    with testcase.assertRaisesRegex(ValueError, "^sealed_preview_required$"):
        store.save_preview_revision("legacy-request", "legacy-preview", 1, "plan", None, "ops", None, [], workspace_identity=workspace)

    with testcase.assertRaisesRegex(ValueError, "^controlled_evidence_source$"):
        EvidenceRecord._create_controlled(
            workspace, "trust-preview", 1, "remote", "driver", None, "issue:1", {}, None,
            "fake-driver", "repo", {"state": "open"}, "evidence-v1",
        )

    malformed = snapshot.to_dict()
    malformed["query_complete"] = "false"
    with testcase.assertRaisesRegex(ValueError, "^remote_query_completeness_boolean_required$"):
        TypedRemoteSnapshot.from_records(
            "repo", {"state": "open"}, malformed["query_complete"], "false",
            malformed["issue_records"], malformed["permissions"], malformed["capabilities"], [],
        )

    other_snapshot = TypedRemoteSnapshot.from_records(
        "repo-b", {"state": "open"}, True, True,
        [{"issue_id": "2", "item_type": "issue", "title": "Other", "updated_at": "2026-01-01T00:00:00+00:00", "repository_identity": "repo-b"}],
        {"issues:read": True}, ["issues"], [],
    )
    with testcase.assertRaisesRegex(ValueError, "^repository_identity_mismatch$"):
        save(make_canonical(preview_id="trust-repository", remote_snapshot=other_snapshot.to_dict(), remote_snapshot_digest=other_snapshot.digest()))
    with testcase.assertRaisesRegex(ValueError, "^conceptual_repository_forbidden$"):
        save(make_canonical(preview_id="trust-conceptual", preview_level="Conceptual", repository_identity="repo", remote_snapshot=None, remote_snapshot_digest=None, remote_authority=None))
    with testcase.assertRaisesRegex(ValueError, "^preview_level_unverified$"):
        save(make_canonical(preview_id="trust-authority-test", remote_authority="test_fixture"))
    with testcase.assertRaisesRegex(ValueError, "^preview_level_unverified$"):
        save(make_canonical(preview_id="trust-authority-driver", remote_authority="typed_driver"))

    for preview_id in ("trust-preview", "trust-workspace", "trust-projection", "trust-repository", "trust-conceptual", "trust-authority-test", "trust-authority-driver"):
        with testcase.assertRaises(ValueError):
            store.get_preview(workspace, preview_id)
    with testcase.assertRaises(ValueError):
        store.get_evidence_records(workspace, ["missing"])
    return 13


def run_strict_type_contract(testcase, store_factory: Callable[[], tuple[object, str]]) -> int:
    """Replay strict SealedPreview type rejection against each Store adapter."""
    store, workspace = store_factory()
    semantic = {"strict": True}
    operations = [{"operation_kind": "create_issue", "client_refs": ["item"], "depends_on": []}]
    items = [{"client_ref": "item", "previous_client_ref": None, "item_id": "item-1"}]
    base = {
        "workspace_identity": workspace, "request_id": "strict-request", "preview_id": "strict-preview", "revision": 1,
        "preview_level": "Conceptual", "provenance_status": "declared_unverified",
        "repository_identity": None, "remote_authority": None, "semantic_payload": semantic,
        "operation_intents": operations, "plan_digest": digest(semantic),
        "operation_set_digest": digest({"operation_intents": operations}),
        "remote_snapshot": None, "remote_snapshot_digest": None, "items": items,
        "evidence_ids": [], "blockers": [], "planner_observations": [],
    }

    def reject(case, **changes):
        payload = deepcopy(base)
        payload["preview_id"] = f"strict-{case}"
        payload.update(changes)
        payload["sealed_preview_digest"] = digest({key: value for key, value in payload.items() if key != "sealed_preview_digest"})
        with testcase.assertRaises(ValueError):
            store.save_preview_revision(
                payload["request_id"] if isinstance(payload["request_id"], str) else "strict-request",
                payload["preview_id"] if isinstance(payload["preview_id"], str) else f"strict-{case}",
                payload["revision"] if isinstance(payload["revision"], int) else 1,
                payload["plan_digest"], None, payload["operation_set_digest"], None,
                payload["items"] if isinstance(payload["items"], list) else items,
                workspace_identity=workspace, canonical_payload=payload, evidence_records=[],
            )
        with testcase.assertRaisesRegex(ValueError, "^preview_not_found$"):
            store.get_preview(workspace, f"strict-{case}")

    reject("revision-bool", revision=True)
    reject("revision-string", revision="1")
    reject("request-number", request_id=7)
    reject("preview-number", preview_id=8)
    reject("operations-map", operation_intents={})
    reject("items-map", items={})
    reject("provenance", provenance_status="runtime_verified")
    return 7


def run_sealed_schema_contract(testcase, store_factory: Callable[[], tuple[object, str]]) -> int:
    """Reject non-canonical SealedPreview inputs and verify canonical round-trip."""
    store, workspace = store_factory()
    semantic = {"schema": "valid"}
    operations = [{"operation_kind": "create_issue", "client_refs": ["item"], "depends_on": []}]
    items = [{"client_ref": "item", "previous_client_ref": None, "item_id": "item-1"}]
    base = {
        "workspace_identity": workspace, "request_id": "schema-request", "preview_id": "schema-valid", "revision": 1,
        "preview_level": "Conceptual", "provenance_status": "declared_unverified",
        "repository_identity": None, "remote_authority": None, "semantic_payload": semantic,
        "operation_intents": operations, "plan_digest": digest(semantic),
        "operation_set_digest": digest({"operation_intents": operations}),
        "remote_snapshot": None, "remote_snapshot_digest": None, "items": items,
        "evidence_ids": [], "blockers": [], "planner_observations": [],
    }
    base["sealed_preview_digest"] = digest(base)

    def reject(case, mutate):
        payload = deepcopy(base)
        payload["preview_id"] = f"schema-{case}"
        mutate(payload)
        with testcase.assertRaises(ValueError):
            store.save_preview_revision(
                "schema-request", payload["preview_id"], 1, payload["plan_digest"], None,
                payload["operation_set_digest"], None,
                payload["items"] if isinstance(payload.get("items"), list) else items,
                workspace_identity=workspace, canonical_payload=payload, evidence_records=[],
            )
        with testcase.assertRaisesRegex(ValueError, "^preview_not_found$"):
            store.get_preview(workspace, payload["preview_id"])

    reject("missing-blockers", lambda value: value.pop("blockers"))
    reject("blockers-map", lambda value: value.update({"blockers": "not-a-list"}))
    reject("blockers-item", lambda value: value.update({"blockers": ["ok", 7]}))
    reject("missing-observations", lambda value: value.pop("planner_observations"))
    reject("observations-map", lambda value: value.update({"planner_observations": {"not": "a-list"}}))
    reject("observations-item", lambda value: value.update({"planner_observations": ["not-a-map"]}))
    reject("operation-item", lambda value: value.update({"operation_intents": ["not-a-map"]}))
    reject("item-item", lambda value: value.update({"items": ["not-a-map"]}))
    reject("extra-field", lambda value: value.update({"undefined_field": True}))
    def whitespace(value):
        value["semantic_payload"] = {"schema": "  valid  "}
        value["plan_digest"] = digest({"schema": "valid"})
        value["sealed_preview_digest"] = digest({key: item for key, item in value.items() if key != "sealed_preview_digest"})
    reject("unnormalized-text", whitespace)

    store.save_preview_revision(
        "schema-request", "schema-valid", 1, base["plan_digest"], None,
        base["operation_set_digest"], None, items, workspace_identity=workspace,
        canonical_payload=base, evidence_records=[],
    )
    stored = store.get_preview(workspace, "schema-valid")["canonical_payload"]
    testcase.assertEqual(stored, base)
    return 11
