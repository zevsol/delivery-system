"""Synthetic V7 read projections; no Host snapshot or remote service is used."""

from __future__ import annotations

from contextlib import closing
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from delivery_system import sqlite_schema
from delivery_system.application_identity import CredentialContinuityAnchor, LogicalApplicationIdentity
from delivery_system.application_identity import operation_identity, request_identity
from delivery_system.audit_state import ApprovalRecord
from delivery_system.auditor import RuleEvaluationDraft, RuntimeAuditor
from delivery_system.drivers.contract import DriverReadResponse, DriverTrustContext
from delivery_system.execution_state import ApplicationExecutionState, OperationAttemptState
from delivery_system.execution_store import ReadOnlyExecutionProjectionStore, SQLiteExecutionStore
from delivery_system.receipts import ApplicationReceipt, AuthorityProvenance, OperationReceipt
from delivery_system.protocol import digest
from delivery_system.read_only_state import ReadOnlyState, ReadOnlyStateError
from delivery_system.rules import SemanticOutcome, build_registry_v1
from delivery_system.runtime import (
    ReadOnlyApplicationStatusProjection, ReadOnlyApprovalStatusProjection,
    ReadOnlyAuditContextProjection, ReadOnlyPreviewProjectionStore,
    RuntimeApprovalAuthorityService, RuntimeContext, RuntimePlanner, SQLitePreviewStore,
    _execution_operations,
)
from delivery_system.sqlite_maintenance import SQLiteBackupManifest


RELEASE = "synthetic-i2-release"
TRUST = DriverTrustContext("fixture-driver", "offline://fixture", "fixture-v1")


def _sourced(value, source="user_asserted"):
    return {"value": value, "declared_source": source}


def _plan(repository_aware=False):
    return {
        "repository_claim": {"owner": "Owner", "name": "Repo"} if repository_aware else None,
        "work_items": [{
            "client_ref": "item", "role": _sourced("Bug", "model_proposed"),
            "title": _sourced("Synthetic item"), "context_problem": _sourced("Problem"),
            "outcome": _sourced("Outcome", "model_proposed"), "scope": _sourced(["repo"]),
            "non_goals": _sourced([], "model_assumption"),
            "acceptance_criteria": _sourced(["Works"]),
            "verification": _sourced(["Test"], "model_proposed"),
            "required_capabilities": _sourced(["issues"]),
            "write_metadata": _sourced({}, "model_proposed"),
        }],
        "planned_relationships": [], "operation_intents": [],
    }


class _FixtureDriver:
    def __init__(self, *, write=False):
        self.write = write

    def read_repository(self, repository, query_scope):
        issue = {"issue_id": "I1", "item_type": "issue", "title": "Existing",
                 "updated_at": "2026-08-13T00:00:00+00:00", "repository_identity": "owner/repo"}
        material = {"source_identity": TRUST.trusted_driver_identity,
                    "repository_identity": "owner/repo", "query_scope": query_scope,
                    "payload": {"issue_records": [issue], "relationship_records": []}}
        payload = {"requested_repository": repository, "canonical_repository": "owner/repo",
                   "remote_repository_id": "R1", "authenticated_subject": "U1",
                   "visibility": "private", "permissions": {"read": True, "write": self.write},
                   "capabilities": {"issues": True, "relationships": True},
                   "query_scope": dict(query_scope), "query_complete": True,
                   "pagination_complete": True, "issue_records": [issue],
                   "relationship_records": [], "evidence_material": [material],
                   "source_identity": TRUST.trusted_driver_identity}
        return DriverReadResponse(**payload, remote_content_digest=digest(payload))


@unittest.skipUnless(os.name == "posix" and Path("/proc/self/fd").is_dir(), "Linux proc fd required")
class ReadOnlyProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.context = RuntimeContext.from_workspace_root(self.temp.name)
        self.writable = SQLitePreviewStore(
            self.context, ignore_checker=lambda _path: True,
            tracked_checker=lambda _path: False,
        )
        with closing(sqlite3.connect(self.context.state_path)) as connection:
            sqlite_schema.ensure_schema_v7(
                connection, expected_workspace_identity=self.context.workspace_identity,
            )
        self.preview = RuntimePlanner(self.context, self.writable).preview(_plan())
        self.bundle = Path(self.temp.name) / "synthetic-bundle"
        self.bundle.mkdir()
        self.seal()

    def seal(self):
        raw = Path(self.context.state_path).read_bytes()
        (self.bundle / "state.sqlite3").write_bytes(raw)
        manifest = SQLiteBackupManifest(
            format="delivery-system-sqlite-backup", format_version=1,
            release_id=RELEASE, schema_version=7,
            workspace_identity=self.context.workspace_identity,
            database_filename="state.sqlite3", database_size=len(raw),
            database_sha256=hashlib.sha256(raw).hexdigest(),
            created_at_utc=datetime(2026, 10, 17, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
        )
        (self.bundle / "manifest.json").write_bytes(manifest.to_json_bytes())

    def open_state(self):
        return ReadOnlyState.open(
            self.bundle, expected_workspace_identity=self.context.workspace_identity,
            expected_release_id=RELEASE,
        )

    def projections(self, state, *, trust=None, policy=None):
        store = ReadOnlyPreviewProjectionStore(
            self.context, state, trust_context=trust, custody_policy=policy,
        )
        execution = ReadOnlyExecutionProjectionStore(state, self.context.workspace_identity)
        return (
            store,
            ReadOnlyAuditContextProjection(self.context, store, build_registry_v1()),
            ReadOnlyApprovalStatusProjection(self.context, store),
            ReadOnlyApplicationStatusProjection(self.context, store, execution),
        )

    def assert_preview_status_read_rejected_without_mutation(
        self, preview, *, trust, policy, expected_error,
    ):
        database_path = Path(self.context.state_path)
        before = database_path.read_bytes()
        with self.open_state() as state:
            store, _, _, _ = self.projections(state, trust=trust, policy=policy)
            with self.assertRaisesRegex(ValueError, expected_error):
                store._read_preview_revision_for_status(
                    self.context.workspace_identity, preview["preview_id"], preview["revision"],
                )
        self.assertEqual(database_path.read_bytes(), before)

    def add_repository_preview(self, *, with_operation=False):
        store = SQLitePreviewStore(
            self.context, ignore_checker=lambda _path: True,
            tracked_checker=lambda _path: False, trust_context=TRUST,
        )
        plan = _plan(repository_aware=True)
        if with_operation:
            plan["operation_intents"] = [
                {"operation_kind": "create_issue", "client_refs": ["item"], "depends_on": []},
            ]
        preview = RuntimePlanner(self.context, store, _FixtureDriver(), TRUST).preview(plan)
        self.seal()
        return preview

    def add_write_preview_and_audit(self):
        store = SQLitePreviewStore(
            self.context, ignore_checker=lambda _path: True,
            tracked_checker=lambda _path: False, trust_context=TRUST,
        )
        plan = _plan(repository_aware=True)
        plan["operation_intents"] = [{"operation_kind": "create_issue", "client_refs": ["item"], "depends_on": []}]
        preview = RuntimePlanner(self.context, store, _FixtureDriver(write=True), TRUST).preview(plan)
        auditor = RuntimeAuditor(self.context, store, build_registry_v1(), TRUST)
        audit_context = auditor.get_context(preview["preview_id"], preview["revision"])
        evaluations = [
            RuleEvaluationDraft(rule["rule_id"], rule["rule_version"], SemanticOutcome.PASSED, "synthetic")
            for rule in audit_context["semantic_rule_contexts"] if rule["applicability"] == "Applicable"
        ]
        audit = auditor.record_audit(preview["preview_id"], preview["revision"],
                                     audit_context["audit_context_digest"], evaluations, [])
        self.seal()
        return preview, audit

    def add_pending_application(self, preview):
        with closing(sqlite3.connect(self.context.state_path)) as connection:
            row = connection.execute(
                "SELECT payload FROM records WHERE workspace_identity=? AND record_type='preview' AND record_id=?",
                (self.context.workspace_identity, preview["preview_id"]),
            ).fetchone()
        canonical = json.loads(row[0])["canonical_payload"]
        binding_fields = (
            "workspace_identity", "repository_identity", "preview_id", "revision",
            "sealed_preview_digest", "plan_digest", "operation_set_digest", "remote_snapshot_digest",
        )
        values = {key: canonical[key] for key in binding_fields}
        values.update(audit_id="synthetic-audit", audit_digest="synthetic-audit-digest",
                      approval_id="synthetic-approval", approval_digest="synthetic-approval-digest",
                      github_subject_identity="U1", driver_identity=TRUST.trusted_driver_identity,
                      remote_authority=TRUST.remote_authority, required_capabilities=["issues"])
        identity = LogicalApplicationIdentity(values)
        state = ApplicationExecutionState(
            identity.application_id, identity, "Pending", 0, None, None, None,
            started_at="2026-10-17T00:00:00Z", updated_at="2026-10-17T00:00:00Z",
            continuity_anchor=CredentialContinuityAnchor("PRINCIPAL", ("synthetic-principal",)),
        ).with_digest()
        with closing(sqlite3.connect(self.context.state_path)) as connection:
            connection.execute(
                "INSERT INTO application_execution(workspace_identity, application_id, payload) VALUES (?, ?, ?)",
                (self.context.workspace_identity, state.application_id,
                 json.dumps(state.payload() | {"state_digest": state.state_digest}, sort_keys=True)),
            )
            connection.commit()
        self.seal()
        return state

    def apply_synthetic_execution(self, state, preview):
        with closing(sqlite3.connect(self.context.state_path)) as connection:
            row = connection.execute(
                "SELECT payload FROM records WHERE record_type='preview' AND record_id=?",
                (preview["preview_id"],),
            ).fetchone()
        operation = _execution_operations(json.loads(row[0])["canonical_payload"])[0]
        operation_id = operation_identity(state.application_id, 0, operation)
        provenance = AuthorityProvenance.from_dict({
            "domain": "delivery-system:authority-provenance:v1",
            "authority_id": "synthetic-authority", "credential_binding_id": "synthetic-binding",
            "credential_instance_id": "synthetic-instance", "issuer_id": "synthetic-issuer",
            "credential_principal_identity": "synthetic-principal",
            "github_subject_identity": "U1", "issued_at": "2026-10-17T00:00:00Z",
            "expires_at": "2026-10-17T01:00:00Z", "driver_identity": TRUST.trusted_driver_identity,
            "remote_authority": TRUST.remote_authority, "application_id": state.application_id,
        })
        attempt = OperationAttemptState(
            state.application_id, operation_id, 0, operation, provenance,
            TRUST.trusted_driver_identity, TRUST.remote_authority, request_identity(operation_id),
            "Applied", "2026-10-17T00:00:00Z", "2026-10-17T00:01:00Z", state.identity,
        ).with_digest()
        remote_payload = {"synthetic": True}
        remote_result = {"result_kind": "issue_created", "result_identity": "I-new",
                         "result_digest": digest(remote_payload), "result_payload": remote_payload}
        receipt_id = "operation-receipt-" + digest({
            "domain": "delivery-system:operation-receipt-id:v1", "operation_identity": operation_id,
        }).split(":", 1)[1]
        operation_receipt = OperationReceipt(
            receipt_id, state.application_id, state.identity, operation_id, 0, operation,
            request_identity(operation_id), provenance, remote_result,
            "2026-10-17T00:00:00Z", "2026-10-17T00:01:00Z",
        ).with_digest()
        app_receipt_id = "application-receipt-" + digest({
            "domain": "delivery-system:application-receipt-id:v1", "application_id": state.application_id,
        }).split(":", 1)[1]
        app_receipt = ApplicationReceipt(
            app_receipt_id, state.application_id, state.identity,
            state.identity.values()["operation_set_digest"],
            ({"operation_receipt_id": receipt_id, "operation_receipt_digest": operation_receipt.receipt_digest},),
            "Applied", "2026-10-17T00:00:00Z", "2026-10-17T00:01:00Z",
        ).with_digest()
        applied = replace(
            state, state="Applied", next_operation_index=1,
            operation_receipt_refs=(receipt_id,), updated_at="2026-10-17T00:01:00Z",
            completed_at="2026-10-17T00:01:00Z",
        ).with_digest()
        with closing(sqlite3.connect(self.context.state_path)) as connection:
            connection.execute(
                "UPDATE application_execution SET payload=? WHERE application_id=?",
                (json.dumps(applied.payload() | {"state_digest": applied.state_digest}), state.application_id),
            )
            connection.execute(
                "INSERT INTO operation_attempts(workspace_identity, application_id, operation_identity, payload) VALUES (?, ?, ?, ?)",
                (self.context.workspace_identity, state.application_id, operation_id,
                 json.dumps(attempt.payload() | {"attempt_digest": attempt.attempt_digest})),
            )
            connection.execute(
                "INSERT INTO operation_receipts(workspace_identity, application_id, operation_identity, payload) VALUES (?, ?, ?, ?)",
                (self.context.workspace_identity, state.application_id, operation_id, json.dumps(operation_receipt.to_dict())),
            )
            connection.execute(
                "INSERT INTO application_receipts(workspace_identity, application_id, payload) VALUES (?, ?, ?)",
                (self.context.workspace_identity, state.application_id, json.dumps(app_receipt.to_dict())),
            )
            connection.commit()
        self.seal()
        return applied, operation_receipt, app_receipt

    def test_conceptual_audit_context_needs_no_driver_or_policy(self):
        with self.open_state() as state:
            _, audit, _, _ = self.projections(state)
            result = audit.get_context(self.preview["preview_id"], 1)
            self.assertEqual(result["audit_scope"], "Conceptual")
            self.assertEqual(result["context_status"], "audit_ready")
            self.assertFalse(any(record["source_kind"] == "driver" for record in result["evidence_records"]))

    def test_repository_audit_context_requires_custody_policy(self):
        preview = self.add_repository_preview()
        for policy in (None, lambda _manifest, _canonical: False):
            with self.subTest(policy=policy), self.open_state() as state:
                _, audit, _, _ = self.projections(state, trust=TRUST, policy=policy)
                with self.assertRaisesRegex(ValueError, "repository_aware_promotion_required"):
                    audit.get_context(preview["preview_id"], 1)
        with self.open_state() as state:
            _, audit, _, _ = self.projections(state, trust=TRUST, policy=lambda _manifest, _canonical: True)
            result = audit.get_context(preview["preview_id"], 1)
            self.assertEqual(result["audit_scope"], "RepositoryAware")
            self.assertEqual(sum(record["source_kind"] == "driver" for record in result["evidence_records"]), 1)

    def test_repository_policy_runs_inside_one_read_snapshot(self):
        preview = self.add_repository_preview()
        with self.open_state() as state:
            observed = []

            def policy(_manifest, _canonical):
                observed.append(state._connection.in_transaction)
                return True

            _, audit, _, _ = self.projections(state, trust=TRUST, policy=policy)
            audit.get_context(preview["preview_id"], 1)
            self.assertTrue(observed)
            self.assertTrue(all(observed))
            self.assertFalse(state._connection.in_transaction)

    def test_write_eligible_audit_context_requires_external_policy(self):
        preview, _audit_record = self.add_write_preview_and_audit()
        with self.open_state() as state:
            _, audit, _, _ = self.projections(state, trust=TRUST)
            with self.assertRaisesRegex(ValueError, "repository_aware_promotion_required"):
                audit.get_context(preview["preview_id"], 1)
        with self.open_state() as state:
            _, audit, _, _ = self.projections(state, trust=TRUST,
                                               policy=lambda _manifest, _canonical: True)
            self.assertEqual(audit.get_context(preview["preview_id"], 1)["audit_scope"], "WriteEligible")

    def test_unknown_driver_identity_fails_closed(self):
        preview = self.add_repository_preview()
        other = DriverTrustContext("unknown-driver", TRUST.origin, TRUST.contract_version)
        with self.open_state() as state:
            _, audit, _, _ = self.projections(state, trust=other, policy=lambda _manifest, _canonical: True)
            with self.assertRaisesRegex(ValueError, "driver_trust_context_mismatch"):
                audit.get_context(preview["preview_id"], 1)

    def test_repository_status_read_binds_driver_and_remote_authority(self):
        preview = self.add_repository_preview()
        self.assert_preview_status_read_rejected_without_mutation(
            preview, trust=None, policy=lambda _manifest, _canonical: True,
            expected_error="driver_trust_context_required",
        )

        for trust in (
            DriverTrustContext("other-driver", TRUST.origin, TRUST.contract_version),
            DriverTrustContext(TRUST.trusted_driver_identity, "offline://other", TRUST.contract_version),
        ):
            policy_calls = []

            def approve(_manifest, _canonical):
                policy_calls.append(True)
                return True

            with self.subTest(trust=trust):
                self.assert_preview_status_read_rejected_without_mutation(
                    preview, trust=trust, policy=approve,
                    expected_error="driver_trust_context_mismatch",
                )
                self.assertEqual(policy_calls, [])

    def test_repository_status_read_requires_literal_policy_approval(self):
        preview = self.add_repository_preview()
        self.assert_preview_status_read_rejected_without_mutation(
            preview, trust=TRUST, policy=None,
            expected_error="repository_aware_promotion_required",
        )
        for result in (False, None, 1):
            with self.subTest(policy_result=result):
                self.assert_preview_status_read_rejected_without_mutation(
                    preview, trust=TRUST,
                    policy=lambda _manifest, _canonical, result=result: result,
                    expected_error="repository_aware_promotion_required",
                )

    def test_repository_status_read_sanitizes_policy_exception(self):
        preview = self.add_repository_preview()

        def fail_policy(_manifest, _canonical):
            raise RuntimeError("CUSTODY_SECRET_SENTINEL")

        database_path = Path(self.context.state_path)
        before = database_path.read_bytes()
        with self.open_state() as state:
            store, _, _, _ = self.projections(state, trust=TRUST, policy=fail_policy)
            with self.assertRaisesRegex(ValueError, "repository_aware_promotion_required") as raised:
                store._read_preview_revision_for_status(
                    self.context.workspace_identity, preview["preview_id"], preview["revision"],
                )
            self.assertNotIn("CUSTODY_SECRET_SENTINEL", str(raised.exception))
            self.assertTrue(raised.exception.__suppress_context__)
        self.assertEqual(database_path.read_bytes(), before)

    def test_write_eligible_status_read_enforces_trust_and_policy(self):
        preview, _audit_record = self.add_write_preview_and_audit()
        self.assert_preview_status_read_rejected_without_mutation(
            preview, trust=None, policy=lambda _manifest, _canonical: True,
            expected_error="driver_trust_context_required",
        )
        wrong_authority = DriverTrustContext(
            TRUST.trusted_driver_identity, TRUST.origin, "other-contract-version",
        )
        self.assert_preview_status_read_rejected_without_mutation(
            preview, trust=wrong_authority, policy=lambda _manifest, _canonical: True,
            expected_error="driver_trust_context_mismatch",
        )
        self.assert_preview_status_read_rejected_without_mutation(
            preview, trust=TRUST, policy=None,
            expected_error="repository_aware_promotion_required",
        )

        with self.open_state() as state:
            store, _, _, _ = self.projections(
                state, trust=TRUST, policy=lambda _manifest, _canonical: True,
            )
            loaded = store._read_preview_revision_for_status(
                self.context.workspace_identity, preview["preview_id"], preview["revision"],
            )
            self.assertEqual(loaded["canonical_payload"]["preview_level"], "WriteEligible")

    def test_repository_evidence_tampering_fails_closed(self):
        preview = self.add_repository_preview()
        with closing(sqlite3.connect(self.context.state_path)) as connection:
            connection.execute(
                "UPDATE records SET payload='{}' WHERE record_type='evidence' AND workspace_identity=?",
                (self.context.workspace_identity,),
            )
            connection.commit()
        self.seal()
        with self.open_state() as state:
            _, audit, _, _ = self.projections(state, trust=TRUST, policy=lambda _manifest, _canonical: True)
            with self.assertRaises(ValueError):
                audit.get_context(preview["preview_id"], 1)

    def test_missing_repository_evidence_fails_closed(self):
        preview = self.add_repository_preview()
        with closing(sqlite3.connect(self.context.state_path)) as connection:
            connection.execute(
                "DELETE FROM records WHERE record_type='evidence' AND json_extract(payload, '$.source_kind')='driver'",
            )
            connection.commit()
        self.seal()
        with self.open_state() as state:
            _, audit, _, _ = self.projections(state, trust=TRUST,
                                               policy=lambda _manifest, _canonical: True)
            with self.assertRaisesRegex(ValueError, "evidence_not_found"):
                audit.get_context(preview["preview_id"], 1)

    def test_conflicting_repository_bindings_fail_closed(self):
        preview = self.add_repository_preview()
        with closing(sqlite3.connect(self.context.state_path)) as connection:
            original = connection.execute(
                "SELECT payload FROM records WHERE record_type='preview' AND record_id=?",
                (preview["preview_id"],),
            ).fetchone()[0]
        for field in ("remote_snapshot_digest", "remote_authority", "plan_digest", "operation_set_digest"):
            with self.subTest(field=field):
                modified = json.loads(original)
                modified["canonical_payload"][field] = "sha256:" + "0" * 64
                with closing(sqlite3.connect(self.context.state_path)) as connection:
                    connection.execute(
                        "UPDATE records SET payload=? WHERE record_type='preview' AND record_id=?",
                        (json.dumps(modified), preview["preview_id"]),
                    )
                    connection.commit()
                self.seal()
                with self.open_state() as state:
                    _, audit, _, _ = self.projections(state, trust=TRUST,
                                                       policy=lambda _manifest, _canonical: True)
                    with self.assertRaises(ValueError):
                        audit.get_context(preview["preview_id"], 1)
        with closing(sqlite3.connect(self.context.state_path)) as connection:
            connection.execute(
                "UPDATE records SET payload=? WHERE record_type='preview' AND record_id=?",
                (original, preview["preview_id"]),
            )
            connection.commit()

    def test_stale_revision_and_malformed_seal_fail_closed(self):
        with self.open_state() as state:
            _, audit, _, _ = self.projections(state)
            with self.assertRaisesRegex(ValueError, "context_stale"):
                audit.get_context(self.preview["preview_id"], 2)
        with closing(sqlite3.connect(self.context.state_path)) as connection:
            row = connection.execute(
                "SELECT payload FROM records WHERE record_type='preview' AND record_id=?",
                (self.preview["preview_id"],),
            ).fetchone()
            payload = json.loads(row[0])
            payload["canonical_payload"]["sealed_preview_digest"] = "sha256:" + "0" * 64
            connection.execute(
                "UPDATE records SET payload=? WHERE record_type='preview' AND record_id=?",
                (json.dumps(payload), self.preview["preview_id"]),
            )
            connection.commit()
        self.seal()
        with self.open_state() as state:
            _, audit, _, _ = self.projections(state)
            with self.assertRaisesRegex(ValueError, "preview_digest_mismatch"):
                audit.get_context(self.preview["preview_id"], 1)

    def test_missing_state_and_wrong_workspace_fail_without_creation(self):
        missing = Path(self.temp.name) / "missing-bundle"
        with self.assertRaises(ReadOnlyStateError):
            ReadOnlyState.open(missing, expected_workspace_identity=self.context.workspace_identity,
                               expected_release_id=RELEASE)
        self.assertFalse(missing.exists())
        with self.open_state() as state:
            wrong = RuntimeContext(self.context.workspace_root, self.context.normalized_workspace_root,
                                   "wrong-workspace", self.context.state_path)
            with self.assertRaisesRegex(ValueError, "read_only_state_unavailable"):
                ReadOnlyPreviewProjectionStore(wrong, state)

    def test_execution_store_must_share_the_exact_i1_state(self):
        with self.open_state() as first, self.open_state() as second:
            store = ReadOnlyPreviewProjectionStore(self.context, first)
            other_execution = ReadOnlyExecutionProjectionStore(second, self.context.workspace_identity)
            with self.assertRaisesRegex(ValueError, "read_only_state_unavailable"):
                ReadOnlyApplicationStatusProjection(self.context, store, other_execution)
            adapter = store._connect()
            with self.assertRaisesRegex(ReadOnlyStateError, "read_only_query_invalid"):
                adapter.execute("UPDATE records SET payload='changed'")

    def test_missing_audit_and_application_preserve_existing_errors(self):
        with self.open_state() as state:
            _, _, approval, application = self.projections(state)
            with self.assertRaisesRegex(ValueError, "audit_not_found"):
                approval.get_status(self.preview["preview_id"], 1)
            with self.assertRaisesRegex(ValueError, "application_id_invalid"):
                application.get_status("invalid")
            with self.assertRaisesRegex(ValueError, "application_not_found"):
                application.get_status("application-" + "0" * 64)

    def test_approval_status_projects_missing_and_current_records(self):
        preview, audit_record = self.add_write_preview_and_audit()
        self.assertEqual(audit_record.audit_scope, "WriteEligible")
        policy = lambda _manifest, _canonical: True
        with self.open_state() as state:
            _, _, approval, _ = self.projections(state, trust=TRUST, policy=policy)
            self.assertEqual(approval.get_status(preview["preview_id"], 1)["status"], "NO_CURRENT_APPROVAL")
        from delivery_system.runtime import RuntimeApprovalAuthorityService
        approval_id = RuntimeApprovalAuthorityService._approval_id(audit_record)
        record = ApprovalRecord.create(
            approval_id, audit_record, "owner/repo", "synthetic-claim",
            "2026-10-17T00:00:00Z", f"批准写入 {preview['preview_id']} 1",
        )
        with closing(sqlite3.connect(self.context.state_path)) as connection:
            connection.execute(
                "INSERT INTO records(workspace_identity, record_type, record_id, revision, payload) VALUES (?, 'approval', ?, NULL, ?)",
                (self.context.workspace_identity, approval_id, json.dumps(record.to_dict(), sort_keys=True)),
            )
            connection.commit()
        self.seal()
        with self.open_state() as state:
            _, _, approval, _ = self.projections(state, trust=TRUST, policy=policy)
            result = approval.get_status(preview["preview_id"], 1)
            self.assertEqual(result["status"], "CURRENT")
            self.assertEqual(result["approval"]["approval_id"], approval_id)
            with self.assertRaisesRegex(ValueError, "preview_stale"):
                approval.get_status(preview["preview_id"], 2)
        with closing(sqlite3.connect(self.context.state_path)) as connection:
            payload = record.to_dict()
            payload["status"] = "invalid"
            connection.execute(
                "UPDATE records SET payload=? WHERE record_type='approval' AND record_id=?",
                (json.dumps(payload), approval_id),
            )
            connection.commit()
        self.seal()
        with self.open_state() as state:
            _, _, approval, _ = self.projections(state, trust=TRUST, policy=policy)
            with self.assertRaisesRegex(ValueError, "approval_invalid"):
                approval.get_status(preview["preview_id"], 1)

    def test_no_current_approval_does_not_hide_corrupt_preview(self):
        preview, _audit_record = self.add_write_preview_and_audit()
        with closing(sqlite3.connect(self.context.state_path)) as connection:
            row = connection.execute(
                "SELECT payload FROM records WHERE record_type='preview' AND record_id=?",
                (preview["preview_id"],),
            ).fetchone()
            payload = json.loads(row[0])
            payload["canonical_payload"]["sealed_preview_digest"] = "sha256:" + "0" * 64
            connection.execute(
                "UPDATE records SET payload=? WHERE record_type='preview' AND record_id=?",
                (json.dumps(payload), preview["preview_id"]),
            )
            connection.commit()
        self.seal()
        with self.open_state() as state:
            _, _, approval, _ = self.projections(state, trust=TRUST,
                                                  policy=lambda _manifest, _canonical: True)
            with self.assertRaisesRegex(ValueError, "preview_digest_mismatch"):
                approval.get_status(preview["preview_id"], 1)

    def test_pending_application_and_approved_context_use_validated_snapshot(self):
        preview = self.add_repository_preview()
        execution = self.add_pending_application(preview)
        with self.open_state() as state:
            _, _, _, application = self.projections(state, trust=TRUST,
                                                     policy=lambda _manifest, _canonical: True)
            result = application.get_status(execution.application_id)
            self.assertEqual(result["state"], "Pending")
            self.assertEqual(result["attempts"], [])
            self.assertEqual(result["operation_receipts"], [])
            self.assertEqual(result["integrity_status"], "verified")
            values = execution.identity.values()
            recovered = application.get_status_by_approved_context(
                values["preview_id"], values["revision"], values["approval_id"], values["approval_digest"],
            )
            self.assertEqual(recovered["application_id"], execution.application_id)

    def test_repository_application_status_requires_custody_policy(self):
        preview = self.add_repository_preview()
        execution = self.add_pending_application(preview)
        with self.open_state() as state:
            _, _, _, application = self.projections(state, trust=TRUST)
            with self.assertRaisesRegex(ValueError, "repository_aware_promotion_required"):
                application.get_status(execution.application_id)

    def test_approval_and_application_status_cannot_bypass_trust_binding(self):
        preview, _audit_record = self.add_write_preview_and_audit()
        execution = self.add_pending_application(preview)
        wrong_authority = DriverTrustContext(
            TRUST.trusted_driver_identity, "offline://different-origin", TRUST.contract_version,
        )
        database_path = Path(self.context.state_path)
        before = database_path.read_bytes()
        with self.open_state() as state:
            _, _, approval, application = self.projections(
                state, trust=wrong_authority,
                policy=lambda _manifest, _canonical: True,
            )
            with self.assertRaisesRegex(ValueError, "driver_trust_context_mismatch"):
                approval.get_status(preview["preview_id"], preview["revision"])
            with self.assertRaisesRegex(ValueError, "driver_trust_context_mismatch"):
                application.get_status(execution.application_id)
            values = execution.identity.values()
            with self.assertRaisesRegex(ValueError, "driver_trust_context_mismatch"):
                application.get_status_by_approved_context(
                    values["preview_id"], values["revision"],
                    values["approval_id"], values["approval_digest"],
                )
        self.assertEqual(database_path.read_bytes(), before)

    def test_applied_application_validates_attempts_and_both_receipt_levels(self):
        preview = self.add_repository_preview(with_operation=True)
        pending = self.add_pending_application(preview)
        applied, operation_receipt, _ = self.apply_synthetic_execution(pending, preview)
        with self.open_state() as state:
            _, _, _, application = self.projections(state, trust=TRUST,
                                                     policy=lambda _manifest, _canonical: True)
            result = application.get_status(applied.application_id)
            self.assertEqual(result["state"], "Applied")
            self.assertEqual(result["attempt_count"], 1)
            self.assertEqual(result["completed_operation_count"], 1)
            self.assertEqual(result["operation_receipts"][0]["receipt_digest"], operation_receipt.receipt_digest)
            self.assertEqual(result["application_receipt"]["status"], "Applied")
        with closing(sqlite3.connect(self.context.state_path)) as connection:
            connection.execute(
                "UPDATE operation_receipts SET payload='{}' WHERE application_id=?",
                (applied.application_id,),
            )
            connection.commit()
        self.seal()
        with self.open_state() as state:
            _, _, _, application = self.projections(state, trust=TRUST,
                                                     policy=lambda _manifest, _canonical: True)
            with self.assertRaises(ValueError):
                application.get_status(applied.application_id)

    def test_malformed_execution_and_conflicting_context_fail_closed(self):
        preview = self.add_repository_preview()
        execution = self.add_pending_application(preview)
        with self.open_state() as state:
            _, _, _, application = self.projections(state, trust=TRUST,
                                                     policy=lambda _manifest, _canonical: True)
            with self.assertRaisesRegex(ValueError, "application_not_found"):
                application.get_status_by_approved_context(preview["preview_id"], 1, "other", "other")
        with closing(sqlite3.connect(self.context.state_path)) as connection:
            connection.execute(
                "UPDATE application_execution SET payload='{}' WHERE application_id=?",
                (execution.application_id,),
            )
            connection.commit()
        self.seal()
        with self.open_state() as state:
            _, _, _, application = self.projections(state, trust=TRUST,
                                                     policy=lambda _manifest, _canonical: True)
            with self.assertRaisesRegex(ValueError, "state_integrity_invalid"):
                application.get_status(execution.application_id)

    def test_malformed_attempt_and_receipts_fail_closed(self):
        for table, code in (
            ("operation_attempts", "attempt_integrity_invalid"),
            ("operation_receipts", "receipt_integrity_invalid"),
            ("application_receipts", "application_receipt_integrity_invalid"),
        ):
            with self.subTest(table=table):
                preview = self.add_repository_preview(with_operation=True)
                execution = self.add_pending_application(preview)
                with closing(sqlite3.connect(self.context.state_path)) as connection:
                    row = connection.execute(
                        "SELECT payload FROM records WHERE record_type='preview' AND record_id=?",
                        (preview["preview_id"],),
                    ).fetchone()
                    canonical = json.loads(row[0])["canonical_payload"]
                    operation = _execution_operations(canonical)[0]
                    operation_id = operation_identity(execution.application_id, 0, operation)
                    if table == "application_receipts":
                        connection.execute(
                            "INSERT INTO application_receipts(workspace_identity, application_id, payload) VALUES (?, ?, '{}')",
                            (self.context.workspace_identity, execution.application_id),
                        )
                    else:
                        connection.execute(
                            f"INSERT INTO {table}(workspace_identity, application_id, operation_identity, payload) VALUES (?, ?, ?, '{{}}')",
                            (self.context.workspace_identity, execution.application_id, operation_id),
                        )
                    connection.commit()
                self.seal()
                with self.open_state() as state:
                    _, _, _, application = self.projections(
                        state, trust=TRUST, policy=lambda _manifest, _canonical: True,
                    )
                    with self.assertRaisesRegex(ValueError, code):
                        application.get_status(execution.application_id)
                with closing(sqlite3.connect(self.context.state_path)) as connection:
                    connection.execute(f"DELETE FROM {table} WHERE application_id=?", (execution.application_id,))
                    connection.execute("DELETE FROM application_execution WHERE application_id=?", (execution.application_id,))
                    connection.commit()

    def test_projection_reads_use_retained_state_and_never_construct_writable_stores(self):
        with self.open_state() as state:
            original_fd = state._database_fd
            self.bundle.joinpath("state.sqlite3").rename(self.bundle / "former.sqlite3")
            with patch.object(SQLitePreviewStore, "__init__", side_effect=AssertionError("writable preview")), \
                 patch.object(SQLiteExecutionStore, "__init__", side_effect=AssertionError("writable execution")), \
                 patch.object(RuntimeApprovalAuthorityService, "__init__", side_effect=AssertionError("mutable authority")), \
                 patch.object(sqlite_schema, "ensure_schema_v7", side_effect=AssertionError("migration")):
                _, audit, approval, application = self.projections(state)
                self.assertEqual(audit.get_context(self.preview["preview_id"], 1)["audit_scope"], "Conceptual")
                with self.assertRaisesRegex(ValueError, "audit_not_found"):
                    approval.get_status(self.preview["preview_id"], 1)
                with self.assertRaisesRegex(ValueError, "application_not_found"):
                    application.get_status("application-" + "0" * 64)
            self.assertEqual(state._database_fd, original_fd)

    def test_projection_rollback_failure_invalidates_retained_state(self):
        class FailingRollbackConnection:
            def __init__(self, connection):
                self.connection = connection
                self.statements = []

            def execute(self, statement, *args):
                self.statements.append(statement)
                if statement == "ROLLBACK":
                    raise RuntimeError("injected rollback failure")
                return self.connection.execute(statement, *args)

            def close(self):
                self.connection.close()

        with self.open_state() as state:
            retained_fd = state._database_fd
            proxy = FailingRollbackConnection(state._connection)
            state._connection = proxy
            self.bundle.joinpath("state.sqlite3").rename(self.bundle / "former.sqlite3")
            with patch.object(SQLitePreviewStore, "__init__", side_effect=AssertionError("writable preview")), \
                 patch.object(SQLiteExecutionStore, "__init__", side_effect=AssertionError("writable execution")), \
                 patch.object(RuntimeApprovalAuthorityService, "__init__", side_effect=AssertionError("mutable authority")):
                _, audit, _, _ = self.projections(state)
                with self.assertRaisesRegex(ValueError, "context_stale") as caught:
                    audit.get_context(self.preview["preview_id"], 2)
            self.assertEqual(caught.exception.cleanup_failures, ("rollback:RuntimeError",))
            self.assertTrue(state._closed)
            self.assertIsNone(state._connection)
            self.assertIsNone(state._database_fd)
            self.assertIn("SELECT", " ".join(proxy.statements))
            with self.assertRaises(OSError):
                import os
                os.fstat(retained_fd)
            with self.assertRaisesRegex(ReadOnlyStateError, "read_only_state_closed"):
                audit.get_context(self.preview["preview_id"], 1)

    def test_policy_close_inside_projection_snapshot_does_not_close_descriptor_twice(self):
        preview = self.add_repository_preview()
        with self.open_state() as state:
            retained_fd = state._database_fd
            attempts = []
            real_close = os.close

            def guarded_close(value):
                if value == retained_fd:
                    if attempts:
                        raise AssertionError("duplicate database descriptor close")
                    attempts.append(value)
                real_close(value)

            def policy(_manifest, _canonical):
                state.close()
                return True

            self.bundle.joinpath("state.sqlite3").rename(self.bundle / "former.sqlite3")
            with patch("delivery_system.read_only_state._close_descriptor", side_effect=guarded_close), \
                 patch.object(SQLitePreviewStore, "__init__", side_effect=AssertionError("writable preview")), \
                 patch.object(SQLiteExecutionStore, "__init__", side_effect=AssertionError("writable execution")):
                _, audit, _, _ = self.projections(state, trust=TRUST, policy=policy)
                with self.assertRaisesRegex(ReadOnlyStateError, "read_only_state_closed"):
                    audit.get_context(preview["preview_id"], 1)
            self.assertEqual(attempts, [retained_fd])
            self.assertTrue(state._closed)
            self.assertIsNone(state._connection)
            self.assertIsNone(state._database_fd)


if __name__ == "__main__":
    unittest.main()
