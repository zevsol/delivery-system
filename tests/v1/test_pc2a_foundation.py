"""Adversarial PC2-A identity, persistence, receipt, and schema contracts."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from delivery_system.application_identity import (APPLICATION_ID_DOMAIN, APPLICATION_BINDING_FIELDS,
    CredentialContinuityAnchor, LogicalApplicationIdentity, application_id, authority_is_compatible, operation_identity, request_identity)
from delivery_system.canonical import digest
from delivery_system.execution_state import ApplicationExecutionState, OperationAttemptState
from delivery_system.execution_store import SQLiteExecutionStore
from delivery_system.receipts import ApplicationReceipt, AuthorityProvenance, OperationReceipt
from delivery_system.runtime import RuntimeApplicationExecutionContext
from delivery_system import sqlite_schema


def authority(**changes):
    value = {"workspace_identity": "workspace-1", "repository_identity": "owner/repo", "preview_id": "preview-1", "revision": 1,
             "sealed_preview_digest": "sha256:sealed", "plan_digest": "sha256:plan", "operation_set_digest": "sha256:operations",
             "remote_snapshot_digest": "sha256:remote", "audit_id": "audit-1", "audit_digest": "sha256:audit", "approval_id": "approval-1",
             "approval_digest": "sha256:approval", "github_subject_identity": "github-user-1", "driver_identity": "driver-1",
             "remote_authority": "sha256:authority", "required_capabilities": ("issues:write",), "credential_principal_identity": "principal-1",
             "authority_id": "authority-1", "issued_at": "2026-09-01T00:00:00Z", "expires_at": "2026-09-01T01:00:00Z",
             "credential_binding_id": "binding-1", "credential_instance_id": "credential-1", "issuer_id": "issuer-1"}
    value.update(changes)
    return value


OP = {"operation_kind": "create_issue", "client_refs": ["item"], "depends_on": []}


class PC2AFoundationTests(unittest.TestCase):
    def _live_authority(self, version="1"):
        from tests.v1.test_operational_approval_authority import OperationalApprovalAuthorityTests
        from delivery_system.attestation import IssuerTrustDecision
        harness = OperationalApprovalAuthorityTests()
        directory, context, store, preview, audit, service = harness._setup("memory")
        provider = service.attestation_service._RuntimeAttestationOrchestrationService__provider
        provider.attestation_version = version
        if version == "2":
            boundary = service.attestation_service._RuntimeAttestationOrchestrationService__boundary
            issuer = boundary._AttestationRuntimeBoundary__issuer_policy
            issuer.evaluate = lambda issuer_id, key_id, signature_algorithm, attestation_version, credential_class: IssuerTrustDecision(True)
        command = f"批准写入 {preview['preview_id']} 1"
        approval = service.record_approval(preview["preview_id"], 1, command, "human")
        authority = service.issue_application_authority(preview["preview_id"], 1, approval.approval_id)
        return directory, service.create_execution_context(authority.authority_id)

    def test_identity_strict_and_capability_order(self):
        first = authority(required_capabilities=("issues:write", "issues:read"))
        second = authority(required_capabilities=("issues:read", "issues:write"), authority_id="authority-2")
        self.assertEqual(application_id(first), application_id(second))
        identity = LogicalApplicationIdentity.from_authority(first)
        self.assertEqual(identity.to_dict()["domain"], APPLICATION_ID_DOMAIN)
        self.assertEqual(tuple(identity.values()["required_capabilities"]), ("issues:read", "issues:write"))
        for field in APPLICATION_BINDING_FIELDS:
            with self.subTest(field=field):
                changed = authority(**{field: 2 if field == "revision" else ("x" if field != "required_capabilities" else ("other",))})
                self.assertNotEqual(application_id(first), application_id(changed))
        with self.assertRaises(ValueError): LogicalApplicationIdentity.from_dict({"domain": "wrong", "application": identity.values()})
        with self.assertRaises(ValueError): LogicalApplicationIdentity.from_dict({"domain": APPLICATION_ID_DOMAIN, "application": {**identity.values(), "extra": 1}})
        with self.assertRaises(ValueError): application_id(authority(required_capabilities=("issues:write", "issues:write")))
        with self.assertRaises(ValueError): application_id(authority(revision=True))

    def test_identity_does_not_retain_mutable_input_and_compatibility_is_exact(self):
        caps = ["issues:write"]
        value = authority(required_capabilities=caps)
        identity = LogicalApplicationIdentity.from_authority(value)
        caps.append("issues:read")
        value["repository_identity"] = "changed/repo"
        self.assertEqual(identity.values()["required_capabilities"], ["issues:write"])
        self.assertFalse(authority_is_compatible(authority(authority_id="new"), identity.to_dict()))
        self.assertFalse(authority_is_compatible(authority(), {**identity.to_dict(), "extra": 1}))
        self.assertFalse(authority_is_compatible(authority(), {"domain": "wrong", "application": identity.values()}))

    def test_operation_and_request_identity_are_strict_and_deterministic(self):
        app = application_id(authority())
        self.assertEqual(request_identity(operation_identity(app, 0, OP)), request_identity(operation_identity(app, 0, OP)))
        self.assertNotEqual(operation_identity(app, 0, OP), operation_identity(app, 1, OP))
        with self.assertRaises(ValueError): operation_identity(app, True, OP)
        with self.assertRaises(ValueError): operation_identity(app, 0, {**OP, "authority_id": "bad"})
        with self.assertRaises(ValueError): operation_identity(app, 0, {"operation_kind": OP["operation_kind"], "client_refs": OP["client_refs"]})

    def test_models_validate_bindings_and_are_success_only(self):
        directory, live = self._live_authority()
        try:
            identity = LogicalApplicationIdentity.from_authority(live)
            provenance = live.provenance
            result_payload = {"repository_identity": live.repository_identity, "issue_number": 1}
            result = {"result_kind": "issue", "result_identity": "issue-1", "result_digest": digest(result_payload), "result_payload": result_payload}
            receipt = OperationReceipt.create(identity, 0, OP, live, result, "2026-09-01T00:00:00Z", "2026-09-01T00:00:01Z")
            self.assertTrue(receipt.verify_integrity())
            attempt = OperationAttemptState(identity.application_id, receipt.operation_identity, 0, OP, provenance, live.driver_identity, live.remote_authority, request_identity(receipt.operation_identity), "Applying", receipt.started_at, receipt.started_at, identity, _live_context=live).with_digest()
            self.assertTrue(attempt.verify_integrity())
            with self.assertRaises(ValueError): OperationAttemptState(identity.application_id, "bad", 0, OP, provenance, live.driver_identity, live.remote_authority, request_identity(receipt.operation_identity), "Applying", receipt.started_at, receipt.started_at, identity)
        finally:
            directory.cleanup()

    def test_sqlite_v6_restart_conflicts_and_applied_replay(self):
        auth_directory, live = self._live_authority()
        try:
            identity = LogicalApplicationIdentity.from_authority(live)
            result_payload = {"repository_identity": live.repository_identity, "issue_number": 1}
            result = {"result_kind": "issue", "result_identity": "issue-1", "result_digest": digest(result_payload), "result_payload": result_payload}
            receipt = live.new_receipt(0, result, "2026-09-01T00:00:00Z", "2026-09-01T00:00:01Z")
            app_receipt = live.finalize_application_receipt((receipt,), receipt.started_at, receipt.completed_at)
            state = live.new_execution_state(state="Applied", next_operation_index=1, owner_id=None, current_attempt_id=None,
                                              recovery_code=None, operation_receipt_refs=(receipt.operation_receipt_id,),
                                              started_at=receipt.started_at, updated_at=receipt.completed_at,
                                              completed_at=receipt.completed_at)
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "state.sqlite3"
                store = SQLiteExecutionStore(path, identity.values()["workspace_identity"], runtime_service=live.service)
                store.record_operation_receipt(receipt)
                store.record_application_receipt(app_receipt)
                store.save_execution(state)
                self.assertEqual(store.get_execution(identity.application_id, expected_operations=(OP,)).state, "Applied")
                with self.assertRaisesRegex(ValueError, "receipt_binding_conflict"):
                    changed_payload = {"repository_identity": live.repository_identity, "issue_number": 2}
                    store.record_operation_receipt(OperationReceipt.create(identity, 0, OP, live, {"result_kind": "issue", "result_identity": "issue-2", "result_digest": digest(changed_payload), "result_payload": changed_payload}, receipt.started_at, receipt.completed_at))
        finally:
            auth_directory.cleanup()

    def test_v5_to_v6_and_workspace_keying(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite3"
            with closing(sqlite3.connect(path)) as connection:
                sqlite_schema.ensure_schema_v4(connection, expected_workspace_identity="workspace-1")
            store = SQLiteExecutionStore(path, "workspace-1")
            with closing(sqlite3.connect(path)) as connection:
                self.assertEqual(connection.execute("SELECT schema_version FROM store_meta").fetchone()[0], 6)
            with self.assertRaises(sqlite_schema.SchemaOwnerError): SQLiteExecutionStore(path, "workspace-2")

    def test_deep_immutability_and_applied_missing_receipt_fail_closed(self):
        auth_directory, live = self._live_authority()
        try:
            identity = LogicalApplicationIdentity.from_authority(live)
            exported = identity.to_dict()
            exported["application"]["required_capabilities"].append("issues:read")
            self.assertEqual(identity.values()["required_capabilities"], ["issues:write"])
            result_payload = {"repository_identity": live.repository_identity, "issue_number": 1}
            result = {"result_kind": "issue", "result_identity": "issue-1", "result_digest": digest(result_payload), "result_payload": result_payload}
            receipt = live.new_receipt(0, result, "2026-09-01T00:00:00Z", "2026-09-01T00:00:01Z")
            result_payload["issue_number"] = 99
            self.assertTrue(receipt.verify_integrity())
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "state.sqlite3"
                store = SQLiteExecutionStore(path, identity.values()["workspace_identity"], runtime_service=live.service)
                state = live.new_execution_state(state="Applied", next_operation_index=1, owner_id=None, current_attempt_id=None,
                                                  recovery_code=None, operation_receipt_refs=(), started_at=receipt.started_at,
                                                  updated_at=receipt.completed_at, completed_at=receipt.completed_at)
                store.save_execution(state)
                with self.assertRaisesRegex(ValueError, "application_receipt_not_found"):
                    store.get_execution(identity.application_id, expected_operations=(OP,))
        finally:
            auth_directory.cleanup()

    def test_v6_extra_object_and_missing_index_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite3"
            SQLiteExecutionStore(path, "workspace-1")
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("CREATE TABLE unexpected_v6(value TEXT)")
            with self.assertRaises(sqlite_schema.SchemaOwnerError): SQLiteExecutionStore(path, "workspace-1")

    def test_identity_and_compatibility_complete_negative_matrix(self):
        identity = LogicalApplicationIdentity.from_authority(authority())
        for field in APPLICATION_BINDING_FIELDS:
            with self.subTest(field=field):
                altered = authority(**{field: (2 if field == "revision" else ("changed" if field != "required_capabilities" else ("changed",)))})
                self.assertFalse(authority_is_compatible(altered, identity.to_dict()))
        for field in APPLICATION_BINDING_FIELDS:
            with self.subTest(missing=field):
                missing = identity.values()
                del missing[field]
                with self.assertRaises(ValueError): LogicalApplicationIdentity(missing)
        for value in (0, -1, "1", True):
            with self.assertRaises(ValueError): application_id(authority(revision=value))
        for value in ("", None, 1, ["issues:write"], ("",), (1,)):
            with self.assertRaises(ValueError): application_id(authority(repository_identity=value))

    def test_operation_shape_and_content_complete_matrix(self):
        app = application_id(authority())
        for missing in ("operation_kind", "client_refs", "depends_on"):
            malformed = dict(OP)
            del malformed[missing]
            with self.assertRaises(ValueError): operation_identity(app, 0, malformed)
        for extra in ("provider_payload", "operation_id", "receipt_data", "authority_id"):
            with self.assertRaises(ValueError): operation_identity(app, 0, {**OP, extra: "forbidden"})
        for malformed in ({**OP, "client_refs": "item-1"}, {**OP, "client_refs": [1]}, {**OP, "depends_on": ""}, {**OP, "depends_on": [1]}):
            with self.assertRaises(ValueError): operation_identity(app, 0, malformed)
        for index in (-1, "0", True, 0.0):
            with self.assertRaises(ValueError): operation_identity(app, index, OP)
        original = {"operation_kind": "create_issue", "client_refs": ["item"], "depends_on": []}
        operation_identity(app, 0, original)
        self.assertEqual(original, OP)
        self.assertNotEqual(operation_identity(app, 0, OP), operation_identity(app, 0, {**OP, "operation_kind": "add_dependency", "client_refs": ["item-1", "item-2"]}))
        self.assertNotEqual(operation_identity(app, 0, OP), operation_identity(app, 0, {**OP, "client_refs": ["item-2"]}))
        self.assertNotEqual(operation_identity(app, 0, OP), operation_identity(app, 0, {**OP, "depends_on": ["blocker"]}))

    def test_request_identity_ignores_issuance_and_coordination_metadata(self):
        first = LogicalApplicationIdentity.from_authority(authority())
        second = LogicalApplicationIdentity.from_authority(authority(authority_id="authority-2", credential_binding_id="binding-2", credential_instance_id="credential-2", issuer_id="issuer-2", issued_at="2026-09-01T00:30:00Z", expires_at="2026-09-01T02:00:00Z"))
        op1 = operation_identity(first.application_id, 0, OP)
        op2 = operation_identity(second.application_id, 0, OP)
        self.assertEqual(op1, op2)
        self.assertEqual(request_identity(op1), request_identity(op2))

    def test_runtime_v1_v2_continuity_and_live_provenance_boundary(self):
        v1_directory, v1 = self._live_authority("1")
        v2_directory, v2 = self._live_authority("2")
        try:
            v1_identity = LogicalApplicationIdentity.from_authority(v1)
            v2_identity = LogicalApplicationIdentity.from_authority(v2)
            self.assertEqual(v1.credential_principal_identity, "")
            self.assertTrue(v2.credential_principal_identity)
            self.assertEqual(set(v1_identity.values()), set(APPLICATION_BINDING_FIELDS))
            self.assertEqual(v1_identity.application_id, LogicalApplicationIdentity.from_authority(
                {**v1.to_dict(), "credential_principal_identity": "different-principal"}).application_id)

            v1_anchor = v1.continuity_anchor
            v2_anchor = v2.continuity_anchor
            self.assertEqual(v1_anchor.mode, "LEGACY_INSTANCE")
            self.assertEqual(v2_anchor.mode, "PRINCIPAL")
            self.assertTrue(authority_is_compatible(v1, v1_identity, v1_anchor))
            self.assertTrue(authority_is_compatible(v2, v2_identity, v2_anchor))
            self.assertFalse(authority_is_compatible(v1, v1_identity, v2_anchor))
            self.assertFalse(authority_is_compatible(v2, v2_identity, v1_anchor))

            self.assertEqual(v1.provenance.credential_principal_identity, "")
            self.assertTrue(v2.provenance.credential_principal_identity)
            with self.assertRaisesRegex(ValueError, "authority_provenance_invalid"):
                AuthorityProvenance.from_value(v1.to_dict())
        finally:
            v1_directory.cleanup()
            v2_directory.cleanup()

    def test_c4_live_ownership_expiry_and_historical_separation(self):
        directory, live = self._live_authority()
        other_directory, other = self._live_authority()
        try:
            identity = live.identity
            payload = {"repository_identity": live.repository_identity, "issue_number": 1}
            remote = {"result_kind": "issue", "result_identity": "issue-1", "result_digest": digest(payload), "result_payload": payload}
            with self.assertRaisesRegex(ValueError, "runtime_authority_required"):
                OperationReceipt.create(identity, 0, OP, live.to_dict(), remote, "2026-09-01T00:00:00Z", "2026-09-01T00:00:01Z")
            with self.assertRaisesRegex(ValueError, "runtime_authority_required"):
                OperationReceipt.create(identity, 0, OP, live.provenance.to_dict(), remote, "2026-09-01T00:00:00Z", "2026-09-01T00:00:01Z")
            with self.assertRaisesRegex(ValueError, "runtime_authority_required"):
                OperationReceipt.create(identity, 0, OP, live.service.resolve_application_authority(live.authority_id), remote, "2026-09-01T00:00:00Z", "2026-09-01T00:00:01Z")

            receipt = live.new_receipt(0, remote, "2026-09-01T00:00:00Z", "2026-09-01T00:00:01Z")
            historical = AuthorityProvenance.from_dict(live.provenance.to_dict())
            caller_receipt = OperationReceipt(receipt.operation_receipt_id, receipt.application_id, identity, receipt.operation_identity, 0, OP,
                                               request_identity(receipt.operation_identity), historical, remote, receipt.started_at, receipt.completed_at)
            with tempfile.TemporaryDirectory() as path:
                historical_store = SQLiteExecutionStore(Path(path) / "state.sqlite3", identity.values()["workspace_identity"])
                with self.assertRaisesRegex(ValueError, "runtime_authority_required"):
                    historical_store.record_operation_receipt(caller_receipt)

            with tempfile.TemporaryDirectory() as path:
                store = SQLiteExecutionStore(Path(path) / "state.sqlite3", identity.values()["workspace_identity"], runtime_service=other.service)
                with self.assertRaisesRegex(ValueError, "runtime_context_owner_mismatch"):
                    store.record_operation_receipt(receipt)

            live.service.clock = lambda: datetime(2026, 8, 14, 14, tzinfo=timezone.utc)
            with self.assertRaisesRegex(ValueError, "runtime_authority_invalid"):
                live.new_receipt(0, remote, "2026-09-01T00:00:00Z", "2026-09-01T00:00:01Z")
        finally:
            directory.cleanup()
            other_directory.cleanup()

    def test_c5_unregistered_context_and_artifacts_cannot_first_insert(self):
        directory, live = self._live_authority()
        try:
            with self.assertRaisesRegex(ValueError, "runtime_context_internal_only"):
                RuntimeApplicationExecutionContext(None, None, None, None, ())
            self.assertFalse(hasattr(live.service, "_register_live_artifact"))
            identity = live.identity
            remote_payload = {"repository_identity": live.repository_identity, "issue_number": 1}
            remote = {"result_kind": "issue", "result_identity": "issue-1", "result_digest": digest(remote_payload), "result_payload": remote_payload}
            registered_receipt = live.new_receipt(0, remote, "2026-09-01T00:00:00Z", "2026-09-01T00:00:01Z")
            registered_attempt = live.new_attempt(0, state="Applying", started_at=registered_receipt.started_at, updated_at=registered_receipt.started_at)
            registered_state = live.new_execution_state(state="Pending", next_operation_index=0, owner_id=None, current_attempt_id=None,
                                                        recovery_code=None, operation_receipt_refs=(), started_at=registered_receipt.started_at,
                                                        updated_at=registered_receipt.started_at)
            registered_application_receipt = live.finalize_application_receipt((registered_receipt,), registered_receipt.started_at, registered_receipt.completed_at)
            with tempfile.TemporaryDirectory() as path:
                store = SQLiteExecutionStore(Path(path) / "state.sqlite3", identity.values()["workspace_identity"], runtime_service=live.service)
                for artifact, method in ((replace(registered_state), store.save_execution),
                                         (replace(registered_attempt), store.save_attempt),
                                         (replace(registered_receipt), store.record_operation_receipt),
                                         (replace(registered_application_receipt), store.record_application_receipt)):
                    with self.subTest(kind=type(artifact).__name__):
                        with self.assertRaisesRegex(ValueError, "runtime_authority_required"):
                            method(artifact)
        finally:
            directory.cleanup()

    def test_attempt_binding_and_legitimate_coordination_update(self):
        auth_directory, live = self._live_authority()
        try:
            identity = LogicalApplicationIdentity.from_authority(live)
            provenance = live.provenance
            opid = operation_identity(identity.application_id, 0, OP)
            base = OperationAttemptState(identity.application_id, opid, 0, OP, provenance, live.driver_identity, live.remote_authority, request_identity(opid), "Applying", "2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z", identity, _live_context=live).with_digest()
            for field, value in (("operation_identity", "operation-bad"), ("operation_index", 1), ("request_identity", "request-bad"), ("driver_identity", "driver-bad"), ("remote_authority", "sha256:other")):
                with self.subTest(field=field):
                    with self.assertRaises(ValueError): OperationAttemptState(**{**base.__dict__, field: value})
            updated = replace(base, state="OutcomeUnknown", updated_at="2026-09-01T00:00:01Z").with_digest()
            self.assertTrue(updated.verify_integrity())
        finally:
            auth_directory.cleanup()

    def test_receipt_provenance_and_export_immutability_matrix(self):
        auth_directory, live = self._live_authority()
        try:
            identity = LogicalApplicationIdentity.from_authority(live)
            payload = {"repository_identity": live.repository_identity, "issue_number": 1}
            remote = {"result_kind": "issue", "result_identity": "issue-1", "result_digest": digest(payload), "result_payload": payload}
            receipt = OperationReceipt.create(identity, 0, OP, live, remote, "2026-09-01T00:00:00Z", "2026-09-01T00:00:01Z")
            exported = receipt.to_dict()
            exported["remote_result"]["result_payload"]["issue_number"] = 99
            self.assertTrue(receipt.verify_integrity())
            for field in ("authority_id", "credential_binding_id", "credential_instance_id", "issuer_id", "credential_principal_identity", "github_subject_identity", "issued_at", "expires_at", "driver_identity", "remote_authority", "application_id"):
                bad = receipt.authority_binding.to_dict()
                del bad[field]
                with self.assertRaises(ValueError): replace(receipt, authority_binding=bad)
            with self.assertRaises(ValueError): replace(receipt, request_identity="request-bad")
            with self.assertRaises(ValueError): replace(receipt, application_id="application-other")
            with self.assertRaises(ValueError): replace(receipt, remote_result={"provider": "github"})
        finally:
            auth_directory.cleanup()

    def test_application_receipt_finalization_negative_matrix_and_mixed_authority(self):
        auth_directory, live = self._live_authority()
        try:
            identity = LogicalApplicationIdentity.from_authority(live)
            payload = {"repository_identity": live.repository_identity, "issue_number": 1}
            remote = {"result_kind": "issue", "result_identity": "issue-1", "result_digest": digest(payload), "result_payload": payload}
            first = OperationReceipt.create(identity, 0, OP, live, remote, "2026-09-01T00:00:00Z", "2026-09-01T00:00:01Z")
            self.assertTrue(ApplicationReceipt.create(identity, identity.values()["operation_set_digest"], (OP,), (first,), first.started_at, first.completed_at).verify_integrity())
            other_identity = LogicalApplicationIdentity.from_authority({**identity.values(), "repository_identity": "other/repo"})
            cases = ((), (first, first), (replace(first, receipt_digest="sha256:bad"),))
            for receipts in cases:
                with self.subTest(receipts=len(receipts)):
                    with self.assertRaises(ValueError): ApplicationReceipt.create(identity, identity.values()["operation_set_digest"], (OP,), receipts, first.started_at, first.completed_at)
            with self.assertRaises(ValueError): ApplicationReceipt.create(other_identity, identity.values()["operation_set_digest"], (OP,), (first,), first.started_at, first.completed_at)
        finally:
            auth_directory.cleanup()

    def test_v6_table_constraint_and_index_tamper_matrix(self):
        table_mutations = (
            ("type", "replace(sql, 'payload TEXT NOT NULL', 'payload INTEGER NOT NULL')"),
            ("nullability", "replace(sql, 'payload TEXT NOT NULL', 'payload TEXT')"),
            ("primary_key", "replace(sql, 'PRIMARY KEY (workspace_identity, application_id)', 'PRIMARY KEY (workspace_identity)')"),
            ("check", "replace(sql, 'length(payload) > 0', 'length(payload) >= 0')"),
            ("missing_column", "'CREATE TABLE application_execution (workspace_identity TEXT NOT NULL, application_id TEXT NOT NULL, PRIMARY KEY (workspace_identity, application_id))'"),
        )
        for name, expression in table_mutations:
            with self.subTest(table_mutation=name), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "state.sqlite3"
                SQLiteExecutionStore(path, "workspace-1")
                with closing(sqlite3.connect(path)) as connection:
                    connection.execute("PRAGMA writable_schema=ON")
                    connection.execute(f"UPDATE sqlite_master SET sql={expression} WHERE type='table' AND name='application_execution'")
                    connection.execute("PRAGMA writable_schema=OFF")
                    connection.commit()
                with self.assertRaises(sqlite_schema.SchemaOwnerError): SQLiteExecutionStore(path, "workspace-1")
        index_mutations = (
            ("wrong_column", "CREATE INDEX idx_application_receipts_workspace_application ON application_receipts(application_id)"),
            ("wrong_order", "CREATE INDEX idx_application_receipts_workspace_application ON application_receipts(application_id, workspace_identity)"),
            ("wrong_unique", "CREATE UNIQUE INDEX idx_application_receipts_workspace_application ON application_receipts(workspace_identity, application_id)"),
        )
        for name, ddl in index_mutations:
            with self.subTest(index_mutation=name), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "state.sqlite3"
                SQLiteExecutionStore(path, "workspace-1")
                with closing(sqlite3.connect(path)) as connection:
                    connection.execute("DROP INDEX idx_application_receipts_workspace_application")
                    connection.execute(ddl)
                    connection.commit()
                with self.assertRaises(sqlite_schema.SchemaOwnerError): SQLiteExecutionStore(path, "workspace-1")

    def test_v6_inherited_v5_object_and_metadata_tamper_matrix(self):
        mutations = ("table", "index", "extra", "unsupported", "incomplete")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "state.sqlite3"
                SQLiteExecutionStore(path, "workspace-1")
                with closing(sqlite3.connect(path)) as connection:
                    if mutation == "table":
                        connection.execute("PRAGMA writable_schema=ON")
                        connection.execute("UPDATE sqlite_master SET sql=replace(sql, 'payload TEXT NOT NULL', 'payload INTEGER NOT NULL') WHERE type='table' AND name='records'")
                        connection.execute("PRAGMA writable_schema=OFF")
                    elif mutation == "index":
                        connection.execute("DROP INDEX idx_attestation_artifacts_workspace_digest")
                        connection.execute("CREATE INDEX idx_attestation_artifacts_workspace_digest ON attestation_artifacts(workspace_identity)")
                    elif mutation == "extra":
                        connection.execute("CREATE TABLE unexpected_inherited(value TEXT)")
                    elif mutation == "unsupported":
                        connection.execute("UPDATE store_meta SET schema_version=99")
                    else:
                        connection.execute("DROP INDEX idx_application_receipts_workspace_application")
                    connection.commit()
                with self.assertRaises(sqlite_schema.SchemaOwnerError): SQLiteExecutionStore(path, "workspace-1")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite3"
            SQLiteExecutionStore(path, "workspace-1")
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("DROP INDEX idx_application_receipts_workspace_application")
            with self.assertRaises(sqlite_schema.SchemaOwnerError): SQLiteExecutionStore(path, "workspace-1")


if __name__ == "__main__":
    unittest.main()
