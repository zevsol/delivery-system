from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from delivery_system.auditor import RuleEvaluationDraft, RuntimeAuditor
from delivery_system.drivers.contract import DriverReadResponse
from delivery_system.host_composition import compose_write_enabled_host, load_host_configuration
from delivery_system.protocol import digest
from delivery_system.rules import SemanticOutcome, build_registry_v1
from delivery_system.runtime import RuntimeContext, RuntimePlanner

from tests.v1 import test_h4_host_composition as host_fixture
from tests.v1 import test_operational_approval_authority as approval_fixture


NOW = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
INSTANCE_ID = "00000000-0000-4000-8000-000000000201"
SUBJECT = f"github-app-installation-{host_fixture.APP_ID}-{host_fixture.INSTALLATION_ID}"


class LocalHostDriver:
    def __init__(self, trust_context) -> None:
        self.trust_context = trust_context

    def read_repository(self, repository: str, query_scope: dict[str, object]) -> DriverReadResponse:
        issue = {
            "issue_id": "I1", "item_type": "issue", "title": "Existing",
            "updated_at": "2026-09-06T00:00:00+00:00", "repository_identity": "owner/repo",
        }
        payload = {
            "requested_repository": repository,
            "canonical_repository": "owner/repo",
            "remote_repository_id": "R1",
            "authenticated_subject": SUBJECT,
            "visibility": "private",
            "permissions": {"read": True, "write": True},
            "capabilities": {"issues": True, "relationships": True},
            "query_scope": dict(query_scope),
            "query_complete": True,
            "pagination_complete": True,
            "issue_records": [issue],
            "relationship_records": [],
            "evidence_material": [{
                "source_identity": self.trust_context.trusted_driver_identity,
                "repository_identity": "owner/repo",
                "query_scope": dict(query_scope),
                "payload": {"issue_records": [issue], "relationship_records": []},
            }],
            "source_identity": self.trust_context.trusted_driver_identity,
        }
        return DriverReadResponse(
            **payload,
            remote_content_digest=digest(payload),
        )


class HostRestartIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = tempfile.TemporaryDirectory()
        self.keys = tempfile.TemporaryDirectory()
        root = Path(self.workspace.name)
        keys = Path(self.keys.name)
        self.context = RuntimeContext.from_workspace_root(root)
        self.rsa_path = keys / "github-rsa.pem"
        self.credential_private_path = keys / "credential-private.pem"
        self.credential_public_path = keys / "credential-public.pem"
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        credential_key = ed25519.Ed25519PrivateKey.generate()
        self.rsa_path.write_bytes(host_fixture._pem_private(rsa_key))
        self.credential_private_path.write_bytes(host_fixture._pem_private(credential_key))
        self.credential_public_path.write_bytes(host_fixture._pem_public(credential_key.public_key()))
        self.environment = host_fixture._environment(
            self.rsa_path, self.credential_private_path, self.credential_public_path,
        )
        self.transport = host_fixture.FakeRevocationTransport()

    def tearDown(self) -> None:
        self.keys.cleanup()
        self.workspace.cleanup()

    def _compose(self, *, environment=None):
        return compose_write_enabled_host(
            self.context,
            configuration=load_host_configuration(environment or self.environment),
            bootstrap_transport=host_fixture.FakeBootstrapTransport(),
            clock=lambda: NOW,
            credential_instance_id_factory=lambda: INSTANCE_ID,
            nonce_factory=lambda: "nonce-" + "b" * 32,
            revocation_transport=self.transport,
        )

    def _prepare(self, composition):
        driver = LocalHostDriver(composition.trust_context)
        preview = RuntimePlanner(
            composition.context, composition.store, driver, composition.trust_context,
        ).preview(approval_fixture.plan())
        auditor = RuntimeAuditor(
            composition.context, composition.store, build_registry_v1(), composition.trust_context,
        )
        audit_context = auditor.get_context(preview["preview_id"], 1)
        evaluations = [
            RuleEvaluationDraft(rule["rule_id"], rule["rule_version"], SemanticOutcome.PASSED, "verified")
            for rule in audit_context["semantic_rule_contexts"] if rule["applicability"] == "Applicable"
        ]
        audit = auditor.record_audit(
            preview["preview_id"], 1, audit_context["audit_context_digest"], evaluations, [],
        )
        service = composition.approval_authority_service
        approval = service.record_approval(
            preview["preview_id"], 1, f"批准写入 {preview['preview_id']} 1", "human",
        )
        return preview, audit, approval

    def _compose_with_store_ready(self, **kwargs):
        return patch.object(
            type(self.context), "ensure_store_ready",
            lambda context, **ignored: Path(context.state_path).parent.mkdir(parents=True, exist_ok=True),
        )

    def test_sqlite_service_a_to_b_reconstructs_without_reissuance(self) -> None:
        with self._compose_with_store_ready():
            first = self._compose()
        try:
            preview, _audit, approval = self._prepare(first)
            original = first.approval_authority_service.issue_application_authority(
                preview["preview_id"], 1, approval.approval_id,
            )
            issuance_id = first.approval_authority_service._authority_issuance_ids[original.authority_id]
            binding_before = first.authority_binding_store.load_authority_binding(
                self.context.workspace_identity, issuance_id,
            )
            artifact_before = first.attestation_persistence_store.get_artifact_aggregate(
                self.context.workspace_identity, binding_before.payload.attestation_artifact_id,
            )
            first.close()
            with self._compose_with_store_ready():
                second = self._compose()
            try:
                service = second.approval_authority_service
                self.assertEqual(service._live_credential_contexts, {})
                with self.assertRaisesRegex(ValueError, "^application_authority_not_found$"):
                    service.resolve_application_authority(original.authority_id)
                recovered = service.reconstruct_application_authority_after_restart(
                    preview["preview_id"], 1, approval.approval_id,
                )
                self.assertEqual(recovered.authority_id, original.authority_id)
                self.assertEqual(recovered.issued_at, original.issued_at)
                self.assertEqual(recovered.expires_at, original.expires_at)
                self.assertEqual(
                    service._authority_issuance_ids[recovered.authority_id], issuance_id,
                )
                self.assertIs(service.resolve_application_authority(recovered.authority_id), recovered)
                self.assertEqual(
                    second.authority_binding_store.load_authority_binding(
                        self.context.workspace_identity, issuance_id,
                    ), binding_before,
                )
                self.assertEqual(
                    second.attestation_persistence_store.get_artifact_aggregate(
                        self.context.workspace_identity, binding_before.payload.attestation_artifact_id,
                    ), artifact_before,
                )
                self.assertIsNone(second.attestation_persistence_store.get_latest_revalidation_event(
                    self.context.workspace_identity, binding_before.payload.attestation_artifact_id,
                ))
                self.assertEqual(len(self.transport.calls), 2)
            finally:
                second.close()
        finally:
            first.close()

    def test_revocation_change_between_processes_blocks_reconstruction(self) -> None:
        with self._compose_with_store_ready():
            first = self._compose()
        try:
            preview, _audit, approval = self._prepare(first)
            first.approval_authority_service.issue_application_authority(
                preview["preview_id"], 1, approval.approval_id,
            )
            first.close()
            self.transport.response = {
                "status": "revoked", "revoked_at": "2026-09-07T12:00:00Z", "reason": "security-event",
            }
            with self._compose_with_store_ready():
                second = self._compose()
            try:
                with self.assertRaisesRegex(ValueError, "^restart_reconstruction_credential_revoked$"):
                    second.approval_authority_service.reconstruct_application_authority_after_restart(
                        preview["preview_id"], 1, approval.approval_id,
                    )
                self.assertEqual(second.approval_authority_service._authorities, {})
            finally:
                second.close()
        finally:
            first.close()

    def test_retired_authority_key_between_processes_blocks_reconstruction(self) -> None:
        with self._compose_with_store_ready():
            first = self._compose()
        try:
            preview, _audit, approval = self._prepare(first)
            first.approval_authority_service.issue_application_authority(
                preview["preview_id"], 1, approval.approval_id,
            )
            first.close()
            authority_bundle = Path(self.environment["DELIVERY_SYSTEM_AUTHORITY_BINDING_TRUSTED_KEYS_PATH"])
            data = json.loads(authority_bundle.read_text(encoding="utf-8"))
            authority_bundle.write_text(json.dumps({"version": 1, "keys": []}), encoding="utf-8")
            try:
                with self.assertRaises(Exception):
                    with self._compose_with_store_ready():
                        self._compose()
            finally:
                authority_bundle.write_text(json.dumps(data), encoding="utf-8")
        finally:
            first.close()


if __name__ == "__main__":
    unittest.main()
