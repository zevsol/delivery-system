"""Offline adversarial coverage for the Host credential continuity boundary."""

from copy import copy, deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import pickle
from unittest import TestCase
from unittest.mock import patch

from delivery_system.attestation_github_app import GitHubAppInstallationCapabilityEvidence
from delivery_system.drivers.github_write import HttpsWriteTransport, WriteTransportResponse
from delivery_system.github_app_credential import GitHubAppInstallationCredentialLease
from delivery_system.runtime import RuntimeApprovalAuthorityService
import delivery_system.applier as applier_module
import delivery_system.runtime as runtime_module
from tests.v1 import test_pc2b_applier_orchestration as pc2b
from tests.v1 import test_operational_approval_authority as approval_fixture


TOKEN = "pc4-test-token"


class CredentialContinuityTests(TestCase):
    def _compose(self, *, real_executor=False):
        return pc2b.ApplierOrchestrationTests()._compose(real_executor=real_executor)

    @staticmethod
    def _evidence(**changes):
        values = dict(
            app_id=1, installation_id=1, installation_account_identity="owner", repository_id=1,
            repository_identity="owner/repo", repository_scope=("owner/repo",),
            effective_permissions=(("issues", "write"),),
            expires_at="2026-08-14T13:00:00Z", observed_at="2026-08-14T11:00:00Z",
            credential_instance_id="fake-instance-1",
        )
        values.update(changes)
        return GitHubAppInstallationCapabilityEvidence(**values)

    def test_lease_is_exact_and_secret_protected(self):
        evidence = self._evidence()
        with self.assertRaisesRegex(ValueError, "^host_credential_capability_invalid$"):
            GitHubAppInstallationCredentialLease(TOKEN, evidence)
        lease = GitHubAppInstallationCredentialLease._mint(TOKEN, evidence)
        self.assertEqual(repr(lease), "<GitHubAppInstallationCredentialLease protected>")
        self.assertNotIn(TOKEN, repr(lease))
        with self.assertRaisesRegex(ValueError, "copy_forbidden"):
            copy(lease)
        with self.assertRaisesRegex(ValueError, "copy_forbidden"):
            deepcopy(lease)
        with self.assertRaisesRegex(ValueError, "serialization_forbidden"):
            pickle.dumps(lease)

        class LeaseSubclass(GitHubAppInstallationCredentialLease):
            pass

        subclass = LeaseSubclass._mint(TOKEN, evidence)
        directory, context, store, preview, audit, service = approval_fixture.OperationalApprovalAuthorityTests()._setup("memory")
        try:
            with self.assertRaisesRegex(ValueError, "^host_credential_capability_invalid$"):
                RuntimeApprovalAuthorityService(context, store, service.attestation_service,
                                                clock=service.clock, host_credential_lease=subclass)
        finally:
            directory.cleanup()

    def test_historical_write_token_provider_is_removed(self):
        directory, context, store, preview, audit, service = approval_fixture.OperationalApprovalAuthorityTests()._setup("memory")
        try:
            with self.assertRaises(TypeError):
                RuntimeApprovalAuthorityService(context, store, service.attestation_service,
                                                clock=service.clock, write_token_provider=object())
        finally:
            directory.cleanup()

    def test_real_offline_production_chain_dispatches_only_after_guard(self):
        directory, context, preview, service, authority, _ = self._compose(real_executor=True)
        calls = []

        def post(transport, path, body, headers):
            calls.append((path, dict(headers)))
            return WriteTransportResponse(201, {"Content-Type": "application/json"},
                                          b'{"id":1,"number":1,"node_id":"node-1"}')

        try:
            store = pc2b.ApplierOrchestrationTests()._store(context, service, directory)
            with patch.object(HttpsWriteTransport, "post", post):
                result = service.create_applier(store).apply(authority.authority_id)
            self.assertEqual(result.state, "Applied")
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][1]["Authorization"], "Bearer " + TOKEN)
            self.assertNotIn(TOKEN, repr(authority))
            with open(store.path, "rb") as database:
                self.assertNotIn(TOKEN.encode("ascii"), database.read())
        finally:
            directory.cleanup()

    def test_authority_expiry_precedes_credential_expired_settlement(self):
        for label, expired_at in (
            ("exact", datetime(2026, 8, 14, 13, 0, tzinfo=timezone.utc)),
            ("after", datetime(2026, 8, 14, 13, 1, tzinfo=timezone.utc)),
        ):
            with self.subTest(label=label):
                directory, context, preview, service, authority, driver = self._compose()
                try:
                    store = pc2b.ApplierOrchestrationTests()._store(context, service, directory)
                    expected_operations = service.create_execution_context(
                        authority.authority_id).expected_operations
                    original_materialize = applier_module._materialize

                    def expire_after_materialization(*args, **kwargs):
                        command = original_materialize(*args, **kwargs)
                        service.clock = lambda expired_at=expired_at: expired_at
                        return command

                    token_calls = []
                    original_token = service._host_credential_lease._dispatch_token
                    with patch.object(applier_module, "_materialize",
                                      side_effect=expire_after_materialization), \
                         patch.object(type(service._host_credential_lease), "_dispatch_token",
                                      lambda lease: (token_calls.append(True) or original_token())):
                        result = service.create_applier(store).apply(authority.authority_id)

                    self.assertEqual((result.state, result.recovery_code, result.next_operation_index),
                                     ("Applying", "application_recovery_required", 0))
                    self.assertEqual(len(driver.trace), 0)
                    self.assertEqual(len(token_calls), 0)
                    with self.assertRaises(ValueError):
                        store.get_application_receipt(result.application_id)
                    self.assertEqual(store.get_execution(
                        result.application_id,
                        expected_operations=expected_operations,
                    ).next_operation_index, 0)
                finally:
                    directory.cleanup()

    def _assert_swap_blocked(self, evidence_change, expected_code):
        directory, context, preview, service, authority, driver = self._compose()
        try:
            replacement = GitHubAppInstallationCredentialLease._mint(TOKEN, evidence_change)
            service._host_credential_lease = replacement
            service._host_credential_snapshot = replacement._snapshot()
            store = pc2b.ApplierOrchestrationTests()._store(context, service, directory)
            result = service.create_applier(store).apply(authority.authority_id)
            self.assertEqual((result.state, result.recovery_code), ("Blocked", expected_code))
            self.assertEqual(len(driver.trace), 0)
        finally:
            directory.cleanup()

    def test_instance_principal_repository_scope_capability_and_digest_swaps_block(self):
        cases = (
            (self._evidence(credential_instance_id="other-instance"), "credential_instance_mismatch"),
            (self._evidence(app_id=2), "credential_principal_mismatch"),
            (self._evidence(repository_identity="other/repo", repository_scope=("other/repo",)), "credential_repository_mismatch"),
            (self._evidence(observed_at="2026-08-14T11:01:00Z"), "credential_currentness_mismatch"),
        )
        for evidence, code in cases:
            with self.subTest(code=code):
                self._assert_swap_blocked(evidence, code)

    def test_lease_rejects_broader_scope_and_insufficient_permission(self):
        with self.assertRaisesRegex(ValueError, "^host_credential_capability_invalid$"):
            GitHubAppInstallationCredentialLease._mint(TOKEN, self._evidence(
                repository_scope=("owner/repo", "other/repo")))
        with self.assertRaisesRegex(ValueError, "^host_credential_capability_invalid$"):
            GitHubAppInstallationCredentialLease._mint(TOKEN, self._evidence(
                effective_permissions=(("issues", "read"),)))

    def test_metadata_tamper_and_missing_lease_block_without_dispatch(self):
        directory, context, preview, service, authority, driver = self._compose()
        try:
            lease = service._host_credential_lease
            object.__setattr__(lease, "_GitHubAppInstallationCredentialLease__token", "tampered")
            store = pc2b.ApplierOrchestrationTests()._store(context, service, directory)
            result = service.create_applier(store).apply(authority.authority_id)
            self.assertEqual((result.state, result.recovery_code), ("Blocked", "credential_capability_unregistered"))
            self.assertEqual(len(driver.trace), 0)
        finally:
            directory.cleanup()
