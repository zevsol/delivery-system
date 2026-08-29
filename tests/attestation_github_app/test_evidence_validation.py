from __future__ import annotations

from datetime import datetime, timezone
import unittest
import unicodedata

from delivery_system.attestation_github_app import (
    GitHubAppCapabilityProviderError,
    GitHubAppInstallationCapabilityEvidence,
    _normalize_evidence,
)


NOW = datetime(2026, 8, 14, 12, tzinfo=timezone.utc)


def evidence(**changes):
    value = {
        "app_id": 12345,
        "installation_id": 67890,
        "installation_account_identity": "account-identity",
        "repository_id": 42,
        "repository_identity": "Owner/Repo",
        "repository_scope": ["owner/repo"],
        "effective_permissions": {"issues": "write"},
        "expires_at": "2026-08-14T13:00:00Z",
        "observed_at": "2026-08-14T11:00:00Z",
        "credential_instance_id": "credential-instance-" + "a" * 32,
    }
    value.update(changes)
    return value


class EvidenceValidationTests(unittest.TestCase):
    def test_normalizes_to_immutable_target_only_evidence(self):
        result = _normalize_evidence(evidence())
        self.assertIsInstance(result, GitHubAppInstallationCapabilityEvidence)
        self.assertEqual(result.repository_identity, "owner/repo")
        self.assertEqual(result.repository_scope, ("owner/repo",))
        self.assertEqual(result.effective_permissions, (("issues", "write"),))
        with self.assertRaises(Exception):
            result.repository_scope += ("other/repo",)

    def test_rejects_malformed_evidence_and_permissions(self):
        cases = (
            {"app_id": 0},
            {"repository_identity": "owner/repo/extra"},
            {"repository_scope": []},
            {"repository_scope": ["other/repo", "owner/repo"]},
            {"effective_permissions": []},
            {"effective_permissions": {"issues": "admin"}},
            {"effective_permissions": {"contents": "write"}},
        )
        for change in cases:
            with self.subTest(change=change):
                with self.assertRaises(GitHubAppCapabilityProviderError):
                    _normalize_evidence(evidence(**change))

    def test_normalizes_utc_and_rejects_bad_types(self):
        result = _normalize_evidence(evidence(expires_at="2026-08-14T12:00:00+00:00"))
        self.assertEqual(result.expires_at, "2026-08-14T12:00:00Z")
        with self.assertRaises(GitHubAppCapabilityProviderError):
            _normalize_evidence(evidence(app_id=True))

    def test_normalized_evidence_is_accepted_and_normalization_is_idempotent(self):
        normalized = _normalize_evidence(evidence())
        self.assertEqual(_normalize_evidence(normalized), normalized)
        self.assertEqual(_normalize_evidence(evidence()), normalized)

    def test_directly_constructed_malformed_evidence_is_rejected(self):
        base = _normalize_evidence(evidence())
        cases = (
            base.__class__(**{**base.__dict__, "repository_scope": ("other/repo",)}),
            base.__class__(**{**base.__dict__, "effective_permissions": (("issues", "admin"),)}),
            base.__class__(**{**base.__dict__, "effective_permissions": (("issues", "read"), ("issues", "write"))}),
        )
        for malformed in cases:
            with self.subTest(malformed=malformed):
                with self.assertRaises(GitHubAppCapabilityProviderError):
                    _normalize_evidence(malformed)

    def test_installation_account_identity_uses_nfc(self):
        composed = "Café Account"
        decomposed = unicodedata.normalize("NFD", composed)
        self.assertNotEqual(composed, decomposed)
        first = _normalize_evidence(evidence(installation_account_identity=composed))
        second = _normalize_evidence(evidence(installation_account_identity=decomposed))
        self.assertEqual(first.installation_account_identity, second.installation_account_identity)


if __name__ == "__main__":
    unittest.main()
