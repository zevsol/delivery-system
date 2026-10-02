from __future__ import annotations

import inspect
from pathlib import Path
import tempfile
import unittest

from delivery_system.host_composition import (
    HostConfiguration,
    compose_write_enabled_host,
    load_host_configuration,
)

from tests.v1.test_h4_host_composition import _environment


class HostConfigurationContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.environment = _environment(root / "rsa.pem", root / "ed-private.pem", root / "ed-public.pem")
        self.configuration = load_host_configuration(self.environment)

    def tearDown(self) -> None:
        self.directory.cleanup()

    @staticmethod
    def _documented_inventory(document: str) -> dict[str, tuple[str, str]]:
        state = None
        inventory = {}
        for line in document.splitlines():
            if line == "The following inputs are required:":
                state = "required"
            elif line == "The following inputs are optional:":
                state = "optional"
            elif line.startswith("| `DELIVERY_SYSTEM_"):
                cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
                if len(cells) != 4:
                    raise AssertionError(f"unexpected Host configuration table row: {line}")
                name = cells[0].strip("`")
                if cells[1] == "forbidden":
                    inventory[name] = ("forbidden", cells[3])
                else:
                    if state is None:
                        raise AssertionError(f"Host configuration row has no required/optional section: {line}")
                    inventory[name] = (state, cells[3])
        return inventory

    def test_canonical_environment_inventory_and_documentation_match(self) -> None:
        fields = HostConfiguration.ENVIRONMENT_FIELDS
        required = {field.name for field in fields if field.state == "required"}
        optional = {field.name for field in fields if field.state == "optional"}
        forbidden = {field.name for field in fields if field.state == "forbidden"}
        self.assertEqual(len(required), 16)
        self.assertEqual(optional, {
            "DELIVERY_SYSTEM_REVOCATION_AUTH_TOKEN_PATH",
            "DELIVERY_SYSTEM_ATTESTATION_LIFECYCLE_PATH",
            "DELIVERY_SYSTEM_AUTHORITY_BINDING_LIFECYCLE_PATH",
        })
        self.assertEqual(forbidden, {"DELIVERY_SYSTEM_GITHUB_INSTALLATION_ID"})
        self.assertEqual(required & optional, set())
        self.assertEqual(required & forbidden, set())
        self.assertEqual(set(HostConfiguration.REQUIRED_ENVIRONMENT_FIELDS), required)
        self.assertEqual(set(HostConfiguration.OPTIONAL_ENVIRONMENT_FIELDS), optional)
        self.assertEqual(set(HostConfiguration.FORBIDDEN_ENVIRONMENT_FIELDS), forbidden)
        self.assertTrue(set(HostConfiguration.PROTECTED_REFERENCE_FIELDS) <= required | optional)
        self.assertTrue(set(HostConfiguration.PUBLIC_REFERENCE_FIELDS) <= required | optional)
        classified = (
            set(HostConfiguration.PROTECTED_REFERENCE_FIELDS)
            | set(HostConfiguration.PUBLIC_REFERENCE_FIELDS)
            | set(HostConfiguration.NON_SECRET_FIELDS)
        )
        self.assertEqual(classified, required | optional)
        self.assertEqual(set(HostConfiguration.PROTECTED_REFERENCE_FIELDS) & set(HostConfiguration.NON_SECRET_FIELDS), set())
        self.assertEqual(set(HostConfiguration.PUBLIC_REFERENCE_FIELDS) & set(HostConfiguration.NON_SECRET_FIELDS), set())
        document = Path("docs/host-configuration.md").read_text(encoding="utf-8")
        classification = {
            "non-secret": "non-secret",
            "protected-reference": "protected reference",
            "public-trust-material-reference": "public trust-material reference",
            "non-secret-lifecycle-policy-reference": "non-secret lifecycle-policy reference",
            "forbidden": "forbidden",
        }
        expected = {
            field.name: (field.state, classification[field.classification])
            for field in fields
        }
        self.assertEqual(self._documented_inventory(document), expected)

    def test_required_optional_and_forbidden_membership_drives_adapter(self) -> None:
        for field in HostConfiguration.ENVIRONMENT_FIELDS:
            if field.state != "required":
                continue
            candidate = dict(self.environment)
            candidate.pop(field.name)
            with self.subTest(field=field.name), self.assertRaises(ValueError):
                load_host_configuration(candidate)
        self.assertIsInstance(load_host_configuration(self.environment), HostConfiguration)
        forbidden = dict(self.environment)
        forbidden["DELIVERY_SYSTEM_GITHUB_INSTALLATION_ID"] = "54321"
        with self.assertRaises(ValueError):
            load_host_configuration(forbidden)

    def test_direct_configuration_construction_preserves_validation_contract(self) -> None:
        candidates = (
            {"attestation_issuer_id": "Bad_ID"},
            {"attestation_private_key_path": "relative.pem"},
            {"revocation_provider_url": "not-a-url"},
            {"revocation_timeout_ms": 0},
            {"revocation_auth_token_path": "relative-token"},
        )
        for candidate in candidates:
            values = {
                "github_app": self.configuration.github_app,
                "attestation_issuer_id": self.configuration.attestation_issuer_id,
                "attestation_key_id": self.configuration.attestation_key_id,
                "attestation_private_key_path": self.configuration.attestation_private_key_path,
                "attestation_public_key_path": self.configuration.attestation_public_key_path,
                "attestation_trusted_keys_path": self.configuration.attestation_trusted_keys_path,
                "authority_binding_issuer_id": self.configuration.authority_binding_issuer_id,
                "authority_binding_active_key_id": self.configuration.authority_binding_active_key_id,
                "authority_binding_private_key_path": self.configuration.authority_binding_private_key_path,
                "authority_binding_public_key_path": self.configuration.authority_binding_public_key_path,
                "authority_binding_trusted_keys_path": self.configuration.authority_binding_trusted_keys_path,
                "revocation_provider_url": self.configuration.revocation_provider_url,
                "revocation_timeout_ms": self.configuration.revocation_timeout_ms,
                "revocation_auth_token_path": self.configuration.revocation_auth_token_path,
            }
            values.update(candidate)
            with self.subTest(candidate=candidate):
                with self.assertRaises(ValueError):
                    HostConfiguration(**values)

    def test_composition_requires_explicit_configuration_keyword(self) -> None:
        parameters = inspect.signature(compose_write_enabled_host).parameters
        self.assertIn("configuration", parameters)
        self.assertEqual(parameters["configuration"].kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertNotIn("environment", parameters)

    def test_github_app_fresh_composition_continuity_contract_is_documented(self) -> None:
        host_document = Path("docs/host-configuration.md").read_text(encoding="utf-8")
        architecture_document = Path("docs/architecture-and-lifecycle.md").read_text(encoding="utf-8")
        debt_document = Path("docs/debt-register.md").read_text(encoding="utf-8")
        host_document = host_document.lower()
        for phrase in (
            "github app fresh-composition continuity",
            "g1 → g2",
            "successful installation lease",
            "no automatic fallback to g1",
            "no automatic installation-token renewal/reacquisition loop",
            "normal rotation",
            "compromise",
            "rsa private-key material remains external and non-persistent",
        ):
            with self.subTest(document="host", phrase=phrase):
                self.assertIn(phrase, host_document)
        architecture_document = architecture_document.lower()
        debt_document = debt_document.lower()
        for phrase in (
            "fresh-composition github app continuity is supported",
            "no persistent app-key history",
            "no simultaneous multi-key runtime",
            "no universal keymanager",
            "no live reload",
            "no automatic app-key rotation",
            "no automatic rollback or failover",
            "one acquisition per fresh composition",
            "expired lease fails closed before write dispatch",
            "no automatic renewal or reacquisition",
            "fresh composition obtains a fresh lease and credential instance",
            "initial attestation checks external revocation status",
            "restart reconstruction checks it again",
            "do not promise per-write external revocation polling",
            "does not revoke a github installation token through github",
            "delete or revoke an app private key",
            "durable key-transition history is not required",
            "no transition ledger is introduced",
            "`arc-key-lifecycle-01` is resolved for this bounded first-release contract",
        ):
            with self.subTest(document="architecture", phrase=phrase):
                self.assertIn(phrase, architecture_document)
        self.assertNotIn("`arc-key-lifecycle-01` remains open", architecture_document)
        self.assertRegex(
            debt_document,
            r"### arc-key-lifecycle-01 — key rotation and recovery\s+- category: security; status: resolved;",
        )
        self.assertNotRegex(
            debt_document,
            r"### arc-key-lifecycle-01 — key rotation and recovery\s+- category: security; status: open;",
        )


if __name__ == "__main__":
    unittest.main()
