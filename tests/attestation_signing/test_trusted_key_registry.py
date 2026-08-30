from __future__ import annotations

import copy
import pickle
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from delivery_system.attestation_signing import (
    AttestationSigningConfigurationError,
    TrustedEd25519IssuerKeyRegistry,
    TrustedEd25519Key,
)


# TEST ONLY / NON-PRODUCTION: deterministic public keys derived in memory.
TEST_ONLY_PRIVATE_BYTES = bytes(range(32))
ALTERNATE_PRIVATE_BYTES = bytes(range(32, 64))


class EvilStr(str):
    pass


def key(issuer: str = "host-issuer", key_id: str = "key-1", private_bytes=TEST_ONLY_PRIVATE_BYTES):
    private = Ed25519PrivateKey.from_private_bytes(private_bytes)
    return TrustedEd25519Key(issuer, key_id, private.public_key())


class TrustedKeyRegistryTests(unittest.TestCase):
    def test_valid_single_and_multiple_entries(self):
        first = key()
        second = key(key_id="key-2", private_bytes=ALTERNATE_PRIVATE_BYTES)
        registry = TrustedEd25519IssuerKeyRegistry((first, second))
        self.assertIs(registry.resolve("host-issuer", "key-1", "ed25519"), first.public_key)
        self.assertIs(registry.resolve("host-issuer", "key-2", "ed25519"), second.public_key)

    def test_duplicate_identity_is_rejected(self):
        with self.assertRaisesRegex(AttestationSigningConfigurationError, "^trusted_key_duplicate$"):
            TrustedEd25519IssuerKeyRegistry((key(), key()))

    def test_policy_decisions_fail_closed_and_accept_exact_tuple(self):
        registry = TrustedEd25519IssuerKeyRegistry((key(),))
        accepted = registry.evaluate("host-issuer", "key-1", "ed25519", "2", "github-app-installation-token")
        self.assertTrue(accepted.accepted)
        self.assertEqual(
            registry.evaluate("unknown", "key-1", "ed25519", "2", "github-app-installation-token").failure_code,
            "attestation_issuer_untrusted",
        )
        self.assertEqual(
            registry.evaluate("host-issuer", "unknown", "ed25519", "2", "github-app-installation-token").failure_code,
            "attestation_issuer_untrusted",
        )
        self.assertEqual(
            registry.evaluate("host-issuer", "key-1", "rsa", "2", "github-app-installation-token").failure_code,
            "attestation_algorithm_unsupported",
        )
        self.assertEqual(
            registry.evaluate("host-issuer", "key-1", "ed25519", "1", "github-app-installation-token").failure_code,
            "attestation_version_unsupported",
        )
        self.assertEqual(
            registry.evaluate("host-issuer", "key-1", "ed25519", "2", "other-class").failure_code,
            "attestation_credential_class_unsupported",
        )

    def test_configuration_values_are_strict(self):
        with self.assertRaises(AttestationSigningConfigurationError):
            TrustedEd25519Key(EvilStr("host-issuer"), "key-1", key().public_key)
        with self.assertRaises(AttestationSigningConfigurationError):
            TrustedEd25519Key("host-issuer", "key-1", Ed25519PrivateKey.from_private_bytes(TEST_ONLY_PRIVATE_BYTES))  # type: ignore[arg-type]
        with self.assertRaises(AttestationSigningConfigurationError):
            TrustedEd25519IssuerKeyRegistry((key(),), allowed_attestation_versions=(EvilStr("2"),))
        with self.assertRaises(AttestationSigningConfigurationError):
            TrustedEd25519IssuerKeyRegistry((key(),), allowed_credential_classes=(EvilStr("github-app-installation-token"),))

    def test_registry_is_immutable_static_configuration(self):
        registry = TrustedEd25519IssuerKeyRegistry((key(),))
        self.assertFalse(hasattr(registry, "__dict__"))
        self.assertEqual(repr(registry), "<TrustedEd25519IssuerKeyRegistry protected>")
        for method in ("add", "remove", "rotate", "revoke"):
            self.assertFalse(hasattr(registry, method))
        self.assertFalse(hasattr(registry, "private_key"))
        self.assertNotIn("<cryptography", repr(registry))
        self.assertIsNone(registry.resolve("host-issuer", "key-1", "other"))
        self.assertIsNone(registry.resolve("host-issuer", "key-2", "ed25519"))
        for name, value in (
            ("_TrustedEd25519IssuerKeyRegistry__lookup", {}),
            ("_TrustedEd25519IssuerKeyRegistry__versions", ("1",)),
            ("_TrustedEd25519IssuerKeyRegistry__classes", ("other",)),
            ("_TrustedEd25519IssuerKeyRegistry__entries", ()),
        ):
            with self.subTest(name=name):
                with self.assertRaises(AttestationSigningConfigurationError):
                    setattr(registry, name, value)
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with self.subTest(operation=operation):
                with self.assertRaises(AttestationSigningConfigurationError):
                    operation(registry)


if __name__ == "__main__":
    unittest.main()
