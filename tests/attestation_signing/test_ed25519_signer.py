from __future__ import annotations

from base64 import urlsafe_b64decode
import copy
import pickle
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from delivery_system.attestation_signing import (
    AttestationSigningConfigurationError,
    AttestationSigningError,
    Ed25519HostSigner,
)


# TEST ONLY / NON-PRODUCTION: fixed deterministic material never leaves memory.
TEST_ONLY_PRIVATE_BYTES = bytes(range(32))
PAYLOAD = b"S2-1 deterministic claims payload"


class EvilStr(str):
    def __str__(self) -> str:
        raise RuntimeError("RAW_TOKEN_SENTINEL")


class EvilBytes(bytes):
    pass


class ThrowingPrivateKey:
    def sign(self, payload: bytes) -> bytes:
        raise RuntimeError("RAW_TOKEN_SENTINEL")


class Ed25519SignerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.from_private_bytes(TEST_ONLY_PRIVATE_BYTES)

    def make(self, issuer: str = "host-issuer", key_id: str = "key-1") -> Ed25519HostSigner:
        return Ed25519HostSigner(issuer, key_id, self.private_key)

    def test_signs_real_ed25519_proof_with_canonical_encoding(self):
        proof = self.make().sign(PAYLOAD)
        self.assertIs(type(proof), str)
        self.assertEqual(len(proof), 86)
        self.assertNotIn("=", proof)
        self.assertRegex(proof, r"^[A-Za-z0-9_-]{86}$")
        decoded = urlsafe_b64decode(proof + "==")
        self.assertIs(type(decoded), bytes)
        self.assertEqual(len(decoded), 64)
        self.assertEqual(__import__("base64").urlsafe_b64encode(decoded).decode("ascii").rstrip("="), proof)

    def test_same_key_and_payload_are_deterministic_and_payload_changes_signature(self):
        first = self.make().sign(PAYLOAD)
        second = self.make().sign(PAYLOAD)
        changed = self.make().sign(PAYLOAD + b" changed")
        self.assertEqual(first, second)
        self.assertNotEqual(first, changed)

    def test_metadata_and_key_configuration_are_strict(self):
        for issuer, key_id, field in (
            ("", "key-1", "issuer_id"),
            ("HOST-ISSUER", "key-1", "issuer_id"),
            ("host-issuer", "", "key_id"),
            ("host-issuer", "KEY-1", "key_id"),
            (EvilStr("host-issuer"), "key-1", "issuer_id"),
            ("host-issuer", EvilStr("key-1"), "key_id"),
        ):
            with self.subTest(field=field):
                with self.assertRaises(AttestationSigningConfigurationError):
                    self.make(issuer, key_id)

    def test_rejects_non_ed25519_key_and_non_bytes_payloads(self):
        with self.assertRaises(AttestationSigningConfigurationError):
            Ed25519HostSigner("host-issuer", "key-1", self.private_key.public_key())  # type: ignore[arg-type]
        signer = self.make()
        for payload in (bytearray(PAYLOAD), memoryview(PAYLOAD), EvilBytes(PAYLOAD), "payload"):
            with self.subTest(payload_type=type(payload).__name__):
                with self.assertRaises(AttestationSigningError):
                    signer.sign(payload)  # type: ignore[arg-type]

    def test_signing_dependency_failure_is_stable_and_redacted(self):
        signer = self.make()
        object.__setattr__(signer, "_Ed25519HostSigner__private_key", ThrowingPrivateKey())
        with self.assertRaises(AttestationSigningError) as context:
            signer.sign(PAYLOAD)
        self.assertEqual(str(context.exception), "attestation_signing_failed")
        self.assertNotIn("RAW_TOKEN_SENTINEL", str(context.exception))
        self.assertNotIn("RAW_TOKEN_SENTINEL", repr(context.exception))

    def test_signer_has_safe_repr_and_no_private_key_export_surface(self):
        signer = self.make()
        self.assertEqual(repr(signer), "<Ed25519HostSigner protected>")
        self.assertNotIn("private", repr(signer).lower())
        self.assertFalse(hasattr(signer, "private_key"))
        self.assertFalse(hasattr(signer, "private_bytes"))
        self.assertEqual(signer.issuer_id, "host-issuer")
        self.assertEqual(signer.key_id, "key-1")
        self.assertEqual(signer.signature_algorithm, "ed25519")

    def test_signer_configuration_and_generic_copy_surfaces_are_sealed(self):
        signer = self.make()
        self.assertFalse(hasattr(signer, "__dict__"))
        with self.assertRaises(TypeError):
            vars(signer)
        for name, value in (("issuer_id", "other"), ("key_id", "other"), ("_Ed25519HostSigner__private_key", self.private_key)):
            with self.subTest(name=name):
                with self.assertRaises(AttestationSigningConfigurationError):
                    setattr(signer, name, value)
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with self.subTest(operation=operation):
                with self.assertRaises(AttestationSigningConfigurationError) as context:
                    operation(signer)
                self.assertNotIn("private", str(context.exception).lower())
                self.assertNotIn("RAW_TOKEN_SENTINEL", repr(context.exception))


if __name__ == "__main__":
    unittest.main()
