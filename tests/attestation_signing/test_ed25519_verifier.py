from __future__ import annotations

from base64 import urlsafe_b64encode
import copy
import pickle
from unittest.mock import patch
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from delivery_system.attestation_signing import (
    AttestationSigningConfigurationError,
    AttestationVerificationError,
    Ed25519HostSigner,
    Ed25519ProofVerifier,
    TrustedEd25519IssuerKeyRegistry,
    TrustedEd25519Key,
)


# TEST ONLY / NON-PRODUCTION: fixed deterministic material never leaves memory.
TEST_ONLY_PRIVATE_BYTES = bytes(range(32))
ALTERNATE_PRIVATE_BYTES = bytes(range(32, 64))
PAYLOAD = b"S2-1 verifier payload"


class EvilStr(str):
    pass


def private(value=TEST_ONLY_PRIVATE_BYTES):
    return Ed25519PrivateKey.from_private_bytes(value)


def proof_for(value=TEST_ONLY_PRIVATE_BYTES, payload=PAYLOAD):
    return Ed25519HostSigner("host-issuer", "key-1", private(value)).sign(payload)


def registry(*entries):
    return TrustedEd25519IssuerKeyRegistry(entries or (
        TrustedEd25519Key("host-issuer", "key-1", private().public_key()),
    ))


class Ed25519VerifierTests(unittest.TestCase):
    def test_matching_real_signer_proof_verifies(self):
        verifier = Ed25519ProofVerifier(registry())
        self.assertTrue(verifier.verify(PAYLOAD, proof_for(), "host-issuer", "key-1", "ed25519"))

    def test_wrong_key_issuer_or_key_id_fails_without_fallback(self):
        alternate = TrustedEd25519Key("host-issuer", "key-2", private(ALTERNATE_PRIVATE_BYTES).public_key())
        verifier = Ed25519ProofVerifier(registry(
            TrustedEd25519Key("host-issuer", "key-1", private().public_key()), alternate
        ))
        proof = proof_for()
        self.assertFalse(verifier.verify(PAYLOAD, proof, "host-issuer", "key-2", "ed25519"))
        self.assertFalse(verifier.verify(PAYLOAD, proof, "unknown", "key-1", "ed25519"))
        self.assertFalse(verifier.verify(PAYLOAD, proof, "host-issuer", "unknown", "ed25519"))
        self.assertFalse(verifier.verify(PAYLOAD, proof, "host-issuer", "key-1", "rsa"))

    def test_tampered_payload_and_proof_fail(self):
        verifier = Ed25519ProofVerifier(registry())
        proof = proof_for()
        self.assertFalse(verifier.verify(PAYLOAD + b"!", proof, "host-issuer", "key-1", "ed25519"))
        self.assertFalse(verifier.verify(PAYLOAD, proof_for(ALTERNATE_PRIVATE_BYTES), "host-issuer", "key-1", "ed25519"))

    def test_malformed_padded_noncanonical_and_wrong_length_proofs_fail(self):
        verifier = Ed25519ProofVerifier(registry())
        proof = proof_for()
        malformed = (
            "!" * 86,
            proof + "=",
            proof[:-1] + ("A" if proof[-1] != "A" else "B"),
            urlsafe_b64encode(b"short").decode("ascii").rstrip("="),
        )
        for candidate in malformed:
            with self.subTest(candidate=candidate):
                self.assertFalse(verifier.verify(PAYLOAD, candidate, "host-issuer", "key-1", "ed25519"))

    def test_passive_input_subclasses_fail_closed(self):
        verifier = Ed25519ProofVerifier(registry())
        proof = proof_for()
        cases = (
            (bytearray(PAYLOAD), proof, "host-issuer", "key-1", "ed25519"),
            (PAYLOAD, EvilStr(proof), "host-issuer", "key-1", "ed25519"),
            (PAYLOAD, proof, EvilStr("host-issuer"), "key-1", "ed25519"),
            (PAYLOAD, proof, "host-issuer", EvilStr("key-1"), "ed25519"),
            (PAYLOAD, proof, "host-issuer", "key-1", EvilStr("ed25519")),
        )
        for values in cases:
            with self.subTest(types=tuple(type(value).__name__ for value in values)):
                self.assertFalse(verifier.verify(*values))  # type: ignore[arg-type]

    def test_invalid_signature_is_false(self):
        verifier = Ed25519ProofVerifier(registry())
        with patch.object(
            TrustedEd25519IssuerKeyRegistry,
            "resolve",
            return_value=private().public_key(),
        ):
            self.assertFalse(verifier.verify(PAYLOAD, proof_for(ALTERNATE_PRIVATE_BYTES), "host-issuer", "key-1", "ed25519"))

    def test_unexpected_registry_dependency_failure_is_stable_and_redacted(self):
        verifier = Ed25519ProofVerifier(registry())
        with patch.object(
            TrustedEd25519IssuerKeyRegistry,
            "resolve",
            side_effect=RuntimeError("RAW_TOKEN_SENTINEL"),
        ):
            with self.assertRaises(AttestationVerificationError) as context:
                verifier.verify(PAYLOAD, proof_for(), "host-issuer", "key-1", "ed25519")
        self.assertEqual(str(context.exception), "attestation_verifier_failed")
        self.assertNotIn("RAW_TOKEN_SENTINEL", str(context.exception))
        self.assertNotIn("RAW_TOKEN_SENTINEL", repr(context.exception))

    def test_verifier_binding_and_generic_copy_surfaces_are_sealed(self):
        verifier = Ed25519ProofVerifier(registry())
        self.assertFalse(hasattr(verifier, "__dict__"))
        with self.assertRaises(TypeError):
            vars(verifier)
        for name, value in (
            ("_Ed25519ProofVerifier__registry", registry()),
            ("unexpected", object()),
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(AttestationSigningConfigurationError, "^verifier_configuration_sealed$"):
                    setattr(verifier, name, value)
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(AttestationSigningConfigurationError, "^verifier_(?:copy_forbidden|serialization_forbidden)$"):
                    operation(verifier)
        self.assertTrue(verifier.verify(PAYLOAD, proof_for(), "host-issuer", "key-1", "ed25519"))


if __name__ == "__main__":
    unittest.main()
