"""Deterministic tests for role-scoped Ed25519 lifecycle policy."""

from __future__ import annotations

import json
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from delivery_system.attestation_signing import (
    Ed25519HostSigner,
    Ed25519ProofVerifier,
    TrustedEd25519IssuerKeyRegistry,
    TrustedEd25519Key,
)
from delivery_system.ed25519_lifecycle import (
    Ed25519LifecycleError,
    parse_lifecycle_manifest,
    preflight_ed25519_lifecycle,
    public_key_fingerprint,
)


def _entry(issuer: str, key_id: str, key: ed25519.Ed25519PrivateKey, state: str) -> dict[str, str]:
    return {
        "issuer_id": issuer,
        "key_id": key_id,
        "algorithm": "ed25519",
        "public_key_fingerprint": public_key_fingerprint(key.public_key()),
        "state": state,
    }


def _manifest(role: str, issuer: str, entries: list[dict[str, str]]) -> dict[str, object]:
    return {"version": 1, "role": role, "issuer_id": issuer, "keys": entries}


class Ed25519LifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.k1 = ed25519.Ed25519PrivateKey.generate()
        self.k2 = ed25519.Ed25519PrivateKey.generate()
        self.k3 = ed25519.Ed25519PrivateKey.generate()

    def _candidates(self, *items: tuple[str, str, ed25519.Ed25519PrivateKey]) -> tuple[TrustedEd25519Key, ...]:
        return tuple(TrustedEd25519Key(issuer, key_id, key.public_key()) for issuer, key_id, key in items)

    @staticmethod
    def _verifier(result) -> Ed25519ProofVerifier:
        return Ed25519ProofVerifier(TrustedEd25519IssuerKeyRegistry(result.effective_trust_keys))

    def test_canonical_fingerprint_is_raw_public_key_and_serialization_stable(self) -> None:
        public = self.k1.public_key()
        raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        pem_key = serialization.load_pem_public_key(pem)
        der_key = serialization.load_der_public_key(der)
        expected = "sha256:" + __import__("hashlib").sha256(raw).hexdigest()
        self.assertEqual(public_key_fingerprint(public), expected)
        self.assertEqual(public_key_fingerprint(pem_key), expected)
        self.assertEqual(public_key_fingerprint(der_key), expected)

    def test_legacy_mode_derives_only_configured_identity_active(self) -> None:
        result = preflight_ed25519_lifecycle(
            role="attestation",
            active_issuer_id="issuer",
            active_key_id="k1",
            private_key=self.k1,
            public_key=self.k1.public_key(),
            trust_candidates=self._candidates(("issuer", "k1", self.k1), ("issuer", "k2", self.k2)),
        )
        self.assertEqual(result.mode, "legacy")
        self.assertEqual(result.active_key_id, "k1")
        self.assertEqual([(item.issuer_id, item.key_id) for item in result.effective_trust_keys], [
            ("issuer", "k1"), ("issuer", "k2"),
        ])
        self.assertEqual([(item.issuer_id, item.key_id) for item in result.historical_trusted_identities], [("issuer", "k2")])

    def test_active_k1_signs_and_verifies_through_production_path(self) -> None:
        result = preflight_ed25519_lifecycle(
            role="attestation",
            active_issuer_id="issuer",
            active_key_id="k1",
            private_key=self.k1,
            public_key=self.k1.public_key(),
            trust_candidates=self._candidates(("issuer", "k1", self.k1)),
        )
        payload = b"canonical-attestation-payload"
        signer = Ed25519HostSigner("issuer", "k1", self.k1)
        proof = signer.sign(payload)
        self.assertTrue(self._verifier(result).verify(payload, proof, "issuer", "k1", "ed25519"))

    def test_k2_active_keeps_genuine_k1_artifact_verifiable(self) -> None:
        candidates = self._candidates(("issuer", "k1", self.k1), ("issuer", "k2", self.k2))
        result = preflight_ed25519_lifecycle(
            role="attestation",
            active_issuer_id="issuer",
            active_key_id="k2",
            private_key=self.k2,
            public_key=self.k2.public_key(),
            trust_candidates=candidates,
            manifest=parse_lifecycle_manifest(_manifest("attestation", "issuer", [
                _entry("issuer", "k1", self.k1, "historical"),
                _entry("issuer", "k2", self.k2, "active"),
            ]), role="attestation"),
        )
        payload = b"canonical-attestation-payload"
        k2_signer = Ed25519HostSigner("issuer", "k2", self.k2)
        k1_signer = Ed25519HostSigner("issuer", "k1", self.k1)
        verifier = self._verifier(result)
        self.assertEqual(k2_signer.key_id, "k2")
        self.assertTrue(verifier.verify(payload, k2_signer.sign(payload), "issuer", "k2", "ed25519"))
        self.assertTrue(verifier.verify(payload, k1_signer.sign(payload), "issuer", "k1", "ed25519"))

    def test_retired_and_compromised_genuine_k1_artifacts_are_rejected_without_fallback(self) -> None:
        candidates = self._candidates(("issuer", "k1", self.k1), ("issuer", "k2", self.k2))
        payload = b"canonical-attestation-payload"
        for state in ("retired", "compromised"):
            with self.subTest(state=state):
                result = preflight_ed25519_lifecycle(
                    role="attestation",
                    active_issuer_id="issuer",
                    active_key_id="k2",
                    private_key=self.k2,
                    public_key=self.k2.public_key(),
                    trust_candidates=candidates,
                    manifest=parse_lifecycle_manifest(_manifest("attestation", "issuer", [
                        _entry("issuer", "k1", self.k1, state),
                        _entry("issuer", "k2", self.k2, "active"),
                    ]), role="attestation"),
                )
                verifier = self._verifier(result)
                k1_proof = Ed25519HostSigner("issuer", "k1", self.k1).sign(payload)
                k2_proof = Ed25519HostSigner("issuer", "k2", self.k2).sign(payload)
                self.assertFalse(verifier.verify(payload, k1_proof, "issuer", "k1", "ed25519"))
                self.assertTrue(verifier.verify(payload, k2_proof, "issuer", "k2", "ed25519"))

    def test_rejected_active_k2_does_not_fallback_to_k1(self) -> None:
        with self.assertRaisesRegex(Ed25519LifecycleError, "^lifecycle_active_selector_disagreement$"):
            preflight_ed25519_lifecycle(
                role="attestation",
                active_issuer_id="issuer",
                active_key_id="k2",
                private_key=self.k2,
                public_key=self.k2.public_key(),
                trust_candidates=self._candidates(("issuer", "k1", self.k1), ("issuer", "k2", self.k2)),
                manifest=parse_lifecycle_manifest(_manifest("attestation", "issuer", [
                    _entry("issuer", "k1", self.k1, "active"),
                    _entry("issuer", "k2", self.k2, "retired"),
                ]), role="attestation"),
            )

    def test_managed_rotation_keeps_k1_historical_and_k2_active(self) -> None:
        candidates = self._candidates(("issuer", "k1", self.k1), ("issuer", "k2", self.k2))
        result = preflight_ed25519_lifecycle(
            role="attestation",
            active_issuer_id="issuer",
            active_key_id="k2",
            private_key=self.k2,
            public_key=self.k2.public_key(),
            trust_candidates=candidates,
            manifest=parse_lifecycle_manifest(_manifest("attestation", "issuer", [
                _entry("issuer", "k1", self.k1, "historical"),
                _entry("issuer", "k2", self.k2, "active"),
            ]), role="attestation"),
        )
        self.assertEqual(result.mode, "managed")
        self.assertEqual(result.active_key_id, "k2")
        self.assertEqual([(item.issuer_id, item.key_id) for item in result.historical_trusted_identities], [("issuer", "k1")])
        self.assertEqual({item.key_id for item in result.effective_trust_keys}, {"k1", "k2"})

    def test_retired_and_compromised_candidates_are_excluded(self) -> None:
        result = preflight_ed25519_lifecycle(
            role="authority-binding",
            active_issuer_id="issuer",
            active_key_id="k2",
            private_key=self.k2,
            public_key=self.k2.public_key(),
            trust_candidates=self._candidates(("issuer", "k1", self.k1), ("issuer", "k2", self.k2), ("issuer", "k3", self.k3)),
            manifest=parse_lifecycle_manifest(_manifest("authority-binding", "issuer", [
                _entry("issuer", "k1", self.k1, "retired"),
                _entry("issuer", "k2", self.k2, "active"),
                _entry("issuer", "k3", self.k3, "compromised"),
            ]), role="authority-binding"),
        )
        self.assertEqual([(item.key_id) for item in result.effective_trust_keys], ["k2"])
        self.assertEqual([item.key_id for item in result.excluded_retired_identities], ["k1"])
        self.assertEqual([item.key_id for item in result.excluded_compromised_identities], ["k3"])

    def test_duplicate_json_member_is_rejected(self) -> None:
        duplicate = '{"version":1,"role":"attestation","issuer_id":"issuer","issuer_id":"other","keys":[]}'
        with self.assertRaisesRegex(Ed25519LifecycleError, "^lifecycle_duplicate_json_member$"):
            parse_lifecycle_manifest(duplicate, role="attestation")

    def test_nested_duplicate_json_member_is_rejected(self) -> None:
        fingerprint = public_key_fingerprint(self.k1.public_key())
        duplicate = (
            '{"version":1,"role":"attestation","issuer_id":"issuer","keys":['
            '{"issuer_id":"issuer","key_id":"k1","algorithm":"ed25519",'
            f'"public_key_fingerprint":"{fingerprint}","state":"active",'
            '"state":"historical"}]}'
        )
        with self.assertRaisesRegex(Ed25519LifecycleError, "^lifecycle_duplicate_json_member$"):
            parse_lifecycle_manifest(duplicate, role="attestation")

    def test_malformed_state_types_fail_at_lifecycle_boundary(self) -> None:
        for state in ([], {}, None, 1, True):
            value = _manifest("attestation", "issuer", [_entry("issuer", "k1", self.k1, "active")])
            value["keys"][0]["state"] = state
            with self.subTest(state_type=type(state).__name__), self.assertRaisesRegex(
                Ed25519LifecycleError, "^lifecycle_state_invalid$",
            ):
                parse_lifecycle_manifest(value, role="attestation")

    def test_unknown_fields_states_and_fingerprints_fail_closed(self) -> None:
        cases = (
            ({"version": 1, "role": "attestation", "issuer_id": "issuer", "extra": 1, "keys": []}, "lifecycle_manifest_field_unknown"),
            (_manifest("attestation", "issuer", [_entry("issuer", "k1", self.k1, "unknown")]), "lifecycle_state_unknown"),
            (_manifest("attestation", "issuer", [{**_entry("issuer", "k1", self.k1, "active"), "public_key_fingerprint": "sha256:bad"}]), "lifecycle_fingerprint_invalid"),
        )
        for value, code in cases:
            with self.subTest(code=code), self.assertRaisesRegex(Ed25519LifecycleError, "^" + code + "$"):
                parse_lifecycle_manifest(value, role="attestation")

    def test_multiple_active_unknown_candidate_and_selector_mismatch_fail_closed(self) -> None:
        candidates = self._candidates(("issuer", "k1", self.k1), ("issuer", "k2", self.k2))
        multiple_active = parse_lifecycle_manifest(_manifest("attestation", "issuer", [
            _entry("issuer", "k1", self.k1, "active"), _entry("issuer", "k2", self.k2, "active"),
        ]), role="attestation")
        with self.assertRaisesRegex(Ed25519LifecycleError, "^lifecycle_active_count_invalid$"):
            preflight_ed25519_lifecycle(role="attestation", active_issuer_id="issuer", active_key_id="k1", private_key=self.k1, public_key=self.k1.public_key(), trust_candidates=candidates, manifest=multiple_active)
        unknown = parse_lifecycle_manifest(_manifest("attestation", "issuer", [
            _entry("issuer", "k1", self.k1, "active"), _entry("issuer", "issuer-unknown", self.k3, "historical"),
        ]), role="attestation")
        with self.assertRaisesRegex(Ed25519LifecycleError, "^lifecycle_identity_unknown$"):
            preflight_ed25519_lifecycle(role="attestation", active_issuer_id="issuer", active_key_id="k1", private_key=self.k1, public_key=self.k1.public_key(), trust_candidates=candidates, manifest=unknown)

    def test_missing_historical_candidate_and_fingerprint_mismatch_fail_closed(self) -> None:
        missing = parse_lifecycle_manifest(_manifest("attestation", "issuer", [_entry("issuer", "k1", self.k1, "active"), _entry("issuer", "k2", self.k2, "historical")]), role="attestation")
        with self.assertRaisesRegex(Ed25519LifecycleError, "^lifecycle_identity_unknown$"):
            preflight_ed25519_lifecycle(role="attestation", active_issuer_id="issuer", active_key_id="k1", private_key=self.k1, public_key=self.k1.public_key(), trust_candidates=self._candidates(("issuer", "k1", self.k1)), manifest=missing)
        mismatch_value = _manifest("attestation", "issuer", [_entry("issuer", "k1", self.k1, "active")])
        mismatch_value["keys"][0]["public_key_fingerprint"] = public_key_fingerprint(self.k2.public_key())
        mismatch = parse_lifecycle_manifest(mismatch_value, role="attestation")
        with self.assertRaisesRegex(Ed25519LifecycleError, "^lifecycle_fingerprint_mismatch$"):
            preflight_ed25519_lifecycle(role="attestation", active_issuer_id="issuer", active_key_id="k1", private_key=self.k1, public_key=self.k1.public_key(), trust_candidates=self._candidates(("issuer", "k1", self.k1)), manifest=mismatch)

    def test_managed_and_legacy_role_policies_are_isolated(self) -> None:
        attestation_managed = preflight_ed25519_lifecycle(
            role="attestation",
            active_issuer_id="attestation-issuer",
            active_key_id="k1",
            private_key=self.k1,
            public_key=self.k1.public_key(),
            trust_candidates=self._candidates(("attestation-issuer", "k1", self.k1), ("attestation-issuer", "k2", self.k2)),
            manifest=parse_lifecycle_manifest(_manifest("attestation", "attestation-issuer", [
                _entry("attestation-issuer", "k1", self.k1, "active"),
                _entry("attestation-issuer", "k2", self.k2, "retired"),
            ]), role="attestation"),
        )
        authority_legacy = preflight_ed25519_lifecycle(
            role="authority-binding",
            active_issuer_id="authority-issuer",
            active_key_id="a1",
            private_key=self.k1,
            public_key=self.k1.public_key(),
            trust_candidates=self._candidates(("authority-issuer", "a1", self.k1), ("authority-issuer", "a2", self.k2)),
        )
        self.assertFalse(self._verifier(attestation_managed).verify(b"x", "!" * 86, "attestation-issuer", "k2", "ed25519"))
        self.assertEqual([item.key_id for item in authority_legacy.historical_trusted_identities], ["a2"])

        attestation_legacy = preflight_ed25519_lifecycle(
            role="attestation",
            active_issuer_id="attestation-issuer",
            active_key_id="k1",
            private_key=self.k1,
            public_key=self.k1.public_key(),
            trust_candidates=self._candidates(("attestation-issuer", "k1", self.k1), ("attestation-issuer", "k2", self.k2)),
        )
        authority_managed = preflight_ed25519_lifecycle(
            role="authority-binding",
            active_issuer_id="authority-issuer",
            active_key_id="a1",
            private_key=self.k1,
            public_key=self.k1.public_key(),
            trust_candidates=self._candidates(("authority-issuer", "a1", self.k1), ("authority-issuer", "a2", self.k2)),
            manifest=parse_lifecycle_manifest(_manifest("authority-binding", "authority-issuer", [
                _entry("authority-issuer", "a1", self.k1, "active"),
                _entry("authority-issuer", "a2", self.k2, "retired"),
            ]), role="authority-binding"),
        )
        self.assertEqual([item.key_id for item in attestation_legacy.historical_trusted_identities], ["k2"])
        self.assertEqual([item.key_id for item in authority_managed.excluded_retired_identities], ["a2"])


if __name__ == "__main__":
    unittest.main()
