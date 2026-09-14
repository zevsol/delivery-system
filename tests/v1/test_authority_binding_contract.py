from __future__ import annotations

from base64 import urlsafe_b64encode
from dataclasses import FrozenInstanceError
import hashlib
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from delivery_system.attestation_signing import (
    Ed25519HostSigner,
    Ed25519ProofVerifier,
    TrustedEd25519IssuerKeyRegistry,
    TrustedEd25519Key,
)
from delivery_system.authority_binding import (
    AUTHORITY_BINDING_DOMAIN,
    AuthorityBindingContractError,
    AuthorityBindingRecord,
    Ed25519AuthorityBindingProofVerifier,
    Ed25519AuthorityBindingSigner,
    SignedAuthorityBinding,
    create_signed_authority_binding,
)


PRIVATE_BYTES = bytes(range(32))
ALTERNATE_PRIVATE_BYTES = bytes(range(32, 64))
APPLICATION_ID = "application-" + "a" * 64
BINDING_ID = "binding-" + "b" * 64
ARTIFACT_ID = "artifact-" + "c" * 64
ARTIFACT_DIGEST = "sha256:" + "d" * 64
OPERATION_ONE = "operation-" + "e" * 64
OPERATION_TWO = "operation-" + "f" * 64


def private(value: bytes = PRIVATE_BYTES) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(value)


def record(**changes: object) -> AuthorityBindingRecord:
    values: dict[str, object] = {
        "workspace_identity": "workspace-1",
        "application_id": APPLICATION_ID,
        "credential_binding_id": BINDING_ID,
        "required_capabilities": ("issues:write",),
        "authority_issued_at": "2026-09-11T13:00:00Z",
        "attestation_artifact_id": ARTIFACT_ID,
        "attestation_artifact_digest": ARTIFACT_DIGEST,
        "authorized_operation_identities": (OPERATION_ONE, OPERATION_TWO),
    }
    values.update(changes)
    return AuthorityBindingRecord.create(**values)  # type: ignore[arg-type]


def signer(value: bytes = PRIVATE_BYTES, issuer: str = "authority-issuer", key_id: str = "authority-key") -> Ed25519AuthorityBindingSigner:
    return Ed25519AuthorityBindingSigner(Ed25519HostSigner(issuer, key_id, private(value)))


def verifier(
    value: bytes = PRIVATE_BYTES,
    issuer: str = "authority-issuer",
    key_id: str = "authority-key",
    entries: tuple[TrustedEd25519Key, ...] | None = None,
) -> Ed25519AuthorityBindingProofVerifier:
    registry_entries = entries or (TrustedEd25519Key(issuer, key_id, private(value).public_key()),)
    registry = TrustedEd25519IssuerKeyRegistry(registry_entries)
    return Ed25519AuthorityBindingProofVerifier(Ed25519ProofVerifier(registry))


class AuthorityBindingContractTests(unittest.TestCase):
    def test_exact_payload_projection_and_canonical_bytes(self) -> None:
        value = record(required_capabilities=("issues:write", "issues:read"), authorized_operation_identities=(OPERATION_TWO, OPERATION_ONE))
        self.assertEqual(value.to_dict(), {
            "domain": AUTHORITY_BINDING_DOMAIN,
            "payload_version": 1,
            "workspace_identity": "workspace-1",
            "application_id": APPLICATION_ID,
            "credential_binding_id": BINDING_ID,
            "required_capabilities": ["issues:read", "issues:write"],
            "authority_issued_at": "2026-09-11T13:00:00Z",
            "attestation_artifact_id": ARTIFACT_ID,
            "attestation_artifact_digest": ARTIFACT_DIGEST,
            "authorized_operation_identities": [OPERATION_ONE, OPERATION_TWO],
        })
        self.assertEqual(value.canonical_bytes(), record(required_capabilities=("issues:write", "issues:read"), authorized_operation_identities=(OPERATION_ONE, OPERATION_TWO)).canonical_bytes())

    def test_canonical_bytes_match_independent_fixed_oracle(self) -> None:
        value = record(required_capabilities=("issues:write", "issues:read"), authorized_operation_identities=(OPERATION_TWO, OPERATION_ONE))
        self.assertEqual(value.canonical_bytes(), (
            b'{"application_id":"application-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
            b'"attestation_artifact_digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",'
            b'"attestation_artifact_id":"artifact-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",'
            b'"authority_issued_at":"2026-09-11T13:00:00Z",'
            b'"authorized_operation_identities":["operation-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",'
            b'"operation-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"],'
            b'"credential_binding_id":"binding-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",'
            b'"domain":"delivery-system:authority-binding:v1","payload_version":1,'
            b'"required_capabilities":["issues:read","issues:write"],"workspace_identity":"workspace-1"}'
        ))

    def test_issuance_id_is_payload_hash_and_changes_for_issued_at(self) -> None:
        value = record()
        expected = "authority-issuance-" + hashlib.sha256(value.canonical_bytes()).hexdigest()
        self.assertEqual(value.authority_issuance_id, expected)
        self.assertNotEqual(value.authority_issuance_id, record(authority_issued_at="2026-09-11T13:00:01Z").authority_issuance_id)

    def test_each_authenticated_field_changes_identity(self) -> None:
        fields = {
            "workspace_identity": "workspace-2",
            "application_id": "application-" + "1" * 64,
            "credential_binding_id": "binding-" + "2" * 64,
            "required_capabilities": ("issues:read",),
            "authority_issued_at": "2026-09-11T13:00:01Z",
            "attestation_artifact_id": "artifact-" + "3" * 64,
            "attestation_artifact_digest": "sha256:" + "4" * 64,
            "authorized_operation_identities": (OPERATION_ONE,),
        }
        original = record()
        for field, changed in fields.items():
            with self.subTest(field=field):
                self.assertNotEqual(original.authority_issuance_id, record(**{field: changed}).authority_issuance_id)

    def test_collections_are_sorted_and_duplicate_free(self) -> None:
        value = record(required_capabilities=("issues:write", "issues:read"), authorized_operation_identities=(OPERATION_TWO, OPERATION_ONE))
        self.assertEqual(value.required_capabilities, ("issues:read", "issues:write"))
        self.assertEqual(value.authorized_operation_identities, (OPERATION_ONE, OPERATION_TWO))
        with self.assertRaisesRegex(AuthorityBindingContractError, "^required_capabilities_duplicate$"):
            record(required_capabilities=("issues:write", "issues:write"))
        with self.assertRaisesRegex(AuthorityBindingContractError, "^authorized_operation_identities_duplicate$"):
            record(authorized_operation_identities=(OPERATION_ONE, OPERATION_ONE))

    def test_multiple_operations_are_supported_and_malformed_values_fail_closed(self) -> None:
        self.assertEqual(len(record().authorized_operation_identities), 2)
        for field, value in (
            ("authorized_operation_identities", ("",)),
            ("authorized_operation_identities", ("operation-invalid",)),
            ("required_capabilities", ("",)),
            ("application_id", "application-invalid"),
            ("attestation_artifact_digest", "not-a-digest"),
        ):
            with self.subTest(field=field, value=value):
                with self.assertRaises(AuthorityBindingContractError):
                    record(**{field: value})

    def test_timestamps_normalize_to_utc_deterministically(self) -> None:
        first = record(authority_issued_at="2026-09-11T15:00:00+02:00")
        second = record(authority_issued_at="2026-09-11T13:00:00Z")
        self.assertEqual(first.authority_issued_at, second.authority_issued_at)
        self.assertEqual(first.canonical_bytes(), second.canonical_bytes())

    def test_unicode_scalars_are_supported_and_surrogates_are_rejected(self) -> None:
        self.assertTrue(record(workspace_identity="工作区").canonical_bytes())
        self.assertTrue(record(workspace_identity="workspace-😀").canonical_bytes())
        self.assertEqual(
            record(workspace_identity="café").canonical_bytes(),
            record(workspace_identity="cafe\u0301").canonical_bytes(),
        )
        for malformed in ("\ud800", "\udfff", "\ud800\udfff"):
            with self.subTest(malformed=repr(malformed)):
                with self.assertRaisesRegex(AuthorityBindingContractError, "^workspace_identity_invalid$"):
                    record(workspace_identity=malformed)

    def test_record_and_collections_are_immutable_without_stale_views(self) -> None:
        value = record()
        canonical = value.canonical_bytes()
        issuance_id = value.authority_issuance_id
        signed = create_signed_authority_binding(value, signer())
        with self.assertRaises(FrozenInstanceError):
            value.application_id = APPLICATION_ID  # type: ignore[misc]
        with self.assertRaises((AttributeError, TypeError)):
            value.required_capabilities.append("issues:read")  # type: ignore[attr-defined]
        with self.assertRaises((AttributeError, TypeError)):
            value.authorized_operation_identities[0] = OPERATION_TWO  # type: ignore[index]
        self.assertEqual(value.canonical_bytes(), canonical)
        self.assertEqual(value.authority_issuance_id, issuance_id)
        self.assertTrue(verifier().verify(signed))

    def test_valid_signature_verifies_and_is_over_canonical_payload(self) -> None:
        signed = create_signed_authority_binding(record(), signer())
        self.assertTrue(verifier().verify(signed))
        id_only_proof = signer().sign_authority_binding(signed.payload.authority_issuance_id.encode("utf-8"))
        self.assertFalse(verifier().verify(SignedAuthorityBinding(
            signed.payload, signed.issuer_id, signed.key_id, signed.signature_algorithm, id_only_proof,
        )))

    def test_payload_mutation_and_operation_assignment_mutation_fail(self) -> None:
        signed = create_signed_authority_binding(record(), signer())
        changed = record(application_id="application-" + "1" * 64)
        mutated = SignedAuthorityBinding(changed, signed.issuer_id, signed.key_id, signed.signature_algorithm, signed.proof)
        self.assertFalse(verifier().verify(mutated))
        changed_operations = record(authorized_operation_identities=(OPERATION_ONE,))
        changed_assignment = SignedAuthorityBinding(changed_operations, signed.issuer_id, signed.key_id, signed.signature_algorithm, signed.proof)
        self.assertFalse(verifier().verify(changed_assignment))

    def test_substitutions_and_negative_signature_metadata_fail(self) -> None:
        signed = create_signed_authority_binding(record(), signer())
        cases = (
            SignedAuthorityBinding(record(), "other-issuer", signed.key_id, signed.signature_algorithm, signed.proof),
            SignedAuthorityBinding(record(), signed.issuer_id, "other-key", signed.signature_algorithm, signed.proof),
            SignedAuthorityBinding(record(), signed.issuer_id, signed.key_id, signed.signature_algorithm, signer(ALTERNATE_PRIVATE_BYTES).sign_authority_binding(record().canonical_bytes())),
        )
        for candidate in cases:
            with self.subTest(candidate=candidate.issuer_id, key=candidate.key_id):
                self.assertFalse(verifier().verify(candidate))
        raw = signed.to_dict()
        for field, value in (("signature_algorithm", "rsa-sha256"), ("proof", "!" * 86)):
            raw[field] = value
            self.assertFalse(verifier().verify(raw))
            raw = signed.to_dict()

    def test_trusted_key_policy_rejects_independent_attacker_key(self) -> None:
        trusted = verifier()
        attacker_signed = create_signed_authority_binding(record(), signer(ALTERNATE_PRIVATE_BYTES))
        self.assertFalse(trusted.verify(attacker_signed))

    def test_envelope_metadata_cannot_manufacture_trust(self) -> None:
        trusted = verifier()
        attacker = signer(ALTERNATE_PRIVATE_BYTES, issuer="authority-issuer", key_id="trusted-looking-key")
        signed = create_signed_authority_binding(record(), attacker)
        self.assertFalse(trusted.verify(signed))
        raw = signed.to_dict()
        raw["issuer_id"] = "authority-issuer"
        raw["key_id"] = "authority-key"
        self.assertFalse(trusted.verify(raw))

    def test_wrong_domain_and_version_are_rejected_at_contract_boundary(self) -> None:
        raw = record().to_dict()
        raw["domain"] = "delivery-system:credential-attestation:v1"
        with self.assertRaisesRegex(AuthorityBindingContractError, "^authority_binding_domain_invalid$"):
            AuthorityBindingRecord.from_dict(raw)
        raw = record().to_dict()
        raw["payload_version"] = 2
        with self.assertRaisesRegex(AuthorityBindingContractError, "^authority_binding_version_unsupported$"):
            AuthorityBindingRecord.from_dict(raw)

    def test_credential_attestation_domain_cannot_be_accepted_as_binding(self) -> None:
        signed = create_signed_authority_binding(record(), signer())
        raw = signed.to_dict()
        raw["payload"]["domain"] = "delivery-system:credential-attestation:v1"
        self.assertFalse(verifier().verify(raw))

    def test_recomputed_issuance_id_without_signature_is_not_authentication(self) -> None:
        signed = create_signed_authority_binding(record(), signer())
        changed = record(credential_binding_id="binding-" + "9" * 64)
        recomputed = changed.authority_issuance_id
        forged = SignedAuthorityBinding(changed, signed.issuer_id, signed.key_id, signed.signature_algorithm, signed.proof)
        self.assertNotEqual(recomputed, record().authority_issuance_id)
        self.assertFalse(verifier().verify(forged))

    def test_explicit_adapter_does_not_change_existing_signer_contract(self) -> None:
        host_signer = Ed25519HostSigner("authority-issuer", "authority-key", private())
        adapter = Ed25519AuthorityBindingSigner(host_signer)
        self.assertEqual(adapter.issuer_id, host_signer.issuer_id)
        self.assertEqual(adapter.key_id, host_signer.key_id)
        self.assertNotIn("credential", repr(adapter).lower())
        with self.assertRaisesRegex(AuthorityBindingContractError, "^authority_binding_signing_payload_invalid$"):
            adapter.sign_authority_binding(bytearray(record().canonical_bytes()))  # type: ignore[arg-type]

    def test_envelope_parsing_is_strict_and_verifier_is_offline(self) -> None:
        signed = create_signed_authority_binding(record(), signer())
        parsed = SignedAuthorityBinding.from_dict(signed.to_dict())
        self.assertTrue(verifier().verify(parsed))
        self.assertFalse(verifier().verify({"payload": signed.payload.to_dict()}))

    def test_historical_key_verifies_after_active_key_rotation(self) -> None:
        old_issuer = "authority-issuer"
        old_key = "authority-key-old"
        new_key = "authority-key-new"
        signed_with_old_key = create_signed_authority_binding(
            record(), signer(issuer=old_issuer, key_id=old_key),
        )
        rotation_registry = (
            TrustedEd25519Key(old_issuer, old_key, private().public_key()),
            TrustedEd25519Key(old_issuer, new_key, private(ALTERNATE_PRIVATE_BYTES).public_key()),
        )
        self.assertTrue(verifier(entries=rotation_registry).verify(signed_with_old_key))

    def test_retired_historical_key_fails_closed(self) -> None:
        old_key = "authority-key-old"
        signed_with_old_key = create_signed_authority_binding(
            record(), signer(key_id=old_key),
        )
        trusted_new_key_only = (
            TrustedEd25519Key("authority-issuer", "authority-key-new", private(ALTERNATE_PRIVATE_BYTES).public_key()),
        )
        self.assertFalse(verifier(entries=trusted_new_key_only).verify(signed_with_old_key))

    def test_multiple_trusted_keys_verify_independently(self) -> None:
        first_issuer = "authority-issuer"
        first_key = "authority-key-one"
        second_key = "authority-key-two"
        entries = (
            TrustedEd25519Key(first_issuer, first_key, private().public_key()),
            TrustedEd25519Key(first_issuer, second_key, private(ALTERNATE_PRIVATE_BYTES).public_key()),
        )
        self.assertTrue(verifier(entries=entries).verify(
            create_signed_authority_binding(record(), signer(key_id=first_key)),
        ))
        self.assertTrue(verifier(entries=entries).verify(
            create_signed_authority_binding(record(), signer(ALTERNATE_PRIVATE_BYTES, key_id=second_key)),
        ))

    def test_historical_issuer_rotation_and_retirement(self) -> None:
        old_issuer = "authority-issuer-old"
        new_issuer = "authority-issuer-new"
        old_key = "authority-key-old"
        new_key = "authority-key-new"
        old_signed = create_signed_authority_binding(
            record(), signer(issuer=old_issuer, key_id=old_key),
        )
        new_signed = create_signed_authority_binding(
            record(), signer(ALTERNATE_PRIVATE_BYTES, issuer=new_issuer, key_id=new_key),
        )
        both_trusted = (
            TrustedEd25519Key(old_issuer, old_key, private().public_key()),
            TrustedEd25519Key(new_issuer, new_key, private(ALTERNATE_PRIVATE_BYTES).public_key()),
        )
        self.assertTrue(verifier(entries=both_trusted).verify(old_signed))
        self.assertTrue(verifier(entries=both_trusted).verify(new_signed))
        self.assertFalse(verifier(entries=(both_trusted[1],)).verify(old_signed))

    def test_unknown_key_and_unknown_issuer_fail_closed(self) -> None:
        trusted = verifier()
        unknown_key = create_signed_authority_binding(
            record(), signer(key_id="unknown-key"),
        )
        unknown_issuer = create_signed_authority_binding(
            record(), signer(issuer="unknown-issuer"),
        )
        self.assertFalse(trusted.verify(unknown_key))
        self.assertFalse(trusted.verify(unknown_issuer))


if __name__ == "__main__":
    unittest.main()
