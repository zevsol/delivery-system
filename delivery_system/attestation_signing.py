"""Host-local Ed25519 signing and static trust configuration.

The module accepts already-constructed cryptography key objects.  It does not
load, generate, serialize, persist, or otherwise provision key material.
"""

from __future__ import annotations

from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from delivery_system.attestation import IssuerTrustDecision


_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
_PROOF_RE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_ALGORITHM = "ed25519"
_PROOF_BYTES = 64
_PROOF_TEXT = 86


class AttestationSigningConfigurationError(ValueError):
    """Raised for invalid Host signing or trust configuration."""


class AttestationSigningError(ValueError):
    """Raised when an injected signing capability fails."""


class AttestationVerificationError(ValueError):
    """Raised when a trusted verification capability fails unexpectedly."""


def _safe_id(value: object, field: str) -> str:
    if type(value) is not str or _ID_RE.fullmatch(value) is None:
        raise AttestationSigningConfigurationError(f"{field}_invalid")
    return value


def _safe_allowlist(values: Iterable[str], field: str) -> tuple[str, ...]:
    if type(values) not in (tuple, list):
        raise AttestationSigningConfigurationError(f"{field}_invalid")
    result: list[str] = []
    for value in values:
        if type(value) is not str or not value or value in result:
            raise AttestationSigningConfigurationError(f"{field}_invalid")
        result.append(value)
    if not result:
        raise AttestationSigningConfigurationError(f"{field}_invalid")
    return tuple(result)


class Ed25519HostSigner:
    """Host-owned Ed25519 signer backed by an already-constructed key."""

    __slots__ = ("__issuer_id", "__key_id", "__private_key")

    def __init__(self, issuer_id: str, key_id: str, private_key: Ed25519PrivateKey) -> None:
        object.__setattr__(self, "_Ed25519HostSigner__issuer_id", _safe_id(issuer_id, "issuer_id"))
        object.__setattr__(self, "_Ed25519HostSigner__key_id", _safe_id(key_id, "key_id"))
        if not isinstance(private_key, Ed25519PrivateKey):
            raise AttestationSigningConfigurationError("private_key_invalid")
        object.__setattr__(self, "_Ed25519HostSigner__private_key", private_key)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttestationSigningConfigurationError("signer_configuration_sealed")

    def __copy__(self):
        raise AttestationSigningConfigurationError("signer_copy_forbidden")

    def __deepcopy__(self, memo):
        raise AttestationSigningConfigurationError("signer_copy_forbidden")

    def __reduce_ex__(self, protocol):
        raise AttestationSigningConfigurationError("signer_serialization_forbidden")

    @property
    def issuer_id(self) -> str:
        return self.__issuer_id

    @property
    def key_id(self) -> str:
        return self.__key_id

    @property
    def signature_algorithm(self) -> str:
        return _ALGORITHM

    def __repr__(self) -> str:
        return "<Ed25519HostSigner protected>"

    def sign(self, canonical_claims_payload: bytes) -> str:
        if type(canonical_claims_payload) is not bytes:
            raise AttestationSigningError("signing_payload_invalid")
        try:
            signature = self.__private_key.sign(canonical_claims_payload)
        except Exception:
            raise AttestationSigningError("attestation_signing_failed") from None
        if type(signature) is not bytes or len(signature) != _PROOF_BYTES:
            raise AttestationSigningError("attestation_signing_failed")
        proof = urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        if type(proof) is not str or len(proof) != _PROOF_TEXT or _PROOF_RE.fullmatch(proof) is None:
            raise AttestationSigningError("attestation_signing_failed")
        return proof


@dataclass(frozen=True)
class TrustedEd25519Key:
    """Immutable public verification material for one issuer/key identity."""

    issuer_id: str
    key_id: str
    public_key: Ed25519PublicKey

    def __post_init__(self) -> None:
        _safe_id(self.issuer_id, "issuer_id")
        _safe_id(self.key_id, "key_id")
        if not isinstance(self.public_key, Ed25519PublicKey):
            raise AttestationSigningConfigurationError("public_key_invalid")

    @property
    def signature_algorithm(self) -> str:
        return _ALGORITHM

    def __repr__(self) -> str:
        return "<TrustedEd25519Key public-key-configured>"


class TrustedEd25519IssuerKeyRegistry:
    """Immutable exact-tuple issuer/key trust policy."""

    __slots__ = ("__entries", "__lookup", "__versions", "__classes")

    def __init__(
        self,
        entries: tuple[TrustedEd25519Key, ...] | list[TrustedEd25519Key],
        *,
        allowed_attestation_versions: tuple[str, ...] | list[str] = ("2",),
        allowed_credential_classes: tuple[str, ...] | list[str] = ("github-app-installation-token",),
    ) -> None:
        if type(entries) not in (tuple, list) or not entries:
            raise AttestationSigningConfigurationError("trusted_keys_invalid")
        normalized_entries: list[TrustedEd25519Key] = []
        identities: set[tuple[str, str, str]] = set()
        for entry in entries:
            if type(entry) is not TrustedEd25519Key:
                raise AttestationSigningConfigurationError("trusted_keys_invalid")
            identity = (entry.issuer_id, entry.key_id, _ALGORITHM)
            if identity in identities:
                raise AttestationSigningConfigurationError("trusted_key_duplicate")
            identities.add(identity)
            normalized_entries.append(entry)
        versions = _safe_allowlist(allowed_attestation_versions, "attestation_versions")
        classes = _safe_allowlist(allowed_credential_classes, "credential_classes")
        object.__setattr__(self, "_TrustedEd25519IssuerKeyRegistry__entries", tuple(normalized_entries))
        object.__setattr__(self, "_TrustedEd25519IssuerKeyRegistry__lookup", MappingProxyType({
            (entry.issuer_id, entry.key_id, _ALGORITHM): entry.public_key
            for entry in normalized_entries
        }))
        object.__setattr__(self, "_TrustedEd25519IssuerKeyRegistry__versions", versions)
        object.__setattr__(self, "_TrustedEd25519IssuerKeyRegistry__classes", classes)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttestationSigningConfigurationError("registry_configuration_sealed")

    def __copy__(self):
        raise AttestationSigningConfigurationError("registry_copy_forbidden")

    def __deepcopy__(self, memo):
        raise AttestationSigningConfigurationError("registry_copy_forbidden")

    def __reduce_ex__(self, protocol):
        raise AttestationSigningConfigurationError("registry_serialization_forbidden")

    def __repr__(self) -> str:
        return "<TrustedEd25519IssuerKeyRegistry protected>"

    def resolve(self, issuer_id: str, key_id: str, signature_algorithm: str) -> Ed25519PublicKey | None:
        if type(issuer_id) is not str or type(key_id) is not str or type(signature_algorithm) is not str:
            return None
        if signature_algorithm != _ALGORITHM:
            return None
        return self.__lookup.get((issuer_id, key_id, _ALGORITHM))

    def evaluate(
        self,
        issuer_id: str,
        key_id: str,
        signature_algorithm: str,
        attestation_version: str,
        credential_class: str,
    ) -> IssuerTrustDecision:
        if type(signature_algorithm) is not str or signature_algorithm != _ALGORITHM:
            return IssuerTrustDecision(False, "attestation_algorithm_unsupported")
        if type(issuer_id) is not str or type(key_id) is not str:
            return IssuerTrustDecision(False, "attestation_issuer_untrusted")
        if self.resolve(issuer_id, key_id, signature_algorithm) is None:
            return IssuerTrustDecision(False, "attestation_issuer_untrusted")
        if type(attestation_version) is not str or attestation_version not in self.__versions:
            return IssuerTrustDecision(False, "attestation_version_unsupported")
        if type(credential_class) is not str or credential_class not in self.__classes:
            return IssuerTrustDecision(False, "attestation_credential_class_unsupported")
        return IssuerTrustDecision(True)


def _decode_proof(proof: str) -> bytes | None:
    if type(proof) is not str or len(proof) != _PROOF_TEXT or "=" in proof:
        return None
    if _PROOF_RE.fullmatch(proof) is None:
        return None
    try:
        proof.encode("ascii")
        decoded = urlsafe_b64decode(proof + "==")
    except Exception:
        return None
    if type(decoded) is not bytes or len(decoded) != _PROOF_BYTES:
        return None
    if urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != proof:
        return None
    return decoded


class Ed25519ProofVerifier:
    """Concrete verifier resolving one exact trusted issuer/key tuple."""

    __slots__ = ("__registry",)

    def __init__(self, registry: TrustedEd25519IssuerKeyRegistry) -> None:
        if type(registry) is not TrustedEd25519IssuerKeyRegistry:
            raise AttestationSigningConfigurationError("trusted_registry_invalid")
        object.__setattr__(self, "_Ed25519ProofVerifier__registry", registry)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttestationSigningConfigurationError("verifier_configuration_sealed")

    def __copy__(self):
        raise AttestationSigningConfigurationError("verifier_copy_forbidden")

    def __deepcopy__(self, memo):
        raise AttestationSigningConfigurationError("verifier_copy_forbidden")

    def __reduce_ex__(self, protocol):
        raise AttestationSigningConfigurationError("verifier_serialization_forbidden")

    def __repr__(self) -> str:
        return "<Ed25519ProofVerifier protected>"

    def verify(
        self,
        payload: bytes,
        proof: str,
        issuer_id: str,
        key_id: str,
        signature_algorithm: str,
    ) -> bool:
        if any(type(value) is not str for value in (proof, issuer_id, key_id, signature_algorithm)):
            return False
        if type(payload) is not bytes or signature_algorithm != _ALGORITHM:
            return False
        signature = _decode_proof(proof)
        if signature is None:
            return False
        try:
            public_key = self.__registry.resolve(issuer_id, key_id, signature_algorithm)
        except Exception:
            raise AttestationVerificationError("attestation_verifier_failed") from None
        if public_key is None:
            return False
        try:
            public_key.verify(signature, payload)
        except InvalidSignature:
            return False
        except Exception:
            raise AttestationVerificationError("attestation_verifier_failed") from None
        return True
