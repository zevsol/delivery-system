"""Authenticated authority-binding contract primitives for I1.

This module deliberately contains no persistence, Runtime wiring, credential
resolution, or restart behavior.  It defines only the canonical business
payload and its authority-binding-specific signing and verification seams.
"""

from __future__ import annotations

from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import re
from typing import Any, Mapping, Protocol
import unicodedata

from delivery_system.attestation_signing import Ed25519HostSigner, Ed25519ProofVerifier
from delivery_system.canonical import canonical_payload


AUTHORITY_BINDING_DOMAIN = "delivery-system:authority-binding:v1"
AUTHORITY_BINDING_PAYLOAD_VERSION = 1
AUTHORITY_BINDING_SIGNATURE_ALGORITHM = "ed25519"

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
_APPLICATION_ID_RE = re.compile(r"^application-[0-9a-f]{64}$")
_BINDING_ID_RE = re.compile(r"^binding-[0-9a-f]{64}$")
_ARTIFACT_ID_RE = re.compile(r"^artifact-[0-9a-f]{64}$")
_OPERATION_ID_RE = re.compile(r"^operation-[0-9a-f]{64}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CAPABILITY_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}:[a-z][a-z0-9-]{0,63}$")
_PROOF_RE = re.compile(r"^[A-Za-z0-9_-]{86}$")


class AuthorityBindingContractError(ValueError):
    """Stable, non-sensitive authority-binding contract failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _error(code: str) -> None:
    raise AuthorityBindingContractError(code)


def _text(value: Any, field: str) -> str:
    if type(value) is not str:
        _error(f"{field}_invalid")
    normalized = unicodedata.normalize("NFC", value).strip()
    if not normalized or any(
        ord(char) < 0x20
        or ord(char) == 0x7F
        or 0xD800 <= ord(char) <= 0xDFFF
        for char in normalized
    ):
        _error(f"{field}_invalid")
    return normalized


def _id(value: Any, field: str) -> str:
    normalized = _text(value, field)
    if _ID_RE.fullmatch(normalized) is None:
        _error(f"{field}_invalid")
    return normalized


def _exact_id(value: Any, field: str, pattern: re.Pattern[str]) -> str:
    normalized = _text(value, field)
    if pattern.fullmatch(normalized) is None:
        _error(f"{field}_invalid")
    return normalized


def _digest(value: Any, field: str) -> str:
    normalized = _text(value, field)
    if _DIGEST_RE.fullmatch(normalized) is None:
        _error(f"{field}_invalid")
    return normalized


def _timestamp(value: Any) -> str:
    normalized = _text(value, "authority_issued_at")
    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except (TypeError, ValueError, OverflowError):
        _error("authority_issued_at_invalid")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _error("authority_issued_at_invalid")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_collection(value: Any, field: str, pattern: re.Pattern[str] | None = None) -> tuple[str, ...]:
    if type(value) not in (list, tuple) or not value:
        _error(f"{field}_invalid")
    normalized = tuple(_text(item, field) for item in value)
    if pattern is not None and any(pattern.fullmatch(item) is None for item in normalized):
        _error(f"{field}_invalid")
    if len(normalized) != len(set(normalized)):
        _error(f"{field}_duplicate")
    return tuple(sorted(normalized))


def _proof(value: Any) -> str:
    if type(value) is not str or len(value) != 86 or _PROOF_RE.fullmatch(value) is None:
        _error("authority_binding_proof_invalid")
    try:
        decoded = urlsafe_b64decode(value + "==")
    except (TypeError, ValueError):
        _error("authority_binding_proof_invalid")
    if len(decoded) != 64 or urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        _error("authority_binding_proof_invalid")
    return value


@dataclass(frozen=True, slots=True)
class AuthorityBindingRecord:
    """Canonical v1 business payload for one authority issuance assignment."""

    domain: str
    payload_version: int
    workspace_identity: str
    application_id: str
    credential_binding_id: str
    required_capabilities: tuple[str, ...] | list[str]
    authority_issued_at: str
    attestation_artifact_id: str
    attestation_artifact_digest: str
    authorized_operation_identities: tuple[str, ...] | list[str]

    def __post_init__(self) -> None:
        if type(self.domain) is not str or self.domain != AUTHORITY_BINDING_DOMAIN:
            _error("authority_binding_domain_invalid")
        if type(self.payload_version) is not int or isinstance(self.payload_version, bool) or self.payload_version != AUTHORITY_BINDING_PAYLOAD_VERSION:
            _error("authority_binding_version_unsupported")
        workspace = _text(self.workspace_identity, "workspace_identity")
        application = _exact_id(self.application_id, "application_id", _APPLICATION_ID_RE)
        binding = _exact_id(self.credential_binding_id, "credential_binding_id", _BINDING_ID_RE)
        required = _canonical_collection(self.required_capabilities, "required_capabilities", _CAPABILITY_RE)
        issued_at = _timestamp(self.authority_issued_at)
        artifact = _exact_id(self.attestation_artifact_id, "attestation_artifact_id", _ARTIFACT_ID_RE)
        artifact_digest = _digest(self.attestation_artifact_digest, "attestation_artifact_digest")
        operations = _canonical_collection(
            self.authorized_operation_identities,
            "authorized_operation_identities",
            _OPERATION_ID_RE,
        )
        for field, value in (
            ("workspace_identity", workspace),
            ("application_id", application),
            ("credential_binding_id", binding),
            ("required_capabilities", required),
            ("authority_issued_at", issued_at),
            ("attestation_artifact_id", artifact),
            ("attestation_artifact_digest", artifact_digest),
            ("authorized_operation_identities", operations),
        ):
            object.__setattr__(self, field, value)

    @classmethod
    def create(
        cls,
        *,
        workspace_identity: str,
        application_id: str,
        credential_binding_id: str,
        required_capabilities: tuple[str, ...] | list[str],
        authority_issued_at: str,
        attestation_artifact_id: str,
        attestation_artifact_digest: str,
        authorized_operation_identities: tuple[str, ...] | list[str],
    ) -> "AuthorityBindingRecord":
        return cls(
            AUTHORITY_BINDING_DOMAIN,
            AUTHORITY_BINDING_PAYLOAD_VERSION,
            workspace_identity,
            application_id,
            credential_binding_id,
            required_capabilities,
            authority_issued_at,
            attestation_artifact_id,
            attestation_artifact_digest,
            authorized_operation_identities,
        )

    @classmethod
    def from_dict(cls, value: Any) -> "AuthorityBindingRecord":
        expected = {
            "domain", "payload_version", "workspace_identity", "application_id",
            "credential_binding_id", "required_capabilities", "authority_issued_at",
            "attestation_artifact_id", "attestation_artifact_digest",
            "authorized_operation_identities",
        }
        if type(value) is not dict or set(value) != expected:
            _error("authority_binding_payload_invalid")
        try:
            return cls(**value)
        except AuthorityBindingContractError:
            raise
        except (TypeError, ValueError):
            _error("authority_binding_payload_invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "payload_version": self.payload_version,
            "workspace_identity": self.workspace_identity,
            "application_id": self.application_id,
            "credential_binding_id": self.credential_binding_id,
            "required_capabilities": list(self.required_capabilities),
            "authority_issued_at": self.authority_issued_at,
            "attestation_artifact_id": self.attestation_artifact_id,
            "attestation_artifact_digest": self.attestation_artifact_digest,
            "authorized_operation_identities": list(self.authorized_operation_identities),
        }

    def canonical_bytes(self) -> bytes:
        return canonical_payload(self.to_dict()).encode("utf-8")

    @property
    def authority_issuance_id(self) -> str:
        return "authority-issuance-" + hashlib.sha256(self.canonical_bytes()).hexdigest()


class AuthorityBindingSigner(Protocol):
    """Distinct logical signer role for authority-binding payloads."""

    issuer_id: str
    key_id: str
    signature_algorithm: str

    def sign_authority_binding(self, canonical_payload_bytes: bytes) -> str: ...


class AuthorityBindingProofVerifier(Protocol):
    """Distinct offline verifier role for authority-binding envelopes."""

    def verify(self, value: "SignedAuthorityBinding" | Mapping[str, Any]) -> bool: ...


@dataclass(frozen=True, slots=True)
class SignedAuthorityBinding:
    """Detached authority-binding proof envelope."""

    payload: AuthorityBindingRecord
    issuer_id: str
    key_id: str
    signature_algorithm: str
    proof: str

    def __post_init__(self) -> None:
        if type(self.payload) is not AuthorityBindingRecord:
            _error("authority_binding_payload_invalid")
        issuer = _id(self.issuer_id, "issuer_id")
        key = _id(self.key_id, "key_id")
        if self.signature_algorithm != AUTHORITY_BINDING_SIGNATURE_ALGORITHM:
            _error("authority_binding_algorithm_unsupported")
        proof = _proof(self.proof)
        object.__setattr__(self, "issuer_id", issuer)
        object.__setattr__(self, "key_id", key)
        object.__setattr__(self, "proof", proof)

    @classmethod
    def from_dict(cls, value: Any) -> "SignedAuthorityBinding":
        expected = {"payload", "issuer_id", "key_id", "signature_algorithm", "proof"}
        if type(value) is not dict or set(value) != expected:
            _error("authority_binding_envelope_invalid")
        try:
            payload = AuthorityBindingRecord.from_dict(value["payload"])
            return cls(payload, value["issuer_id"], value["key_id"], value["signature_algorithm"], value["proof"])
        except AuthorityBindingContractError:
            raise
        except (TypeError, ValueError):
            _error("authority_binding_envelope_invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload": self.payload.to_dict(),
            "issuer_id": self.issuer_id,
            "key_id": self.key_id,
            "signature_algorithm": self.signature_algorithm,
            "proof": self.proof,
        }


def create_signed_authority_binding(
    payload: AuthorityBindingRecord,
    signer: AuthorityBindingSigner,
) -> SignedAuthorityBinding:
    if type(payload) is not AuthorityBindingRecord:
        _error("authority_binding_payload_invalid")
    try:
        issuer_id = _id(signer.issuer_id, "issuer_id")
        key_id = _id(signer.key_id, "key_id")
        algorithm = signer.signature_algorithm
        if algorithm != AUTHORITY_BINDING_SIGNATURE_ALGORITHM:
            _error("authority_binding_algorithm_unsupported")
        sign = signer.sign_authority_binding
    except AuthorityBindingContractError:
        raise
    except (AttributeError, TypeError):
        _error("authority_binding_signer_invalid")
    proof = sign(payload.canonical_bytes())
    return SignedAuthorityBinding(payload, issuer_id, key_id, algorithm, proof)


class Ed25519AuthorityBindingSigner:
    """Explicit authority-binding adapter over the existing Ed25519 primitive.

    Constructing this adapter is the explicit logical authorization boundary;
    an ``Ed25519HostSigner`` is not automatically an authority-binding signer.
    """

    __slots__ = ("__delegate",)

    def __init__(self, delegate: Ed25519HostSigner) -> None:
        if type(delegate) is not Ed25519HostSigner:
            _error("authority_binding_signer_invalid")
        object.__setattr__(self, "_Ed25519AuthorityBindingSigner__delegate", delegate)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AuthorityBindingContractError("authority_binding_signer_immutable")

    @property
    def issuer_id(self) -> str:
        return self.__delegate.issuer_id

    @property
    def key_id(self) -> str:
        return self.__delegate.key_id

    @property
    def signature_algorithm(self) -> str:
        return self.__delegate.signature_algorithm

    def sign_authority_binding(self, canonical_payload_bytes: bytes) -> str:
        if type(canonical_payload_bytes) is not bytes:
            _error("authority_binding_signing_payload_invalid")
        return self.__delegate.sign(canonical_payload_bytes)

    def __repr__(self) -> str:
        return "<Ed25519AuthorityBindingSigner protected>"


class Ed25519AuthorityBindingProofVerifier:
    """Authority-binding-specific policy wrapper over Ed25519 verification."""

    __slots__ = ("__delegate",)

    def __init__(self, delegate: Ed25519ProofVerifier) -> None:
        if type(delegate) is not Ed25519ProofVerifier:
            _error("authority_binding_verifier_invalid")
        object.__setattr__(self, "_Ed25519AuthorityBindingProofVerifier__delegate", delegate)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AuthorityBindingContractError("authority_binding_verifier_immutable")

    def verify(self, value: SignedAuthorityBinding | Mapping[str, Any]) -> bool:
        try:
            envelope = value if type(value) is SignedAuthorityBinding else SignedAuthorityBinding.from_dict(value)
            if envelope.signature_algorithm != AUTHORITY_BINDING_SIGNATURE_ALGORITHM:
                return False
            return self.__delegate.verify(
                envelope.payload.canonical_bytes(), envelope.proof,
                envelope.issuer_id, envelope.key_id, envelope.signature_algorithm,
            )
        except Exception:
            return False

    def __repr__(self) -> str:
        return "<Ed25519AuthorityBindingProofVerifier protected>"


__all__ = [
    "AUTHORITY_BINDING_DOMAIN",
    "AUTHORITY_BINDING_PAYLOAD_VERSION",
    "AUTHORITY_BINDING_SIGNATURE_ALGORITHM",
    "AuthorityBindingContractError",
    "AuthorityBindingRecord",
    "AuthorityBindingSigner",
    "AuthorityBindingProofVerifier",
    "SignedAuthorityBinding",
    "create_signed_authority_binding",
    "Ed25519AuthorityBindingSigner",
    "Ed25519AuthorityBindingProofVerifier",
]
