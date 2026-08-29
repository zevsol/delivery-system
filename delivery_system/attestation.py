"""Offline-only credential capability attestation contract.

This module defines the Runtime boundary around an issuer-backed proof.  It
does not implement cryptography, credential handling, revocation storage,
network access, WriteEligible, Approval, or execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import hashlib
import re
import secrets
import time
import threading
from typing import Any, Callable, Mapping, Protocol, Sequence
import unicodedata
import weakref
from types import MappingProxyType

from delivery_system.protocol import canonical_payload, digest


ATTESTATION_DOMAIN = "delivery-system:credential-capability-attestation:v1"
ATTESTATION_V2_DOMAIN = "delivery-system:credential-capability-attestation:v2"
ATTESTATION_VERSION_V1 = "1"
ATTESTATION_VERSION_V2 = "2"
CHALLENGE_DOMAIN = "delivery-system:runtime-attestation-challenge:v1"
SUPPORTED_SIGNATURE_ALGORITHMS = frozenset({"ed25519"})
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
_CAPABILITY_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}:[a-z][a-z0-9-]{0,63}$")
_PROOF_RE = re.compile(r"^[A-Za-z0-9_-]+$")
REVOCATION_CONTRACT_VERSION = "1"
ED25519_PROOF_SIZE = 64
ED25519_PROOF_TEXT_LENGTH = 86
_V1_CLAIMS_FIELDS = (
    "attestation_version", "attestation_id", "issuer_id", "key_id", "signature_algorithm",
    "credential_class", "credential_instance_id", "github_subject_identity", "repository_identity",
    "granted_capabilities", "driver_identity", "remote_authority", "preview_id", "revision",
    "operation_set_digest", "remote_snapshot_digest", "evidence_digest", "issued_at", "expires_at",
    "nonce", "source_verification_digest",
)
_V2_CLAIMS_FIELDS = _V1_CLAIMS_FIELDS + ("challenge_digest", "credential_principal_identity")
_CLAIMS_FIELDS = _V1_CLAIMS_FIELDS
_CLAIMS_KEYSET = frozenset(_CLAIMS_FIELDS)
_V2_CLAIMS_KEYSET = frozenset(_V2_CLAIMS_FIELDS)

class AttestationContractError(ValueError):
    """Safe, stable contract error used for local construction failures."""


@dataclass(frozen=True)
class AttestationFailure:
    code: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "detail": self.detail}


@dataclass(frozen=True)
class RevocationStatus:
    """Read-only status returned by an injected revocation reader."""

    attestation_revoked: bool = False
    credential_instance_revoked: bool = False
    revoked_at: str | None = None
    reason: str | None = None
    version: str = "1"

    def __post_init__(self) -> None:
        if not isinstance(self.attestation_revoked, bool) or not isinstance(self.credential_instance_revoked, bool):
            raise AttestationContractError("revocation_status_invalid")
        if not isinstance(self.version, str) or not self.version:
            raise AttestationContractError("revocation_status_invalid")
        if self.revoked_at is not None:
            normalized, _ = _utc_timestamp(self.revoked_at)
            object.__setattr__(self, "revoked_at", normalized)
        if self.attestation_revoked or self.credential_instance_revoked:
            if self.revoked_at is None or self.reason is None:
                raise AttestationContractError("revocation_status_invalid")
            object.__setattr__(self, "reason", _safe_id(self.reason, "revocation_reason"))
        elif self.revoked_at is not None or self.reason is not None:
            raise AttestationContractError("revocation_status_invalid")

    def validate(self, current_time: datetime) -> None:
        if self.version != REVOCATION_CONTRACT_VERSION:
            raise AttestationContractError("attestation_revocation_version_unsupported")
        if self.revoked_at is not None:
            _, revoked_at = _utc_timestamp(self.revoked_at)
            if revoked_at > current_time:
                raise AttestationContractError("attestation_revocation_invalid")


class CredentialCapabilityProofVerifier(Protocol):
    """Runtime-injected verifier; implementations live outside this module."""

    def verify(
        self,
        payload: bytes,
        proof: str,
        issuer_id: str,
        key_id: str,
        signature_algorithm: str,
    ) -> bool: ...


class TrustedIssuerPolicy(Protocol):
    """Runtime-injected issuer/key/version/class trust policy."""

    def evaluate(
        self,
        issuer_id: str,
        key_id: str,
        signature_algorithm: str,
        attestation_version: str,
        credential_class: str,
    ) -> "IssuerTrustDecision": ...


@dataclass(frozen=True)
class IssuerTrustDecision:
    accepted: bool
    failure_code: str = "attestation_issuer_untrusted"

    def __post_init__(self) -> None:
        if not isinstance(self.accepted, bool):
            raise AttestationContractError("attestation_issuer_untrusted")
        allowed = {
            "attestation_issuer_untrusted",
            "attestation_credential_class_unsupported",
            "attestation_version_unsupported",
            "attestation_algorithm_unsupported",
        }
        if self.failure_code not in allowed:
            raise AttestationContractError("attestation_issuer_untrusted")


class RevocationReader(Protocol):
    """Read-only Runtime revocation query; no persistence is implemented here."""

    def read_status(
        self,
        attestation_id: str,
        credential_instance_id: str,
        issuer_id: str,
        key_id: str,
        version: str,
    ) -> RevocationStatus: ...


class CredentialCapabilityProvider(Protocol):
    """Host boundary: return an untrusted signed envelope, never a secret."""

    def attest(
        self,
        request: "CredentialCapabilityRequest",
    ) -> "SignedCredentialCapabilityAttestation": ...


class CredentialCapabilityPolicy(Protocol):
    """Runtime-injected closed capability vocabulary policy."""

    def is_supported(self, capability: str) -> bool: ...


def _safe_text(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise AttestationContractError(f"{field}_invalid")
    normalized = unicodedata.normalize("NFC", value).strip()
    if not normalized or any(ord(char) < 0x20 or ord(char) == 0x7F for char in normalized):
        raise AttestationContractError(f"{field}_invalid")
    return normalized


def _safe_id(value: Any, field: str) -> str:
    normalized = _safe_text(value, field)
    if not _ID_RE.fullmatch(normalized):
        raise AttestationContractError(f"{field}_invalid")
    return normalized


def _digest(value: Any, field: str) -> str:
    normalized = _safe_text(value, field)
    if not _DIGEST_RE.fullmatch(normalized):
        raise AttestationContractError(f"{field}_invalid")
    return normalized


def _utc_timestamp(value: Any) -> tuple[str, datetime]:
    normalized = _safe_text(value, "timestamp")
    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise AttestationContractError("timestamp_invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise AttestationContractError("timestamp_invalid")
    utc = parsed.astimezone(timezone.utc)
    return utc.isoformat().replace("+00:00", "Z"), utc


def _current_time(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timezone.utc.utcoffset(value):
        raise AttestationContractError("current_time_invalid")
    return value.astimezone(timezone.utc)


def _capabilities(values: Any, field: str) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise AttestationContractError(f"{field}_invalid")
    normalized = tuple(_safe_text(value, field) for value in values)
    if len(set(normalized)) != len(normalized):
        raise AttestationContractError(f"{field}_duplicate")
    if any(not _CAPABILITY_RE.fullmatch(value) for value in normalized):
        raise AttestationContractError(f"{field}_invalid")
    return tuple(sorted(normalized))


def _proof(value: Any, signature_algorithm: str) -> str:
    if signature_algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
        raise AttestationContractError("attestation_algorithm_unsupported")
    if not isinstance(value, str) or len(value) != ED25519_PROOF_TEXT_LENGTH:
        raise AttestationContractError("proof_invalid")
    if not _PROOF_RE.fullmatch(value):
        raise AttestationContractError("proof_invalid")
    try:
        if "=" in value or any(ord(char) > 0x7F for char in value):
            raise ValueError
        decoded = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except (ValueError, TypeError):
        raise AttestationContractError("proof_invalid")
    if len(decoded) != ED25519_PROOF_SIZE:
        raise AttestationContractError("proof_invalid")
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if canonical != value:
        raise AttestationContractError("proof_invalid")
    return value


def _mapping(value: Any, field: str, keys: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys or any(not isinstance(key, str) for key in value):
        raise AttestationContractError(f"{field}_invalid")
    return value


def _claims_projection(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        if "attestation_version" not in value:
            raise AttestationContractError("attestation_invalid")
        version = value["attestation_version"]
        fields = _V2_CLAIMS_FIELDS if version == ATTESTATION_VERSION_V2 else _V1_CLAIMS_FIELDS
        mapping = _mapping(value, "claims", set(fields))
        return {field: mapping[field] for field in fields}
    if not isinstance(value, CredentialCapabilityAttestationClaims):
        raise AttestationContractError("attestation_invalid")
    try:
        fields = _V2_CLAIMS_FIELDS if value.attestation_version == ATTESTATION_VERSION_V2 else _V1_CLAIMS_FIELDS
        return {field: getattr(value, field) for field in fields}
    except Exception as exc:
        raise AttestationContractError("attestation_invalid") from exc


def _parse_untrusted_signed_attestation(value: Any) -> "SignedCredentialCapabilityAttestation":
    if isinstance(value, Mapping):
        mapping = _mapping(value, "attestation", {"claims", "proof"})
        raw_claims = mapping["claims"]
        raw_proof = mapping["proof"]
    elif isinstance(value, SignedCredentialCapabilityAttestation):
        try:
            raw_claims = getattr(value, "claims")
            raw_proof = getattr(value, "proof")
        except Exception as exc:
            raise AttestationContractError("attestation_invalid") from exc
    else:
        raise AttestationContractError("attestation_invalid")
    claims = CredentialCapabilityAttestationClaims(**dict(_claims_projection(raw_claims)))
    return SignedCredentialCapabilityAttestation(claims, raw_proof)


def _revalidate_issuer_decision(value: Any) -> IssuerTrustDecision:
    if not isinstance(value, IssuerTrustDecision):
        raise AttestationContractError("attestation_verifier_unavailable")
    try:
        return IssuerTrustDecision(getattr(value, "accepted"), getattr(value, "failure_code"))
    except Exception as exc:
        raise AttestationContractError("attestation_verifier_unavailable") from exc


def _revalidate_revocation_status(value: Any, current_time: datetime) -> RevocationStatus:
    if not isinstance(value, RevocationStatus):
        raise AttestationContractError("attestation_revocation_invalid")
    try:
        status = RevocationStatus(
            attestation_revoked=getattr(value, "attestation_revoked"),
            credential_instance_revoked=getattr(value, "credential_instance_revoked"),
            revoked_at=getattr(value, "revoked_at"),
            reason=getattr(value, "reason"),
            version=getattr(value, "version"),
        )
    except AttestationContractError as exc:
        raise AttestationContractError("attestation_revocation_invalid") from exc
    except Exception as exc:
        raise AttestationContractError("attestation_revocation_invalid") from exc
    status.validate(current_time)
    return status


class CredentialCapabilityRequest:
    __slots__ = (
        "repository_identity", "github_subject_identity", "required_capabilities", "driver_identity",
        "remote_authority", "preview_id", "revision", "operation_set_digest", "remote_snapshot_digest",
        "evidence_digest", "challenge_digest", "__challenge_value", "__boundary_provenance", "__weakref__",
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise AttestationContractError("runtime_request_required")

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttestationContractError("runtime_request_immutable")

    @staticmethod
    def _normalized_values(values: Mapping[str, Any]) -> dict[str, Any]:
        normalized: dict[str, Any] = {
            "repository_identity": _safe_text(values["repository_identity"], "repository_identity"),
            "github_subject_identity": _safe_text(values["github_subject_identity"], "github_subject_identity"),
            "required_capabilities": _capabilities(values["required_capabilities"], "required_capabilities"),
            "driver_identity": _safe_text(values["driver_identity"], "driver_identity"),
            "remote_authority": _digest(values["remote_authority"], "remote_authority"),
            "preview_id": _safe_id(values["preview_id"], "preview_id"),
        }
        if not normalized["required_capabilities"]:
            raise AttestationContractError("required_capabilities_missing")
        revision = values["revision"]
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise AttestationContractError("revision_invalid")
        normalized["revision"] = revision
        for field in ("operation_set_digest", "remote_snapshot_digest", "evidence_digest"):
            normalized[field] = _digest(values[field], field)
        return normalized

    def _belongs_to(self, provenance: object) -> bool:
        return self.__boundary_provenance is provenance

    @property
    def challenge_value(self) -> str:
        return object.__getattribute__(self, "_CredentialCapabilityRequest__challenge_value")


@dataclass(frozen=True)
class CredentialCapabilityAttestationClaims:
    attestation_version: str
    attestation_id: str
    issuer_id: str
    key_id: str
    signature_algorithm: str
    credential_class: str
    credential_instance_id: str
    github_subject_identity: str
    repository_identity: str
    granted_capabilities: tuple[str, ...]
    driver_identity: str
    remote_authority: str
    preview_id: str
    revision: int
    operation_set_digest: str
    remote_snapshot_digest: str
    evidence_digest: str
    issued_at: str
    expires_at: str
    nonce: str
    source_verification_digest: str
    challenge_digest: str = ""
    credential_principal_identity: str = ""

    def __post_init__(self) -> None:
        for field in ("attestation_version", "issuer_id", "key_id", "signature_algorithm", "credential_class", "credential_instance_id", "preview_id", "nonce"):
            object.__setattr__(self, field, _safe_id(getattr(self, field), field))
        for field in ("github_subject_identity", "repository_identity", "driver_identity"):
            object.__setattr__(self, field, _safe_text(getattr(self, field), field))
        if self.attestation_id != "":
            object.__setattr__(self, "attestation_id", _safe_id(self.attestation_id, "attestation_id"))
        if not isinstance(self.revision, int) or isinstance(self.revision, bool) or self.revision < 1:
            raise AttestationContractError("revision_invalid")
        capabilities = _capabilities(self.granted_capabilities, "granted_capabilities")
        object.__setattr__(self, "granted_capabilities", capabilities)
        issued, issued_dt = _utc_timestamp(self.issued_at)
        expires, expires_dt = _utc_timestamp(self.expires_at)
        if expires_dt <= issued_dt:
            raise AttestationContractError("attestation_expiry_invalid")
        object.__setattr__(self, "issued_at", issued)
        object.__setattr__(self, "expires_at", expires)
        for field in ("remote_authority", "operation_set_digest", "remote_snapshot_digest", "evidence_digest", "source_verification_digest"):
            object.__setattr__(self, field, _digest(getattr(self, field), field))
        if self.attestation_version == ATTESTATION_VERSION_V2:
            object.__setattr__(self, "challenge_digest", _digest(self.challenge_digest, "challenge_digest"))
            object.__setattr__(self, "credential_principal_identity", _safe_text(self.credential_principal_identity, "credential_principal_identity"))
        elif self.attestation_version != ATTESTATION_VERSION_V1:
            raise AttestationContractError("attestation_version_unsupported")
        elif self.challenge_digest or self.credential_principal_identity:
            raise AttestationContractError("attestation_v1_extension_forbidden")
        expected_id = self.derived_attestation_id()
        if self.attestation_id == "":
            object.__setattr__(self, "attestation_id", expected_id)
        elif self.attestation_id != expected_id:
            raise AttestationContractError("attestation_id_mismatch")

    def _identity_payload(self) -> dict[str, Any]:
        payload = {
            "attestation_version": self.attestation_version,
            "issuer_id": self.issuer_id,
            "key_id": self.key_id,
            "signature_algorithm": self.signature_algorithm,
            "credential_class": self.credential_class,
            "credential_instance_id": self.credential_instance_id,
            "github_subject_identity": self.github_subject_identity,
            "repository_identity": self.repository_identity,
            "granted_capabilities": list(self.granted_capabilities),
            "driver_identity": self.driver_identity,
            "remote_authority": self.remote_authority,
            "preview_id": self.preview_id,
            "revision": self.revision,
            "operation_set_digest": self.operation_set_digest,
            "remote_snapshot_digest": self.remote_snapshot_digest,
            "evidence_digest": self.evidence_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "source_verification_digest": self.source_verification_digest,
        }
        if self.attestation_version == ATTESTATION_VERSION_V2:
            payload.update({
                "challenge_digest": self.challenge_digest,
                "credential_principal_identity": self.credential_principal_identity,
            })
        return payload

    def _domain(self) -> str:
        return ATTESTATION_V2_DOMAIN if self.attestation_version == ATTESTATION_VERSION_V2 else ATTESTATION_DOMAIN

    def derived_attestation_id(self) -> str:
        material = canonical_payload({"domain": self._domain(), "claims": self._identity_payload()}).encode("utf-8")
        return "attestation-" + hashlib.sha256(material).hexdigest()

    def claims_digest(self) -> str:
        return digest({"domain": self._domain(), "claims": self._identity_payload()})

    def to_payload(self) -> dict[str, Any]:
        return {"domain": self._domain(), "claims": {**self._identity_payload(), "attestation_id": self.attestation_id}}

    @classmethod
    def from_mapping(cls, value: Any) -> "CredentialCapabilityAttestationClaims":
        return cls(**dict(_claims_projection(value)))


@dataclass(frozen=True)
class SignedCredentialCapabilityAttestation:
    claims: CredentialCapabilityAttestationClaims
    proof: str

    def __post_init__(self) -> None:
        if not isinstance(self.claims, CredentialCapabilityAttestationClaims):
            raise AttestationContractError("attestation_invalid")
        object.__setattr__(self, "proof", _proof(self.proof, self.claims.signature_algorithm))

    @classmethod
    def from_mapping(cls, value: Any) -> "SignedCredentialCapabilityAttestation":
        mapping = _mapping(value, "attestation", {"claims", "proof"})
        return cls(CredentialCapabilityAttestationClaims.from_mapping(mapping["claims"]), mapping["proof"])


class VerifiedCredentialCapabilityAttestation:
    """Boundary-bound, single-use verification ticket; not an Execution Lease."""

    __slots__ = ("__attestation_id", "__claims_digest", "__weakref__")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise AttestationContractError("verified_attestation_required")

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttestationContractError("verified_attestation_immutable")

    @property
    def attestation_id(self) -> str:
        return self.__attestation_id

    @property
    def claims_digest(self) -> str:
        return self.__claims_digest

    def __copy__(self) -> "VerifiedCredentialCapabilityAttestation":
        raise AttestationContractError("attestation_copy_forbidden")

    def __deepcopy__(self, memo: dict[int, Any]) -> "VerifiedCredentialCapabilityAttestation":
        raise AttestationContractError("attestation_copy_forbidden")

    def __repr__(self) -> str:
        return "<VerifiedCredentialCapabilityAttestation protected>"


@dataclass(frozen=True)
class AttestationVerificationResult:
    verified: VerifiedCredentialCapabilityAttestation | None
    failures: tuple[AttestationFailure, ...]

    @property
    def success(self) -> bool:
        return self.verified is not None and not self.failures

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "failures": [failure.to_dict() for failure in self.failures],
            "verified": self.verified is not None,
        }


def _failure(code: str) -> AttestationVerificationResult:
    return AttestationVerificationResult(None, (AttestationFailure(code, code),))


def _request_mismatch(claims: CredentialCapabilityAttestationClaims, request: Mapping[str, Any]) -> str | None:
    checks = (
        ("repository_identity", "attestation_binding_mismatch"),
        ("github_subject_identity", "attestation_binding_mismatch"),
        ("driver_identity", "attestation_binding_mismatch"),
        ("remote_authority", "attestation_binding_mismatch"),
        ("preview_id", "attestation_binding_mismatch"),
        ("revision", "attestation_binding_mismatch"),
        ("operation_set_digest", "attestation_binding_mismatch"),
        ("remote_snapshot_digest", "attestation_binding_mismatch"),
        ("evidence_digest", "attestation_binding_mismatch"),
    )
    for field, code in checks:
        if getattr(claims, field) != request[field]:
            return code
    if not set(request["required_capabilities"]).issubset(set(claims.granted_capabilities)):
        return "credential_capability_insufficient"
    if claims.attestation_version == ATTESTATION_VERSION_V2:
        if claims.challenge_digest != request["challenge_digest"]:
            return "attestation_challenge_mismatch"
        if not claims.credential_principal_identity:
            return "attestation_credential_principal_missing"
    return None


def _check_capabilities(policy: CredentialCapabilityPolicy | None, capabilities: tuple[str, ...]) -> str | None:
    if policy is None:
        return "attestation_capability_policy_unavailable"
    for capability in capabilities:
        try:
            supported = policy.is_supported(capability)
        except Exception:
            return "attestation_capability_policy_unavailable"
        if not isinstance(supported, bool):
            return "attestation_capability_policy_unavailable"
        if not supported:
            return "credential_capability_unknown"
    return None


@dataclass(frozen=True)
class _TicketRecord:
    claims: CredentialCapabilityAttestationClaims
    owner: "AttestationRuntimeBoundary"
    state: str = "Active"


class AttestationRuntimeBoundary:
    """Per-Runtime authority for request creation, verification and ticket use."""

    def __init__(
        self,
        issuer_policy: TrustedIssuerPolicy | None,
        proof_verifier: CredentialCapabilityProofVerifier | None,
        revocation_reader: RevocationReader | None,
        capability_policy: CredentialCapabilityPolicy | None,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not callable(monotonic_clock):
            raise TypeError("attestation_monotonic_clock_invalid")
        self.__issuer_policy = issuer_policy
        self.__proof_verifier = proof_verifier
        self.__revocation_reader = revocation_reader
        self.__capability_policy = capability_policy
        self.__monotonic_clock = monotonic_clock
        self.__provenance = object()
        self.__lock = threading.RLock()
        self.__requests: weakref.WeakKeyDictionary[CredentialCapabilityRequest, Mapping[str, Any]] = weakref.WeakKeyDictionary()
        self.__challenges: weakref.WeakKeyDictionary[CredentialCapabilityRequest, dict[str, Any]] = weakref.WeakKeyDictionary()
        self.__tickets: weakref.WeakKeyDictionary[VerifiedCredentialCapabilityAttestation, _TicketRecord] = weakref.WeakKeyDictionary()

    def create_request(self, **values: Any) -> CredentialCapabilityRequest:
        normalized = CredentialCapabilityRequest._normalized_values(values)
        challenge_value = secrets.token_urlsafe(32)
        challenge_context = {key: normalized[key] for key in sorted(normalized)}
        normalized["challenge_digest"] = digest({
            "domain": CHALLENGE_DOMAIN,
            "challenge": challenge_value,
            "context": challenge_context,
        })
        capability_failure = _check_capabilities(self.__capability_policy, normalized["required_capabilities"])
        if capability_failure is not None:
            raise AttestationContractError(capability_failure)
        request = object.__new__(CredentialCapabilityRequest)
        for field, value in normalized.items():
            object.__setattr__(request, field, value)
        object.__setattr__(request, "_CredentialCapabilityRequest__challenge_value", challenge_value)
        object.__setattr__(request, "_CredentialCapabilityRequest__boundary_provenance", self.__provenance)
        snapshot = MappingProxyType(dict(normalized))
        with self.__lock:
            self.__requests[request] = snapshot
            self.__challenges[request] = {"value": challenge_value, "issued": self.__monotonic_clock(), "consumed": False}
        return request

    def challenge_is_current(self, request: CredentialCapabilityRequest, *, max_age_seconds: float = 300.0) -> bool:
        with self.__lock:
            state = self.__challenges.get(request)
            return state is not None and not state["consumed"] and self.__monotonic_clock() - state["issued"] < max_age_seconds

    def consume_challenge(self, request: CredentialCapabilityRequest) -> None:
        with self.__lock:
            state = self.__challenges.get(request)
            if state is None or state["consumed"]:
                raise AttestationContractError("attestation_challenge_replayed")
            if self.__monotonic_clock() - state["issued"] >= 300.0:
                raise AttestationContractError("attestation_challenge_expired")
            state["consumed"] = True

    def consume_ticket(self, ticket: VerifiedCredentialCapabilityAttestation) -> CredentialCapabilityAttestationClaims:
        if not isinstance(ticket, VerifiedCredentialCapabilityAttestation):
            raise AttestationContractError("attestation_invalid")
        with self.__lock:
            record = self.__tickets.get(ticket)
            if record is None or record.owner is not self:
                raise AttestationContractError("attestation_boundary_mismatch")
            if record.state != "Active":
                raise AttestationContractError("attestation_replayed")
            object.__setattr__(record, "state", "Consumed")
            return record.claims

    def verify(
        self,
        signed_attestation: SignedCredentialCapabilityAttestation | Mapping[str, Any] | None,
        request: CredentialCapabilityRequest,
        current_time: datetime,
    ) -> AttestationVerificationResult:
        """Verify using only this boundary's fixed policy, verifier and reader."""
        try:
            now = _current_time(current_time)
            if not isinstance(request, CredentialCapabilityRequest):
                return _failure("attestation_request_unavailable")
            with self.__lock:
                request_snapshot = self.__requests.get(request)
            if request_snapshot is None:
                return _failure("attestation_request_unavailable")
            if not request._belongs_to(self.__provenance):
                return _failure("attestation_binding_mismatch")
            for field, expected in request_snapshot.items():
                if getattr(request, field, object()) != expected:
                    return _failure("attestation_request_tampered")
            if signed_attestation is None:
                return _failure("attestation_missing")
            envelope = _parse_untrusted_signed_attestation(signed_attestation)
            claims = envelope.claims
            if claims.attestation_version not in {ATTESTATION_VERSION_V1, ATTESTATION_VERSION_V2}:
                return _failure("attestation_version_unsupported")
            if claims.signature_algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
                return _failure("attestation_algorithm_unsupported")
            if self.__issuer_policy is None or self.__proof_verifier is None:
                return _failure("attestation_verifier_unavailable")
            try:
                decision = self.__issuer_policy.evaluate(
                    claims.issuer_id, claims.key_id, claims.signature_algorithm,
                    claims.attestation_version, claims.credential_class,
                )
            except Exception:
                return _failure("attestation_verifier_unavailable")
            try:
                decision = _revalidate_issuer_decision(decision)
            except AttestationContractError:
                return _failure("attestation_verifier_unavailable")
            if not decision.accepted:
                return _failure(decision.failure_code)
            payload = canonical_payload(claims.to_payload()).encode("utf-8")
            try:
                valid_signature = self.__proof_verifier.verify(
                    payload, envelope.proof, claims.issuer_id, claims.key_id, claims.signature_algorithm,
                )
            except Exception:
                return _failure("attestation_verifier_unavailable")
            if valid_signature is not True:
                return _failure("attestation_signature_invalid")
            capability_failure = _check_capabilities(self.__capability_policy, claims.granted_capabilities)
            if capability_failure is not None:
                return _failure(capability_failure)
            mismatch = _request_mismatch(claims, request_snapshot)
            if mismatch is not None:
                return _failure(mismatch)
            if claims.attestation_version == ATTESTATION_VERSION_V2:
                if not self.challenge_is_current(request):
                    return _failure("attestation_challenge_expired")
                try:
                    self.consume_challenge(request)
                except AttestationContractError as exc:
                    return _failure(str(exc))
            _, issued = _utc_timestamp(claims.issued_at)
            _, expires = _utc_timestamp(claims.expires_at)
            if now < issued:
                return _failure("attestation_not_yet_valid")
            if now >= expires:
                return _failure("attestation_expired")
            if self.__revocation_reader is None:
                return _failure("attestation_revocation_unavailable")
            try:
                status = self.__revocation_reader.read_status(
                    claims.attestation_id, claims.credential_instance_id, claims.issuer_id,
                    claims.key_id, REVOCATION_CONTRACT_VERSION,
                )
            except Exception:
                return _failure("attestation_revocation_unavailable")
            try:
                status = _revalidate_revocation_status(status, now)
            except AttestationContractError as exc:
                if str(exc) == "attestation_revocation_version_unsupported":
                    return _failure("attestation_revocation_version_unsupported")
                return _failure("attestation_revocation_invalid")
            if status.attestation_revoked:
                return _failure("attestation_revoked")
            if status.credential_instance_revoked:
                return _failure("credential_instance_revoked")
            ticket = object.__new__(VerifiedCredentialCapabilityAttestation)
            object.__setattr__(ticket, "_VerifiedCredentialCapabilityAttestation__attestation_id", claims.attestation_id)
            object.__setattr__(ticket, "_VerifiedCredentialCapabilityAttestation__claims_digest", claims.claims_digest())
            with self.__lock:
                self.__tickets[ticket] = _TicketRecord(claims, self)
            return AttestationVerificationResult(ticket, ())
        except AttestationContractError as exc:
            code = str(exc)
            allowed = {
                "attestation_invalid", "attestation_version_unsupported", "attestation_algorithm_unsupported",
                "attestation_id_mismatch", "attestation_expiry_invalid", "attestation_binding_mismatch",
                "attestation_capability_insufficient", "credential_capability_insufficient", "proof_invalid",
                "required_capabilities_missing", "attestation_credential_class_unsupported",
                "credential_capability_unknown", "attestation_capability_policy_unavailable",
                "attestation_request_unavailable", "attestation_request_tampered",
                "attestation_challenge_mismatch", "attestation_challenge_expired", "attestation_challenge_replayed",
                "attestation_credential_principal_missing", "attestation_v1_extension_forbidden",
            }
            return _failure(code if code in allowed else "attestation_invalid")
        except (TypeError, KeyError, ValueError):
            return _failure("attestation_invalid")
        except Exception:
            return _failure("attestation_invalid")


def verify_credential_capability_attestation(
    signed_attestation: SignedCredentialCapabilityAttestation | Mapping[str, Any] | None,
    request: CredentialCapabilityRequest,
    boundary: AttestationRuntimeBoundary | None,
    current_time: datetime,
) -> AttestationVerificationResult:
    """Compatibility entry point requiring an explicit Runtime Boundary."""
    if not isinstance(boundary, AttestationRuntimeBoundary):
        return _failure("attestation_verifier_unavailable")
    return boundary.verify(signed_attestation, request, current_time)
