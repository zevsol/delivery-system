"""Offline domain contracts for historical attestation persistence.

This module deliberately contains no Store, database, migration, Runtime
wiring, credential, network, or current-capability behavior.  It validates
historical objects and owns the in-process Revalidation Attempt boundary only.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import hashlib
import re
import secrets
import threading
from typing import Any, Callable, Mapping, Protocol
import unicodedata
import weakref

from delivery_system.attestation import (
    ATTESTATION_DOMAIN,
    ATTESTATION_V2_DOMAIN,
    ATTESTATION_VERSION_V1,
    ATTESTATION_VERSION_V2,
    CredentialCapabilityAttestationClaims,
    SUPPORTED_SIGNATURE_ALGORITHMS,
)
from delivery_system.protocol import _text as _canonical_text
from delivery_system.protocol import canonical_payload, digest


ARTIFACT_CONTRACT_VERSION = "offline-attestation-artifact-v1"
REFERENCE_CONTRACT_VERSION = "attestation-binding-reference-v1"
REFERENCE_V2_CONTRACT_VERSION = "attestation-binding-reference-v2"
ATTEMPT_CONTRACT_VERSION = "revalidation-attempt-v1"
EVENT_IDENTITY_VERSION = "1"
EVENT_PAYLOAD_VERSION = "1"

ARTIFACT_ID_DOMAIN = "delivery-system:attestation-artifact-identity:v1"
ARTIFACT_CONTENT_DOMAIN = "delivery-system:attestation-artifact-content:v1"
REFERENCE_ID_DOMAIN = "delivery-system:attestation-binding-reference-identity:v1"
REFERENCE_CONTENT_DOMAIN = "delivery-system:attestation-binding-reference-content:v1"
ATTEMPT_ID_DOMAIN = "delivery-system:revalidation-attempt:v1"
EVENT_ID_DOMAIN = "delivery-system:attestation-revalidation-event-identity:v1"
EVENT_CONTENT_DOMAIN = "delivery-system:attestation-revalidation-event-content:v1"

ATTESTATION_REVALIDATION_FAILURE_CODES = frozenset({
    "attestation_revalidation_preview_stale",
    "attestation_revalidation_audit_stale",
    "attestation_revalidation_evidence_mismatch",
    "attestation_revalidation_expired",
    "attestation_revalidation_revoked",
    "attestation_revalidation_verifier_unavailable",
    "attestation_revalidation_revocation_unavailable",
    "attestation_signature_invalid",
    "credential_capability_insufficient",
})

FUTURE_STORE_ERROR_CODES = frozenset({
    "attestation_artifact_aggregate_corrupt",
    "attestation_artifact_conflict",
    "attestation_binding_reference_conflict",
})

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_ATTEMPT_RE = re.compile(r"^attempt-[0-9a-f]{32}$")
_EVENT_RE = re.compile(r"^revalidation-event-[0-9a-f]{64}$")
_ARTIFACT_RE = re.compile(r"^artifact-[0-9a-f]{64}$")
_REFERENCE_RE = re.compile(r"^binding-reference-[0-9a-f]{64}$")
_BINDING_RE = re.compile(r"^binding-[0-9a-f]{64}$")


class PersistenceContractError(ValueError):
    """Stable, non-sensitive domain failure."""

    def __init__(self, code: str) -> None:
        if type(code) is not str or not code:
            code = "attestation_persistence_payload_invalid"
        self.code = code
        super().__init__(code)


class AttemptEntropySource(Protocol):
    def __call__(self, size: int) -> bytes: ...


def _error(code: str) -> None:
    raise PersistenceContractError(code)


def _keys(value: Any, expected: frozenset[str]) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value.keys()) != expected:
        _error("attestation_persistence_keyset_invalid")
    if any(type(key) is not str for key in value):
        _error("attestation_persistence_keyset_invalid")
    return value


def _text(value: Any, field: str) -> str:
    if type(value) is not str or not value:
        _error("attestation_persistence_type_invalid")
    normalized = _canonical_text(value)
    if not normalized or any(ord(char) < 0x20 or ord(char) == 0x7F for char in normalized):
        _error("attestation_persistence_payload_invalid")
    return normalized


def _integer(value: Any) -> int:
    if type(value) is not int or value < 1:
        _error("attestation_persistence_type_invalid")
    return value


def _digest_value(value: Any) -> str:
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        _error("attestation_persistence_payload_invalid")
    return value


def _timestamp(value: Any) -> str:
    if type(value) is not str:
        _error("attestation_persistence_type_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError, OverflowError):
        _error("attestation_persistence_payload_invalid")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _error("attestation_persistence_payload_invalid")
    utc = parsed.astimezone(timezone.utc)
    return utc.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _prefixed_id(value: Any, regex: re.Pattern[str]) -> str:
    if type(value) is not str or regex.fullmatch(value) is None:
        _error("attestation_persistence_payload_invalid")
    return value


def _exact_derived(value: Any, regex: re.Pattern[str]) -> str:
    return _prefixed_id(value, regex)


def _sha_id(domain: str, payload: Mapping[str, Any], prefix: str) -> str:
    material = canonical_payload({"domain": domain, "payload": dict(payload)})
    return prefix + hashlib.sha256(material.encode("utf-8")).hexdigest()


def _claims_fields(value: Any) -> dict[str, Any]:
    v1_fields = (
        "attestation_version", "attestation_id", "issuer_id", "key_id",
        "signature_algorithm", "credential_class", "credential_instance_id",
        "github_subject_identity", "repository_identity", "granted_capabilities",
        "driver_identity", "remote_authority", "preview_id", "revision",
        "operation_set_digest", "remote_snapshot_digest", "evidence_digest",
        "issued_at", "expires_at", "nonce", "source_verification_digest",
    )
    v2_fields = v1_fields + ("challenge_digest", "credential_principal_identity")
    external_capabilities = False
    if type(value) is dict:
        external_capabilities = True
        outer = _keys(value, frozenset({"domain", "claims"}))
        if type(outer["domain"]) is not str:
            _error("attestation_persistence_type_invalid")
        fields = v2_fields if outer["domain"] == ATTESTATION_V2_DOMAIN else v1_fields
        if outer["domain"] not in {ATTESTATION_DOMAIN, ATTESTATION_V2_DOMAIN}:
            _error("attestation_persistence_payload_invalid")
        nested = _keys(outer["claims"], frozenset(fields))
        raw = {field: nested[field] for field in fields}
    elif type(value) is CredentialCapabilityAttestationClaims:
        fields = v2_fields if value.attestation_version == ATTESTATION_VERSION_V2 else v1_fields
        try:
            raw = {field: getattr(value, field) for field in fields}
        except Exception:
            _error("attestation_persistence_payload_invalid")
    else:
        _error("attestation_persistence_type_invalid")
    if external_capabilities and type(raw["granted_capabilities"]) is not list:
        _error("attestation_persistence_type_invalid")
    if not external_capabilities and type(raw["granted_capabilities"]) is not tuple:
        _error("attestation_persistence_type_invalid")
    if not raw["granted_capabilities"] or any(type(item) is not str for item in raw["granted_capabilities"]):
        _error("attestation_persistence_payload_invalid")
    try:
        capabilities = tuple(sorted(_text(item, "granted_capability") for item in raw["granted_capabilities"]))
    except PersistenceContractError:
        raise
    if len(set(capabilities)) != len(capabilities):
        _error("attestation_persistence_payload_invalid")
    raw["granted_capabilities"] = capabilities
    for field in fields:
        if field == "granted_capabilities":
            continue
        if field == "revision":
            _integer(raw[field])
        elif field.endswith("_digest") or field == "remote_authority":
            _digest_value(raw[field])
        elif field in {"issued_at", "expires_at"}:
            raw[field] = _timestamp(raw[field])
        else:
            raw[field] = _text(raw[field], field)
    if raw["attestation_version"] not in {ATTESTATION_VERSION_V1, ATTESTATION_VERSION_V2} or raw["signature_algorithm"] not in SUPPORTED_SIGNATURE_ALGORITHMS:
        _error("attestation_persistence_payload_invalid")
    try:
        claims = CredentialCapabilityAttestationClaims(**raw)
    except Exception:
        _error("attestation_persistence_payload_invalid")
    if type(claims) is not CredentialCapabilityAttestationClaims:
        _error("attestation_persistence_type_invalid")
    return {field: getattr(claims, field) for field in fields}


def _claims_payload(value: Any) -> dict[str, Any]:
    raw = _claims_fields(value)
    return CredentialCapabilityAttestationClaims(**raw).to_payload()


def _claims_object(value: Any) -> CredentialCapabilityAttestationClaims:
    raw = _claims_fields(value)
    try:
        claims = CredentialCapabilityAttestationClaims(**raw)
    except Exception:
        _error("attestation_persistence_payload_invalid")
    return claims


def _canonical_proof(value: Any) -> str:
    if type(value) is not str or len(value) != 86 or re.fullmatch(r"[A-Za-z0-9_-]{86}", value) is None:
        _error("attestation_persistence_payload_invalid")
    try:
        decoded = base64.urlsafe_b64decode(value + "==")
    except Exception:
        _error("attestation_persistence_payload_invalid")
    if len(decoded) != 64 or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        _error("attestation_persistence_payload_invalid")
    return value


def _binding_id(value: Any) -> str:
    return _prefixed_id(value, _BINDING_RE)


@dataclass(frozen=True, slots=True)
class PersistedAttestationArtifact:
    artifact_contract_version: str
    artifact_id: str
    workspace_identity: str
    attestation_id: str
    claims_payload: CredentialCapabilityAttestationClaims
    detached_proof: str
    claims_digest: str
    artifact_digest: str
    original_verified_at: str
    created_at: str

    def __post_init__(self) -> None:
        if type(self.artifact_contract_version) is not str or self.artifact_contract_version != ARTIFACT_CONTRACT_VERSION:
            _error("attestation_persistence_payload_invalid")
        workspace = _text(self.workspace_identity, "workspace_identity")
        claims = _claims_object(self.claims_payload)
        proof = _canonical_proof(self.detached_proof)
        attestation_id = _text(self.attestation_id, "attestation_id")
        if attestation_id != claims.attestation_id:
            _error("attestation_persistence_payload_invalid")
        claims_payload = _claims_payload(claims)
        claims_digest = _digest_value(self.claims_digest)
        if claims_digest != claims.claims_digest():
            _error("attestation_persistence_payload_invalid")
        original = _timestamp(self.original_verified_at)
        created = _timestamp(self.created_at)
        issued = _timestamp(claims.issued_at)
        expires = _timestamp(claims.expires_at)
        issued_dt = datetime.fromisoformat(issued.replace("Z", "+00:00"))
        original_dt = datetime.fromisoformat(original.replace("Z", "+00:00"))
        expires_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
        if not (issued_dt <= original_dt < expires_dt and created_dt >= original_dt):
            _error("attestation_persistence_payload_invalid")
        content = self._content_payload_for(
            workspace, attestation_id, claims_payload, proof, claims_digest, original, created
        )
        expected_digest = digest(content)
        artifact_digest = _exact_derived(self.artifact_digest, _DIGEST_RE)
        artifact_id = _exact_derived(self.artifact_id, _ARTIFACT_RE)
        if artifact_digest != expected_digest:
            _error("attestation_persistence_payload_invalid")
        expected_id = _sha_id(
            ARTIFACT_ID_DOMAIN,
            {"identity_version": "1", "workspace_identity": workspace, "attestation_id": attestation_id},
            "artifact-",
        )
        if artifact_id != expected_id:
            _error("attestation_persistence_payload_invalid")
        for field, value in {
            "workspace_identity": workspace, "claims_payload": claims,
            "detached_proof": proof, "claims_digest": claims_digest,
            "original_verified_at": original, "created_at": created,
        }.items():
            object.__setattr__(self, field, value)
        object.__setattr__(self, "artifact_id", artifact_id)
        object.__setattr__(self, "artifact_digest", artifact_digest)

    @staticmethod
    def _content_payload_for(workspace: str, attestation_id: str, claims_payload: dict[str, Any],
                             proof: str, claims_digest: str, original: str, created: str) -> dict[str, Any]:
        return {
            "domain": ARTIFACT_CONTENT_DOMAIN,
            "artifact_contract_version": ARTIFACT_CONTRACT_VERSION,
            "workspace_identity": workspace,
            "attestation_id": attestation_id,
            "claims_payload": claims_payload,
            "detached_proof": proof,
            "claims_digest": claims_digest,
            "original_verified_at": original,
            "created_at": created,
        }

    def content_payload(self) -> dict[str, Any]:
        return _artifact_projection(self, content=True)

    def to_payload(self) -> dict[str, Any]:
        return _artifact_projection(self)

    @classmethod
    def from_untrusted(cls, value: Any) -> "PersistedAttestationArtifact":
        if type(value) is cls:
            try:
                raw = {field: getattr(value, field) for field in cls.__dataclass_fields__}
            except Exception:
                _error("attestation_persistence_payload_invalid")
        elif type(value) is dict:
            raw = _keys(value, frozenset(cls.__dataclass_fields__))
        else:
            _error("attestation_persistence_type_invalid")
        try:
            return cls(**raw)
        except PersistenceContractError:
            raise
        except Exception:
            _error("attestation_persistence_payload_invalid")


def _artifact_projection(value: Any, *, content: bool = False) -> dict[str, Any]:
    normalized = PersistedAttestationArtifact.from_untrusted(value)
    if content:
        return normalized._content_payload_for(
            normalized.workspace_identity, normalized.attestation_id,
            _claims_payload(normalized.claims_payload), normalized.detached_proof,
            normalized.claims_digest, normalized.original_verified_at,
            normalized.created_at,
        )
    return {
        "artifact_contract_version": normalized.artifact_contract_version,
        "artifact_id": normalized.artifact_id,
        "workspace_identity": normalized.workspace_identity,
        "attestation_id": normalized.attestation_id,
        "claims_payload": _claims_payload(normalized.claims_payload),
        "detached_proof": normalized.detached_proof,
        "claims_digest": normalized.claims_digest,
        "artifact_digest": normalized.artifact_digest,
        "original_verified_at": normalized.original_verified_at,
        "created_at": normalized.created_at,
    }


@dataclass(frozen=True, slots=True)
class AttestationBindingReference:
    reference_contract_version: str
    reference_id: str
    workspace_identity: str
    artifact_id: str
    artifact_digest: str
    binding_id: str
    repository_identity: str
    github_subject_identity: str
    driver_identity: str
    remote_authority: str
    preview_id: str
    revision: int
    plan_digest: str
    sealed_preview_digest: str
    operation_set_digest: str
    remote_snapshot_digest: str
    audit_id: str
    audit_digest: str
    evidence_id: str
    evidence_digest: str
    original_verified_at: str
    binding_reference_digest: str
    credential_principal_identity: str = ""
    challenge_digest: str = ""

    def __post_init__(self) -> None:
        if type(self.reference_contract_version) is not str or self.reference_contract_version not in {REFERENCE_CONTRACT_VERSION, REFERENCE_V2_CONTRACT_VERSION}:
            _error("attestation_persistence_payload_invalid")
        text_fields = (
            "workspace_identity", "artifact_id", "binding_id", "repository_identity",
            "github_subject_identity", "driver_identity", "preview_id",
            "audit_id", "evidence_id",
        )
        normalized = {field: _text(getattr(self, field), field) for field in text_fields}
        normalized["reference_contract_version"] = self.reference_contract_version
        normalized["artifact_id"] = _prefixed_id(self.artifact_id, _ARTIFACT_RE)
        normalized["binding_id"] = _binding_id(self.binding_id)
        for field in ("artifact_digest", "remote_authority", "plan_digest", "sealed_preview_digest", "operation_set_digest",
                      "remote_snapshot_digest", "audit_digest", "evidence_digest"):
            normalized[field] = _digest_value(getattr(self, field))
        normalized["preview_id"] = _text(self.preview_id, "preview_id")
        normalized["audit_id"] = _text(self.audit_id, "audit_id")
        normalized["evidence_id"] = _text(self.evidence_id, "evidence_id")
        normalized["revision"] = _integer(self.revision)
        normalized["original_verified_at"] = _timestamp(self.original_verified_at)
        if self.reference_contract_version == REFERENCE_V2_CONTRACT_VERSION:
            normalized["credential_principal_identity"] = _text(self.credential_principal_identity, "credential_principal_identity")
            normalized["challenge_digest"] = _digest_value(self.challenge_digest)
        elif self.credential_principal_identity or self.challenge_digest:
            _error("attestation_persistence_payload_invalid")
        else:
            normalized["credential_principal_identity"] = ""
            normalized["challenge_digest"] = ""
        content = self._content_payload_for(normalized)
        expected_digest = digest(content)
        binding_reference_digest = _exact_derived(self.binding_reference_digest, _DIGEST_RE)
        reference_id = _exact_derived(self.reference_id, _REFERENCE_RE)
        if binding_reference_digest != expected_digest:
            _error("attestation_persistence_payload_invalid")
        expected_id = _sha_id(
            REFERENCE_ID_DOMAIN,
            {"reference_version": "2" if normalized["reference_contract_version"] == REFERENCE_V2_CONTRACT_VERSION else "1", "workspace_identity": normalized["workspace_identity"],
             "artifact_id": normalized["artifact_id"], "binding_id": normalized["binding_id"]},
            "binding-reference-",
        )
        if reference_id != expected_id:
            _error("attestation_persistence_payload_invalid")
        for field, value in normalized.items():
            object.__setattr__(self, field, value)
        object.__setattr__(self, "reference_id", reference_id)
        object.__setattr__(self, "binding_reference_digest", binding_reference_digest)

    @staticmethod
    def _content_payload_for(values: Mapping[str, Any]) -> dict[str, Any]:
        fields = (
            "workspace_identity", "artifact_id", "artifact_digest", "binding_id",
            "repository_identity", "github_subject_identity", "driver_identity",
            "remote_authority", "preview_id", "revision", "plan_digest",
            "sealed_preview_digest", "operation_set_digest", "remote_snapshot_digest",
            "audit_id", "audit_digest", "evidence_id", "evidence_digest",
            "original_verified_at",
        )
        if values["reference_contract_version"] == REFERENCE_V2_CONTRACT_VERSION:
            fields = fields + ("credential_principal_identity", "challenge_digest")
        return {
            "domain": REFERENCE_CONTENT_DOMAIN,
            "reference_contract_version": values["reference_contract_version"],
            **{field: values[field] for field in fields},
        }

    def content_payload(self) -> dict[str, Any]:
        return _reference_projection(self, content=True)

    def to_payload(self) -> dict[str, Any]:
        return _reference_projection(self)

    @classmethod
    def from_untrusted(cls, value: Any) -> "AttestationBindingReference":
        if type(value) is cls:
            try:
                raw = {field: getattr(value, field) for field in cls.__dataclass_fields__}
            except Exception:
                _error("attestation_persistence_payload_invalid")
        elif type(value) is dict:
            legacy_fields = frozenset(cls.__dataclass_fields__) - {"credential_principal_identity", "challenge_digest"}
            if frozenset(value) == legacy_fields:
                raw = dict(value)
                raw.update({"credential_principal_identity": "", "challenge_digest": ""})
            else:
                raw = _keys(value, frozenset(cls.__dataclass_fields__))
        else:
            _error("attestation_persistence_type_invalid")
        try:
            return cls(**raw)
        except PersistenceContractError:
            raise
        except Exception:
            _error("attestation_persistence_payload_invalid")


def _reference_projection(value: Any, *, content: bool = False) -> dict[str, Any]:
    normalized = AttestationBindingReference.from_untrusted(value)
    fields = (
        "workspace_identity", "artifact_id", "artifact_digest", "binding_id",
        "repository_identity", "github_subject_identity", "driver_identity",
        "remote_authority", "preview_id", "revision", "plan_digest",
        "sealed_preview_digest", "operation_set_digest", "remote_snapshot_digest",
        "audit_id", "audit_digest", "evidence_id", "evidence_digest",
        "original_verified_at",
    )
    if normalized.reference_contract_version == REFERENCE_V2_CONTRACT_VERSION:
        fields = fields + ("credential_principal_identity", "challenge_digest")
    if content:
        return normalized._content_payload_for({field: getattr(normalized, field) for field in fields})
    payload = {field: getattr(normalized, field) for field in normalized.__dataclass_fields__ if field not in {"credential_principal_identity", "challenge_digest"}}
    if normalized.reference_contract_version == REFERENCE_V2_CONTRACT_VERSION:
        payload.update({"credential_principal_identity": normalized.credential_principal_identity, "challenge_digest": normalized.challenge_digest})
    return payload


def validate_artifact_aggregate(artifact: Any, reference: Any) -> tuple[PersistedAttestationArtifact, AttestationBindingReference]:
    normalized_artifact = PersistedAttestationArtifact.from_untrusted(artifact)
    normalized_reference = AttestationBindingReference.from_untrusted(reference)
    if (
        normalized_artifact.workspace_identity != normalized_reference.workspace_identity
        or normalized_artifact.artifact_id != normalized_reference.artifact_id
        or normalized_artifact.artifact_digest != normalized_reference.artifact_digest
        or normalized_reference.repository_identity != normalized_artifact.claims_payload.repository_identity
        or normalized_reference.github_subject_identity != normalized_artifact.claims_payload.github_subject_identity
        or normalized_reference.driver_identity != normalized_artifact.claims_payload.driver_identity
        or normalized_reference.remote_authority != normalized_artifact.claims_payload.remote_authority
        or normalized_reference.preview_id != normalized_artifact.claims_payload.preview_id
        or normalized_reference.revision != normalized_artifact.claims_payload.revision
        or normalized_reference.operation_set_digest != normalized_artifact.claims_payload.operation_set_digest
        or normalized_reference.remote_snapshot_digest != normalized_artifact.claims_payload.remote_snapshot_digest
        or normalized_reference.evidence_digest != normalized_artifact.claims_payload.evidence_digest
        or normalized_reference.original_verified_at != normalized_artifact.original_verified_at
        or (normalized_artifact.claims_payload.attestation_version == ATTESTATION_VERSION_V2 and (
            normalized_reference.reference_contract_version != REFERENCE_V2_CONTRACT_VERSION
            or normalized_reference.credential_principal_identity != normalized_artifact.claims_payload.credential_principal_identity
            or normalized_reference.challenge_digest != normalized_artifact.claims_payload.challenge_digest
        ))
    ):
        _error("attestation_persistence_payload_invalid")
    return normalized_artifact, normalized_reference


@dataclass(frozen=True, slots=True)
class AttestationRevalidationEvent:
    event_identity_version: str
    event_payload_version: str
    event_id: str
    workspace_identity: str
    artifact_id: str
    artifact_digest: str
    revalidation_attempt_id: str
    revalidation_context_digest: str
    binding_reference_digest: str
    outcome: str
    revalidated_at: str
    failure_code: str | None
    result_digest: str | None
    event_payload_digest: str

    def __post_init__(self) -> None:
        if type(self.event_identity_version) is not str or self.event_identity_version != EVENT_IDENTITY_VERSION:
            _error("attestation_persistence_payload_invalid")
        if type(self.event_payload_version) is not str or self.event_payload_version != EVENT_PAYLOAD_VERSION:
            _error("attestation_persistence_payload_invalid")
        workspace = _text(self.workspace_identity, "workspace_identity")
        artifact = _prefixed_id(self.artifact_id, _ARTIFACT_RE)
        artifact_digest = _digest_value(self.artifact_digest)
        attempt = _prefixed_id(self.revalidation_attempt_id, _ATTEMPT_RE)
        context = _digest_value(self.revalidation_context_digest)
        reference = _digest_value(self.binding_reference_digest)
        timestamp = _timestamp(self.revalidated_at)
        if type(self.outcome) is not str or self.outcome not in {"Successful", "Failed"}:
            _error("attestation_persistence_payload_invalid")
        if self.outcome == "Successful":
            if self.failure_code is not None or type(self.failure_code) is not type(None):
                _error("attestation_persistence_payload_invalid")
            result = _digest_value(self.result_digest)
        else:
            if type(self.failure_code) is not str or self.failure_code not in ATTESTATION_REVALIDATION_FAILURE_CODES:
                _error("attestation_persistence_payload_invalid")
            if self.result_digest is not None:
                _error("attestation_persistence_payload_invalid")
            result = None
        identity = {
            "domain": EVENT_ID_DOMAIN,
            "event_identity_version": EVENT_IDENTITY_VERSION,
            "workspace_identity": workspace,
            "artifact_id": artifact,
            "revalidation_attempt_id": attempt,
        }
        expected_event_id = "revalidation-event-" + hashlib.sha256(canonical_payload(identity).encode("utf-8")).hexdigest()
        event_id = _exact_derived(self.event_id, _EVENT_RE)
        event_payload_digest = _exact_derived(self.event_payload_digest, _DIGEST_RE)
        if event_id != expected_event_id:
            _error("attestation_persistence_payload_invalid")
        content = self._content_payload_for(
            workspace, artifact, artifact_digest, attempt, context, reference,
            self.outcome, timestamp, self.failure_code, result,
        )
        expected_payload_digest = digest(content)
        if event_payload_digest != expected_payload_digest:
            _error("attestation_persistence_payload_invalid")
        for field, value in {
            "workspace_identity": workspace, "artifact_id": artifact,
            "artifact_digest": artifact_digest, "revalidation_attempt_id": attempt,
            "revalidation_context_digest": context, "binding_reference_digest": reference,
            "revalidated_at": timestamp, "result_digest": result,
        }.items():
            object.__setattr__(self, field, value)
        object.__setattr__(self, "event_id", event_id)
        object.__setattr__(self, "event_payload_digest", event_payload_digest)

    @staticmethod
    def _content_payload_for(workspace: str, artifact: str, artifact_digest: str, attempt: str,
                             context: str, reference: str, outcome: str, timestamp: str,
                             failure_code: str | None, result: str | None) -> dict[str, Any]:
        return {
            "domain": EVENT_CONTENT_DOMAIN,
            "event_payload_version": EVENT_PAYLOAD_VERSION,
            "workspace_identity": workspace,
            "artifact_id": artifact,
            "artifact_digest": artifact_digest,
            "revalidation_attempt_id": attempt,
            "revalidation_context_digest": context,
            "binding_reference_digest": reference,
            "outcome": outcome,
            "revalidated_at": timestamp,
            "failure_code": failure_code,
            "result_digest": result,
        }

    @classmethod
    def create(cls, *, workspace_identity: str, artifact_id: str, artifact_digest: str,
               revalidation_attempt_id: str, revalidation_context_digest: str,
               binding_reference_digest: str, outcome: str, revalidated_at: str,
               failure_code: str | None = None, result_digest: str | None = None) -> "AttestationRevalidationEvent":
        workspace = _text(workspace_identity, "workspace_identity")
        artifact = _prefixed_id(artifact_id, _ARTIFACT_RE)
        attempt = _prefixed_id(revalidation_attempt_id, _ATTEMPT_RE)
        identity = {
            "domain": EVENT_ID_DOMAIN, "event_identity_version": EVENT_IDENTITY_VERSION,
            "workspace_identity": workspace, "artifact_id": artifact,
            "revalidation_attempt_id": attempt,
        }
        event_id = "revalidation-event-" + hashlib.sha256(canonical_payload(identity).encode("utf-8")).hexdigest()
        timestamp = _timestamp(revalidated_at)
        content = cls._content_payload_for(
            workspace, artifact, _digest_value(artifact_digest), attempt,
            _digest_value(revalidation_context_digest), _digest_value(binding_reference_digest),
            outcome, timestamp, failure_code, result_digest,
        )
        return cls(EVENT_IDENTITY_VERSION, EVENT_PAYLOAD_VERSION, event_id, workspace, artifact,
                   artifact_digest, attempt, revalidation_context_digest,
                   binding_reference_digest, outcome, timestamp, failure_code,
                   result_digest, digest(content))

    def content_payload(self) -> dict[str, Any]:
        return _event_projection(self, content=True)

    def to_payload(self) -> dict[str, Any]:
        return _event_projection(self)

    @classmethod
    def from_untrusted(cls, value: Any) -> "AttestationRevalidationEvent":
        if type(value) is cls:
            try:
                raw = {field: getattr(value, field) for field in cls.__dataclass_fields__}
            except Exception:
                _error("attestation_persistence_payload_invalid")
        elif type(value) is dict:
            raw = _keys(value, frozenset(cls.__dataclass_fields__))
        else:
            _error("attestation_persistence_type_invalid")
        try:
            return cls(**raw)
        except PersistenceContractError:
            raise
        except Exception:
            _error("attestation_persistence_payload_invalid")


def _event_projection(value: Any, *, content: bool = False) -> dict[str, Any]:
    normalized = AttestationRevalidationEvent.from_untrusted(value)
    if content:
        return normalized._content_payload_for(
            normalized.workspace_identity, normalized.artifact_id, normalized.artifact_digest,
            normalized.revalidation_attempt_id, normalized.revalidation_context_digest,
            normalized.binding_reference_digest, normalized.outcome, normalized.revalidated_at,
            normalized.failure_code, normalized.result_digest,
        )
    return {field: getattr(normalized, field) for field in normalized.__dataclass_fields__}


def _event_snapshot(value: Any) -> tuple[Any, ...]:
    normalized = AttestationRevalidationEvent.from_untrusted(value)
    return tuple(
        (field, type(getattr(normalized, field)), getattr(normalized, field))
        for field in normalized.__dataclass_fields__
    )


class _AttemptBoundaryToken:
    __slots__ = ("boundary_ref", "__weakref__")

    def __init__(self, boundary: "RevalidationAttemptBoundary") -> None:
        self.boundary_ref = weakref.ref(boundary)


class RevalidationAttempt:
    __slots__ = ("__attempt_id", "__workspace_identity", "__artifact_id", "__boundary_token", "__weakref__")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        _error("attestation_attempt_boundary_mismatch")

    @classmethod
    def _instantiate(cls, token: object, attempt_id: str, workspace_identity: str, artifact_id: str) -> "RevalidationAttempt":
        attempt = object.__new__(cls)
        object.__setattr__(attempt, "_RevalidationAttempt__attempt_id", attempt_id)
        object.__setattr__(attempt, "_RevalidationAttempt__workspace_identity", workspace_identity)
        object.__setattr__(attempt, "_RevalidationAttempt__artifact_id", artifact_id)
        object.__setattr__(attempt, "_RevalidationAttempt__boundary_token", token)
        return attempt

    @property
    def revalidation_attempt_id(self) -> str:
        return self.__attempt_id

    @property
    def workspace_identity(self) -> str:
        return self.__workspace_identity

    @property
    def artifact_id(self) -> str:
        return self.__artifact_id

    @property
    def attempt_contract_version(self) -> str:
        return ATTEMPT_CONTRACT_VERSION

    def to_payload(self) -> dict[str, str]:
        try:
            token = self.__boundary_token
        except Exception:
            _error("attestation_attempt_tampered")
        if not isinstance(token, _AttemptBoundaryToken):
            _error("attestation_attempt_boundary_mismatch")
        boundary = token.boundary_ref()
        if boundary is None:
            _error("attestation_attempt_boundary_mismatch")
        boundary._validate_attempt_projection(self)
        return {
            "attempt_contract_version": ATTEMPT_CONTRACT_VERSION,
            "revalidation_attempt_id": self.__attempt_id,
            "workspace_identity": self.__workspace_identity,
            "artifact_id": self.__artifact_id,
        }

    def __setattr__(self, name: str, value: Any) -> None:
        _error("attestation_attempt_tampered")

    def __copy__(self) -> "RevalidationAttempt":
        _error("attestation_attempt_tampered")

    def __deepcopy__(self, memo: dict[int, Any]) -> "RevalidationAttempt":
        _error("attestation_attempt_tampered")


class RevalidationAttemptBoundary:
    def __init__(self, entropy_source: AttemptEntropySource | None = None) -> None:
        self.__token = _AttemptBoundaryToken(self)
        self.__entropy_source = secrets.token_bytes if entropy_source is None else entropy_source
        self.__lock = threading.RLock()
        self.__attempts: dict[str, tuple[weakref.ReferenceType[RevalidationAttempt], tuple[str, str], str | None, AttestationRevalidationEvent | None, tuple[Any, ...] | None]] = {}
        self.__attempt_tombstones: set[str] = set()

    def create_attempt(self, workspace_identity: str, artifact_id: str) -> RevalidationAttempt:
        workspace = _text(workspace_identity, "workspace_identity")
        artifact = _prefixed_id(artifact_id, _ARTIFACT_RE)
        try:
            entropy = self.__entropy_source(16)
        except Exception:
            _error("attestation_attempt_entropy_unavailable")
        if type(entropy) is not bytes or len(entropy) != 16:
            _error("attestation_attempt_entropy_unavailable")
        attempt_id = "attempt-" + entropy.hex()
        with self.__lock:
            if attempt_id in self.__attempt_tombstones:
                _error("attestation_attempt_id_collision")
            attempt = RevalidationAttempt._instantiate(self.__token, attempt_id, workspace, artifact)
            self.__attempt_tombstones.add(attempt_id)
            self.__attempts[attempt_id] = (weakref.ref(attempt), (workspace, artifact), None, None, None)
            return attempt

    def _owned(self, attempt: Any) -> tuple[str, str, str, tuple[str, str], str | None, AttestationRevalidationEvent | None]:
        if type(attempt) is not RevalidationAttempt:
            _error("attestation_attempt_boundary_mismatch")
        try:
            attempt_id = attempt.revalidation_attempt_id
            workspace = attempt.workspace_identity
            artifact = attempt.artifact_id
        except Exception:
            _error("attestation_attempt_tampered")
        try:
            checked_attempt_id = _prefixed_id(attempt_id, _ATTEMPT_RE)
            checked_workspace = _text(workspace, "workspace_identity")
            checked_artifact = _prefixed_id(artifact, _ARTIFACT_RE)
        except PersistenceContractError:
            _error("attestation_attempt_tampered")
        if (checked_attempt_id, checked_workspace, checked_artifact) != (attempt_id, workspace, artifact):
            _error("attestation_attempt_tampered")
        with self.__lock:
            entry = self.__attempts.get(checked_attempt_id)
            if entry is None or entry[0]() is not attempt or getattr(attempt, "_RevalidationAttempt__boundary_token", None) is not self.__token:
                _error("attestation_attempt_boundary_mismatch")
            if entry[1] != (checked_workspace, checked_artifact):
                _error("attestation_attempt_tampered")
            return checked_attempt_id, checked_workspace, checked_artifact, entry[1], entry[2], entry[3]

    def _validate_attempt_projection(self, attempt: RevalidationAttempt) -> None:
        self._owned(attempt)

    def finalize(self, attempt: RevalidationAttempt, event: Any) -> AttestationRevalidationEvent:
        attempt_id, workspace, artifact, _, _, _ = self._owned(attempt)
        normalized = AttestationRevalidationEvent.from_untrusted(event)
        if normalized.revalidation_attempt_id != attempt_id or normalized.workspace_identity != workspace or normalized.artifact_id != artifact:
            _error("attestation_attempt_boundary_mismatch")
        with self.__lock:
            entry = self.__attempts.get(attempt_id)
            if entry is None or entry[0]() is not attempt:
                _error("attestation_attempt_boundary_mismatch")
            current_digest = entry[2]
            if current_digest is None:
                snapshot = _event_snapshot(normalized)
                self.__attempts[attempt_id] = (entry[0], entry[1], normalized.event_payload_digest, normalized, snapshot)
                return normalized
            registered = entry[3]
            snapshot = entry[4]
            try:
                registered_snapshot = _event_snapshot(registered)
            except PersistenceContractError:
                _error("attestation_persistence_payload_invalid")
            if registered is None or snapshot is None or registered_snapshot != snapshot:
                _error("attestation_persistence_payload_invalid")
            if current_digest == normalized.event_payload_digest:
                return entry[3]  # type: ignore[return-value]
            _error("attestation_revalidation_event_conflict")

    def owns(self, attempt: Any) -> bool:
        try:
            self._owned(attempt)
            return True
        except PersistenceContractError:
            return False


__all__ = [
    "ARTIFACT_CONTRACT_VERSION", "REFERENCE_CONTRACT_VERSION", "ATTEMPT_CONTRACT_VERSION",
    "EVENT_IDENTITY_VERSION", "EVENT_PAYLOAD_VERSION", "ATTESTATION_REVALIDATION_FAILURE_CODES",
    "FUTURE_STORE_ERROR_CODES", "PersistenceContractError", "AttemptEntropySource",
    "PersistedAttestationArtifact", "AttestationBindingReference", "RevalidationAttempt",
    "RevalidationAttemptBoundary", "AttestationRevalidationEvent", "validate_artifact_aggregate",
]
