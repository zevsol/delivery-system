"""Offline Runtime orchestration for the credential attestation contract.

This module consumes existing Runtime-owned Preview, Evidence, and Audit
state.  It does not persist attestations, implement credentials or crypto, or
make a WriteEligible decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import re
import threading
from typing import Any, Callable, Mapping, Protocol, Sequence
import weakref

from delivery_system.attestation import (
    AttestationRuntimeBoundary,
    CredentialCapabilityProvider,
    CredentialCapabilityRequest,
    CredentialCapabilityAttestationClaims,
    SignedCredentialCapabilityAttestation,
)
from delivery_system.drivers.contract import DriverTrustContext
from delivery_system.evidence import EvidenceRecord
from delivery_system.protocol import canonical_payload
from delivery_system.runtime import (
    AuditContextService,
    AuditRecord,
    AuditResult,
    AuditStatus,
    PreviewLevel,
    RuntimeContext,
)


class RuntimeCapabilityRequirementResolver(Protocol):
    """Resolve the minimum capabilities from canonical Runtime operations."""

    def resolve(self, operation_intents: Sequence[Mapping[str, Any]]) -> Sequence[str]: ...


@dataclass(frozen=True)
class RuntimeAttestationFailure:
    code: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code}


class RuntimeCredentialCapabilityBinding:
    """Runtime-owned ephemeral result; construction is service-internal."""

    __slots__ = (
        "binding_id", "workspace_identity", "attestation_version", "attestation_id", "claims_digest",
        "credential_instance_id", "issuer_id", "key_id", "algorithm", "credential_class",
        "credential_principal_identity", "challenge_digest", "repository_identity", "github_subject_identity", "required_capabilities",
        "granted_capabilities", "driver_identity", "remote_authority", "preview_id", "revision",
        "plan_digest", "sealed_preview_digest", "operation_set_digest", "remote_snapshot_digest",
        "evidence_id", "evidence_digest", "audit_id", "audit_digest", "source_verification_digest",
        "issued_at", "expires_at", "verified_at", "__weakref__",
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise ValueError("runtime_binding_internal_only")

    def __setattr__(self, name: str, value: Any) -> None:
        raise ValueError("runtime_binding_immutable")

    def __copy__(self) -> "RuntimeCredentialCapabilityBinding":
        raise ValueError("runtime_binding_copy_forbidden")

    def __deepcopy__(self, memo: dict[int, Any]) -> "RuntimeCredentialCapabilityBinding":
        raise ValueError("runtime_binding_copy_forbidden")

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__slots__ if not name.endswith("__weakref__")}

    def __repr__(self) -> str:
        return "<RuntimeCredentialCapabilityBinding protected>"


@dataclass(frozen=True)
class RuntimeAttestationResult:
    binding: RuntimeCredentialCapabilityBinding | None
    failures: tuple[RuntimeAttestationFailure, ...]

    @property
    def success(self) -> bool:
        return self.binding is not None and not self.failures

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "binding": self.binding.to_dict() if self.binding is not None else None,
            "failures": [failure.to_dict() for failure in self.failures],
        }


def _failure(code: str) -> RuntimeAttestationResult:
    return RuntimeAttestationResult(None, (RuntimeAttestationFailure(code),))


def _utc_now(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("current_time_invalid")
    return value.astimezone(timezone.utc)


def _subject_from_payload(payload: Any) -> str | None:
    if not isinstance(payload, Mapping):
        return None
    for field in ("authenticated_user_node_id", "authenticated_user_id", "authenticated_subject"):
        value = payload.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _normalise_requirements(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise ValueError("attestation_capability_requirement_invalid")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError("attestation_capability_requirement_invalid")
    normalised = tuple(item.strip() for item in value)
    if len(set(normalised)) != len(normalised) or normalised != tuple(sorted(normalised)):
        raise ValueError("attestation_capability_requirement_invalid")
    return normalised


class RuntimeAttestationOrchestrationService:
    """Explicit Runtime-only bridge from sealed state to an ephemeral Binding."""

    def __init__(
        self,
        context: RuntimeContext,
        store: Any,
        trust_context: DriverTrustContext,
        boundary: AttestationRuntimeBoundary,
        provider: CredentialCapabilityProvider,
        capability_resolver: RuntimeCapabilityRequirementResolver,
        *,
        clock: Callable[[], datetime],
    ) -> None:
        if not isinstance(context, RuntimeContext) or not isinstance(trust_context, DriverTrustContext):
            raise TypeError("attestation_runtime_boundary_invalid")
        if not isinstance(boundary, AttestationRuntimeBoundary):
            raise TypeError("attestation_runtime_boundary_invalid")
        self.__context = context
        self.__store = store
        self.__trust = trust_context
        self.__boundary = boundary
        self.__provider = provider
        self.__resolver = capability_resolver
        self.__clock = clock
        self.__lock = threading.RLock()
        self.__bindings_by_id: dict[str, RuntimeCredentialCapabilityBinding] = {}
        self.__bindings_by_state: dict[tuple[Any, ...], RuntimeCredentialCapabilityBinding] = {}
        self.__binding_registry: weakref.WeakKeyDictionary[RuntimeCredentialCapabilityBinding, tuple[Any, str]] = weakref.WeakKeyDictionary()

    @staticmethod
    def _binding_fields(binding: RuntimeCredentialCapabilityBinding) -> dict[str, Any]:
        if type(binding) is not RuntimeCredentialCapabilityBinding:
            raise ValueError("attestation_binding_integrity_failed")
        return {
            name: object.__getattribute__(binding, name)
            for name in RuntimeCredentialCapabilityBinding.__slots__
            if not name.endswith("__weakref__")
        }

    @classmethod
    def _typed_binding_snapshot(cls, binding: RuntimeCredentialCapabilityBinding) -> tuple[tuple[str, str, Any], ...]:
        fields = cls._binding_fields(binding)
        capability_fields = {"required_capabilities", "granted_capabilities"}
        digest_fields = {
            "claims_digest", "plan_digest", "sealed_preview_digest",
            "operation_set_digest", "remote_snapshot_digest", "evidence_digest",
            "audit_digest", "source_verification_digest", "remote_authority",
        }
        snapshot: list[tuple[str, str, Any]] = []
        for name in RuntimeCredentialCapabilityBinding.__slots__:
            if name.endswith("__weakref__"):
                continue
            value = fields[name]
            if name == "revision":
                if type(value) is not int or value < 1:
                    raise ValueError("attestation_binding_integrity_failed")
                type_tag = "int"
            elif name in capability_fields:
                if type(value) is not tuple or not value or any(type(item) is not str or not item for item in value):
                    raise ValueError("attestation_binding_integrity_failed")
                if tuple(sorted(value)) != value or len(set(value)) != len(value):
                    raise ValueError("attestation_binding_integrity_failed")
                type_tag = "tuple[str]"
            elif name in {"issued_at", "expires_at", "verified_at"}:
                if type(value) is not str or not value:
                    raise ValueError("attestation_binding_integrity_failed")
                try:
                    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                    if parsed.tzinfo is None or parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
                        raise ValueError
                except (TypeError, ValueError):
                    raise ValueError("attestation_binding_integrity_failed")
                type_tag = "str:utc"
            else:
                if name in {"challenge_digest", "credential_principal_identity"} and fields.get("attestation_version") == "1":
                    if value != "":
                        raise ValueError("attestation_binding_integrity_failed")
                    type_tag = "legacy-empty"
                    snapshot.append((name, type_tag, value))
                    continue
                if type(value) is not str or not value:
                    raise ValueError("attestation_binding_integrity_failed")
                if name in digest_fields and not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
                    raise ValueError("attestation_binding_integrity_failed")
                type_tag = "str"
            snapshot.append((name, type_tag, value))
        return tuple(snapshot)

    @classmethod
    def _binding_contract(cls, binding: RuntimeCredentialCapabilityBinding) -> tuple[Any, str]:
        fields = cls._binding_fields(binding)
        cls._typed_binding_snapshot(binding)
        binding_id = fields.pop("binding_id")
        fields.pop("verified_at")
        payload = canonical_payload({
            "domain": "delivery-system:runtime-attestation-binding:v1",
            "binding": fields,
        })
        recomputed = "binding-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()
        snapshot = cls._typed_binding_snapshot(binding)
        if binding_id != recomputed:
            raise ValueError("attestation_binding_integrity_failed")
        return snapshot, recomputed

    def _registered_binding_is_intact(self, binding: RuntimeCredentialCapabilityBinding) -> bool:
        try:
            binding_id = object.__getattribute__(binding, "binding_id")
            registered = self.__bindings_by_id.get(binding_id)
            entry = self.__binding_registry.get(binding)
            if registered is not binding or entry is None:
                return False
            return entry == self._binding_contract(binding)
        except Exception:
            return False

    def _load_runtime_state(self, preview_id: str, revision: int) -> tuple[dict[str, Any], AuditRecord, EvidenceRecord, dict[str, Any]] | RuntimeAttestationResult:
        try:
            stored_preview = self.__store.get_preview(self.__context.workspace_identity, preview_id)
            stored_canonical = stored_preview.get("canonical_payload") if isinstance(stored_preview, Mapping) else None
            if not isinstance(stored_canonical, Mapping):
                stored_canonical = stored_preview
        except KeyError:
            return _failure("attestation_preview_not_found")
        except ValueError as exc:
            if str(exc) == "preview_not_found":
                return _failure("attestation_preview_not_found")
            return _failure("attestation_preview_integrity_invalid")
        except Exception:
            return _failure("attestation_preview_integrity_invalid")
        if not isinstance(stored_canonical, Mapping):
            return _failure("attestation_preview_integrity_invalid")
        if stored_canonical.get("workspace_identity") != self.__context.workspace_identity:
            return _failure("attestation_preview_integrity_invalid")
        stored_revision = stored_canonical.get("revision")
        if not isinstance(stored_revision, int) or isinstance(stored_revision, bool) or stored_revision < 1:
            return _failure("attestation_preview_integrity_invalid")
        if stored_revision != revision:
            return _failure("attestation_preview_stale")
        if stored_canonical.get("preview_level") != PreviewLevel.REPOSITORY_AWARE.value:
            return _failure("attestation_preview_not_repository_aware")
        try:
            context = AuditContextService(self.__context, self.__store, self.__trust).get(preview_id, revision)
        except KeyError:
            return _failure("attestation_preview_integrity_invalid")
        except (TypeError, ValueError) as exc:
            if str(exc) == "context_stale":
                return _failure("attestation_preview_stale")
            if str(exc) in {"evidence_missing", "evidence_not_found"}:
                return _failure("attestation_evidence_missing")
            return _failure("attestation_preview_integrity_invalid")
        except Exception:
            return _failure("attestation_preview_integrity_invalid")
        canonical = context.get("sealed_preview")
        if not isinstance(canonical, Mapping):
            return _failure("attestation_preview_integrity_invalid")
        if canonical.get("workspace_identity") != self.__context.workspace_identity:
            return _failure("attestation_preview_integrity_invalid")
        if canonical.get("preview_level") != PreviewLevel.REPOSITORY_AWARE.value:
            return _failure("attestation_preview_not_repository_aware")
        if canonical.get("preview_id") != preview_id or canonical.get("revision") != revision:
            return _failure("attestation_preview_stale")
        if not all(isinstance(canonical.get(field), str) and canonical.get(field) for field in (
            "plan_digest", "operation_set_digest", "sealed_preview_digest", "remote_snapshot_digest", "remote_authority",
        )):
            return _failure("attestation_preview_integrity_invalid")
        try:
            audits = self.__store.list_active_audits(self.__context.workspace_identity, preview_id, revision)
        except Exception:
            return _failure("attestation_audit_missing")
        if not audits:
            return _failure("attestation_audit_missing")
        if len(audits) != 1:
            return _failure("attestation_audit_ambiguous")
        audit = audits[0]
        if audit.status is not AuditStatus.ACTIVE:
            return _failure("attestation_audit_not_active")
        if audit.result is not AuditResult.PASSED:
            return _failure("attestation_audit_not_passed")
        if audit.audit_scope != PreviewLevel.REPOSITORY_AWARE.value or not audit.audit_context_digest:
            return _failure("attestation_audit_binding_mismatch")
        if not audit.verify_digest():
            return _failure("attestation_audit_binding_mismatch")
        audit_fields = {
            "workspace_identity": self.__context.workspace_identity,
            "preview_id": preview_id,
            "revision": revision,
            "plan_digest": canonical.get("plan_digest"),
            "operation_set_digest": canonical.get("operation_set_digest"),
            "remote_snapshot_digest": canonical.get("remote_snapshot_digest"),
            "sealed_preview_digest": canonical.get("sealed_preview_digest"),
        }
        if any(getattr(audit, field) != expected for field, expected in audit_fields.items()):
            return _failure("attestation_audit_binding_mismatch")
        evidence_data = context.get("evidence_records")
        if not isinstance(evidence_data, list):
            return _failure("attestation_evidence_missing")
        driver_records = [record for record in evidence_data if isinstance(record, Mapping) and record.get("source_kind") == "driver"]
        if not driver_records:
            return _failure("attestation_evidence_missing")
        if len(driver_records) != 1:
            return _failure("attestation_evidence_ambiguous")
        try:
            evidence = EvidenceRecord.from_dict(driver_records[0])
        except Exception:
            return _failure("attestation_evidence_binding_mismatch")
        if (
            evidence.evidence_type != "driver_remote_read"
            or evidence.verification_status != "driver_verified"
            or evidence.source_identity != self.__trust.trusted_driver_identity
            or evidence.workspace_identity != self.__context.workspace_identity
            or evidence.preview_id != preview_id
            or evidence.revision != revision
            or evidence.repository_identity != canonical.get("repository_identity")
        ):
            return _failure("attestation_evidence_binding_mismatch")
        subject = _subject_from_payload(evidence.payload)
        if subject is None:
            return _failure("attestation_subject_unavailable")
        return context, audit, evidence, {"subject": subject}

    def _create_request(self, canonical: Mapping[str, Any], audit: AuditRecord, evidence: EvidenceRecord, subject: str) -> CredentialCapabilityRequest | RuntimeAttestationResult:
        operations = canonical.get("operation_intents")
        if not isinstance(operations, list) or not operations or any(not isinstance(item, Mapping) for item in operations):
            return _failure("attestation_capability_requirement_invalid")
        try:
            required = _normalise_requirements(self.__resolver.resolve(tuple(dict(item) for item in operations)))
        except ValueError as exc:
            code = str(exc)
            if code == "attestation_capability_requirement_invalid":
                return _failure(code)
            return _failure("attestation_capability_resolution_unavailable")
        except Exception:
            return _failure("attestation_capability_resolution_unavailable")
        try:
            return self.__boundary.create_request(
                repository_identity=canonical["repository_identity"],
                github_subject_identity=subject,
                required_capabilities=required,
                driver_identity=evidence.source_identity,
                remote_authority=canonical["remote_authority"],
                preview_id=canonical["preview_id"],
                revision=canonical["revision"],
                operation_set_digest=canonical["operation_set_digest"],
                remote_snapshot_digest=canonical["remote_snapshot_digest"],
                evidence_digest=evidence.evidence_digest,
            )
        except Exception:
            return _failure("attestation_capability_requirement_invalid")

    @staticmethod
    def _binding_payload(values: Mapping[str, Any]) -> dict[str, Any]:
        return {key: values[key] for key in values if key != "verified_at"}

    def _make_binding(self, claims: CredentialCapabilityAttestationClaims, request: CredentialCapabilityRequest,
                      canonical: Mapping[str, Any], audit: AuditRecord, evidence: EvidenceRecord,
                      verified_at: datetime) -> RuntimeCredentialCapabilityBinding:
        values: dict[str, Any] = {
            "workspace_identity": self.__context.workspace_identity,
            "attestation_version": claims.attestation_version,
            "attestation_id": claims.attestation_id, "claims_digest": claims.claims_digest(),
            "credential_instance_id": claims.credential_instance_id, "issuer_id": claims.issuer_id,
            "key_id": claims.key_id, "algorithm": claims.signature_algorithm,
            "credential_class": claims.credential_class, "repository_identity": claims.repository_identity,
            "credential_principal_identity": claims.credential_principal_identity,
            "challenge_digest": claims.challenge_digest,
            "github_subject_identity": claims.github_subject_identity,
            "required_capabilities": request.required_capabilities,
            "granted_capabilities": claims.granted_capabilities, "driver_identity": claims.driver_identity,
            "remote_authority": claims.remote_authority, "preview_id": claims.preview_id,
            "revision": claims.revision, "plan_digest": canonical["plan_digest"],
            "sealed_preview_digest": canonical["sealed_preview_digest"],
            "operation_set_digest": claims.operation_set_digest,
            "remote_snapshot_digest": claims.remote_snapshot_digest, "evidence_id": evidence.evidence_id,
            "evidence_digest": claims.evidence_digest, "audit_id": audit.audit_id,
            "audit_digest": audit.audit_digest, "source_verification_digest": claims.source_verification_digest,
            "issued_at": claims.issued_at, "expires_at": claims.expires_at,
            "verified_at": verified_at.isoformat().replace("+00:00", "Z"),
        }
        binding_id = "binding-" + hashlib.sha256(canonical_payload({"domain": "delivery-system:runtime-attestation-binding:v1", "binding": self._binding_payload(values)}).encode("utf-8")).hexdigest()
        values["binding_id"] = binding_id
        binding = object.__new__(RuntimeCredentialCapabilityBinding)
        for field, value in values.items():
            object.__setattr__(binding, field, value)
        return binding

    def orchestrate(self, preview_id: str, revision: int) -> RuntimeAttestationResult:
        try:
            if not isinstance(preview_id, str) or not preview_id or not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
                return _failure("attestation_preview_not_found")
            with self.__lock:
                loaded = self._load_runtime_state(preview_id, revision)
                if isinstance(loaded, RuntimeAttestationResult):
                    return loaded
                context, audit, evidence, subject_data = loaded
                canonical = context["sealed_preview"]
                request_result = self._create_request(canonical, audit, evidence, subject_data["subject"])
                if isinstance(request_result, RuntimeAttestationResult):
                    return request_result
                request = request_result
                try:
                    envelope = self.__provider.attest(request)
                except Exception:
                    return _failure("attestation_provider_unavailable")
                if not isinstance(envelope, (Mapping, SignedCredentialCapabilityAttestation)):
                    return _failure("attestation_provider_response_invalid")
                try:
                    now = _utc_now(self.__clock())
                except Exception:
                    return _failure("attestation_provider_response_invalid")
                verification = self.__boundary.verify(envelope, request, now)
                if not verification.success or verification.verified is None:
                    code = verification.failures[0].code if verification.failures else "attestation_invalid"
                    return _failure(code)
                try:
                    claims = self.__boundary.consume_ticket(verification.verified)
                except Exception:
                    return _failure("attestation_ticket_consume_failed")
                try:
                    binding = self._make_binding(claims, request, canonical, audit, evidence, now)
                except Exception:
                    return _failure("attestation_provider_response_invalid")
                state_key = (
                    self.__context.workspace_identity, preview_id, revision,
                    canonical["plan_digest"], canonical["sealed_preview_digest"],
                    canonical["operation_set_digest"], canonical["remote_snapshot_digest"], evidence.evidence_id,
                    audit.audit_id, audit.audit_digest,
                )
                existing = self.__bindings_by_state.get(state_key)
                if existing is not None:
                    if not self._registered_binding_is_intact(existing):
                        return _failure("attestation_binding_integrity_failed")
                    if existing.attestation_id != binding.attestation_id or existing.claims_digest != binding.claims_digest:
                        return _failure("attestation_binding_conflict")
                    return RuntimeAttestationResult(existing, ())
                self.__bindings_by_state[state_key] = binding
                self.__bindings_by_id[binding.binding_id] = binding
                self.__binding_registry[binding] = self._binding_contract(binding)
                return RuntimeAttestationResult(binding, ())
        except Exception:
            return _failure("attestation_provider_response_invalid")

    def lookup_binding(self, binding_id: str) -> RuntimeCredentialCapabilityBinding | None:
        with self.__lock:
            binding = self.__bindings_by_id.get(binding_id)
            if binding is None or not self._registered_binding_is_intact(binding):
                return None
            return binding

    def accepts_binding(self, binding: RuntimeCredentialCapabilityBinding) -> bool:
        with self.__lock:
            return type(binding) is RuntimeCredentialCapabilityBinding and self._registered_binding_is_intact(binding)
