"""Deterministic, failure-closed validation of read-only Driver facts."""

from __future__ import annotations

from dataclasses import dataclass
from weakref import WeakKeyDictionary
import threading
from typing import Mapping, Sequence

from delivery_system.evidence import EvidenceRecord
from delivery_system.protocol import canonical_payload, digest
from delivery_system.remote_snapshot import TypedRemoteSnapshot

from .contract import (
    DriverReadResponse,
    ReadOnlyDriver,
    RuntimeEvidenceBinding,
    DriverTrustContext,
    ValidatedRemoteFacts,
    RuntimeEvidenceBindingResult,
    DriverError,
    normalize_repository_identity,
)


MINIMUM_PERMISSIONS = ("read",)
MINIMUM_CAPABILITIES = ("issues", "relationships")
SUPPORTED_VISIBILITIES = frozenset({"public", "private", "internal"})
RUNTIME_EVIDENCE_KEYS = frozenset({"workspace_identity", "preview_id", "revision", "evidence_id", "verification_status"})
_VALIDATION_TICKET = object()
_VALIDATED_FACTS: WeakKeyDictionary[ValidatedRemoteFacts, object] = WeakKeyDictionary()
_VALIDATED_FACTS_LOCK = threading.RLock()


@dataclass(frozen=True)
class PreflightFailure:
    code: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "detail": self.detail}


@dataclass(frozen=True)
class PreflightResult:
    passed: bool
    repository_identity: str | None
    snapshot: TypedRemoteSnapshot | None
    evidence_records: tuple[EvidenceRecord, ...]
    failures: tuple[PreflightFailure, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "passed": self.passed,
            "repository_identity": self.repository_identity,
            "snapshot": self.snapshot.to_dict() if self.snapshot else None,
            "evidence_ids": [record.evidence_id for record in self.evidence_records],
            "failures": [failure.to_dict() for failure in self.failures],
        }


def _failure(code: str, detail: str) -> PreflightFailure:
    return PreflightFailure(code, detail)


def _valid_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _invalid_response(response: object) -> tuple[PreflightFailure, ...]:
    if not isinstance(response, DriverReadResponse):
        return (_failure("driver_response_invalid", "Driver returned an unexpected response type"),)
    return ()


def _validate_scope(scope: Mapping[str, object], expected: Mapping[str, object]) -> bool:
    try:
        return canonical_payload(scope) == canonical_payload(expected)
    except (TypeError, ValueError):
        return False


def _valid_mapping_items(value: object, *, allow_unknown: bool = False) -> bool:
    if not isinstance(value, Mapping):
        return False
    return all(
        isinstance(key, str) and bool(key.strip()) and isinstance(item, (bool, type(None)))
        for key, item in value.items()
    )


def _valid_record_sequence(value: object) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes)) and all(isinstance(item, Mapping) for item in value)


def _response_shape_is_valid(response: DriverReadResponse) -> bool:
    return (
        isinstance(response.permissions, Mapping)
        and _valid_mapping_items(response.permissions)
        and isinstance(response.capabilities, Mapping)
        and _valid_mapping_items(response.capabilities)
        and isinstance(response.query_scope, Mapping)
        and _valid_record_sequence(response.issue_records)
        and _valid_record_sequence(response.relationship_records)
        and _valid_record_sequence(response.evidence_material)
        and isinstance(response.query_complete, bool)
        and isinstance(response.pagination_complete, bool)
        and _valid_string(response.remote_content_digest)
    )


def _normalize_requirements(values: Sequence[str] | None, minimum: tuple[str, ...]) -> tuple[str, ...] | None:
    if values is None:
        values = ()
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        return None
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            return None
        value = value.strip()
        if value in normalized:
            return None
        normalized.append(value)
    return tuple(dict.fromkeys((*minimum, *normalized)))


def _remote_content_payload(response: DriverReadResponse, canonical: str, trusted_identity: str) -> dict[str, object]:
    payload: dict[str, object] = {
        "requested_repository": response.requested_repository,
        "canonical_repository": canonical,
        "remote_repository_id": response.remote_repository_id,
        "authenticated_subject": response.authenticated_subject,
        "visibility": response.visibility,
        "permissions": dict(response.permissions),
        "capabilities": dict(response.capabilities),
        "query_scope": dict(response.query_scope),
        "query_complete": response.query_complete,
        "pagination_complete": response.pagination_complete,
        "issue_records": list(response.issue_records),
        "relationship_records": list(response.relationship_records),
        "evidence_material": list(response.evidence_material),
        "source_identity": trusted_identity,
    }
    optional = {
        "schema_version": "github-rest-remote-content-v1" if any(value is not None for value in (
            response.remote_repository_node_id, response.authenticated_user_id,
            response.authenticated_user_node_id, response.authenticated_login)) else None,
        "remote_repository_node_id": response.remote_repository_node_id,
        "authenticated_user_id": response.authenticated_user_id,
        "authenticated_user_node_id": response.authenticated_user_node_id,
        "authenticated_login": response.authenticated_login,
    }
    payload.update({key: value for key, value in optional.items() if value is not None})
    return payload


def validate_driver_facts(
    driver: ReadOnlyDriver, repository: str, query_scope: Mapping[str, object],
    trusted_driver_identity: str, *, required_permissions: Sequence[str] | None = None,
    required_capabilities: Sequence[str] | None = None,
) -> tuple[ValidatedRemoteFacts | None, tuple[PreflightFailure, ...]]:
    """Phase one: one read, validation, and immutable facts only."""
    try:
        requested = normalize_repository_identity(repository)
    except ValueError:
        return None, (_failure("repository_identity_invalid", "Requested repository is not owner/name"),)
    permissions = _normalize_requirements(required_permissions, MINIMUM_PERMISSIONS)
    capabilities = _normalize_requirements(required_capabilities, MINIMUM_CAPABILITIES)
    if permissions is None or capabilities is None:
        return None, (_failure("requirements_invalid", "Required permissions and capabilities must be non-empty strings"),)
    if not _valid_string(trusted_driver_identity) or not isinstance(query_scope, Mapping) or not query_scope:
        return None, (_failure("driver_identity_untrusted", "Trusted Driver identity or query scope is invalid"),)
    try:
        response = driver.read_repository(repository, query_scope)
    except DriverError as exc:
        return None, (_failure(exc.code, "Driver read failed"),)
    except Exception:
        return None, (_failure("driver_call_failed", "Driver read failed"),)
    failures = list(_invalid_response(response))
    if failures:
        return None, tuple(failures)
    assert isinstance(response, DriverReadResponse)
    if not _response_shape_is_valid(response):
        return None, (_failure("driver_response_invalid", "Driver returned malformed read facts"),)
    if not _valid_string(response.source_identity) or response.source_identity != trusted_driver_identity:
        return None, (_failure("driver_identity_untrusted", "Response source identity does not match trusted Driver identity"),)
    if response.requested_repository != repository:
        failures.append(_failure("requested_repository_mismatch", "Driver did not preserve the requested repository"))
    try:
        canonical = normalize_repository_identity(response.canonical_repository)
    except ValueError:
        canonical = None
        failures.append(_failure("remote_identity_unknown", "Canonical repository identity is invalid"))
    if canonical != requested:
        failures.append(_failure("repository_identity_mismatch", "Requested and remote repository identities differ"))
    if not _valid_string(response.remote_repository_id): failures.append(_failure("remote_identity_unknown", "Stable remote repository identity is missing"))
    if not _valid_string(response.authenticated_subject): failures.append(_failure("authenticated_subject_unknown", "Authenticated remote subject is missing"))
    if not _valid_string(response.visibility) or response.visibility not in SUPPORTED_VISIBILITIES: failures.append(_failure("repository_visibility_unknown", "Repository visibility is missing or unsupported"))
    for permission in permissions:
        value = response.permissions.get(permission)
        if value is None: failures.append(_failure("permission_unknown", permission))
        elif value is not True: failures.append(_failure("permission_insufficient", permission))
    for capability in capabilities:
        value = response.capabilities.get(capability)
        if value is None: failures.append(_failure("capability_unknown", capability))
        elif value is not True: failures.append(_failure("capability_insufficient", capability))
    if not response.query_complete: failures.append(_failure("query_scope_incomplete", "Remote query scope is incomplete"))
    if not response.pagination_complete: failures.append(_failure("pagination_incomplete", "Remote result pagination is incomplete"))
    if not _validate_scope(response.query_scope, query_scope): failures.append(_failure("query_scope_mismatch", "Driver response scope differs from requested scope"))
    for record in response.evidence_material:
        if RUNTIME_EVIDENCE_KEYS.intersection(record): failures.append(_failure("driver_response_invalid", "Driver Evidence material contains Runtime-owned identity")); break
        if record.get("source_identity") != trusted_driver_identity: failures.append(_failure("evidence_source_untrusted", "Evidence source identity does not match trusted Driver identity")); break
        if record.get("repository_identity") != canonical or not _validate_scope(record.get("query_scope"), response.query_scope): failures.append(_failure("evidence_scope_invalid", "Evidence scope does not match the remote read")); break
        payload = record.get("payload")
        if not isinstance(payload, Mapping) or payload.get("issue_records") != list(response.issue_records) or payload.get("relationship_records") != list(response.relationship_records): failures.append(_failure("evidence_remote_content_mismatch", "Evidence payload does not match remote records")); break
    if not response.evidence_material: failures.append(_failure("evidence_missing", "At least one scoped Driver Evidence material is required"))
    if failures or canonical is None: return None, tuple(failures)
    content_payload = _remote_content_payload(response, canonical, trusted_driver_identity)
    try: content_digest = digest(content_payload)
    except (TypeError, ValueError): return None, (_failure("driver_response_invalid", "Remote facts cannot be canonicalized"),)
    if response.remote_content_digest != content_digest: return None, (_failure("remote_state_inconsistent", "Driver content digest does not match remote facts"),)
    facts = ValidatedRemoteFacts(response, content_payload, content_digest, _validation_ticket=_VALIDATION_TICKET)
    with _VALIDATED_FACTS_LOCK:
        _VALIDATED_FACTS[facts] = _VALIDATION_TICKET
    return facts, ()


def bind_validated_facts(
    facts: ValidatedRemoteFacts, binding: RuntimeEvidenceBinding, trust_context: DriverTrustContext,
) -> RuntimeEvidenceBindingResult:
    """Phase two: bind verified facts to final Runtime identity exactly once."""
    response = facts.response
    with _VALIDATED_FACTS_LOCK:
        ticket = _VALIDATED_FACTS.pop(facts, None) if isinstance(facts, ValidatedRemoteFacts) else None
    if ticket is not _VALIDATION_TICKET or facts._validation_ticket is not _VALIDATION_TICKET:
        raise ValueError("validated_remote_facts_required")
    expected_payload = _remote_content_payload(response, response.canonical_repository, trust_context.trusted_driver_identity)
    if facts.canonical_remote_content_payload != expected_payload or facts.remote_content_digest != digest(expected_payload):
        raise ValueError("validated_remote_facts_mismatch")
    if response.source_identity != trust_context.trusted_driver_identity:
        raise ValueError("driver_identity_untrusted")
    evidence = EvidenceRecord.create_verified_driver(
        binding.workspace_identity, binding.preview_id, binding.revision,
        "driver_remote_read", f"repository:{response.canonical_repository}",
        facts.canonical_remote_content_payload, trust_context.trusted_driver_identity,
        response.canonical_repository, response.query_scope,
    )
    snapshot = TypedRemoteSnapshot.from_records(
        response.canonical_repository, response.query_scope, response.query_complete,
        response.pagination_complete, list(response.issue_records),
        {key: value for key, value in response.permissions.items() if isinstance(value, bool)},
        [key for key, value in response.capabilities.items() if value is True],
        list(response.relationship_records), evidence_ids=[evidence.evidence_id],
    )
    from delivery_system.runtime import RuntimePromotion
    promotion = RuntimePromotion._create(trust_context, evidence, snapshot, facts.remote_content_digest, snapshot.digest())
    return RuntimeEvidenceBindingResult(binding, trust_context, evidence, snapshot, snapshot.digest(), promotion)


def run_preflight(
    driver: ReadOnlyDriver,
    repository: str,
    query_scope: Mapping[str, object],
    evidence_binding: RuntimeEvidenceBinding,
    trusted_driver_identity: str,
    *,
    required_permissions: Sequence[str] | None = None,
    required_capabilities: Sequence[str] | None = None,
) -> PreflightResult:
    """Read and validate Driver facts without creating other Runtime state."""
    try: requested = normalize_repository_identity(repository)
    except ValueError: return PreflightResult(False, None, None, (), (_failure("repository_identity_invalid", "Requested repository is not owner/name"),))
    if (not isinstance(evidence_binding, RuntimeEvidenceBinding)
            or not _valid_string(evidence_binding.workspace_identity)
            or not _valid_string(evidence_binding.preview_id)
            or not isinstance(evidence_binding.revision, int)
            or isinstance(evidence_binding.revision, bool)
            or evidence_binding.revision < 1):
        return PreflightResult(False, requested, None, (), (_failure("driver_evidence_binding_invalid", "Runtime evidence binding is invalid"),))
    facts, failures = validate_driver_facts(driver, repository, query_scope, trusted_driver_identity, required_permissions=required_permissions, required_capabilities=required_capabilities)
    if failures or facts is None:
        return PreflightResult(False, requested, None, (), failures)
    response = facts.response
    canonical = response.canonical_repository
    try:
        bound = bind_validated_facts(facts, evidence_binding, DriverTrustContext(trusted_driver_identity, "offline://driver", "offline-v1"))
    except (TypeError, ValueError, KeyError):
        return PreflightResult(False, canonical, None, (), (_failure("remote_state_inconsistent", "Remote records are not a valid TypedRemoteSnapshot"),))
    return PreflightResult(True, canonical, bound.snapshot, (bound.evidence_record,), ())
