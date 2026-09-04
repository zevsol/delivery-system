"""Offline GitHub App installation capability evidence provider.

This module deliberately stops at an injected, normalized evidence source and
an injected Host signer.  It does not acquire credentials, access secrets, or
perform network I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any, Callable, Mapping, Protocol
import unicodedata

from delivery_system.attestation import (
    CredentialCapabilityAttestationClaims,
    CredentialCapabilityProvider,
    CredentialCapabilityRequest,
    SignedCredentialCapabilityAttestation,
)
from delivery_system.drivers.contract import normalize_repository_identity
from delivery_system.protocol import canonical_payload, digest


SOURCE_VERIFICATION_DOMAIN = "delivery-system:github-app-installation-capability-evidence:v1"
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
_SUPPORTED_REQUIREMENTS = ("issues:write",)
GITHUB_APP_INSTALLATION_CREDENTIAL_CLASS = "github-app-installation-token"
_PERMISSIONS = frozenset({"issues"})


class GitHubAppCapabilityProviderError(ValueError):
    """Stable, secret-free error raised at the provider boundary."""

    def __init__(self, code: str = "github_app_capability_evidence_invalid") -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class GitHubAppInstallationEvidenceRequest:
    """Sanitized input sent to the evidence source."""

    repository_identity: str
    required_capabilities: tuple[str, ...]
    credential_instance_id: str


@dataclass(frozen=True)
class GitHubAppInstallationCapabilityEvidence:
    """Immutable, secret-free normalized GitHub App installation evidence."""

    app_id: int
    installation_id: int
    installation_account_identity: str
    repository_id: int
    repository_identity: str
    repository_scope: tuple[str, ...]
    effective_permissions: tuple[tuple[str, str], ...]
    expires_at: str
    observed_at: str
    credential_instance_id: str


def github_app_installation_principal(app_id: int, installation_id: int) -> str:
    return f"github-app-installation-{app_id}-{installation_id}"


class GitHubAppInstallationEvidenceSource(Protocol):
    """Injected source of normalized, secret-free installation evidence."""

    def obtain(
        self, request: GitHubAppInstallationEvidenceRequest
    ) -> GitHubAppInstallationCapabilityEvidence | Mapping[str, Any]: ...


class HostAttestationSigner(Protocol):
    """Injected Host signing seam; key lifecycle is outside this Slice."""

    issuer_id: str
    key_id: str
    signature_algorithm: str

    def sign(self, canonical_claims_payload: bytes) -> str: ...


def _text(value: Any, field: str) -> str:
    if type(value) is not str:
        raise GitHubAppCapabilityProviderError(f"{field}_invalid")
    value = unicodedata.normalize("NFC", value).strip()
    if not value or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise GitHubAppCapabilityProviderError(f"{field}_invalid")
    return value


def _id(value: Any, field: str) -> str:
    value = _text(value, field)
    if not _ID_RE.fullmatch(value):
        raise GitHubAppCapabilityProviderError(f"{field}_invalid")
    return value


def _positive_int(value: Any, field: str) -> int:
    if type(value) is not int or value < 1:
        raise GitHubAppCapabilityProviderError(f"{field}_invalid")
    return value


def _utc(value: Any, field: str) -> tuple[str, datetime]:
    value = _text(value, field)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GitHubAppCapabilityProviderError(f"{field}_invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise GitHubAppCapabilityProviderError(f"{field}_invalid")
    normalized = parsed.astimezone(timezone.utc)
    return normalized.isoformat().replace("+00:00", "Z"), normalized


def _now(value: Any) -> datetime:
    if type(value) is not datetime or value.tzinfo is not timezone.utc:
        raise GitHubAppCapabilityProviderError("provider_clock_invalid")
    return value


def _normalize_permissions(value: Any) -> tuple[tuple[str, str], ...]:
    if type(value) is dict:
        entries = list(value.items())
    elif type(value) is tuple:
        entries = []
        for entry in value:
            if type(entry) is not tuple or len(entry) != 2:
                raise GitHubAppCapabilityProviderError("effective_permissions_invalid")
            entries.append((entry[0], entry[1]))
    else:
        raise GitHubAppCapabilityProviderError("effective_permissions_invalid")
    normalized: list[tuple[str, str]] = []
    seen: set[str] = set()
    for key, permission in entries:
        if type(key) is not str or key in seen or key not in _PERMISSIONS:
            raise GitHubAppCapabilityProviderError("effective_permissions_invalid")
        seen.add(key)
        permission = _text(permission, "effective_permission")
        if permission not in {"read", "write"}:
            raise GitHubAppCapabilityProviderError("effective_permissions_invalid")
        normalized.append((key, permission))
    return tuple(sorted(normalized))


def _normalize_evidence(value: Any) -> GitHubAppInstallationCapabilityEvidence:
    dataclass_input = type(value) is GitHubAppInstallationCapabilityEvidence
    if dataclass_input:
        raw = {field: getattr(value, field) for field in value.__dataclass_fields__}
    elif type(value) is dict:
        required = {
            "app_id", "installation_id", "installation_account_identity", "repository_id",
            "repository_identity", "repository_scope", "effective_permissions", "expires_at",
            "observed_at", "credential_instance_id",
        }
        if any(type(key) is not str for key in value):
            raise GitHubAppCapabilityProviderError("evidence_shape_invalid")
        if set(value) != required:
            raise GitHubAppCapabilityProviderError("evidence_shape_invalid")
        raw = dict(value)
    else:
        raise GitHubAppCapabilityProviderError("evidence_shape_invalid")
    try:
        repository_identity = normalize_repository_identity(_text(raw["repository_identity"], "repository_identity"))
    except (GitHubAppCapabilityProviderError, ValueError):
        raise GitHubAppCapabilityProviderError("repository_identity_invalid") from None
    scope = raw["repository_scope"]
    if dataclass_input:
        valid_scope = type(scope) is tuple
    else:
        valid_scope = type(scope) is list or type(scope) is tuple
    if not valid_scope or len(scope) != 1:
        raise GitHubAppCapabilityProviderError("repository_scope_invalid")
    try:
        normalized_scope = (normalize_repository_identity(_text(scope[0], "repository_scope")),)
    except (GitHubAppCapabilityProviderError, ValueError):
        raise GitHubAppCapabilityProviderError("repository_scope_invalid") from None
    if normalized_scope[0] != repository_identity:
        raise GitHubAppCapabilityProviderError("repository_scope_invalid")
    permissions = _normalize_permissions(raw["effective_permissions"])
    expires_at, _ = _utc(raw["expires_at"], "expires_at")
    observed_at, _ = _utc(raw["observed_at"], "observed_at")
    return GitHubAppInstallationCapabilityEvidence(
        app_id=_positive_int(raw["app_id"], "app_id"),
        installation_id=_positive_int(raw["installation_id"], "installation_id"),
        installation_account_identity=_text(raw["installation_account_identity"], "installation_account_identity"),
        repository_id=_positive_int(raw["repository_id"], "repository_id"),
        repository_identity=repository_identity,
        repository_scope=normalized_scope,
        effective_permissions=permissions,
        expires_at=expires_at,
        observed_at=observed_at,
        credential_instance_id=_id(raw["credential_instance_id"], "credential_instance_id"),
    )


def _permission(evidence: GitHubAppInstallationCapabilityEvidence, name: str) -> str | None:
    return dict(evidence.effective_permissions).get(name)


def github_app_installation_source_verification_digest(
    evidence: GitHubAppInstallationCapabilityEvidence, request: Mapping[str, Any]
) -> str:
    return digest({
        "domain": SOURCE_VERIFICATION_DOMAIN,
        "evidence": {
            "app_id": evidence.app_id,
            "installation_id": evidence.installation_id,
            "installation_account_identity": evidence.installation_account_identity,
            "repository_id": evidence.repository_id,
            "repository_identity": evidence.repository_identity,
            "repository_scope": list(evidence.repository_scope),
            "effective_permissions": {key: value for key, value in evidence.effective_permissions},
            "observed_at": evidence.observed_at,
            "expires_at": evidence.expires_at,
            "credential_instance_id": evidence.credential_instance_id,
        },
        "request_binding": {
            key: request[key] for key in (
                "repository_identity", "required_capabilities", "github_subject_identity",
                "driver_identity", "remote_authority", "preview_id", "revision",
                "operation_set_digest", "remote_snapshot_digest", "evidence_digest",
                "challenge_digest",
            )
        },
    })


class GitHubAppCredentialCapabilityProvider(CredentialCapabilityProvider):
    """Concrete offline provider behind the existing Attestation V2 boundary."""

    def __init__(
        self,
        evidence_source: GitHubAppInstallationEvidenceSource,
        signer: HostAttestationSigner,
        *,
        clock: Callable[[], datetime],
        credential_instance_id_factory: Callable[[], str],
        nonce_factory: Callable[[], str],
    ) -> None:
        self.__evidence_source = evidence_source
        self.__signer = signer
        self.__clock = clock
        self.__credential_instance_id_factory = credential_instance_id_factory
        self.__nonce_factory = nonce_factory

    def __repr__(self) -> str:
        return "<GitHubAppCredentialCapabilityProvider offline>"

    @staticmethod
    def _dependency_call(call: Callable[[], Any]) -> Any:
        try:
            return call()
        except Exception:
            raise GitHubAppCapabilityProviderError("github_app_capability_provider_failed") from None

    def _snapshot_evidence(self, value: Any) -> Any:
        if isinstance(value, Mapping):
            return self._dependency_call(lambda: dict(value))
        return value

    @staticmethod
    def _request_values(request: CredentialCapabilityRequest) -> dict[str, Any]:
        repository_identity = normalize_repository_identity(request.repository_identity)
        required = tuple(request.required_capabilities)
        if required != _SUPPORTED_REQUIREMENTS:
            raise GitHubAppCapabilityProviderError("unsupported_capability_requirement")
        return {
            "repository_identity": repository_identity,
            "required_capabilities": required,
            "github_subject_identity": _text(request.github_subject_identity, "github_subject_identity"),
            "driver_identity": _text(request.driver_identity, "driver_identity"),
            "remote_authority": request.remote_authority,
            "preview_id": request.preview_id,
            "revision": request.revision,
            "operation_set_digest": request.operation_set_digest,
            "remote_snapshot_digest": request.remote_snapshot_digest,
            "evidence_digest": request.evidence_digest,
            "challenge_digest": request.challenge_digest,
        }

    def attest(self, request: CredentialCapabilityRequest) -> SignedCredentialCapabilityAttestation:
        try:
            if not isinstance(request, CredentialCapabilityRequest):
                raise GitHubAppCapabilityProviderError("request_invalid")
            values = self._request_values(request)
            instance_id = _id(
                self._dependency_call(self.__credential_instance_id_factory),
                "credential_instance_id",
            )
            sanitized = GitHubAppInstallationEvidenceRequest(
                values["repository_identity"], values["required_capabilities"], instance_id
            )
            evidence = _normalize_evidence(
                self._snapshot_evidence(
                    self._dependency_call(lambda: self.__evidence_source.obtain(sanitized))
                )
            )
            now = _now(self._dependency_call(self.__clock))
            _, observed = _utc(evidence.observed_at, "observed_at")
            _, expires = _utc(evidence.expires_at, "expires_at")
            if evidence.credential_instance_id != instance_id:
                raise GitHubAppCapabilityProviderError("credential_instance_mismatch")
            if evidence.repository_identity != values["repository_identity"] or evidence.repository_scope != (values["repository_identity"],):
                raise GitHubAppCapabilityProviderError("repository_scope_mismatch")
            if observed > now:
                raise GitHubAppCapabilityProviderError("evidence_observed_in_future")
            if now >= expires:
                raise GitHubAppCapabilityProviderError("evidence_expired")
            granted = ("issues:write",) if _permission(evidence, "issues") == "write" else ()
            source_digest = github_app_installation_source_verification_digest(
                evidence, {**values, "repository_identity": values["repository_identity"]}
            )
            try:
                raw_issuer_id = self.__signer.issuer_id
                raw_key_id = self.__signer.key_id
                raw_algorithm = self.__signer.signature_algorithm
            except Exception:
                raise GitHubAppCapabilityProviderError("github_app_capability_provider_failed") from None
            issuer_id = _id(raw_issuer_id, "issuer_id")
            key_id = _id(raw_key_id, "key_id")
            algorithm = _id(raw_algorithm, "signature_algorithm")
            issued_at = now.isoformat().replace("+00:00", "Z")
            nonce = _id(self._dependency_call(self.__nonce_factory), "nonce")
            claims = CredentialCapabilityAttestationClaims(
                attestation_version="2", attestation_id="", issuer_id=issuer_id, key_id=key_id,
                signature_algorithm=algorithm, credential_class=GITHUB_APP_INSTALLATION_CREDENTIAL_CLASS,
                credential_instance_id=instance_id,
                github_subject_identity=values["github_subject_identity"],
                repository_identity=values["repository_identity"], granted_capabilities=granted,
                driver_identity=values["driver_identity"], remote_authority=values["remote_authority"],
                preview_id=values["preview_id"], revision=values["revision"],
                operation_set_digest=values["operation_set_digest"],
                remote_snapshot_digest=values["remote_snapshot_digest"], evidence_digest=values["evidence_digest"],
                issued_at=issued_at, expires_at=evidence.expires_at, nonce=nonce,
                source_verification_digest=source_digest, challenge_digest=values["challenge_digest"],
                credential_principal_identity=github_app_installation_principal(evidence.app_id, evidence.installation_id),
            )
            payload = canonical_payload(claims.to_payload()).encode("utf-8")
            proof = self._dependency_call(lambda: self.__signer.sign(payload))
            if type(proof) is not str:
                raise GitHubAppCapabilityProviderError("github_app_capability_provider_failed")
            return SignedCredentialCapabilityAttestation(claims, proof)
        except GitHubAppCapabilityProviderError:
            raise
        except Exception as exc:
            raise GitHubAppCapabilityProviderError("github_app_capability_provider_failed") from None
