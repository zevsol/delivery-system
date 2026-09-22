"""Explicit production Host composition for the GitHub App write profile.

The module is inert on import.  ``compose_write_enabled_host`` is the only
operation that reads Host configuration, acquires credentials, and builds a
write-capable Runtime composition.  The default MCP server does not call it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from typing import Any, Callable, Mapping
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .attestation import AttestationRuntimeBoundary
from .attestation_github_app import (
    GitHubAppCredentialCapabilityProvider,
    GitHubAppInstallationCapabilityEvidence,
    GitHubAppInstallationEvidenceRequest,
    github_app_installation_principal,
)
from .attestation_key_source import FileEd25519PrivateKeySource, FileEd25519PublicKeySource
from .attestation_runtime import RuntimeAttestationOrchestrationService
from .attestation_signing import (
    Ed25519HostSigner,
    Ed25519ProofVerifier,
    TrustedEd25519IssuerKeyRegistry,
    TrustedEd25519Key,
)
from .authority_binding import Ed25519AuthorityBindingProofVerifier, Ed25519AuthorityBindingSigner
from .authority_binding_persistence import SQLiteAuthorityBindingPersistenceStore
from .drivers.contract import DriverTrustContext
from .drivers.rest import GitHubAppInstallationReadOnlyDriver
from .existing_endpoints import ExistingEndpointRevalidator
from .github_app_bootstrap import (
    GitHubAppBootstrapConfig,
    GitHubAppBootstrapTransport,
    FileGitHubAppPrivateKeySource,
    GitHubAppInstallationCredentialBootstrap,
    GitHubAppPrivateKeySource,
)
from .github_app_credential import GitHubAppInstallationCredentialLease
from .attestation_persistence_store import SQLiteAttestationPersistenceStore
from .restart_credential_verification import DefaultRestartCredentialAttestationVerifier
from .runtime import RuntimeApprovalAuthorityService, RuntimeContext, SQLitePreviewStore
from .execution_store import SQLiteExecutionStore
from .verified_attestation_artifact import VerifiedAttestationArtifactAdapter
from .host_revocation import ExternalRevocationReader, RevocationTransport


_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$\Z")
_DECIMAL_ID_RE = re.compile(r"^[0-9]{1,20}\Z")
_MAX_GITHUB_ID = (10 ** 20) - 1
_FAILED = object()


class HostCompositionError(ValueError):
    """Stable, secret-free error at the explicit Host composition boundary."""

    def __init__(self, code: str = "host_composition_failed") -> None:
        super().__init__(code)
        self.code = code


def _configuration_error() -> HostCompositionError:
    return HostCompositionError("host_configuration_invalid")


def _attempt(operation: Callable[[], Any]) -> Any:
    try:
        return operation()
    except Exception:
        return _FAILED


def _required_text(values: Mapping[str, str], name: str) -> str:
    value = values.get(name)
    if type(value) is not str or not value.strip():
        raise _configuration_error()
    return value.strip()


def _required_id(values: Mapping[str, str], name: str) -> int:
    value = _required_text(values, name)
    if _DECIMAL_ID_RE.fullmatch(value) is None:
        raise _configuration_error()
    parsed = int(value)
    if not 1 <= parsed <= _MAX_GITHUB_ID:
        raise _configuration_error()
    return parsed


def _required_path(values: Mapping[str, str], name: str) -> str:
    value = _required_text(values, name)
    if not os.path.isabs(value):
        raise _configuration_error()
    return value


def _optional_path(values: Mapping[str, str], name: str) -> str | None:
    value = values.get(name)
    if value is None or not value.strip():
        return None
    return _required_path(values, name)


def _required_timeout_ms(values: Mapping[str, str], name: str) -> int:
    value = _required_text(values, name)
    if not value.isdecimal():
        raise _configuration_error()
    parsed = int(value)
    if not 1 <= parsed <= 120_000:
        raise _configuration_error()
    return parsed


@dataclass(frozen=True)
class _HostEnvironmentField:
    name: str
    semantic_key: str
    state: str
    classification: str


_HOST_ENVIRONMENT_FIELDS = (
    _HostEnvironmentField("DELIVERY_SYSTEM_GITHUB_APP_ID", "github_app_id", "required", "non-secret"),
    _HostEnvironmentField("DELIVERY_SYSTEM_GITHUB_REPOSITORY", "github_repository", "required", "non-secret"),
    _HostEnvironmentField("DELIVERY_SYSTEM_GITHUB_REPOSITORY_ID", "github_repository_id", "required", "non-secret"),
    _HostEnvironmentField("DELIVERY_SYSTEM_GITHUB_APP_PRIVATE_KEY_PATH", "github_app_private_key_path", "required", "protected-reference"),
    _HostEnvironmentField("DELIVERY_SYSTEM_ATTESTATION_ISSUER_ID", "attestation_issuer_id", "required", "non-secret"),
    _HostEnvironmentField("DELIVERY_SYSTEM_ATTESTATION_KEY_ID", "attestation_key_id", "required", "non-secret"),
    _HostEnvironmentField("DELIVERY_SYSTEM_ATTESTATION_PRIVATE_KEY_PATH", "attestation_private_key_path", "required", "protected-reference"),
    _HostEnvironmentField("DELIVERY_SYSTEM_ATTESTATION_PUBLIC_KEY_PATH", "attestation_public_key_path", "required", "public-trust-material-reference"),
    _HostEnvironmentField("DELIVERY_SYSTEM_ATTESTATION_TRUSTED_KEYS_PATH", "attestation_trusted_keys_path", "required", "public-trust-material-reference"),
    _HostEnvironmentField("DELIVERY_SYSTEM_AUTHORITY_BINDING_ISSUER_ID", "authority_binding_issuer_id", "required", "non-secret"),
    _HostEnvironmentField("DELIVERY_SYSTEM_AUTHORITY_BINDING_ACTIVE_KEY_ID", "authority_binding_active_key_id", "required", "non-secret"),
    _HostEnvironmentField("DELIVERY_SYSTEM_AUTHORITY_BINDING_PRIVATE_KEY_PATH", "authority_binding_private_key_path", "required", "protected-reference"),
    _HostEnvironmentField("DELIVERY_SYSTEM_AUTHORITY_BINDING_PUBLIC_KEY_PATH", "authority_binding_public_key_path", "required", "public-trust-material-reference"),
    _HostEnvironmentField("DELIVERY_SYSTEM_AUTHORITY_BINDING_TRUSTED_KEYS_PATH", "authority_binding_trusted_keys_path", "required", "public-trust-material-reference"),
    _HostEnvironmentField("DELIVERY_SYSTEM_REVOCATION_PROVIDER_URL", "revocation_provider_url", "required", "non-secret"),
    _HostEnvironmentField("DELIVERY_SYSTEM_REVOCATION_TIMEOUT_MS", "revocation_timeout_ms", "required", "non-secret"),
    _HostEnvironmentField("DELIVERY_SYSTEM_REVOCATION_AUTH_TOKEN_PATH", "revocation_auth_token_path", "optional", "protected-reference"),
    _HostEnvironmentField("DELIVERY_SYSTEM_GITHUB_INSTALLATION_ID", "github_installation_id", "forbidden", "forbidden"),
)
_REQUIRED_ENVIRONMENT_FIELDS = tuple(field.name for field in _HOST_ENVIRONMENT_FIELDS if field.state == "required")
_OPTIONAL_ENVIRONMENT_FIELDS = tuple(field.name for field in _HOST_ENVIRONMENT_FIELDS if field.state == "optional")
_FORBIDDEN_ENVIRONMENT_FIELDS = tuple(field.name for field in _HOST_ENVIRONMENT_FIELDS if field.state == "forbidden")
_PROTECTED_REFERENCE_FIELDS = tuple(field.name for field in _HOST_ENVIRONMENT_FIELDS if field.classification == "protected-reference")
_PUBLIC_REFERENCE_FIELDS = tuple(field.name for field in _HOST_ENVIRONMENT_FIELDS if field.classification == "public-trust-material-reference")
_NON_SECRET_FIELDS = tuple(field.name for field in _HOST_ENVIRONMENT_FIELDS if field.classification == "non-secret")


@dataclass(frozen=True)
class HostConfiguration:
    """Non-secret Host inputs for the explicit GitHub App write profile."""

    github_app: GitHubAppBootstrapConfig
    attestation_issuer_id: str
    attestation_key_id: str
    attestation_private_key_path: str
    attestation_public_key_path: str
    attestation_trusted_keys_path: str
    authority_binding_issuer_id: str
    authority_binding_active_key_id: str
    authority_binding_private_key_path: str
    authority_binding_public_key_path: str
    authority_binding_trusted_keys_path: str
    revocation_provider_url: str
    revocation_timeout_ms: int
    revocation_auth_token_path: str | None

    ENVIRONMENT_FIELDS = _HOST_ENVIRONMENT_FIELDS
    REQUIRED_ENVIRONMENT_FIELDS = _REQUIRED_ENVIRONMENT_FIELDS
    OPTIONAL_ENVIRONMENT_FIELDS = _OPTIONAL_ENVIRONMENT_FIELDS
    FORBIDDEN_ENVIRONMENT_FIELDS = _FORBIDDEN_ENVIRONMENT_FIELDS
    PROTECTED_REFERENCE_FIELDS = _PROTECTED_REFERENCE_FIELDS
    PUBLIC_REFERENCE_FIELDS = _PUBLIC_REFERENCE_FIELDS
    NON_SECRET_FIELDS = _NON_SECRET_FIELDS

    def __post_init__(self) -> None:
        if type(self.github_app) is not GitHubAppBootstrapConfig:
            raise _configuration_error()
        for name in (
            "attestation_issuer_id", "attestation_key_id",
            "authority_binding_issuer_id", "authority_binding_active_key_id",
        ):
            value = getattr(self, name)
            if type(value) is not str or _ID_RE.fullmatch(value) is None:
                raise _configuration_error()
        for name in (
            "attestation_private_key_path", "attestation_public_key_path",
            "attestation_trusted_keys_path", "authority_binding_private_key_path",
            "authority_binding_public_key_path", "authority_binding_trusted_keys_path",
        ):
            value = getattr(self, name)
            if type(value) is not str or not value.strip() or not os.path.isabs(value):
                raise _configuration_error()
        if type(self.revocation_provider_url) is not str or not self.revocation_provider_url.strip():
            raise _configuration_error()
        from urllib.parse import urlparse
        parsed_url = urlparse(self.revocation_provider_url)
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
            raise _configuration_error()
        if (
            type(self.revocation_timeout_ms) is not int
            or isinstance(self.revocation_timeout_ms, bool)
            or not 1 <= self.revocation_timeout_ms <= 120_000
        ):
            raise _configuration_error()
        if self.revocation_auth_token_path is not None and (
            type(self.revocation_auth_token_path) is not str
            or not self.revocation_auth_token_path.strip()
            or not os.path.isabs(self.revocation_auth_token_path)
        ):
            raise _configuration_error()

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> "HostConfiguration":
        raw_values = dict(os.environ if environment is None else environment)
        if any(
            field.state == "forbidden" and field.name in raw_values
            for field in cls.ENVIRONMENT_FIELDS
        ):
            raise _configuration_error()
        values = {
            field.semantic_key: raw_values[field.name]
            for field in cls.ENVIRONMENT_FIELDS
            if field.state != "forbidden" and field.name in raw_values
        }
        github_app = GitHubAppBootstrapConfig(
            app_id=_required_id(values, "github_app_id"),
            repository_identity=_required_text(values, "github_repository"),
            repository_id=_required_id(values, "github_repository_id"),
            private_key_path=_required_path(values, "github_app_private_key_path"),
        )
        issuer_id = _required_text(values, "attestation_issuer_id")
        key_id = _required_text(values, "attestation_key_id")
        if _ID_RE.fullmatch(issuer_id) is None or _ID_RE.fullmatch(key_id) is None:
            raise _configuration_error()
        authority_issuer_id = _required_text(values, "authority_binding_issuer_id")
        authority_key_id = _required_text(values, "authority_binding_active_key_id")
        if (_ID_RE.fullmatch(authority_issuer_id) is None or
                _ID_RE.fullmatch(authority_key_id) is None):
            raise _configuration_error()
        provider_url = _required_text(values, "revocation_provider_url")
        from urllib.parse import urlparse
        parsed_url = urlparse(provider_url)
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
            raise _configuration_error()
        return cls(
            github_app=github_app,
            attestation_issuer_id=issuer_id,
            attestation_key_id=key_id,
            attestation_private_key_path=_required_path(values, "attestation_private_key_path"),
            attestation_public_key_path=_required_path(values, "attestation_public_key_path"),
            attestation_trusted_keys_path=_required_path(values, "attestation_trusted_keys_path"),
            authority_binding_issuer_id=authority_issuer_id,
            authority_binding_active_key_id=authority_key_id,
            authority_binding_private_key_path=_required_path(values, "authority_binding_private_key_path"),
            authority_binding_public_key_path=_required_path(values, "authority_binding_public_key_path"),
            authority_binding_trusted_keys_path=_required_path(values, "authority_binding_trusted_keys_path"),
            revocation_provider_url=provider_url,
            revocation_timeout_ms=_required_timeout_ms(values, "revocation_timeout_ms"),
            revocation_auth_token_path=_optional_path(values, "revocation_auth_token_path"),
        )

    def __repr__(self) -> str:
        return "<HostConfiguration protected>"


def load_host_configuration(environment: Mapping[str, str] | None = None) -> HostConfiguration:
    """Load configuration only when the explicit Host profile requests it."""

    try:
        return HostConfiguration.from_environment(environment)
    except HostCompositionError:
        raise
    except Exception:
        raise _configuration_error() from None


def _path_identities(path: str) -> tuple[str, str]:
    lexical = os.path.normcase(os.path.abspath(path))
    try:
        resolved = os.path.normcase(str(Path(path).resolve(strict=False)))
    except (OSError, RuntimeError):
        raise HostCompositionError("host_key_path_invalid") from None
    return lexical, resolved


def _inside(root: str, candidate: str) -> bool:
    try:
        return os.path.commonpath((root, candidate)) == root
    except ValueError:
        return False


def _opened_object_path(fd: int) -> str:
    if type(fd) is not int or isinstance(fd, bool) or fd < 0:
        raise HostCompositionError("host_key_opened_object_invalid")
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        import msvcrt

        try:
            handle = msvcrt.get_osfhandle(fd)
        except (OSError, ValueError):
            raise HostCompositionError("host_key_opened_object_invalid") from None
        if handle == -1:
            raise HostCompositionError("host_key_opened_object_invalid") from None
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_final_path = kernel32.GetFinalPathNameByHandleW
        get_final_path.argtypes = (wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD)
        get_final_path.restype = wintypes.DWORD
        buffer_size = 512
        for _ in range(8):
            buffer = ctypes.create_unicode_buffer(buffer_size)
            result = get_final_path(handle, buffer, buffer_size, 0)
            if result == 0:
                raise HostCompositionError("host_key_opened_object_invalid") from None
            if result < buffer_size:
                value = buffer.value
                if value.startswith("\\\\?\\UNC\\"):
                    value = "\\\\" + value[8:]
                elif value.startswith("\\\\?\\"):
                    value = value[4:]
                if value.startswith("\\\\.\\") or not os.path.isabs(value):
                    raise HostCompositionError("host_key_opened_object_invalid") from None
                return os.path.normcase(os.path.abspath(value))
            buffer_size = max(buffer_size * 2, int(result) + 1)
            if buffer_size > 1024 * 1024:
                break
        raise HostCompositionError("host_key_opened_object_invalid") from None

    target: str | None = None
    for directory in ("/proc/self/fd", "/dev/fd"):
        try:
            target = os.readlink(os.path.join(directory, str(fd)))
        except OSError:
            continue
        break
    if (target is None or not target or target.endswith(" (deleted)") or
            not os.path.isabs(target)):
        raise HostCompositionError("host_key_opened_object_invalid") from None
    try:
        resolved = Path(target).resolve(strict=True)
    except (OSError, RuntimeError):
        raise HostCompositionError("host_key_opened_object_invalid") from None
    return os.path.normcase(str(resolved))


def _workspace_opened_object_validator(context: RuntimeContext) -> Callable[[int], None]:
    if type(context) is not RuntimeContext:
        raise HostCompositionError("workspace_identity_unavailable")
    try:
        root = os.path.normcase(str(Path(context.normalized_workspace_root).resolve(strict=True)))
    except (OSError, RuntimeError):
        raise HostCompositionError("workspace_identity_unavailable") from None

    def validate(fd: int) -> None:
        actual = _opened_object_path(fd)
        if _inside(root, actual):
            raise HostCompositionError("host_key_path_workspace_controlled")

    return validate


def _validate_external_key_paths(context: RuntimeContext, config: HostConfiguration) -> None:
    if type(context) is not RuntimeContext:
        raise HostCompositionError("workspace_identity_unavailable")
    root = os.path.normcase(os.path.abspath(context.normalized_workspace_root))
    paths = (
        config.github_app.private_key_path,
        config.attestation_private_key_path,
        config.attestation_public_key_path,
        config.attestation_trusted_keys_path,
        config.authority_binding_private_key_path,
        config.authority_binding_public_key_path,
        config.authority_binding_trusted_keys_path,
    )
    if config.revocation_auth_token_path is not None:
        paths = paths + (config.revocation_auth_token_path,)
    identities = [_path_identities(path) for path in paths]
    for lexical, resolved in identities:
        if _inside(root, lexical) or _inside(root, resolved):
            raise HostCompositionError("host_key_path_workspace_controlled")
    if (len({lexical for lexical, _ in identities}) != len(identities) or
            len({resolved for _, resolved in identities}) != len(identities)):
        raise HostCompositionError("host_key_role_path_conflict")


def _read_external_json(path: str, opened_object_validator: Callable[[int], None]) -> Any:
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            opened_object_validator(fd)
            stat = os.fstat(fd)
            if not os.path.isfile(path) or stat.st_size <= 0 or stat.st_size > 1024 * 1024:
                raise ValueError
            data = os.read(fd, stat.st_size + 1)
        finally:
            os.close(fd)
        if len(data) != stat.st_size or len(data) > 1024 * 1024:
            raise ValueError
        return json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
    except Exception as exc:
        if isinstance(exc, HostCompositionError):
            raise
        raise HostCompositionError("host_trust_bundle_invalid") from None


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _load_trust_bundle(
    context: RuntimeContext,
    path: str,
    opened_object_validator: Callable[[int], None],
    role: str,
) -> tuple[TrustedEd25519Key, ...]:
    try:
        raw = _read_external_json(path, opened_object_validator)
        if set(raw) != {"version", "keys"} or raw["version"] != 1:
            raise ValueError
        entries = raw["keys"]
        if type(entries) is not list or not entries:
            raise ValueError
        loaded: list[TrustedEd25519Key] = []
        for entry in entries:
            if type(entry) is not dict or set(entry) != {"issuer_id", "key_id", "algorithm", "public_key_path"}:
                raise ValueError
            issuer_id = entry["issuer_id"]
            key_id = entry["key_id"]
            if (type(issuer_id) is not str or _ID_RE.fullmatch(issuer_id) is None or
                    type(key_id) is not str or _ID_RE.fullmatch(key_id) is None or
                    entry["algorithm"] != "ed25519"):
                raise ValueError
            public_path = entry["public_key_path"]
            if type(public_path) is not str or not os.path.isabs(public_path):
                raise ValueError
            lexical, resolved = _path_identities(public_path)
            root = os.path.normcase(os.path.abspath(context.normalized_workspace_root))
            if _inside(root, lexical) or _inside(root, resolved):
                raise HostCompositionError("host_key_path_workspace_controlled")
            public_key = FileEd25519PublicKeySource(
                public_path, opened_file_validator=opened_object_validator,
            ).load_ed25519_public_key()
            loaded.append(TrustedEd25519Key(issuer_id, key_id, public_key))
        registry = TrustedEd25519IssuerKeyRegistry(tuple(loaded))
        if role == "attestation":
            return tuple(loaded)
        return tuple(loaded)
    except HostCompositionError:
        raise
    except Exception:
        raise HostCompositionError(f"{role}_trust_bundle_invalid") from None


def _public_key_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _require_active_trusted_key(
    entries: tuple[TrustedEd25519Key, ...], issuer_id: str, key_id: str,
    public_key: Ed25519PublicKey, role: str,
) -> None:
    matches = [entry for entry in entries if entry.issuer_id == issuer_id and entry.key_id == key_id]
    if len(matches) != 1 or _public_key_bytes(matches[0].public_key) != _public_key_bytes(public_key):
        raise HostCompositionError(f"{role}_active_key_not_trusted")


def _read_secret_token(path: str | None, opened_object_validator: Callable[[int], None]) -> str | None:
    if path is None:
        return None
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            opened_object_validator(fd)
            data = os.read(fd, 4097)
        finally:
            os.close(fd)
        token = data.decode("utf-8").strip()
        if not token or len(data) > 4096:
            raise ValueError
        return token
    except Exception:
        raise HostCompositionError("host_revocation_auth_invalid") from None


class _LeaseReadAuthView:
    """One read-auth view over the already-acquired Host lease."""

    __slots__ = ("__lease",)

    def __init__(self, lease: GitHubAppInstallationCredentialLease) -> None:
        if type(lease) is not GitHubAppInstallationCredentialLease:
            raise HostCompositionError("host_credential_capability_invalid")
        object.__setattr__(self, "_LeaseReadAuthView__lease", lease)

    def __setattr__(self, name: str, value: object) -> None:
        raise HostCompositionError("host_credential_capability_invalid")

    def __repr__(self) -> str:
        return "<_LeaseReadAuthView protected>"

    def __copy__(self) -> "_LeaseReadAuthView":
        raise HostCompositionError("host_credential_capability_copy_forbidden")

    def __deepcopy__(self, memo: dict[int, Any]) -> "_LeaseReadAuthView":
        raise HostCompositionError("host_credential_capability_copy_forbidden")

    def __reduce__(self) -> Any:
        raise HostCompositionError("host_credential_capability_serialization_forbidden")

    def __reduce_ex__(self, protocol: int) -> Any:
        raise HostCompositionError("host_credential_capability_serialization_forbidden")

    def get_token(self) -> str:
        return self.__lease._dispatch_token()

    def authenticated_subject_identity(self) -> str:
        snapshot = self.__lease._snapshot()
        return github_app_installation_principal(snapshot.app_id, snapshot.installation_id)

    def effective_permissions(self) -> Mapping[str, str]:
        snapshot = self.__lease._snapshot()
        return dict(snapshot.effective_permissions)


class _LeaseEvidenceSource:
    """Secret-free attestation projection rooted in one exact lease object."""

    __slots__ = ("__lease",)

    def __init__(self, lease: GitHubAppInstallationCredentialLease) -> None:
        if type(lease) is not GitHubAppInstallationCredentialLease:
            raise HostCompositionError("host_credential_capability_invalid")
        object.__setattr__(self, "_LeaseEvidenceSource__lease", lease)

    def __setattr__(self, name: str, value: object) -> None:
        raise HostCompositionError("host_credential_capability_invalid")

    def __repr__(self) -> str:
        return "<_LeaseEvidenceSource protected>"

    def obtain(self, request: GitHubAppInstallationEvidenceRequest) -> GitHubAppInstallationCapabilityEvidence:
        if not isinstance(request, GitHubAppInstallationEvidenceRequest):
            raise HostCompositionError("credential_evidence_invalid")
        evidence = self.__lease._snapshot()
        if (request.repository_identity != evidence.repository_identity or
                request.required_capabilities != ("issues:write",) or
                request.credential_instance_id != evidence.credential_instance_id):
            raise HostCompositionError("credential_evidence_mismatch")
        return evidence


class _HostCapabilityPolicy:
    __slots__ = ()

    def is_supported(self, capability: str) -> bool:
        return type(capability) is str and capability == "issues:write"


class _HostCapabilityResolver:
    __slots__ = ()

    def resolve(self, operation_intents: Any) -> tuple[str, ...]:
        if type(operation_intents) not in (tuple, list) or not operation_intents:
            raise ValueError("attestation_capability_requirement_invalid")
        allowed = {"create_issue", "add_sub_issue", "add_dependency", "verify_relationship"}
        for intent in operation_intents:
            if not isinstance(intent, Mapping) or type(intent.get("operation_kind")) is not str:
                raise ValueError("attestation_capability_requirement_invalid")
            if intent["operation_kind"] not in allowed:
                raise ValueError("attestation_capability_requirement_invalid")
        return ("issues:write",)


class HostComposition:
    """Immutable-reference bundle returned by explicit Host composition."""

    __slots__ = (
        "context", "configuration", "lease", "driver", "trust_context", "signer", "registry", "verifier",
        "authority_signer", "authority_registry", "authority_verifier", "revocation_reader",
        "restart_credential_verifier", "attestation_persistence_store", "authority_binding_store",
        "artifact_link_adapter", "provider", "attestation_service", "approval_authority_service",
        "execution_store", "store",
    )

    def __init__(self, *, context: RuntimeContext, configuration: HostConfiguration,
                 lease: GitHubAppInstallationCredentialLease, driver: Any,
                 trust_context: DriverTrustContext, signer: Ed25519HostSigner,
                 registry: TrustedEd25519IssuerKeyRegistry, verifier: Ed25519ProofVerifier,
                 authority_signer: Ed25519AuthorityBindingSigner,
                 authority_registry: TrustedEd25519IssuerKeyRegistry,
                 authority_verifier: Ed25519AuthorityBindingProofVerifier,
                 revocation_reader: ExternalRevocationReader,
                 restart_credential_verifier: DefaultRestartCredentialAttestationVerifier,
                 attestation_persistence_store: SQLiteAttestationPersistenceStore,
                 authority_binding_store: SQLiteAuthorityBindingPersistenceStore,
                 artifact_link_adapter: VerifiedAttestationArtifactAdapter,
                 provider: GitHubAppCredentialCapabilityProvider,
                 attestation_service: RuntimeAttestationOrchestrationService,
                 approval_authority_service: RuntimeApprovalAuthorityService,
                 execution_store: SQLiteExecutionStore, store: SQLitePreviewStore) -> None:
        values = locals()
        for name in self.__slots__:
            object.__setattr__(self, name, values[name])

    def __setattr__(self, name: str, value: object) -> None:
        raise HostCompositionError("host_composition_sealed")

    def __repr__(self) -> str:
        return "<HostComposition github-app-write protected>"

    def __copy__(self) -> "HostComposition":
        raise HostCompositionError("host_composition_copy_forbidden")

    def __deepcopy__(self, memo: dict[int, Any]) -> "HostComposition":
        raise HostCompositionError("host_composition_copy_forbidden")

    def __reduce_ex__(self, protocol: int) -> Any:
        raise HostCompositionError("host_composition_serialization_forbidden")

    def close(self) -> None:
        store = getattr(self, "attestation_persistence_store", None)
        close = getattr(store, "close", None)
        if callable(close):
            close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def create_server(self) -> Any:
        from mcp_server.server import create_server
        return create_server(
            self.context,
            self.store,
            self.driver,
            self.trust_context,
            self.approval_authority_service,
            self.execution_store,
        )


def _compose_write_enabled_host(
    context: RuntimeContext,
    *,
    configuration: HostConfiguration,
    bootstrap_transport: GitHubAppBootstrapTransport | None,
    private_key_source: GitHubAppPrivateKeySource | None,
    ed_private_source: FileEd25519PrivateKeySource | None,
    ed_public_source: FileEd25519PublicKeySource | None,
    clock: Callable[[], datetime],
    credential_instance_id_factory: Callable[[], str] | None,
    nonce_factory: Callable[[], str],
    revocation_transport: RevocationTransport | None,
) -> HostComposition:
    if type(configuration) is not HostConfiguration:
        raise _configuration_error()
    _validate_external_key_paths(context, configuration)
    opened_object_validator = _workspace_opened_object_validator(context)
    rsa_source = private_key_source or FileGitHubAppPrivateKeySource(
        configuration.github_app.private_key_path,
        opened_file_validator=opened_object_validator,
    )
    bootstrap = GitHubAppInstallationCredentialBootstrap(
        configuration.github_app,
        private_key_source=rsa_source,
        transport=bootstrap_transport,
        clock=clock,
        credential_instance_id_factory=credential_instance_id_factory or (lambda: str(uuid.uuid4())),
    )
    lease = bootstrap.acquire()

    private_source = ed_private_source or FileEd25519PrivateKeySource(
        configuration.attestation_private_key_path,
        opened_file_validator=opened_object_validator,
    )
    public_source = ed_public_source or FileEd25519PublicKeySource(
        configuration.attestation_public_key_path,
        opened_file_validator=opened_object_validator,
    )
    private_key = private_source.load_ed25519_private_key()
    public_key = public_source.load_ed25519_public_key()
    derived_public = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    configured_public = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if derived_public != configured_public:
        raise HostCompositionError("attestation_key_pair_mismatch")

    signer = Ed25519HostSigner(configuration.attestation_issuer_id, configuration.attestation_key_id, private_key)
    attestation_entries = _load_trust_bundle(
        context, configuration.attestation_trusted_keys_path,
        opened_object_validator, "attestation",
    )
    _require_active_trusted_key(
        attestation_entries, configuration.attestation_issuer_id,
        configuration.attestation_key_id, public_key, "attestation",
    )
    registry = TrustedEd25519IssuerKeyRegistry(attestation_entries)
    verifier = Ed25519ProofVerifier(registry)

    authority_private_source = FileEd25519PrivateKeySource(
        configuration.authority_binding_private_key_path,
        opened_file_validator=opened_object_validator,
    )
    authority_public_source = FileEd25519PublicKeySource(
        configuration.authority_binding_public_key_path,
        opened_file_validator=opened_object_validator,
    )
    authority_private_key = authority_private_source.load_ed25519_private_key()
    authority_public_key = authority_public_source.load_ed25519_public_key()
    authority_derived_public = _public_key_bytes(authority_private_key.public_key())
    if authority_derived_public != _public_key_bytes(authority_public_key):
        raise HostCompositionError("authority_binding_key_pair_mismatch")
    if authority_derived_public == _public_key_bytes(public_key):
        raise HostCompositionError("host_key_role_conflict")
    authority_signing_delegate = Ed25519HostSigner(
        configuration.authority_binding_issuer_id,
        configuration.authority_binding_active_key_id,
        authority_private_key,
    )
    authority_signer = Ed25519AuthorityBindingSigner(authority_signing_delegate)
    authority_entries = _load_trust_bundle(
        context, configuration.authority_binding_trusted_keys_path,
        opened_object_validator, "authority_binding",
    )
    _require_active_trusted_key(
        authority_entries, configuration.authority_binding_issuer_id,
        configuration.authority_binding_active_key_id, authority_public_key,
        "authority_binding",
    )
    authority_registry = TrustedEd25519IssuerKeyRegistry(authority_entries)
    authority_verifier = Ed25519AuthorityBindingProofVerifier(
        Ed25519ProofVerifier(authority_registry),
    )

    revocation_token = _read_secret_token(
        configuration.revocation_auth_token_path, opened_object_validator,
    )
    revocation_reader = ExternalRevocationReader(
        endpoint=configuration.revocation_provider_url,
        timeout_ms=configuration.revocation_timeout_ms,
        repository_identity=configuration.github_app.repository_identity,
        transport=revocation_transport,
        auth_token=revocation_token,
    )
    capability_policy = _HostCapabilityPolicy()
    boundary = AttestationRuntimeBoundary(registry, verifier, revocation_reader, capability_policy)
    evidence_source = _LeaseEvidenceSource(lease)
    provider = GitHubAppCredentialCapabilityProvider(
        evidence_source,
        signer,
        clock=clock,
        credential_instance_id_factory=lambda: lease._snapshot().credential_instance_id,
        nonce_factory=nonce_factory,
    )
    trust_context = DriverTrustContext(
        GitHubAppInstallationReadOnlyDriver.trusted_driver_identity,
        GitHubAppInstallationReadOnlyDriver.origin,
        GitHubAppInstallationReadOnlyDriver.contract_version,
    )
    read_auth_view = _LeaseReadAuthView(lease)
    driver = GitHubAppInstallationReadOnlyDriver(
        read_auth_view,
        configuration.github_app.repository_id,
    )
    existing_endpoint_revalidator = ExistingEndpointRevalidator(driver, trust_context)
    store = SQLitePreviewStore(context, trust_context=trust_context)
    attestation_service = RuntimeAttestationOrchestrationService(
        context,
        store,
        trust_context,
        boundary,
        provider,
        _HostCapabilityResolver(),
        clock=clock,
    )
    attestation_persistence_store = SQLiteAttestationPersistenceStore(
        context.state_path, workspace_identity=context.workspace_identity,
    )
    authority_binding_store = SQLiteAuthorityBindingPersistenceStore(
        context.state_path, workspace_identity=context.workspace_identity,
    )
    artifact_link_adapter = VerifiedAttestationArtifactAdapter(
        attestation_persistence_store, clock=clock,
    )
    restart_credential_verifier = DefaultRestartCredentialAttestationVerifier(
        issuer_policy=registry,
        proof_verifier=verifier,
        revocation_reader=revocation_reader,
        capability_policy=capability_policy,
    )
    approval_authority_service = RuntimeApprovalAuthorityService(
        context,
        store,
        attestation_service,
        clock=clock,
        host_credential_lease=lease,
        artifact_link_adapter=artifact_link_adapter,
        authority_binding_signer=authority_signer,
        authority_binding_store=authority_binding_store,
        authority_binding_verifier=authority_verifier,
        attestation_persistence_store=attestation_persistence_store,
        restart_credential_verifier=restart_credential_verifier,
        existing_endpoint_revalidator=existing_endpoint_revalidator,
    )
    execution_store = SQLiteExecutionStore(context.state_path, context.workspace_identity,
                                            runtime_service=approval_authority_service)
    return HostComposition(
        context=context,
        configuration=configuration,
        lease=lease,
        driver=driver,
        trust_context=trust_context,
        signer=signer,
        registry=registry,
        verifier=verifier,
        authority_signer=authority_signer,
        authority_registry=authority_registry,
        authority_verifier=authority_verifier,
        revocation_reader=revocation_reader,
        restart_credential_verifier=restart_credential_verifier,
        attestation_persistence_store=attestation_persistence_store,
        authority_binding_store=authority_binding_store,
        artifact_link_adapter=artifact_link_adapter,
        provider=provider,
        attestation_service=attestation_service,
        approval_authority_service=approval_authority_service,
        execution_store=execution_store,
        store=store,
    )


def compose_write_enabled_host(
    context: RuntimeContext,
    *,
    configuration: HostConfiguration,
    bootstrap_transport: GitHubAppBootstrapTransport | None = None,
    private_key_source: GitHubAppPrivateKeySource | None = None,
    ed_private_source: FileEd25519PrivateKeySource | None = None,
    ed_public_source: FileEd25519PublicKeySource | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    credential_instance_id_factory: Callable[[], str] | None = None,
    nonce_factory: Callable[[], str] = lambda: str(uuid.uuid4()),
    revocation_transport: RevocationTransport | None = None,
) -> HostComposition:
    """Acquire and compose one explicit, write-capable Host instance."""

    result = _attempt(lambda: _compose_write_enabled_host(
        context,
        configuration=configuration,
        bootstrap_transport=bootstrap_transport,
        private_key_source=private_key_source,
        ed_private_source=ed_private_source,
        ed_public_source=ed_public_source,
        clock=clock,
        credential_instance_id_factory=credential_instance_id_factory,
        nonce_factory=nonce_factory,
        revocation_transport=revocation_transport,
    ))
    if type(result) is not HostComposition:
        raise HostCompositionError() from None
    return result
