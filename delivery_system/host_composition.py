"""Explicit production Host composition for the GitHub App write profile.

The module is inert on import.  ``compose_write_enabled_host`` is the only
operation that reads Host configuration, acquires credentials, and builds a
write-capable Runtime composition.  The default MCP server does not call it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import re
from typing import Any, Callable, Mapping
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .attestation import AttestationRuntimeBoundary, RevocationStatus
from .attestation_github_app import (
    GitHubAppCredentialCapabilityProvider,
    GitHubAppInstallationCapabilityEvidence,
    GitHubAppInstallationEvidenceRequest,
)
from .attestation_key_source import FileEd25519PrivateKeySource, FileEd25519PublicKeySource
from .attestation_runtime import RuntimeAttestationOrchestrationService
from .attestation_signing import (
    Ed25519HostSigner,
    Ed25519ProofVerifier,
    TrustedEd25519IssuerKeyRegistry,
    TrustedEd25519Key,
)
from .drivers.contract import DriverTrustContext
from .drivers.rest import LocalRestReadOnlyDriver
from .github_app_bootstrap import (
    GitHubAppBootstrapConfig,
    GitHubAppBootstrapTransport,
    FileGitHubAppPrivateKeySource,
    GitHubAppInstallationCredentialBootstrap,
    GitHubAppPrivateKeySource,
)
from .github_app_credential import GitHubAppInstallationCredentialLease
from .runtime import RuntimeApprovalAuthorityService, RuntimeContext, SQLitePreviewStore
from .execution_store import SQLiteExecutionStore


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


@dataclass(frozen=True)
class HostConfiguration:
    """Non-secret Host inputs for the explicit GitHub App write profile."""

    github_app: GitHubAppBootstrapConfig
    attestation_issuer_id: str
    attestation_key_id: str
    attestation_private_key_path: str
    attestation_public_key_path: str

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> "HostConfiguration":
        values = dict(os.environ if environment is None else environment)
        if "DELIVERY_SYSTEM_GITHUB_INSTALLATION_ID" in values:
            raise _configuration_error()
        github_app = GitHubAppBootstrapConfig(
            app_id=_required_id(values, "DELIVERY_SYSTEM_GITHUB_APP_ID"),
            repository_identity=_required_text(values, "DELIVERY_SYSTEM_GITHUB_REPOSITORY"),
            repository_id=_required_id(values, "DELIVERY_SYSTEM_GITHUB_REPOSITORY_ID"),
            private_key_path=_required_path(values, "DELIVERY_SYSTEM_GITHUB_APP_PRIVATE_KEY_PATH"),
        )
        issuer_id = _required_text(values, "DELIVERY_SYSTEM_ATTESTATION_ISSUER_ID")
        key_id = _required_text(values, "DELIVERY_SYSTEM_ATTESTATION_KEY_ID")
        if _ID_RE.fullmatch(issuer_id) is None or _ID_RE.fullmatch(key_id) is None:
            raise _configuration_error()
        return cls(
            github_app=github_app,
            attestation_issuer_id=issuer_id,
            attestation_key_id=key_id,
            attestation_private_key_path=_required_path(values, "DELIVERY_SYSTEM_ATTESTATION_PRIVATE_KEY_PATH"),
            attestation_public_key_path=_required_path(values, "DELIVERY_SYSTEM_ATTESTATION_PUBLIC_KEY_PATH"),
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
    )
    identities = [_path_identities(path) for path in paths]
    for lexical, resolved in identities:
        if _inside(root, lexical) or _inside(root, resolved):
            raise HostCompositionError("host_key_path_workspace_controlled")
    if (len({lexical for lexical, _ in identities}) != 3 or
            len({resolved for _, resolved in identities}) != 3):
        raise HostCompositionError("host_key_role_path_conflict")


class _LeaseTokenView:
    """One read-driver view over the already-acquired Host lease."""

    __slots__ = ("__lease",)

    def __init__(self, lease: GitHubAppInstallationCredentialLease) -> None:
        if type(lease) is not GitHubAppInstallationCredentialLease:
            raise HostCompositionError("host_credential_capability_invalid")
        object.__setattr__(self, "_LeaseTokenView__lease", lease)

    def __setattr__(self, name: str, value: object) -> None:
        raise HostCompositionError("host_credential_capability_invalid")

    def __repr__(self) -> str:
        return "<_LeaseTokenView protected>"

    def get_token(self) -> str:
        return self.__lease._dispatch_token()


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


class _HostRevocationReader:
    __slots__ = ()

    def read_status(self, attestation_id: str, credential_instance_id: str, issuer_id: str,
                    key_id: str, version: str) -> RevocationStatus:
        return RevocationStatus()


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
        "provider", "attestation_service", "approval_authority_service", "execution_store", "store",
    )

    def __init__(self, *, context: RuntimeContext, configuration: HostConfiguration,
                 lease: GitHubAppInstallationCredentialLease, driver: Any,
                 trust_context: DriverTrustContext, signer: Ed25519HostSigner,
                 registry: TrustedEd25519IssuerKeyRegistry, verifier: Ed25519ProofVerifier,
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
    environment: Mapping[str, str] | None,
    bootstrap_transport: GitHubAppBootstrapTransport | None,
    private_key_source: GitHubAppPrivateKeySource | None,
    ed_private_source: FileEd25519PrivateKeySource | None,
    ed_public_source: FileEd25519PublicKeySource | None,
    clock: Callable[[], datetime],
    credential_instance_id_factory: Callable[[], str] | None,
    nonce_factory: Callable[[], str],
) -> HostComposition:
    configuration = load_host_configuration(environment)
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
    trusted_key = TrustedEd25519Key(configuration.attestation_issuer_id, configuration.attestation_key_id, public_key)
    registry = TrustedEd25519IssuerKeyRegistry((trusted_key,))
    verifier = Ed25519ProofVerifier(registry)
    boundary = AttestationRuntimeBoundary(registry, verifier, _HostRevocationReader(), _HostCapabilityPolicy())
    evidence_source = _LeaseEvidenceSource(lease)
    provider = GitHubAppCredentialCapabilityProvider(
        evidence_source,
        signer,
        clock=clock,
        credential_instance_id_factory=lambda: lease._snapshot().credential_instance_id,
        nonce_factory=nonce_factory,
    )
    trust_context = DriverTrustContext(
        LocalRestReadOnlyDriver.trusted_driver_identity,
        LocalRestReadOnlyDriver.origin,
        LocalRestReadOnlyDriver.contract_version,
    )
    token_view = _LeaseTokenView(lease)
    driver = LocalRestReadOnlyDriver(token_provider=token_view)
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
    approval_authority_service = RuntimeApprovalAuthorityService(
        context,
        store,
        attestation_service,
        clock=clock,
        host_credential_lease=lease,
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
        provider=provider,
        attestation_service=attestation_service,
        approval_authority_service=approval_authority_service,
        execution_store=execution_store,
        store=store,
    )


def compose_write_enabled_host(
    context: RuntimeContext,
    *,
    environment: Mapping[str, str] | None = None,
    bootstrap_transport: GitHubAppBootstrapTransport | None = None,
    private_key_source: GitHubAppPrivateKeySource | None = None,
    ed_private_source: FileEd25519PrivateKeySource | None = None,
    ed_public_source: FileEd25519PublicKeySource | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    credential_instance_id_factory: Callable[[], str] | None = None,
    nonce_factory: Callable[[], str] = lambda: str(uuid.uuid4()),
) -> HostComposition:
    """Acquire and compose one explicit, write-capable Host instance."""

    result = _attempt(lambda: _compose_write_enabled_host(
        context,
        environment=environment,
        bootstrap_transport=bootstrap_transport,
        private_key_source=private_key_source,
        ed_private_source=ed_private_source,
        ed_public_source=ed_public_source,
        clock=clock,
        credential_instance_id_factory=credential_instance_id_factory,
        nonce_factory=nonce_factory,
    ))
    if type(result) is not HostComposition:
        raise HostCompositionError() from None
    return result
