"""Typed read-only Driver boundary; no concrete production Driver is bundled."""

from .contract import DriverReadResponse, ReadOnlyDriver, RuntimeEvidenceBinding, DriverTrustContext, normalize_repository_identity
from .preflight import PreflightFailure, PreflightResult, run_preflight, validate_driver_facts
from .rest import LocalRestReadOnlyDriver, HttpsRestTransport, TransportResponse, TokenProvider, SecretTokenProvider

__all__ = [
    "DriverReadResponse",
    "ReadOnlyDriver",
    "RuntimeEvidenceBinding",
    "DriverTrustContext",
    "normalize_repository_identity",
    "PreflightFailure",
    "PreflightResult",
    "run_preflight",
    "validate_driver_facts",
    "LocalRestReadOnlyDriver",
    "HttpsRestTransport",
    "TransportResponse",
    "TokenProvider",
    "SecretTokenProvider",
]
