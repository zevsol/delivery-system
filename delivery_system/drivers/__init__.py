"""Typed read-only Driver boundary; no concrete production Driver is bundled."""

from .contract import DriverReadResponse, ReadOnlyDriver, RuntimeEvidenceBinding, normalize_repository_identity
from .preflight import PreflightFailure, PreflightResult, run_preflight

__all__ = [
    "DriverReadResponse",
    "ReadOnlyDriver",
    "RuntimeEvidenceBinding",
    "normalize_repository_identity",
    "PreflightFailure",
    "PreflightResult",
    "run_preflight",
]
