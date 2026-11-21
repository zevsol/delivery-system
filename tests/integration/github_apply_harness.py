"""Fail-closed support for a separately authorized GitHub Apply canary.

This module is test infrastructure. It does not call GitHub or invoke Apply.
Live orchestration must first pass the explicit opt-in and Host/sandbox checks
defined here, then use the existing Delivery System Runtime workflow.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit
from typing import Callable, Mapping, Sequence


class HarnessConfigurationError(ValueError):
    """Secret-free, stable configuration or provenance failure."""


class EvidenceError(ValueError):
    """Evidence does not match the closed sanitized schema."""


@dataclass(frozen=True, slots=True)
class SandboxTarget:
    app_id: str
    repository: str
    repository_id: str


# Reviewed candidate pairs supplied by the project owner. These are policy
# allowlist entries only; neither is asserted to be the currently configured
# Host identity. The environment must select exactly one matching pair.
SANDBOX_TARGETS = (
    SandboxTarget("5408282", "zevsol/ds-acceptance-sandbox", "1428063796"),
    SandboxTarget("4948530", "zevsol/delivery-system-integration-test", "1333027111"),
)
PRODUCTION_REPOSITORY = "zevsol/delivery-system"
EXPECTED_ORIGIN_URL = "https://github.com/zevsol/delivery-system.git"
LIVE_OPT_IN_VARIABLE = "DELIVERY_SYSTEM_LIVE_GITHUB_APPLY"
LIVE_OPT_IN_VALUE = "1"
FORBIDDEN_INSTALLATION_VARIABLE = "DELIVERY_SYSTEM_GITHUB_INSTALLATION_ID"

_REQUIRED_PATHS = (
    "DELIVERY_SYSTEM_GITHUB_APP_PRIVATE_KEY_PATH",
    "DELIVERY_SYSTEM_ATTESTATION_PRIVATE_KEY_PATH",
    "DELIVERY_SYSTEM_ATTESTATION_PUBLIC_KEY_PATH",
    "DELIVERY_SYSTEM_ATTESTATION_TRUSTED_KEYS_PATH",
    "DELIVERY_SYSTEM_AUTHORITY_BINDING_PRIVATE_KEY_PATH",
    "DELIVERY_SYSTEM_AUTHORITY_BINDING_PUBLIC_KEY_PATH",
    "DELIVERY_SYSTEM_AUTHORITY_BINDING_TRUSTED_KEYS_PATH",
)
_REQUIRED_VALUES = (
    "DELIVERY_SYSTEM_GITHUB_APP_ID",
    "DELIVERY_SYSTEM_GITHUB_REPOSITORY",
    "DELIVERY_SYSTEM_GITHUB_REPOSITORY_ID",
    "DELIVERY_SYSTEM_ATTESTATION_ISSUER_ID",
    "DELIVERY_SYSTEM_ATTESTATION_KEY_ID",
    "DELIVERY_SYSTEM_AUTHORITY_BINDING_ISSUER_ID",
    "DELIVERY_SYSTEM_AUTHORITY_BINDING_ACTIVE_KEY_ID",
    "DELIVERY_SYSTEM_REVOCATION_PROVIDER_URL",
    "DELIVERY_SYSTEM_REVOCATION_TIMEOUT_MS",
)
_OPTIONAL_PATHS = (
    "DELIVERY_SYSTEM_REVOCATION_AUTH_TOKEN_PATH",
    "DELIVERY_SYSTEM_ATTESTATION_LIFECYCLE_PATH",
    "DELIVERY_SYSTEM_AUTHORITY_BINDING_LIFECYCLE_PATH",
)
_SAFE_FAILURES = frozenset({
    "configuration_invalid", "provenance_invalid", "scope_invalid",
    "permission_missing", "process_timeout", "process_failed",
    "outcome_ambiguous", "remote_rejected", "evidence_invalid",
})
_OPERATIONS = frozenset({
    "create_issue", "add_parent", "add_dependency", "add_label",
})
_OPERATION_STATES = frozenset({
    "not_started", "submitted", "confirmed", "rejected", "ambiguous",
})
_HEX_SHA = re.compile(r"^[0-9a-f]{40}$")
_DECIMAL_ID = re.compile(r"^[1-9][0-9]{0,19}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


@dataclass(frozen=True, slots=True)
class HostConfiguration:
    app_id: str
    repository: str
    repository_id: str
    revocation_provider_url: str
    revocation_timeout_ms: int
    # File references are deliberately excluded from repr/evidence.
    protected_file_paths: tuple[Path, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    state: str
    exit_code: int | None
    timed_out: bool
    retry_allowed: bool = False


@dataclass(frozen=True, slots=True)
class ExecutionClassification:
    outcome: str
    retry_allowed: bool = False


def require_live_opt_in(environment: Mapping[str, str]) -> None:
    if environment.get(LIVE_OPT_IN_VARIABLE) != LIVE_OPT_IN_VALUE:
        raise HarnessConfigurationError("live_opt_in_required")


def _required(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name)
    if not isinstance(value, str) or not value.strip():
        raise HarnessConfigurationError("configuration_invalid")
    return value.strip()


def validate_host_configuration(environment: Mapping[str, str]) -> HostConfiguration:
    """Validate Host references without reading protected file contents."""
    if FORBIDDEN_INSTALLATION_VARIABLE in environment:
        raise HarnessConfigurationError("configuration_invalid")
    values = {name: _required(environment, name) for name in _REQUIRED_VALUES}
    app_id = values["DELIVERY_SYSTEM_GITHUB_APP_ID"]
    repository = values["DELIVERY_SYSTEM_GITHUB_REPOSITORY"].casefold()
    repository_id = values["DELIVERY_SYSTEM_GITHUB_REPOSITORY_ID"]
    if not _DECIMAL_ID.fullmatch(app_id) or not _DECIMAL_ID.fullmatch(repository_id):
        raise HarnessConfigurationError("configuration_invalid")
    if not _REPOSITORY.fullmatch(repository) or repository == PRODUCTION_REPOSITORY:
        raise HarnessConfigurationError("configuration_invalid")
    matches = [
        target for target in SANDBOX_TARGETS
        if target.app_id == app_id and target.repository == repository
        and target.repository_id == repository_id
    ]
    if len(matches) != 1:
        raise HarnessConfigurationError("configuration_invalid")
    try:
        timeout_ms = int(values["DELIVERY_SYSTEM_REVOCATION_TIMEOUT_MS"])
    except ValueError:
        raise HarnessConfigurationError("configuration_invalid") from None
    if not 1 <= timeout_ms <= 120_000:
        raise HarnessConfigurationError("configuration_invalid")
    revocation_url = values["DELIVERY_SYSTEM_REVOCATION_PROVIDER_URL"]
    parsed_revocation_url = urlsplit(revocation_url)
    if (parsed_revocation_url.scheme != "https" or not parsed_revocation_url.hostname
            or parsed_revocation_url.username or parsed_revocation_url.password
            or parsed_revocation_url.fragment or any(ch.isspace() for ch in revocation_url)):
        raise HarnessConfigurationError("configuration_invalid")

    paths: list[Path] = []
    for name in (*_REQUIRED_PATHS, *_OPTIONAL_PATHS):
        raw = environment.get(name)
        if (name in _REQUIRED_PATHS and (not isinstance(raw, str) or not raw.strip())
                or raw is not None and not isinstance(raw, str)):
            raise HarnessConfigurationError("configuration_invalid")
        if raw:
            path = Path(raw).expanduser()
            try:
                metadata = path.stat()
            except OSError:
                raise HarnessConfigurationError("configuration_invalid") from None
            if not path.is_absolute() or not path.is_file() or metadata.st_size <= 0:
                raise HarnessConfigurationError("configuration_invalid")
            paths.append(path)
    return HostConfiguration(
        app_id=app_id,
        repository=repository,
        repository_id=repository_id,
        revocation_provider_url=revocation_url,
        revocation_timeout_ms=timeout_ms,
        protected_file_paths=tuple(paths),
    )


def validate_remote_scope(
    configuration: HostConfiguration,
    *,
    app_id: str,
    installation_id: str,
    repository: str,
    repository_id: str,
    installed_repositories: Sequence[str],
    permissions: Mapping[str, str],
) -> None:
    """Require exact single-repository installation and Issues write access."""
    canonical = repository.casefold()
    if app_id != configuration.app_id or not _DECIMAL_ID.fullmatch(installation_id):
        raise HarnessConfigurationError("scope_invalid")
    if canonical == PRODUCTION_REPOSITORY or canonical != configuration.repository:
        raise HarnessConfigurationError("scope_invalid")
    if repository_id != configuration.repository_id:
        raise HarnessConfigurationError("scope_invalid")
    if (not isinstance(installed_repositories, Sequence)
            or any(not isinstance(item, str) for item in installed_repositories)
            or tuple(sorted(item.casefold() for item in installed_repositories)) != (canonical,)):
        raise HarnessConfigurationError("scope_invalid")
    if (not isinstance(permissions, Mapping) or permissions.get("issues") != "write"
            or any(name not in {"issues", "metadata"} for name in permissions)
            or permissions.get("metadata", "read") != "read"):
        raise HarnessConfigurationError("permission_missing")


def verify_checkout_provenance(
    checkout: str | Path,
    expected_commit: str,
    *,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> str:
    if not _HEX_SHA.fullmatch(expected_commit):
        raise HarnessConfigurationError("provenance_invalid")
    root = Path(checkout).resolve()
    try:
        actual_root = run(
            ["git", "rev-parse", "--show-toplevel"], cwd=root,
            check=True, capture_output=True, text=True, timeout=5,
        ).stdout.strip()
        actual_commit = run(
            ["git", "rev-parse", "HEAD"], cwd=root,
            check=True, capture_output=True, text=True, timeout=5,
        ).stdout.strip()
        actual_origin = run(
            ["git", "remote", "get-url", "origin"], cwd=root,
            check=True, capture_output=True, text=True, timeout=5,
        ).stdout.strip().rstrip("/")
    except (OSError, subprocess.SubprocessError):
        raise HarnessConfigurationError("provenance_invalid") from None
    accepted_origins = {
        EXPECTED_ORIGIN_URL,
        "https://github.com/zevsol/delivery-system",
        "git@github.com:zevsol/delivery-system.git",
        "git@github.com:zevsol/delivery-system",
    }
    if (Path(actual_root).resolve() != root or actual_commit != expected_commit
            or actual_origin not in accepted_origins):
        raise HarnessConfigurationError("provenance_invalid")
    return actual_commit


def run_bounded_subprocess(
    arguments: Sequence[str],
    *,
    cwd: str | Path,
    timeout_seconds: float = 10,
    popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
) -> ExecutionResult:
    """Run without a shell or captured payload; terminate a timed-out child."""
    if (not arguments or any(not isinstance(arg, str) or not arg for arg in arguments)
            or timeout_seconds <= 0 or timeout_seconds > 300):
        raise HarnessConfigurationError("configuration_invalid")
    process = popen(
        list(arguments), cwd=Path(cwd), shell=False,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, close_fds=True,
    )
    try:
        code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
        return ExecutionResult("timed_out", None, True)
    return ExecutionResult("succeeded" if code == 0 else "failed", code, False)


def classify_execution(state: str, *, remote_request_started: bool) -> ExecutionClassification:
    if state not in _OPERATION_STATES:
        raise HarnessConfigurationError("configuration_invalid")
    if state == "confirmed":
        return ExecutionClassification("confirmed")
    if state == "rejected":
        return ExecutionClassification("rejected")
    if state == "not_started" and not remote_request_started:
        return ExecutionClassification("not_started")
    if state == "submitted" or remote_request_started or state == "ambiguous":
        return ExecutionClassification("ambiguous")
    return ExecutionClassification("not_started")


def build_evidence(
    *,
    repository: str,
    repository_id: str,
    operations: Sequence[Mapping[str, object]],
    failure_code: str | None = None,
) -> dict[str, object]:
    """Build a closed evidence object without titles, bodies, tokens or payloads."""
    if (not isinstance(repository, str) or not isinstance(repository_id, str)
            or isinstance(operations, (str, bytes, bytearray))
            or not isinstance(operations, Sequence)):
        raise EvidenceError("evidence_invalid")
    canonical = repository.casefold()
    target = next((item for item in SANDBOX_TARGETS
                   if item.repository == canonical and item.repository_id == repository_id), None)
    if target is None or canonical == PRODUCTION_REPOSITORY:
        raise EvidenceError("evidence_invalid")
    if failure_code is not None and (not isinstance(failure_code, str) or failure_code not in _SAFE_FAILURES):
        raise EvidenceError("evidence_invalid")
    safe_operations: list[dict[str, str]] = []
    for operation in operations:
        if (not isinstance(operation, Mapping) or set(operation) != {"kind", "state"}
                or not isinstance(operation.get("kind"), str)
                or not isinstance(operation.get("state"), str)
                or operation.get("kind") not in _OPERATIONS
                or operation.get("state") not in _OPERATION_STATES):
            raise EvidenceError("evidence_invalid")
        safe_operations.append({"kind": str(operation["kind"]), "state": str(operation["state"])})
    counts = {state: sum(item["state"] == state for item in safe_operations)
              for state in sorted(_OPERATION_STATES)}
    return {
        "schema_version": "github-apply-harness-v1",
        "target_repository": canonical,
        "target_repository_id": repository_id,
        "operations": safe_operations,
        "operation_counts": counts,
        "failure_code": failure_code,
        "retry_attempts": 0,
    }


def _validate_evidence(evidence: Mapping[str, object]) -> None:
    if not isinstance(evidence, Mapping) or set(evidence) != {
        "schema_version", "target_repository", "target_repository_id",
        "operations", "operation_counts", "failure_code", "retry_attempts",
    } or evidence.get("schema_version") != "github-apply-harness-v1" or evidence.get("retry_attempts") != 0:
        raise EvidenceError("evidence_invalid")
    try:
        expected = build_evidence(
            repository=str(evidence.get("target_repository", "")),
            repository_id=str(evidence.get("target_repository_id", "")),
            operations=evidence.get("operations", []),  # type: ignore[arg-type]
            failure_code=evidence.get("failure_code"),  # type: ignore[arg-type]
        )
    except (TypeError, ValueError):
        raise EvidenceError("evidence_invalid") from None
    if dict(evidence) != expected:
        raise EvidenceError("evidence_invalid")


def evidence_directory(repository_root: str | Path) -> Path:
    """Return the only supported retained-evidence location for a checkout."""
    return Path(repository_root).resolve() / ".dev" / "integration-evidence" / "github-apply"


def write_evidence(repository_root: str | Path, evidence: Mapping[str, object]) -> dict[str, object]:
    """Write only validated JSON under the checkout's ignored .dev evidence area."""
    _validate_evidence(evidence)
    destination = evidence_directory(repository_root)
    destination.mkdir(parents=True, exist_ok=True)
    report_path = destination / "github-apply-report.json"
    manifest_path = destination / "evidence-manifest.json"
    report_bytes = (json.dumps(evidence, sort_keys=True, indent=2) + "\n").encode("utf-8")
    manifest = {
        "schema_version": "github-apply-evidence-manifest-v1",
        "files": [{
            "path": report_path.name,
            "size_bytes": len(report_bytes),
            "sha256": hashlib.sha256(report_bytes).hexdigest(),
        }],
    }
    manifest_bytes = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode("utf-8")
    created: list[Path] = []
    try:
        for path, data in ((report_path, report_bytes), (manifest_path, manifest_bytes)):
            stream = path.open("xb")
            created.append(path)
            with stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
    except OSError:
        for path in created:
            try:
                path.unlink()
            except OSError:
                pass
        raise EvidenceError("evidence_invalid") from None
    return manifest


def verify_evidence_manifest(directory: str | Path) -> bool:
    root = Path(directory)
    try:
        manifest = json.loads((root / "evidence-manifest.json").read_text(encoding="utf-8"))
        if set(manifest) != {"schema_version", "files"} or manifest["schema_version"] != "github-apply-evidence-manifest-v1":
            return False
        if not isinstance(manifest["files"], list) or len(manifest["files"]) != 1:
            return False
        item = manifest["files"][0]
        if set(item) != {"path", "size_bytes", "sha256"} or item["path"] != "github-apply-report.json":
            return False
        payload = (root / item["path"]).read_bytes()
        return (len(payload) == item["size_bytes"]
                and hashlib.sha256(payload).hexdigest() == item["sha256"])
    except (OSError, ValueError, TypeError, KeyError):
        return False
