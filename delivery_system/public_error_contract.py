"""MCP-independent public error and recovery contract."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any


class PublicErrorCategory(str, Enum):
    INPUT_VALIDATION = "INPUT_VALIDATION"
    DOMAIN_BUSINESS = "DOMAIN_BUSINESS"
    CURRENTNESS_STALENESS = "CURRENTNESS_STALENESS"
    IDENTITY_BINDING = "IDENTITY_BINDING"
    PERSISTENCE_WORKSPACE = "PERSISTENCE_WORKSPACE"
    AUTHORITY_CREDENTIAL = "AUTHORITY_CREDENTIAL"
    TRANSPORT_HOST = "TRANSPORT_HOST"


class RetryDisposition(str, Enum):
    NO_AUTOMATIC_RETRY = "NO_AUTOMATIC_RETRY"


class RecoveryAction(str, Enum):
    CORRECT_CALLER_INPUT = "CORRECT_CALLER_INPUT"
    ESTABLISH_CURRENT_AUDIT_CONTEXT = "ESTABLISH_CURRENT_AUDIT_CONTEXT"
    ESTABLISH_CURRENT_PREVIEW_THEN_RESTART_CEREMONY = (
        "ESTABLISH_CURRENT_PREVIEW_THEN_RESTART_CEREMONY"
    )
    RESTART_APPROVAL_CEREMONY = "RESTART_APPROVAL_CEREMONY"
    INVESTIGATE_APPROVAL_STATE = "INVESTIGATE_APPROVAL_STATE"
    RESTORE_WORKSPACE_CONTEXT = "RESTORE_WORKSPACE_CONTEXT"
    REACQUIRE_CURRENT_CREDENTIAL = "REACQUIRE_CURRENT_CREDENTIAL"
    REESTABLISH_APPLICATION_AUTHORITY_AFTER_CURRENT_APPROVAL = (
        "REESTABLISH_APPLICATION_AUTHORITY_AFTER_CURRENT_APPROVAL"
    )
    INVESTIGATE_DURABLE_STATE = "INVESTIGATE_DURABLE_STATE"
    ESCALATE_TO_HOST_OPERATOR = "ESCALATE_TO_HOST_OPERATOR"


@dataclass(frozen=True, slots=True)
class PublicToolError:
    code: str
    category: PublicErrorCategory
    retry_disposition: RetryDisposition
    recovery_action: RecoveryAction

    def to_meta(self) -> dict[str, str]:
        return {
            "code": self.code,
            "category": self.category.value,
            "retry_disposition": self.retry_disposition.value,
            "recovery_action": self.recovery_action.value,
        }


@dataclass(frozen=True, slots=True)
class PublicErrorDescriptor:
    code: str
    category: PublicErrorCategory
    retry_disposition: RetryDisposition
    recovery_action: RecoveryAction
    safe_text: str

    def public_error(self) -> PublicToolError:
        return PublicToolError(
            code=self.code,
            category=self.category,
            retry_disposition=self.retry_disposition,
            recovery_action=self.recovery_action,
        )


_NO_RETRY = RetryDisposition.NO_AUTOMATIC_RETRY


def _descriptor(
    code: str,
    category: PublicErrorCategory,
    recovery_action: RecoveryAction,
    safe_text: str,
) -> PublicErrorDescriptor:
    return PublicErrorDescriptor(code, category, _NO_RETRY, recovery_action, safe_text)


_REGISTRY = {
    "application_authority_id_invalid": _descriptor(
        "application_authority_id_invalid", PublicErrorCategory.INPUT_VALIDATION,
        RecoveryAction.CORRECT_CALLER_INPUT,
        "application_authority_id_invalid: Application Authority input is invalid.",
    ),
    "application_authority_rejected": _descriptor(
        "application_authority_rejected", PublicErrorCategory.AUTHORITY_CREDENTIAL,
        RecoveryAction.REESTABLISH_APPLICATION_AUTHORITY_AFTER_CURRENT_APPROVAL,
        "application_authority_rejected: Application Authority could not be accepted for the current Approval.",
    ),
    "application_binding_conflict": _descriptor(
        "application_binding_conflict", PublicErrorCategory.IDENTITY_BINDING,
        RecoveryAction.INVESTIGATE_DURABLE_STATE,
        "application_binding_conflict: Application identity binding is inconsistent.",
    ),
    "application_id_invalid": _descriptor(
        "application_id_invalid", PublicErrorCategory.INPUT_VALIDATION,
        RecoveryAction.CORRECT_CALLER_INPUT,
        "application_id_invalid: Application identifier input is invalid.",
    ),
    "application_not_found": _descriptor(
        "application_not_found", PublicErrorCategory.PERSISTENCE_WORKSPACE,
        RecoveryAction.INVESTIGATE_DURABLE_STATE,
        "application_not_found: The requested Application was not found in durable state.",
    ),
    "application_reconciliation_boundary_unavailable": _descriptor(
        "application_reconciliation_boundary_unavailable", PublicErrorCategory.TRANSPORT_HOST,
        RecoveryAction.ESCALATE_TO_HOST_OPERATOR,
        "application_reconciliation_boundary_unavailable: The Application observation boundary is unavailable.",
    ),
    "application_reconciliation_state_invalid": _descriptor(
        "application_reconciliation_state_invalid", PublicErrorCategory.PERSISTENCE_WORKSPACE,
        RecoveryAction.INVESTIGATE_DURABLE_STATE,
        "application_reconciliation_state_invalid: Durable reconciliation state is invalid.",
    ),
    "application_receipt_integrity_invalid": _descriptor(
        "application_receipt_integrity_invalid", PublicErrorCategory.PERSISTENCE_WORKSPACE,
        RecoveryAction.INVESTIGATE_DURABLE_STATE,
        "application_receipt_integrity_invalid: Durable Application receipt integrity could not be verified.",
    ),
    "application_receipt_not_found": _descriptor(
        "application_receipt_not_found", PublicErrorCategory.PERSISTENCE_WORKSPACE,
        RecoveryAction.INVESTIGATE_DURABLE_STATE,
        "application_receipt_not_found: The Application receipt is missing from durable state.",
    ),
    "application_replay_validation_required": _descriptor(
        "application_replay_validation_required", PublicErrorCategory.PERSISTENCE_WORKSPACE,
        RecoveryAction.INVESTIGATE_DURABLE_STATE,
        "application_replay_validation_required: Durable Application replay validation is required.",
    ),
    "approval_audit_ambiguous": _descriptor(
        "approval_audit_ambiguous", PublicErrorCategory.IDENTITY_BINDING,
        RecoveryAction.INVESTIGATE_APPROVAL_STATE,
        "approval_audit_ambiguous: Approval state is bound to more than one eligible Audit.",
    ),
    "approval_binding_conflict": _descriptor(
        "approval_binding_conflict", PublicErrorCategory.IDENTITY_BINDING,
        RecoveryAction.INVESTIGATE_APPROVAL_STATE,
        "approval_binding_conflict: Existing Approval binding conflicts with the requested Approval.",
    ),
    "approval_binding_mismatch": _descriptor(
        "approval_binding_mismatch", PublicErrorCategory.IDENTITY_BINDING,
        RecoveryAction.INVESTIGATE_APPROVAL_STATE,
        "approval_binding_mismatch: Approval identity does not match the current Approval context.",
    ),
    "approval_command_invalid": _descriptor(
        "approval_command_invalid", PublicErrorCategory.INPUT_VALIDATION,
        RecoveryAction.CORRECT_CALLER_INPUT,
        "approval_command_invalid: The Approval command is not valid.",
    ),
    "approval_invalid": _descriptor(
        "approval_invalid", PublicErrorCategory.DOMAIN_BUSINESS,
        RecoveryAction.INVESTIGATE_APPROVAL_STATE,
        "approval_invalid: Approval data could not be safely validated.",
    ),
    "approval_not_found": _descriptor(
        "approval_not_found", PublicErrorCategory.IDENTITY_BINDING,
        RecoveryAction.INVESTIGATE_APPROVAL_STATE,
        "approval_not_found: The required Approval record was not found.",
    ),
    "approval_runtime_boundary_invalid": _descriptor(
        "approval_runtime_boundary_invalid", PublicErrorCategory.TRANSPORT_HOST,
        RecoveryAction.ESCALATE_TO_HOST_OPERATOR,
        "approval_runtime_boundary_invalid: The Approval Runtime boundary is unavailable or invalid.",
    ),
    "approval_stale": _descriptor(
        "approval_stale", PublicErrorCategory.CURRENTNESS_STALENESS,
        RecoveryAction.RESTART_APPROVAL_CEREMONY,
        "approval_stale: The Approval is no longer current for the target.",
    ),
    "approval_workspace_mismatch": _descriptor(
        "approval_workspace_mismatch", PublicErrorCategory.IDENTITY_BINDING,
        RecoveryAction.INVESTIGATE_APPROVAL_STATE,
        "approval_workspace_mismatch: Approval workspace binding is inconsistent.",
    ),
    "attempt_integrity_invalid": _descriptor(
        "attempt_integrity_invalid", PublicErrorCategory.PERSISTENCE_WORKSPACE,
        RecoveryAction.INVESTIGATE_DURABLE_STATE,
        "attempt_integrity_invalid: Durable execution attempt integrity could not be verified.",
    ),
    "attestation_service_unavailable": _descriptor(
        "attestation_service_unavailable", PublicErrorCategory.TRANSPORT_HOST,
        RecoveryAction.ESCALATE_TO_HOST_OPERATOR,
        "attestation_service_unavailable: The attestation service is unavailable.",
    ),
    "audit_context_stale": _descriptor(
        "audit_context_stale", PublicErrorCategory.CURRENTNESS_STALENESS,
        RecoveryAction.ESTABLISH_CURRENT_AUDIT_CONTEXT,
        "audit_context_stale: Audit context is no longer current.",
    ),
    "audit_not_found": _descriptor(
        "audit_not_found", PublicErrorCategory.CURRENTNESS_STALENESS,
        RecoveryAction.ESTABLISH_CURRENT_AUDIT_CONTEXT,
        "audit_not_found: The required Audit was not found.",
    ),
    "audit_stale": _descriptor(
        "audit_stale", PublicErrorCategory.CURRENTNESS_STALENESS,
        RecoveryAction.ESTABLISH_CURRENT_AUDIT_CONTEXT,
        "audit_stale: The Audit is no longer current.",
    ),
    "authority_issuance_requires_recovery": _descriptor(
        "authority_issuance_requires_recovery", PublicErrorCategory.AUTHORITY_CREDENTIAL,
        RecoveryAction.REESTABLISH_APPLICATION_AUTHORITY_AFTER_CURRENT_APPROVAL,
        "authority_issuance_requires_recovery: Application Authority issuance requires recovery.",
    ),
    "context_stale": _descriptor(
        "context_stale", PublicErrorCategory.CURRENTNESS_STALENESS,
        RecoveryAction.ESTABLISH_CURRENT_AUDIT_CONTEXT,
        "context_stale: The requested context is no longer current.",
    ),
    "credential_binding_mismatch": _descriptor(
        "credential_binding_mismatch", PublicErrorCategory.IDENTITY_BINDING,
        RecoveryAction.INVESTIGATE_DURABLE_STATE,
        "credential_binding_mismatch: Credential binding does not match durable authority state.",
    ),
    "credential_capability_insufficient": _descriptor(
        "credential_capability_insufficient", PublicErrorCategory.AUTHORITY_CREDENTIAL,
        RecoveryAction.REESTABLISH_APPLICATION_AUTHORITY_AFTER_CURRENT_APPROVAL,
        "credential_capability_insufficient: Credential capabilities are insufficient for the current authority.",
    ),
    "credential_expired": _descriptor(
        "credential_expired", PublicErrorCategory.AUTHORITY_CREDENTIAL,
        RecoveryAction.REACQUIRE_CURRENT_CREDENTIAL,
        "credential_expired: The current credential has expired.",
    ),
    "driver_trust_context_mismatch": _descriptor(
        "driver_trust_context_mismatch", PublicErrorCategory.IDENTITY_BINDING,
        RecoveryAction.INVESTIGATE_DURABLE_STATE,
        "driver_trust_context_mismatch: Driver trust context does not match durable state.",
    ),
    "input_invalid": _descriptor(
        "input_invalid", PublicErrorCategory.INPUT_VALIDATION,
        RecoveryAction.CORRECT_CALLER_INPUT,
        "input_invalid: Tool input could not be validated.",
    ),
    "internal_error": _descriptor(
        "internal_error", PublicErrorCategory.TRANSPORT_HOST,
        RecoveryAction.ESCALATE_TO_HOST_OPERATOR,
        "internal_error: The tool could not complete the request. Escalate to the host operator.",
    ),
    "operation_receipt_not_found": _descriptor(
        "operation_receipt_not_found", PublicErrorCategory.PERSISTENCE_WORKSPACE,
        RecoveryAction.INVESTIGATE_DURABLE_STATE,
        "operation_receipt_not_found: The operation receipt is missing from durable state.",
    ),
    "preview_digest_mismatch": _descriptor(
        "preview_digest_mismatch", PublicErrorCategory.PERSISTENCE_WORKSPACE,
        RecoveryAction.INVESTIGATE_DURABLE_STATE,
        "preview_digest_mismatch: Preview integrity could not be verified.",
    ),
    "preview_not_found": _descriptor(
        "preview_not_found", PublicErrorCategory.CURRENTNESS_STALENESS,
        RecoveryAction.ESTABLISH_CURRENT_PREVIEW_THEN_RESTART_CEREMONY,
        "preview_not_found: The requested Preview was not found.",
    ),
    "preview_stale": _descriptor(
        "preview_stale", PublicErrorCategory.CURRENTNESS_STALENESS,
        RecoveryAction.ESTABLISH_CURRENT_PREVIEW_THEN_RESTART_CEREMONY,
        "preview_stale: The requested Preview is no longer current.",
    ),
    "reconciliation_operation_unsupported": _descriptor(
        "reconciliation_operation_unsupported", PublicErrorCategory.DOMAIN_BUSINESS,
        RecoveryAction.INVESTIGATE_DURABLE_STATE,
        "reconciliation_operation_unsupported: This application operation cannot be observed through the current recovery path.",
    ),
    "receipt_integrity_invalid": _descriptor(
        "receipt_integrity_invalid", PublicErrorCategory.PERSISTENCE_WORKSPACE,
        RecoveryAction.INVESTIGATE_DURABLE_STATE,
        "receipt_integrity_invalid: Durable operation receipt integrity could not be verified.",
    ),
    "remote_observation_unavailable": _descriptor(
        "remote_observation_unavailable", PublicErrorCategory.TRANSPORT_HOST,
        RecoveryAction.ESCALATE_TO_HOST_OPERATOR,
        "remote_observation_unavailable: Remote postcondition observation is unavailable.",
    ),
    "sealed_preview_schema_invalid": _descriptor(
        "sealed_preview_schema_invalid", PublicErrorCategory.PERSISTENCE_WORKSPACE,
        RecoveryAction.INVESTIGATE_DURABLE_STATE,
        "sealed_preview_schema_invalid: Stored Preview structure could not be validated.",
    ),
    "sealed_preview_unavailable": _descriptor(
        "sealed_preview_unavailable", PublicErrorCategory.PERSISTENCE_WORKSPACE,
        RecoveryAction.INVESTIGATE_DURABLE_STATE,
        "sealed_preview_unavailable: The sealed Preview is unavailable or incomplete.",
    ),
    "state_integrity_invalid": _descriptor(
        "state_integrity_invalid", PublicErrorCategory.PERSISTENCE_WORKSPACE,
        RecoveryAction.INVESTIGATE_DURABLE_STATE,
        "state_integrity_invalid: Durable application state integrity could not be verified.",
    ),
    "store_corrupt": _descriptor(
        "store_corrupt", PublicErrorCategory.PERSISTENCE_WORKSPACE,
        RecoveryAction.INVESTIGATE_DURABLE_STATE,
        "store_corrupt: Durable workspace state appears corrupted.",
    ),
    "store_unavailable": _descriptor(
        "store_unavailable", PublicErrorCategory.PERSISTENCE_WORKSPACE,
        RecoveryAction.INVESTIGATE_DURABLE_STATE,
        "store_unavailable: Durable workspace storage is unavailable.",
    ),
    "verified_attestation_context_unverified": _descriptor(
        "verified_attestation_context_unverified", PublicErrorCategory.AUTHORITY_CREDENTIAL,
        RecoveryAction.REESTABLISH_APPLICATION_AUTHORITY_AFTER_CURRENT_APPROVAL,
        "verified_attestation_context_unverified: Verified attestation context is unavailable for current authority issuance.",
    ),
    "workspace_identity_unavailable": _descriptor(
        "workspace_identity_unavailable", PublicErrorCategory.PERSISTENCE_WORKSPACE,
        RecoveryAction.RESTORE_WORKSPACE_CONTEXT,
        "workspace_identity_unavailable: Workspace context is unavailable for this operation.",
    ),
    "write_execution_boundary_unavailable": _descriptor(
        "write_execution_boundary_unavailable", PublicErrorCategory.TRANSPORT_HOST,
        RecoveryAction.ESCALATE_TO_HOST_OPERATOR,
        "write_execution_boundary_unavailable: The write execution boundary is unavailable.",
    ),
    "write_executor_required": _descriptor(
        "write_executor_required", PublicErrorCategory.TRANSPORT_HOST,
        RecoveryAction.ESCALATE_TO_HOST_OPERATOR,
        "write_executor_required: The configured write executor is unavailable.",
    ),
}

PUBLIC_ERROR_REGISTRY = MappingProxyType(_REGISTRY)
REGISTRY_CODES = frozenset(PUBLIC_ERROR_REGISTRY)
INTERNAL_ERROR_CODE = "internal_error"


def descriptor_for_code(code: str | None) -> PublicErrorDescriptor:
    if type(code) is str:
        descriptor = PUBLIC_ERROR_REGISTRY.get(code)
        if descriptor is not None:
            return descriptor
    return PUBLIC_ERROR_REGISTRY[INTERNAL_ERROR_CODE]


def public_error_for_code(code: str | None) -> PublicToolError:
    return descriptor_for_code(code).public_error()


def registered_code_from_exception(error: BaseException) -> str | None:
    """Return only an allowlisted code from an exception's typed data."""
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        code = getattr(current, "code", None)
        if type(code) is str and code in PUBLIC_ERROR_REGISTRY:
            return code
        if isinstance(current, ValueError) and len(current.args) == 1:
            candidate = current.args[0]
            if type(candidate) is str and candidate in PUBLIC_ERROR_REGISTRY:
                return candidate
        current = current.__cause__ or current.__context__
    return None


__all__ = [
    "INTERNAL_ERROR_CODE",
    "PUBLIC_ERROR_REGISTRY",
    "REGISTRY_CODES",
    "PublicErrorCategory",
    "PublicErrorDescriptor",
    "PublicToolError",
    "RecoveryAction",
    "RetryDisposition",
    "descriptor_for_code",
    "public_error_for_code",
    "registered_code_from_exception",
]
