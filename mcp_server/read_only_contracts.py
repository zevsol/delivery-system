"""Shared MCP schemas and safe error handling without a server factory."""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from mcp.server import MCPServer
from mcp.server.context import ServerRequestContext
from mcp.server.mcpserver.context import Context
from mcp.server.mcpserver.exceptions import ToolError
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS, CallToolRequestParams, CallToolResult, TextContent
from pydantic import (
    BaseModel, BeforeValidator, ConfigDict, Field, StrictInt, StrictStr,
    ValidationError, model_validator,
)

from delivery_system.drivers.contract import DriverError
from delivery_system.public_error_contract import (
    INTERNAL_ERROR_CODE, PUBLIC_ERROR_REGISTRY, PublicErrorDescriptor, descriptor_for_code,
)
from delivery_system.runtime import StorePreflightError


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


_APPLICATION_ID_PATTERN = re.compile(r"^application-[0-9a-f]{64}$")


def _validate_application_id_input(value: Any) -> Any:
    if type(value) is not str or _APPLICATION_ID_PATTERN.fullmatch(value) is None:
        raise ValueError("application_id_invalid")
    return value


ApplicationIdInput = Annotated[
    StrictStr,
    Field(pattern=r"^application-[0-9a-f]{64}$"),
    BeforeValidator(_validate_application_id_input),
]


class AuditContextInput(StrictModel):
    preview_id: str = Field(min_length=1)
    revision: StrictInt = Field(ge=1)


class AuditContextOutput(StrictModel):
    context_status: Literal["audit_ready"]
    workspace_identity: str
    preview_id: str
    revision: int = Field(ge=1)
    sealed_preview: dict[str, Any]
    evidence_records: list[dict[str, Any]]
    audit_context_digest: str
    rule_registry_version: str | None = None
    rule_registry_digest: str | None = None
    audit_scope: Literal["Conceptual", "RepositoryAware", "WriteEligible"]
    semantic_rule_contexts: list[dict[str, Any]]


class RecordApprovalOutput(StrictModel):
    approval_id: str
    audit_id: str
    audit_digest: str
    audit_result: Literal["Passed"]
    preview_id: str
    revision: int
    plan_digest: str
    remote_snapshot_digest: str
    operation_set_digest: str
    repository_identity: str
    approval_command: str
    approver_claim: str
    approved_at: str
    status: Literal["valid"]


class ApprovalStatusInput(StrictModel):
    preview_id: StrictStr = Field(min_length=1)
    revision: StrictInt = Field(ge=1)


class ApprovalStatusOutput(StrictModel):
    status: Literal["CURRENT", "NO_CURRENT_APPROVAL"]
    preview_id: StrictStr = Field(min_length=1)
    revision: StrictInt = Field(ge=1)
    approval: RecordApprovalOutput | None = None


class ApplicationReceiptStatusOutput(StrictModel):
    application_receipt_id: StrictStr = Field(min_length=1)
    receipt_digest: StrictStr = Field(min_length=1)
    status: Literal["Applied"]
    operation_receipt_count: StrictInt = Field(ge=0)
    started_at: StrictStr = Field(min_length=1)
    completed_at: StrictStr = Field(min_length=1)


class OperationReceiptStatusOutput(StrictModel):
    operation_receipt_id: StrictStr = Field(min_length=1)
    receipt_digest: StrictStr = Field(min_length=1)
    operation_index: StrictInt = Field(ge=0)
    started_at: StrictStr = Field(min_length=1)
    completed_at: StrictStr = Field(min_length=1)


class AttemptStatusOutput(StrictModel):
    operation_identity: StrictStr = Field(min_length=1)
    operation_index: StrictInt = Field(ge=0)
    state: Literal["Applying", "Failed", "Blocked", "OutcomeUnknown", "Applied"]
    attempt_digest: StrictStr = Field(min_length=1)
    started_at: StrictStr = Field(min_length=1)
    updated_at: StrictStr = Field(min_length=1)
    failure_code: StrictStr | None = None


class GetApplicationStatusInput(StrictModel):
    application_id: ApplicationIdInput | None = None
    preview_id: StrictStr | None = Field(default=None, min_length=1)
    revision: StrictInt | None = Field(default=None, ge=1)
    approval_id: StrictStr | None = Field(default=None, min_length=1)
    approval_digest: StrictStr | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def validate_lookup_mode(self) -> "GetApplicationStatusInput":
        context_fields = ("preview_id", "revision", "approval_id", "approval_digest")
        context_present = all(
            value is not None
            for value in (self.preview_id, self.revision, self.approval_id, self.approval_digest)
        )
        application_field_present = "application_id" in self.model_fields_set
        context_field_present = any(field in self.model_fields_set for field in context_fields)
        if self.application_id is not None:
            if context_field_present:
                raise ValueError("application_status_input_invalid")
            return self
        if application_field_present or not context_present:
            raise ValueError("application_status_input_invalid")
        return self


class ApplicationStatusOutput(StrictModel):
    application_id: StrictStr = Field(min_length=1)
    preview_id: StrictStr = Field(min_length=1)
    revision: StrictInt = Field(ge=1)
    operation_set_digest: StrictStr = Field(min_length=1)
    state: Literal["Pending", "Applying", "PartiallyApplied", "Failed", "Blocked", "OutcomeUnknown", "Applied"]
    next_operation_index: StrictInt = Field(ge=0)
    completed_operation_count: StrictInt = Field(ge=0)
    total_operation_count: StrictInt = Field(ge=0)
    attempt_count: StrictInt = Field(ge=0)
    recovery_code: StrictStr | None = Field(default=None, min_length=1)
    application_receipt: ApplicationReceiptStatusOutput | None = None
    operation_receipts: list[OperationReceiptStatusOutput]
    attempts: list[AttemptStatusOutput]
    started_at: StrictStr = Field(min_length=1)
    updated_at: StrictStr = Field(min_length=1)
    completed_at: StrictStr | None = Field(default=None, min_length=1)
    integrity_status: Literal["verified"]


_PUBLIC_ERROR_META_KEY = "com.delivery-system/public-tool-error"


def _exception_chain(error: BaseException):
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def _specific_validation_code(error: ValidationError) -> str | None:
    try:
        details = error.errors()
    except Exception:
        return None
    for detail in details:
        context = detail.get("ctx")
        if not isinstance(context, dict):
            continue
        nested = context.get("error")
        if (
            isinstance(nested, ValueError)
            and len(nested.args) == 1
            and type(nested.args[0]) is str
            and nested.args[0] == "application_id_invalid"
        ):
            return nested.args[0]
    return None


def _registered_code_from_trusted_exception(error: BaseException) -> str | None:
    if isinstance(error, (DriverError, StorePreflightError)):
        code = error.code
        if type(code) is str and code in PUBLIC_ERROR_REGISTRY:
            return code
    if isinstance(error, ValueError) and len(error.args) == 1:
        candidate = error.args[0]
        if type(candidate) is str and candidate in PUBLIC_ERROR_REGISTRY:
            return candidate
    return None


def _descriptor_for_tool_error(error: ToolError) -> PublicErrorDescriptor:
    for cause in _exception_chain(error.__cause__):
        if isinstance(cause, ValidationError):
            return descriptor_for_code(_specific_validation_code(cause) or "input_invalid")
        code = _registered_code_from_trusted_exception(cause)
        if code is not None:
            return descriptor_for_code(code)
    return descriptor_for_code(INTERNAL_ERROR_CODE)


def _error_result(descriptor: PublicErrorDescriptor) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=descriptor.safe_text)],
        structured_content=None,
        is_error=True,
        meta={_PUBLIC_ERROR_META_KEY: descriptor.public_error().to_meta()},
    )


class DeliverySystemMCPServer(MCPServer):
    """MCP transport with the repository's established safe error mapping."""

    async def _handle_call_tool(
        self, ctx: ServerRequestContext[Any], params: CallToolRequestParams,
    ) -> CallToolResult:
        context = Context(
            request_context=ctx,
            mcp_server=self,
            input_params=params,
            subscriptions=self._subscriptions,
        )
        try:
            return await self.call_tool(params.name, params.arguments or {}, context)
        except MCPError:
            raise
        except ToolError as error:
            if error.__cause__ is None:
                raise MCPError(code=INVALID_PARAMS, message="Unknown tool") from None
            return _error_result(_descriptor_for_tool_error(error))
        except Exception:
            return _error_result(descriptor_for_code(INTERNAL_ERROR_CODE))


__all__ = [
    "ApplicationIdInput", "ApplicationReceiptStatusOutput", "ApplicationStatusOutput",
    "ApprovalStatusInput", "ApprovalStatusOutput", "AttemptStatusOutput",
    "AuditContextInput", "AuditContextOutput", "DeliverySystemMCPServer",
    "GetApplicationStatusInput", "OperationReceiptStatusOutput", "RecordApprovalOutput",
    "StrictModel", "_descriptor_for_tool_error", "_error_result",
    "_PUBLIC_ERROR_META_KEY",
    "_exception_chain", "_registered_code_from_trusted_exception",
    "_specific_validation_code",
]
