"""Dedicated MCP factory exposing historical read-only snapshot projections."""

from __future__ import annotations

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from delivery_system.read_only_composition import ReadOnlyComposition
from delivery_system.release_identity import current_release_id

from .read_only_contracts import (
    ApprovalStatusInput,
    ApprovalStatusOutput,
    AuditContextInput,
    AuditContextOutput,
    DeliverySystemMCPServer,
    GetApplicationStatusInput,
    ApplicationStatusOutput,
)


READ_ONLY_SERVER_NAME = "delivery-system-local-state-readonly"
READ_ONLY_SERVER_VERSION = current_release_id()


def create_read_only_server(composition: ReadOnlyComposition) -> MCPServer:
    """Build exactly three tools around a caller-owned read-only composition."""
    if not isinstance(composition, ReadOnlyComposition):
        raise ValueError("read_only_state_unavailable")

    mcp = DeliverySystemMCPServer(READ_ONLY_SERVER_NAME)
    annotations = ToolAnnotations(
        read_only_hint=True, destructive_hint=False, open_world_hint=False,
    )

    @mcp.tool(
        name="delivery_get_audit_context",
        description=("Read validated audit context from the supplied historical snapshot. "
                     "Results describe recorded snapshot state, not live GitHub state."),
        annotations=annotations,
        structured_output=True,
    )
    def delivery_get_audit_context(payload: AuditContextInput) -> AuditContextOutput:
        return AuditContextOutput.model_validate(
            composition.get_audit_context(payload.preview_id, payload.revision)
        )

    @mcp.tool(
        name="delivery_get_approval_status",
        description=("Read approval status recorded for the exact preview in the supplied "
                     "historical snapshot; CURRENT means current within that snapshot."),
        annotations=annotations,
        structured_output=True,
    )
    def delivery_get_approval_status(payload: ApprovalStatusInput) -> ApprovalStatusOutput:
        return ApprovalStatusOutput.model_validate(
            composition.get_approval_status(payload.preview_id, payload.revision)
        )

    @mcp.tool(
        name="delivery_get_application_status",
        description=("Read validated application status from the supplied historical snapshot, "
                     "by application ID or the exact approved context. No retry or remote "
                     "observation is performed."),
        annotations=annotations,
        structured_output=True,
    )
    def delivery_get_application_status(payload: GetApplicationStatusInput) -> ApplicationStatusOutput:
        if payload.application_id is not None:
            result = composition.get_application_status(payload.application_id)
        else:
            result = composition.get_application_status_by_approved_context(
                payload.preview_id, payload.revision, payload.approval_id, payload.approval_digest,
            )
        return ApplicationStatusOutput.model_validate(result)

    return mcp


__all__ = ["create_read_only_server"]
