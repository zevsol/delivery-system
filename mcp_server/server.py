"""Official SDK stdio adapter for the Corrective Runtime Prototype."""

from __future__ import annotations

import argparse
from typing import Any, Literal

from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from delivery_system.runtime import AuditContextService, RuntimeContext, RuntimePlanner, SQLitePreviewStore
from delivery_system.drivers.contract import DriverTrustContext
from delivery_system.auditor import FindingDraft, RuleEvaluationDraft, RuntimeAuditor
from delivery_system.rules import ResultClass, RuleRegistry, SemanticOutcome, build_registry_v1


SERVER_NAME = "delivery-system-planner"
SERVER_VERSION = "0.3.0"
TOOL_NAME = "delivery_plan_preview"
TOOL_ANNOTATIONS = ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourcedValueInput(StrictModel):
    value: Any
    declared_source: Literal["user_asserted", "model_proposed", "model_assumption"]


class RepositoryClaimInput(StrictModel):
    owner: str = Field(min_length=1)
    name: str = Field(min_length=1)
    url: str | None = None


class ExistingIssueClaimInput(StrictModel):
    url: str | None = None
    number: int | None = Field(default=None, ge=1)


class DraftWorkItemInput(StrictModel):
    client_ref: str = Field(min_length=1)
    previous_client_ref: str | None = Field(default=None, min_length=1)
    role: SourcedValueInput
    title: SourcedValueInput
    context_problem: SourcedValueInput
    outcome: SourcedValueInput
    scope: SourcedValueInput
    non_goals: SourcedValueInput
    acceptance_criteria: SourcedValueInput
    verification: SourcedValueInput
    required_capabilities: SourcedValueInput
    write_metadata: SourcedValueInput


class PlannedRelationshipInput(StrictModel):
    kind: Literal["planned_parent", "planned_dependency"]
    from_client_ref: str
    to_client_ref: str
    rationale: SourcedValueInput


class OperationIntentInput(StrictModel):
    operation_kind: Literal["create_issue", "add_sub_issue", "add_dependency", "verify_relationship"]
    client_refs: list[str] = Field(min_length=1)
    depends_on: list[str] = Field(default_factory=list)


class PlanDraftInput(StrictModel):
    repository_claim: RepositoryClaimInput | None = None
    existing_issue_claims: list[ExistingIssueClaimInput] = Field(default_factory=list)
    work_items: list[DraftWorkItemInput] = Field(min_length=1)
    planned_relationships: list[PlannedRelationshipInput] = Field(default_factory=list)
    operation_intents: list[OperationIntentInput] = Field(default_factory=list)


class PreviewRequestInput(StrictModel):
    plan: PlanDraftInput
    previous_preview_id: str | None = None


class PreviewOutput(StrictModel):
    workspace_identity: str
    provenance_status: Literal["declared_unverified"]
    request_id: str
    preview_id: str
    revision: int = Field(ge=1)
    preview_level: Literal["Conceptual", "RepositoryAware", "WriteEligible"]
    semantic_payload: dict[str, Any]
    operation_intents: list[dict[str, Any]]
    plan_digest: str
    operation_set_digest: str
    repository_identity: str | None
    remote_authority: str | None
    remote_snapshot_digest: str | None
    findings: list[dict[str, Any]]
    blockers: list[str]
    planner_observations: list[dict[str, Any]]
    evidence_ids: list[str]
    stale: bool
    write_eligible: bool
    items: list[dict[str, Any]]
    sealed_preview_digest: str
    audit_context_digest: str
    remote_snapshot: dict[str, Any] | None = None


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


class RuleEvaluationInput(StrictModel):
    rule_id: str = Field(min_length=1)
    rule_version: str = Field(min_length=1)
    outcome: Literal["Passed", "Failed", "Unknown", "Blocked"]
    rationale: str
    finding_refs: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class FindingInput(StrictModel):
    finding_ref: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    result_class: Literal[
        "work_item_content_gap", "decomposition_risk", "acceptance_criteria_gap",
        "assumption_clarity_gap", "relationship_risk", "dependency_risk",
        "duplicate_overlap_risk", "missing_information", "semantic_blocker",
    ]
    severity: Literal["Blocker", "High", "Medium", "Low"]
    title: str
    rationale: str
    evidence_refs: list[str] = Field(default_factory=list)
    affected_item_ids: list[str] = Field(default_factory=list)
    required_action: str
    suggested_resolution: str | None = None


class RecordAuditInput(StrictModel):
    preview_id: str = Field(min_length=1)
    revision: StrictInt = Field(ge=1)
    expected_audit_context_digest: str = Field(min_length=1)
    semantic_evaluations: list[RuleEvaluationInput]
    finding_drafts: list[FindingInput]


class RecordAuditOutput(StrictModel):
    audit_id: str
    preview_id: str
    revision: int
    audit_scope: Literal["Conceptual", "RepositoryAware", "WriteEligible"]
    audit_payload_digest: str
    audit_digest: str
    result: Literal["Passed", "NeedsInformation", "ChangesRequired", "Blocked"]
    status: Literal["Active", "Stale", "Invalid"]
    findings: list[dict[str, Any]]
    rule_evaluations: list[dict[str, Any]]
    approval_eligible: bool


def create_server(context: RuntimeContext | None = None, store: Any | None = None, driver: Any = None,
                  trust_context: DriverTrustContext | None = None) -> MCPServer:
    if (driver is None) != (trust_context is None):
        raise ValueError("driver_trust_context_required")
    if store is not None and trust_context is not None:
        existing = getattr(store, "trust_context", None)
        if existing is not None and existing != trust_context:
            raise ValueError("driver_trust_context_mismatch")
    mcp = MCPServer(SERVER_NAME)
    registry = build_registry_v1()

    @mcp.tool(
        name=TOOL_NAME,
        description="Create a planning preview without writing to GitHub; local PreviewStore state may be written.",
        annotations=TOOL_ANNOTATIONS,
        structured_output=True,
    )
    def delivery_plan_preview(payload: PreviewRequestInput) -> PreviewOutput:
        if context is None:
            raise ValueError("workspace_identity_unavailable")
        service = RuntimePlanner(context, store, driver, trust_context)
        if store is None:
            raise ValueError("store_unavailable")
        return PreviewOutput.model_validate(service.preview(payload.plan.model_dump(), payload.previous_preview_id))

    @mcp.tool(
        name="delivery_get_audit_context",
        description="Read a complete sealed planning preview for later audit; it does not write GitHub.",
        annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=False),
        structured_output=True,
    )
    def delivery_get_audit_context(payload: AuditContextInput) -> AuditContextOutput:
        if context is None or store is None:
            raise ValueError("workspace_identity_unavailable")
        return AuditContextOutput.model_validate(RuntimeAuditor(context, store, registry).get_context(payload.preview_id, payload.revision))

    @mcp.tool(
        name="delivery_record_audit",
        description="Record a Runtime-validated audit of a planning preview; writes only local PreviewStore state and never writes GitHub.",
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False),
        structured_output=True,
    )
    def delivery_record_audit(payload: RecordAuditInput) -> RecordAuditOutput:
        if context is None or store is None:
            raise ValueError("workspace_identity_unavailable")
        audit = RuntimeAuditor(context, store, registry).record_audit(
            payload.preview_id,
            payload.revision,
            payload.expected_audit_context_digest,
            [RuleEvaluationDraft(
                item.rule_id, item.rule_version, SemanticOutcome(item.outcome), item.rationale,
                tuple(item.finding_refs), tuple(item.evidence_refs),
            ) for item in payload.semantic_evaluations],
            [FindingDraft(
                item.finding_ref, item.rule_id, ResultClass(item.result_class), item.severity,
                item.title, item.rationale, tuple(item.evidence_refs), tuple(item.affected_item_ids),
                item.required_action, item.suggested_resolution,
            ) for item in payload.finding_drafts],
        )
        return RecordAuditOutput.model_validate({
            "audit_id": audit.audit_id,
            "preview_id": audit.preview_id,
            "revision": audit.revision,
            "audit_scope": audit.audit_scope,
            "audit_payload_digest": audit.audit_payload_digest,
            "audit_digest": audit.audit_digest,
            "result": audit.result.value,
            "status": audit.status.value,
            "findings": list(audit.findings),
            "rule_evaluations": list(audit.rule_evaluations),
            "approval_eligible": audit.approval_eligible,
        })

    return mcp


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="delivery-system-mcp")
    parser.add_argument("--workspace-root", required=True)
    args = parser.parse_args(argv)
    context = RuntimeContext.from_workspace_root(args.workspace_root)
    store = SQLitePreviewStore(context)
    create_server(context, store).run()


mcp = create_server()


if __name__ == "__main__":
    main()
