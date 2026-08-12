"""Runtime Auditor contract; semantic decisions remain declarative inputs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import re
import uuid
from typing import Any, Mapping, cast

from delivery_system.protocol import digest
from delivery_system.rules import ResultClass, RuleCategory, RuleRegistry, SemanticOutcome
from delivery_system.runtime import (
    AuditRecord, AuditResult, AuditStatus, AuditContextService,
    RuntimeContext, _preview_binding_value, compute_audit_context_digest,
)

_EVALUATION_FIELDS = frozenset({"rule_id", "rule_version", "outcome", "rationale", "finding_refs", "evidence_refs"})
_FINDING_FIELDS = frozenset({"finding_id", "rule_id", "rule_version", "outcome", "result_class", "severity", "title", "rationale", "evidence_refs", "affected_item_ids", "required_action", "suggested_resolution"})


def _validate_audit_children(evaluations: list[dict[str, Any]], findings: list[dict[str, Any]]) -> None:
    for entry in evaluations:
        if not isinstance(entry, dict) or set(entry) != _EVALUATION_FIELDS:
            raise ValueError("audit_commit_boundary_required")
        if any(not isinstance(entry[key], str) or not entry[key] for key in ("rule_id", "rule_version", "outcome", "rationale")):
            raise ValueError("audit_commit_boundary_required")
        for key in ("finding_refs", "evidence_refs"):
            values = entry[key]
            if not isinstance(values, list) or any(not isinstance(value, str) or not value for value in values) or len(values) != len(set(values)):
                raise ValueError("audit_commit_boundary_required")
    for finding in findings:
        if not isinstance(finding, dict) or set(finding) != _FINDING_FIELDS:
            raise ValueError("audit_commit_boundary_required")
        for key in ("finding_id", "rule_id", "rule_version", "outcome", "result_class", "severity", "title", "rationale", "required_action"):
            if not isinstance(finding[key], str) or not finding[key]:
                raise ValueError("audit_commit_boundary_required")
        if finding["suggested_resolution"] is not None and not isinstance(finding["suggested_resolution"], str):
            raise ValueError("audit_commit_boundary_required")
        for key in ("evidence_refs", "affected_item_ids"):
            values = finding[key]
            if not isinstance(values, list) or any(not isinstance(value, str) or not value for value in values) or len(values) != len(set(values)):
                raise ValueError("audit_commit_boundary_required")


def validate_current_commit_context(audit: AuditRecord, envelope: dict[str, Any],
                                    evidence_records: list[dict[str, Any]], registry: RuleRegistry,
                                    expected_workspace_identity: str) -> None:
    """Single current-state validator used inside both Store commit boundaries."""
    from delivery_system.runtime import _validate_preview_payload
    if audit.status is not AuditStatus.ACTIVE:
        raise ValueError("audit_commit_boundary_required")
    if not isinstance(envelope, dict) or set(envelope) != {"request_id", "preview_id", "revision", "canonical_payload"}:
        raise ValueError("audit_commit_boundary_required")
    record_request_id = envelope["request_id"]
    record_preview_id = envelope["preview_id"]
    record_revision = envelope["revision"]
    canonical = envelope["canonical_payload"]
    if (not isinstance(record_request_id, str) or not record_request_id or
            not isinstance(record_preview_id, str) or not record_preview_id or
            not isinstance(record_revision, int) or isinstance(record_revision, bool) or record_revision < 1 or
            not isinstance(canonical, dict)):
        raise ValueError("audit_commit_boundary_required")
    if (record_request_id != canonical.get("request_id") or
            record_preview_id != canonical.get("preview_id") or
            record_revision != canonical.get("revision") or
            audit.workspace_identity != expected_workspace_identity or
            audit.preview_id != record_preview_id or audit.revision != record_revision or
            audit.audit_scope != canonical.get("preview_level") or
            audit.plan_digest != canonical.get("plan_digest") or
            audit.operation_set_digest != canonical.get("operation_set_digest") or
            audit.remote_snapshot_digest != canonical.get("remote_snapshot_digest") or
            audit.sealed_preview_digest != canonical.get("sealed_preview_digest")):
        raise ValueError("audit_commit_boundary_required")
    canonical_evidence_ids = canonical.get("evidence_ids")
    if (not isinstance(canonical_evidence_ids, list) or
            any(not isinstance(value, str) or not value for value in canonical_evidence_ids) or
            len(canonical_evidence_ids) != len(set(canonical_evidence_ids)) or
            tuple(audit.evidence_refs) != tuple(sorted(canonical_evidence_ids))):
        raise ValueError("audit_commit_boundary_required")
    plan_digest = canonical.get("plan_digest")
    operation_set_digest = canonical.get("operation_set_digest")
    if not isinstance(plan_digest, str) or not isinstance(operation_set_digest, str):
        raise ValueError("audit_commit_boundary_required")
    normalized = _validate_preview_payload(
        canonical, record_request_id, record_preview_id, record_revision,
        plan_digest, operation_set_digest,
        canonical.get("remote_snapshot_digest"), canonical.get("repository_identity"),
        evidence_records, expected_workspace_identity,
    )
    if normalized != canonical:
        raise ValueError("audit_commit_boundary_required")
    from delivery_system.runtime import _validate_formal_audit_boundary
    _validate_formal_audit_boundary(audit, canonical, expected_workspace_identity)
    _validate_audit_children(list(audit.rule_evaluations), list(audit.findings))
    validate_committed_audit(audit, canonical, evidence_records, registry)


@dataclass(frozen=True)
class RuleEvaluationDraft:
    rule_id: str
    rule_version: str
    outcome: SemanticOutcome | str
    rationale: str
    finding_refs: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class FindingDraft:
    finding_ref: str
    rule_id: str
    result_class: ResultClass | str
    severity: str
    title: str
    rationale: str
    evidence_refs: tuple[str, ...]
    affected_item_ids: tuple[str, ...]
    required_action: str
    suggested_resolution: str | None


def build_finding_id(workspace_identity: str, preview_id: str, revision: int,
                     rule_id: str, rule_version: str, outcome: SemanticOutcome | str,
                     result_class: ResultClass | str, severity: str, title: str,
                     rationale: str, evidence_refs: tuple[str, ...],
                     affected_item_ids: tuple[str, ...], required_action: str,
                     suggested_resolution: str | None) -> str:
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise ValueError("invalid_input")
    values = (workspace_identity, preview_id, rule_id, rule_version, severity, title, rationale, required_action)
    if any(not isinstance(value, str) or not value for value in values):
        raise ValueError("invalid_input")
    if severity not in {"Blocker", "High", "Medium", "Low"}:
        raise ValueError("invalid_input")
    if not isinstance(outcome, (SemanticOutcome, str)) or not isinstance(result_class, (ResultClass, str)):
        raise ValueError("invalid_input")
    if not isinstance(suggested_resolution, (str, type(None))):
        raise ValueError("invalid_input")
    if any(not isinstance(value, str) or not value for value in evidence_refs + affected_item_ids):
        raise ValueError("invalid_input")
    if len(set(evidence_refs)) != len(evidence_refs) or len(set(affected_item_ids)) != len(affected_item_ids):
        raise ValueError("invalid_input")
    from delivery_system.protocol import canonical_payload
    payload = {
        "domain": "delivery-system:finding-id:v1",
        "workspace_identity": workspace_identity,
        "preview_id": preview_id,
        "revision": revision,
        "rule_id": rule_id,
        "rule_version": rule_version,
        "outcome": SemanticOutcome(outcome).value,
        "result_class": ResultClass(result_class).value,
        "severity": severity,
        "title": title,
        "rationale": rationale,
        "evidence_refs": sorted(evidence_refs),
        "affected_item_ids": sorted(affected_item_ids),
        "required_action": required_action,
        "suggested_resolution": suggested_resolution,
    }
    return "finding_" + hashlib.sha256(canonical_payload(payload).encode("utf-8")).hexdigest()


def rule_is_applicable(rule, canonical: dict[str, Any]) -> bool:
    if rule.applicability == "Applicable":
        return True
    relationships = canonical.get("semantic_payload", {}).get("planned_relationships", [])
    if rule.rule_id == "SEM-PARENT-SUBISSUE":
        return any(value.get("kind") in {"planned_parent", "planned_parent_candidate"} for value in relationships)
    if rule.rule_id == "SEM-DEPENDENCY":
        return any(value.get("kind") in {"planned_dependency", "planned_dependency_candidate"} for value in relationships)
    if rule.rule_id == "SEM-DUPLICATE-OVERLAP":
        return canonical.get("preview_level") != "Conceptual"
    return False


def validate_committed_audit(audit: AuditRecord, canonical: dict[str, Any],
                             evidence_records: list[dict[str, Any]], registry: RuleRegistry) -> None:
    """Pure Runtime-owned validation shared by Auditor and Store commit boundaries."""
    _validate_audit_children(list(audit.rule_evaluations), list(audit.findings))
    if audit.rule_registry_version != registry.registry_version or audit.rule_registry_digest != registry.registry_digest:
        raise ValueError("audit_commit_boundary_required")
    evidence_context = cast(list[Mapping[str, Any]], evidence_records)
    expected_context = compute_audit_context_digest(
        audit.workspace_identity, audit.preview_id, audit.revision,
        audit.sealed_preview_digest, evidence_context,
        registry.registry_version, registry.registry_digest, audit.audit_scope,
    )
    if audit.audit_context_digest != expected_context:
        raise ValueError("audit_commit_boundary_required")
    rules = {rule.rule_id: rule for rule in registry.semantic_rules}
    evaluations = list(audit.rule_evaluations)
    if len({entry.get("rule_id") for entry in evaluations}) != len(evaluations):
        raise ValueError("audit_commit_boundary_required")
    if {entry.get("rule_id") for entry in evaluations} != set(rules):
        raise ValueError("audit_commit_boundary_required")
    evidence_ids = {record["evidence_id"] for record in evidence_records}
    item_ids = {item["item_id"] for item in canonical.get("items", [])}
    eval_by_rule = {entry["rule_id"]: entry for entry in evaluations}
    for rule_id, rule in rules.items():
        entry = eval_by_rule[rule_id]
        if entry.get("rule_version") != rule.rule_version:
            raise ValueError("audit_commit_boundary_required")
        applicable = rule_is_applicable(rule, canonical)
        if not applicable:
            if entry.get("outcome") != SemanticOutcome.NOT_APPLICABLE.value or entry.get("finding_refs") != [] or entry.get("evidence_refs") != []:
                raise ValueError("audit_commit_boundary_required")
        elif entry.get("outcome") not in {SemanticOutcome.PASSED.value, SemanticOutcome.FAILED.value, SemanticOutcome.UNKNOWN.value, SemanticOutcome.BLOCKED.value}:
            raise ValueError("audit_commit_boundary_required")
        if any(ref not in evidence_ids for ref in entry.get("evidence_refs", [])):
            raise ValueError("audit_commit_boundary_required")
    findings = list(audit.findings)
    findings_by_id: dict[str, dict[str, Any]] = {}
    for finding in findings:
        finding_id = finding.get("finding_id")
        if (not isinstance(finding_id, str) or not finding_id or
                finding_id in findings_by_id or "finding_ref" in finding):
            raise ValueError("audit_commit_boundary_required")
        findings_by_id[finding_id] = finding
    referenced_ids: list[str] = []
    for entry in evaluations:
        outcome = entry["outcome"]
        refs = entry.get("finding_refs", [])
        if outcome == SemanticOutcome.PASSED.value or outcome == SemanticOutcome.NOT_APPLICABLE.value:
            if refs:
                raise ValueError("audit_commit_boundary_required")
        elif not refs:
            raise ValueError("audit_commit_boundary_required")
        for finding_id in refs:
            finding = findings_by_id.get(finding_id)
            if finding is None or finding.get("rule_id") != entry["rule_id"]:
                raise ValueError("audit_commit_boundary_required")
            referenced_ids.append(finding_id)
    if sorted(referenced_ids) != sorted(findings_by_id.keys()):
        raise ValueError("audit_commit_boundary_required")
    for finding_id, finding in findings_by_id.items():
        rule_id = finding.get("rule_id")
        if not isinstance(rule_id, str):
            raise ValueError("audit_commit_boundary_required")
        rule = rules.get(rule_id)
        entry = eval_by_rule.get(rule_id)
        if rule is None or entry is None or entry["outcome"] == SemanticOutcome.NOT_APPLICABLE.value:
            raise ValueError("audit_commit_boundary_required")
        if (finding.get("rule_version") != rule.rule_version or
                finding.get("outcome") != entry.get("outcome") or
                finding.get("severity") not in {"Blocker", "High", "Medium", "Low"}):
            raise ValueError("audit_commit_boundary_required")
        outcome = SemanticOutcome(entry["outcome"])
        expected_class = {
            SemanticOutcome.FAILED: rule.failed_result_class,
            SemanticOutcome.UNKNOWN: rule.unknown_result_class,
            SemanticOutcome.BLOCKED: rule.blocked_result_class,
        }.get(outcome)
        if finding.get("result_class") != expected_class or any(ref not in evidence_ids for ref in finding.get("evidence_refs", [])) or any(item not in item_ids for item in finding.get("affected_item_ids", [])):
            raise ValueError("audit_commit_boundary_required")
        computed_id = build_finding_id(
            audit.workspace_identity, audit.preview_id, audit.revision,
            finding["rule_id"], rule.rule_version, outcome, finding["result_class"],
            finding["severity"], finding["title"], finding["rationale"],
            tuple(finding.get("evidence_refs", [])), tuple(finding.get("affected_item_ids", [])),
            finding["required_action"], finding.get("suggested_resolution"),
        )
        if computed_id != finding_id:
            raise ValueError("audit_commit_boundary_required")
    outcomes = {entry["outcome"] for entry in evaluations}
    expected_result = (AuditResult.BLOCKED if "Blocked" in outcomes else
                       AuditResult.NEEDS_INFORMATION if "Unknown" in outcomes else
                       AuditResult.CHANGES_REQUIRED if "Failed" in outcomes else AuditResult.PASSED)
    if audit.result is not expected_result:
        raise ValueError("audit_commit_boundary_required")
    payload = {
        "workspace_identity": audit.workspace_identity, "preview_id": audit.preview_id,
        "revision": audit.revision, "audit_scope": audit.audit_scope,
        "sealed_preview_digest": audit.sealed_preview_digest, "plan_digest": audit.plan_digest,
        "operation_set_digest": audit.operation_set_digest, "remote_snapshot_digest": audit.remote_snapshot_digest,
        "audit_context_digest": audit.audit_context_digest, "rule_registry_version": registry.registry_version,
        "rule_registry_digest": registry.registry_digest, "semantic_evaluations": evaluations,
        "findings": findings, "result": audit.result.value,
    }
    if digest(payload) != audit.audit_payload_digest or not audit.verify_digest():
        raise ValueError("audit_commit_boundary_required")


class RuntimeAuditor:
    def __init__(self, context: RuntimeContext, store: Any, registry: RuleRegistry):
        self.context = context
        self.store = store
        self.registry = registry

    def _applicable(self, rule, canonical: dict[str, Any]) -> bool:
        return rule_is_applicable(rule, canonical)

    def get_context(self, preview_id: str, revision: int) -> dict[str, Any]:
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise ValueError("invalid_input")
        context = AuditContextService(self.context, self.store).get(preview_id, revision)
        canonical = context["sealed_preview"]
        semantic_contexts = []
        for rule in self.registry.semantic_rules:
            applicable = self._applicable(rule, canonical)
            semantic_contexts.append({
                "rule_id": rule.rule_id,
                "rule_version": rule.rule_version,
                "applicability": "Applicable" if applicable else "NotApplicable",
                "applicability_reason": "required by registry" if applicable else "no matching relationship or remote evidence",
                "mandatory": rule.mandatory,
                "input_scope": rule.input_scope,
                "evaluation_contract": rule.evaluation_contract,
                "allowed_outcomes": list(rule.allowed_outcomes),
                "allowed_result_classes": [value for value in (
                    rule.failed_result_class, rule.unknown_result_class, rule.blocked_result_class
                ) if value is not None],
            })
        context["audit_scope"] = canonical["preview_level"]
        context["context_status"] = "audit_ready"
        context["rule_registry_version"] = self.registry.registry_version
        context["rule_registry_digest"] = self.registry.registry_digest
        context["semantic_rule_contexts"] = semantic_contexts
        evidence = context["evidence_records"]
        context["audit_context_digest"] = compute_audit_context_digest(
            self.context.workspace_identity, preview_id, revision,
            canonical["sealed_preview_digest"], evidence,
            self.registry.registry_version, self.registry.registry_digest,
            canonical["preview_level"],
        )
        return context

    def _validate(self, context: dict[str, Any], evaluations: list[RuleEvaluationDraft], findings: list[FindingDraft]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        rules = {rule.rule_id: rule for rule in self.registry.semantic_rules}
        contexts = {item["rule_id"]: item for item in context["semantic_rule_contexts"]}
        evidence_ids = {record["evidence_id"] for record in context["evidence_records"]}
        runtime_rule_ids = {rule.rule_id for rule in self.registry.runtime_rules}
        if any(e.rule_id in runtime_rule_ids for e in evaluations):
            raise ValueError("invalid_runtime_rule_submission")
        if any(e.rule_id not in rules for e in evaluations):
            raise ValueError("invalid_input")
        if len({e.rule_id for e in evaluations}) != len(evaluations):
            raise ValueError("invalid_input")
        if any(e.outcome == SemanticOutcome.NOT_APPLICABLE or str(e.outcome) == "NotApplicable" for e in evaluations):
            raise ValueError("invalid_not_applicable_submission")
        eval_by_rule = {e.rule_id: e for e in evaluations}
        if any(e.rule_version != rules[e.rule_id].rule_version for e in evaluations):
            raise ValueError("invalid_input")
        if any(reference not in evidence_ids for evaluation in evaluations for reference in evaluation.evidence_refs):
            raise ValueError("invalid_input")
        for rule_id, rule_context in contexts.items():
            if rule_context["applicability"] == "Applicable" and rule_context["mandatory"] and rule_id not in eval_by_rule:
                raise ValueError("audit_coverage_incomplete")
            if rule_context["applicability"] == "NotApplicable" and rule_id in eval_by_rule:
                raise ValueError("invalid_input")
        finding_refs = [finding.finding_ref for finding in findings]
        if len(finding_refs) != len(set(finding_refs)):
            raise ValueError("invalid_input")
        item_ids = {item["item_id"] for item in context["sealed_preview"].get("items", [])}
        findings_by_ref = {finding.finding_ref: finding for finding in findings}
        finding_ids_by_ref: dict[str, str] = {}
        for finding in findings:
            if finding.rule_id not in eval_by_rule or any(item_id not in item_ids for item_id in finding.affected_item_ids):
                raise ValueError("invalid_input")
            if any(reference not in evidence_ids for reference in finding.evidence_refs):
                raise ValueError("invalid_input")
            try:
                result_class = ResultClass(finding.result_class)
                outcome = SemanticOutcome(eval_by_rule[finding.rule_id].outcome)
            except ValueError as exc:
                raise ValueError("invalid_input") from exc
            rule = rules[finding.rule_id]
            expected = {
                SemanticOutcome.FAILED: rule.failed_result_class,
                SemanticOutcome.UNKNOWN: rule.unknown_result_class,
                SemanticOutcome.BLOCKED: rule.blocked_result_class,
            }.get(outcome)
            if expected != result_class.value:
                raise ValueError("invalid_input")
            if finding.severity not in {"Blocker", "High", "Medium", "Low"}:
                raise ValueError("invalid_input")
            finding_ids_by_ref[finding.finding_ref] = build_finding_id(
                self.context.workspace_identity, context["preview_id"], context["revision"],
                finding.rule_id, rule.rule_version, outcome, result_class, finding.severity,
                finding.title, finding.rationale, finding.evidence_refs,
                finding.affected_item_ids, finding.required_action, finding.suggested_resolution,
            )
        if len(set(finding_ids_by_ref.values())) != len(finding_ids_by_ref):
            raise ValueError("invalid_input")
        for evaluation in evaluations:
            outcome = SemanticOutcome(evaluation.outcome)
            refs = set(evaluation.finding_refs)
            if outcome in {SemanticOutcome.FAILED, SemanticOutcome.UNKNOWN, SemanticOutcome.BLOCKED} and not refs:
                raise ValueError("invalid_input")
            if outcome is SemanticOutcome.PASSED and refs:
                raise ValueError("invalid_input")
            if any(ref not in findings_by_ref or findings_by_ref[ref].rule_id != evaluation.rule_id for ref in refs):
                raise ValueError("invalid_input")
        referenced = {ref for evaluation in evaluations for ref in evaluation.finding_refs}
        if referenced != set(findings_by_ref):
            raise ValueError("invalid_input")
        evaluation_payload = [{"rule_id": e.rule_id, "rule_version": e.rule_version, "outcome": SemanticOutcome(e.outcome).value, "rationale": e.rationale, "finding_refs": sorted(finding_ids_by_ref[ref] for ref in e.finding_refs), "evidence_refs": sorted(e.evidence_refs)} for e in evaluations]
        for rule_id, rule_context in contexts.items():
            if rule_context["applicability"] == "NotApplicable":
                rule = rules[rule_id]
                evaluation_payload.append({
                    "rule_id": rule_id,
                    "rule_version": rule.rule_version,
                    "outcome": SemanticOutcome.NOT_APPLICABLE.value,
                    "rationale": rule_context["applicability_reason"],
                    "finding_refs": [],
                    "evidence_refs": [],
                })
        finding_payload = [{"finding_id": finding_ids_by_ref[f.finding_ref], "rule_id": f.rule_id, "rule_version": rules[f.rule_id].rule_version, "outcome": SemanticOutcome(eval_by_rule[f.rule_id].outcome).value, "result_class": ResultClass(f.result_class).value, "severity": f.severity, "title": f.title, "rationale": f.rationale, "evidence_refs": sorted(f.evidence_refs), "affected_item_ids": sorted(f.affected_item_ids), "required_action": f.required_action, "suggested_resolution": f.suggested_resolution} for f in findings]
        return sorted(evaluation_payload, key=lambda value: value["rule_id"]), sorted(finding_payload, key=lambda value: value["finding_id"])

    def record_audit(self, preview_id: str, revision: int, expected_context_digest: str,
                     evaluations: list[RuleEvaluationDraft], findings: list[FindingDraft]) -> AuditRecord:
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise ValueError("invalid_input")
        if not isinstance(expected_context_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_context_digest):
            raise ValueError("invalid_input")
        context = self.get_context(preview_id, revision)
        if expected_context_digest != context["audit_context_digest"]:
            raise ValueError("audit_context_stale")
        evaluation_payload, finding_payload = self._validate(context, evaluations, findings)
        result = AuditResult.PASSED
        outcomes = [entry["outcome"] for entry in evaluation_payload]
        if "Blocked" in outcomes:
            result = AuditResult.BLOCKED
        elif "Unknown" in outcomes:
            result = AuditResult.NEEDS_INFORMATION
        elif "Failed" in outcomes:
            result = AuditResult.CHANGES_REQUIRED
        payload = {
            "workspace_identity": self.context.workspace_identity,
            "preview_id": preview_id,
            "revision": revision,
            "audit_scope": context["audit_scope"],
            "sealed_preview_digest": context["sealed_preview"]["sealed_preview_digest"],
            "plan_digest": context["sealed_preview"]["plan_digest"],
            "operation_set_digest": context["sealed_preview"]["operation_set_digest"],
            "remote_snapshot_digest": context["sealed_preview"].get("remote_snapshot_digest"),
            "audit_context_digest": expected_context_digest,
            "rule_registry_version": self.registry.registry_version,
            "rule_registry_digest": self.registry.registry_digest,
            "semantic_evaluations": evaluation_payload,
            "findings": finding_payload,
            "result": result.value,
        }
        audit_payload_digest = digest(payload)
        audit = AuditRecord.create(
            "audit-" + uuid.uuid4().hex, preview_id, revision,
            payload["plan_digest"], payload["remote_snapshot_digest"],
            payload["operation_set_digest"], result,
            workspace_identity=self.context.workspace_identity,
            audit_scope=context["audit_scope"], audit_payload_digest=audit_payload_digest,
            audit_context_digest=expected_context_digest,
            rule_registry_version=self.registry.registry_version,
            rule_registry_digest=self.registry.registry_digest,
            rule_evaluations=tuple(evaluation_payload), findings=tuple(finding_payload),
            evidence_refs=tuple(sorted(record["evidence_id"] for record in context["evidence_records"])),
            sealed_preview_digest=payload["sealed_preview_digest"],
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        validate_committed_audit(audit, context["sealed_preview"], context["evidence_records"], self.registry)
        return self.store.commit_audit(audit)
