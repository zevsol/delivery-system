"""Runtime-owned Rule Registry v1 for the Slice 2B audit contract."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from delivery_system.protocol import digest


class RuleCategory(str, Enum):
    RUNTIME_GATE = "RuntimeGate"
    SEMANTIC = "Semantic"


class SemanticOutcome(str, Enum):
    PASSED = "Passed"
    FAILED = "Failed"
    UNKNOWN = "Unknown"
    BLOCKED = "Blocked"
    NOT_APPLICABLE = "NotApplicable"


class ResultClass(str, Enum):
    WORK_ITEM_CONTENT_GAP = "work_item_content_gap"
    DECOMPOSITION_RISK = "decomposition_risk"
    ACCEPTANCE_CRITERIA_GAP = "acceptance_criteria_gap"
    ASSUMPTION_CLARITY_GAP = "assumption_clarity_gap"
    RELATIONSHIP_RISK = "relationship_risk"
    DEPENDENCY_RISK = "dependency_risk"
    DUPLICATE_OVERLAP_RISK = "duplicate_overlap_risk"
    MISSING_INFORMATION = "missing_information"
    SEMANTIC_BLOCKER = "semantic_blocker"


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    rule_version: str
    category: RuleCategory
    mandatory: bool
    applicability: str
    allowed_outcomes: tuple[str, ...]
    input_scope: str
    evaluation_contract: str
    failed_result_class: str | None = None
    unknown_result_class: str | None = None
    blocked_result_class: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "category": self.category.value,
            "mandatory": self.mandatory,
            "applicability": self.applicability,
            "allowed_outcomes": list(self.allowed_outcomes),
            "input_scope": self.input_scope,
            "evaluation_contract": self.evaluation_contract,
            "failed_result_class": self.failed_result_class,
            "unknown_result_class": self.unknown_result_class,
            "blocked_result_class": self.blocked_result_class,
        }


RUNTIME_RULE_IDS = (
    "RT-PREVIEW-SCHEMA", "RT-PREVIEW-DIGESTS", "RT-PREVIEW-REVISION-CURRENT",
    "RT-PREVIEW-WORKSPACE", "RT-PREVIEW-REMOTE-BINDING", "RT-PREVIEW-EVIDENCE-REFERENCES",
    "RT-AUDIT-CONTEXT-FRESH", "RT-AUDIT-COVERAGE",
)


def _semantic(rule_id: str, contract: str, input_scope: str, failed: str, *, applicability: str = "Applicable") -> RuleDefinition:
    return RuleDefinition(
        rule_id, "1.0", RuleCategory.SEMANTIC, True, applicability,
        ("Passed", "Failed", "Unknown", "Blocked"), input_scope, contract,
        failed, ResultClass.MISSING_INFORMATION.value, ResultClass.SEMANTIC_BLOCKER.value,
    )


def build_registry_v1() -> "RuleRegistry":
    gates = tuple(RuleDefinition(rule_id, "1.0", RuleCategory.RUNTIME_GATE, True, "Always",
                                 ("Pass", "Fail"), "Runtime-owned validation", "Runtime gate validation")
                  for rule_id in RUNTIME_RULE_IDS)
    semantic = (
        _semantic("SEM-WORK-ITEM-COMPLETENESS", "Checks that each Work Item satisfies its role-specific content contract, with explicit Context/Problem, Outcome, Scope, Acceptance Criteria, and Verification; undeclared inference is not treated as a user fact.", "Work Item fields and provenance", ResultClass.WORK_ITEM_CONTENT_GAP.value),
        _semantic("SEM-WORK-ITEM-DECOMPOSITION", "Checks that Work Items are independently understandable and deliverable, that Scope and Outcome agree, and that oversized items, resultless technical tasks, or missing shared capabilities are identified.", "Work Item collection, Scope, and Outcome", ResultClass.DECOMPOSITION_RISK.value),
        _semantic("SEM-ACCEPTANCE-CRITERIA", "Checks that Acceptance Criteria are observable, verifiable, and bounded, and that Verification can prove the result rather than merely describe implementation steps.", "Acceptance Criteria and Verification", ResultClass.ACCEPTANCE_CRITERIA_GAP.value),
        _semantic("SEM-ASSUMPTION-CLARITY", "Checks that User Asserted, Model Proposed, and Model Assumption values remain distinct; unconfirmed facts affecting scope, acceptance, or relationships must request clarification.", "Provenance and assumptions", ResultClass.ASSUMPTION_CLARITY_GAP.value),
        _semantic("SEM-PARENT-SUBISSUE", "Checks that a child genuinely serves the parent Outcome, that hierarchy is necessary, and that there is no semantic inversion, orphan child, or unreasonable depth.", "Parent/Sub-issue candidates and relationships", ResultClass.RELATIONSHIP_RISK.value, applicability="Runtime"),
        _semantic("SEM-DEPENDENCY", "Checks that dependency direction, blocking cause, and necessity have evidence; implementation-order proximity alone is insufficient.", "Dependency candidates and relationships", ResultClass.DEPENDENCY_RISK.value, applicability="Runtime"),
        _semantic("SEM-DUPLICATE-OVERLAP", "Uses current Remote Evidence to assess Duplicate, Partial Overlap, Related, or other relationships; title, keyword overlap, or similarity alone cannot establish duplication.", "Remote Evidence and Work Items", ResultClass.DUPLICATE_OVERLAP_RISK.value, applicability="Runtime"),
    )
    return RuleRegistry("1.0", gates + semantic)


@dataclass(frozen=True)
class RuleRegistry:
    registry_version: str
    rules: tuple[RuleDefinition, ...]

    @property
    def registry_digest(self) -> str:
        return digest({"registry_version": self.registry_version, "rules": [rule.to_dict() for rule in self.rules]})

    @property
    def runtime_rules(self) -> tuple[RuleDefinition, ...]:
        return tuple(rule for rule in self.rules if rule.category is RuleCategory.RUNTIME_GATE)

    @property
    def semantic_rules(self) -> tuple[RuleDefinition, ...]:
        return tuple(rule for rule in self.rules if rule.category is RuleCategory.SEMANTIC)

    def get(self, rule_id: str) -> RuleDefinition:
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule
        raise ValueError("invalid_input")
