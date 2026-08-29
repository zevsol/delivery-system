"""Planner core: deterministic, read-only conversion of requests to previews."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from .protocol import (
    Assumption,
    Proposed,
    RemoteItemType,
    LegacyRemoteSnapshot,
    UserFact,
    canonical_payload,
    digest,
    preview_id as make_preview_id,
    request_id as make_request_id,
)


@dataclass(frozen=True)
class PlannerCompatibilityPreview:
    """Legacy Slice 1 presentation adapter; not a Runtime SealedPreview."""
    level: str
    request_id: str
    preview_id: str
    revision: int
    stable_digest: str
    remote_snapshot_digest: str | None
    repository: dict[str, Any] | None
    remote_snapshot: Any
    proposed_items: tuple[dict[str, Any], ...]
    duplicate_findings: tuple[dict[str, Any], ...]
    capability_gaps: tuple[str, ...]
    assumptions: tuple[dict[str, Any], ...]
    operations: tuple[dict[str, Any], ...]
    blockers: tuple[str, ...] = ()
    write_eligible: bool = False

    @property
    def preview_level(self) -> str:
        return self.level

    def to_dict(self) -> dict[str, Any]:
        return deepcopy(self.__dict__)

    def is_stale(self, current_remote_snapshot_digest: str | None) -> bool:
        return self.remote_snapshot_digest != current_remote_snapshot_digest


class PlannerDriver(Protocol):
    def inspect_repository(self, repository: str) -> dict[str, Any]: ...
    def search_issues(self, repository: str, query: str) -> list[dict[str, Any]]: ...


def _words(value: Any) -> set[str]:
    return {word.lower() for word in str(value or "").replace("/", " ").split() if len(word) > 2}


def _item_type(candidate: dict[str, Any]) -> RemoteItemType:
    try:
        return RemoteItemType(candidate["item_type"])
    except (KeyError, ValueError) as exc:
        raise ValueError("Remote candidate requires item_type 'issue' or 'pull_request'") from exc


def _evidence(request: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    request_scope = _words(request.get("scope"))
    candidate_scope = _words(candidate.get("scope"))
    return {
        "candidate_title": candidate.get("title", ""),
        "candidate_scope": candidate.get("scope", ""),
        "common_points": sorted(request_scope & candidate_scope),
        "differences": {
            "problem": request.get("problem", "") != candidate.get("problem", ""),
            "outcome": request.get("outcome", "") != candidate.get("outcome", ""),
        },
        "missing_evidence": ["semantic_review", "acceptance_criteria_comparison"],
    }


def classify_candidate(request: dict[str, Any], candidate: dict[str, Any], rid: str) -> dict[str, Any]:
    """Classify runtime-verifiable identity and expose semantic work for review."""
    item_type = _item_type(candidate)
    if item_type is RemoteItemType.PULL_REQUEST:
        raise ValueError("Pull Requests must be filtered before classification")
    same_item = request.get("item_key") is not None and candidate.get("item_key") == request.get("item_key")
    same_marker = request.get("verified_machine_marker") is not None and candidate.get("verified_machine_marker") == request.get("verified_machine_marker")
    if candidate.get("request_id") == rid or same_item or same_marker:
        category, confidence = "exact_identity", "high"
        missing = []
    elif candidate.get("existing_dependency"):
        category, confidence = "existing_dependency", "medium"
        missing = []
    elif candidate.get("existing_parent"):
        category, confidence = "existing_parent", "medium"
        missing = []
    elif candidate.get("proposed_dependency_candidate"):
        category, confidence = "proposed_dependency_candidate", "low"
        missing = ["remote_dependency_confirmation"]
    elif candidate.get("proposed_parent_candidate"):
        category, confidence = "proposed_parent_candidate", "low"
        missing = ["remote_parent_confirmation"]
    else:
        category, confidence = "requires_semantic_review", "unverified"
        missing = ["semantic_review"]
    evidence = _evidence(request, candidate)
    evidence["missing_evidence"] = missing or evidence["missing_evidence"]
    return {
        "issue_id": candidate.get("issue_id"),
        "category": category,
        "confidence": confidence,
        "evidence": evidence,
        "recommended_action": "review_with_user",
    }


class Planner:
    """Create Conceptual or Repository-aware previews without GitHub writes."""

    def __init__(self, driver: PlannerDriver | None = None, id_factory: Callable[[], str] | None = None):
        self.driver = driver
        self.id_factory = id_factory

    def plan(
        self,
        request: dict[str, Any],
        repository: str | None = None,
        previous_preview: PlannerCompatibilityPreview | None = None,
        request_identifier: str | None = None,
        preview_identifier: str | None = None,
    ) -> PlannerCompatibilityPreview:
        original = deepcopy(request)
        self._validate_request_schema(original)
        rid = make_request_id(original, existing=request_identifier or (previous_preview.request_id if previous_preview else None), id_factory=self.id_factory)
        if previous_preview and rid != previous_preview.request_id:
            raise ValueError("Previous Preview Request ID does not match")
        pid = make_preview_id(rid, existing=preview_identifier or (previous_preview.preview_id if previous_preview else None), id_factory=self.id_factory)
        if previous_preview and pid != previous_preview.preview_id:
            raise ValueError("Previous Preview ID does not match")

        info: dict[str, Any] | None = None
        candidates: list[dict[str, Any]] = []
        findings: tuple[dict[str, Any], ...] = ()
        blockers: list[str] = []
        capability_gaps: tuple[str, ...] = ()
        snapshot: LegacyRemoteSnapshot | None = None
        snapshot_digest: str | None = None
        level = "Conceptual"
        if repository and self.driver is not None:
            info = self.driver.inspect_repository(repository)
            if not info.get("can_read", False):
                capability_gaps = ("repository_read",)
            else:
                level = "Repository-aware"
                candidates = self.driver.search_issues(repository, str(original.get("problem", original.get("title", ""))))
                typed_candidates = [_item_type(candidate) for candidate in candidates]
                if any(candidate.get("issue_id") in (None, "") for candidate in candidates):
                    raise ValueError("Remote candidate requires a stable issue_id before classification")
                issue_candidates = [candidate for candidate, item_type in zip(candidates, typed_candidates) if item_type is RemoteItemType.ISSUE]
                findings = tuple(classify_candidate(original, candidate, rid) for candidate in issue_candidates)
                capabilities = tuple(sorted(info.get("capabilities", ())))
                requested = set(original.get("required_capabilities", ()))
                capability_gaps = tuple(sorted(requested - set(capabilities)))
                permissions = info.get("permissions")
                if not isinstance(permissions, dict) or any(not isinstance(value, bool) for value in permissions.values()):
                    blockers.append("permissions_missing_or_invalid")
                if info.get("capability_conflict"):
                    blockers.append("capability_detection_conflict")
                if not info.get("query_complete", True):
                    blockers.append("remote_query_incomplete")
                issue_ids = tuple(sorted(str(item["issue_id"]) for item in issue_candidates if item.get("issue_id") is not None))
                issue_updated_at = tuple(sorted((str(item["issue_id"]), str(item.get("updated_at", ""))) for item in issue_candidates if item.get("issue_id") is not None))
                snapshot = LegacyRemoteSnapshot(
                    repository_id=str(info.get("repository_id", repository)),
                    issue_ids=issue_ids,
                    issue_updated_at=issue_updated_at,
                    capabilities=capabilities,
                    permissions=tuple(sorted((str(key), value) for key, value in (permissions or {}).items())),
                    query_complete=bool(info.get("query_complete", True)),
                    candidate_records=tuple(deepcopy(issue_candidate) for issue_candidate in issue_candidates),
                )
                snapshot_digest = digest(snapshot.to_dict())

        proposed_item = self._proposed_item(original)
        plan_payload = self._semantic_plan_payload(original, repository, proposed_item, findings)
        stable = digest(plan_payload)
        revision = 1
        if previous_preview:
            if previous_preview.revision < 1:
                raise ValueError("Previous Preview revision is invalid")
            revision = previous_preview.revision if previous_preview.stable_digest == stable else previous_preview.revision + 1
        assumptions = self._assumptions(original, repository, blockers)
        return PlannerCompatibilityPreview(
            level=level,
            request_id=rid,
            preview_id=pid,
            revision=revision,
            stable_digest=stable,
            remote_snapshot_digest=snapshot_digest,
            repository=deepcopy(info) if level == "Repository-aware" else None,
            remote_snapshot=snapshot,
            proposed_items=(proposed_item,),
            duplicate_findings=findings,
            capability_gaps=capability_gaps,
            assumptions=assumptions,
            operations=tuple(deepcopy(original.get("operations", ()))),
            blockers=tuple(sorted(blockers)),
            write_eligible=False,
        )

    @staticmethod
    def _semantic_plan_payload(request: dict[str, Any], repository: str | None, proposed_item: dict[str, Any], findings: tuple[dict[str, Any], ...]) -> dict[str, Any]:
        user_facts = request.get("user_facts", {})
        return {
            "repository": repository,
            "proposed_items": proposed_item,
            "relationships": request.get("relationships", ()),
            "operations": request.get("operations", ()),
            "scope": user_facts.get("scope", request.get("scope", "")),
            "non_goals": request.get("non_goals", ()),
            "acceptance_criteria": user_facts.get("acceptance_criteria", request.get("acceptance_criteria", ())),
            "approved_metadata": request.get("approved_metadata", {}),
            "proposals": request.get("proposed", {}),
            "assumptions": request.get("assumptions", ()),
            "required_capabilities": request.get("required_capabilities", ()),
        }

    @classmethod
    def _proposed_item(cls, request: dict[str, Any]) -> dict[str, Any]:
        user_facts = request.get("user_facts", {})
        proposals = request.get("proposed", {})
        criteria = user_facts.get("acceptance_criteria")
        if criteria is not None and not isinstance(criteria, (list, tuple)):
            raise TypeError("user_facts.acceptance_criteria must be a sequence")
        criteria_values = [UserFact(item).to_dict() for item in criteria] if criteria is not None else [Assumption("acceptance criteria required").to_dict()]

        def source_field(field: str, default: Any, missing_is_assumption: bool = False) -> dict[str, Any]:
            if field in user_facts:
                return UserFact(user_facts[field]).to_dict()
            if field in proposals:
                return Proposed(proposals[field]).to_dict()
            if missing_is_assumption:
                return Assumption(default).to_dict()
            return Proposed(default).to_dict()

        return {
            "title": source_field("title", "Proposed GitHub work item"),
            "problem": source_field("problem", "problem information is required", True),
            "outcome": source_field("outcome", "outcome information is required", True),
            "scope": source_field("scope", "scope information is required", True),
            "acceptance_criteria": criteria_values,
        }

    @staticmethod
    def _validate_request_schema(request: dict[str, Any]) -> None:
        user_facts = request.get("user_facts", {})
        if not isinstance(user_facts, dict):
            raise TypeError("user_facts must be a mapping")
        criteria = user_facts.get("acceptance_criteria", request.get("acceptance_criteria"))
        if criteria is not None and not isinstance(criteria, (list, tuple)):
            raise TypeError("user_facts.acceptance_criteria must be a sequence")

    @staticmethod
    def _assumptions(request: dict[str, Any], repository: str | None, blockers: list[str]) -> tuple[dict[str, Any], ...]:
        result = [Assumption(value).to_dict() for value in request.get("assumptions", ())]
        if not repository:
            result.append(Assumption("repository is required for repository-aware claims").to_dict())
        result.extend(Assumption(value).to_dict() for value in blockers)
        return tuple(result)
