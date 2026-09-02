"""Runtime-owned validation for the bounded V1 write-operation contract."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence


WRITE_OPERATION_KINDS = ("create_issue", "add_sub_issue", "add_dependency")
_RELATIONSHIP_KINDS = {
    "add_sub_issue": "planned_parent",
    "add_dependency": "planned_dependency",
}
_OPERATION_FIELDS = frozenset(("operation_kind", "client_refs", "depends_on"))


@dataclass(frozen=True)
class WriteOperationEvaluation:
    operations: tuple[dict[str, Any], ...]
    eligible: bool
    blockers: tuple[str, ...]


def normalize_write_operations(operation_intents: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], ...]:
    """Validate the canonical operation-entry shape without trusting provider fields."""
    if not isinstance(operation_intents, Sequence) or isinstance(operation_intents, (str, bytes)):
        raise ValueError("write_operation_set_invalid")
    normalized: list[dict[str, Any]] = []
    for operation in operation_intents:
        if not isinstance(operation, Mapping) or set(operation) != _OPERATION_FIELDS:
            raise ValueError("write_operation_shape_invalid")
        kind = operation["operation_kind"]
        refs = operation["client_refs"]
        dependencies = operation["depends_on"]
        if (not isinstance(kind, str) or not kind or
                not isinstance(refs, list) or not isinstance(dependencies, list) or
                not all(isinstance(ref, str) and bool(ref) for ref in refs) or
                not all(isinstance(value, str) and bool(value) for value in dependencies)):
            raise ValueError("write_operation_shape_invalid")
        if len(refs) != len(set(refs)):
            raise ValueError("write_operation_client_refs_duplicate")
        normalized.append({
            "operation_kind": kind,
            "client_refs": list(refs),
            "depends_on": list(dependencies),
        })
    return tuple(normalized)


def operation_set_digest_payload(operation_intents: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Canonicalize planning data without granting it write eligibility."""
    if not isinstance(operation_intents, Sequence) or isinstance(operation_intents, (str, bytes)):
        raise ValueError("write_operation_set_invalid")
    if not all(isinstance(operation, Mapping) for operation in operation_intents):
        raise ValueError("write_operation_shape_invalid")
    return {"operation_intents": [
        {key: value for key, value in operation.items()
         if key not in {"id", "operation_id"}}
        for operation in operation_intents
    ]}


def evaluate_write_operations(
    operation_intents: Sequence[Mapping[str, Any]],
    items: Sequence[Mapping[str, Any]],
    semantic_payload: Mapping[str, Any],
) -> WriteOperationEvaluation:
    """Evaluate whether the exact canonical operation sequence is V1 write-eligible."""
    operations = normalize_write_operations(operation_intents)
    item_refs = [item.get("client_ref") for item in items if isinstance(item, Mapping)]
    blockers: list[str] = []
    if (len(item_refs) != len(items) or not item_refs or
            any(not isinstance(ref, str) or not ref for ref in item_refs) or
            len(item_refs) != len(set(item_refs))):
        raise ValueError("write_operation_item_set_invalid")
    known_refs = set(item_refs)

    for operation in operations:
        kind = operation["operation_kind"]
        refs = operation["client_refs"]
        if any(ref not in known_refs for ref in refs):
            blockers.append("write_operation_unknown_client_ref")
        if operation["depends_on"]:
            blockers.append("write_operation_dependencies_unsupported")
        if kind not in WRITE_OPERATION_KINDS:
            blockers.append("write_operation_kind_not_write_eligible")
        elif kind == "create_issue" and len(refs) != 1:
            blockers.append("write_operation_create_issue_shape_invalid")
        elif kind in _RELATIONSHIP_KINDS and (len(refs) != 2 or refs[0] == refs[1]):
            blockers.append("write_operation_relationship_shape_invalid")

    create_refs = [op["client_refs"][0] for op in operations
                   if op["operation_kind"] == "create_issue" and len(op["client_refs"]) == 1]
    if len(create_refs) != len(set(create_refs)):
        blockers.append("write_operation_duplicate_create_issue")
    if set(create_refs) != known_refs or len(create_refs) != len(known_refs):
        blockers.append("write_operation_create_issue_incomplete")

    planned = semantic_payload.get("planned_relationships", ())
    planned_pairs: list[tuple[str, str, str]] = []
    if not isinstance(planned, list):
        raise ValueError("write_operation_relationships_invalid")
    for relationship in planned:
        if not isinstance(relationship, Mapping):
            raise ValueError("write_operation_relationships_invalid")
        kind = relationship.get("kind")
        source = relationship.get("from_client_ref")
        target = relationship.get("to_client_ref")
        if kind not in {"planned_parent", "planned_dependency"} or not all(
                isinstance(value, str) and bool(value) for value in (source, target)):
            raise ValueError("write_operation_relationships_invalid")
        planned_pairs.append((kind, source, target))

    operation_pairs = {
        (_RELATIONSHIP_KINDS[operation["operation_kind"]], *operation["client_refs"])
        for operation in operations
        if operation["operation_kind"] in _RELATIONSHIP_KINDS and len(operation["client_refs"]) == 2
    }
    if any(pair not in operation_pairs for pair in planned_pairs):
        blockers.append("write_operation_relationship_incomplete")
    if any(pair not in planned_pairs for pair in operation_pairs):
        blockers.append("write_operation_relationship_unplanned")

    expected = tuple(
        {"operation_kind": "create_issue", "client_refs": [ref], "depends_on": []}
        for ref in item_refs
    ) + tuple(
        {"operation_kind": "add_sub_issue" if kind == "planned_parent" else "add_dependency",
         "client_refs": [source, target], "depends_on": []}
        for kind, source, target in planned_pairs
    )
    if operations != expected:
        blockers.append("write_operation_order_invalid")

    return WriteOperationEvaluation(operations, not blockers, tuple(sorted(set(blockers))))
