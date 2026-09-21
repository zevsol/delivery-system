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
_V2_CREATE_FIELDS = frozenset(("operation_kind", "endpoint", "depends_on"))
_V2_REL_FIELDS = frozenset(("operation_kind", "operands", "depends_on"))


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


def operation_set_digest_payload_v2(operation_intents: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Canonical V2 operation payload; legacy operation shapes are never rewritten."""
    if not isinstance(operation_intents, Sequence) or isinstance(operation_intents, (str, bytes)):
        raise ValueError("write_operation_set_invalid")
    result = []
    for operation in operation_intents:
        if not isinstance(operation, Mapping):
            raise ValueError("write_operation_shape_invalid")
        result.append(dict(operation))
    return {"canonical_version": "2", "operation_intents": result}


def _v2_endpoint(value: Any) -> tuple[str, str]:
    if not isinstance(value, Mapping) or set(value) != {"endpoint_type", "client_ref"} and set(value) != {"endpoint_type", "endpoint_ref"}:
        raise ValueError("write_operation_endpoint_invalid")
    kind = value.get("endpoint_type")
    if kind == "work_item" and set(value) == {"endpoint_type", "client_ref"}:
        ref = value.get("client_ref")
    elif kind == "existing_issue" and set(value) == {"endpoint_type", "endpoint_ref"}:
        ref = value.get("endpoint_ref")
    else:
        raise ValueError("write_operation_endpoint_invalid")
    if not isinstance(ref, str) or not ref:
        raise ValueError("write_operation_endpoint_invalid")
    return str(kind), ref


def normalize_write_operations_v2(operation_intents: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], ...]:
    if not isinstance(operation_intents, Sequence) or isinstance(operation_intents, (str, bytes)):
        raise ValueError("write_operation_set_invalid")
    normalized = []
    for operation in operation_intents:
        if not isinstance(operation, Mapping):
            raise ValueError("write_operation_shape_invalid")
        kind = operation.get("operation_kind")
        deps = operation.get("depends_on")
        if not isinstance(kind, str) or not isinstance(deps, list) or any(not isinstance(v, str) or not v for v in deps):
            raise ValueError("write_operation_shape_invalid")
        if kind == "create_issue":
            if set(operation) != _V2_CREATE_FIELDS:
                raise ValueError("write_operation_shape_invalid")
            endpoint = operation.get("endpoint")
            if _v2_endpoint(endpoint)[0] != "work_item":
                raise ValueError("write_operation_create_endpoint_invalid")
            normalized.append({"operation_kind": kind, "endpoint": dict(endpoint), "depends_on": list(deps)})
        elif kind in {"add_sub_issue", "add_dependency"}:
            if set(operation) != _V2_REL_FIELDS:
                raise ValueError("write_operation_shape_invalid")
            operands = operation.get("operands")
            if not isinstance(operands, list) or len(operands) != 2:
                raise ValueError("write_operation_relationship_shape_invalid")
            first, second = _v2_endpoint(operands[0]), _v2_endpoint(operands[1])
            if first == second:
                raise ValueError("write_operation_relationship_shape_invalid")
            normalized.append({"operation_kind": kind, "operands": [dict(operands[0]), dict(operands[1])], "depends_on": list(deps)})
        else:
            raise ValueError("write_operation_kind_not_write_eligible")
    return tuple(normalized)


def evaluate_write_operations_v2(
    operation_intents: Sequence[Mapping[str, Any]],
    items: Sequence[Mapping[str, Any]],
    semantic_payload: Mapping[str, Any],
    endpoint_bindings: Sequence[Mapping[str, Any]],
    relationship_records: Sequence[Mapping[str, Any]] = (),
) -> WriteOperationEvaluation:
    operations = normalize_write_operations_v2(operation_intents)
    item_refs = [item.get("client_ref") for item in items if isinstance(item, Mapping)]
    if not item_refs or any(not isinstance(ref, str) or not ref for ref in item_refs) or len(item_refs) != len(set(item_refs)):
        raise ValueError("write_operation_item_set_invalid")
    endpoint_refs = [binding.get("endpoint_ref") for binding in endpoint_bindings if isinstance(binding, Mapping)]
    if any(not isinstance(ref, str) or not ref for ref in endpoint_refs) or len(endpoint_refs) != len(set(endpoint_refs)):
        raise ValueError("write_operation_endpoint_set_invalid")
    if set(item_refs) & set(endpoint_refs):
        raise ValueError("write_operation_reference_namespace_collision")
    known_work = set(item_refs); known_existing = set(endpoint_refs)
    blockers: list[str] = []
    for operation in operations:
        if operation["depends_on"]:
            blockers.append("write_operation_dependencies_unsupported")
        if operation["operation_kind"] == "create_issue":
            kind, ref = _v2_endpoint(operation["endpoint"])
            if kind != "work_item" or ref not in known_work:
                blockers.append("write_operation_unknown_endpoint")
        else:
            for operand in operation["operands"]:
                kind, ref = _v2_endpoint(operand)
                if (kind == "work_item" and ref not in known_work) or (kind == "existing_issue" and ref not in known_existing):
                    blockers.append("write_operation_unknown_endpoint")
    create_refs = [op["endpoint"]["client_ref"] for op in operations if op["operation_kind"] == "create_issue"]
    if len(create_refs) != len(set(create_refs)) or set(create_refs) != known_work:
        blockers.append("write_operation_create_issue_incomplete")
    planned = semantic_payload.get("planned_relationships", [])
    if not isinstance(planned, list):
        raise ValueError("write_operation_relationships_invalid")
    planned_pairs = []
    for rel in planned:
        if not isinstance(rel, Mapping):
            raise ValueError("write_operation_relationships_invalid")
        kind = rel.get("kind")
        if kind not in {"planned_parent", "planned_dependency"}:
            raise ValueError("write_operation_relationships_invalid")
        source = _v2_endpoint(rel.get("from_endpoint")); target = _v2_endpoint(rel.get("to_endpoint"))
        if source == target:
            blockers.append("write_operation_relationship_shape_invalid")
        if source[0] == target[0] == "existing_issue":
            blockers.append("write_operation_existing_to_existing_unsupported")
        planned_pairs.append((kind, source, target))
    operation_pairs = set()
    for op in operations:
        if op["operation_kind"] in {"add_sub_issue", "add_dependency"}:
            kind = "planned_parent" if op["operation_kind"] == "add_sub_issue" else "planned_dependency"
            operation_pairs.add((kind, _v2_endpoint(op["operands"][0]), _v2_endpoint(op["operands"][1])))
    if set(planned_pairs) != operation_pairs:
        blockers.append("write_operation_relationship_incomplete")
    binding_ids = {
        binding.get("endpoint_ref"): binding.get("issue_id")
        for binding in endpoint_bindings
        if isinstance(binding, Mapping)
    }
    for kind, source, target in planned_pairs:
        if source[0] != "existing_issue" or target[0] != "existing_issue":
            continue
        remote_kind = "existing_parent" if kind == "planned_parent" else "existing_dependency"
        source_id = binding_ids.get(source[1])
        target_id = binding_ids.get(target[1])
        if not isinstance(source_id, str) or not isinstance(target_id, str):
            continue
        if any(
            isinstance(record, Mapping)
            and record.get("kind") == remote_kind
            and record.get("from") == source_id
            and record.get("to") == target_id
            for record in relationship_records
        ):
            blockers.append("relationship_already_exists")
    expected = tuple({"operation_kind": "create_issue", "endpoint": {"endpoint_type": "work_item", "client_ref": ref}, "depends_on": []} for ref in item_refs)
    expected += tuple({"operation_kind": "add_sub_issue" if kind == "planned_parent" else "add_dependency", "operands": [dict({"endpoint_type": src[0], ("client_ref" if src[0] == "work_item" else "endpoint_ref"): src[1]}), dict({"endpoint_type": dst[0], ("client_ref" if dst[0] == "work_item" else "endpoint_ref"): dst[1]})], "depends_on": []} for kind, src, dst in planned_pairs)
    if operations != expected:
        blockers.append("write_operation_order_invalid")
    return WriteOperationEvaluation(operations, not blockers, tuple(sorted(set(blockers))))
