"""Runtime-owned, offline-testable orchestration for approved V1 writes."""

from __future__ import annotations

from dataclasses import dataclass
import json
import uuid
from typing import Any, Mapping

from .canonical import digest
from .drivers.write_contract import CreateIssueCommand, RemoteIssueReference, RelationshipCommand, WriteObservationKind
from .execution_store import SQLiteExecutionStore
from .application_identity import operation_identity
from .execution_state import APPLIER_ORCHESTRATION_POLICY


@dataclass(frozen=True, slots=True)
class ApplyResult:
    application_id: str
    state: str
    next_operation_index: int
    application_receipt_id: str | None = None
    recovery_code: str | None = None


def _json_value(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _source(item: Mapping[str, Any], field: str) -> Any:
    value = item.get(field)
    if not isinstance(value, Mapping) or set(value) != {"value", "declared_source", "provenance_status"}:
        raise ValueError("sealed_item_field_invalid")
    if value.get("provenance_status") != "declared_unverified" or not isinstance(value.get("declared_source"), str) or not value["declared_source"]:
        raise ValueError("sealed_item_provenance_invalid")
    return value["value"]


def render_create_issue(item: Mapping[str, Any]) -> tuple[str, str]:
    """Render only the approved item projection into the bounded B2 command."""
    client_ref = item.get("client_ref")
    if type(client_ref) is not str or not client_ref:
        raise ValueError("sealed_item_field_invalid")
    fields = ("role", "title", "context_problem", "outcome", "scope", "non_goals",
              "acceptance_criteria", "verification", "required_capabilities", "write_metadata")
    values = {field: _source(item, field) for field in fields}
    title = values["title"]
    if type(title) is not str or not title or any(ord(char) < 0x20 or ord(char) == 0x7f for char in title):
        raise ValueError("sealed_item_field_invalid")
    if any(field in {"non_goals", "acceptance_criteria", "required_capabilities"} and not isinstance(values[field], (list, tuple)) for field in fields):
        raise ValueError("sealed_item_field_invalid")
    sections = [("Client reference", client_ref), ("Role", values["role"]),
                ("Context / Problem", values["context_problem"]), ("Outcome", values["outcome"]),
                ("Scope", values["scope"]), ("Non-goals", values["non_goals"]),
                ("Acceptance criteria", values["acceptance_criteria"]), ("Verification", values["verification"]),
                ("Required capabilities", values["required_capabilities"]),
                ("Write metadata (informational only)", values["write_metadata"])]
    body_parts = []
    for heading, value in sections:
        encoded = _json_value(value)
        body_parts.append(f"## {heading}\n\n    {encoded}")
    return title, "\n\n".join(body_parts)


class Applier:
    """Private-construction Applier; the public surface is only ``apply``."""

    __slots__ = ("_apply_fn",)

    def __init__(self) -> None:
        raise ValueError("applier_internal_only")

    @classmethod
    def _from_runtime(cls, service: Any, store: SQLiteExecutionStore, capability: Any) -> "Applier":
        self = object.__new__(cls)
        object.__setattr__(self, "_apply_fn", lambda authority_id: _apply(service, store, capability, authority_id))
        return self

    def apply(self, application_authority_id: str) -> ApplyResult:
        return self._apply_fn(application_authority_id)


def _apply(service: Any, store: SQLiteExecutionStore, capability: Any, authority_id: str) -> ApplyResult:
    context = service.create_execution_context(authority_id)
    application_id = context.identity.application_id
    now = service._utc(service.clock())
    initial = context.new_execution_state(state="Pending", next_operation_index=0, owner_id=None,
                                         current_attempt_id=None, recovery_code=None,
                                         operation_receipt_refs=(), started_at=now, updated_at=now,
                                         completed_at=None, orchestration_policy=APPLIER_ORCHESTRATION_POLICY)
    state = store.create_execution_if_absent(capability, initial)
    expected = context.expected_operations
    if state.state == "Applied":
        state = store.get_execution(application_id, expected_operations=expected)
        return ApplyResult(application_id, state.state, state.next_operation_index,
                           store.get_application_receipt(application_id).application_receipt_id)
    if state.state == "Applying":
        return ApplyResult(application_id, state.state, state.next_operation_index, recovery_code="application_recovery_required")
    if state.state in {"Failed", "Blocked", "OutcomeUnknown"}:
        return ApplyResult(application_id, state.state, state.next_operation_index, recovery_code=state.recovery_code)

    while state.next_operation_index < len(expected):
        owner = "execution-owner-" + uuid.uuid4().hex
        try:
            state, attempt = store.claim_next_operation(capability, application_id, state.state_digest, context, owner, service._utc(service.clock()))
        except ValueError as exc:
            if str(exc) in {"application_claim_unavailable", "application_state_stale"}:
                current = store.get_execution(application_id, expected_operations=expected)
                changed = (current.state_digest != state.state_digest or
                           current.state != state.state or
                           current.next_operation_index != state.next_operation_index or
                           current.owner_id != state.owner_id or
                           current.current_attempt_id != state.current_attempt_id)
                if not changed:
                    raise
                receipt_id = None
                if current.state == "Applied":
                    receipt_id = store.get_application_receipt(application_id).application_receipt_id
                return ApplyResult(application_id, current.state, current.next_operation_index,
                                   application_receipt_id=receipt_id,
                                   recovery_code=(None if current.state == "Applied" else
                                                  "application_recovery_required" if current.state in {"Applying", "PartiallyApplied"}
                                                  else current.recovery_code))
            raise
        try:
            store.validate_claim(capability, application_id, state.state_digest, attempt.operation_identity,
                                 attempt.attempt_digest, owner, context)
            command = _materialize(context, attempt, store)
        except ValueError as exc:
            code = str(exc)
            target = "Blocked" if code in {"write_reference_unavailable", "write_executor_invalid", "runtime_authority_required"} else "Failed"
            state = store.settle_operation(capability, application_id, state.state_digest, attempt.operation_identity,
                                           attempt.attempt_digest, owner, context, target, code, service._utc(service.clock()))
            return ApplyResult(application_id, state.state, state.next_operation_index, recovery_code=code)
        try:
            context._require_current()
        except ValueError as exc:
            if str(exc) != "runtime_authority_invalid":
                raise
            return ApplyResult(application_id, state.state, state.next_operation_index,
                               recovery_code="application_recovery_required")
        try:
            observation = capability.dispatch(context, attempt.operation["operation_kind"], command)
        except ValueError as exc:
            code = str(exc)
            if code in {
                "credential_capability_unregistered", "credential_principal_mismatch",
                "credential_instance_mismatch", "credential_repository_mismatch",
                "credential_scope_mismatch", "credential_capability_mismatch",
                "credential_currentness_mismatch", "credential_expired",
            }:
                state = store.settle_operation(capability, application_id, state.state_digest,
                                               attempt.operation_identity, attempt.attempt_digest, owner,
                                               context, "Blocked", code, service._utc(service.clock()))
                return ApplyResult(application_id, state.state, state.next_operation_index,
                                   recovery_code=code)
            raise
        try:
            context._require_current()
        except ValueError as exc:
            if str(exc) != "runtime_authority_invalid":
                raise
            return ApplyResult(application_id, state.state, state.next_operation_index,
                               recovery_code="application_recovery_required")
        if observation.kind is WriteObservationKind.DEFINITIVE_SUCCESS:
            try:
                remote = _trusted_success_result(context, attempt, observation)
                receipt = context.new_receipt(attempt.operation_index, remote, attempt.started_at,
                                              service._utc(service.clock()))
                state = store.complete_operation_success(capability, application_id, state.state_digest,
                                                         attempt.operation_identity, attempt.attempt_digest, owner,
                                                         context, receipt, service._utc(service.clock()))
            except ValueError as exc:
                if str(exc) != "runtime_authority_invalid":
                    raise
                return ApplyResult(application_id, state.state, state.next_operation_index,
                                   recovery_code="application_recovery_required")
            continue
        code = observation.code or ("github_write_rejected" if observation.kind is WriteObservationKind.DEFINITIVE_REJECTED else "github_write_transport_ambiguous")
        if observation.kind is WriteObservationKind.AMBIGUOUS:
            target = "OutcomeUnknown"
        elif code in {"github_write_authority_rejected", "github_write_target_unavailable", "github_write_conflict", "github_write_rate_limited", "github_write_redirect_rejected"}:
            target = "Blocked"
        else:
            target = "Failed"
        try:
            state = store.settle_operation(capability, application_id, state.state_digest, attempt.operation_identity,
                                           attempt.attempt_digest, owner, context, target, code, service._utc(service.clock()))
        except ValueError as exc:
            if str(exc) != "runtime_authority_invalid":
                raise
            return ApplyResult(application_id, state.state, state.next_operation_index,
                               recovery_code="application_recovery_required")
        return ApplyResult(application_id, state.state, state.next_operation_index, recovery_code=code)
    state = store.finalize_application(capability, application_id, state.state_digest, context, service._utc(service.clock()))
    return ApplyResult(application_id, state.state, state.next_operation_index,
                       store.get_application_receipt(application_id).application_receipt_id)


def _materialize(context: Any, attempt: Any, store: SQLiteExecutionStore) -> Any:
    operation = attempt.operation
    items = {item["client_ref"]: item for item in context.canonical_items}
    kind = operation["operation_kind"]
    refs = operation["client_refs"]
    if kind == "create_issue":
        title, body = render_create_issue(items[refs[0]])
        return CreateIssueCommand(context.repository_identity, refs[0], title, body, attempt.request_identity)
    if kind in {"add_sub_issue", "add_dependency"}:
        if any(ref not in items for ref in refs):
            raise ValueError("write_reference_unavailable")
        references = []
        for ref in refs:
            references.append(_reference_from_receipt(context, store, ref))
        return RelationshipCommand(context.repository_identity, references[0], references[1])
    raise ValueError("write_operation_kind_invalid")


def _trusted_success_result(context: Any, attempt: Any, observation: Any) -> dict[str, Any]:
    """Re-validate the bounded B2 evidence before it becomes a durable receipt."""
    payload = observation.result_payload
    if not isinstance(payload, Mapping):
        raise ValueError("write_observation_invalid")
    kind = attempt.operation["operation_kind"]
    if kind == "create_issue":
        required = {"repository_identity", "issue_number", "numeric_issue_id", "node_id",
                    "executor_identity", "contract_version", "response_status"}
        if set(payload) != required or payload.get("repository_identity") != context.repository_identity:
            raise ValueError("write_observation_invalid")
        numeric_id = payload.get("numeric_issue_id")
        if (type(payload.get("issue_number")) is not int or payload["issue_number"] <= 0 or
                type(numeric_id) is not str or not (1 <= len(numeric_id) <= 20) or
                numeric_id[0] == "0" or not all("0" <= char <= "9" for char in numeric_id) or
                type(payload.get("node_id")) is not str or not payload["node_id"] or
                payload.get("executor_identity") != "delivery-system:github-rest-write-v1" or
                type(payload.get("contract_version")) is not str or payload.get("response_status") != 201):
            raise ValueError("write_observation_invalid")
    elif kind in {"add_sub_issue", "add_dependency"}:
        if (type(payload.get("repository_identity")) is not str or
                payload.get("repository_identity") != context.repository_identity or
                payload.get("executor_identity") != "delivery-system:github-rest-write-v1" or
                type(payload.get("contract_version")) is not str or payload.get("response_status") != 201):
            raise ValueError("write_observation_invalid")
    else:
        raise ValueError("write_operation_kind_invalid")
    if type(observation.result_identity) is not str or not observation.result_identity:
        raise ValueError("write_observation_invalid")
    return {"result_kind": "github." + kind + ".v1",
            "result_identity": observation.result_identity,
            "result_digest": digest(dict(payload)),
            "result_payload": dict(payload)}


def _reference_from_receipt(context: Any, store: SQLiteExecutionStore, client_ref: str) -> RemoteIssueReference:
    for index, operation in enumerate(context.expected_operations):
        if operation["operation_kind"] != "create_issue" or operation["client_refs"] != [client_ref]:
            continue
        receipt = store.get_operation_receipt(context.identity.application_id,
                                               operation_identity(context.identity.application_id, index, operation))
        payload = dict(receipt.remote_result["result_payload"])
        if receipt.remote_result["result_kind"] != "github.create_issue.v1" or payload.get("repository_identity") != context.repository_identity:
            break
        return RemoteIssueReference(payload["repository_identity"], payload["issue_number"], payload["numeric_issue_id"], payload["node_id"])
    raise ValueError("write_reference_unavailable")
