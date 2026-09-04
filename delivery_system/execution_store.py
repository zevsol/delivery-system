"""SQLite persistence seam for PC2-A execution coordination and receipts."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from . import sqlite_schema
from .application_identity import operation_identity
from .execution_state import (ApplicationExecutionState, OperationAttemptState,
                               validate_application_transition, validate_attempt_transition)
from .receipts import ApplicationReceipt, OperationReceipt


class SQLiteExecutionStore:
    """Workspace-owned V6 execution records; receipts are immutable by identity."""

    def __init__(self, path: str | Path, workspace_identity: str, *, runtime_service: Any = None) -> None:
        self.path = Path(path)
        self.workspace_identity = workspace_identity
        self.runtime_service = runtime_service
        with closing(sqlite_schema._open_connection(self.path)) as connection:
            sqlite_schema.ensure_schema_v6(connection, expected_workspace_identity=workspace_identity)

    def _connection(self) -> sqlite3.Connection:
        return sqlite_schema._open_connection(self.path)

    def save_execution(self, state: ApplicationExecutionState) -> ApplicationExecutionState:
        candidate = state.with_digest()
        if state.identity.values()["workspace_identity"] != self.workspace_identity:
            raise ValueError("application_binding_conflict")
        payload = json.dumps(candidate.payload() | {"state_digest": candidate.state_digest}, ensure_ascii=False, sort_keys=True)
        with closing(self._connection()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute("SELECT payload FROM application_execution WHERE workspace_identity=? AND application_id=?",
                                         (self.workspace_identity, state.application_id)).fetchone()
            if existing is not None:
                if existing[0] != payload:
                    old = ApplicationExecutionState(**json.loads(existing[0]))
                    if (old.identity.to_dict() != state.identity.to_dict() or old.application_id != state.application_id or
                            old.continuity_anchor != state.continuity_anchor):
                        raise ValueError("application_binding_conflict")
                    if state._live_context is None or self.runtime_service is None:
                        raise ValueError("runtime_authority_required")
                    self.runtime_service.validate_live_artifact(state, state._live_context, "execution")
            else:
                if state._live_context is None or self.runtime_service is None:
                    raise ValueError("runtime_authority_required")
                self.runtime_service.validate_live_artifact(state, state._live_context, "execution")
            if existing is not None and existing[0] == payload:
                connection.commit()
                return candidate
            if existing is not None:
                old = ApplicationExecutionState(**json.loads(existing[0]))
                if (old.identity.to_dict() != state.identity.to_dict() or old.application_id != state.application_id or
                        old.continuity_anchor != state.continuity_anchor):
                    raise ValueError("application_binding_conflict")
            connection.execute("INSERT INTO application_execution(workspace_identity, application_id, payload) VALUES (?, ?, ?) ON CONFLICT(workspace_identity, application_id) DO UPDATE SET payload=excluded.payload",
                               (self.workspace_identity, candidate.application_id, payload))
            connection.commit()
        return candidate

    def get_execution(self, application_id: str, *, expected_operations: tuple[dict[str, Any], ...] | None = None) -> ApplicationExecutionState:
        with closing(self._connection()) as connection:
            row = connection.execute("SELECT payload FROM application_execution WHERE workspace_identity=? AND application_id=?",
                                     (self.workspace_identity, application_id)).fetchone()
        if row is None:
            raise ValueError("application_not_found")
        data = json.loads(row[0])
        state = ApplicationExecutionState(**data)
        if state.identity.values()["workspace_identity"] != self.workspace_identity:
            raise ValueError("application_binding_conflict")
        if not state.verify_integrity():
            raise ValueError("state_integrity_invalid")
        if state.state == "Applied":
            if expected_operations is None:
                raise ValueError("application_replay_validation_required")
            receipt = self.get_application_receipt(application_id)
            if not receipt.verify_integrity() or receipt.application_id != state.application_id or receipt.identity.to_dict() != state.identity.to_dict():
                raise ValueError("application_receipt_integrity_invalid")
            if tuple(ref["operation_receipt_id"] for ref in receipt.operation_receipt_refs) != state.operation_receipt_refs:
                raise ValueError("application_receipt_integrity_invalid")
            operation_indexes = []
            operation_receipts = []
            for ref in receipt.operation_receipt_refs:
                operation = self._get_operation_receipt_by_id(application_id, ref["operation_receipt_id"])
                if operation.receipt_digest != ref["operation_receipt_digest"] or not operation.verify_integrity():
                    raise ValueError("application_receipt_integrity_invalid")
                operation_indexes.append(operation.operation_index)
                operation_receipts.append(operation)
            if operation_indexes != list(range(len(operation_indexes))):
                raise ValueError("application_receipt_integrity_invalid")
            if not receipt.validate_against(expected_operations, operation_receipts):
                raise ValueError("application_replay_binding_invalid")
        return state

    def save_attempt(self, attempt: OperationAttemptState) -> OperationAttemptState:
        candidate = attempt.with_digest()
        if attempt.identity.values()["workspace_identity"] != self.workspace_identity:
            raise ValueError("operation_attempt_binding_conflict")
        payload = json.dumps(candidate.payload() | {"attempt_digest": candidate.attempt_digest}, ensure_ascii=False, sort_keys=True)
        with closing(self._connection()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute("SELECT payload FROM operation_attempts WHERE workspace_identity=? AND application_id=? AND operation_identity=?",
                                         (self.workspace_identity, attempt.application_id, attempt.operation_identity)).fetchone()
            if existing is not None and existing[0] == payload:
                connection.commit()
                return candidate
            if existing is not None:
                old = OperationAttemptState(**json.loads(existing[0]))
                immutable = (old.identity.to_dict(), old.operation_index, dict(old.operation), old.request_identity, old.authority_binding.to_dict())
                candidate_binding = (attempt.identity.to_dict(), attempt.operation_index, dict(attempt.operation), attempt.request_identity, attempt.authority_binding.to_dict())
                if immutable != candidate_binding:
                    raise ValueError("operation_attempt_binding_conflict")
                if attempt._live_context is None or self.runtime_service is None:
                    raise ValueError("runtime_authority_required")
                self.runtime_service.validate_live_artifact(attempt, attempt._live_context, "attempt")
            else:
                if attempt._live_context is None or self.runtime_service is None:
                    raise ValueError("runtime_authority_required")
                self.runtime_service.validate_live_artifact(attempt, attempt._live_context, "attempt")
            connection.execute("INSERT INTO operation_attempts(workspace_identity, application_id, operation_identity, payload) VALUES (?, ?, ?, ?) ON CONFLICT(workspace_identity, application_id, operation_identity) DO UPDATE SET payload=excluded.payload",
                               (self.workspace_identity, candidate.application_id, candidate.operation_identity, payload))
            connection.commit()
        return candidate

    def create_attempt_if_absent(self, attempt: OperationAttemptState) -> OperationAttemptState:
        """Atomically claim the first durable attempt for one operation."""
        candidate = attempt.with_digest()
        if attempt.identity.values()["workspace_identity"] != self.workspace_identity:
            raise ValueError("operation_attempt_binding_conflict")
        if attempt.state != "Applying" or attempt.failure_code is not None:
            raise ValueError("operation_attempt_claim_state_invalid")
        payload = json.dumps(candidate.payload() | {"attempt_digest": candidate.attempt_digest}, ensure_ascii=False, sort_keys=True)
        with closing(self._connection()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute("SELECT 1 FROM operation_attempts WHERE workspace_identity=? AND application_id=? AND operation_identity=?",
                                         (self.workspace_identity, candidate.application_id, candidate.operation_identity)).fetchone()
            if existing is not None:
                connection.rollback()
                raise ValueError("operation_attempt_already_exists")
            if attempt._live_context is None or self.runtime_service is None:
                raise ValueError("runtime_authority_required")
            self.runtime_service.validate_live_artifact(attempt, attempt._live_context, "attempt")
            connection.execute("INSERT INTO operation_attempts(workspace_identity, application_id, operation_identity, payload) VALUES (?, ?, ?, ?)",
                               (self.workspace_identity, candidate.application_id, candidate.operation_identity, payload))
            connection.commit()
        return candidate

    def transition_attempt(self, expected_attempt_digest: str, candidate: OperationAttemptState) -> OperationAttemptState:
        live_candidate = candidate
        stored_candidate = candidate.with_digest()
        if live_candidate.identity.values()["workspace_identity"] != self.workspace_identity:
            raise ValueError("operation_attempt_binding_conflict")
        with closing(self._connection()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT payload FROM operation_attempts WHERE workspace_identity=? AND application_id=? AND operation_identity=?",
                                     (self.workspace_identity, live_candidate.application_id, live_candidate.operation_identity)).fetchone()
            if row is None:
                connection.rollback(); raise ValueError("operation_attempt_not_found")
            previous = OperationAttemptState(**json.loads(row[0]))
            if not previous.verify_integrity() or previous.attempt_digest != expected_attempt_digest:
                connection.rollback(); raise ValueError("attempt_state_stale")
            validate_attempt_transition(previous, live_candidate)
            if live_candidate._live_context is None or self.runtime_service is None:
                connection.rollback(); raise ValueError("runtime_authority_required")
            self.runtime_service.validate_live_artifact(live_candidate, live_candidate._live_context, "attempt")
            if (previous.identity.to_dict(), previous.operation_index, dict(previous.operation), previous.request_identity,
                    previous.authority_binding.to_dict(), previous.started_at) != (live_candidate.identity.to_dict(), live_candidate.operation_index,
                    dict(live_candidate.operation), live_candidate.request_identity, live_candidate.authority_binding.to_dict(), live_candidate.started_at):
                connection.rollback(); raise ValueError("operation_attempt_binding_conflict")
            payload = json.dumps(stored_candidate.payload() | {"attempt_digest": stored_candidate.attempt_digest}, ensure_ascii=False, sort_keys=True)
            connection.execute("UPDATE operation_attempts SET payload=? WHERE workspace_identity=? AND application_id=? AND operation_identity=?",
                               (payload, self.workspace_identity, live_candidate.application_id, live_candidate.operation_identity))
            connection.commit()
        return stored_candidate

    def transition_execution(self, expected_state_digest: str, candidate: ApplicationExecutionState) -> ApplicationExecutionState:
        live_candidate = candidate
        stored_candidate = candidate.with_digest()
        if live_candidate.identity.values()["workspace_identity"] != self.workspace_identity:
            raise ValueError("application_binding_conflict")
        with closing(self._connection()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT payload FROM application_execution WHERE workspace_identity=? AND application_id=?",
                                     (self.workspace_identity, live_candidate.application_id)).fetchone()
            if row is None:
                connection.rollback(); raise ValueError("application_not_found")
            previous = ApplicationExecutionState(**json.loads(row[0]))
            if not previous.verify_integrity() or previous.state_digest != expected_state_digest:
                connection.rollback(); raise ValueError("application_state_stale")
            if live_candidate.state == "Applied":
                connection.rollback(); raise ValueError("application_finalization_required")
            validate_application_transition(previous, live_candidate)
            if live_candidate._live_context is None or self.runtime_service is None:
                connection.rollback(); raise ValueError("runtime_authority_required")
            self.runtime_service.validate_live_artifact(live_candidate, live_candidate._live_context, "execution")
            progress_delta = live_candidate.next_operation_index - previous.next_operation_index
            if progress_delta == 1:
                appended_id = live_candidate.operation_receipt_refs[-1]
                receipt_rows = connection.execute("SELECT payload FROM operation_receipts WHERE workspace_identity=? AND application_id=?",
                                                  (self.workspace_identity, live_candidate.application_id)).fetchall()
                appended = None
                for receipt_row in receipt_rows:
                    loaded = OperationReceipt(**json.loads(receipt_row[0]))
                    if loaded.operation_receipt_id == appended_id:
                        appended = loaded
                        break
                if appended is None or not appended.verify_integrity() or appended.identity.to_dict() != live_candidate.identity.to_dict() or appended.operation_index != previous.next_operation_index:
                    connection.rollback(); raise ValueError("application_progress_invalid")
                if live_candidate._live_context is not None:
                    operations = live_candidate._live_context.expected_operations
                    if previous.next_operation_index >= len(operations) or appended.operation_identity != operation_identity(live_candidate.application_id, previous.next_operation_index, operations[previous.next_operation_index]):
                        connection.rollback(); raise ValueError("application_progress_invalid")
            else:
                appended = None
            payload = json.dumps(stored_candidate.payload() | {"state_digest": stored_candidate.state_digest}, ensure_ascii=False, sort_keys=True)
            connection.execute("UPDATE application_execution SET payload=? WHERE workspace_identity=? AND application_id=?",
                               (payload, self.workspace_identity, live_candidate.application_id))
            connection.commit()
        return stored_candidate

    def get_attempt(self, application_id: str, operation_identity: str) -> OperationAttemptState:
        with closing(self._connection()) as connection:
            row = connection.execute("SELECT payload FROM operation_attempts WHERE workspace_identity=? AND application_id=? AND operation_identity=?",
                                     (self.workspace_identity, application_id, operation_identity)).fetchone()
        if row is None:
            raise ValueError("operation_attempt_not_found")
        attempt = OperationAttemptState(**json.loads(row[0]))
        if attempt.identity.values()["workspace_identity"] != self.workspace_identity:
            raise ValueError("operation_attempt_binding_conflict")
        if not attempt.verify_integrity():
            raise ValueError("attempt_integrity_invalid")
        return attempt

    def record_operation_receipt(self, receipt: OperationReceipt) -> OperationReceipt:
        if receipt.identity.values()["workspace_identity"] != self.workspace_identity:
            raise ValueError("workspace_mismatch")
        candidate = receipt.with_digest()
        payload = json.dumps(candidate.payload() | {"receipt_digest": candidate.receipt_digest}, ensure_ascii=False, sort_keys=True)
        with closing(self._connection()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute("SELECT payload FROM operation_receipts WHERE workspace_identity=? AND application_id=? AND operation_identity=?",
                                          (self.workspace_identity, receipt.application_id, receipt.operation_identity)).fetchone()
            if existing is not None and existing[0] != payload:
                raise ValueError("receipt_binding_conflict")
            if existing is None:
                if receipt._live_context is None or self.runtime_service is None:
                    raise ValueError("runtime_authority_required")
                self.runtime_service.validate_live_artifact(receipt, receipt._live_context, "operation_receipt")
            connection.execute("INSERT OR IGNORE INTO operation_receipts(workspace_identity, application_id, operation_identity, payload) VALUES (?, ?, ?, ?)",
                               (self.workspace_identity, candidate.application_id, candidate.operation_identity, payload))
            connection.commit()
        return candidate

    def get_operation_receipt(self, application_id: str, operation_identity: str) -> OperationReceipt:
        with closing(self._connection()) as connection:
            row = connection.execute("SELECT payload FROM operation_receipts WHERE workspace_identity=? AND application_id=? AND operation_identity=?",
                                     (self.workspace_identity, application_id, operation_identity)).fetchone()
        if row is None:
            raise ValueError("operation_receipt_not_found")
        receipt = OperationReceipt(**json.loads(row[0]))
        if receipt.identity.values()["workspace_identity"] != self.workspace_identity:
            raise ValueError("workspace_mismatch")
        if not receipt.verify_integrity():
            raise ValueError("receipt_integrity_invalid")
        return receipt

    def _get_operation_receipt_by_id(self, application_id: str, receipt_id: str) -> OperationReceipt:
        with closing(self._connection()) as connection:
            row = connection.execute("SELECT payload FROM operation_receipts WHERE workspace_identity=? AND application_id=?", (self.workspace_identity, application_id)).fetchall()
        for candidate in row:
            receipt = OperationReceipt(**json.loads(candidate[0]))
            if receipt.operation_receipt_id == receipt_id:
                if not receipt.verify_integrity():
                    raise ValueError("receipt_integrity_invalid")
                return receipt
        raise ValueError("operation_receipt_not_found")

    def record_application_receipt(self, receipt: ApplicationReceipt) -> ApplicationReceipt:
        if receipt.identity.values()["workspace_identity"] != self.workspace_identity:
            raise ValueError("workspace_mismatch")
        candidate = receipt.with_digest()
        payload = json.dumps(candidate.payload() | {"receipt_digest": candidate.receipt_digest}, ensure_ascii=False, sort_keys=True)
        with closing(self._connection()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute("SELECT payload FROM application_receipts WHERE workspace_identity=? AND application_id=?",
                                          (self.workspace_identity, receipt.application_id)).fetchone()
            if existing is not None and existing[0] != payload:
                raise ValueError("receipt_binding_conflict")
            if existing is None:
                if receipt._live_context is None or self.runtime_service is None:
                    raise ValueError("runtime_authority_required")
                self.runtime_service.validate_live_artifact(receipt, receipt._live_context, "application_receipt")
            connection.execute("INSERT OR IGNORE INTO application_receipts(workspace_identity, application_id, payload) VALUES (?, ?, ?)",
                               (self.workspace_identity, candidate.application_id, payload))
            connection.commit()
        return candidate

    def get_application_receipt(self, application_id: str) -> ApplicationReceipt:
        with closing(self._connection()) as connection:
            row = connection.execute("SELECT payload FROM application_receipts WHERE workspace_identity=? AND application_id=?",
                                     (self.workspace_identity, application_id)).fetchone()
        if row is None:
            raise ValueError("application_receipt_not_found")
        receipt = ApplicationReceipt(**json.loads(row[0]))
        if receipt.identity.values()["workspace_identity"] != self.workspace_identity:
            raise ValueError("workspace_mismatch")
        if not receipt.verify_integrity():
            raise ValueError("receipt_integrity_invalid")
        return receipt
