"""Durable persistence for authenticated authority-binding records.

This module stores the exact canonical AuthorityBindingRecord v1 bytes and
detached proof envelope.  It performs structural persistence validation only;
cryptographic verification and Runtime authority reconstruction remain later
concerns.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sqlite3
import threading
from typing import Any, Protocol

from delivery_system import sqlite_schema
from delivery_system.authority_binding import (
    AUTHORITY_BINDING_SIGNATURE_ALGORITHM,
    AuthorityBindingRecord,
    SignedAuthorityBinding,
)


_ISSUANCE_ID_RE = re.compile(r"^authority-issuance-[0-9a-f]{64}$")
_OPERATION_ID_RE = re.compile(r"^operation-[0-9a-f]{64}$")


class AuthorityBindingPersistenceError(ValueError):
    """Stable persistence-layer failure without exposing storage details."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _error(code: str) -> None:
    raise AuthorityBindingPersistenceError(code)


def _workspace(value: Any) -> str:
    if type(value) is not str or not value or value != value.strip():
        _error("authority_binding_persistence_workspace_invalid")
    return value


def _issuance_id(value: Any) -> str:
    if type(value) is not str or _ISSUANCE_ID_RE.fullmatch(value) is None:
        _error("authority_binding_persistence_lookup_invalid")
    return value


def _strict_json_object(value: bytes) -> dict[str, Any]:
    if type(value) is not bytes or not value:
        _error("authority_binding_persistence_payload_corrupt")

    def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                _error("authority_binding_persistence_payload_corrupt")
            result[key] = item
        return result

    try:
        decoded = value.decode("utf-8", errors="strict")
        parsed = json.loads(decoded, object_pairs_hook=reject_duplicate_pairs)
    except (UnicodeDecodeError, TypeError, ValueError, json.JSONDecodeError):
        _error("authority_binding_persistence_payload_corrupt")
    if type(parsed) is not dict:
        _error("authority_binding_persistence_payload_corrupt")
    return parsed


def _validated_binding(
    canonical_payload: bytes,
    authority_issuance_id: str,
    issuer_id: str,
    key_id: str,
    signature_algorithm: str,
    detached_proof: str,
    *,
    expected_workspace: str,
) -> "PersistedAuthorityBinding":
    parsed = _strict_json_object(canonical_payload)
    try:
        payload = AuthorityBindingRecord.from_dict(parsed)
        signed = SignedAuthorityBinding(
            payload,
            issuer_id,
            key_id,
            signature_algorithm,
            detached_proof,
        )
    except Exception as exc:
        if isinstance(exc, AuthorityBindingPersistenceError):
            raise
        _error("authority_binding_persistence_payload_corrupt")
    if payload.workspace_identity != expected_workspace:
        _error("authority_binding_persistence_workspace_mismatch")
    if payload.canonical_bytes() != canonical_payload:
        _error("authority_binding_persistence_payload_corrupt")
    if payload.authority_issuance_id != authority_issuance_id:
        _error("authority_binding_persistence_issuance_id_corrupt")
    if signed.signature_algorithm != AUTHORITY_BINDING_SIGNATURE_ALGORITHM:
        _error("authority_binding_persistence_envelope_corrupt")
    return PersistedAuthorityBinding(
        signed=signed,
        canonical_payload=canonical_payload,
        authority_issuance_id=authority_issuance_id,
    )


@dataclass(frozen=True, slots=True)
class PersistedAuthorityBinding:
    """Untrusted persisted binding data awaiting later proof verification."""

    signed: SignedAuthorityBinding
    canonical_payload: bytes
    authority_issuance_id: str

    def __post_init__(self) -> None:
        if type(self.signed) is not SignedAuthorityBinding or type(self.canonical_payload) is not bytes:
            _error("authority_binding_persistence_payload_corrupt")
        if self.signed.payload.canonical_bytes() != self.canonical_payload:
            _error("authority_binding_persistence_payload_corrupt")
        if self.signed.payload.authority_issuance_id != self.authority_issuance_id:
            _error("authority_binding_persistence_issuance_id_corrupt")

    @property
    def payload(self) -> AuthorityBindingRecord:
        return self.signed.payload

    @property
    def issuer_id(self) -> str:
        return self.signed.issuer_id

    @property
    def key_id(self) -> str:
        return self.signed.key_id

    @property
    def signature_algorithm(self) -> str:
        return self.signed.signature_algorithm

    @property
    def detached_proof(self) -> str:
        return self.signed.proof


class AuthorityBindingPersistenceStore(Protocol):
    def save_authority_binding(self, binding: SignedAuthorityBinding) -> PersistedAuthorityBinding: ...

    def load_authority_binding(
        self, workspace_identity: str, authority_issuance_id: str
    ) -> PersistedAuthorityBinding | None: ...

    def resolve_authority_binding_for_operation(
        self, workspace_identity: str, operation_identity: str
    ) -> PersistedAuthorityBinding | None: ...


def _candidate(binding: SignedAuthorityBinding, expected_workspace: str) -> PersistedAuthorityBinding:
    if type(binding) is not SignedAuthorityBinding:
        _error("authority_binding_persistence_binding_invalid")
    payload = binding.payload
    if payload.workspace_identity != expected_workspace:
        _error("authority_binding_persistence_workspace_mismatch")
    canonical_payload = payload.canonical_bytes()
    return _validated_binding(
        canonical_payload,
        payload.authority_issuance_id,
        binding.issuer_id,
        binding.key_id,
        binding.signature_algorithm,
        binding.proof,
        expected_workspace=expected_workspace,
    )


def _assignment_set(binding: PersistedAuthorityBinding) -> frozenset[str]:
    return frozenset(binding.payload.authorized_operation_identities)


class InMemoryAuthorityBindingPersistenceStore:
    """Thread-safe process-local implementation of the V7 store contract."""

    def __init__(self, *, workspace_identity: str) -> None:
        self.workspace_identity = _workspace(workspace_identity)
        self._lock = threading.RLock()
        self._bindings: dict[tuple[str, str], PersistedAuthorityBinding] = {}
        self._assignments: dict[tuple[str, str], str] = {}

    def _load_parent_locked(
        self, issuance_id: str
    ) -> PersistedAuthorityBinding | None:
        key = (self.workspace_identity, issuance_id)
        binding = self._bindings.get(key)
        if binding is None:
            if any(
                assigned_issuance == issuance_id
                for (workspace, _operation), assigned_issuance in self._assignments.items()
                if workspace == self.workspace_identity
            ):
                _error("authority_binding_persistence_projection_corrupt")
            return None
        checked = _validated_binding(
            binding.canonical_payload,
            binding.authority_issuance_id,
            binding.issuer_id,
            binding.key_id,
            binding.signature_algorithm,
            binding.detached_proof,
            expected_workspace=self.workspace_identity,
        )
        assignments = {
            operation
            for (workspace, operation), assigned_issuance in self._assignments.items()
            if workspace == self.workspace_identity and assigned_issuance == issuance_id
        }
        if assignments != _assignment_set(checked):
            _error("authority_binding_persistence_projection_corrupt")
        return checked

    def save_authority_binding(self, binding: SignedAuthorityBinding) -> PersistedAuthorityBinding:
        candidate = _candidate(binding, self.workspace_identity)
        operations = _assignment_set(candidate)
        with self._lock:
            existing = self._load_parent_locked(candidate.authority_issuance_id)
            if existing is not None:
                if existing == candidate:
                    return existing
                _error("authority_binding_persistence_conflict")
            for operation in operations:
                assigned = self._assignments.get((self.workspace_identity, operation))
                if assigned is not None:
                    _error("authority_binding_persistence_operation_conflict")
            self._bindings[(self.workspace_identity, candidate.authority_issuance_id)] = candidate
            for operation in operations:
                self._assignments[(self.workspace_identity, operation)] = candidate.authority_issuance_id
            return candidate

    def load_authority_binding(
        self, workspace_identity: str, authority_issuance_id: str
    ) -> PersistedAuthorityBinding | None:
        workspace = _workspace(workspace_identity)
        issuance = _issuance_id(authority_issuance_id)
        if workspace != self.workspace_identity:
            _error("authority_binding_persistence_workspace_mismatch")
        with self._lock:
            return self._load_parent_locked(issuance)

    def resolve_authority_binding_for_operation(
        self, workspace_identity: str, operation_identity: str
    ) -> PersistedAuthorityBinding | None:
        workspace = _workspace(workspace_identity)
        operation = _operation_identity(operation_identity)
        if workspace != self.workspace_identity:
            _error("authority_binding_persistence_workspace_mismatch")
        with self._lock:
            issuance = self._assignments.get((workspace, operation))
            if issuance is None:
                return None
            binding = self._load_parent_locked(issuance)
            if binding is None:
                _error("authority_binding_persistence_projection_corrupt")
            if operation not in _assignment_set(binding):
                _error("authority_binding_persistence_projection_corrupt")
            return binding


def _operation_identity(value: Any) -> str:
    if type(value) is not str or _OPERATION_ID_RE.fullmatch(value) is None:
        _error("authority_binding_persistence_lookup_invalid")
    return value


class SQLiteAuthorityBindingPersistenceStore:
    """SQLite-backed V7 authority-binding persistence."""

    def __init__(self, database_path: str | Path, *, workspace_identity: str) -> None:
        if not isinstance(database_path, (str, Path)):
            _error("authority_binding_persistence_database_invalid")
        self.path = Path(database_path)
        self.workspace_identity = _workspace(workspace_identity)
        try:
            with closing(sqlite_schema._open_connection(self.path)) as connection:
                sqlite_schema.ensure_schema_v7(
                    connection,
                    expected_workspace_identity=self.workspace_identity,
                )
        except AuthorityBindingPersistenceError:
            raise
        except sqlite_schema.SchemaOwnerError as exc:
            raise AuthorityBindingPersistenceError(exc.code) from exc
        except sqlite3.Error as exc:
            raise AuthorityBindingPersistenceError(
                "authority_binding_persistence_sqlite_operational"
            ) from exc

    def _connection(self) -> sqlite3.Connection:
        try:
            return sqlite_schema._open_connection(self.path)
        except sqlite_schema.SchemaOwnerError as exc:
            raise AuthorityBindingPersistenceError(exc.code) from exc

    @staticmethod
    def _rollback(connection: sqlite3.Connection) -> None:
        try:
            connection.rollback()
        except sqlite3.Error:
            pass

    @staticmethod
    def _sqlite_failure(exc: sqlite3.Error) -> AuthorityBindingPersistenceError:
        message = str(exc).lower()
        code = (
            "authority_binding_persistence_sqlite_busy"
            if isinstance(exc, sqlite3.OperationalError) and ("busy" in message or "locked" in message)
            else "authority_binding_persistence_sqlite_operational"
        )
        return AuthorityBindingPersistenceError(code)

    def _load_parent_locked(
        self, connection: sqlite3.Connection, issuance_id: str
    ) -> PersistedAuthorityBinding | None:
        row = connection.execute(
            "SELECT canonical_payload, issuer_id, key_id, signature_algorithm, detached_proof "
            "FROM authority_bindings WHERE workspace_identity=? AND authority_issuance_id=?",
            (self.workspace_identity, issuance_id),
        ).fetchone()
        assignment_rows = connection.execute(
            "SELECT operation_identity, authority_issuance_id FROM authority_binding_operations "
            "WHERE workspace_identity=? AND authority_issuance_id=? ORDER BY operation_identity",
            (self.workspace_identity, issuance_id),
        ).fetchall()
        if row is None:
            if assignment_rows:
                _error("authority_binding_persistence_projection_corrupt")
            return None
        if len(row) != 5 or type(row[0]) is not bytes:
            _error("authority_binding_persistence_payload_corrupt")
        binding = _validated_binding(
            row[0],
            issuance_id,
            row[1],
            row[2],
            row[3],
            row[4],
            expected_workspace=self.workspace_identity,
        )
        assignments = set()
        for assignment in assignment_rows:
            if len(assignment) != 2 or type(assignment[0]) is not str or assignment[1] != issuance_id:
                _error("authority_binding_persistence_projection_corrupt")
            assignments.add(assignment[0])
        if assignments != _assignment_set(binding):
            _error("authority_binding_persistence_projection_corrupt")
        return binding

    def _load_in_transaction(
        self, connection: sqlite3.Connection, issuance_id: str
    ) -> PersistedAuthorityBinding | None:
        try:
            connection.execute("BEGIN")
            result = self._load_parent_locked(connection, issuance_id)
            connection.commit()
            return result
        except AuthorityBindingPersistenceError:
            self._rollback(connection)
            raise
        except sqlite3.Error as exc:
            self._rollback(connection)
            raise self._sqlite_failure(exc) from exc

    def save_authority_binding(self, binding: SignedAuthorityBinding) -> PersistedAuthorityBinding:
        candidate = _candidate(binding, self.workspace_identity)
        operations = tuple(sorted(_assignment_set(candidate)))
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._load_parent_locked(connection, candidate.authority_issuance_id)
            if existing is not None:
                if existing == candidate:
                    connection.commit()
                    return existing
                _error("authority_binding_persistence_conflict")
            connection.execute(
                "INSERT INTO authority_bindings "
                "(workspace_identity, authority_issuance_id, canonical_payload, issuer_id, key_id, signature_algorithm, detached_proof) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    self.workspace_identity,
                    candidate.authority_issuance_id,
                    candidate.canonical_payload,
                    candidate.issuer_id,
                    candidate.key_id,
                    candidate.signature_algorithm,
                    candidate.detached_proof,
                ),
            )
            for operation in operations:
                connection.execute(
                    "INSERT INTO authority_binding_operations "
                    "(workspace_identity, operation_identity, authority_issuance_id) VALUES (?, ?, ?)",
                    (self.workspace_identity, operation, candidate.authority_issuance_id),
                )
            connection.commit()
            return candidate
        except AuthorityBindingPersistenceError:
            self._rollback(connection)
            raise
        except sqlite3.IntegrityError as exc:
            self._rollback(connection)
            raise AuthorityBindingPersistenceError(
                "authority_binding_persistence_operation_conflict"
            ) from exc
        except sqlite3.Error as exc:
            self._rollback(connection)
            raise self._sqlite_failure(exc) from exc
        finally:
            connection.close()

    def load_authority_binding(
        self, workspace_identity: str, authority_issuance_id: str
    ) -> PersistedAuthorityBinding | None:
        workspace = _workspace(workspace_identity)
        issuance = _issuance_id(authority_issuance_id)
        if workspace != self.workspace_identity:
            _error("authority_binding_persistence_workspace_mismatch")
        connection = self._connection()
        try:
            return self._load_in_transaction(connection, issuance)
        finally:
            connection.close()

    def resolve_authority_binding_for_operation(
        self, workspace_identity: str, operation_identity: str
    ) -> PersistedAuthorityBinding | None:
        workspace = _workspace(workspace_identity)
        operation = _operation_identity(operation_identity)
        if workspace != self.workspace_identity:
            _error("authority_binding_persistence_workspace_mismatch")
        connection = self._connection()
        try:
            try:
                connection.execute("BEGIN")
                row = connection.execute(
                    "SELECT authority_issuance_id FROM authority_binding_operations "
                    "WHERE workspace_identity=? AND operation_identity=?",
                    (workspace, operation),
                ).fetchone()
                if row is None:
                    connection.commit()
                    return None
                if len(row) != 1 or type(row[0]) is not str:
                    _error("authority_binding_persistence_projection_corrupt")
                result = self._load_parent_locked(connection, row[0])
                if result is None or operation not in _assignment_set(result):
                    _error("authority_binding_persistence_projection_corrupt")
                connection.commit()
                return result
            except AuthorityBindingPersistenceError:
                self._rollback(connection)
                raise
            except sqlite3.Error as exc:
                self._rollback(connection)
                raise self._sqlite_failure(exc) from exc
        finally:
            connection.close()


__all__ = [
    "AuthorityBindingPersistenceError",
    "AuthorityBindingPersistenceStore",
    "PersistedAuthorityBinding",
    "InMemoryAuthorityBindingPersistenceStore",
    "SQLiteAuthorityBindingPersistenceStore",
]
