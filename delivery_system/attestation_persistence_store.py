"""Offline, process-local persistence adapter for attestation history.

This module owns no SQLite schema, durable restart behavior, Runtime wiring,
current trust, or capability authorization.  It stores only canonical
historical projections in an instance-local InMemory adapter.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any, Protocol

from delivery_system.attestation_persistence import (
    AttestationBindingReference,
    AttestationRevalidationEvent,
    PersistenceContractError,
    PersistedAttestationArtifact,
    _ARTIFACT_RE,
    _prefixed_id,
    _text,
    validate_artifact_aggregate,
)
from delivery_system.protocol import canonical_payload
from delivery_system import sqlite_schema


STORE_ERROR_CODES = frozenset({
    "attestation_artifact_not_found",
    "attestation_artifact_aggregate_corrupt",
    "attestation_artifact_conflict",
    "attestation_binding_reference_conflict",
    "attestation_revalidation_event_binding_mismatch",
    "attestation_revalidation_event_corrupt",
    "attestation_revalidation_event_conflict",
    "attestation_persistence_workspace_mismatch",
    "attestation_persistence_commit_outcome_unknown",
    "attestation_persistence_rollback_failed",
    "attestation_persistence_close_failed",
    "attestation_persistence_store_unavailable",
    "attestation_persistence_schema_owner_failed",
    "attestation_persistence_projection_corrupt",
    "attestation_persistence_schema_version_unsupported",
    "attestation_persistence_schema_metadata_corrupt",
    "attestation_persistence_schema_shape_mismatch",
    "attestation_persistence_migration_failed",
    "attestation_persistence_sqlite_busy",
    "attestation_persistence_sqlite_operational",
})


class StoreContractError(PersistenceContractError):
    """Stable Store-owned error without payload or implementation details."""

    def __init__(self, code: str) -> None:
        if type(code) is not str or code not in STORE_ERROR_CODES:
            code = "attestation_revalidation_event_corrupt"
        super().__init__(code)


def _store_error(code: str) -> None:
    raise StoreContractError(code)


def _sqlite_error_code(exc: BaseException) -> str:
    message = str(exc).lower()
    if isinstance(exc, sqlite3.OperationalError) and ("busy" in message or "locked" in message):
        return "attestation_persistence_sqlite_busy"
    return "attestation_persistence_sqlite_operational"


def _is_connection_fatal(exc: BaseException) -> bool:
    return isinstance(exc, sqlite3.ProgrammingError) or "closed" in str(exc).lower()


def _strict_projection_mapping(value: Any, expected: frozenset[str]) -> dict[str, Any]:
    if type(value) is not dict:
        raise PersistenceContractError("attestation_persistence_type_invalid")
    if any(type(key) is not str for key in value.keys()):
        raise PersistenceContractError("attestation_persistence_keyset_invalid")
    if frozenset(value.keys()) != expected:
        raise PersistenceContractError("attestation_persistence_keyset_invalid")
    return value


@dataclass(frozen=True, slots=True)
class AttestationArtifactAggregate:
    artifact: PersistedAttestationArtifact
    binding_reference: AttestationBindingReference

    def __post_init__(self) -> None:
        normalized_artifact, normalized_reference = validate_artifact_aggregate(
            self.artifact, self.binding_reference
        )
        object.__setattr__(self, "artifact", normalized_artifact)
        object.__setattr__(self, "binding_reference", normalized_reference)

    @classmethod
    def from_untrusted(cls, value: Any) -> "AttestationArtifactAggregate":
        try:
            if type(value) is cls:
                raw = {
                    "artifact": getattr(value, "artifact"),
                    "binding_reference": getattr(value, "binding_reference"),
                }
            elif type(value) is dict:
                raw = _strict_projection_mapping(
                    value, frozenset({"artifact", "binding_reference"})
                )
            else:
                raise PersistenceContractError("attestation_persistence_type_invalid")
            artifact = PersistedAttestationArtifact.from_untrusted(raw["artifact"])
            reference = AttestationBindingReference.from_untrusted(raw["binding_reference"])
            return cls(artifact, reference)
        except PersistenceContractError:
            raise
        except Exception:
            raise PersistenceContractError("attestation_persistence_payload_invalid")

    def to_payload(self) -> dict[str, Any]:
        normalized = AttestationArtifactAggregate.from_untrusted(self)
        return {
            "artifact": normalized.artifact.to_payload(),
            "binding_reference": normalized.binding_reference.to_payload(),
        }


@dataclass(frozen=True, slots=True)
class SequencedAttestationRevalidationEvent:
    event_sequence: int
    event: AttestationRevalidationEvent

    def __post_init__(self) -> None:
        if type(self.event_sequence) is not int or self.event_sequence < 1:
            raise PersistenceContractError("attestation_persistence_type_invalid")
        normalized = AttestationRevalidationEvent.from_untrusted(self.event)
        object.__setattr__(self, "event", normalized)

    @classmethod
    def from_untrusted(cls, value: Any) -> "SequencedAttestationRevalidationEvent":
        try:
            if type(value) is cls:
                sequence = getattr(value, "event_sequence")
                event = getattr(value, "event")
            elif type(value) is dict:
                raw = _strict_projection_mapping(
                    value, frozenset({"event_sequence", "event"})
                )
                sequence = raw["event_sequence"]
                event = raw["event"]
            else:
                raise PersistenceContractError("attestation_persistence_type_invalid")
            return cls(sequence, event)
        except PersistenceContractError:
            raise
        except Exception:
            raise PersistenceContractError("attestation_persistence_payload_invalid")

    def to_payload(self) -> dict[str, Any]:
        normalized = SequencedAttestationRevalidationEvent.from_untrusted(self)
        return {
            "event_sequence": normalized.event_sequence,
            "event": normalized.event.to_payload(),
        }


class AttestationPersistenceStore(Protocol):
    def persist_artifact(
        self,
        artifact: PersistedAttestationArtifact,
        binding_reference: AttestationBindingReference,
    ) -> AttestationArtifactAggregate: ...

    def get_artifact_aggregate(
        self,
        workspace_identity: str,
        artifact_id: str,
    ) -> AttestationArtifactAggregate | None: ...

    def append_revalidation_event(
        self,
        event: AttestationRevalidationEvent,
    ) -> SequencedAttestationRevalidationEvent: ...

    def get_latest_revalidation_event(
        self,
        workspace_identity: str,
        artifact_id: str,
    ) -> SequencedAttestationRevalidationEvent | None: ...


def _snapshot(value: dict[str, Any]) -> str:
    return canonical_payload(value)


def _json_snapshot(value: Any, error_code: str) -> dict[str, Any]:
    try:
        if type(value) is not str:
            _store_error(error_code)
        parsed = json.loads(value)
    except Exception:
        _store_error(error_code)
    if type(parsed) is not dict:
        _store_error(error_code)
    return parsed


class InMemoryAttestationPersistenceStore:
    """An instance-local, RLock-protected historical Store adapter."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._artifact_snapshots: dict[tuple[str, str], str] = {}
        self._reference_snapshots: dict[tuple[str, str], str] = {}
        self._aggregate_keys: set[tuple[str, str]] = set()
        self._event_snapshots: dict[tuple[str, str], dict[str, tuple[int, str]]] = {}
        self._event_partitions: set[tuple[str, str]] = set()

    def _validate_aggregate_containers_locked(self) -> None:
        try:
            if (
                type(self._artifact_snapshots) is not dict
                or type(self._reference_snapshots) is not dict
                or type(self._aggregate_keys) is not set
            ):
                _store_error("attestation_artifact_aggregate_corrupt")
            for key in self._artifact_snapshots.keys():
                self._partition_key(key, "attestation_artifact_aggregate_corrupt")
            for key in self._reference_snapshots.keys():
                self._partition_key(key, "attestation_artifact_aggregate_corrupt")
            for key in self._aggregate_keys:
                self._partition_key(key, "attestation_artifact_aggregate_corrupt")
        except StoreContractError:
            raise
        except Exception:
            _store_error("attestation_artifact_aggregate_corrupt")

    def _validate_event_containers_locked(self) -> None:
        try:
            if type(self._event_snapshots) is not dict or type(self._event_partitions) is not set:
                _store_error("attestation_revalidation_event_corrupt")
            for key in self._event_snapshots.keys():
                self._partition_key(key, "attestation_revalidation_event_corrupt")
            for key in self._event_partitions:
                self._partition_key(key, "attestation_revalidation_event_corrupt")
        except StoreContractError:
            raise
        except Exception:
            _store_error("attestation_revalidation_event_corrupt")

    @staticmethod
    def _partition_key(value: Any, error_code: str) -> tuple[str, str]:
        try:
            if type(value) is not tuple or len(value) != 2:
                _store_error(error_code)
            workspace, artifact_id = value
            if type(workspace) is not str or type(artifact_id) is not str:
                _store_error(error_code)
            canonical_workspace = _text(workspace, "workspace_identity")
            if canonical_workspace != workspace:
                _store_error(error_code)
            canonical_artifact_id = _prefixed_id(artifact_id, _ARTIFACT_RE)
            if canonical_artifact_id != artifact_id:
                _store_error(error_code)
            return workspace, artifact_id
        except StoreContractError:
            raise
        except Exception:
            _store_error(error_code)

    def _event_state_locked(
        self, key: tuple[str, str]
    ) -> dict[str, tuple[int, str]] | None:
        try:
            self._validate_event_containers_locked()
            has_marker = key in self._event_partitions
            has_records = key in self._event_snapshots
            if not has_marker and not has_records:
                return None
            if not has_marker or not has_records:
                _store_error("attestation_revalidation_event_corrupt")
            records = self._event_snapshots[key]
            if type(records) is not dict or not records:
                _store_error("attestation_revalidation_event_corrupt")
            return records
        except StoreContractError:
            raise
        except Exception:
            _store_error("attestation_revalidation_event_corrupt")

    @staticmethod
    def _key(workspace_identity: Any, artifact_id: Any) -> tuple[str, str]:
        workspace = _text(workspace_identity, "workspace_identity")
        artifact = _prefixed_id(artifact_id, _ARTIFACT_RE)
        return workspace, artifact

    @staticmethod
    def _artifact_snapshot(artifact: PersistedAttestationArtifact) -> str:
        return _snapshot(artifact.to_payload())

    @staticmethod
    def _reference_snapshot(reference: AttestationBindingReference) -> str:
        return _snapshot(reference.to_payload())

    @staticmethod
    def _event_snapshot(event: AttestationRevalidationEvent) -> str:
        return _snapshot(event.to_payload())

    def _read_aggregate_locked(
        self, key: tuple[str, str]
    ) -> AttestationArtifactAggregate | None:
        try:
            self._validate_aggregate_containers_locked()
            marker = key in self._aggregate_keys
            has_artifact = key in self._artifact_snapshots
            has_reference = key in self._reference_snapshots
            if not marker and not has_artifact and not has_reference:
                return None
            if not marker or not has_artifact or not has_reference:
                _store_error("attestation_artifact_aggregate_corrupt")
            artifact_snapshot = self._artifact_snapshots[key]
            reference_snapshot = self._reference_snapshots[key]
            if type(artifact_snapshot) is not str or type(reference_snapshot) is not str:
                _store_error("attestation_artifact_aggregate_corrupt")
        except StoreContractError:
            raise
        except Exception:
            _store_error("attestation_artifact_aggregate_corrupt")
        try:
            artifact = PersistedAttestationArtifact.from_untrusted(
                _json_snapshot(artifact_snapshot, "attestation_artifact_aggregate_corrupt")
            )
            reference = AttestationBindingReference.from_untrusted(
                _json_snapshot(reference_snapshot, "attestation_artifact_aggregate_corrupt")
            )
            normalized_artifact, normalized_reference = validate_artifact_aggregate(
                artifact, reference
            )
            if key != (normalized_artifact.workspace_identity, normalized_artifact.artifact_id):
                _store_error("attestation_artifact_aggregate_corrupt")
            if artifact_snapshot != self._artifact_snapshot(normalized_artifact):
                _store_error("attestation_artifact_aggregate_corrupt")
            if reference_snapshot != self._reference_snapshot(normalized_reference):
                _store_error("attestation_artifact_aggregate_corrupt")
            return AttestationArtifactAggregate(normalized_artifact, normalized_reference)
        except StoreContractError:
            raise
        except PersistenceContractError:
            _store_error("attestation_artifact_aggregate_corrupt")
        except Exception:
            _store_error("attestation_artifact_aggregate_corrupt")

    def _read_events_locked(
        self,
        key: tuple[str, str],
        aggregate: AttestationArtifactAggregate,
    ) -> dict[str, tuple[int, AttestationRevalidationEvent]]:
        records = self._event_state_locked(key)
        if records is None:
            return {}
        parsed: dict[str, tuple[int, AttestationRevalidationEvent]] = {}
        sequences: list[int] = []
        try:
            for indexed_id, record in records.items():
                if type(indexed_id) is not str or type(record) is not tuple or len(record) != 2:
                    _store_error("attestation_revalidation_event_corrupt")
                sequence, snapshot = record
                if type(sequence) is not int or sequence < 1 or type(snapshot) is not str:
                    _store_error("attestation_revalidation_event_corrupt")
                event = AttestationRevalidationEvent.from_untrusted(
                    _json_snapshot(snapshot, "attestation_revalidation_event_corrupt")
                )
                if event.event_id != indexed_id:
                    _store_error("attestation_revalidation_event_corrupt")
                if (event.workspace_identity, event.artifact_id) != key:
                    _store_error("attestation_revalidation_event_corrupt")
                if (
                    event.artifact_digest != aggregate.artifact.artifact_digest
                    or event.binding_reference_digest
                    != aggregate.binding_reference.binding_reference_digest
                ):
                    _store_error("attestation_revalidation_event_corrupt")
                if snapshot != self._event_snapshot(event):
                    _store_error("attestation_revalidation_event_corrupt")
                if sequence in sequences:
                    _store_error("attestation_revalidation_event_corrupt")
                parsed[indexed_id] = (sequence, event)
                sequences.append(sequence)
            if sorted(sequences) != list(range(1, len(sequences) + 1)):
                _store_error("attestation_revalidation_event_corrupt")
            return parsed
        except StoreContractError:
            raise
        except (PersistenceContractError, KeyError, TypeError, ValueError):
            _store_error("attestation_revalidation_event_corrupt")
        except Exception:
            _store_error("attestation_revalidation_event_corrupt")

    def persist_artifact(
        self,
        artifact: PersistedAttestationArtifact,
        binding_reference: AttestationBindingReference,
    ) -> AttestationArtifactAggregate:
        normalized_artifact = PersistedAttestationArtifact.from_untrusted(artifact)
        normalized_reference = AttestationBindingReference.from_untrusted(binding_reference)
        normalized_artifact, normalized_reference = validate_artifact_aggregate(
            normalized_artifact, normalized_reference
        )
        candidate = AttestationArtifactAggregate(normalized_artifact, normalized_reference)
        key = (candidate.artifact.workspace_identity, candidate.artifact.artifact_id)
        artifact_snapshot = self._artifact_snapshot(candidate.artifact)
        reference_snapshot = self._reference_snapshot(candidate.binding_reference)
        with self._lock:
            self._event_state_locked(key)
            existing = self._read_aggregate_locked(key)
            if existing is None:
                if self._event_state_locked(key) is not None:
                    _store_error("attestation_revalidation_event_corrupt")
            if existing is not None:
                if (
                    existing.artifact.artifact_digest != candidate.artifact.artifact_digest
                    or self._artifact_snapshot(existing.artifact) != artifact_snapshot
                ):
                    _store_error("attestation_artifact_conflict")
                if (
                    existing.binding_reference.binding_reference_digest
                    != candidate.binding_reference.binding_reference_digest
                    or self._reference_snapshot(existing.binding_reference) != reference_snapshot
                ):
                    _store_error("attestation_binding_reference_conflict")
                return AttestationArtifactAggregate(existing.artifact, existing.binding_reference)
            self._artifact_snapshots[key] = artifact_snapshot
            self._reference_snapshots[key] = reference_snapshot
            self._aggregate_keys.add(key)
            return AttestationArtifactAggregate(candidate.artifact, candidate.binding_reference)

    def get_artifact_aggregate(
        self,
        workspace_identity: str,
        artifact_id: str,
    ) -> AttestationArtifactAggregate | None:
        key = self._key(workspace_identity, artifact_id)
        with self._lock:
            aggregate = self._read_aggregate_locked(key)
            if aggregate is None:
                if self._event_state_locked(key) is not None:
                    _store_error("attestation_revalidation_event_corrupt")
            else:
                self._event_state_locked(key)
            return aggregate

    def append_revalidation_event(
        self,
        event: AttestationRevalidationEvent,
    ) -> SequencedAttestationRevalidationEvent:
        normalized_event = AttestationRevalidationEvent.from_untrusted(event)
        key = (normalized_event.workspace_identity, normalized_event.artifact_id)
        with self._lock:
            aggregate = self._read_aggregate_locked(key)
            if aggregate is None:
                if self._event_state_locked(key) is not None:
                    _store_error("attestation_revalidation_event_corrupt")
                _store_error("attestation_artifact_not_found")
            if (
                normalized_event.artifact_digest != aggregate.artifact.artifact_digest
                or normalized_event.binding_reference_digest
                != aggregate.binding_reference.binding_reference_digest
            ):
                _store_error("attestation_revalidation_event_binding_mismatch")
            events = self._read_events_locked(key, aggregate)
            candidate_snapshot = self._event_snapshot(normalized_event)
            existing = events.get(normalized_event.event_id)
            if existing is not None:
                sequence, existing_event = existing
                if self._event_snapshot(existing_event) != candidate_snapshot:
                    raise PersistenceContractError("attestation_revalidation_event_conflict")
                return SequencedAttestationRevalidationEvent(sequence, existing_event)
            sequence = len(events) + 1
            self._event_partitions.add(key)
            self._event_snapshots.setdefault(key, {})[normalized_event.event_id] = (
                sequence, candidate_snapshot
            )
            return SequencedAttestationRevalidationEvent(sequence, normalized_event)

    def get_latest_revalidation_event(
        self,
        workspace_identity: str,
        artifact_id: str,
    ) -> SequencedAttestationRevalidationEvent | None:
        key = self._key(workspace_identity, artifact_id)
        with self._lock:
            aggregate = self._read_aggregate_locked(key)
            if aggregate is None:
                if self._event_state_locked(key) is not None:
                    _store_error("attestation_revalidation_event_corrupt")
                _store_error("attestation_artifact_not_found")
            events = self._read_events_locked(key, aggregate)
            if not events:
                return None
            sequence, event = max(events.values(), key=lambda item: item[0])
            return SequencedAttestationRevalidationEvent(sequence, event)


class SQLiteAttestationPersistenceStore:
    """SQLite-backed implementation of the four-method Store contract."""

    OPEN = "OPEN"
    TRANSACTION_ACTIVE = "TRANSACTION_ACTIVE"
    COMMIT_OUTCOME_UNKNOWN = "COMMIT_OUTCOME_UNKNOWN"
    QUARANTINED = "QUARANTINED"
    CLOSED = "CLOSED"

    def __init__(
        self,
        database_path: str | Path,
        *,
        workspace_identity: str,
    ) -> None:
        if not isinstance(database_path, (str, Path)):
            raise StoreContractError("attestation_persistence_schema_owner_failed")
        self._validate_workspace(workspace_identity)
        self._workspace_identity = workspace_identity
        self._lock = threading.RLock()
        self._state = self.OPEN
        self._connection: sqlite3.Connection | None = None
        try:
            self._connection = sqlite_schema._open_connection(database_path)
            sqlite_schema.ensure_schema_v4(
                self._connection,
                expected_workspace_identity=workspace_identity,
            )
        except Exception as exc:
            connection = self._connection
            self._connection = None
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass
            self._state = self.CLOSED
            if isinstance(exc, sqlite_schema.SchemaOwnerError) and exc.code in STORE_ERROR_CODES:
                raise StoreContractError(exc.code) from exc
            raise StoreContractError("attestation_persistence_schema_owner_failed") from exc

    @staticmethod
    def _validate_workspace(value: Any) -> str:
        if type(value) is not str or not value or value != value.strip():
            raise StoreContractError("attestation_persistence_workspace_mismatch")
        import unicodedata
        if unicodedata.normalize("NFC", value) != value:
            raise StoreContractError("attestation_persistence_workspace_mismatch")
        return value

    def _require_open_locked(self) -> sqlite3.Connection:
        if self._state != self.OPEN or self._connection is None:
            _store_error("attestation_persistence_store_unavailable")
        return self._connection

    def _raise_sqlite_failure_locked(self, exc: sqlite3.Error) -> None:
        code = _sqlite_error_code(exc)
        if _is_connection_fatal(exc):
            self._terminate_connection_locked()
        elif self._state == self.TRANSACTION_ACTIVE:
            self._rollback_locked(exc)
        raise StoreContractError(code) from exc

    def _terminate_connection_locked(self) -> None:
        connection = self._connection
        self._connection = None
        self._state = self.CLOSED
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass

    def close(self) -> None:
        with self._lock:
            if self._state == self.CLOSED:
                return
            connection = self._connection
            self._connection = None
            self._state = self.CLOSED
            if connection is None:
                return
            try:
                connection.close()
            except Exception as exc:
                raise StoreContractError("attestation_persistence_close_failed") from exc

    @staticmethod
    def _canonical(value: Any) -> str:
        try:
            return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except Exception as exc:
            raise StoreContractError("attestation_persistence_projection_corrupt") from exc

    @staticmethod
    def _row_text(row: tuple[Any, ...], index: int, error: str) -> str:
        value = row[index]
        if type(value) is not str:
            _store_error(error)
        return value

    def _begin_locked(self, immediate: bool) -> sqlite3.Connection:
        connection = self._require_open_locked()
        try:
            connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            self._state = self.TRANSACTION_ACTIVE
            return connection
        except sqlite3.OperationalError as exc:
            if "busy" in str(exc).lower() or "locked" in str(exc).lower():
                _store_error("attestation_persistence_sqlite_busy")
            _store_error("attestation_persistence_sqlite_operational")
        except sqlite3.Error as exc:
            if _is_connection_fatal(exc):
                self._terminate_connection_locked()
            _store_error(_sqlite_error_code(exc))

    def _rollback_locked(self, primary: Exception | None = None) -> None:
        connection = self._connection
        try:
            if connection is not None:
                connection.rollback()
        except Exception as exc:
            self._state = self.QUARANTINED
            self._terminate_connection_locked()
            if primary is not None:
                raise StoreContractError("attestation_persistence_rollback_failed") from exc
            raise StoreContractError("attestation_persistence_rollback_failed") from exc
        self._state = self.OPEN

    def _commit_locked(self, candidate: Any) -> Any:
        connection = self._connection
        try:
            if connection is None:
                _store_error("attestation_persistence_store_unavailable")
            connection.commit()
            self._state = self.OPEN
            return candidate
        except Exception as exc:
            self._state = self.COMMIT_OUTCOME_UNKNOWN
            self._terminate_connection_locked()
            raise StoreContractError("attestation_persistence_commit_outcome_unknown") from exc

    @staticmethod
    def _artifact_row(row: tuple[Any, ...]) -> PersistedAttestationArtifact:
        try:
            claims = json.loads(row[4])
            payload = {
                "artifact_contract_version": row[2], "artifact_id": row[1],
                "workspace_identity": row[0], "attestation_id": row[3],
                "claims_payload": claims, "detached_proof": row[5],
                "claims_digest": row[6], "artifact_digest": row[7],
                "original_verified_at": row[8], "created_at": row[9],
            }
            if type(claims) is not dict or SQLiteAttestationPersistenceStore._canonical(payload) != row[30]:
                _store_error("attestation_persistence_projection_corrupt")
            claim_values = claims.get("claims")
            if type(claim_values) is not dict:
                _store_error("attestation_persistence_projection_corrupt")
            expected = {
                "attestation_version": row[10], "issuer_id": row[11], "key_id": row[12],
                "signature_algorithm": row[13], "credential_class": row[14],
                "credential_instance_id": row[15], "github_subject_identity": row[16],
                "repository_identity": row[17], "granted_capabilities": json.loads(row[18]),
                "driver_identity": row[19], "remote_authority": row[20], "preview_id": row[21],
                "revision": row[22], "operation_set_digest": row[23],
                "remote_snapshot_digest": row[24], "evidence_digest": row[25],
                "issued_at": row[26], "expires_at": row[27], "nonce": row[28],
                "source_verification_digest": row[29],
            }
            for key, value in expected.items():
                if claim_values.get(key) != value:
                    _store_error("attestation_persistence_projection_corrupt")
            return PersistedAttestationArtifact.from_untrusted(payload)
        except StoreContractError:
            raise
        except Exception as exc:
            raise StoreContractError("attestation_persistence_projection_corrupt") from exc

    @staticmethod
    def _reference_row(row: tuple[Any, ...]) -> AttestationBindingReference:
        try:
            payload = {key: row[index] for index, key in enumerate((
                "workspace_identity", "reference_id", "artifact_id", "artifact_digest", "binding_id",
                "repository_identity", "github_subject_identity", "driver_identity", "remote_authority",
                "preview_id", "revision", "plan_digest", "sealed_preview_digest", "operation_set_digest",
                "remote_snapshot_digest", "audit_id", "audit_digest", "evidence_id", "evidence_digest",
                "original_verified_at", "reference_contract_version", "binding_reference_digest",
            ))}
            parsed = json.loads(row[22])
            if type(parsed) is not dict or SQLiteAttestationPersistenceStore._canonical(parsed) != row[22]:
                _store_error("attestation_persistence_projection_corrupt")
            if SQLiteAttestationPersistenceStore._canonical(payload) != row[22]:
                _store_error("attestation_persistence_projection_corrupt")
            return AttestationBindingReference.from_untrusted(payload)
        except StoreContractError:
            raise
        except Exception as exc:
            raise StoreContractError("attestation_persistence_projection_corrupt") from exc

    @staticmethod
    def _event_row(row: tuple[Any, ...]) -> tuple[int, AttestationRevalidationEvent]:
        try:
            payload = {
                "event_identity_version": row[2], "event_payload_version": row[3],
                "event_id": row[1], "workspace_identity": row[0], "artifact_id": row[4],
                "artifact_digest": row[5], "revalidation_attempt_id": row[6],
                "revalidation_context_digest": row[7], "binding_reference_digest": row[8],
                "outcome": row[9], "revalidated_at": row[10], "failure_code": row[11],
                "result_digest": row[12], "event_payload_digest": row[13],
            }
            parsed = json.loads(row[15])
            if type(parsed) is not dict or SQLiteAttestationPersistenceStore._canonical(parsed) != row[15]:
                _store_error("attestation_persistence_projection_corrupt")
            if SQLiteAttestationPersistenceStore._canonical(payload) != row[15]:
                _store_error("attestation_persistence_projection_corrupt")
            return row[14], AttestationRevalidationEvent.from_untrusted(payload)
        except StoreContractError:
            raise
        except Exception as exc:
            raise StoreContractError("attestation_persistence_projection_corrupt") from exc

    def _aggregate_locked(self, connection: sqlite3.Connection, workspace: str, artifact_id: str) -> AttestationArtifactAggregate | None:
        try:
            artifact_rows = list(connection.execute("SELECT * FROM attestation_artifacts WHERE workspace_identity=? AND artifact_id=?", (workspace, artifact_id)))
            reference_rows = list(connection.execute("SELECT * FROM attestation_binding_references WHERE workspace_identity=? AND artifact_id=?", (workspace, artifact_id)))
            if not artifact_rows and not reference_rows:
                if connection.execute("SELECT 1 FROM attestation_revalidation_events WHERE workspace_identity=? AND artifact_id=? LIMIT 1", (workspace, artifact_id)).fetchone() is not None:
                    _store_error("attestation_revalidation_event_corrupt")
                return None
            if len(artifact_rows) != 1 or len(reference_rows) != 1:
                _store_error("attestation_artifact_aggregate_corrupt")
            try:
                artifact = self._artifact_row(artifact_rows[0])
                reference = self._reference_row(reference_rows[0])
            except StoreContractError as exc:
                if exc.code == "attestation_persistence_projection_corrupt":
                    _store_error("attestation_artifact_aggregate_corrupt")
                raise
            if (artifact.workspace_identity, artifact.artifact_id) != (workspace, artifact_id):
                _store_error("attestation_artifact_aggregate_corrupt")
            aggregate = AttestationArtifactAggregate(artifact, reference)
            event_rows = list(connection.execute("SELECT * FROM attestation_revalidation_events WHERE workspace_identity=? AND artifact_id=? ORDER BY event_sequence", (workspace, artifact_id)))
            try:
                parsed_events = [self._event_row(row) for row in event_rows]
            except StoreContractError as exc:
                if exc.code == "attestation_persistence_projection_corrupt":
                    _store_error("attestation_revalidation_event_corrupt")
                raise
            if [sequence for sequence, _ in parsed_events] != list(range(1, len(parsed_events) + 1)):
                _store_error("attestation_revalidation_event_corrupt")
            for _, event in parsed_events:
                if event.artifact_digest != artifact.artifact_digest or event.binding_reference_digest != reference.binding_reference_digest:
                    _store_error("attestation_revalidation_event_corrupt")
            return aggregate
        except StoreContractError:
            raise
        except sqlite3.Error:
            raise
        except Exception as exc:
            raise StoreContractError("attestation_artifact_aggregate_corrupt") from exc

    def persist_artifact(self, artifact: PersistedAttestationArtifact, binding_reference: AttestationBindingReference) -> AttestationArtifactAggregate:
        with self._lock:
            connection = self._require_open_locked()
            try:
                normalized_artifact, normalized_reference = validate_artifact_aggregate(artifact, binding_reference)
                if normalized_artifact.workspace_identity != self._workspace_identity or normalized_reference.workspace_identity != self._workspace_identity:
                    _store_error("attestation_persistence_workspace_mismatch")
                candidate = AttestationArtifactAggregate(normalized_artifact, normalized_reference)
                self._begin_locked(True)
                existing = self._aggregate_locked(connection, self._workspace_identity, candidate.artifact.artifact_id)
                if existing is not None:
                    if existing.artifact.to_payload() != candidate.artifact.to_payload():
                        _store_error("attestation_artifact_conflict")
                    if existing.binding_reference.to_payload() != candidate.binding_reference.to_payload():
                        _store_error("attestation_binding_reference_conflict")
                    result = existing
                else:
                    artifact_payload = candidate.artifact.to_payload()
                    claims = artifact_payload["claims_payload"]["claims"]
                    connection.execute("INSERT INTO attestation_artifacts VALUES (" + ",".join("?" for _ in range(31)) + ")", (
                        candidate.artifact.workspace_identity, candidate.artifact.artifact_id, candidate.artifact.artifact_contract_version, candidate.artifact.attestation_id,
                        self._canonical(artifact_payload["claims_payload"]), candidate.artifact.detached_proof, candidate.artifact.claims_digest, candidate.artifact.artifact_digest, candidate.artifact.original_verified_at, candidate.artifact.created_at,
                        claims["attestation_version"], claims["issuer_id"], claims["key_id"], claims["signature_algorithm"], claims["credential_class"], claims["credential_instance_id"], claims["github_subject_identity"], claims["repository_identity"], self._canonical(claims["granted_capabilities"]), claims["driver_identity"], claims["remote_authority"], claims["preview_id"], claims["revision"], claims["operation_set_digest"], claims["remote_snapshot_digest"], claims["evidence_digest"], claims["issued_at"], claims["expires_at"], claims["nonce"], claims["source_verification_digest"], self._canonical(artifact_payload)))
                    reference_payload = candidate.binding_reference.to_payload()
                    connection.execute("INSERT INTO attestation_binding_references VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", tuple(reference_payload[key] for key in (
                        "workspace_identity", "reference_id", "artifact_id", "artifact_digest", "binding_id", "repository_identity", "github_subject_identity", "driver_identity", "remote_authority", "preview_id", "revision", "plan_digest", "sealed_preview_digest", "operation_set_digest", "remote_snapshot_digest", "audit_id", "audit_digest", "evidence_id", "evidence_digest", "original_verified_at", "reference_contract_version", "binding_reference_digest")) + (self._canonical(reference_payload),))
                    result = self._aggregate_locked(connection, self._workspace_identity, candidate.artifact.artifact_id)
                    if result is None:
                        _store_error("attestation_artifact_aggregate_corrupt")
                return self._commit_locked(result)
            except StoreContractError as exc:
                if self._state == self.TRANSACTION_ACTIVE:
                    self._rollback_locked(exc)
                raise
            except sqlite3.IntegrityError as exc:
                if self._state == self.TRANSACTION_ACTIVE:
                    self._rollback_locked(exc)
                _store_error("attestation_artifact_conflict")
            except sqlite3.Error as exc:
                self._raise_sqlite_failure_locked(exc)
            except Exception as exc:
                if self._state == self.TRANSACTION_ACTIVE:
                    self._rollback_locked(exc)
                _store_error("attestation_persistence_projection_corrupt")

    def get_artifact_aggregate(self, workspace_identity: str, artifact_id: str) -> AttestationArtifactAggregate | None:
        with self._lock:
            self._validate_workspace(workspace_identity)
            if workspace_identity != self._workspace_identity:
                _store_error("attestation_persistence_workspace_mismatch")
            connection = self._begin_locked(False)
            try:
                result = self._aggregate_locked(connection, workspace_identity, artifact_id)
                self._commit_locked(result)
                return result
            except StoreContractError as exc:
                if self._state == self.TRANSACTION_ACTIVE:
                    self._rollback_locked(exc)
                raise
            except sqlite3.Error as exc:
                self._raise_sqlite_failure_locked(exc)

    def append_revalidation_event(self, event: AttestationRevalidationEvent) -> SequencedAttestationRevalidationEvent:
        with self._lock:
            connection = self._require_open_locked()
            try:
                normalized = AttestationRevalidationEvent.from_untrusted(event)
                if normalized.workspace_identity != self._workspace_identity:
                    _store_error("attestation_persistence_workspace_mismatch")
                self._begin_locked(True)
                aggregate = self._aggregate_locked(connection, self._workspace_identity, normalized.artifact_id)
                if aggregate is None:
                    _store_error("attestation_artifact_not_found")
                if normalized.artifact_digest != aggregate.artifact.artifact_digest or normalized.binding_reference_digest != aggregate.binding_reference.binding_reference_digest:
                    _store_error("attestation_revalidation_event_binding_mismatch")
                rows = list(connection.execute("SELECT * FROM attestation_revalidation_events WHERE workspace_identity=? AND artifact_id=? ORDER BY event_sequence", (self._workspace_identity, normalized.artifact_id)))
                try:
                    parsed = [self._event_row(row) for row in rows]
                except StoreContractError as exc:
                    if exc.code == "attestation_persistence_projection_corrupt":
                        _store_error("attestation_revalidation_event_corrupt")
                    raise
                sequences = [sequence for sequence, _ in parsed]
                if sequences != list(range(1, len(sequences) + 1)):
                    _store_error("attestation_revalidation_event_corrupt")
                existing = next(((sequence, current) for sequence, current in parsed if current.event_id == normalized.event_id), None)
                if existing is not None:
                    if existing[1].to_payload() != normalized.to_payload():
                        _store_error("attestation_revalidation_event_conflict")
                    result = SequencedAttestationRevalidationEvent(existing[0], existing[1])
                else:
                    sequence = len(parsed) + 1
                    payload = normalized.to_payload()
                    connection.execute("INSERT INTO attestation_revalidation_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
                        payload["workspace_identity"], payload["event_id"], payload["event_identity_version"], payload["event_payload_version"], payload["artifact_id"], payload["artifact_digest"], payload["revalidation_attempt_id"], payload["revalidation_context_digest"], payload["binding_reference_digest"], payload["outcome"], payload["revalidated_at"], payload["failure_code"], payload["result_digest"], payload["event_payload_digest"], sequence, self._canonical(payload)))
                    check = list(connection.execute("SELECT * FROM attestation_revalidation_events WHERE workspace_identity=? AND event_id=?", (self._workspace_identity, normalized.event_id)))
                    if len(check) != 1:
                        _store_error("attestation_revalidation_event_corrupt")
                    stored_sequence, stored_event = self._event_row(check[0])
                    result = SequencedAttestationRevalidationEvent(stored_sequence, stored_event)
                return self._commit_locked(result)
            except StoreContractError as exc:
                if self._state == self.TRANSACTION_ACTIVE:
                    self._rollback_locked(exc)
                raise
            except sqlite3.IntegrityError as exc:
                if self._state == self.TRANSACTION_ACTIVE:
                    self._rollback_locked(exc)
                _store_error("attestation_revalidation_event_conflict")
            except sqlite3.Error as exc:
                self._raise_sqlite_failure_locked(exc)
            except Exception as exc:
                if self._state == self.TRANSACTION_ACTIVE:
                    self._rollback_locked(exc)
                _store_error("attestation_revalidation_event_corrupt")

    def get_latest_revalidation_event(self, workspace_identity: str, artifact_id: str) -> SequencedAttestationRevalidationEvent | None:
        with self._lock:
            self._validate_workspace(workspace_identity)
            if workspace_identity != self._workspace_identity:
                _store_error("attestation_persistence_workspace_mismatch")
            connection = self._begin_locked(False)
            try:
                aggregate = self._aggregate_locked(connection, workspace_identity, artifact_id)
                if aggregate is None:
                    _store_error("attestation_artifact_not_found")
                rows = list(connection.execute("SELECT * FROM attestation_revalidation_events WHERE workspace_identity=? AND artifact_id=? ORDER BY event_sequence", (workspace_identity, artifact_id)))
                parsed = [self._event_row(row) for row in rows]
                if [sequence for sequence, _ in parsed] != list(range(1, len(parsed) + 1)):
                    _store_error("attestation_revalidation_event_corrupt")
                result = None if not parsed else SequencedAttestationRevalidationEvent(*parsed[-1])
                self._commit_locked(result)
                return result
            except StoreContractError as exc:
                if self._state == self.TRANSACTION_ACTIVE:
                    self._rollback_locked(exc)
                raise
            except sqlite3.Error as exc:
                self._raise_sqlite_failure_locked(exc)


__all__ = [
    "STORE_ERROR_CODES",
    "StoreContractError",
    "AttestationPersistenceStore",
    "AttestationArtifactAggregate",
    "SequencedAttestationRevalidationEvent",
    "InMemoryAttestationPersistenceStore",
    "SQLiteAttestationPersistenceStore",
]
