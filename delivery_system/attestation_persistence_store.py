"""Offline, process-local persistence adapter for attestation history.

This module owns no SQLite schema, durable restart behavior, Runtime wiring,
current trust, or capability authorization.  It stores only canonical
historical projections in an instance-local InMemory adapter.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
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


STORE_ERROR_CODES = frozenset({
    "attestation_artifact_not_found",
    "attestation_artifact_aggregate_corrupt",
    "attestation_artifact_conflict",
    "attestation_binding_reference_conflict",
    "attestation_revalidation_event_binding_mismatch",
    "attestation_revalidation_event_corrupt",
})


class StoreContractError(PersistenceContractError):
    """Stable Store-owned error without payload or implementation details."""

    def __init__(self, code: str) -> None:
        if type(code) is not str or code not in STORE_ERROR_CODES:
            code = "attestation_revalidation_event_corrupt"
        super().__init__(code)


def _store_error(code: str) -> None:
    raise StoreContractError(code)


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


__all__ = [
    "STORE_ERROR_CODES",
    "StoreContractError",
    "AttestationPersistenceStore",
    "AttestationArtifactAggregate",
    "SequencedAttestationRevalidationEvent",
    "InMemoryAttestationPersistenceStore",
]
