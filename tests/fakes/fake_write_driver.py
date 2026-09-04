"""Deterministic offline WriteDriver for PC2-B tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from delivery_system.drivers.write_contract import (
    CreateIssueCommand, RelationshipCommand, WriteObservation,
    WriteObservationKind, WRITE_EXECUTOR_IDENTITY,
)


@dataclass(frozen=True)
class DispatchTrace:
    operation: str
    command: object
    observation: WriteObservation


class FakeWriteDriver:
    """A no-network driver with scripted transport-level observations."""

    is_fake = True
    executor_identity = WRITE_EXECUTOR_IDENTITY

    def __init__(self, observations: Iterable[WriteObservation] = ()) -> None:
        self._observations = list(observations)
        self._trace: list[DispatchTrace] = []

    @property
    def trace(self) -> tuple[DispatchTrace, ...]:
        return tuple(self._trace)

    def _next(self, operation: str, command: object) -> WriteObservation:
        if not isinstance(command, (CreateIssueCommand, RelationshipCommand)):
            raise ValueError("write_command_invalid")
        if not self._observations:
            observation = WriteObservation(WriteObservationKind.AMBIGUOUS, code="fake_observation_exhausted")
        else:
            observation = self._observations.pop(0)
        self._trace.append(DispatchTrace(operation, command, observation))
        return observation

    def create_issue(self, command: CreateIssueCommand) -> WriteObservation:
        return self._next("create_issue", command)

    def add_sub_issue(self, command: RelationshipCommand) -> WriteObservation:
        return self._next("add_sub_issue", command)

    def add_dependency(self, command: RelationshipCommand) -> WriteObservation:
        return self._next("add_dependency", command)
