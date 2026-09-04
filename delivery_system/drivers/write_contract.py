"""Narrow, typed GitHub V1 write-executor boundary."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping, Protocol

from .contract import normalize_repository_identity


WRITE_EXECUTOR_IDENTITY = "delivery-system:github-rest-write-v1"
WRITE_EXECUTOR_ORIGIN = "https://api.github.com"
WRITE_CONTRACT_VERSION = "github-rest-write-v1"


def correlation_marker_for_request(request_identity: str) -> str:
    if type(request_identity) is not str or not request_identity:
        raise ValueError("write_correlation_invalid")
    return f"<!-- delivery-system-request:{request_identity} -->"


class WriteObservationKind(str, Enum):
    DEFINITIVE_SUCCESS = "DefinitiveSuccess"
    DEFINITIVE_REJECTED = "DefinitiveRejected"
    AMBIGUOUS = "Ambiguous"


@dataclass(frozen=True)
class RemoteIssueReference:
    repository_identity: str
    issue_number: int
    numeric_issue_id: str
    node_id: str

    def __post_init__(self) -> None:
        repository = normalize_repository_identity(self.repository_identity)
        if type(self.issue_number) is not int or self.issue_number < 1:
            raise ValueError("write_reference_invalid")
        if any(type(value) is not str or not value.strip() for value in (self.numeric_issue_id, self.node_id)):
            raise ValueError("write_reference_invalid")
        object.__setattr__(self, "repository_identity", repository)


@dataclass(frozen=True)
class CreateIssueCommand:
    repository_identity: str
    client_ref: str
    title: str
    body: str
    request_identity: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "repository_identity", normalize_repository_identity(self.repository_identity))
        if any(type(value) is not str or not value.strip() for value in (self.client_ref, self.title, self.body, self.request_identity)):
            raise ValueError("write_command_invalid")

    @property
    def correlation_marker(self) -> str:
        return correlation_marker_for_request(self.request_identity)


@dataclass(frozen=True)
class RelationshipCommand:
    repository_identity: str
    first: RemoteIssueReference
    second: RemoteIssueReference

    def __post_init__(self) -> None:
        repository = normalize_repository_identity(self.repository_identity)
        if self.first.repository_identity != repository or self.second.repository_identity != repository or self.first == self.second:
            raise ValueError("write_command_invalid")
        object.__setattr__(self, "repository_identity", repository)


def _freeze_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_value(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_value(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze_value(item) for item in value)
    return value


@dataclass(frozen=True)
class WriteObservation:
    kind: WriteObservationKind
    result_identity: str = ""
    result_payload: Mapping[str, Any] | None = None
    code: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.kind, WriteObservationKind):
            raise ValueError("write_observation_invalid")
        if self.result_identity and not isinstance(self.result_identity, str):
            raise ValueError("write_observation_invalid")
        if self.code and not isinstance(self.code, str):
            raise ValueError("write_observation_invalid")
        if self.result_payload is not None:
            if not isinstance(self.result_payload, Mapping):
                raise ValueError("write_observation_invalid")
            object.__setattr__(self, "result_payload", _freeze_value(self.result_payload))


class WriteDriver(Protocol):
    """Exactly the executable GitHub V1 operation surface."""

    executor_identity: str

    def create_issue(self, command: CreateIssueCommand) -> WriteObservation: ...

    def add_sub_issue(self, command: RelationshipCommand) -> WriteObservation: ...

    def add_dependency(self, command: RelationshipCommand) -> WriteObservation: ...
