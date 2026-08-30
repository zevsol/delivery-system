"""Canonical, deterministic planning protocol primitives."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import uuid
from typing import Any, Callable, Mapping

from .canonical import _sort_key, _text, canonical_payload, digest, normalize


class RemoteItemType(str, Enum):
    ISSUE = "issue"
    PULL_REQUEST = "pull_request"


def _new_id(prefix: str, id_factory: Callable[[], str] | None = None) -> str:
    token = (id_factory or (lambda: uuid.uuid4().hex))()
    if not isinstance(token, str) or len(token) < 32 or any(char not in "0123456789abcdef" for char in token):
        raise ValueError("Injected lifecycle ID must contain at least 128 lowercase hexadecimal bits")
    return f"{prefix}-{token}"


def _validate_id(value: str, prefix: str) -> str:
    if not isinstance(value, str) or not value.startswith(prefix + "-"):
        raise ValueError(f"Expected {prefix} ID")
    hexadecimal = value[len(prefix) + 1:]
    if len(hexadecimal) < 32 or any(char not in "0123456789abcdef" for char in hexadecimal):
        raise ValueError(f"{prefix} ID must contain at least 128 bits")
    return value


def request_id(request: Mapping[str, Any], existing: str | None = None, id_factory: Callable[[], str] | None = None) -> str:
    """Return a lifecycle ID; new IDs never derive from mutable request content."""
    if existing is not None:
        return _validate_id(existing, "request")
    return _new_id("request", id_factory)


def preview_id(request_identifier: str, existing: str | None = None, id_factory: Callable[[], str] | None = None) -> str:
    """Return a plan lifecycle ID; plan content is never part of identity."""
    _validate_id(request_identifier, "request")
    if existing is not None:
        return _validate_id(existing, "preview")
    return _new_id("preview", id_factory)


@dataclass(frozen=True)
class UserFact:
    value: Any

    @property
    def kind(self) -> str:
        return "user_fact"

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "value": normalize(self.value)}


@dataclass(frozen=True)
class Proposed:
    value: Any

    @property
    def kind(self) -> str:
        return "proposed"

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "value": normalize(self.value)}


@dataclass(frozen=True)
class Assumption:
    value: Any

    @property
    def kind(self) -> str:
        return "assumption"

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "value": normalize(self.value)}


@dataclass(frozen=True)
class LegacyRemoteSnapshot:
    repository_id: str
    issue_ids: tuple[str, ...] = ()
    issue_updated_at: tuple[tuple[str, str], ...] = ()
    capabilities: tuple[str, ...] = ()
    permissions: tuple[tuple[str, bool], ...] = ()
    query_complete: bool = True
    candidate_records: tuple[dict[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        ids = list(self.issue_ids)
        if len(ids) != len(set(ids)):
            raise ValueError("Remote Snapshot contains duplicate Issue IDs")
        updated = list(self.issue_updated_at)
        if len({key for key, _ in updated}) != len(updated):
            raise ValueError("Remote Snapshot contains duplicate Issue update keys")
        if any(key not in set(ids) for key, _ in updated):
            raise ValueError("Remote Snapshot update keys must reference Issue IDs")
        permissions = list(self.permissions)
        if len({key for key, _ in permissions}) != len(permissions):
            raise ValueError("Remote Snapshot contains duplicate permission keys")
        return {
            "repository_id": self.repository_id,
            "issue_ids": sorted(ids),
            "issue_updated_at": {key: value for key, value in sorted(updated)},
            "capabilities": sorted(set(self.capabilities)),
            "permissions": {key: value for key, value in sorted(permissions)},
            "query_complete": self.query_complete,
            "candidate_records": sorted((normalize(record) for record in self.candidate_records), key=_sort_key),
        }


# Runtime owns the formal models. The legacy shape remains only as a named
# Slice 1 test/presentation adapter; the public RemoteSnapshot name is typed.
from delivery_system.runtime import SealedPreview as Preview, TypedRemoteSnapshot
RemoteSnapshot = TypedRemoteSnapshot
