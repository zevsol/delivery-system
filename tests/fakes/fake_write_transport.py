"""Deterministic offline transport for the GitHub write adapter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from delivery_system.drivers.contract import DriverError
from delivery_system.drivers.github_write import WriteTransportResponse


@dataclass(frozen=True)
class FakePostTrace:
    path: str
    body: bytes


class FakeWriteTransport:
    """Scripts bounded responses or exception instances; never accesses a network."""

    __slots__ = ("_outcomes", "_position", "_trace")

    def __init__(self, outcomes: Iterable[WriteTransportResponse | BaseException] = ()) -> None:
        self._outcomes = tuple(outcomes)
        self._position = 0
        self._trace: list[FakePostTrace] = []

    @property
    def trace(self) -> tuple[FakePostTrace, ...]:
        return tuple(self._trace)

    def post(self, path: str, body: bytes, headers: Mapping[str, str]) -> WriteTransportResponse:
        if not isinstance(headers, Mapping):
            raise DriverError("fake_write_request_invalid")
        self._trace.append(FakePostTrace(path, bytes(body)))
        if self._position >= len(self._outcomes):
            raise TimeoutError("fake timeout")
        outcome = self._outcomes[self._position]
        self._position += 1
        if isinstance(outcome, BaseException):
            raise outcome
        if not isinstance(outcome, WriteTransportResponse):
            raise DriverError("fake_write_response_invalid")
        return outcome
