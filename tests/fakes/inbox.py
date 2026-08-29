"""Test-only legacy Inbox protocol fixture; not part of the Runtime package."""

from dataclasses import dataclass

SCHEMA = "<!-- delivery-system:inbox-schema:1 -->"
USER_START = "<!-- delivery-system:user:start -->"
USER_END = "<!-- delivery-system:user:end -->"
MANAGED_START = "<!-- delivery-system:managed:start -->"
MANAGED_END = "<!-- delivery-system:managed:end -->"
MARKERS = (SCHEMA, USER_START, USER_END, MANAGED_START, MANAGED_END)


class InboxProtocolError(ValueError):
    """Malformed test Inbox input."""


@dataclass(frozen=True)
class InboxDocument:
    user_text: str
    managed_text: str


def _positions(text: str) -> dict[str, int]:
    positions = {}
    for marker in MARKERS:
        count = text.count(marker)
        if count != 1:
            raise InboxProtocolError(f"Inbox marker must occur exactly once: {marker}")
        positions[marker] = text.index(marker)
    if not (
        positions[SCHEMA] < positions[USER_START] < positions[USER_END]
        < positions[MANAGED_START] < positions[MANAGED_END]
    ):
        raise InboxProtocolError("Inbox markers are out of order or nested")
    return positions


def parse_inbox(text: str) -> InboxDocument:
    if not isinstance(text, str):
        raise InboxProtocolError("Inbox input must be text")
    positions = _positions(text)
    user_text = text[positions[USER_START] + len(USER_START):positions[USER_END]]
    managed_text = text[positions[MANAGED_START] + len(MANAGED_START):positions[MANAGED_END]]
    return InboxDocument(user_text=user_text, managed_text=managed_text)


def replace_managed(text: str, managed_text: str) -> str:
    positions = _positions(text)
    if any(marker in managed_text for marker in MARKERS):
        raise InboxProtocolError("Managed content cannot contain Inbox protocol markers")
    start = positions[MANAGED_START] + len(MANAGED_START)
    end = positions[MANAGED_END]
    return text[:start] + managed_text + text[end:]
