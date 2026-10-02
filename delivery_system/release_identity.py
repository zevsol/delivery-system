"""Resolve the Delivery System release identity without leaking source paths."""

from __future__ import annotations

from importlib import metadata as importlib_metadata
from pathlib import Path
import re


_DISTRIBUTION_NAME = "delivery-system"
_PROJECT_SECTION_RE = re.compile(r"(?ms)^\[project\]\s*(.*?)(?=^\[|\Z)")
_VERSION_ASSIGNMENT_RE = re.compile(r"^\s*version\s*=\s*(.*?)\s*(?:#.*)?$")
_QUOTED_VERSION_RE = re.compile(r"^([\"'])([^\"']+)\1$")


class ReleaseIdentityError(RuntimeError):
    """Internal failure resolving the canonical release identity."""

    def __init__(self) -> None:
        super().__init__("release_identity_unavailable")


def _normalise_version(value: object) -> str:
    if not isinstance(value, str):
        raise ReleaseIdentityError()
    result = value.strip()
    if not result:
        raise ReleaseIdentityError()
    return result


def _source_project_path() -> Path:
    return Path(__file__).resolve().parent.parent / "pyproject.toml"


def _source_project_version(project_path: Path | None = None) -> str:
    path = _source_project_path() if project_path is None else project_path
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ReleaseIdentityError() from exc

    sections = list(_PROJECT_SECTION_RE.finditer(text))
    if len(sections) != 1:
        raise ReleaseIdentityError()

    body = sections[0].group(1)
    assignments: list[str] = []
    for line in body.splitlines():
        if re.match(r"^\s*version\s*=", line):
            assignments.append(line)
    if len(assignments) != 1:
        raise ReleaseIdentityError()

    match = _VERSION_ASSIGNMENT_RE.fullmatch(assignments[0])
    if match is None:
        raise ReleaseIdentityError()
    quoted = _QUOTED_VERSION_RE.fullmatch(match.group(1).strip())
    if quoted is None:
        raise ReleaseIdentityError()
    return _normalise_version(quoted.group(2))


def _distribution_version() -> str:
    try:
        return _normalise_version(importlib_metadata.version(_DISTRIBUTION_NAME))
    except importlib_metadata.PackageNotFoundError:
        raise
    except Exception as exc:
        raise ReleaseIdentityError() from exc


def current_release_id() -> str:
    """Return the canonical release identity, failing closed on drift."""

    try:
        installed = _distribution_version()
    except importlib_metadata.PackageNotFoundError:
        return _source_project_version()

    source_path = _source_project_path()
    if not source_path.is_file():
        return installed
    source = _source_project_version(source_path)
    if installed != source:
        raise ReleaseIdentityError()
    return installed
