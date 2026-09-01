"""Raw preview and evidence reads for Store implementations."""

from __future__ import annotations

import json
import sqlite3
from copy import deepcopy
from typing import Literal, Mapping, Sequence

from delivery_system.evidence import EvidenceRecord


class StoreReadMiss(LookupError):
    __slots__ = ("kind",)

    def __init__(self, kind: Literal["preview", "evidence"]) -> None:
        if kind not in {"preview", "evidence"}:
            raise ValueError("invalid_store_read_miss")
        self.kind = kind
        super().__init__(kind)


def read_inmemory_preview_latest(
    previews: Mapping[tuple[str, str], Mapping[str, object]],
    workspace_identity: str,
    preview_id: str,
) -> dict[str, object]:
    try:
        return deepcopy(dict(previews[(workspace_identity, preview_id)]))
    except KeyError as exc:
        raise StoreReadMiss("preview") from exc


def read_inmemory_preview_revision(
    preview_history: Mapping[tuple[str, str, int], Mapping[str, object]],
    workspace_identity: str,
    preview_id: str,
    revision: int,
) -> dict[str, object]:
    try:
        return deepcopy(dict(preview_history[(workspace_identity, preview_id, revision)]))
    except KeyError as exc:
        raise StoreReadMiss("preview") from exc


def read_inmemory_evidence_records(
    evidence: Mapping[tuple[str, str], EvidenceRecord],
    workspace_identity: str,
    evidence_ids: Sequence[str],
) -> list[dict[str, object]]:
    result = []
    for evidence_id in evidence_ids:
        record = evidence.get((workspace_identity, evidence_id))
        if record is None:
            raise StoreReadMiss("evidence")
        result.append(deepcopy(record.to_dict()))
    return result


def read_sqlite_latest_preview_revision(
    connection: sqlite3.Connection,
    workspace_identity: str,
    preview_id: str,
) -> int | None:
    row = connection.execute(
        "SELECT MAX(revision) FROM records WHERE workspace_identity=? AND record_type='preview' AND record_id=?",
        (workspace_identity, preview_id),
    ).fetchone()
    return None if row is None or row[0] is None else int(row[0])


def read_sqlite_preview_latest(
    connection: sqlite3.Connection,
    workspace_identity: str,
    preview_id: str,
) -> dict[str, object]:
    row = connection.execute(
        "SELECT revision, payload FROM records WHERE workspace_identity=? AND record_type='preview' AND record_id=? ORDER BY revision DESC LIMIT 1",
        (workspace_identity, preview_id),
    ).fetchone()
    if row is None:
        raise StoreReadMiss("preview")
    result = json.loads(row[1])
    result["revision"] = row[0]
    return result


def read_sqlite_preview_revision(
    connection: sqlite3.Connection,
    workspace_identity: str,
    preview_id: str,
    revision: int,
) -> dict[str, object]:
    row = connection.execute(
        "SELECT payload FROM records WHERE workspace_identity=? AND record_type='preview' AND record_id=? AND revision=?",
        (workspace_identity, preview_id, revision),
    ).fetchone()
    if row is None:
        raise StoreReadMiss("preview")
    return json.loads(row[0])


def read_sqlite_evidence_records(
    connection: sqlite3.Connection,
    workspace_identity: str,
    evidence_ids: Sequence[str],
    revision: int | None = None,
) -> list[dict[str, object]]:
    result = []
    for evidence_id in evidence_ids:
        if revision is None:
            row = connection.execute(
                "SELECT payload FROM records WHERE workspace_identity=? AND record_type='evidence' AND record_id=? ORDER BY revision DESC LIMIT 1",
                (workspace_identity, evidence_id),
            ).fetchone()
        else:
            row = connection.execute(
                "SELECT payload FROM records WHERE workspace_identity=? AND record_type='evidence' AND record_id=? AND revision=?",
                (workspace_identity, evidence_id, revision),
            ).fetchone()
        if row is None:
            raise StoreReadMiss("evidence")
        result.append(json.loads(row[0]))
    return result
