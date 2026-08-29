"""Shared SQLite schema ownership for the preview and attestation stores."""

from __future__ import annotations

import json
import re
import sqlite3
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 5
_V3_TABLES = ("store_meta", "item_lineage", "records", "audit_history")
_V4_TABLES = _V3_TABLES + (
    "attestation_artifacts",
    "attestation_binding_references",
    "attestation_revalidation_events",
)


class SchemaOwnerError(Exception):
    """Sanitized schema-owner failure with a stable code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _open_connection(path: str | Path) -> sqlite3.Connection:
    """Module-private connection seam used by production and deterministic tests."""
    try:
        connection = sqlite3.connect(
            path, timeout=5, isolation_level=None, check_same_thread=False
        )
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection
    except sqlite3.Error as exc:
        raise SchemaOwnerError("attestation_persistence_sqlite_operational") from exc


def _workspace(value: Any) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise SchemaOwnerError("attestation_persistence_workspace_mismatch")
    if unicodedata.normalize("NFC", value) != value:
        raise SchemaOwnerError("attestation_persistence_workspace_mismatch")
    return value


def _safe_sql(connection: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    try:
        return list(connection.execute(sql, params))
    except sqlite3.Error as exc:
        if isinstance(exc, sqlite3.OperationalError) and _is_busy(exc):
            raise SchemaOwnerError("attestation_persistence_sqlite_busy") from exc
        raise SchemaOwnerError("attestation_persistence_sqlite_operational") from exc


def _is_busy(exc: BaseException) -> bool:
    text = str(exc).lower()
    return isinstance(exc, sqlite3.OperationalError) and ("busy" in text or "locked" in text)


def _execute_script(connection: sqlite3.Connection, script: str) -> None:
    for statement in script.split(";"):
        statement = statement.strip()
        if statement:
            try:
                connection.execute(statement)
            except sqlite3.Error as exc:
                if _is_busy(exc):
                    raise SchemaOwnerError("attestation_persistence_sqlite_busy") from exc
                raise SchemaOwnerError("attestation_persistence_migration_failed") from exc


def _objects(connection: sqlite3.Connection) -> list[tuple[str, str, str, str]]:
    rows = _safe_sql(
        connection,
        "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
    )
    return [(str(row[0]), str(row[1]), str(row[2]), str(row[3])) for row in rows]


def _table_info(connection: sqlite3.Connection, table: str) -> tuple[tuple[Any, ...], ...]:
    return tuple(_safe_sql(connection, f"PRAGMA table_info({table})"))


def _table_xinfo(connection: sqlite3.Connection, table: str) -> tuple[tuple[Any, ...], ...]:
    return tuple(_safe_sql(connection, f"PRAGMA table_xinfo({table})"))


def _table_sql(objects: list[tuple[str, str, str, str]], table: str) -> str:
    for kind, name, _table_name, sql in objects:
        if kind == "table" and name == table:
            return sql
    return ""


def _foreign_keys(connection: sqlite3.Connection, table: str) -> tuple[tuple[Any, ...], ...]:
    return tuple(_safe_sql(connection, f"PRAGMA foreign_key_list({table})"))


def _index_xinfo(connection: sqlite3.Connection, name: str) -> tuple[tuple[Any, ...], ...]:
    rows = _safe_sql(connection, f"PRAGMA index_xinfo({name})")
    return tuple(
        (row[2], row[3], row[4], row[5])
        for row in rows
    )


def _index_semantics(connection: sqlite3.Connection, table: str) -> tuple[tuple[Any, ...], ...]:
    result: list[tuple[Any, ...]] = []
    for row in _safe_sql(connection, f"PRAGMA index_list({table})"):
        name = str(row[1])
        unique = int(row[2])
        origin = str(row[3]) if len(row) > 3 else ""
        partial = int(row[4]) if len(row) > 4 else 0
        result.append((name, unique, origin, partial, _index_xinfo(connection, name)))
    return tuple(sorted(result, key=lambda value: value[0]))


def _foreign_key_signature(connection: sqlite3.Connection, table: str) -> tuple[tuple[Any, ...], ...]:
    groups: dict[int, list[tuple[Any, Any]]] = {}
    attributes: dict[int, tuple[Any, ...]] = {}
    for row in _foreign_keys(connection, table):
        groups.setdefault(int(row[0]), []).append((row[3], row[4]))
        attributes[int(row[0])] = (row[2], row[5], row[6], row[7])
    return tuple(sorted((attributes[key] + (tuple(values),) for key, values in groups.items()), key=str))


@dataclass(frozen=True)
class _DDLToken:
    kind: str
    value: str


class _DDLTokenError(ValueError):
    pass


_DDL_KEYWORDS = frozenset(
    {
        "and", "as", "between", "case", "cast", "collate", "else", "escape",
        "glob", "in", "is", "like", "match", "not", "null", "or", "regexp",
        "then", "when", "with", "true", "false", "check",
    }
)
_DDL_OPERATORS = tuple(
    sorted(
        ("->>", "<<", ">>", "||", "->", "<>" , "!=", "<=", ">=", "=="),
        key=len,
        reverse=True,
    )
)
_DDL_PUNCTUATION = frozenset("(),;.*+-/%|&^~<>!=?:")


def _word_token(value: str) -> _DDLToken:
    canonical = value.casefold()
    kind = "KEYWORD" if canonical in _DDL_KEYWORDS else "IDENT"
    return _DDLToken(kind, canonical)


def _lex_ddl(sql: str) -> tuple[_DDLToken, ...]:
    tokens: list[_DDLToken] = []
    index = 0
    length = len(sql)
    while index < length:
        char = sql[index]
        if char.isspace():
            index += 1
            continue
        if sql.startswith("--", index):
            newline = sql.find("\n", index + 2)
            index = length if newline < 0 else newline + 1
            continue
        if sql.startswith("/*", index):
            end = sql.find("*/", index + 2)
            if end < 0:
                raise _DDLTokenError("unterminated block comment")
            index = end + 2
            continue
        if char == "'":
            index += 1
            value: list[str] = []
            while index < length:
                if sql[index] == "'":
                    if index + 1 < length and sql[index + 1] == "'":
                        value.append("'")
                        index += 2
                        continue
                    index += 1
                    break
                value.append(sql[index])
                index += 1
            else:
                raise _DDLTokenError("unterminated string")
            tokens.append(_DDLToken("STRING", "".join(value)))
            continue
        if char in ('"', "`"):
            terminator = char
            index += 1
            value: list[str] = []
            while index < length:
                if sql[index] == terminator:
                    if index + 1 < length and sql[index + 1] == terminator:
                        value.append(terminator)
                        index += 2
                        continue
                    index += 1
                    break
                value.append(sql[index])
                index += 1
            else:
                raise _DDLTokenError("unterminated quoted identifier")
            tokens.append(_DDLToken("IDENT", "".join(value).casefold()))
            continue
        if char == "[":
            index += 1
            value: list[str] = []
            while index < length:
                if sql[index] == "]":
                    if index + 1 < length and sql[index + 1] == "]":
                        value.append("]")
                        index += 2
                        continue
                    index += 1
                    break
                value.append(sql[index])
                index += 1
            else:
                raise _DDLTokenError("unterminated bracket identifier")
            tokens.append(_DDLToken("IDENT", "".join(value).casefold()))
            continue
        if char.isalpha() or char == "_" or ord(char) >= 128:
            start = index
            index += 1
            while index < length and (sql[index].isalnum() or sql[index] == "_" or ord(sql[index]) >= 128):
                index += 1
            tokens.append(_word_token(sql[start:index]))
            continue
        if char.isdigit() or (char == "." and index + 1 < length and sql[index + 1].isdigit()):
            start = index
            index += 1
            while index < length and (sql[index].isalnum() or sql[index] in ".+-"):
                if sql[index] in "+-" and sql[index - 1].lower() not in {"e"}:
                    break
                index += 1
            tokens.append(_DDLToken("NUMBER", sql[start:index].casefold()))
            continue
        operator = next((candidate for candidate in _DDL_OPERATORS if sql.startswith(candidate, index)), None)
        if operator is not None:
            tokens.append(_DDLToken("OPERATOR", operator))
            index += len(operator)
            continue
        if char in _DDL_PUNCTUATION:
            kind = "OPERATOR" if char in "+-*/%|&^~<>!=?:" else "PUNCT"
            tokens.append(_DDLToken(kind, char))
            index += 1
            continue
        raise _DDLTokenError(f"unrecognized DDL character: {char!r}")
    return tuple(tokens)


def _canonical_constraint(tokens: tuple[_DDLToken, ...]) -> tuple[str, ...]:
    return tuple(f"{token.kind}:{token.value}" for token in tokens)


def _check_expressions(sql: str) -> tuple[tuple[str, ...], ...]:
    try:
        tokens = _lex_ddl(sql)
        checks: list[tuple[str, ...]] = []
        for index, token in enumerate(tokens):
            if token.kind != "KEYWORD" or token.value != "check":
                continue
            opening = index + 1
            if opening >= len(tokens) or tokens[opening] != _DDLToken("PUNCT", "("):
                raise _DDLTokenError("CHECK must be followed by an opening parenthesis")
            depth = 0
            closing = None
            for cursor in range(opening, len(tokens)):
                current = tokens[cursor]
                if current == _DDLToken("PUNCT", "("):
                    depth += 1
                elif current == _DDLToken("PUNCT", ")"):
                    depth -= 1
                    if depth == 0:
                        closing = cursor
                        break
                    if depth < 0:
                        raise _DDLTokenError("unbalanced CHECK parentheses")
            if closing is None:
                raise _DDLTokenError("unterminated CHECK expression")
            checks.append(_canonical_constraint(tokens[opening + 1:closing]))
        return tuple(sorted(checks))
    except _DDLTokenError as exc:
        raise SchemaOwnerError("attestation_persistence_schema_shape_mismatch") from exc


def _script_table_definition(script: str, table: str) -> str:
    pattern = re.compile(r"CREATE\s+TABLE\s+" + re.escape(table) + r"\s*\(", re.IGNORECASE)
    match = pattern.search(script)
    if match is None:
        return ""
    opening = script.find("(", match.start(), match.end())
    depth = 0
    quote: str | None = None
    for index in range(opening, len(script)):
        char = script[index]
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in ("'", '"', '`'):
            quote = char
            continue
        if char == "[":
            quote = "]"
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return script[match.start():index + 1]
    return ""


def _expected_index_xinfo(columns: tuple[str, ...]) -> tuple[tuple[Any, ...], ...]:
    return tuple((column, 0, "BINARY", 1) for column in columns) + ((None, 0, "BINARY", 0),)


def _expected_internal_indexes(table: str) -> tuple[tuple[Any, ...], ...]:
    columns = _V3_COLUMNS.get(table, _V4_LAYOUT.get(table, ()))
    primary_rows = [
        row for row in columns
        if (row[4] if len(row) == 5 else row[3])
    ]
    primary = tuple(
        row[0]
        for row in sorted(
            primary_rows,
            key=lambda row: row[4] if len(row) == 5 else row[3],
        )
    )
    uniques = {
        "attestation_artifacts": (("workspace_identity", "attestation_id"),),
        "attestation_binding_references": (
            ("workspace_identity", "reference_id"),
            ("workspace_identity", "binding_id"),
            ("workspace_identity", "artifact_id", "binding_reference_digest"),
        ),
        "attestation_revalidation_events": (("workspace_identity", "artifact_id", "event_sequence"),),
    }.get(table, ())
    expected = [(1, "pk", 0, _expected_index_xinfo(primary))] if primary else []
    expected.extend((1, "u", 0, _expected_index_xinfo(unique)) for unique in uniques)
    return tuple(sorted(expected, key=str))


def _check_index_semantics(
    connection: sqlite3.Connection,
    table: str,
    explicit_names: tuple[str, ...],
) -> bool:
    actual = _index_semantics(connection, table)
    actual_explicit = {
        name: (unique, origin, partial, xinfo)
        for name, unique, origin, partial, xinfo in actual
        if not name.startswith("sqlite_autoindex_")
    }
    if set(actual_explicit) != set(explicit_names):
        return False
    for name in explicit_names:
        unique, origin, partial, xinfo = actual_explicit[name]
        if (unique, origin, partial) != (0, "c", 0):
            return False
        expected_columns = {
            "idx_attestation_artifacts_workspace_preview_revision": ("workspace_identity", "claims_preview_id", "claims_revision"),
            "idx_attestation_artifacts_workspace_digest": ("workspace_identity", "artifact_digest"),
            "idx_attestation_references_workspace_binding": ("workspace_identity", "binding_id"),
            "idx_attestation_events_workspace_artifact_sequence": ("workspace_identity", "artifact_id", "event_sequence"),
        }[name]
        if xinfo != _expected_index_xinfo(expected_columns):
            return False
    actual_internal = sorted(
        (unique, origin, partial, xinfo)
        for name, unique, origin, partial, xinfo in actual
        if name.startswith("sqlite_autoindex_")
    )
    return tuple(actual_internal) == _expected_internal_indexes(table)


_V3_COLUMNS = {
    "store_meta": (("schema_version", "INTEGER", 1, None, 0), ("workspace_identity", "TEXT", 1, None, 0)),
    "item_lineage": (("workspace_identity", "TEXT", 1, None, 1), ("preview_id", "TEXT", 1, None, 2), ("revision", "INTEGER", 1, None, 3), ("client_ref", "TEXT", 1, None, 4), ("item_id", "TEXT", 1, None, 0), ("tombstone", "INTEGER", 1, "0", 0)),
    "records": (("workspace_identity", "TEXT", 1, None, 1), ("record_type", "TEXT", 1, None, 2), ("record_id", "TEXT", 1, None, 3), ("revision", "INTEGER", 0, None, 4), ("payload", "TEXT", 1, None, 0)),
    "audit_history": (("workspace_identity", "TEXT", 1, None, 1), ("audit_id", "TEXT", 1, None, 2), ("event_no", "INTEGER", 1, None, 3), ("payload", "TEXT", 1, None, 0), ("reason", "TEXT", 1, None, 0), ("occurred_at", "TEXT", 1, None, 0)),
}

def _v3_fingerprint(connection: sqlite3.Connection) -> bool:
    objects = _objects(connection)
    if {(kind, name) for kind, name, _table_name, _sql in objects} != {("table", name) for name in _V3_TABLES}:
        return False
    for table, expected in _V3_COLUMNS.items():
        actual = _table_xinfo(connection, table)
        if len(actual) != len(expected):
            return False
        for row, wanted in zip(actual, expected):
            # cid, name, type, notnull, dflt_value, pk, hidden/generated
            if (row[1], row[2].upper(), row[3], row[4], row[5]) != wanted or row[6] != 0:
                return False
        if _check_expressions(_table_sql(objects, table)):
            return False
        if _foreign_key_signature(connection, table):
            return False
        if not _check_index_semantics(connection, table, ()):
            return False
    return True


_V4_DDL = r"""
CREATE TABLE attestation_artifacts (
    workspace_identity TEXT NOT NULL CHECK (length(workspace_identity) > 0), artifact_id TEXT NOT NULL CHECK (length(artifact_id) > 0), artifact_contract_version TEXT NOT NULL CHECK (artifact_contract_version = 'offline-attestation-artifact-v1'), attestation_id TEXT NOT NULL CHECK (length(attestation_id) > 0), claims_payload_json TEXT NOT NULL CHECK (length(claims_payload_json) > 0), detached_proof TEXT NOT NULL CHECK (length(detached_proof) > 0), claims_digest TEXT NOT NULL CHECK (length(claims_digest) = 71 AND substr(claims_digest, 1, 7) = 'sha256:' AND substr(claims_digest, 8) NOT GLOB '*[^0-9a-f]*'), artifact_digest TEXT NOT NULL CHECK (length(artifact_digest) = 71 AND substr(artifact_digest, 1, 7) = 'sha256:' AND substr(artifact_digest, 8) NOT GLOB '*[^0-9a-f]*'), original_verified_at TEXT NOT NULL CHECK (length(original_verified_at) > 0), created_at TEXT NOT NULL CHECK (length(created_at) > 0), claims_attestation_version TEXT NOT NULL CHECK (claims_attestation_version IN ('1', '2')), claims_issuer_id TEXT NOT NULL CHECK (length(claims_issuer_id) > 0), claims_key_id TEXT NOT NULL CHECK (length(claims_key_id) > 0), claims_signature_algorithm TEXT NOT NULL CHECK (length(claims_signature_algorithm) > 0), claims_credential_class TEXT NOT NULL CHECK (length(claims_credential_class) > 0), claims_credential_instance_id TEXT NOT NULL CHECK (length(claims_credential_instance_id) > 0), claims_github_subject_identity TEXT NOT NULL CHECK (length(claims_github_subject_identity) > 0), claims_repository_identity TEXT NOT NULL CHECK (length(claims_repository_identity) > 0), claims_granted_capabilities_json TEXT NOT NULL CHECK (length(claims_granted_capabilities_json) > 0), claims_driver_identity TEXT NOT NULL CHECK (length(claims_driver_identity) > 0), claims_remote_authority TEXT NOT NULL CHECK (length(claims_remote_authority) = 71 AND substr(claims_remote_authority, 1, 7) = 'sha256:' AND substr(claims_remote_authority, 8) NOT GLOB '*[^0-9a-f]*'), claims_preview_id TEXT NOT NULL CHECK (length(claims_preview_id) > 0), claims_revision INTEGER NOT NULL CHECK (claims_revision > 0), claims_operation_set_digest TEXT NOT NULL CHECK (length(claims_operation_set_digest) = 71 AND substr(claims_operation_set_digest, 1, 7) = 'sha256:' AND substr(claims_operation_set_digest, 8) NOT GLOB '*[^0-9a-f]*'), claims_remote_snapshot_digest TEXT NOT NULL CHECK (length(claims_remote_snapshot_digest) = 71 AND substr(claims_remote_snapshot_digest, 1, 7) = 'sha256:' AND substr(claims_remote_snapshot_digest, 8) NOT GLOB '*[^0-9a-f]*'), claims_evidence_digest TEXT NOT NULL CHECK (length(claims_evidence_digest) = 71 AND substr(claims_evidence_digest, 1, 7) = 'sha256:' AND substr(claims_evidence_digest, 8) NOT GLOB '*[^0-9a-f]*'), claims_issued_at TEXT NOT NULL CHECK (length(claims_issued_at) > 0), claims_expires_at TEXT NOT NULL CHECK (length(claims_expires_at) > 0), claims_nonce TEXT NOT NULL CHECK (length(claims_nonce) > 0), claims_source_verification_digest TEXT NOT NULL CHECK (length(claims_source_verification_digest) = 71 AND substr(claims_source_verification_digest, 1, 7) = 'sha256:' AND substr(claims_source_verification_digest, 8) NOT GLOB '*[^0-9a-f]*'), claims_challenge_digest TEXT, claims_credential_principal_identity TEXT, canonical_json TEXT NOT NULL CHECK (length(canonical_json) > 0), CHECK ((claims_attestation_version = '1' AND claims_challenge_digest IS NULL AND claims_credential_principal_identity IS NULL) OR (claims_attestation_version = '2' AND claims_challenge_digest IS NOT NULL AND claims_credential_principal_identity IS NOT NULL)), PRIMARY KEY (workspace_identity, artifact_id), UNIQUE (workspace_identity, attestation_id)
);
CREATE TABLE attestation_binding_references (
    workspace_identity TEXT NOT NULL CHECK (length(workspace_identity) > 0), reference_id TEXT NOT NULL CHECK (length(reference_id) > 0), artifact_id TEXT NOT NULL CHECK (length(artifact_id) > 0), artifact_digest TEXT NOT NULL CHECK (length(artifact_digest) = 71 AND substr(artifact_digest, 1, 7) = 'sha256:' AND substr(artifact_digest, 8) NOT GLOB '*[^0-9a-f]*'), binding_id TEXT NOT NULL CHECK (length(binding_id) > 0), repository_identity TEXT NOT NULL CHECK (length(repository_identity) > 0), github_subject_identity TEXT NOT NULL CHECK (length(github_subject_identity) > 0), driver_identity TEXT NOT NULL CHECK (length(driver_identity) > 0), remote_authority TEXT NOT NULL CHECK (length(remote_authority) = 71 AND substr(remote_authority, 1, 7) = 'sha256:' AND substr(remote_authority, 8) NOT GLOB '*[^0-9a-f]*'), preview_id TEXT NOT NULL CHECK (length(preview_id) > 0), revision INTEGER NOT NULL CHECK (revision > 0), plan_digest TEXT NOT NULL CHECK (length(plan_digest) = 71 AND substr(plan_digest, 1, 7) = 'sha256:' AND substr(plan_digest, 8) NOT GLOB '*[^0-9a-f]*'), sealed_preview_digest TEXT NOT NULL CHECK (length(sealed_preview_digest) = 71 AND substr(sealed_preview_digest, 1, 7) = 'sha256:' AND substr(sealed_preview_digest, 8) NOT GLOB '*[^0-9a-f]*'), operation_set_digest TEXT NOT NULL CHECK (length(operation_set_digest) = 71 AND substr(operation_set_digest, 1, 7) = 'sha256:' AND substr(operation_set_digest, 8) NOT GLOB '*[^0-9a-f]*'), remote_snapshot_digest TEXT NOT NULL CHECK (length(remote_snapshot_digest) = 71 AND substr(remote_snapshot_digest, 1, 7) = 'sha256:' AND substr(remote_snapshot_digest, 8) NOT GLOB '*[^0-9a-f]*'), audit_id TEXT NOT NULL CHECK (length(audit_id) > 0), audit_digest TEXT NOT NULL CHECK (length(audit_digest) = 71 AND substr(audit_digest, 1, 7) = 'sha256:' AND substr(audit_digest, 8) NOT GLOB '*[^0-9a-f]*'), evidence_id TEXT NOT NULL CHECK (length(evidence_id) > 0), evidence_digest TEXT NOT NULL CHECK (length(evidence_digest) = 71 AND substr(evidence_digest, 1, 7) = 'sha256:' AND substr(evidence_digest, 8) NOT GLOB '*[^0-9a-f]*'), original_verified_at TEXT NOT NULL CHECK (length(original_verified_at) > 0), reference_contract_version TEXT NOT NULL CHECK (reference_contract_version IN ('attestation-binding-reference-v1', 'attestation-binding-reference-v2')), binding_reference_digest TEXT NOT NULL CHECK (length(binding_reference_digest) = 71 AND substr(binding_reference_digest, 1, 7) = 'sha256:' AND substr(binding_reference_digest, 8) NOT GLOB '*[^0-9a-f]*'), credential_principal_identity TEXT, challenge_digest TEXT, canonical_json TEXT NOT NULL CHECK (length(canonical_json) > 0), CHECK ((reference_contract_version = 'attestation-binding-reference-v1' AND credential_principal_identity IS NULL AND challenge_digest IS NULL) OR (reference_contract_version = 'attestation-binding-reference-v2' AND credential_principal_identity IS NOT NULL AND challenge_digest IS NOT NULL)), PRIMARY KEY (workspace_identity, artifact_id), UNIQUE (workspace_identity, reference_id), UNIQUE (workspace_identity, binding_id), UNIQUE (workspace_identity, artifact_id, binding_reference_digest), FOREIGN KEY (workspace_identity, artifact_id) REFERENCES attestation_artifacts(workspace_identity, artifact_id) ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE TABLE attestation_revalidation_events (
    workspace_identity TEXT NOT NULL CHECK (length(workspace_identity) > 0), event_id TEXT NOT NULL CHECK (length(event_id) > 0), event_identity_version TEXT NOT NULL CHECK (event_identity_version = '1'), event_payload_version TEXT NOT NULL CHECK (event_payload_version = '1'), artifact_id TEXT NOT NULL CHECK (length(artifact_id) > 0), artifact_digest TEXT NOT NULL CHECK (length(artifact_digest) = 71 AND substr(artifact_digest, 1, 7) = 'sha256:' AND substr(artifact_digest, 8) NOT GLOB '*[^0-9a-f]*'), revalidation_attempt_id TEXT NOT NULL CHECK (length(revalidation_attempt_id) > 0), revalidation_context_digest TEXT NOT NULL CHECK (length(revalidation_context_digest) = 71 AND substr(revalidation_context_digest, 1, 7) = 'sha256:' AND substr(revalidation_context_digest, 8) NOT GLOB '*[^0-9a-f]*'), binding_reference_digest TEXT NOT NULL CHECK (length(binding_reference_digest) = 71 AND substr(binding_reference_digest, 1, 7) = 'sha256:' AND substr(binding_reference_digest, 8) NOT GLOB '*[^0-9a-f]*'), outcome TEXT NOT NULL CHECK (outcome IN ('Successful', 'Failed')), revalidated_at TEXT NOT NULL CHECK (length(revalidated_at) > 0), failure_code TEXT CHECK (failure_code IS NULL OR length(failure_code) > 0), result_digest TEXT CHECK (result_digest IS NULL OR (length(result_digest) = 71 AND substr(result_digest, 1, 7) = 'sha256:' AND substr(result_digest, 8) NOT GLOB '*[^0-9a-f]*')), event_payload_digest TEXT NOT NULL CHECK (length(event_payload_digest) = 71 AND substr(event_payload_digest, 1, 7) = 'sha256:' AND substr(event_payload_digest, 8) NOT GLOB '*[^0-9a-f]*'), event_sequence INTEGER NOT NULL CHECK (event_sequence > 0), canonical_json TEXT NOT NULL CHECK (length(canonical_json) > 0), PRIMARY KEY (workspace_identity, event_id), UNIQUE (workspace_identity, artifact_id, event_sequence), FOREIGN KEY (workspace_identity, artifact_id) REFERENCES attestation_artifacts(workspace_identity, artifact_id) ON DELETE RESTRICT ON UPDATE RESTRICT, FOREIGN KEY (workspace_identity, artifact_id, binding_reference_digest) REFERENCES attestation_binding_references(workspace_identity, artifact_id, binding_reference_digest) ON DELETE RESTRICT ON UPDATE RESTRICT, CHECK ((outcome = 'Successful' AND failure_code IS NULL AND result_digest IS NOT NULL) OR (outcome = 'Failed' AND failure_code IS NOT NULL AND result_digest IS NULL))
);
CREATE INDEX idx_attestation_artifacts_workspace_preview_revision ON attestation_artifacts(workspace_identity, claims_preview_id, claims_revision);
CREATE INDEX idx_attestation_artifacts_workspace_digest ON attestation_artifacts(workspace_identity, artifact_digest);
CREATE INDEX idx_attestation_references_workspace_binding ON attestation_binding_references(workspace_identity, binding_id);
CREATE INDEX idx_attestation_events_workspace_artifact_sequence ON attestation_revalidation_events(workspace_identity, artifact_id, event_sequence);
"""

_V4_LAYOUT = {
    "attestation_artifacts": [(name, "INTEGER" if name == "claims_revision" else "TEXT", 1, pk) for name, pk in (
        ("workspace_identity", 1), ("artifact_id", 2), ("artifact_contract_version", 0), ("attestation_id", 0), ("claims_payload_json", 0), ("detached_proof", 0), ("claims_digest", 0), ("artifact_digest", 0), ("original_verified_at", 0), ("created_at", 0), ("claims_attestation_version", 0), ("claims_issuer_id", 0), ("claims_key_id", 0), ("claims_signature_algorithm", 0), ("claims_credential_class", 0), ("claims_credential_instance_id", 0), ("claims_github_subject_identity", 0), ("claims_repository_identity", 0), ("claims_granted_capabilities_json", 0), ("claims_driver_identity", 0), ("claims_remote_authority", 0), ("claims_preview_id", 0), ("claims_revision", 0), ("claims_operation_set_digest", 0), ("claims_remote_snapshot_digest", 0), ("claims_evidence_digest", 0), ("claims_issued_at", 0), ("claims_expires_at", 0), ("claims_nonce", 0), ("claims_source_verification_digest", 0), ("claims_challenge_digest", 0), ("claims_credential_principal_identity", 0), ("canonical_json", 0))],
    "attestation_binding_references": [(name, "INTEGER" if name == "revision" else "TEXT", 1, pk) for name, pk in (
        ("workspace_identity", 1), ("reference_id", 0), ("artifact_id", 2), ("artifact_digest", 0), ("binding_id", 0), ("repository_identity", 0), ("github_subject_identity", 0), ("driver_identity", 0), ("remote_authority", 0), ("preview_id", 0), ("revision", 0), ("plan_digest", 0), ("sealed_preview_digest", 0), ("operation_set_digest", 0), ("remote_snapshot_digest", 0), ("audit_id", 0), ("audit_digest", 0), ("evidence_id", 0), ("evidence_digest", 0), ("original_verified_at", 0), ("reference_contract_version", 0), ("binding_reference_digest", 0), ("credential_principal_identity", 0), ("challenge_digest", 0), ("canonical_json", 0))],
    "attestation_revalidation_events": [(name, "INTEGER" if name == "event_sequence" else "TEXT", 0 if name in {"failure_code", "result_digest"} else 1, pk) for name, pk in (
        ("workspace_identity", 1), ("event_id", 2), ("event_identity_version", 0), ("event_payload_version", 0), ("artifact_id", 0), ("artifact_digest", 0), ("revalidation_attempt_id", 0), ("revalidation_context_digest", 0), ("binding_reference_digest", 0), ("outcome", 0), ("revalidated_at", 0), ("failure_code", 0), ("result_digest", 0), ("event_payload_digest", 0), ("event_sequence", 0), ("canonical_json", 0))],
}


def _v4_fingerprint(connection: sqlite3.Connection) -> bool:
    if _safe_sql(connection, "PRAGMA user_version")[0][0] != 0 or _safe_sql(connection, "PRAGMA application_id")[0][0] != 0:
        return False
    objects = _objects(connection)
    expected_objects = {("table", name) for name in _V4_TABLES} | {
        ("index", name) for name in {
            "idx_attestation_artifacts_workspace_preview_revision",
            "idx_attestation_artifacts_workspace_digest",
            "idx_attestation_references_workspace_binding",
            "idx_attestation_events_workspace_artifact_sequence",
        }
    }
    if {(kind, name) for kind, name, _table_name, _sql in objects} != expected_objects:
        return False
    for table in _V4_TABLES:
        actual = _table_xinfo(connection, table)
        expected = _V3_COLUMNS.get(table, _V4_LAYOUT.get(table, ()))
        if len(actual) != len(expected):
            return False
        for row, wanted in zip(actual, expected):
            if table in _V3_COLUMNS:
                match = (row[1], row[2].upper(), row[3], row[4], row[5]) == wanted
            else:
                expected_notnull = 0 if table == "attestation_artifacts" and wanted[0] in {"claims_challenge_digest", "claims_credential_principal_identity"} else wanted[2]
                expected_notnull = 0 if table == "attestation_binding_references" and wanted[0] in {"challenge_digest", "credential_principal_identity"} else expected_notnull
                match = (row[1], row[2].upper(), row[3], row[4], row[5]) == (wanted[0], wanted[1].upper(), expected_notnull, None, wanted[3])
            match = match and row[6] == 0
            if not match:
                return False
        if _check_expressions(_table_sql(objects, table)) != _check_expressions(
            _script_table_definition(_V4_DDL, table)
        ):
            return False
        explicit_names = {
            "attestation_artifacts": ("idx_attestation_artifacts_workspace_preview_revision", "idx_attestation_artifacts_workspace_digest"),
            "attestation_binding_references": ("idx_attestation_references_workspace_binding",),
            "attestation_revalidation_events": ("idx_attestation_events_workspace_artifact_sequence",),
        }.get(table, ())
        if not _check_index_semantics(connection, table, explicit_names):
            return False
    binding_fks = _foreign_key_signature(connection, "attestation_binding_references")
    event_fks = _foreign_key_signature(connection, "attestation_revalidation_events")
    expected_binding = (("attestation_artifacts", "RESTRICT", "RESTRICT", "NONE", (("workspace_identity", "workspace_identity"), ("artifact_id", "artifact_id"))),)
    expected_event = (
        ("attestation_artifacts", "RESTRICT", "RESTRICT", "NONE", (("workspace_identity", "workspace_identity"), ("artifact_id", "artifact_id"))),
        ("attestation_binding_references", "RESTRICT", "RESTRICT", "NONE", (("workspace_identity", "workspace_identity"), ("artifact_id", "artifact_id"), ("binding_reference_digest", "binding_reference_digest"))),
    )
    return binding_fks == expected_binding and event_fks == expected_event


def _legacy_v4_fingerprint(connection: sqlite3.Connection) -> bool:
    """Recognize the committed Version 4 layout before the V2 projection columns."""
    try:
        version = _safe_sql(connection, "SELECT schema_version FROM store_meta")
        if len(version) != 1 or version[0][0] != 4:
            return False
        objects = _objects(connection)
        expected_objects = {("table", name) for name in _V4_TABLES} | {
            ("index", name) for name in {
                "idx_attestation_artifacts_workspace_preview_revision",
                "idx_attestation_artifacts_workspace_digest",
                "idx_attestation_references_workspace_binding",
                "idx_attestation_events_workspace_artifact_sequence",
            }
        }
        if {(kind, name) for kind, name, _table, _sql in objects} != expected_objects:
            return False
        legacy_layout = {
            table: tuple(
                entry for entry in layout
                if entry[0] not in {
                    "claims_challenge_digest", "claims_credential_principal_identity",
                    "credential_principal_identity", "challenge_digest",
                }
            )
            for table, layout in _V4_LAYOUT.items()
        }
        for table in _V4_TABLES:
            actual = _table_xinfo(connection, table)
            expected = _V3_COLUMNS.get(table, legacy_layout.get(table, ()))
            if len(actual) != len(expected):
                return False
            for row, wanted in zip(actual, expected):
                if table in _V3_COLUMNS:
                    match = (row[1], row[2].upper(), row[3], row[4], row[5]) == wanted
                else:
                    match = (row[1], row[2].upper(), row[3], row[4], row[5]) == (
                        wanted[0], wanted[1].upper(), wanted[2], None, wanted[3]
                    )
                if not match or row[6] != 0:
                    return False
            explicit_names = {
                "attestation_artifacts": ("idx_attestation_artifacts_workspace_preview_revision", "idx_attestation_artifacts_workspace_digest"),
                "attestation_binding_references": ("idx_attestation_references_workspace_binding",),
                "attestation_revalidation_events": ("idx_attestation_events_workspace_artifact_sequence",),
            }.get(table, ())
            if not _check_index_semantics(connection, table, explicit_names):
                return False
        binding_fks = _foreign_key_signature(connection, "attestation_binding_references")
        event_fks = _foreign_key_signature(connection, "attestation_revalidation_events")
        expected_binding = (("attestation_artifacts", "RESTRICT", "RESTRICT", "NONE", (("workspace_identity", "workspace_identity"), ("artifact_id", "artifact_id"))),)
        expected_event = (
            ("attestation_artifacts", "RESTRICT", "RESTRICT", "NONE", (("workspace_identity", "workspace_identity"), ("artifact_id", "artifact_id"))),
            ("attestation_binding_references", "RESTRICT", "RESTRICT", "NONE", (("workspace_identity", "workspace_identity"), ("artifact_id", "artifact_id"), ("binding_reference_digest", "binding_reference_digest"))),
        )
        return binding_fks == expected_binding and event_fks == expected_event
    except (IndexError, sqlite3.Error):
        return False


def _migrate_legacy_v4_projection(connection: sqlite3.Connection) -> None:
    """Rebuild the two V4 projection tables against the canonical V5 DDL."""
    indexes = (
        "idx_attestation_artifacts_workspace_preview_revision",
        "idx_attestation_artifacts_workspace_digest",
        "idx_attestation_references_workspace_binding",
        "idx_attestation_events_workspace_artifact_sequence",
    )
    for index in indexes:
        connection.execute(f"DROP INDEX {index}")
    connection.execute("ALTER TABLE attestation_artifacts RENAME TO attestation_artifacts_v4")
    connection.execute("ALTER TABLE attestation_binding_references RENAME TO attestation_binding_references_v4")
    connection.execute("ALTER TABLE attestation_revalidation_events RENAME TO attestation_revalidation_events_v4")
    _execute_script(connection, _V4_DDL)
    artifact_columns = _V4_LAYOUT["attestation_artifacts"]
    reference_columns = _V4_LAYOUT["attestation_binding_references"]
    connection.execute(
        "INSERT INTO attestation_artifacts SELECT "
        + ",".join(name for name, _type, _notnull, _pk in artifact_columns if name not in {"claims_challenge_digest", "claims_credential_principal_identity", "canonical_json"})
        + ", NULL, NULL, canonical_json FROM attestation_artifacts_v4"
    )
    connection.execute(
        "INSERT INTO attestation_binding_references SELECT "
        + ",".join(name for name, _type, _notnull, _pk in reference_columns if name not in {"credential_principal_identity", "challenge_digest", "canonical_json"})
        + ", NULL, NULL, canonical_json FROM attestation_binding_references_v4"
    )
    connection.execute("INSERT INTO attestation_revalidation_events SELECT * FROM attestation_revalidation_events_v4")
    connection.execute("DROP TABLE attestation_revalidation_events_v4")
    connection.execute("DROP TABLE attestation_binding_references_v4")
    connection.execute("DROP TABLE attestation_artifacts_v4")


def _metadata(connection: sqlite3.Connection) -> tuple[int, str]:
    rows = _safe_sql(connection, "SELECT schema_version, workspace_identity FROM store_meta")
    if len(rows) != 1 or type(rows[0][0]) is not int or type(rows[0][1]) is not str:
        raise SchemaOwnerError("attestation_persistence_schema_metadata_corrupt")
    version, workspace = rows[0]
    if version < 0:
        raise SchemaOwnerError("attestation_persistence_schema_metadata_corrupt")
    return version, _workspace(workspace)


def _classify_empty(connection: sqlite3.Connection) -> bool:
    count_rows = _safe_sql(connection, "SELECT COUNT(*) FROM sqlite_master")
    user_version = _safe_sql(connection, "PRAGMA user_version")[0][0]
    application_id = _safe_sql(connection, "PRAGMA application_id")[0][0]
    if type(count_rows[0][0]) is not int or type(user_version) is not int or type(application_id) is not int:
        raise SchemaOwnerError("attestation_persistence_schema_metadata_corrupt")
    return count_rows[0][0] == 0 and user_version == 0 and application_id == 0


def _create_v3(connection: sqlite3.Connection, workspace: str) -> None:
    _execute_script(connection,
        """
        CREATE TABLE store_meta (schema_version INTEGER NOT NULL, workspace_identity TEXT NOT NULL);
        CREATE TABLE item_lineage (workspace_identity TEXT NOT NULL, preview_id TEXT NOT NULL, revision INTEGER NOT NULL, client_ref TEXT NOT NULL, item_id TEXT NOT NULL, tombstone INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (workspace_identity, preview_id, revision, client_ref));
        CREATE TABLE records (workspace_identity TEXT NOT NULL, record_type TEXT NOT NULL, record_id TEXT NOT NULL, revision INTEGER, payload TEXT NOT NULL, PRIMARY KEY (workspace_identity, record_type, record_id, revision));
        CREATE TABLE audit_history (workspace_identity TEXT NOT NULL, audit_id TEXT NOT NULL, event_no INTEGER NOT NULL, payload TEXT NOT NULL, reason TEXT NOT NULL, occurred_at TEXT NOT NULL, PRIMARY KEY (workspace_identity, audit_id, event_no));
        """
    )
    connection.execute("INSERT INTO store_meta(schema_version, workspace_identity) VALUES (3, ?)", (workspace,))


def _scan_v3_workspace(connection: sqlite3.Connection, expected: str) -> None:
    rows = _safe_sql(connection, "SELECT workspace_identity FROM store_meta")
    if len(rows) != 1:
        raise SchemaOwnerError("attestation_persistence_schema_metadata_corrupt")
    for table in ("store_meta", "item_lineage", "records", "audit_history"):
        values = _safe_sql(connection, f"SELECT workspace_identity, typeof(workspace_identity) FROM {table}")
        for value, kind in values:
            if kind != "text" or type(value) is not str or _workspace(value) != value or value != expected:
                raise SchemaOwnerError("attestation_persistence_workspace_mismatch")


def ensure_schema_v4(connection: sqlite3.Connection, *, expected_workspace_identity: str) -> None:
    """Classify, validate, and atomically prepare the Version 5 schema."""
    expected = _workspace(expected_workspace_identity)
    try:
        connection.execute("BEGIN IMMEDIATE")
        if _safe_sql(connection, "PRAGMA user_version")[0][0] != 0 or _safe_sql(connection, "PRAGMA application_id")[0][0] != 0:
            raise SchemaOwnerError("attestation_persistence_schema_shape_mismatch")
        if _classify_empty(connection):
            _create_v3(connection, expected)
            _execute_script(connection, _V4_DDL)
            connection.execute("UPDATE store_meta SET schema_version = 5")
            if not _v4_fingerprint(connection):
                raise SchemaOwnerError("attestation_persistence_schema_shape_mismatch")
            connection.commit()
            return
        objects = _objects(connection)
        if {(kind, name) for kind, name, _table, _sql in objects} == {("table", "store_meta")}:
            _metadata(connection)
        if not any(name == "store_meta" for _, name, _, _ in objects):
            raise SchemaOwnerError("attestation_persistence_schema_shape_mismatch")
        if _v3_fingerprint(connection):
            version, _ = _metadata(connection)
            if version > 5:
                raise SchemaOwnerError("attestation_persistence_schema_version_unsupported")
            if version != 3:
                raise SchemaOwnerError("attestation_persistence_schema_metadata_corrupt")
            _scan_v3_workspace(connection, expected)
            _execute_script(connection, _V4_DDL)
            if not _v4_fingerprint(connection):
                raise SchemaOwnerError("attestation_persistence_migration_failed")
            connection.execute("UPDATE store_meta SET schema_version = 5")
            connection.commit()
            return
        if _legacy_v4_fingerprint(connection):
            version, workspace = _metadata(connection)
            if workspace != expected:
                raise SchemaOwnerError("attestation_persistence_workspace_mismatch")
            _migrate_legacy_v4_projection(connection)
            if not _v4_fingerprint(connection):
                raise SchemaOwnerError("attestation_persistence_migration_failed")
            connection.execute("UPDATE store_meta SET schema_version = 5")
            connection.commit()
            return
        if _v4_fingerprint(connection):
            version, workspace = _metadata(connection)
            if version > 5:
                raise SchemaOwnerError("attestation_persistence_schema_version_unsupported")
            if version not in {4, 5}:
                raise SchemaOwnerError("attestation_persistence_schema_metadata_corrupt")
            if workspace != expected:
                raise SchemaOwnerError("attestation_persistence_workspace_mismatch")
            if version == 4:
                connection.execute("UPDATE store_meta SET schema_version = 5")
            connection.commit()
            return
        if any(name == "store_meta" for _, name, _, _ in objects):
            _metadata(connection)
        raise SchemaOwnerError("attestation_persistence_schema_shape_mismatch")
    except SchemaOwnerError:
        try:
            connection.rollback()
        except sqlite3.Error:
            pass
        raise
    except sqlite3.OperationalError as exc:
        try:
            connection.rollback()
        except sqlite3.Error:
            pass
        if _is_busy(exc):
            raise SchemaOwnerError("attestation_persistence_sqlite_busy") from exc
        raise SchemaOwnerError("attestation_persistence_sqlite_operational") from exc
    except sqlite3.Error as exc:
        try:
            connection.rollback()
        except sqlite3.Error:
            pass
        raise SchemaOwnerError("attestation_persistence_sqlite_operational") from exc
