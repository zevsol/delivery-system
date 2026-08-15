from __future__ import annotations

import sqlite3
from contextlib import closing
import multiprocessing as mp
from pathlib import Path
import re
import tempfile
import threading
import unittest
from unittest.mock import patch

from delivery_system import sqlite_schema
from delivery_system.attestation_persistence_store import (
    SQLiteAttestationPersistenceStore,
    StoreContractError,
)
from tests.fakes.attestation_persistence_store_contract import (
    artifact_for,
    event_for,
    reference_for,
)


class _ConnectionProxy:
    def __init__(self, connection: sqlite3.Connection, *, execute_failure=None, commit_failure=None, rollback_failure=None, close_failure=None) -> None:
        self.connection = connection
        self.execute_failure = execute_failure
        self.commit_failure = commit_failure
        self.rollback_failure = rollback_failure
        self.close_failure = close_failure
        self.execute_count = 0

    def execute(self, sql, *args):
        self.execute_count += 1
        if self.execute_failure is not None:
            failure = self.execute_failure(sql, self.execute_count)
            if failure is not None:
                raise failure
        return self.connection.execute(sql, *args)

    def commit(self):
        if self.commit_failure is not None:
            raise self.commit_failure
        return self.connection.commit()

    def rollback(self):
        if self.rollback_failure is not None:
            raise self.rollback_failure
        return self.connection.rollback()

    def close(self):
        if self.close_failure is not None:
            raise self.close_failure
        return self.connection.close()

    def __getattr__(self, name):
        return getattr(self.connection, name)


def _create_v3(path: Path, workspace: str = "workspace-1") -> None:
    with closing(sqlite3.connect(path)) as connection:
        connection.executescript(
            """
            CREATE TABLE store_meta (schema_version INTEGER NOT NULL, workspace_identity TEXT NOT NULL);
            CREATE TABLE item_lineage (workspace_identity TEXT NOT NULL, preview_id TEXT NOT NULL, revision INTEGER NOT NULL, client_ref TEXT NOT NULL, item_id TEXT NOT NULL, tombstone INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (workspace_identity, preview_id, revision, client_ref));
            CREATE TABLE records (workspace_identity TEXT NOT NULL, record_type TEXT NOT NULL, record_id TEXT NOT NULL, revision INTEGER, payload TEXT NOT NULL, PRIMARY KEY (workspace_identity, record_type, record_id, revision));
            CREATE TABLE audit_history (workspace_identity TEXT NOT NULL, audit_id TEXT NOT NULL, event_no INTEGER NOT NULL, payload TEXT NOT NULL, reason TEXT NOT NULL, occurred_at TEXT NOT NULL, PRIMARY KEY (workspace_identity, audit_id, event_no));
            """
        )
        connection.execute("INSERT INTO store_meta VALUES (3, ?)", (workspace,))
        connection.commit()


def _create_v3_quoted(
    path: Path,
    *,
    default: str = "0",
    keyword_case: str = "upper",
    quote_tables: bool = True,
    quote_columns: bool = True,
) -> None:
    integer = "INTEGER" if keyword_case == "upper" else "integer"
    text = "TEXT" if keyword_case == "upper" else "text"
    not_null = "NOT NULL" if keyword_case == "upper" else "not null"
    table = lambda value: f'"{value}"' if quote_tables else value
    column = lambda value: f'"{value}"' if quote_columns else value
    with closing(sqlite3.connect(path)) as connection:
        connection.executescript(
            f'''
            CREATE TABLE {table("store_meta")} ({column("schema_version")} {integer} {not_null}, {column("workspace_identity")} {text} {not_null});
            CREATE TABLE {table("item_lineage")} ({column("workspace_identity")} {text} {not_null}, {column("preview_id")} {text} {not_null}, {column("revision")} {integer} {not_null}, {column("client_ref")} {text} {not_null}, {column("item_id")} {text} {not_null}, {column("tombstone")} {integer} {not_null} DEFAULT {default}, PRIMARY KEY ({column("workspace_identity")}, {column("preview_id")}, {column("revision")}, {column("client_ref")}));
            CREATE TABLE {table("records")} ({column("workspace_identity")} {text} {not_null}, {column("record_type")} {text} {not_null}, {column("record_id")} {text} {not_null}, {column("revision")} {integer}, {column("payload")} {text} {not_null}, PRIMARY KEY ({column("workspace_identity")}, {column("record_type")}, {column("record_id")}, {column("revision")}));
            CREATE TABLE {table("audit_history")} ({column("workspace_identity")} {text} {not_null}, {column("audit_id")} {text} {not_null}, {column("event_no")} {integer} {not_null}, {column("payload")} {text} {not_null}, {column("reason")} {text} {not_null}, {column("occurred_at")} {text} {not_null}, PRIMARY KEY ({column("workspace_identity")}, {column("audit_id")}, {column("event_no")}));
            INSERT INTO {table("store_meta")} VALUES (3, 'workspace-1');
            '''
        )
        connection.commit()


def _create_v4_variant(path: Path, transform=None) -> None:
    _create_v3_quoted(path)
    ddl = sqlite_schema._V4_DDL
    if transform is not None:
        ddl = transform(ddl)
    with closing(sqlite3.connect(path)) as connection:
        connection.executescript(ddl)
        connection.execute('UPDATE "store_meta" SET "schema_version" = 4')
        connection.commit()


def _quote_v4_identifiers(ddl: str) -> str:
    names = set(sqlite_schema._V4_TABLES)
    names.update(
        (
            "idx_attestation_artifacts_workspace_preview_revision",
            "idx_attestation_artifacts_workspace_digest",
            "idx_attestation_references_workspace_binding",
            "idx_attestation_events_workspace_artifact_sequence",
        )
    )
    for table in sqlite_schema._V4_TABLES[4:]:
        names.update(row[0] for row in sqlite_schema._V4_LAYOUT[table])
    for name in sorted(names, key=len, reverse=True):
        ddl = re.sub(rf"(?<![\w\"]){re.escape(name)}(?![\w\"])", f'"{name}"', ddl)
    return ddl


def _spawn_append_worker(path: str, attempt_suffix: str, barrier, queue) -> None:
    artifact = artifact_for()
    reference = reference_for(artifact)
    store = SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
    try:
        store.persist_artifact(artifact, reference)
        barrier.wait(timeout=10)
        event = event_for(artifact, reference, attempt_id="attempt-" + attempt_suffix * 32)
        queue.put(store.append_revalidation_event(event).event_sequence)
    finally:
        store.close()


class SQLiteAttestationPersistenceStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "state.sqlite3"
        self.store = SQLiteAttestationPersistenceStore(self.path, workspace_identity="workspace-1")
        self.artifact = artifact_for()
        self.reference = reference_for(self.artifact)

    def tearDown(self) -> None:
        try:
            self.store.close()
        finally:
            self.directory.cleanup()

    def test_fresh_v4_and_reopen(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT schema_version, workspace_identity FROM store_meta").fetchone(), (4, "workspace-1"))
        aggregate = self.store.persist_artifact(self.artifact, self.reference)
        self.assertEqual(aggregate.artifact.artifact_id, self.artifact.artifact_id)
        self.store.close()
        reopened = SQLiteAttestationPersistenceStore(self.path, workspace_identity="workspace-1")
        try:
            self.assertEqual(
                reopened.get_artifact_aggregate("workspace-1", self.artifact.artifact_id),
                aggregate,
            )
        finally:
            reopened.close()

    def test_aggregate_and_event_round_trip_replay_and_sequence(self) -> None:
        self.store.persist_artifact(self.artifact, self.reference)
        event = event_for(self.artifact, self.reference)
        first = self.store.append_revalidation_event(event)
        replay = self.store.append_revalidation_event(event)
        self.assertEqual(first.event_sequence, 1)
        self.assertEqual(replay.event_sequence, 1)
        self.assertEqual(
            self.store.get_latest_revalidation_event("workspace-1", self.artifact.artifact_id),
            first,
        )

    def test_workspace_is_bound_to_concrete_instance(self) -> None:
        with self.assertRaises(StoreContractError) as raised:
            SQLiteAttestationPersistenceStore(self.path, workspace_identity="workspace-2")
        self.assertEqual(raised.exception.code, "attestation_persistence_workspace_mismatch")
        with self.assertRaises(StoreContractError) as raised:
            self.store.get_artifact_aggregate("workspace-2", self.artifact.artifact_id)
        self.assertEqual(raised.exception.code, "attestation_persistence_workspace_mismatch")

    def test_close_is_idempotent_and_rejects_operations(self) -> None:
        self.store.close()
        self.store.close()
        with self.assertRaises(StoreContractError) as raised:
            self.store.persist_artifact(self.artifact, self.reference)
        self.assertEqual(raised.exception.code, "attestation_persistence_store_unavailable")

    def test_event_conflict_and_partition_sequence(self) -> None:
        self.store.persist_artifact(self.artifact, self.reference)
        event = event_for(self.artifact, self.reference)
        self.store.append_revalidation_event(event)
        changed = event_for(self.artifact, self.reference, revalidated_at="2026-08-14T12:01:00Z")
        with self.assertRaises(StoreContractError) as raised:
            self.store.append_revalidation_event(changed)
        self.assertEqual(raised.exception.code, "attestation_revalidation_event_conflict")
        other = artifact_for(workspace="workspace-2")
        other_reference = reference_for(other)
        other_store = SQLiteAttestationPersistenceStore(self.path.with_name("other.sqlite3"), workspace_identity="workspace-2")
        try:
            other_store.persist_artifact(other, other_reference)
            self.assertEqual(other_store.append_revalidation_event(event_for(other, other_reference)).event_sequence, 1)
        finally:
            other_store.close()

    def test_future_schema_version_fails_closed(self) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("UPDATE store_meta SET schema_version = 99")
            connection.commit()
        with self.assertRaises(StoreContractError) as raised:
            SQLiteAttestationPersistenceStore(self.path, workspace_identity="workspace-1")
        self.assertEqual(raised.exception.code, "attestation_persistence_schema_version_unsupported")

    def test_canonical_row_mutation_is_rejected(self) -> None:
        self.store.persist_artifact(self.artifact, self.reference)
        self.store.close()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                "UPDATE attestation_artifacts SET canonical_json = '{}' WHERE artifact_id = ?",
                (self.artifact.artifact_id,),
            )
            connection.commit()
        reopened = SQLiteAttestationPersistenceStore(self.path, workspace_identity="workspace-1")
        self.store = reopened
        with self.assertRaises(StoreContractError) as raised:
            reopened.get_artifact_aggregate("workspace-1", self.artifact.artifact_id)
        self.assertEqual(raised.exception.code, "attestation_artifact_aggregate_corrupt")

    def test_v3_fixture_migrates_without_attestation_history(self) -> None:
        self.store.close()
        connection = sqlite3.connect(self.path)
        connection.execute("BEGIN")
        connection.execute("DROP TABLE attestation_revalidation_events")
        connection.execute("DROP TABLE attestation_binding_references")
        connection.execute("DROP TABLE attestation_artifacts")
        connection.execute("DELETE FROM store_meta")
        connection.execute("INSERT INTO store_meta(schema_version, workspace_identity) VALUES (3, 'workspace-1')")
        connection.commit()
        connection.close()
        migrated = SQLiteAttestationPersistenceStore(self.path, workspace_identity="workspace-1")
        try:
            self.assertIsNone(migrated.get_latest_revalidation_event("workspace-1", "artifact-" + "a" * 64))
        except StoreContractError as raised:
            self.assertEqual(raised.code, "attestation_artifact_not_found")
        finally:
            migrated.close()

    def _assert_reopen_code(self, mutate, code: str) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.path)) as connection:
            mutate(connection)
            connection.commit()
        with self.assertRaises(StoreContractError) as raised:
            SQLiteAttestationPersistenceStore(self.path, workspace_identity="workspace-1")
        self.assertEqual(raised.exception.code, code)

    def _reset_fixture(self) -> None:
        try:
            self.store.close()
        except StoreContractError:
            pass
        self.directory.cleanup()
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "state.sqlite3"
        self.store = SQLiteAttestationPersistenceStore(self.path, workspace_identity="workspace-1")
        self.artifact = artifact_for()
        self.reference = reference_for(self.artifact)

    def test_v4_fingerprint_rejects_every_table_shape_mutation(self) -> None:
        for table in (
            "store_meta", "item_lineage", "records", "audit_history",
            "attestation_artifacts", "attestation_binding_references",
            "attestation_revalidation_events",
        ):
            with self.subTest(table=table):
                self._assert_reopen_code(
                    lambda connection, table=table: connection.execute(
                        f"ALTER TABLE {table} ADD COLUMN injected TEXT"
                    ),
                    "attestation_persistence_schema_shape_mismatch",
                )
                self._reset_fixture()

    def test_v4_fingerprint_rejects_objects_and_missing_index(self) -> None:
        for sql in (
            "CREATE TABLE injected_table (value TEXT)",
            "CREATE INDEX injected_index ON records(record_id)",
            "CREATE TRIGGER injected_trigger AFTER INSERT ON records BEGIN SELECT 1; END",
            "CREATE VIEW injected_view AS SELECT 1 AS value",
            "DROP INDEX idx_attestation_artifacts_workspace_digest",
            "DROP TABLE attestation_revalidation_events",
        ):
            with self.subTest(sql=sql):
                self._assert_reopen_code(
                    lambda connection, sql=sql: connection.execute(sql),
                    "attestation_persistence_schema_shape_mismatch",
                )
                self._reset_fixture()

    def test_v4_metadata_cardinality_and_pragma_refusal(self) -> None:
        self._assert_reopen_code(
            lambda connection: connection.execute(
                "INSERT INTO store_meta(schema_version, workspace_identity) VALUES (4, 'workspace-1')"
            ),
            "attestation_persistence_schema_metadata_corrupt",
        )
        self._reset_fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pragma.sqlite3"
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("PRAGMA user_version = 7")
                connection.commit()
            with self.assertRaises(StoreContractError) as raised:
                SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            self.assertEqual(raised.exception.code, "attestation_persistence_schema_shape_mismatch")

    def test_v3_workspace_scan_rejects_non_text_and_noncanonical_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "v3.sqlite3"
            _create_v3(path)
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("INSERT INTO records VALUES (1, 'Record', 'id', 1, 'payload')")
                connection.commit()
            with self.assertRaises(StoreContractError) as raised:
                SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            self.assertEqual(raised.exception.code, "attestation_persistence_workspace_mismatch")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "v3.sqlite3"
            _create_v3(path)
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("INSERT INTO records VALUES (' workspace-1 ', 'Record', 'id', 1, 'payload')")
                connection.commit()
            with self.assertRaises(StoreContractError) as raised:
                SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            self.assertEqual(raised.exception.code, "attestation_persistence_workspace_mismatch")

    def test_quoted_table_v3_is_accepted_and_migrated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "quoted-table.sqlite3"
            _create_v3_quoted(path, quote_tables=True, quote_columns=False)
            store = SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            store.close()
            with closing(sqlite3.connect(path)) as connection:
                self.assertEqual(connection.execute("SELECT schema_version FROM store_meta").fetchone()[0], 4)

    def test_quoted_column_v3_is_accepted_and_migrated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "quoted-column.sqlite3"
            _create_v3_quoted(path, quote_tables=False, quote_columns=True)
            store = SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            store.close()
            with closing(sqlite3.connect(path)) as connection:
                self.assertEqual(connection.execute("SELECT schema_version FROM store_meta").fetchone()[0], 4)

    def test_v3_whitespace_and_keyword_case_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "format.sqlite3"
            _create_v3_quoted(path, quote_tables=True, quote_columns=True, keyword_case="lower")
            store = SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            store.close()

    def test_quoted_v3_migration_preserves_data_and_has_no_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "quoted-data.sqlite3"
            _create_v3_quoted(path)
            with closing(sqlite3.connect(path)) as connection:
                connection.execute('INSERT INTO "records" VALUES (?, ?, ?, ?, ?)', ("workspace-1", "Preview", "record-1", 1, "payload"))
                connection.commit()
            store = SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            store.close()
            with closing(sqlite3.connect(path)) as connection:
                self.assertEqual(connection.execute("SELECT payload FROM records").fetchone()[0], "payload")
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM attestation_artifacts").fetchone()[0], 0)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM attestation_revalidation_events").fetchone()[0], 0)

    def test_quoted_v4_reopen_and_quoted_indexes_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "quoted-v4.sqlite3"
            _create_v4_variant(path, _quote_v4_identifiers)
            store = SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            store.close()

    def test_v4_line_comment_before_check_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "line-before.sqlite3"
            _create_v4_variant(path, lambda ddl: ddl.replace("CHECK (", "/* before CHECK */ CHECK (", 1))
            SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1").close()

    def test_v4_line_comment_between_check_and_parenthesis_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "line-between.sqlite3"
            _create_v4_variant(path, lambda ddl: ddl.replace("CHECK (", "CHECK /* between */ (", 1))
            SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1").close()

    def test_v4_block_comment_inside_expression_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "block-inside.sqlite3"
            _create_v4_variant(path, lambda ddl: ddl.replace("length(workspace_identity)", "length(/* inside */ workspace_identity)", 1))
            SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1").close()

    def test_v4_comments_containing_sql_syntax_are_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "comment-syntax.sqlite3"
            transform = lambda ddl: ddl.replace(
                "CHECK (length(workspace_identity) > 0)",
                "/* CHECK(') -- )') */ CHECK (length(workspace_identity) > 0)",
                1,
            )
            _create_v4_variant(path, transform)
            SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1").close()

    def test_v4_comment_only_formatting_is_accepted_on_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "comment-reopen.sqlite3"
            _create_v4_variant(path, lambda ddl: ddl.replace("CHECK (", "CHECK /* formatting */ (", 1))
            first = SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            first.close()
            second = SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            second.close()

    def test_check_string_boundaries_are_preserved(self) -> None:
        expressions = sqlite_schema._check_expressions(
            "CREATE TABLE t (value TEXT CHECK (value = 'CHECK ( -- /* */ )'), other TEXT CHECK (other = ''))"
        )
        self.assertEqual(len(expressions), 2)
        self.assertNotEqual(
            expressions,
            sqlite_schema._check_expressions("CREATE TABLE t (value TEXT CHECK (value = 'different'))"),
        )

    def test_check_escaped_string_and_parenthesis_boundaries_are_preserved(self) -> None:
        expressions = sqlite_schema._check_expressions(
            "CREATE TABLE t (value TEXT CHECK (value = 'it''s ) -- /* keyword */'))"
        )
        self.assertEqual(len(expressions), 1)
        self.assertIn("STRING:it's ) -- /* keyword */", expressions[0])

    def test_check_quoted_identifier_boundaries_are_preserved(self) -> None:
        expressions = sqlite_schema._check_expressions(
            'CREATE TABLE t ("a""b" TEXT CHECK ("a""b" > 0), [other] TEXT CHECK (`other` > 0))'
        )
        self.assertEqual(len(expressions), 2)
        self.assertIn("IDENT:a\"b", expressions[0])

    def test_check_keyword_and_identifier_boundaries_are_distinct(self) -> None:
        self.assertEqual(sqlite_schema._check_expressions("CREATE TABLE t (CHECKSUM (1))"), ())
        self.assertEqual(sqlite_schema._check_expressions('CREATE TABLE t ("CHECK" (1))'), ())

    def test_block_comment_does_not_concatenate_check_keyword(self) -> None:
        tokens = sqlite_schema._lex_ddl("C/*comment*/HECK")
        self.assertEqual(
            [(token.kind, token.value) for token in tokens],
            [("IDENT", "c"), ("IDENT", "heck")],
        )
        self.assertNotIn(sqlite_schema._DDLToken("KEYWORD", "check"), tokens)
        self.assertEqual(
            sqlite_schema._check_expressions("CREATE TABLE t (C/*comment*/HECK (a))"),
            (),
        )

    def test_block_comment_does_not_concatenate_operator(self) -> None:
        tokens = sqlite_schema._lex_ddl(">/*comment*/=")
        self.assertEqual(
            [(token.kind, token.value) for token in tokens],
            [("OPERATOR", ">"), ("OPERATOR", "=")],
        )
        self.assertNotEqual(tuple(token.value for token in tokens), (">=",))
        self.assertEqual(
            [(token.kind, token.value) for token in sqlite_schema._lex_ddl(">=")],
            [("OPERATOR", ">=")],
        )

    def test_block_comment_does_not_concatenate_identifier(self) -> None:
        tokens = sqlite_schema._lex_ddl("identi/*comment*/fier")
        self.assertEqual(
            [(token.kind, token.value) for token in tokens],
            [("IDENT", "identi"), ("IDENT", "fier")],
        )
        self.assertNotEqual(
            [(token.kind, token.value) for token in tokens],
            [("IDENT", "identifier")],
        )

    def test_check_nested_parentheses_and_multiple_constraints_are_ordered(self) -> None:
        expressions = sqlite_schema._check_expressions(
            "CREATE TABLE t (a TEXT CHECK ((length(a) > 0 AND (a != ''))), b TEXT CHECK (b != 'x'))"
        )
        self.assertEqual(len(expressions), 2)
        self.assertNotEqual(expressions[0], expressions[1])

    def test_check_operator_and_numeric_drift_is_not_equivalent(self) -> None:
        base = sqlite_schema._check_expressions("CREATE TABLE t (a TEXT CHECK (length(a) >= 1))")
        self.assertNotEqual(base, sqlite_schema._check_expressions("CREATE TABLE t (a TEXT CHECK (length(a) > 1))"))
        self.assertNotEqual(base, sqlite_schema._check_expressions("CREATE TABLE t (a TEXT CHECK (length(a) >= 0))"))
        self.assertNotEqual(
            sqlite_schema._check_expressions("CREATE TABLE t (a TEXT CHECK (a > 0 AND a < 2))"),
            sqlite_schema._check_expressions("CREATE TABLE t (a TEXT CHECK (a > 0 OR a < 2))"),
        )

    def test_malformed_check_lexing_fails_closed(self) -> None:
        malformed = (
            "CREATE TABLE t (a TEXT CHECK (a = 'unterminated)",
            'CREATE TABLE t ("unterminated TEXT CHECK (a > 0))',
            "CREATE TABLE t (a TEXT CHECK (a > 0) /* unterminated",
            "CREATE TABLE t (a TEXT CHECK ((a > 0)",
            "CREATE TABLE t (a TEXT CHECK (a $ 1))",
        )
        for sql in malformed:
            with self.subTest(sql=sql):
                with self.assertRaisesRegex(sqlite_schema.SchemaOwnerError, "attestation_persistence_schema_shape_mismatch"):
                    sqlite_schema._check_expressions(sql)

    def test_v4_changed_string_literal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "string-drift.sqlite3"
            _create_v4_variant(path, lambda ddl: ddl.replace("'Successful'", "'Different'", 1))
            with self.assertRaisesRegex(StoreContractError, "attestation_persistence_schema_shape_mismatch"):
                SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")

    def test_missing_check_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing-check.sqlite3"
            _create_v4_variant(path, lambda ddl: ddl.replace("CHECK (length(workspace_identity) > 0)", "", 1))
            with self.assertRaises(StoreContractError) as raised:
                SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            self.assertEqual(raised.exception.code, "attestation_persistence_schema_shape_mismatch")
            self.assertNotIn("CHECK", str(raised.exception))

    def test_changed_check_semantics_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "changed-check.sqlite3"
            _create_v4_variant(path, lambda ddl: ddl.replace("length(workspace_identity) > 0", "length(workspace_identity) >= 0", 1))
            with self.assertRaises(StoreContractError) as raised:
                SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            self.assertEqual(raised.exception.code, "attestation_persistence_schema_shape_mismatch")

    def test_missing_unique_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing-unique.sqlite3"
            _create_v4_variant(path, lambda ddl: ddl.replace(", UNIQUE (workspace_identity, attestation_id)", "", 1))
            with self.assertRaises(StoreContractError) as raised:
                SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            self.assertEqual(raised.exception.code, "attestation_persistence_schema_shape_mismatch")

    def test_changed_default_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "changed-default.sqlite3"
            _create_v3_quoted(path, default="1")
            with self.assertRaises(StoreContractError) as raised:
                SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            self.assertEqual(raised.exception.code, "attestation_persistence_schema_shape_mismatch")

    def test_changed_fk_action_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "changed-fk.sqlite3"
            _create_v4_variant(path, lambda ddl: ddl.replace("ON DELETE RESTRICT", "ON DELETE CASCADE", 1))
            with self.assertRaises(StoreContractError) as raised:
                SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            self.assertEqual(raised.exception.code, "attestation_persistence_schema_shape_mismatch")

    def test_changed_index_semantics_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "changed-index.sqlite3"
            _create_v4_variant(path, lambda ddl: ddl.replace("ON attestation_artifacts(workspace_identity, artifact_digest)", "ON attestation_artifacts(workspace_identity, claims_digest)", 1))
            with self.assertRaises(StoreContractError) as raised:
                SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            self.assertEqual(raised.exception.code, "attestation_persistence_schema_shape_mismatch")

    def test_extra_user_index_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "extra-index.sqlite3"
            _create_v4_variant(path)
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("CREATE INDEX injected_index ON records(record_id)")
                connection.commit()
            with self.assertRaises(StoreContractError) as raised:
                SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            self.assertEqual(raised.exception.code, "attestation_persistence_schema_shape_mismatch")

    def test_migration_failure_preserves_v3_and_maps_stably(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "v3.sqlite3"
            _create_v3(path)
            original = sqlite_schema._execute_script

            def fail(connection, script):
                original(connection, script.split("CREATE TABLE attestation_binding_references", 1)[0])
                raise sqlite_schema.SchemaOwnerError("attestation_persistence_migration_failed")

            with patch.object(sqlite_schema, "_execute_script", fail):
                with self.assertRaises(StoreContractError) as raised:
                    SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            self.assertEqual(raised.exception.code, "attestation_persistence_migration_failed")
            self.assertNotIn("secret-path", str(raised.exception))
            with closing(sqlite3.connect(path)) as connection:
                self.assertEqual(connection.execute("SELECT schema_version FROM store_meta").fetchone()[0], 3)
                self.assertEqual(connection.execute("SELECT name FROM sqlite_master WHERE name='attestation_artifacts'").fetchone(), None)

    def test_schema_owner_error_categories_are_preserved_and_sanitized(self) -> None:
        self.store.close()
        categories = (
            "attestation_persistence_schema_shape_mismatch",
            "attestation_persistence_schema_version_unsupported",
            "attestation_persistence_migration_failed",
            "attestation_persistence_workspace_mismatch",
            "attestation_persistence_sqlite_busy",
            "attestation_persistence_sqlite_operational",
            "attestation_persistence_schema_owner_failed",
        )
        for category in categories:
            with self.subTest(category=category):
                with patch.object(sqlite_schema, "ensure_schema_v4", side_effect=sqlite_schema.SchemaOwnerError(category)):
                    with self.assertRaises(StoreContractError) as raised:
                        SQLiteAttestationPersistenceStore(self.path, workspace_identity="workspace-1")
                self.assertEqual(raised.exception.code, category)
                self.assertNotIn("secret", str(raised.exception).lower())

    def test_read_artifact_select_failure_rolls_back_and_sanitizes(self) -> None:
        self.store.persist_artifact(self.artifact, self.reference)
        raw = self.store._connection
        self.store._connection = _ConnectionProxy(
            raw,
            execute_failure=lambda sql, count: sqlite3.OperationalError("raw artifact select / secret-path") if "FROM attestation_artifacts" in sql else None,
        )
        with self.assertRaises(StoreContractError) as raised:
            self.store.get_artifact_aggregate("workspace-1", self.artifact.artifact_id)
        self.assertEqual(raised.exception.code, "attestation_persistence_sqlite_operational")
        self.assertNotIn("secret-path", str(raised.exception))
        self.assertEqual(self.store._state, self.store.OPEN)
        raw.close()
        self.store._connection = None

    def test_read_reference_select_failure_rolls_back_and_sanitizes(self) -> None:
        self.store.persist_artifact(self.artifact, self.reference)
        raw = self.store._connection
        self.store._connection = _ConnectionProxy(
            raw,
            execute_failure=lambda sql, count: sqlite3.OperationalError("raw reference select / secret-path") if "FROM attestation_binding_references" in sql else None,
        )
        with self.assertRaises(StoreContractError) as raised:
            self.store.get_artifact_aggregate("workspace-1", self.artifact.artifact_id)
        self.assertEqual(raised.exception.code, "attestation_persistence_sqlite_operational")
        self.assertEqual(self.store._state, self.store.OPEN)
        raw.close()
        self.store._connection = None

    def test_latest_event_select_failure_leaves_no_active_transaction(self) -> None:
        self.store.persist_artifact(self.artifact, self.reference)
        raw = self.store._connection
        calls = [0]

        def fail_second(sql, count):
            if "FROM attestation_revalidation_events" in sql:
                calls[0] += 1
                if calls[0] == 2:
                    return sqlite3.OperationalError("raw latest select / secret-path")
            return None

        self.store._connection = _ConnectionProxy(raw, execute_failure=fail_second)
        with self.assertRaises(StoreContractError) as raised:
            self.store.get_latest_revalidation_event("workspace-1", self.artifact.artifact_id)
        self.assertEqual(raised.exception.code, "attestation_persistence_sqlite_operational")
        self.assertNotIn("secret-path", str(raised.exception))
        self.assertEqual(self.store._state, self.store.OPEN)
        raw.close()
        self.store._connection = None

    def test_read_projection_and_rollback_failure_states(self) -> None:
        self.store.persist_artifact(self.artifact, self.reference)
        self.store.close()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("UPDATE attestation_artifacts SET canonical_json='{}'")
            connection.commit()
        reopened = SQLiteAttestationPersistenceStore(self.path, workspace_identity="workspace-1")
        self.store = reopened
        with self.assertRaises(StoreContractError) as raised:
            reopened.get_artifact_aggregate("workspace-1", self.artifact.artifact_id)
        self.assertEqual(raised.exception.code, "attestation_artifact_aggregate_corrupt")
        self.assertEqual(reopened._state, reopened.OPEN)
        raw = reopened._connection
        reopened._connection = _ConnectionProxy(raw, rollback_failure=sqlite3.OperationalError("rollback secret"))
        with self.assertRaises(StoreContractError) as raised:
            reopened.get_latest_revalidation_event("workspace-1", self.artifact.artifact_id)
        self.assertEqual(raised.exception.code, "attestation_persistence_rollback_failed")
        self.assertEqual(reopened._state, reopened.CLOSED)
        raw.close()
        reopened._connection = None

    def test_connection_fatal_read_quarantines_and_rejects_followup(self) -> None:
        self.store.persist_artifact(self.artifact, self.reference)
        raw = self.store._connection
        self.store._connection = _ConnectionProxy(
            raw,
            execute_failure=lambda sql, count: sqlite3.ProgrammingError("closed connection / secret-path"),
        )
        with self.assertRaises(StoreContractError) as raised:
            self.store.get_artifact_aggregate("workspace-1", self.artifact.artifact_id)
        self.assertEqual(raised.exception.code, "attestation_persistence_sqlite_operational")
        self.assertEqual(self.store._state, self.store.CLOSED)
        with self.assertRaises(StoreContractError) as raised:
            self.store.get_latest_revalidation_event("workspace-1", self.artifact.artifact_id)
        self.assertEqual(raised.exception.code, "attestation_persistence_store_unavailable")
        raw.close()
        self.store._connection = None

    def test_event_rollback_no_gap_backdated_latest_and_return_isolation(self) -> None:
        self.store.persist_artifact(self.artifact, self.reference)
        first = self.store.append_revalidation_event(event_for(self.artifact, self.reference, attempt_id="attempt-" + "2" * 32))
        with self.assertRaises(StoreContractError) as raised:
            self.store.append_revalidation_event(event_for(self.artifact, self.reference, attempt_id="attempt-" + "3" * 32, artifact_digest="sha256:" + "0" * 64))
        self.assertEqual(raised.exception.code, "attestation_revalidation_event_binding_mismatch")
        second = self.store.append_revalidation_event(event_for(self.artifact, self.reference, attempt_id="attempt-" + "4" * 32, revalidated_at="2020-01-01T00:00:00.000000Z"))
        self.assertEqual((first.event_sequence, second.event_sequence), (1, 2))
        self.assertEqual(self.store.get_latest_revalidation_event("workspace-1", self.artifact.artifact_id).event_sequence, 2)

    def test_second_reference_failure_rolls_back_both_sides(self) -> None:
        raw = self.store._connection
        self.store._connection = _ConnectionProxy(
            raw,
            execute_failure=lambda sql, count: sqlite3.IntegrityError("second reference failure") if "INSERT INTO attestation_binding_references" in sql else None,
        )
        with self.assertRaises(StoreContractError) as raised:
            self.store.persist_artifact(self.artifact, self.reference)
        self.assertEqual(raised.exception.code, "attestation_artifact_conflict")
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM attestation_artifacts").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM attestation_binding_references").fetchone()[0], 0)
        raw.close()
        self.store._connection = None

    def test_orphan_and_workspace_isolation_fail_closed(self) -> None:
        self.store.persist_artifact(self.artifact, self.reference)
        self.store.append_revalidation_event(event_for(self.artifact, self.reference, attempt_id="attempt-" + "c" * 32))
        self.store.close()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys=OFF")
            connection.execute("DELETE FROM attestation_artifacts")
            connection.commit()
        reopened = SQLiteAttestationPersistenceStore(self.path, workspace_identity="workspace-1")
        self.store = reopened
        with self.assertRaises(StoreContractError) as raised:
            reopened.get_artifact_aggregate("workspace-1", self.artifact.artifact_id)
        self.assertEqual(raised.exception.code, "attestation_artifact_aggregate_corrupt")

    def test_multi_connection_distinct_and_replay_converge(self) -> None:
        self.store.persist_artifact(self.artifact, self.reference)
        other = SQLiteAttestationPersistenceStore(self.path, workspace_identity="workspace-1")
        barrier = threading.Barrier(2)
        results = []

        def append(store, event):
            barrier.wait(timeout=5)
            results.append(store.append_revalidation_event(event).event_sequence)

        threads = [
            threading.Thread(target=append, args=(self.store, event_for(self.artifact, self.reference, attempt_id="attempt-" + "5" * 32))),
            threading.Thread(target=append, args=(other, event_for(self.artifact, self.reference, attempt_id="attempt-" + "6" * 32))),
        ]
        for thread in threads: thread.start()
        for thread in threads: thread.join(timeout=5)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(sorted(results), [1, 2])
        replay = event_for(self.artifact, self.reference, attempt_id="attempt-" + "7" * 32)
        self.assertEqual(self.store.append_revalidation_event(replay).event_sequence, 3)
        self.assertEqual(other.append_revalidation_event(replay).event_sequence, 3)
        other.close()

    def test_close_failure_commit_unknown_and_use_after_close(self) -> None:
        raw = self.store._connection
        self.store._connection = _ConnectionProxy(raw, close_failure=sqlite3.OperationalError("close secret"))
        with self.assertRaises(StoreContractError) as raised:
            self.store.close()
        self.assertEqual(raised.exception.code, "attestation_persistence_close_failed")
        self.assertEqual(self.store._state, self.store.CLOSED)
        raw.close()
        self.store._connection = None

        store = SQLiteAttestationPersistenceStore(self.path, workspace_identity="workspace-1")
        raw = store._connection
        store._connection = _ConnectionProxy(raw, commit_failure=sqlite3.OperationalError("commit secret"))
        with self.assertRaises(StoreContractError) as raised:
            store.persist_artifact(self.artifact, self.reference)
        self.assertEqual(raised.exception.code, "attestation_persistence_commit_outcome_unknown")
        self.assertEqual(store._state, store.CLOSED)
        with self.assertRaises(StoreContractError) as raised:
            store.persist_artifact(self.artifact, self.reference)
        self.assertEqual(raised.exception.code, "attestation_persistence_store_unavailable")
        raw.close()
        store._connection = None

    def test_fresh_metadata_unknown_legacy_and_application_id_refusal(self) -> None:
        self.store.close()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA application_id = 42")
            connection.commit()
        with self.assertRaises(StoreContractError) as raised:
            SQLiteAttestationPersistenceStore(self.path, workspace_identity="workspace-1")
        self.assertEqual(raised.exception.code, "attestation_persistence_schema_shape_mismatch")
        for setup, expected in (
            (lambda connection: connection.execute("CREATE TABLE store_meta (schema_version INTEGER NOT NULL, workspace_identity TEXT NOT NULL)"), "attestation_persistence_schema_metadata_corrupt"),
            (lambda connection: connection.execute("CREATE TABLE legacy (value TEXT)"), "attestation_persistence_schema_shape_mismatch"),
        ):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "legacy.sqlite3"
                with closing(sqlite3.connect(path)) as connection:
                    setup(connection)
                    connection.commit()
                with self.assertRaises(StoreContractError) as raised:
                    SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
                self.assertEqual(raised.exception.code, expected)

    def test_different_workspace_fresh_open_is_serialized_without_rebind(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "shared.sqlite3"
            barrier = threading.Barrier(2)
            results = []

            def open_store(workspace):
                barrier.wait(timeout=5)
                try:
                    store = SQLiteAttestationPersistenceStore(path, workspace_identity=workspace)
                except StoreContractError as error:
                    results.append((workspace, error.code))
                else:
                    results.append((workspace, "opened"))
                    store.close()

            threads = [threading.Thread(target=open_store, args=("workspace-1",)), threading.Thread(target=open_store, args=("workspace-2",))]
            for thread in threads: thread.start()
            for thread in threads: thread.join(timeout=10)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(sorted(value for _, value in results), ["attestation_persistence_workspace_mismatch", "opened"])
            winner = next(workspace for workspace, value in results if value == "opened")
            with closing(sqlite3.connect(path)) as connection:
                self.assertEqual(connection.execute("SELECT workspace_identity FROM store_meta").fetchone()[0], winner)

    def test_concurrent_migration_has_one_committed_v4_shape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "v3.sqlite3"
            _create_v3(path)
            barrier = threading.Barrier(2)
            results = []

            def migrate():
                barrier.wait(timeout=5)
                try:
                    store = SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
                except StoreContractError as error:
                    results.append(error.code)
                else:
                    results.append("opened")
                    store.close()

            threads = [threading.Thread(target=migrate), threading.Thread(target=migrate)]
            for thread in threads: thread.start()
            for thread in threads: thread.join(timeout=10)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(sorted(results), ["opened", "opened"])
            with closing(sqlite3.connect(path)) as connection:
                self.assertEqual(connection.execute("SELECT schema_version FROM store_meta").fetchone()[0], 4)

    def test_typed_event_and_sequence_corruption_fail_closed(self) -> None:
        self.store.persist_artifact(self.artifact, self.reference)
        self.store.append_revalidation_event(event_for(self.artifact, self.reference, attempt_id="attempt-" + "8" * 32))
        self.store.close()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("UPDATE attestation_artifacts SET claims_revision='bad'")
            connection.commit()
        reopened = SQLiteAttestationPersistenceStore(self.path, workspace_identity="workspace-1")
        self.store = reopened
        with self.assertRaises(StoreContractError) as raised:
            reopened.get_artifact_aggregate("workspace-1", self.artifact.artifact_id)
        self.assertEqual(raised.exception.code, "attestation_artifact_aggregate_corrupt")
        reopened.close()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("UPDATE attestation_artifacts SET claims_revision=1")
            connection.execute("UPDATE attestation_revalidation_events SET canonical_json='{}', event_sequence=3")
            connection.commit()
        reopened = SQLiteAttestationPersistenceStore(self.path, workspace_identity="workspace-1")
        self.store = reopened
        with self.assertRaises(StoreContractError) as raised:
            reopened.get_latest_revalidation_event("workspace-1", self.artifact.artifact_id)
        self.assertEqual(raised.exception.code, "attestation_revalidation_event_corrupt")

    def test_busy_failure_is_stable_and_not_retried(self) -> None:
        self.store.persist_artifact(self.artifact, self.reference)
        raw = self.store._connection
        calls = [0]

        def fail_begin(sql, count):
            if sql == "BEGIN IMMEDIATE":
                calls[0] += 1
                return sqlite3.OperationalError("database is locked")
            return None

        self.store._connection = _ConnectionProxy(raw, execute_failure=fail_begin)
        with self.assertRaises(StoreContractError) as raised:
            self.store.append_revalidation_event(event_for(self.artifact, self.reference, attempt_id="attempt-" + "9" * 32))
        self.assertEqual(raised.exception.code, "attestation_persistence_sqlite_busy")
        self.assertEqual(calls[0], 1)
        self.assertEqual(self.store._state, self.store.OPEN)
        raw.close()
        self.store._connection = None

    def test_spawn_multiprocess_sequences_are_unique_and_contiguous(self) -> None:
        context = mp.get_context("spawn")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "multiprocess.sqlite3"
            initial = SQLiteAttestationPersistenceStore(path, workspace_identity="workspace-1")
            initial.persist_artifact(self.artifact, self.reference)
            initial.close()
            queue = context.Queue()
            barrier = context.Barrier(2)
            processes = [
                context.Process(target=_spawn_append_worker, args=(str(path), "a", barrier, queue)),
                context.Process(target=_spawn_append_worker, args=(str(path), "b", barrier, queue)),
            ]
            for process in processes: process.start()
            for process in processes: process.join(timeout=15)
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
            self.assertEqual([process.exitcode for process in processes], [0, 0])
            self.assertEqual(sorted(queue.get(timeout=5) for _ in processes), [1, 2])

    def test_concurrent_close_orderings_are_bounded(self) -> None:
        self.store.persist_artifact(self.artifact, self.reference)
        raw = self.store._connection
        entered = threading.Event()
        release = threading.Event()

        def block_insert(sql, count):
            if sql.startswith("INSERT INTO attestation_revalidation_events"):
                entered.set()
                self.assertTrue(release.wait(timeout=5))
            return None

        self.store._connection = _ConnectionProxy(raw, execute_failure=block_insert)
        operation_error = []
        operation = threading.Thread(target=lambda: operation_error.append(self.store.append_revalidation_event(event_for(self.artifact, self.reference, attempt_id="attempt-" + "a" * 32))))
        operation.start()
        self.assertTrue(entered.wait(timeout=5))
        close_done = threading.Event()
        closer = threading.Thread(target=lambda: (self.store.close(), close_done.set()))
        closer.start()
        self.assertFalse(close_done.wait(timeout=0.2))
        release.set()
        operation.join(timeout=5)
        closer.join(timeout=5)
        self.assertFalse(operation.is_alive() or closer.is_alive())
        self.assertTrue(close_done.is_set())
        self.assertEqual(len(operation_error), 1)
        self.assertEqual(operation_error[0].event_sequence, 1)
        raw.close()
        self.store._connection = None

        closed = SQLiteAttestationPersistenceStore(self.path, workspace_identity="workspace-1")
        closed.close()
        with self.assertRaises(StoreContractError) as raised:
            closed.append_revalidation_event(event_for(self.artifact, self.reference, attempt_id="attempt-" + "b" * 32))
        self.assertEqual(raised.exception.code, "attestation_persistence_store_unavailable")


if __name__ == "__main__":
    unittest.main()
