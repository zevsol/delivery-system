"""Focused Linux tests for the descriptor-backed read-only state foundation."""

from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from delivery_system import read_only_state as read_only_module, sqlite_schema
from delivery_system.read_only_state import ReadOnlyState, ReadOnlyStateError
from delivery_system.sqlite_maintenance import SQLiteBackupManifest


WORKSPACE = "ws_v1_test_source"
RELEASE = "test-release"


class _RollbackFailureConnection:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.statements: list[str] = []

    def execute(self, statement: str, *args: object):
        self.statements.append(statement)
        if statement == "ROLLBACK":
            raise RuntimeError("injected rollback failure")
        return self.connection.execute(statement, *args)

    def close(self) -> None:
        self.connection.close()


@unittest.skipUnless(os.name == "posix" and Path("/proc/self/fd").is_dir(), "Linux proc fd required")
class ReadOnlyStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.bundle = Path(self.temporary.name) / "bundle"
        self.bundle.mkdir()
        self.database = self.bundle / "state.sqlite3"
        self.manifest_path = self.bundle / "manifest.json"

    def make_bundle(self) -> None:
        with closing(sqlite_schema._open_connection(self.database)) as connection:
            sqlite_schema.ensure_schema_v7(connection, expected_workspace_identity=WORKSPACE)
            connection.execute(
                "INSERT INTO records(workspace_identity, record_type, record_id, revision, payload) "
                "VALUES (?, 'preview', 'first', 1, 'original')", (WORKSPACE,),
            )
        self.refresh_manifest()

    def refresh_manifest(self) -> None:
        raw = self.database.read_bytes()
        manifest = SQLiteBackupManifest(
            format="delivery-system-sqlite-backup", format_version=1,
            release_id=RELEASE, schema_version=7, workspace_identity=WORKSPACE,
            database_filename="state.sqlite3", database_size=len(raw),
            database_sha256=hashlib.sha256(raw).hexdigest(),
            created_at_utc=datetime(2026, 10, 17, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
        )
        self.manifest_path.write_bytes(manifest.to_json_bytes())

    def open_state(self) -> ReadOnlyState:
        return ReadOnlyState.open(
            self.bundle, expected_workspace_identity=WORKSPACE, expected_release_id=RELEASE,
        )

    def test_missing_database_creates_nothing(self) -> None:
        before = set(self.bundle.iterdir())
        with self.assertRaises(ReadOnlyStateError):
            self.open_state()
        self.assertEqual(set(self.bundle.iterdir()), before)

    def test_workspace_and_release_mismatch(self) -> None:
        self.make_bundle()
        for kwargs in ({"expected_workspace_identity": "other", "expected_release_id": RELEASE},
                       {"expected_workspace_identity": WORKSPACE, "expected_release_id": "other"}):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(ReadOnlyStateError, "read_only_identity_mismatch"):
                ReadOnlyState.open(self.bundle, **kwargs)

    def test_unsupported_schema_version_and_shape(self) -> None:
        self.make_bundle()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("UPDATE store_meta SET schema_version=8")
            connection.commit()
        self.refresh_manifest()
        with self.assertRaises(ReadOnlyStateError):
            self.open_state()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("UPDATE store_meta SET schema_version=7")
            connection.execute("DROP INDEX idx_application_execution_workspace_state")
            connection.commit()
        self.refresh_manifest()
        with self.assertRaises(ReadOnlyStateError):
            self.open_state()

    def test_physical_integrity_failure(self) -> None:
        self.make_bundle()
        self.database.write_bytes(b"not a sqlite image")
        self.refresh_manifest()
        with self.assertRaises(ReadOnlyStateError):
            self.open_state()

    def test_query_only_and_read_only_connection(self) -> None:
        self.make_bundle()
        with self.open_state() as state:
            self.assertEqual(state._connection.execute("PRAGMA query_only").fetchone(), (1,))
            self.assertEqual(state.query("SELECT payload FROM records WHERE record_id=?", ("first",)), [("original",)])
            with self.assertRaises(ReadOnlyStateError):
                state.query("UPDATE records SET payload='changed'")
            with self.assertRaises(sqlite3.OperationalError):
                state._connection.execute("UPDATE records SET payload='changed'")

    def test_symlink_bundle_and_member_rejected(self) -> None:
        self.make_bundle()
        link = Path(self.temporary.name) / "link"
        link.symlink_to(self.bundle, target_is_directory=True)
        with self.assertRaises(ReadOnlyStateError):
            ReadOnlyState.open(link, expected_workspace_identity=WORKSPACE, expected_release_id=RELEASE)
        self.database.rename(self.bundle / "real.sqlite3")
        self.database.symlink_to(self.bundle / "real.sqlite3")
        with self.assertRaises(ReadOnlyStateError):
            self.open_state()

    def test_replacement_after_open_keeps_original_object(self) -> None:
        self.make_bundle()
        with self.open_state() as state:
            old_fd = state._database_fd
            old_identity = os.fstat(old_fd).st_dev, os.fstat(old_fd).st_ino
            self.database.rename(self.bundle / "former.sqlite3")
            with closing(sqlite3.connect(self.database)) as replacement:
                replacement.execute("CREATE TABLE replacement_only(value TEXT)")
            self.assertNotEqual(old_identity, (self.database.stat().st_dev, self.database.stat().st_ino))
            self.assertEqual(state.query("SELECT payload FROM records WHERE record_id='first'"), [("original",)])
            self.assertEqual(state._connection.execute("PRAGMA database_list").fetchone()[1], "main")

    def test_replacement_before_sqlite_open_uses_retained_descriptor(self) -> None:
        self.make_bundle()
        real_connect = sqlite3.connect

        def replace_then_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
            retained_fd = int(str(args[0]).split("/fd/", 1)[1].split("?", 1)[0])
            retained = os.fstat(retained_fd)
            self.database.rename(self.bundle / "former.sqlite3")
            with closing(real_connect(self.database)) as replacement:
                replacement.execute("CREATE TABLE replacement_only(value TEXT)")
                replacement.commit()
            connection = real_connect(*args, **kwargs)
            matching = []
            for name in os.listdir("/proc/self/fd"):
                try:
                    info = os.fstat(int(name))
                except OSError:
                    continue
                if int(name) != retained_fd and (info.st_dev, info.st_ino) == (retained.st_dev, retained.st_ino):
                    matching.append(name)
            self.assertTrue(matching, "SQLite did not open the retained database inode")
            return connection

        with patch("delivery_system.read_only_state.sqlite3.connect", side_effect=replace_then_connect):
            with self.open_state() as state:
                self.assertEqual(state.query("SELECT payload FROM records WHERE record_id='first'"), [("original",)])

    def test_missing_schema_metadata_rejected(self) -> None:
        self.make_bundle()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("DELETE FROM store_meta")
            connection.commit()
        self.refresh_manifest()
        with self.assertRaises(ReadOnlyStateError):
            self.open_state()

    def test_sidecar_and_unexpected_member_rejected(self) -> None:
        self.make_bundle()
        sidecar = self.bundle / "state.sqlite3-wal"
        sidecar.write_bytes(b"unexpected")
        with self.assertRaises(ReadOnlyStateError):
            self.open_state()
        sidecar.unlink()
        (self.bundle / "unexpected").write_bytes(b"x")
        with self.assertRaises(ReadOnlyStateError):
            self.open_state()

    def test_hard_link_and_wal_image_rejected(self) -> None:
        self.make_bundle()
        link = Path(self.temporary.name) / "alias.sqlite3"
        os.link(self.database, link)
        with self.assertRaises(ReadOnlyStateError):
            self.open_state()
        link.unlink()
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(connection.execute("PRAGMA journal_mode=WAL").fetchone(), ("wal",))
        self.refresh_manifest()
        with self.assertRaises(ReadOnlyStateError):
            self.open_state()

    def test_manifest_and_database_digest_mismatch(self) -> None:
        self.make_bundle()
        values = json.loads(self.manifest_path.read_text())
        values["database_sha256"] = "0" * 64
        self.manifest_path.write_text(json.dumps(values))
        with self.assertRaisesRegex(ReadOnlyStateError, "read_only_digest_mismatch"):
            self.open_state()

    def test_close_success_and_failure(self) -> None:
        self.make_bundle()
        state = self.open_state()
        descriptor = state._database_fd
        connection = state._connection
        state.close()
        state.close()
        self.assertIsNone(state._connection)
        self.assertIsNone(state._database_fd)
        with self.assertRaises(OSError):
            os.fstat(descriptor)
        with self.assertRaises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")
        with self.assertRaises(ReadOnlyStateError):
            state.query("SELECT 1 ")
        with patch.object(sqlite_schema, "validate_schema_v7_read_only", side_effect=ValueError("forced")):
            with self.assertRaises(ValueError):
                self.open_state()

    def test_descriptors_close_on_validation_failure(self) -> None:
        self.make_bundle()
        opened: list[int] = []
        real_open = read_only_module._open_regular

        def capture(directory_fd: int, name: str) -> int:
            descriptor = real_open(directory_fd, name)
            opened.append(descriptor)
            return descriptor

        with patch.object(read_only_module, "_open_regular", side_effect=capture):
            with self.assertRaises(ReadOnlyStateError):
                ReadOnlyState.open(self.bundle, expected_workspace_identity="wrong", expected_release_id=RELEASE)
        self.assertEqual(len(opened), 2)
        for descriptor in opened:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def _exercise_cleanup(self, failing: set[str], *, validation_failure: bool) -> BaseException:
        self.make_bundle()
        owned: dict[str, int] = {}
        attempts: list[str] = []
        real_directory_open = read_only_module._open_directory_chain
        real_regular_open = read_only_module._open_regular

        def open_directory(path: Path) -> int:
            descriptor = real_directory_open(path)
            owned["directory_fd"] = descriptor
            return descriptor

        def open_regular(directory_fd: int, name: str) -> int:
            descriptor = real_regular_open(directory_fd, name)
            owned["manifest_fd" if name == "manifest.json" else "database_fd"] = descriptor
            return descriptor

        def close_descriptor(descriptor: int) -> None:
            name = next(name for name, value in owned.items() if value == descriptor)
            attempts.append(name)
            os.close(descriptor)
            if name in failing:
                raise OSError("injected descriptor close failure")

        def close_connection(connection: sqlite3.Connection) -> None:
            attempts.append("connection")
            connection.close()
            if "connection" in failing:
                raise RuntimeError("injected connection close failure")

        def reject_validation(*_args: object, **_kwargs: object) -> None:
            raise ValueError("validation_primary")

        with patch.object(read_only_module, "_open_directory_chain", side_effect=open_directory), \
             patch.object(read_only_module, "_open_regular", side_effect=open_regular), \
             patch.object(read_only_module, "_close_descriptor", side_effect=close_descriptor), \
             patch.object(read_only_module, "_close_connection", side_effect=close_connection):
            if validation_failure:
                with patch.object(sqlite_schema, "validate_schema_v7_read_only", side_effect=reject_validation):
                    with self.assertRaises(BaseException) as caught:
                        self.open_state()
            else:
                with self.assertRaises(BaseException) as caught:
                    self.open_state()

        self.assertCountEqual(attempts, ("connection", "database_fd", "manifest_fd", "directory_fd"))
        for descriptor in owned.values():
            with self.assertRaises(OSError):
                os.fstat(descriptor)
        return caught.exception

    def test_manifest_close_failure_cleans_every_owned_resource(self) -> None:
        error = self._exercise_cleanup({"manifest_fd"}, validation_failure=False)
        self.assertIsInstance(error, ReadOnlyStateError)
        self.assertIn("manifest_fd:OSError", error.cleanup_failures)

    def test_directory_close_failure_cleans_every_owned_resource(self) -> None:
        error = self._exercise_cleanup({"directory_fd"}, validation_failure=False)
        self.assertIsInstance(error, ReadOnlyStateError)
        self.assertIn("directory_fd:OSError", error.cleanup_failures)

    def test_connection_close_failure_does_not_skip_descriptors(self) -> None:
        error = self._exercise_cleanup({"connection"}, validation_failure=True)
        self.assertIsInstance(error, ValueError)
        self.assertEqual(str(error), "validation_primary")
        self.assertIn("connection:RuntimeError", error.cleanup_failures)

    def test_database_close_failure_does_not_skip_other_resources(self) -> None:
        error = self._exercise_cleanup({"database_fd"}, validation_failure=True)
        self.assertEqual(str(error), "validation_primary")
        self.assertIn("database_fd:OSError", error.cleanup_failures)

    def test_multiple_cleanup_failures_preserve_primary_validation_error(self) -> None:
        error = self._exercise_cleanup(
            {"connection", "database_fd", "manifest_fd", "directory_fd"},
            validation_failure=True,
        )
        self.assertEqual(str(error), "validation_primary")
        self.assertEqual(len(error.cleanup_failures), 4)

    def test_normal_post_connection_failure_closes_every_resource(self) -> None:
        error = self._exercise_cleanup(set(), validation_failure=True)
        self.assertEqual(str(error), "validation_primary")
        self.assertFalse(hasattr(error, "cleanup_failures"))

    def test_close_attempts_database_after_connection_close_failure(self) -> None:
        self.make_bundle()
        state = self.open_state()
        descriptor = state._database_fd
        connection = state._connection
        attempts: list[str] = []
        real_connection_close = read_only_module._close_connection
        real_descriptor_close = read_only_module._close_descriptor

        def close_connection(connection: sqlite3.Connection) -> None:
            attempts.append("connection")
            real_connection_close(connection)
            raise RuntimeError("injected connection close failure")

        def close_descriptor(value: int) -> None:
            attempts.append("database_fd")
            real_descriptor_close(value)

        with patch.object(read_only_module, "_close_connection", side_effect=close_connection), \
             patch.object(read_only_module, "_close_descriptor", side_effect=close_descriptor):
            with self.assertRaisesRegex(RuntimeError, "injected connection close failure"):
                state.close()
        self.assertEqual(attempts, ["connection", "database_fd"])
        with self.assertRaises(OSError):
            os.fstat(descriptor)
        with self.assertRaises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")

    def test_digest_wrap_failure_closes_duplicate_not_input(self) -> None:
        self.make_bundle()
        original = os.open(self.database, os.O_RDONLY)
        duplicates: list[int] = []
        real_dup = os.dup

        def duplicate(descriptor: int) -> int:
            value = real_dup(descriptor)
            duplicates.append(value)
            return value

        try:
            with patch.object(read_only_module.os, "dup", side_effect=duplicate), \
                 patch.object(read_only_module.os, "fdopen", side_effect=RuntimeError("wrap_primary")):
                with self.assertRaisesRegex(RuntimeError, "wrap_primary"):
                    read_only_module._bytes_and_digest(original)
            self.assertEqual(len(duplicates), 1)
            with self.assertRaises(OSError):
                os.fstat(duplicates[0])
            os.fstat(original)
        finally:
            os.close(original)

    def test_digest_wrap_and_duplicate_close_failures_preserve_wrap_error(self) -> None:
        self.make_bundle()
        original = os.open(self.database, os.O_RDONLY)
        duplicates: list[int] = []
        close_attempts: list[int] = []
        real_dup = os.dup
        real_close = read_only_module._close_digest_descriptor

        def duplicate(descriptor: int) -> int:
            value = real_dup(descriptor)
            duplicates.append(value)
            return value

        def close_duplicate(descriptor: int) -> None:
            close_attempts.append(descriptor)
            real_close(descriptor)
            raise OSError("injected duplicate close failure")

        try:
            with patch.object(read_only_module.os, "dup", side_effect=duplicate), \
                 patch.object(read_only_module.os, "fdopen", side_effect=RuntimeError("wrap_primary")), \
                 patch.object(read_only_module, "_close_digest_descriptor", side_effect=close_duplicate):
                with self.assertRaisesRegex(RuntimeError, "wrap_primary") as caught:
                    read_only_module._bytes_and_digest(original)
            self.assertEqual(close_attempts, duplicates)
            self.assertEqual(caught.exception.cleanup_failures, ("digest_fd:OSError",))
            with self.assertRaises(OSError):
                os.fstat(duplicates[0])
            os.fstat(original)
        finally:
            os.close(original)

    def test_digest_success_has_one_raw_descriptor_owner(self) -> None:
        self.make_bundle()
        original = os.open(self.database, os.O_RDONLY)
        duplicates: list[int] = []
        close_attempts: list[int] = []
        streams = []
        real_dup = os.dup
        real_fdopen = os.fdopen
        real_close = read_only_module._close_digest_descriptor

        def duplicate(descriptor: int) -> int:
            value = real_dup(descriptor)
            duplicates.append(value)
            return value

        def wrap(descriptor: int, mode: str, *, closefd: bool):
            self.assertFalse(closefd)
            stream = real_fdopen(descriptor, mode, closefd=closefd)
            streams.append(stream)
            return stream

        def close_duplicate(descriptor: int) -> None:
            close_attempts.append(descriptor)
            real_close(descriptor)

        try:
            with patch.object(read_only_module.os, "dup", side_effect=duplicate), \
                 patch.object(read_only_module.os, "fdopen", side_effect=wrap), \
                 patch.object(read_only_module, "_close_digest_descriptor", side_effect=close_duplicate):
                raw, size, digest = read_only_module._bytes_and_digest(original, limit=10_000_000)
            self.assertEqual(raw, self.database.read_bytes())
            self.assertEqual(size, len(raw))
            self.assertEqual(digest, hashlib.sha256(raw).hexdigest())
            self.assertEqual(len(streams), 1)
            self.assertTrue(streams[0].closed)
            self.assertEqual(close_attempts, duplicates)
            with self.assertRaises(OSError):
                os.fstat(duplicates[0])
            os.fstat(original)
        finally:
            os.close(original)

    def test_no_writable_store_or_migration_call(self) -> None:
        self.make_bundle()
        with patch.object(sqlite_schema, "_open_connection", side_effect=AssertionError("writable open")), \
             patch.object(sqlite_schema, "ensure_schema_v7", side_effect=AssertionError("migration")):
            with self.open_state() as state:
                self.assertEqual(state.query("SELECT count(*) FROM records"), [(1,)])

    def test_snapshot_preserves_primary_and_closes_after_rollback_failure(self) -> None:
        self.make_bundle()
        state = self.open_state()
        connection = state._connection
        descriptor = state._database_fd
        unrelated = os.open(self.manifest_path, os.O_RDONLY)
        proxy = _RollbackFailureConnection(connection)
        state._connection = proxy
        primary = ValueError("projection_primary")
        attempts: list[str] = []
        real_connection_close = read_only_module._close_connection
        real_descriptor_close = read_only_module._close_descriptor

        def close_connection(value: object) -> None:
            attempts.append("connection")
            real_connection_close(value)

        def close_descriptor(value: int) -> None:
            self.assertEqual(value, descriptor)
            attempts.append("database_fd")
            real_descriptor_close(value)

        try:
            with patch.object(read_only_module, "_close_connection", side_effect=close_connection), \
                 patch.object(read_only_module, "_close_descriptor", side_effect=close_descriptor):
                with self.assertRaises(ValueError) as caught:
                    with state.snapshot():
                        self.assertTrue(connection.in_transaction)
                        raise primary
            self.assertIs(caught.exception, primary)
            self.assertEqual(primary.cleanup_failures, ("rollback:RuntimeError",))
            self.assertEqual(attempts, ["connection", "database_fd"])
            self.assertTrue(state._closed)
            self.assertIsNone(state._connection)
            self.assertIsNone(state._database_fd)
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute("SELECT 1")
            with self.assertRaises(OSError):
                os.fstat(descriptor)
            os.fstat(unrelated)
            state.close()
            self.assertEqual(attempts, ["connection", "database_fd"])
        finally:
            os.close(unrelated)
            state.close()

    def test_snapshot_rollback_failure_prevents_query_and_snapshot_reuse(self) -> None:
        self.make_bundle()
        state = self.open_state()
        proxy = _RollbackFailureConnection(state._connection)
        state._connection = proxy
        try:
            with self.assertRaisesRegex(ValueError, "projection_primary"):
                with state.snapshot():
                    raise ValueError("projection_primary")
            statements = list(proxy.statements)
            with self.assertRaisesRegex(ReadOnlyStateError, "read_only_state_closed"):
                state.query("SELECT 1")
            with self.assertRaisesRegex(ReadOnlyStateError, "read_only_state_closed"):
                with state.snapshot():
                    self.fail("invalidated snapshot entered")
            self.assertEqual(proxy.statements, statements)
            self.assertEqual(statements, ["BEGIN", "ROLLBACK"])
        finally:
            state.close()

    def test_snapshot_rollback_and_cleanup_failures_are_independent(self) -> None:
        self.make_bundle()
        state = self.open_state()
        descriptor = state._database_fd
        unrelated = os.open(self.manifest_path, os.O_RDONLY)
        state._connection = _RollbackFailureConnection(state._connection)
        primary = ValueError("projection_primary")
        attempts: list[str] = []
        real_connection_close = read_only_module._close_connection
        real_descriptor_close = read_only_module._close_descriptor

        def close_connection(value: object) -> None:
            attempts.append("connection")
            real_connection_close(value)
            raise RuntimeError("injected connection close failure")

        def close_descriptor(value: int) -> None:
            self.assertEqual(value, descriptor)
            attempts.append("database_fd")
            real_descriptor_close(value)
            raise OSError("injected database descriptor close failure")

        try:
            with patch.object(read_only_module, "_close_connection", side_effect=close_connection), \
                 patch.object(read_only_module, "_close_descriptor", side_effect=close_descriptor):
                with self.assertRaises(ValueError) as caught:
                    with state.snapshot():
                        raise primary
            self.assertIs(caught.exception, primary)
            self.assertEqual(primary.cleanup_failures, (
                "rollback:RuntimeError", "connection:RuntimeError", "database_fd:OSError",
            ))
            self.assertEqual(attempts, ["connection", "database_fd"])
            self.assertTrue(state._closed)
            self.assertIsNone(state._connection)
            self.assertIsNone(state._database_fd)
            with self.assertRaises(OSError):
                os.fstat(descriptor)
            os.fstat(unrelated)
            state.close()
            self.assertEqual(attempts, ["connection", "database_fd"])
        finally:
            os.close(unrelated)
            state.close()

    def test_snapshot_normal_projection_failure_rolls_back_and_remains_usable(self) -> None:
        self.make_bundle()
        with self.open_state() as state:
            primary = ValueError("projection_primary")
            with self.assertRaises(ValueError) as caught:
                with state.snapshot():
                    self.assertTrue(state._connection.in_transaction)
                    raise primary
            self.assertIs(caught.exception, primary)
            self.assertFalse(state._connection.in_transaction)
            self.assertFalse(state._closed)
            self.assertEqual(state.query("SELECT payload FROM records WHERE record_id='first'"), [("original",)])

    def test_snapshot_successful_body_rollback_failure_invalidates_state(self) -> None:
        self.make_bundle()
        state = self.open_state()
        state._connection = _RollbackFailureConnection(state._connection)
        try:
            with self.assertRaisesRegex(RuntimeError, "injected rollback failure") as caught:
                with state.snapshot():
                    self.assertEqual(state.query("SELECT 1"), [(1,)])
            self.assertFalse(hasattr(caught.exception, "cleanup_failures"))
            self.assertTrue(state._closed)
            with self.assertRaisesRegex(ReadOnlyStateError, "read_only_state_closed"):
                state.query("SELECT 1")
        finally:
            state.close()

    def test_close_inside_snapshot_transfers_resources_once(self) -> None:
        self.make_bundle()
        for body_raises in (False, True):
            with self.subTest(body_raises=body_raises):
                state = self.open_state()
                descriptor = state._database_fd
                proxy = _RollbackFailureConnection(state._connection)
                state._connection = proxy
                attempts: list[int] = []
                real_close = read_only_module._close_descriptor
                unrelated = os.open(self.manifest_path, os.O_RDONLY)
                reopened: int | None = None

                def guarded_close(value: int) -> None:
                    if value == descriptor:
                        if attempts:
                            raise AssertionError("duplicate database descriptor close")
                        attempts.append(value)
                    real_close(value)

                try:
                    with patch.object(read_only_module, "_close_descriptor", side_effect=guarded_close):
                        if body_raises:
                            primary = ValueError("body_primary")
                            with self.assertRaises(ValueError) as caught:
                                with state.snapshot():
                                    state.close()
                                    raise primary
                            self.assertIs(caught.exception, primary)
                        else:
                            with state.snapshot():
                                state.close()
                                # This descriptor may reuse the old number. The
                                # guard rejects any second close before the OS call.
                                reopened = os.open(self.manifest_path, os.O_RDONLY)
                                os.fstat(reopened)
                    self.assertEqual(proxy.statements, ["BEGIN"])
                    self.assertEqual(attempts, [descriptor])
                    self.assertTrue(state._closed)
                    self.assertIsNone(state._connection)
                    self.assertIsNone(state._database_fd)
                    os.fstat(unrelated)
                    if reopened is not None:
                        os.fstat(reopened)
                    with self.assertRaisesRegex(ReadOnlyStateError, "read_only_state_closed"):
                        state.query("SELECT 1")
                    state.close()
                    self.assertEqual(attempts, [descriptor])
                finally:
                    if reopened is not None:
                        os.close(reopened)
                    os.close(unrelated)
                    state.close()

    def test_close_inside_snapshot_cleanup_failures_do_not_retry_detached_resources(self) -> None:
        self.make_bundle()
        for failing in ({"connection"}, {"database_fd"}, {"connection", "database_fd"}):
            with self.subTest(failing=failing):
                state = self.open_state()
                descriptor = state._database_fd
                proxy = _RollbackFailureConnection(state._connection)
                state._connection = proxy
                attempts: list[str] = []
                real_connection_close = read_only_module._close_connection
                real_descriptor_close = read_only_module._close_descriptor

                def close_connection(value: object) -> None:
                    attempts.append("connection")
                    real_connection_close(value)
                    if "connection" in failing:
                        raise RuntimeError("injected connection close failure")

                def close_descriptor(value: int) -> None:
                    if value == descriptor and "database_fd" in attempts:
                        raise AssertionError("duplicate database descriptor close")
                    self.assertEqual(value, descriptor)
                    attempts.append("database_fd")
                    real_descriptor_close(value)
                    if "database_fd" in failing:
                        raise OSError("injected database descriptor close failure")

                try:
                    with patch.object(read_only_module, "_close_connection", side_effect=close_connection), \
                         patch.object(read_only_module, "_close_descriptor", side_effect=close_descriptor):
                        primary_type = RuntimeError if "connection" in failing else OSError
                        with self.assertRaises(primary_type) as caught:
                            with state.snapshot():
                                state.close()
                        state.close()
                    expected = tuple(
                        label for name, label in (
                            ("connection", "connection:RuntimeError"),
                            ("database_fd", "database_fd:OSError"),
                        ) if name in failing
                    )
                    self.assertEqual(caught.exception.cleanup_failures, expected)
                    self.assertEqual(attempts, ["connection", "database_fd"])
                    self.assertEqual(proxy.statements, ["BEGIN"])
                    self.assertTrue(state._closed)
                    self.assertIsNone(state._connection)
                    self.assertIsNone(state._database_fd)
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
                finally:
                    state.close()


if __name__ == "__main__":
    unittest.main()
