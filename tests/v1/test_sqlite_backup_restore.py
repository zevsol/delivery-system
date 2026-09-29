from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from delivery_system import sqlite_maintenance as maintenance
from delivery_system import sqlite_schema
from delivery_system.runtime import RuntimeContext, SQLitePreviewStore


class SQLiteBackupRestoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name) / "workspace"
        self.workspace.mkdir()
        self.state_dir = self.workspace / ".delivery-system"
        self.state_dir.mkdir()
        self.context = RuntimeContext.from_workspace_root(self.workspace)
        self.path_checks = (
            patch("delivery_system.runtime._default_ignored", return_value=True),
            patch("delivery_system.runtime._default_tracked", return_value=False),
        )
        for checker in self.path_checks:
            checker.start()
            self.addCleanup(checker.stop)

    @property
    def state_path(self) -> Path:
        return Path(self.context.state_path)

    def _create_v7(self, workspace_identity: str | None = None) -> None:
        expected_workspace = workspace_identity or self.context.workspace_identity
        with closing(sqlite_schema._open_connection(self.state_path)) as connection:
            sqlite_schema.ensure_schema_v7(
                connection,
                expected_workspace_identity=expected_workspace,
            )
            connection.execute(
                "INSERT INTO item_lineage VALUES (?, ?, ?, ?, ?, ?)",
                (expected_workspace, "preview", 1, "client", "item", 0),
            )
            connection.execute(
                "INSERT INTO records VALUES (?, ?, ?, ?, ?)",
                (expected_workspace, "preview", "preview-1", 1, "payload"),
            )
            connection.execute(
                "INSERT INTO audit_history VALUES (?, ?, ?, ?, ?, ?)",
                (expected_workspace, "audit-1", 1, "payload", "reason", "2026-09-29T00:00:00Z"),
            )

    def _backup(self, destination: Path | None = None) -> maintenance.BackupResult:
        return maintenance.backup(
            maintenance.BackupRequest(
                workspace_root=self.workspace,
                destination=destination or Path(self.temporary.name) / "backup",
            )
        )

    @staticmethod
    def _sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @classmethod
    def _fingerprint(cls, path: Path) -> tuple[bool, str | None, int | None, str | None]:
        if not path.exists():
            return (False, None, None, None)
        if path.is_dir():
            return (True, "directory", None, None)
        return (True, "file", path.stat().st_size, cls._sha256(path))

    def _source_fingerprint(self) -> dict[str, tuple[bool, str | None, int | None, str | None]]:
        return {
            path.name: self._fingerprint(path)
            for path in (
                self.state_path,
                Path(f"{self.state_path}-wal"),
                Path(f"{self.state_path}-shm"),
                Path(f"{self.state_path}-journal"),
            )
        }

    def _refresh_manifest_digest(self, bundle: Path) -> None:
        database = bundle / "state.sqlite3"
        values = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
        values["database_size"] = database.stat().st_size
        values["database_sha256"] = self._sha256(database)
        (bundle / "manifest.json").write_text(
            json.dumps(values, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )

    @staticmethod
    def _declared_server_version() -> str:
        from mcp_server.server import SERVER_VERSION

        return SERVER_VERSION

    def _manifest_values(self) -> dict[str, object]:
        return json.loads(
            maintenance.SQLiteBackupManifest(
                format=maintenance.BACKUP_FORMAT,
                format_version=maintenance.BACKUP_FORMAT_VERSION,
                release_id=maintenance._current_release_id(),
                schema_version=maintenance.EXPECTED_SCHEMA_VERSION,
                workspace_identity=self.context.workspace_identity,
                database_filename=maintenance.DATABASE_FILENAME,
                database_size=1,
                database_sha256="0" * 64,
                created_at_utc="2026-09-29T00:00:00Z",
            ).to_json_bytes().decode("utf-8")
        )

    @staticmethod
    def _semantic_state(path: Path) -> dict[str, tuple[tuple[object, ...], ...]]:
        result: dict[str, tuple[tuple[object, ...], ...]] = {}
        with closing(sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro", uri=True)) as connection:
            for table in sqlite_schema._V7_TABLES:
                rows = connection.execute(f"SELECT * FROM {table}").fetchall()
                result[table] = tuple(sorted((tuple(row) for row in rows), key=repr))
        return result

    def test_path_validation_has_no_creation_side_effect(self) -> None:
        empty_root = Path(self.temporary.name) / "empty"
        empty_root.mkdir()
        context = RuntimeContext.from_workspace_root(empty_root)
        context.validate_store_paths_read_only(
            ignore_checker=lambda _: True,
            tracked_checker=lambda _: False,
        )
        self.assertFalse((empty_root / ".delivery-system").exists())
        context.ensure_store_ready(
            ignore_checker=lambda _: True,
            tracked_checker=lambda _: False,
        )
        self.assertTrue((empty_root / ".delivery-system").is_dir())

    def test_read_only_v7_validator_accepts_v7_without_mutation(self) -> None:
        self._create_v7()
        before = self._sha256(self.state_path)
        with closing(maintenance._open_read_only_connection(self.state_path)) as connection:
            sqlite_schema.validate_schema_v7_read_only(
                connection,
                expected_workspace_identity=self.context.workspace_identity,
            )
        self.assertEqual(before, self._sha256(self.state_path))

    def test_backup_success_manifest_and_standalone_database(self) -> None:
        self._create_v7()
        Path(f"{self.state_path}-journal").write_bytes(b"")
        before = self._source_fingerprint()
        result = self._backup()
        self.assertEqual(result.destination.name, "backup")
        self.assertEqual(
            sorted(path.name for path in result.destination.iterdir()),
            ["manifest.json", "state.sqlite3"],
        )
        manifest = maintenance.SQLiteBackupManifest.from_json_bytes(
            (result.destination / "manifest.json").read_bytes()
        )
        self.assertEqual(manifest.format, maintenance.BACKUP_FORMAT)
        self.assertEqual(manifest.format_version, 1)
        self.assertEqual(manifest.release_id, maintenance._current_release_id())
        self.assertEqual(manifest.release_id, self._declared_server_version())
        self.assertEqual(manifest.schema_version, 7)
        self.assertEqual(manifest.workspace_identity, self.context.workspace_identity)
        self.assertEqual(manifest.database_filename, "state.sqlite3")
        self.assertEqual(manifest.database_size, (result.destination / "state.sqlite3").stat().st_size)
        self.assertEqual(manifest.database_sha256, self._sha256(result.destination / "state.sqlite3"))
        self.assertEqual(before, self._source_fingerprint())
        self.assertEqual(self._semantic_state(self.state_path), self._semantic_state(result.destination / "state.sqlite3"))
        self.assertFalse((result.destination / "state.sqlite3-wal").exists())
        self.assertFalse((result.destination / "state.sqlite3-shm").exists())
        self.assertFalse((result.destination / "state.sqlite3-journal").exists())

    def test_backup_rejects_existing_destination(self) -> None:
        self._create_v7()
        destination = Path(self.temporary.name) / "backup"
        destination.mkdir()
        with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_backup_destination_exists"):
            self._backup(destination)

    def test_backup_rejects_missing_unsafe_source_and_destination(self) -> None:
        with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_backup_source_missing"):
            self._backup()
        self.state_path.mkdir()
        with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_backup_source_invalid"):
            self._backup()
        self.state_path.rmdir()
        self._create_v7()
        with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_backup_destination_invalid"):
            self._backup(self.state_path)
        with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_backup_destination_invalid"):
            self._backup(Path(self.temporary.name) / "missing-parent" / "backup")

    def test_backup_busy_and_temporary_creation_fail_closed(self) -> None:
        self._create_v7()
        with patch.object(maintenance, "_open_read_only_connection", side_effect=sqlite3.OperationalError("database is locked")):
            with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_backup_source_busy"):
                self._backup()
        with patch.object(
            maintenance,
            "_temporary_bundle",
            side_effect=maintenance.SQLiteMaintenanceError("sqlite_maintenance_backup_creation_failed"),
        ):
            with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_backup_creation_failed"):
                self._backup()

    def test_backup_creation_and_verification_failures_are_sanitized(self) -> None:
        self._create_v7()

        class FailingSourceConnection:
            def backup(self, _destination: object) -> None:
                raise sqlite3.OperationalError("locked")

            def close(self) -> None:
                return None

        with patch.object(maintenance, "_open_read_only_connection", return_value=FailingSourceConnection()), \
             patch.object(maintenance, "_validate_v7_database", return_value=None):
            with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_backup_creation_failed"):
                self._backup()

        with patch.object(
            maintenance,
            "_validate_v7_database",
            side_effect=[None, maintenance.SQLiteMaintenanceError("sqlite_maintenance_backup_verification_failed")],
        ):
            with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_backup_verification_failed"):
                self._backup()

    def test_backup_rejects_non_v7_without_migration(self) -> None:
        with closing(sqlite_schema._open_connection(self.state_path)) as connection:
            sqlite_schema.ensure_schema_v6(connection, expected_workspace_identity=self.context.workspace_identity)
        before = self._sha256(self.state_path)
        with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_backup_source_schema_mismatch"):
            self._backup()
        self.assertEqual(before, self._sha256(self.state_path))
        with closing(sqlite_schema._open_connection(self.state_path)) as connection:
            self.assertEqual(connection.execute("SELECT schema_version FROM store_meta").fetchone()[0], 6)

    def test_backup_rejects_workspace_mismatch(self) -> None:
        self._create_v7(workspace_identity="ws_v1_other")
        with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_backup_source_invalid"):
            self._backup()

    def test_backup_rejects_future_schema(self) -> None:
        self._create_v7()
        with closing(sqlite_schema._open_connection(self.state_path)) as connection:
            connection.execute("UPDATE store_meta SET schema_version = 99")
        with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_backup_source_schema_mismatch"):
            self._backup()

    def test_validation_rejects_integrity_and_foreign_key_failures(self) -> None:
        class FakeConnection:
            def __init__(self, integrity_rows, foreign_rows):
                self.integrity_rows = integrity_rows
                self.foreign_rows = foreign_rows

            def execute(self, statement):
                if "integrity_check" in statement:
                    return self.integrity_rows
                return self.foreign_rows

        with patch.object(sqlite_schema, "validate_schema_v7_read_only"):
            with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "backup_verification_failed"):
                maintenance._validate_v7_database(
                    FakeConnection([("not ok",)], []),
                    expected_workspace_identity="ws_v1_test",
                    error_context="backup_copy",
                )
            with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "backup_verification_failed"):
                maintenance._validate_v7_database(
                    FakeConnection([("ok",)], [("bad",)]),
                    expected_workspace_identity="ws_v1_test",
                    error_context="backup_copy",
                )

    def test_validation_maps_schema_shape_and_busy_by_context(self) -> None:
        class BusyConnection:
            def execute(self, _statement):
                raise sqlite3.OperationalError("database is locked")

        with patch.object(
            sqlite_schema,
            "validate_schema_v7_read_only",
            side_effect=sqlite_schema.SchemaOwnerError("attestation_persistence_schema_shape_mismatch"),
        ):
            for context, code in (
                ("backup_source", "sqlite_maintenance_backup_source_schema_mismatch"),
                ("restore_artifact", "sqlite_maintenance_restore_schema_mismatch"),
                ("restore_staging", "sqlite_maintenance_restore_schema_mismatch"),
            ):
                with self.subTest(context=context):
                    with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, code):
                        maintenance._validate_v7_database(
                            object(),
                            expected_workspace_identity="ws_v1_test",
                            error_context=context,
                        )

        with patch.object(sqlite_schema, "validate_schema_v7_read_only", return_value=None):
            for context, code in (
                ("backup_source", "sqlite_maintenance_backup_source_busy"),
                ("backup_copy", "sqlite_maintenance_backup_verification_failed"),
                ("restore_artifact", "sqlite_maintenance_restore_verification_failed"),
                ("restore_staging", "sqlite_maintenance_restore_verification_failed"),
            ):
                with self.subTest(context=context):
                    with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, code):
                        maintenance._validate_v7_database(
                            BusyConnection(),
                            expected_workspace_identity="ws_v1_test",
                            error_context=context,
                        )

    def test_manifest_parser_rejects_strict_invalid_inputs(self) -> None:
        cases = {
            "bool_format_version": {"format_version": True},
            "missing_field": {"created_at_utc": None},
            "unknown_field": {"unexpected": "value"},
            "digest": {"database_sha256": "A" * 64},
            "size": {"database_size": -1},
            "timestamp": {"created_at_utc": "2026-09-29T00:00:00+00:00"},
        }
        for name, changes in cases.items():
            with self.subTest(name=name):
                values = self._manifest_values()
                if name == "missing_field":
                    values.pop("created_at_utc")
                else:
                    values.update(changes)
                with self.assertRaises(ValueError):
                    maintenance.SQLiteBackupManifest.from_json_bytes(
                        json.dumps(values, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    )
        with self.assertRaises(ValueError):
            maintenance.SQLiteBackupManifest.from_json_bytes(b"\xff")

    def test_restore_rejects_oversized_manifest_with_bounded_read(self) -> None:
        self._create_v7()
        bundle = self._backup().destination
        self.state_path.unlink()
        manifest_path = bundle / "manifest.json"
        manifest_path.write_bytes(b"{" + (b"x" * maintenance.MAX_MANIFEST_BYTES) + b"}")
        with patch.object(maintenance.json, "loads", wraps=maintenance.json.loads) as loads:
            with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_restore_artifact_malformed"):
                maintenance.restore(maintenance.RestoreRequest(self.workspace, bundle))
        loads.assert_not_called()
        self.assertFalse(self.state_path.exists())
        self.assertEqual(manifest_path.stat().st_size, maintenance.MAX_MANIFEST_BYTES + 2)

    def test_backup_sidecar_before_publication_blocks_and_cleans(self) -> None:
        self._create_v7()
        destination = Path(self.temporary.name) / "sidecar-backup"
        created: list[Path] = []
        original_bundle = maintenance._temporary_bundle
        original_manifest = maintenance._manifest_for_database

        def capture_bundle(parent: Path) -> Path:
            bundle = original_bundle(parent)
            created.append(bundle)
            return bundle

        def inject_sidecar(path: Path, **kwargs):
            result = original_manifest(path, **kwargs)
            Path(f"{path}-wal").write_bytes(b"unexpected-sidecar")
            return result

        with patch.object(maintenance, "_temporary_bundle", side_effect=capture_bundle), \
             patch.object(maintenance, "_manifest_for_database", side_effect=inject_sidecar):
            with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_backup_verification_failed"):
                self._backup(destination)
        self.assertFalse(destination.exists())
        self.assertTrue(created)
        self.assertFalse(created[0].exists())

    def test_restore_staging_sidecar_before_activation_blocks_and_cleans(self) -> None:
        self._create_v7()
        bundle = self._backup().destination
        self.state_path.unlink()
        created: list[Path] = []
        original_database = maintenance._temporary_database
        original_empty_slot = maintenance._require_empty_active_slot
        calls = 0

        def capture_database(parent: Path, *, error_code: str) -> Path:
            path = original_database(parent, error_code=error_code)
            created.append(path)
            return path

        def inject_on_final_empty_slot(context: RuntimeContext) -> None:
            nonlocal calls
            original_empty_slot(context)
            calls += 1
            if calls == 2:
                Path(f"{created[0]}-wal").write_bytes(b"unexpected-sidecar")

        with patch.object(maintenance, "_temporary_database", side_effect=capture_database), \
             patch.object(maintenance, "_require_empty_active_slot", side_effect=inject_on_final_empty_slot):
            with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_restore_staging_failed"):
                maintenance.restore(maintenance.RestoreRequest(self.workspace, bundle))
        self.assertFalse(self.state_path.exists())
        self.assertTrue(created)
        self.assertFalse(created[0].exists())
        self.assertFalse(Path(f"{created[0]}-wal").exists())

    def test_restore_rejects_artifact_replacement_after_open_before_copy(self) -> None:
        self._create_v7()
        bundle = self._backup().destination
        self.state_path.unlink()
        artifact = bundle / "state.sqlite3"
        original_bytes = artifact.read_bytes()
        original_open = maintenance._open_read_only_connection
        replaced = False

        def replace_before_open(path: Path):
            nonlocal replaced
            if Path(path) == artifact and not replaced:
                artifact.write_bytes(original_bytes + b"replacement")
                replaced = True
            return original_open(path)

        with patch.object(maintenance, "_open_read_only_connection", side_effect=replace_before_open):
            with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_restore_artifact_size_mismatch"):
                maintenance.restore(maintenance.RestoreRequest(self.workspace, bundle))
        self.assertTrue(replaced)
        self.assertFalse(self.state_path.exists())
        self.assertEqual(artifact.read_bytes(), original_bytes + b"replacement")

    def test_restore_success_and_normal_reopen(self) -> None:
        self._create_v7()
        expected = self._semantic_state(self.state_path)
        bundle = self._backup().destination
        bundle_before = {path.name: self._sha256(path) for path in bundle.iterdir()}
        self.state_path.unlink()
        result = maintenance.restore(
            maintenance.RestoreRequest(workspace_root=self.workspace, source=bundle)
        )
        self.assertEqual(result.state_path, self.state_path)
        self.assertEqual(expected, self._semantic_state(self.state_path))
        self.assertEqual(bundle_before, {path.name: self._sha256(path) for path in bundle.iterdir()})
        SQLitePreviewStore(self.context)

    def test_restore_rejects_missing_unsafe_and_unexpected_artifacts(self) -> None:
        with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_restore_artifact_missing"):
            maintenance.restore(maintenance.RestoreRequest(self.workspace, Path(self.temporary.name) / "missing"))
        unsafe = Path(self.temporary.name) / "not-a-bundle"
        unsafe.write_bytes(b"not a bundle")
        with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_restore_artifact_unsafe"):
            maintenance.restore(maintenance.RestoreRequest(self.workspace, unsafe))

        self._create_v7()
        bundle = self._backup().destination
        self.state_path.unlink()
        (bundle / "extra.txt").write_text("unexpected", encoding="utf-8")
        with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_restore_artifact_unexpected_member"):
            maintenance.restore(maintenance.RestoreRequest(self.workspace, bundle))

    def test_restore_rejects_corrupt_and_schema_shape_mismatch(self) -> None:
        self._create_v7()
        bundle = self._backup().destination
        self.state_path.unlink()
        database = bundle / "state.sqlite3"
        database.write_bytes(b"not sqlite")
        self._refresh_manifest_digest(bundle)
        with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_restore_verification_failed"):
            maintenance.restore(maintenance.RestoreRequest(self.workspace, bundle))

        self._create_v7()
        bundle = self._backup(Path(self.temporary.name) / "shape-backup").destination
        self.state_path.unlink()
        database = bundle / "state.sqlite3"
        with closing(sqlite3.connect(database)) as connection:
            index_name = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_autoindex_%' LIMIT 1"
            ).fetchone()[0]
            connection.execute(f'DROP INDEX "{index_name.replace(chr(34), chr(34) * 2)}"')
        self._refresh_manifest_digest(bundle)
        with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_restore_schema_mismatch"):
            maintenance.restore(maintenance.RestoreRequest(self.workspace, bundle))

    def test_restore_rejects_existing_target_and_each_sidecar(self) -> None:
        self._create_v7()
        bundle = self._backup().destination
        with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_restore_target_exists"):
            maintenance.restore(maintenance.RestoreRequest(self.workspace, bundle))
        self.state_path.unlink()
        for suffix in maintenance.ACTIVE_SIDECAR_SUFFIXES:
            sidecar = Path(f"{self.state_path}-{suffix}")
            sidecar.write_bytes(b"sidecar")
            with self.subTest(suffix=suffix):
                with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_restore_target_sidecar_exists"):
                    maintenance.restore(maintenance.RestoreRequest(self.workspace, bundle))
            sidecar.unlink()

    def test_restore_rejects_manifest_duplicates_unknown_fields_and_digest(self) -> None:
        self._create_v7()
        bundle = self._backup().destination
        self.state_path.unlink()
        manifest_path = bundle / "manifest.json"
        valid = manifest_path.read_text(encoding="utf-8")
        manifest_path.write_text('{"format":"delivery-system-sqlite-backup","format":"duplicate"}', encoding="utf-8")
        with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_restore_artifact_malformed"):
            maintenance.restore(maintenance.RestoreRequest(self.workspace, bundle))
        manifest_path.write_text(valid[:-1] + ',"unknown":1}', encoding="utf-8")
        with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_restore_artifact_malformed"):
            maintenance.restore(maintenance.RestoreRequest(self.workspace, bundle))
        manifest_path.write_text(valid, encoding="utf-8")
        database = bundle / "state.sqlite3"
        original = database.read_bytes()
        database.write_bytes(original + b"tampered")
        with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_restore_artifact_size_mismatch"):
            maintenance.restore(maintenance.RestoreRequest(self.workspace, bundle))

    def test_restore_rejects_release_workspace_and_schema_mismatch(self) -> None:
        self._create_v7()
        bundle = self._backup().destination
        self.state_path.unlink()
        manifest_path = bundle / "manifest.json"
        values = json.loads(manifest_path.read_text(encoding="utf-8"))
        for field, code, replacement in (
            ("release_id", "sqlite_maintenance_restore_release_mismatch", "other-release"),
            ("workspace_identity", "sqlite_maintenance_restore_workspace_mismatch", "ws_v1_other"),
            ("schema_version", "sqlite_maintenance_restore_schema_mismatch", 6),
        ):
            values[field] = replacement
            manifest_path.write_text(json.dumps(values, sort_keys=True, separators=(",", ":")), encoding="utf-8")
            with self.subTest(field=field):
                with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, code):
                    maintenance.restore(maintenance.RestoreRequest(self.workspace, bundle))
            values = json.loads(maintenance.SQLiteBackupManifest(
                format=maintenance.BACKUP_FORMAT,
                format_version=1,
                release_id=maintenance._current_release_id(),
                schema_version=7,
                workspace_identity=self.context.workspace_identity,
                database_filename="state.sqlite3",
                database_size=(bundle / "state.sqlite3").stat().st_size,
                database_sha256=self._sha256(bundle / "state.sqlite3"),
                created_at_utc="2026-09-29T00:00:00Z",
            ).to_json_bytes().decode("utf-8"))

    def test_restore_staging_failure_leaves_target_absent(self) -> None:
        self._create_v7()
        bundle = self._backup().destination
        self.state_path.unlink()
        with patch.object(maintenance, "_open_writable_maintenance_connection", side_effect=sqlite3.OperationalError("locked")):
            with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_restore_staging_failed"):
                maintenance.restore(maintenance.RestoreRequest(self.workspace, bundle))
        self.assertFalse(self.state_path.exists())

    def test_restore_activation_failure_leaves_target_absent(self) -> None:
        self._create_v7()
        bundle = self._backup().destination
        self.state_path.unlink()
        with patch.object(maintenance, "_atomic_publish_no_replace", side_effect=maintenance._AtomicPublicationError("publication_failed")):
            with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_restore_activation_failed"):
                maintenance.restore(maintenance.RestoreRequest(self.workspace, bundle))
        self.assertFalse(self.state_path.exists())

    def test_backup_and_restore_do_not_invoke_migration(self) -> None:
        self._create_v7()
        with patch.object(sqlite_schema, "ensure_schema_v4", side_effect=AssertionError("migration")), \
             patch.object(sqlite_schema, "ensure_schema_v6", side_effect=AssertionError("migration")), \
             patch.object(sqlite_schema, "ensure_schema_v7", side_effect=AssertionError("migration")):
            bundle = self._backup().destination
            self.state_path.unlink()
            maintenance.restore(maintenance.RestoreRequest(self.workspace, bundle))

    def test_cli_success_and_expected_failure_exit_contract(self) -> None:
        self._create_v7()
        destination = Path(self.temporary.name) / "cli-backup"
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(
                maintenance.main([
                    "backup",
                    "--workspace-root", str(self.workspace),
                    "--destination", str(destination),
                ]),
                0,
            )
        self.assertIn("backup succeeded:", stdout.getvalue())
        self.state_path.unlink()
        with redirect_stdout(io.StringIO()):
            self.assertEqual(
                maintenance.main([
                    "restore",
                    "--workspace-root", str(self.workspace),
                    "--source", str(destination),
                ]),
                0,
            )
        empty_workspace = Path(self.temporary.name) / "empty-cli"
        empty_workspace.mkdir()
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(
                maintenance.main([
                    "backup",
                    "--workspace-root", str(empty_workspace),
                    "--destination", str(self.temporary.name) + "-missing-parent" + "\\backup",
                ]),
                2,
            )
        self.assertIn("error: sqlite_maintenance_backup_source_missing", stderr.getvalue())

    def test_cli_busy_failure_reports_only_stable_code(self) -> None:
        self._create_v7()
        stderr = io.StringIO()
        with patch.object(maintenance, "_open_read_only_connection", side_effect=sqlite3.OperationalError("database is locked")), \
             redirect_stderr(stderr):
            result = maintenance.main([
                "backup",
                "--workspace-root", str(self.workspace),
                "--destination", str(Path(self.temporary.name) / "busy-backup"),
            ])
        self.assertEqual(result, 2)
        self.assertEqual(stderr.getvalue(), "error: sqlite_maintenance_backup_source_busy\n")

    def test_backup_publication_failure_leaves_final_destination_absent(self) -> None:
        self._create_v7()
        destination = Path(self.temporary.name) / "backup"
        with patch.object(maintenance, "_atomic_publish_no_replace", side_effect=maintenance._AtomicPublicationError("publication_failed")):
            with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_backup_creation_failed"):
                self._backup(destination)
        self.assertFalse(destination.exists())

    @unittest.skipUnless(os.name == "nt", "native no-replace publication is Windows-specific")
    def test_real_windows_native_file_publication_is_no_replace(self) -> None:
        parent = Path(self.temporary.name)
        source = parent / "source.sqlite3"
        destination = parent / "destination.sqlite3"
        source.write_bytes(b"source")
        maintenance._atomic_publish_no_replace(source, destination)
        self.assertEqual(destination.read_bytes(), b"source")
        self.assertFalse(source.exists())
        source.write_bytes(b"new-source")
        with self.assertRaises(maintenance._AtomicPublicationError):
            maintenance._atomic_publish_no_replace(source, destination)
        self.assertEqual(destination.read_bytes(), b"source")
        self.assertEqual(source.read_bytes(), b"new-source")

    @unittest.skipUnless(os.name == "nt", "native no-replace publication is Windows-specific")
    def test_real_windows_native_directory_publication_is_no_replace(self) -> None:
        parent = Path(self.temporary.name)
        source = parent / "source-bundle"
        destination = parent / "destination-bundle"
        source.mkdir()
        (source / "manifest.json").write_bytes(b"manifest")
        maintenance._atomic_publish_no_replace(source, destination)
        self.assertEqual((destination / "manifest.json").read_bytes(), b"manifest")
        source.mkdir()
        (source / "other").write_bytes(b"new")
        with self.assertRaises(maintenance._AtomicPublicationError):
            maintenance._atomic_publish_no_replace(source, destination)
        self.assertFalse((destination / "other").exists())

    @unittest.skipUnless(os.name == "nt", "native no-replace publication is Windows-specific")
    def test_real_windows_native_race_equivalent_conflict_is_no_replace(self) -> None:
        parent = Path(self.temporary.name)
        source = parent / "race-source.sqlite3"
        destination = parent / "race-destination.sqlite3"
        source.write_bytes(b"source")
        self.assertFalse(destination.exists())
        destination.write_bytes(b"late-destination")
        with self.assertRaises(maintenance._AtomicPublicationError):
            maintenance._atomic_publish_no_replace(source, destination)
        self.assertEqual(destination.read_bytes(), b"late-destination")
        self.assertEqual(source.read_bytes(), b"source")

    def test_unsupported_publication_fails_closed(self) -> None:
        with patch.object(maintenance.os, "name", "posix"):
            with self.assertRaisesRegex(maintenance.SQLiteMaintenanceError, "sqlite_maintenance_publication_unsupported"):
                maintenance._atomic_publish_no_replace(Path("source"), Path("destination"))

    def test_cli_surface_and_no_mcp_dependency(self) -> None:
        parser = maintenance.build_parser()
        self.assertEqual(parser.parse_args(["backup", "--workspace-root", "w", "--destination", "d"]).command, "backup")
        self.assertEqual(parser.parse_args(["restore", "--workspace-root", "w", "--source", "s"]).command, "restore")
        self.assertNotIn("mcp_server", Path(maintenance.__file__).read_text(encoding="utf-8"))
        self.assertNotIn("skill", Path(maintenance.__file__).read_text(encoding="utf-8").lower())


if __name__ == "__main__":
    unittest.main()
