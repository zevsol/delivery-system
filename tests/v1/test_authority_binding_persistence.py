from __future__ import annotations

from contextlib import closing
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from delivery_system import sqlite_schema
from delivery_system.attestation_persistence_store import SQLiteAttestationPersistenceStore
from delivery_system.authority_binding import (
    AuthorityBindingRecord,
    Ed25519AuthorityBindingSigner,
    SignedAuthorityBinding,
    create_signed_authority_binding,
)
from delivery_system.authority_binding_persistence import (
    AuthorityBindingPersistenceError,
    InMemoryAuthorityBindingPersistenceStore,
    SQLiteAuthorityBindingPersistenceStore,
)
from delivery_system.attestation_signing import Ed25519HostSigner
from delivery_system.execution_store import SQLiteExecutionStore
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


APPLICATION_ONE = "application-" + "a" * 64
APPLICATION_TWO = "application-" + "b" * 64
BINDING_ONE = "binding-" + "c" * 64
BINDING_TWO = "binding-" + "d" * 64
ARTIFACT_ID = "artifact-" + "e" * 64
ARTIFACT_DIGEST = "sha256:" + "f" * 64
OPERATION_ONE = "operation-" + "1" * 64
OPERATION_TWO = "operation-" + "2" * 64
OPERATION_THREE = "operation-" + "3" * 64
WORKSPACE = "workspace-1"


def signed(
    *,
    application_id: str = APPLICATION_ONE,
    credential_binding_id: str = BINDING_ONE,
    operations: tuple[str, ...] = (OPERATION_ONE, OPERATION_TWO),
    private_bytes: bytes = bytes(range(32)),
    issuer_id: str = "authority-issuer",
    key_id: str = "authority-key",
) -> SignedAuthorityBinding:
    payload = AuthorityBindingRecord.create(
        workspace_identity=WORKSPACE,
        application_id=application_id,
        credential_binding_id=credential_binding_id,
        required_capabilities=("issues:write",),
        authority_issued_at="2026-09-11T13:00:00Z",
        attestation_artifact_id=ARTIFACT_ID,
        attestation_artifact_digest=ARTIFACT_DIGEST,
        authorized_operation_identities=operations,
    )
    signer = Ed25519AuthorityBindingSigner(
        Ed25519HostSigner(issuer_id, key_id, Ed25519PrivateKey.from_private_bytes(private_bytes))
    )
    return create_signed_authority_binding(payload, signer)


class StoreBehaviorTests(unittest.TestCase):
    def test_inmemory_save_load_resolve_and_exact_idempotency(self) -> None:
        store = InMemoryAuthorityBindingPersistenceStore(workspace_identity=WORKSPACE)
        value = signed()
        first = store.save_authority_binding(value)
        second = store.save_authority_binding(value)
        self.assertEqual(first, second)
        self.assertEqual(store.load_authority_binding(WORKSPACE, value.payload.authority_issuance_id), first)
        self.assertEqual(store.resolve_authority_binding_for_operation(WORKSPACE, OPERATION_TWO), first)
        self.assertIsNone(store.resolve_authority_binding_for_operation(WORKSPACE, OPERATION_THREE))

    def test_sqlite_round_trip_preserves_exact_canonical_bytes_and_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.sqlite3"
            value = signed()
            store = SQLiteAuthorityBindingPersistenceStore(path, workspace_identity=WORKSPACE)
            saved = store.save_authority_binding(value)
            loaded = store.load_authority_binding(WORKSPACE, value.payload.authority_issuance_id)
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(loaded.canonical_payload, value.payload.canonical_bytes())
            self.assertEqual(loaded.signed, value)
            self.assertEqual(loaded.issuer_id, value.issuer_id)
            self.assertEqual(loaded.key_id, value.key_id)
            self.assertEqual(saved, loaded)
            self.assertEqual(store.resolve_authority_binding_for_operation(WORKSPACE, OPERATION_ONE), loaded)

    def test_sqlite_exact_duplicate_is_idempotent_and_envelope_change_conflicts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.sqlite3"
            store = SQLiteAuthorityBindingPersistenceStore(path, workspace_identity=WORKSPACE)
            value = signed()
            self.assertEqual(store.save_authority_binding(value), store.save_authority_binding(value))
            alternate = signed(private_bytes=bytes(range(32, 64)), issuer_id="alternate-issuer", key_id="alternate-key")
            with self.assertRaisesRegex(AuthorityBindingPersistenceError, "^authority_binding_persistence_conflict$"):
                store.save_authority_binding(alternate)

    def test_same_payload_different_envelope_is_conflict(self) -> None:
        memory = InMemoryAuthorityBindingPersistenceStore(workspace_identity=WORKSPACE)
        first = signed()
        alternate = signed(private_bytes=bytes(range(32, 64)), issuer_id="alternate-issuer", key_id="alternate-key")
        memory.save_authority_binding(first)
        with self.assertRaisesRegex(AuthorityBindingPersistenceError, "^authority_binding_persistence_conflict$"):
            memory.save_authority_binding(alternate)

    def test_operation_conflict_rolls_back_parent_and_all_assignments(self) -> None:
        for store_kind in ("memory", "sqlite"):
            with self.subTest(store_kind=store_kind):
                temporary = tempfile.TemporaryDirectory()
                self.addCleanup(temporary.cleanup)
                path = Path(temporary.name) / "state.sqlite3"
                store = (
                    InMemoryAuthorityBindingPersistenceStore(workspace_identity=WORKSPACE)
                    if store_kind == "memory"
                    else SQLiteAuthorityBindingPersistenceStore(path, workspace_identity=WORKSPACE)
                )
                first = signed(operations=(OPERATION_ONE,))
                conflicting = signed(
                    application_id=APPLICATION_TWO,
                    credential_binding_id=BINDING_TWO,
                    operations=(OPERATION_ONE, OPERATION_TWO),
                    private_bytes=bytes(range(32, 64)),
                    issuer_id="second-issuer",
                    key_id="second-key",
                )
                store.save_authority_binding(first)
                with self.assertRaisesRegex(AuthorityBindingPersistenceError, "^authority_binding_persistence_operation_conflict$"):
                    store.save_authority_binding(conflicting)
                self.assertIsNone(store.load_authority_binding(WORKSPACE, conflicting.payload.authority_issuance_id))
                self.assertIsNotNone(store.resolve_authority_binding_for_operation(WORKSPACE, OPERATION_ONE))
                self.assertIsNone(store.resolve_authority_binding_for_operation(WORKSPACE, OPERATION_TWO))
                if store_kind == "sqlite":
                    with closing(sqlite_schema._open_connection(path)) as connection:
                        self.assertEqual(connection.execute("SELECT COUNT(*) FROM authority_bindings").fetchone()[0], 1)
                        self.assertEqual(connection.execute("SELECT COUNT(*) FROM authority_binding_operations").fetchone()[0], 1)

    def test_disjoint_operations_and_multiple_application_issuances_are_allowed(self) -> None:
        store = InMemoryAuthorityBindingPersistenceStore(workspace_identity=WORKSPACE)
        first = signed(operations=(OPERATION_ONE,))
        second = signed(application_id=APPLICATION_TWO, operations=(OPERATION_TWO,), private_bytes=bytes(range(32, 64)), issuer_id="second-issuer", key_id="second-key")
        store.save_authority_binding(first)
        store.save_authority_binding(second)
        self.assertEqual(store.resolve_authority_binding_for_operation(WORKSPACE, OPERATION_ONE), store.load_authority_binding(WORKSPACE, first.payload.authority_issuance_id))
        self.assertEqual(store.resolve_authority_binding_for_operation(WORKSPACE, OPERATION_TWO), store.load_authority_binding(WORKSPACE, second.payload.authority_issuance_id))

    def test_workspace_isolation_is_enforced(self) -> None:
        store = InMemoryAuthorityBindingPersistenceStore(workspace_identity=WORKSPACE)
        value = signed()
        with self.assertRaisesRegex(AuthorityBindingPersistenceError, "^authority_binding_persistence_workspace_mismatch$"):
            store.save_authority_binding(SignedAuthorityBinding(
                AuthorityBindingRecord.create(
                    workspace_identity="workspace-2",
                    application_id=value.payload.application_id,
                    credential_binding_id=value.payload.credential_binding_id,
                    required_capabilities=value.payload.required_capabilities,
                    authority_issued_at=value.payload.authority_issued_at,
                    attestation_artifact_id=value.payload.attestation_artifact_id,
                    attestation_artifact_digest=value.payload.attestation_artifact_digest,
                    authorized_operation_identities=value.payload.authorized_operation_identities,
                ),
                value.issuer_id, value.key_id, value.signature_algorithm, value.proof,
            ))


class SQLiteSchemaTests(unittest.TestCase):
    def test_fresh_database_reaches_v7_and_existing_store_layers_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.sqlite3"
            SQLiteAuthorityBindingPersistenceStore(path, workspace_identity=WORKSPACE)
            with closing(sqlite_schema._open_connection(path)) as connection:
                self.assertEqual(connection.execute("SELECT schema_version FROM store_meta").fetchone()[0], 7)
                self.assertTrue(sqlite_schema._v7_fingerprint(connection))
                sqlite_schema.ensure_schema_v4(connection, expected_workspace_identity=WORKSPACE)
                sqlite_schema.ensure_schema_v6(connection, expected_workspace_identity=WORKSPACE)
            SQLiteAttestationPersistenceStore(path, workspace_identity=WORKSPACE).close()
            SQLiteExecutionStore(path, WORKSPACE)

    def test_v6_migration_is_additive_and_does_not_backfill_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.sqlite3"
            with closing(sqlite_schema._open_connection(path)) as connection:
                sqlite_schema.ensure_schema_v6(connection, expected_workspace_identity=WORKSPACE)
                connection.execute("INSERT INTO application_execution VALUES (?, ?, ?)", (WORKSPACE, APPLICATION_ONE, "legacy-execution"))
                connection.execute("INSERT INTO operation_attempts VALUES (?, ?, ?, ?)", (WORKSPACE, APPLICATION_ONE, OPERATION_ONE, "legacy-attempt"))
                connection.execute("INSERT INTO operation_receipts VALUES (?, ?, ?, ?)", (WORKSPACE, APPLICATION_ONE, OPERATION_ONE, "legacy-receipt"))
                connection.execute("INSERT INTO application_receipts VALUES (?, ?, ?)", (WORKSPACE, APPLICATION_ONE, "legacy-application-receipt"))
            SQLiteAuthorityBindingPersistenceStore(path, workspace_identity=WORKSPACE)
            with closing(sqlite_schema._open_connection(path)) as connection:
                self.assertEqual(connection.execute("SELECT schema_version FROM store_meta").fetchone()[0], 7)
                self.assertEqual(connection.execute("SELECT payload FROM application_execution").fetchone()[0], "legacy-execution")
                self.assertEqual(connection.execute("SELECT payload FROM operation_attempts").fetchone()[0], "legacy-attempt")
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM authority_bindings").fetchone()[0], 0)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM authority_binding_operations").fetchone()[0], 0)

    def test_v6_migration_preserves_preview_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.sqlite3"
            with closing(sqlite_schema._open_connection(path)) as connection:
                sqlite_schema.ensure_schema_v6(connection, expected_workspace_identity=WORKSPACE)
                connection.execute(
                    "INSERT INTO records VALUES (?, ?, ?, ?, ?)",
                    (WORKSPACE, "preview", "preview-1", 1, "legacy-preview"),
                )
                connection.execute(
                    "INSERT INTO audit_history VALUES (?, ?, ?, ?, ?, ?)",
                    (WORKSPACE, "audit-1", 1, "legacy-audit", "reason", "2026-09-11T13:00:00Z"),
                )
            SQLiteAuthorityBindingPersistenceStore(path, workspace_identity=WORKSPACE)
            with closing(sqlite_schema._open_connection(path)) as connection:
                self.assertEqual(connection.execute("SELECT payload FROM records").fetchone()[0], "legacy-preview")
                self.assertEqual(connection.execute("SELECT payload FROM audit_history").fetchone()[0], "legacy-audit")

    def test_failed_v7_migration_rolls_back_schema_and_tables(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.sqlite3"
            with closing(sqlite_schema._open_connection(path)) as connection:
                sqlite_schema.ensure_schema_v6(connection, expected_workspace_identity=WORKSPACE)
            with patch.object(
                sqlite_schema,
                "_execute_script",
                side_effect=sqlite_schema.SchemaOwnerError("attestation_persistence_migration_failed"),
            ):
                with self.assertRaisesRegex(AuthorityBindingPersistenceError, "^attestation_persistence_migration_failed$"):
                    SQLiteAuthorityBindingPersistenceStore(path, workspace_identity=WORKSPACE)
            with closing(sqlite_schema._open_connection(path)) as connection:
                self.assertEqual(connection.execute("SELECT schema_version FROM store_meta").fetchone()[0], 6)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM sqlite_master WHERE name = 'authority_bindings'").fetchone()[0], 0)

    def test_migrated_and_fresh_v7_schema_have_same_objects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fresh_path = Path(temporary) / "fresh.sqlite3"
            migrated_path = Path(temporary) / "migrated.sqlite3"
            SQLiteAuthorityBindingPersistenceStore(fresh_path, workspace_identity=WORKSPACE)
            with closing(sqlite_schema._open_connection(migrated_path)) as connection:
                sqlite_schema.ensure_schema_v6(connection, expected_workspace_identity=WORKSPACE)
            SQLiteAuthorityBindingPersistenceStore(migrated_path, workspace_identity=WORKSPACE)
            with closing(sqlite_schema._open_connection(fresh_path)) as fresh, closing(sqlite_schema._open_connection(migrated_path)) as migrated:
                self.assertEqual(sqlite_schema._objects(fresh), sqlite_schema._objects(migrated))
                self.assertTrue(sqlite_schema._v7_fingerprint(fresh))
                self.assertTrue(sqlite_schema._v7_fingerprint(migrated))

    def test_future_schema_version_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.sqlite3"
            SQLiteAuthorityBindingPersistenceStore(path, workspace_identity=WORKSPACE)
            with closing(sqlite_schema._open_connection(path)) as connection:
                connection.execute("UPDATE store_meta SET schema_version = 99")
            with self.assertRaisesRegex(AuthorityBindingPersistenceError, "^attestation_persistence_schema_version_unsupported$"):
                SQLiteAuthorityBindingPersistenceStore(path, workspace_identity=WORKSPACE)

    def test_corrupt_payload_and_assignment_projection_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.sqlite3"
            value = signed()
            store = SQLiteAuthorityBindingPersistenceStore(path, workspace_identity=WORKSPACE)
            store.save_authority_binding(value)
            with closing(sqlite_schema._open_connection(path)) as connection:
                connection.execute("UPDATE authority_bindings SET canonical_payload = ? WHERE authority_issuance_id = ?", (b"{}", value.payload.authority_issuance_id))
            with self.assertRaisesRegex(AuthorityBindingPersistenceError, "^authority_binding_persistence_payload_corrupt$"):
                store.load_authority_binding(WORKSPACE, value.payload.authority_issuance_id)

            path2 = Path(temporary) / "projection.sqlite3"
            value2 = signed()
            store2 = SQLiteAuthorityBindingPersistenceStore(path2, workspace_identity=WORKSPACE)
            store2.save_authority_binding(value2)
            with closing(sqlite_schema._open_connection(path2)) as connection:
                connection.execute("DELETE FROM authority_binding_operations WHERE operation_identity = ?", (OPERATION_TWO,))
            with self.assertRaisesRegex(AuthorityBindingPersistenceError, "^authority_binding_persistence_projection_corrupt$"):
                store2.load_authority_binding(WORKSPACE, value2.payload.authority_issuance_id)

    def test_corrupt_issuance_id_projection_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.sqlite3"
            value = signed()
            store = SQLiteAuthorityBindingPersistenceStore(path, workspace_identity=WORKSPACE)
            store.save_authority_binding(value)
            replacement = signed(application_id=APPLICATION_TWO, operations=(OPERATION_ONE, OPERATION_TWO))
            with closing(sqlite_schema._open_connection(path)) as connection:
                connection.execute(
                    "UPDATE authority_bindings SET canonical_payload = ? WHERE authority_issuance_id = ?",
                    (replacement.payload.canonical_bytes(), value.payload.authority_issuance_id),
                )
            with self.assertRaisesRegex(AuthorityBindingPersistenceError, "^authority_binding_persistence_issuance_id_corrupt$"):
                store.load_authority_binding(WORKSPACE, value.payload.authority_issuance_id)

    def test_concurrent_competing_assignments_have_one_winner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.sqlite3"
            SQLiteAuthorityBindingPersistenceStore(path, workspace_identity=WORKSPACE)
            values = (
                signed(application_id=APPLICATION_ONE, operations=(OPERATION_THREE,), private_bytes=bytes(range(32)), issuer_id="one", key_id="one-key"),
                signed(application_id=APPLICATION_TWO, operations=(OPERATION_THREE,), private_bytes=bytes(range(32, 64)), issuer_id="two", key_id="two-key"),
            )
            barrier = threading.Barrier(2)
            results: list[str] = []

            def save(value: SignedAuthorityBinding) -> None:
                store = SQLiteAuthorityBindingPersistenceStore(path, workspace_identity=WORKSPACE)
                barrier.wait()
                try:
                    store.save_authority_binding(value)
                    results.append("success")
                except AuthorityBindingPersistenceError as exc:
                    results.append(exc.code)

            threads = [threading.Thread(target=save, args=(value,)) for value in values]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(results.count("success"), 1)
            self.assertEqual(results.count("authority_binding_persistence_operation_conflict"), 1)
            with closing(sqlite_schema._open_connection(path)) as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM authority_bindings").fetchone()[0], 1)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM authority_binding_operations").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
