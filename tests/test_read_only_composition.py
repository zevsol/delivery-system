"""Application composition tests using only disposable synthetic V7 bundles."""

from __future__ import annotations

import os
import sqlite3
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from delivery_system import read_only_composition as composition_module
from delivery_system.read_only_composition import ReadOnlyComposition
from delivery_system.read_only_state import ReadOnlyState, ReadOnlyStateError
from tests import test_read_only_projections as fixtures


@unittest.skipUnless(os.name == "posix" and Path("/proc/self/fd").is_dir(), "Linux proc fd required")
class ReadOnlyCompositionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = fixtures.ReadOnlyProjectionTests(
            "test_conceptual_audit_context_needs_no_driver_or_policy"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def open(self, *, workspace: str | None = None, release: str = fixtures.RELEASE,
             trust=None, policy=None) -> ReadOnlyComposition:
        return ReadOnlyComposition.open(
            self.fixture.bundle,
            expected_workspace_identity=workspace or self.fixture.context.workspace_identity,
            expected_release_id=release,
            trust_context=trust,
            custody_policy=policy,
        )

    def test_explicit_identity_release_and_one_state_for_all_projections(self) -> None:
        source = self.fixture.context.workspace_identity
        with patch.object(ReadOnlyState, "open", wraps=ReadOnlyState.open) as opener:
            with self.open() as composition:
                opener.assert_called_once_with(
                    self.fixture.bundle, expected_workspace_identity=source,
                    expected_release_id=fixtures.RELEASE,
                )
                state = composition._state
                self.assertIs(composition._preview_store.state, state)
                self.assertIs(composition._execution_store._state, state)
                self.assertIs(composition._audit.store.state, state)
                self.assertIs(composition._approval.store.state, state)
                self.assertIs(composition._application.store.state, state)
                self.assertEqual(composition._context.workspace_identity, source)
                self.assertEqual(composition._context.state_path,
                                 str(self.fixture.bundle / "state.sqlite3"))

    def test_direct_constructor_rejects_mismatched_state(self) -> None:
        with self.open() as composition, self.fixture.open_state() as other_state:
            with self.assertRaisesRegex(ValueError, "read_only_state_unavailable"):
                ReadOnlyComposition(
                    other_state, composition._context, composition._preview_store,
                    composition._execution_store, composition._audit,
                    composition._approval, composition._application,
                )

    def test_conceptual_projection_outputs_and_transaction_cleanup(self) -> None:
        with self.open() as composition:
            preview_id = self.fixture.preview["preview_id"]
            audit = composition.get_audit_context(preview_id, 1)
            self.assertEqual(audit["context_status"], "audit_ready")
            self.assertEqual(audit["audit_scope"], "Conceptual")
            self.assertFalse(any(record["source_kind"] == "driver"
                                 for record in audit["evidence_records"]))
            with self.assertRaisesRegex(ValueError, "audit_not_found"):
                composition.get_approval_status(preview_id, 1)
            with self.assertRaisesRegex(ValueError, "application_not_found"):
                composition.get_application_status("application-" + "0" * 64)
            self.assertFalse(composition._state._connection.in_transaction)

    def test_audited_preview_without_approval_preserves_status(self) -> None:
        preview, _audit = self.fixture.add_write_preview_and_audit()
        with self.open(trust=fixtures.TRUST,
                       policy=lambda _manifest, _canonical: True) as composition:
            status = composition.get_approval_status(preview["preview_id"], 1)
            self.assertEqual(status["status"], "NO_CURRENT_APPROVAL")
            self.assertIsNone(status["approval"])

    def test_application_status_preserves_both_lookup_modes(self) -> None:
        preview = self.fixture.add_repository_preview(with_operation=True)
        execution = self.fixture.add_pending_application(preview)
        with self.open(trust=fixtures.TRUST, policy=lambda _manifest, _canonical: True) as composition:
            by_id = composition.get_application_status(execution.application_id)
            self.assertEqual(by_id["state"], "Pending")
            values = execution.identity.values()
            by_context = composition.get_application_status_by_approved_context(
                preview["preview_id"], preview["revision"],
                values["approval_id"], values["approval_digest"],
            )
            self.assertEqual(by_context, by_id)
            self.assertFalse(composition._state._connection.in_transaction)

    def test_missing_invalid_and_mismatched_bundle_fail_without_creation(self) -> None:
        missing = Path(self.fixture.temp.name) / "absent-bundle"
        with self.assertRaises((ReadOnlyStateError, OSError)):
            ReadOnlyComposition.open(
                missing, expected_workspace_identity=self.fixture.context.workspace_identity,
                expected_release_id=fixtures.RELEASE,
            )
        self.assertFalse(missing.exists())
        for workspace, release in (("other-source", fixtures.RELEASE),
                                   (self.fixture.context.workspace_identity, "other-release")):
            with self.subTest(workspace=workspace, release=release):
                with self.assertRaisesRegex(ReadOnlyStateError, "read_only_identity_mismatch"):
                    self.open(workspace=workspace, release=release)
        (self.fixture.bundle / "unexpected").write_text("synthetic", encoding="utf-8")
        with self.assertRaisesRegex(ReadOnlyStateError, "read_only_bundle_invalid"):
            self.open()

    def test_later_constructor_failure_closes_state_and_preserves_primary(self) -> None:
        state = self.fixture.open_state()
        self.addCleanup(state.close)
        primary = RuntimeError("synthetic-constructor-failure")
        with patch.object(ReadOnlyState, "open", return_value=state), patch.object(
            composition_module, "ReadOnlyApplicationStatusProjection", side_effect=primary,
        ), patch.object(state, "close", wraps=state.close) as closer:
            with self.assertRaises(RuntimeError) as caught:
                self.open()
        self.assertIs(caught.exception, primary)
        closer.assert_called_once_with()
        self.assertTrue(state._closed)
        self.assertIsNone(state._connection)
        self.assertIsNone(state._database_fd)

    def test_later_constructor_and_cleanup_failure_preserve_primary(self) -> None:
        state = self.fixture.open_state()
        self.addCleanup(state.close)
        primary = RuntimeError("synthetic-constructor-failure")
        actual_close = state.close
        calls = []

        def close_then_fail():
            calls.append("close")
            actual_close()
            raise OSError("synthetic-close-failure")

        with patch.object(ReadOnlyState, "open", return_value=state), patch.object(
            composition_module, "ReadOnlyApplicationStatusProjection", side_effect=primary,
        ), patch.object(state, "close", side_effect=close_then_fail):
            with self.assertRaises(RuntimeError) as caught:
                self.open()
        self.assertIs(caught.exception, primary)
        self.assertEqual(calls, ["close"])
        self.assertEqual(primary.cleanup_failures, ("composition_state:OSError",))
        self.assertTrue(state._closed)

    def test_close_is_once_only_and_post_close_calls_fail_before_query(self) -> None:
        composition = self.open()
        state = composition._state
        with patch.object(state, "close", wraps=state.close) as closer, patch.object(
            state, "query", side_effect=AssertionError("query after close"),
        ):
            composition.close()
            composition.close()
            closer.assert_called_once_with()
            for call in (
                lambda: composition.get_audit_context("preview", 1),
                lambda: composition.get_approval_status("preview", 1),
                lambda: composition.get_application_status("application-" + "0" * 64),
                lambda: composition.get_application_status_by_approved_context("preview", 1, "a", "d"),
            ):
                with self.assertRaisesRegex(ValueError, "read_only_state_closed"):
                    call()
        self.assertIsNone(state._database_fd)

    def test_close_failure_invalidates_without_retrying_resources(self) -> None:
        composition = self.open()
        state = composition._state
        actual_close = state.close
        calls = []

        def close_then_fail():
            calls.append("close")
            actual_close()
            raise OSError("synthetic-close-failure")

        with patch.object(state, "close", side_effect=close_then_fail):
            with self.assertRaises(OSError):
                composition.close()
            composition.close()
        self.assertEqual(calls, ["close"])
        self.assertTrue(state._closed)
        with self.assertRaisesRegex(ValueError, "read_only_state_closed"):
            composition.get_approval_status(self.fixture.preview["preview_id"], 1)

    def test_context_manager_preserves_body_exception_if_close_fails(self) -> None:
        composition = self.open()
        primary = RuntimeError("synthetic-body-failure")
        actual_close = composition._state.close

        def close_then_fail():
            actual_close()
            raise OSError("synthetic-close-failure")

        with patch.object(composition._state, "close", side_effect=close_then_fail):
            with self.assertRaises(RuntimeError) as caught:
                with composition:
                    raise primary
        self.assertIs(caught.exception, primary)
        self.assertEqual(primary.cleanup_failures, ("composition_state:OSError",))

    def test_repository_and_write_eligible_custody_fail_closed(self) -> None:
        repository = self.fixture.add_repository_preview()
        for policy in (None, lambda _manifest, _canonical: False):
            with self.subTest(level="RepositoryAware", policy=policy), self.open(
                trust=fixtures.TRUST, policy=policy,
            ) as composition:
                with self.assertRaisesRegex(ValueError, "repository_aware_promotion_required"):
                    composition.get_audit_context(repository["preview_id"], 1)
        write_preview, _ = self.fixture.add_write_preview_and_audit()
        with self.open(trust=fixtures.TRUST) as composition:
            with self.assertRaisesRegex(ValueError, "repository_aware_promotion_required"):
                composition.get_audit_context(write_preview["preview_id"], 1)

    def test_composition_uses_only_pinned_sqlite_and_no_writable_services(self) -> None:
        real_connect = sqlite3.connect
        seen = []

        def pinned_connect(path, *args, **kwargs):
            seen.append(str(path))
            if not str(path).startswith("file:///proc/self/fd/"):
                raise AssertionError("pathname reopen")
            return real_connect(path, *args, **kwargs)

        forbidden = (
            "delivery_system.runtime.RuntimeContext.from_workspace_root",
            "delivery_system.runtime.RuntimeContext.ensure_store_ready",
            "delivery_system.runtime.SQLitePreviewStore.__init__",
            "delivery_system.execution_store.SQLiteExecutionStore.__init__",
            "delivery_system.runtime.RuntimeApprovalAuthorityService.__init__",
            "delivery_system.sqlite_schema.ensure_schema_v4",
            "delivery_system.sqlite_schema.ensure_schema_v6",
            "delivery_system.sqlite_schema.ensure_schema_v7",
            "delivery_system.sqlite_maintenance.backup",
            "delivery_system.sqlite_maintenance.restore",
            "delivery_system.applier.Applier.__init__",
            "delivery_system.drivers.rest.GitHubAppInstallationReadOnlyDriver.__init__",
        )
        with ExitStack() as stack:
            for symbol in forbidden:
                stack.enter_context(patch(symbol, side_effect=AssertionError(symbol)))
            stack.enter_context(patch(
                "delivery_system.read_only_state.sqlite3.connect", side_effect=pinned_connect,
            ))
            with self.open() as composition:
                result = composition.get_audit_context(self.fixture.preview["preview_id"], 1)
                self.assertEqual(result["context_status"], "audit_ready")
        self.assertEqual(len(seen), 1)


if __name__ == "__main__":
    unittest.main()
