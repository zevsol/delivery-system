"""Application-only composition for historical reads from one validated bundle.

The caller supplies source identity and any external custody decision. This
module neither establishes custody nor starts a server or opens active state.
"""

from __future__ import annotations

from os import PathLike
from pathlib import Path
from typing import Any, Callable, Mapping

from .drivers.contract import DriverTrustContext
from .execution_store import ReadOnlyExecutionProjectionStore
from .read_only_state import ReadOnlyState, _record_cleanup_failures
from .rules import build_registry_v1
from .runtime import (
    ReadOnlyApplicationStatusProjection,
    ReadOnlyApprovalStatusProjection,
    ReadOnlyAuditContextProjection,
    ReadOnlyPreviewProjectionStore,
    RuntimeContext,
)
from .sqlite_maintenance import SQLiteBackupManifest


CustodyPolicy = Callable[[SQLiteBackupManifest, Mapping[str, Any]], bool]


class ReadOnlyComposition:
    """Own one I1 state and expose only the three I2 read projections."""

    def __init__(self, state: ReadOnlyState, context: RuntimeContext,
                 preview_store: ReadOnlyPreviewProjectionStore,
                 execution_store: ReadOnlyExecutionProjectionStore,
                 audit: ReadOnlyAuditContextProjection,
                 approval: ReadOnlyApprovalStatusProjection,
                 application: ReadOnlyApplicationStatusProjection) -> None:
        if (not isinstance(state, ReadOnlyState) or state._closed or
                not isinstance(context, RuntimeContext) or
                not isinstance(preview_store, ReadOnlyPreviewProjectionStore) or
                not isinstance(execution_store, ReadOnlyExecutionProjectionStore) or
                not isinstance(audit, ReadOnlyAuditContextProjection) or
                not isinstance(approval, ReadOnlyApprovalStatusProjection) or
                not isinstance(application, ReadOnlyApplicationStatusProjection) or
                context.workspace_identity != state.manifest.workspace_identity or
                preview_store.state is not state or execution_store._state is not state or
                preview_store.context is not context or
                audit.store is not preview_store or approval.store is not preview_store or
                application.store is not preview_store):
            raise ValueError("read_only_state_unavailable")
        self._state = state
        self._context = context
        self._preview_store = preview_store
        self._execution_store = execution_store
        self._audit = audit
        self._approval = approval
        self._application = application
        self._closed = False

    @classmethod
    def open(cls, bundle: str | PathLike[str], *, expected_workspace_identity: str,
             expected_release_id: str, trust_context: DriverTrustContext | None = None,
             custody_policy: CustodyPolicy | None = None) -> "ReadOnlyComposition":
        state = ReadOnlyState.open(
            bundle, expected_workspace_identity=expected_workspace_identity,
            expected_release_id=expected_release_id,
        )
        try:
            # Read projections use the source identity, not a locally derived
            # workspace identity. Path fields identify the bundle and are never
            # used to open a store by this composition.
            bundle_path = Path(bundle)
            context = RuntimeContext(
                str(bundle_path), str(bundle_path), expected_workspace_identity,
                str(bundle_path / "state.sqlite3"),
            )
            preview_store = ReadOnlyPreviewProjectionStore(
                context, state, trust_context=trust_context, custody_policy=custody_policy,
            )
            execution_store = ReadOnlyExecutionProjectionStore(state, expected_workspace_identity)
            audit = ReadOnlyAuditContextProjection(context, preview_store, build_registry_v1())
            approval = ReadOnlyApprovalStatusProjection(context, preview_store)
            application = ReadOnlyApplicationStatusProjection(context, preview_store, execution_store)
            return cls(state, context, preview_store, execution_store, audit, approval, application)
        except BaseException as primary:
            try:
                state.close()
            except BaseException as cleanup:
                _record_cleanup_failures(primary, [("composition_state", cleanup)])
            raise

    def _require_open(self) -> None:
        if self._closed or self._state._closed:
            raise ValueError("read_only_state_closed")

    def get_audit_context(self, preview_id: str, revision: int) -> dict[str, Any]:
        self._require_open()
        return self._audit.get_context(preview_id, revision)

    def get_approval_status(self, preview_id: str, revision: int) -> dict[str, Any]:
        self._require_open()
        return self._approval.get_status(preview_id, revision)

    def get_application_status(self, application_id: str) -> dict[str, Any]:
        self._require_open()
        return self._application.get_status(application_id)

    def get_application_status_by_approved_context(
        self, preview_id: str, revision: int, approval_id: str, approval_digest: str,
    ) -> dict[str, Any]:
        self._require_open()
        return self._application.get_status_by_approved_context(
            preview_id, revision, approval_id, approval_digest,
        )

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._state.close()

    def __enter__(self) -> "ReadOnlyComposition":
        self._require_open()
        return self

    def __exit__(self, _type: Any, primary: BaseException | None, _traceback: Any) -> None:
        if primary is None:
            self.close()
        else:
            try:
                self.close()
            except BaseException as cleanup:
                _record_cleanup_failures(primary, [("composition_state", cleanup)])
