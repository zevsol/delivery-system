"""Offline operator maintenance for verified SQLite backup and restore."""

from __future__ import annotations

import argparse
import ctypes
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import tempfile
from typing import Any, Callable, Mapping, Sequence

from delivery_system import sqlite_schema
from delivery_system.release_identity import ReleaseIdentityError, current_release_id
from delivery_system.runtime import (
    RuntimeContext,
    StorePreflightError,
    _canonical_path_identity,
    _is_reparse_or_symlink,
)


BACKUP_FORMAT = "delivery-system-sqlite-backup"
BACKUP_FORMAT_VERSION = 1
EXPECTED_SCHEMA_VERSION = 7
DATABASE_FILENAME = "state.sqlite3"
ACTIVE_SIDECAR_SUFFIXES = ("wal", "shm", "journal")
MAX_MANIFEST_BYTES = 65536
MANIFEST_FIELDS = frozenset({
    "format",
    "format_version",
    "release_id",
    "schema_version",
    "workspace_identity",
    "database_filename",
    "database_size",
    "database_sha256",
    "created_at_utc",
})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$"
)


class SQLiteMaintenanceError(RuntimeError):
    """Sanitized failure for an operator SQLite maintenance operation."""

    def __init__(self, code: str, *, cleanup_failed: bool = False) -> None:
        self.code = code
        self.cleanup_failed = cleanup_failed
        super().__init__(code)


@dataclass(frozen=True)
class BackupRequest:
    workspace_root: Path
    destination: Path


@dataclass(frozen=True)
class RestoreRequest:
    workspace_root: Path
    source: Path


@dataclass(frozen=True)
class BackupResult:
    destination: Path
    manifest: "SQLiteBackupManifest"


@dataclass(frozen=True)
class RestoreResult:
    state_path: Path


@dataclass(frozen=True)
class SQLiteBackupManifest:
    format: str
    format_version: int
    release_id: str
    schema_version: int
    workspace_identity: str
    database_filename: str
    database_size: int
    database_sha256: str
    created_at_utc: str

    def to_json_bytes(self) -> bytes:
        values = {
            "format": self.format,
            "format_version": self.format_version,
            "release_id": self.release_id,
            "schema_version": self.schema_version,
            "workspace_identity": self.workspace_identity,
            "database_filename": self.database_filename,
            "database_size": self.database_size,
            "database_sha256": self.database_sha256,
            "created_at_utc": self.created_at_utc,
        }
        return json.dumps(
            values,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, payload: bytes) -> "SQLiteBackupManifest":
        try:
            text = payload.decode("utf-8")

            def reject_constant(value: str) -> None:
                raise ValueError(value)

            def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
                result: dict[str, Any] = {}
                for key, value in values:
                    if key in result:
                        raise ValueError("duplicate_manifest_key")
                    result[key] = value
                return result

            value = json.loads(
                text,
                object_pairs_hook=pairs,
                parse_constant=reject_constant,
            )
            if type(value) is not dict or set(value) != MANIFEST_FIELDS:
                raise ValueError("manifest_fields")
            if type(value["format"]) is not str or value["format"] != BACKUP_FORMAT:
                raise ValueError("manifest_format")
            if type(value["format_version"]) is not int or value["format_version"] != BACKUP_FORMAT_VERSION:
                raise ValueError("manifest_format_version")
            if type(value["release_id"]) is not str or not value["release_id"].strip():
                raise ValueError("manifest_release_id")
            if type(value["schema_version"]) is not int or value["schema_version"] != EXPECTED_SCHEMA_VERSION:
                raise ValueError("manifest_schema_version")
            if type(value["workspace_identity"]) is not str or not value["workspace_identity"].strip():
                raise ValueError("manifest_workspace_identity")
            if type(value["database_filename"]) is not str or value["database_filename"] != DATABASE_FILENAME:
                raise ValueError("manifest_database_filename")
            if type(value["database_size"]) is not int or value["database_size"] < 0:
                raise ValueError("manifest_database_size")
            if type(value["database_sha256"]) is not str or not _SHA256_RE.fullmatch(value["database_sha256"]):
                raise ValueError("manifest_database_sha256")
            if type(value["created_at_utc"]) is not str or not _UTC_TIMESTAMP_RE.fullmatch(value["created_at_utc"]):
                raise ValueError("manifest_created_at")
            datetime.fromisoformat(value["created_at_utc"][:-1] + "+00:00")
            return cls(**value)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, OverflowError) as exc:
            raise ValueError("manifest_malformed") from exc


def _current_release_id() -> str:
    try:
        return current_release_id()
    except ReleaseIdentityError as exc:
        raise SQLiteMaintenanceError("sqlite_maintenance_release_unavailable") from exc


def _context_from_workspace_root(workspace_root: str | os.PathLike[str] | Path) -> RuntimeContext:
    try:
        return RuntimeContext.from_workspace_root(workspace_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise SQLiteMaintenanceError("sqlite_maintenance_backup_source_unsafe") from exc


def _sidecar_paths(state_path: Path) -> tuple[Path, ...]:
    return tuple(Path(f"{state_path}-{suffix}") for suffix in ACTIVE_SIDECAR_SUFFIXES)


def _path_present(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _require_no_sqlite_sidecars(path: Path, *, error_code: str) -> None:
    if any(_path_present(sidecar) for sidecar in _sidecar_paths(path)):
        raise SQLiteMaintenanceError(error_code)


def _validate_active_store_paths(context: RuntimeContext) -> None:
    try:
        context.validate_store_paths_read_only()
    except StorePreflightError as exc:
        raise SQLiteMaintenanceError("sqlite_maintenance_backup_source_unsafe") from exc


def _reject_reparse_chain(path: Path, *, code: str) -> None:
    current = path
    while True:
        if current.exists() and _is_reparse_or_symlink(current):
            raise SQLiteMaintenanceError(code)
        if current.parent == current:
            return
        current = current.parent


def _resolve_external_path(value: str | os.PathLike[str] | Path, *, code: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    try:
        _reject_reparse_chain(path, code=code)
        return _canonical_path_identity(path, strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise SQLiteMaintenanceError(code) from exc


def _path_same(left: Path, right: Path) -> bool:
    try:
        return _canonical_path_identity(left, strict=False) == _canonical_path_identity(right, strict=False)
    except (OSError, RuntimeError, ValueError):
        return False


def _resolve_backup_destination(context: RuntimeContext, value: Path) -> Path:
    destination = _resolve_external_path(value, code="sqlite_maintenance_backup_destination_invalid")
    parent = destination.parent
    if not parent.exists() or not parent.is_dir() or _is_reparse_or_symlink(parent):
        raise SQLiteMaintenanceError("sqlite_maintenance_backup_destination_invalid")
    active_paths = (Path(context.state_path), *_sidecar_paths(Path(context.state_path)))
    if any(_path_same(destination, active) for active in active_paths):
        raise SQLiteMaintenanceError("sqlite_maintenance_backup_destination_invalid")
    if destination.exists():
        if _is_reparse_or_symlink(destination):
            raise SQLiteMaintenanceError("sqlite_maintenance_backup_destination_invalid")
        raise SQLiteMaintenanceError("sqlite_maintenance_backup_destination_exists")
    return destination


def _resolve_bundle_source(value: Path) -> Path:
    source = _resolve_external_path(value, code="sqlite_maintenance_restore_artifact_unsafe")
    if not source.exists():
        raise SQLiteMaintenanceError("sqlite_maintenance_restore_artifact_missing")
    if not source.is_dir() or _is_reparse_or_symlink(source):
        raise SQLiteMaintenanceError("sqlite_maintenance_restore_artifact_unsafe")
    return source


def _bundle_members(source: Path) -> tuple[Path, Path]:
    try:
        entries = list(source.iterdir())
    except OSError as exc:
        raise SQLiteMaintenanceError("sqlite_maintenance_restore_artifact_unsafe") from exc
    if {entry.name for entry in entries} != {"manifest.json", DATABASE_FILENAME}:
        raise SQLiteMaintenanceError("sqlite_maintenance_restore_artifact_unexpected_member")
    manifest = source / "manifest.json"
    database = source / DATABASE_FILENAME
    for path in (manifest, database):
        if not path.is_file() or _is_reparse_or_symlink(path):
            raise SQLiteMaintenanceError("sqlite_maintenance_restore_artifact_unsafe")
        if not _path_same(path.parent, source):
            raise SQLiteMaintenanceError("sqlite_maintenance_restore_artifact_unsafe")
    return manifest, database


def _require_backup_bundle_members(source: Path) -> None:
    try:
        entries = list(source.iterdir())
    except OSError as exc:
        raise SQLiteMaintenanceError("sqlite_maintenance_backup_verification_failed") from exc
    if {entry.name for entry in entries} != {"manifest.json", DATABASE_FILENAME}:
        raise SQLiteMaintenanceError("sqlite_maintenance_backup_verification_failed")
    for path in (source / "manifest.json", source / DATABASE_FILENAME):
        if not path.is_file() or _is_reparse_or_symlink(path):
            raise SQLiteMaintenanceError("sqlite_maintenance_backup_verification_failed")


def _open_read_only_connection(path: Path) -> sqlite3.Connection:
    uri = path.resolve(strict=True).as_uri() + "?mode=ro"
    connection = sqlite3.connect(
        uri,
        uri=True,
        timeout=5,
        isolation_level=None,
        check_same_thread=False,
    )
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA query_only = ON")
        return connection
    except sqlite3.Error:
        connection.close()
        raise


def _open_writable_maintenance_connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        path,
        timeout=5,
        isolation_level=None,
        check_same_thread=False,
    )
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection
    except sqlite3.Error:
        connection.close()
        raise


def _schema_error_code(error_context: str, code: str) -> str:
    if code == "attestation_persistence_sqlite_busy":
        return "sqlite_maintenance_backup_source_busy" if error_context == "backup_source" else "sqlite_maintenance_restore_verification_failed"
    if code in {
        "attestation_persistence_schema_version_unsupported",
        "attestation_persistence_schema_shape_mismatch",
    }:
        if error_context == "backup_source":
            return "sqlite_maintenance_backup_source_schema_mismatch"
        if error_context == "restore_artifact":
            return "sqlite_maintenance_restore_schema_mismatch"
        if error_context == "restore_staging":
            return "sqlite_maintenance_restore_schema_mismatch"
        return "sqlite_maintenance_backup_verification_failed"
    if code == "attestation_persistence_workspace_mismatch":
        if error_context == "restore_artifact":
            return "sqlite_maintenance_restore_workspace_mismatch"
        return "sqlite_maintenance_backup_source_invalid"
    if error_context == "backup_source":
        return "sqlite_maintenance_backup_source_invalid"
    if error_context == "restore_artifact":
        return "sqlite_maintenance_restore_verification_failed"
    return "sqlite_maintenance_backup_verification_failed"


def _validation_failure_code(error_context: str) -> str:
    if error_context == "backup_source":
        return "sqlite_maintenance_backup_source_invalid"
    if error_context in {"restore_artifact", "restore_staging"}:
        return "sqlite_maintenance_restore_verification_failed"
    return "sqlite_maintenance_backup_verification_failed"


def _validate_v7_database(
    connection: sqlite3.Connection,
    *,
    expected_workspace_identity: str,
    error_context: str,
) -> None:
    try:
        sqlite_schema.validate_schema_v7_read_only(
            connection,
            expected_workspace_identity=expected_workspace_identity,
        )
    except sqlite_schema.SchemaOwnerError as exc:
        raise SQLiteMaintenanceError(_schema_error_code(error_context, exc.code)) from exc
    try:
        integrity = list(connection.execute("PRAGMA integrity_check"))
        if integrity != [("ok",)]:
            raise SQLiteMaintenanceError(_validation_failure_code(error_context))
        if list(connection.execute("PRAGMA foreign_key_check")):
            raise SQLiteMaintenanceError(_validation_failure_code(error_context))
    except SQLiteMaintenanceError:
        raise
    except sqlite3.OperationalError as exc:
        text = str(exc).lower()
        if "busy" in text or "locked" in text:
            if error_context == "backup_source":
                code = "sqlite_maintenance_backup_source_busy"
            elif error_context in {"restore_artifact", "restore_staging"}:
                code = "sqlite_maintenance_restore_verification_failed"
            else:
                code = "sqlite_maintenance_backup_verification_failed"
            raise SQLiteMaintenanceError(code) from exc
        raise SQLiteMaintenanceError(_validation_failure_code(error_context)) from exc
    except sqlite3.Error as exc:
        raise SQLiteMaintenanceError(_validation_failure_code(error_context)) from exc


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError as exc:
        raise SQLiteMaintenanceError("sqlite_maintenance_backup_verification_failed") from exc


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise SQLiteMaintenanceError("sqlite_maintenance_backup_verification_failed") from exc
    return digest.hexdigest()


def _manifest_for_database(
    path: Path,
    *,
    release_id: str,
    workspace_identity: str,
    now: Callable[[], datetime],
) -> SQLiteBackupManifest:
    timestamp = now().astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    return SQLiteBackupManifest(
        format=BACKUP_FORMAT,
        format_version=BACKUP_FORMAT_VERSION,
        release_id=release_id,
        schema_version=EXPECTED_SCHEMA_VERSION,
        workspace_identity=workspace_identity,
        database_filename=DATABASE_FILENAME,
        database_size=_file_size(path),
        database_sha256=_hash_file(path),
        created_at_utc=timestamp,
    )


def _validate_manifest_database(manifest: SQLiteBackupManifest, path: Path, *, error_code: str) -> None:
    if manifest.database_size != _file_size(path) or manifest.database_sha256 != _hash_file(path):
        raise SQLiteMaintenanceError(error_code)


def _validate_restore_artifact_digest(manifest: SQLiteBackupManifest, path: Path) -> None:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise SQLiteMaintenanceError("sqlite_maintenance_restore_artifact_size_mismatch") from exc
    if size != manifest.database_size:
        raise SQLiteMaintenanceError("sqlite_maintenance_restore_artifact_size_mismatch")
    try:
        digest = _hash_file(path)
    except SQLiteMaintenanceError as exc:
        raise SQLiteMaintenanceError("sqlite_maintenance_restore_artifact_digest_mismatch") from exc
    if digest != manifest.database_sha256:
        raise SQLiteMaintenanceError("sqlite_maintenance_restore_artifact_digest_mismatch")


def _read_bounded_manifest(path: Path) -> bytes:
    try:
        with path.open("rb") as stream:
            payload = stream.read(MAX_MANIFEST_BYTES + 1)
    except OSError as exc:
        raise SQLiteMaintenanceError("sqlite_maintenance_restore_artifact_malformed") from exc
    if len(payload) > MAX_MANIFEST_BYTES:
        raise SQLiteMaintenanceError("sqlite_maintenance_restore_artifact_malformed")
    return payload


def _temporary_bundle(parent: Path) -> Path:
    try:
        return Path(tempfile.mkdtemp(prefix=".delivery-system-backup-", dir=parent))
    except OSError as exc:
        raise SQLiteMaintenanceError("sqlite_maintenance_backup_creation_failed") from exc


def _temporary_database(parent: Path, *, error_code: str) -> Path:
    try:
        descriptor, name = tempfile.mkstemp(prefix=".delivery-system-state-", suffix=".sqlite3", dir=parent)
        os.close(descriptor)
        return Path(name)
    except OSError as exc:
        raise SQLiteMaintenanceError(error_code) from exc


def _atomic_publish_no_replace(source: Path, destination: Path) -> None:
    if os.name != "nt":
        raise SQLiteMaintenanceError("sqlite_maintenance_publication_unsupported")
    if source.parent != destination.parent:
        raise RuntimeError("publication_parent_mismatch")
    _move_file_ex_no_replace(source, destination)


def _move_file_ex_no_replace(source: Path, destination: Path) -> None:
    if os.name != "nt":
        raise SQLiteMaintenanceError("sqlite_maintenance_publication_unsupported")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    move_file_ex = kernel32.MoveFileExW
    move_file_ex.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    move_file_ex.restype = ctypes.c_bool
    movefile_write_through = 0x00000008
    if move_file_ex(str(source), str(destination), movefile_write_through):
        return
    error = ctypes.get_last_error()
    if error in {80, 183}:
        raise _AtomicPublicationError("destination_exists")
    raise _AtomicPublicationError("publication_failed")


class _AtomicPublicationError(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _publish(source: Path, destination: Path, *, exists_code: str, failure_code: str) -> None:
    try:
        _atomic_publish_no_replace(source, destination)
    except _AtomicPublicationError as exc:
        if exc.reason == "destination_exists":
            raise SQLiteMaintenanceError(exists_code) from exc
        raise SQLiteMaintenanceError(failure_code) from exc


def _cleanup_path(path: Path) -> None:
    if not _path_present(path):
        return
    if _is_reparse_or_symlink(path):
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def _cleanup(paths: Sequence[Path]) -> bool:
    failed = False
    for path in reversed(tuple(paths)):
        candidates = (path,) if path.is_dir() and not _is_reparse_or_symlink(path) else (
            path,
            *(Path(f"{path}-{suffix}") for suffix in ACTIVE_SIDECAR_SUFFIXES),
        )
        for candidate in candidates:
            try:
                _cleanup_path(candidate)
            except OSError:
                failed = True
    return not failed


def _with_cleanup(error: SQLiteMaintenanceError, paths: Sequence[Path]) -> SQLiteMaintenanceError:
    if paths and not _cleanup(paths):
        error.cleanup_failed = True
    return error


def backup(request: BackupRequest, *, now: Callable[[], datetime] | None = None) -> BackupResult:
    context = _context_from_workspace_root(request.workspace_root)
    _validate_active_store_paths(context)
    source_path = Path(context.state_path)
    if not source_path.exists():
        raise SQLiteMaintenanceError("sqlite_maintenance_backup_source_missing")
    if not source_path.is_file() or _is_reparse_or_symlink(source_path):
        raise SQLiteMaintenanceError("sqlite_maintenance_backup_source_invalid")
    destination = _resolve_backup_destination(context, request.destination)
    release_id = _current_release_id()
    temporary_paths: list[Path] = []
    source_connection: sqlite3.Connection | None = None
    destination_connection: sqlite3.Connection | None = None
    try:
        try:
            source_connection = _open_read_only_connection(source_path)
        except sqlite3.OperationalError as exc:
            text = str(exc).lower()
            code = "sqlite_maintenance_backup_source_busy" if "busy" in text or "locked" in text else "sqlite_maintenance_backup_source_invalid"
            raise SQLiteMaintenanceError(code) from exc
        except (OSError, sqlite3.Error) as exc:
            raise SQLiteMaintenanceError("sqlite_maintenance_backup_source_invalid") from exc
        _validate_v7_database(
            source_connection,
            expected_workspace_identity=context.workspace_identity,
            error_context="backup_source",
        )
        temporary_bundle = _temporary_bundle(destination.parent)
        temporary_paths.append(temporary_bundle)
        temporary_database = temporary_bundle / DATABASE_FILENAME
        try:
            destination_connection = _open_writable_maintenance_connection(temporary_database)
            source_connection.backup(destination_connection)
        except sqlite3.OperationalError as exc:
            text = str(exc).lower()
            code = "sqlite_maintenance_backup_creation_failed"
            raise SQLiteMaintenanceError(code) from exc
        except sqlite3.Error as exc:
            raise SQLiteMaintenanceError("sqlite_maintenance_backup_creation_failed") from exc
        finally:
            if destination_connection is not None:
                destination_connection.close()
                destination_connection = None
            if source_connection is not None:
                source_connection.close()
                source_connection = None
        try:
            with closing(_open_read_only_connection(temporary_database)) as verification_connection:
                _validate_v7_database(
                    verification_connection,
                    expected_workspace_identity=context.workspace_identity,
                    error_context="backup_copy",
                )
        except SQLiteMaintenanceError as exc:
            if exc.code == "sqlite_maintenance_backup_source_busy":
                raise SQLiteMaintenanceError("sqlite_maintenance_backup_verification_failed") from exc
            raise
        except (OSError, sqlite3.Error) as exc:
            raise SQLiteMaintenanceError("sqlite_maintenance_backup_verification_failed") from exc
        manifest = _manifest_for_database(
            temporary_database,
            release_id=release_id,
            workspace_identity=context.workspace_identity,
            now=now or (lambda: datetime.now(timezone.utc)),
        )
        try:
            (temporary_bundle / "manifest.json").write_bytes(manifest.to_json_bytes())
        except OSError as exc:
            raise SQLiteMaintenanceError("sqlite_maintenance_backup_creation_failed") from exc
        _validate_manifest_database(
            manifest,
            temporary_database,
            error_code="sqlite_maintenance_backup_verification_failed",
        )
        _require_no_sqlite_sidecars(
            temporary_database,
            error_code="sqlite_maintenance_backup_verification_failed",
        )
        _require_backup_bundle_members(temporary_bundle)
        _publish(
            temporary_bundle,
            destination,
            exists_code="sqlite_maintenance_backup_destination_exists",
            failure_code="sqlite_maintenance_backup_creation_failed",
        )
        temporary_paths.clear()
        return BackupResult(destination=destination, manifest=manifest)
    except SQLiteMaintenanceError as exc:
        raise _with_cleanup(exc, temporary_paths)
    finally:
        if destination_connection is not None:
            destination_connection.close()
        if source_connection is not None:
            source_connection.close()


def _require_empty_active_slot(context: RuntimeContext) -> None:
    try:
        context.validate_store_paths_read_only()
    except StorePreflightError as exc:
        raise SQLiteMaintenanceError("sqlite_maintenance_restore_target_exists") from exc
    state_path = Path(context.state_path)
    if state_path.exists():
        raise SQLiteMaintenanceError("sqlite_maintenance_restore_target_exists")
    for sidecar in _sidecar_paths(state_path):
        if sidecar.exists():
            raise SQLiteMaintenanceError("sqlite_maintenance_restore_target_sidecar_exists")


def _ensure_restore_parent(context: RuntimeContext) -> Path:
    parent = Path(context.state_path).parent
    if not parent.exists():
        try:
            parent.mkdir(parents=False, exist_ok=False)
        except OSError as exc:
            raise SQLiteMaintenanceError("sqlite_maintenance_restore_staging_failed") from exc
    try:
        context.validate_store_paths_read_only()
        if not parent.is_dir() or _is_reparse_or_symlink(parent):
            raise SQLiteMaintenanceError("sqlite_maintenance_restore_staging_failed")
        root = _canonical_path_identity(Path(context.normalized_workspace_root), strict=True)
        if _canonical_path_identity(parent, strict=True) != _canonical_path_identity(root / ".delivery-system", strict=False):
            raise SQLiteMaintenanceError("sqlite_maintenance_restore_staging_failed")
    except StorePreflightError as exc:
        raise SQLiteMaintenanceError("sqlite_maintenance_restore_staging_failed") from exc
    return parent


def restore(request: RestoreRequest) -> RestoreResult:
    context = _context_from_workspace_root(request.workspace_root)
    _require_empty_active_slot(context)
    source_bundle = _resolve_bundle_source(request.source)
    manifest_path, artifact_path = _bundle_members(source_bundle)
    try:
        manifest = SQLiteBackupManifest.from_json_bytes(_read_bounded_manifest(manifest_path))
    except (OSError, ValueError) as exc:
        cause = exc.__cause__
        if isinstance(cause, ValueError) and str(cause) == "manifest_schema_version":
            raise SQLiteMaintenanceError("sqlite_maintenance_restore_schema_mismatch") from exc
        raise SQLiteMaintenanceError("sqlite_maintenance_restore_artifact_malformed") from exc
    release_id = _current_release_id()
    if manifest.release_id != release_id:
        raise SQLiteMaintenanceError("sqlite_maintenance_restore_release_mismatch")
    if manifest.schema_version != EXPECTED_SCHEMA_VERSION:
        raise SQLiteMaintenanceError("sqlite_maintenance_restore_schema_mismatch")
    if manifest.workspace_identity != context.workspace_identity:
        raise SQLiteMaintenanceError("sqlite_maintenance_restore_workspace_mismatch")
    try:
        _validate_manifest_database(
            manifest,
            artifact_path,
            error_code="sqlite_maintenance_restore_artifact_digest_mismatch",
        )
    except SQLiteMaintenanceError as exc:
        if manifest.database_size != _file_size(artifact_path):
            raise SQLiteMaintenanceError("sqlite_maintenance_restore_artifact_size_mismatch") from exc
        raise
    artifact_connection: sqlite3.Connection | None = None
    staging_connection: sqlite3.Connection | None = None
    temporary_paths: list[Path] = []
    try:
        try:
            artifact_connection = _open_read_only_connection(artifact_path)
        except (OSError, sqlite3.Error) as exc:
            raise SQLiteMaintenanceError("sqlite_maintenance_restore_verification_failed") from exc
        post_open_manifest_path, post_open_artifact_path = _bundle_members(source_bundle)
        if post_open_manifest_path != manifest_path or post_open_artifact_path != artifact_path:
            raise SQLiteMaintenanceError("sqlite_maintenance_restore_artifact_unsafe")
        _validate_restore_artifact_digest(manifest, artifact_path)
        _validate_v7_database(
            artifact_connection,
            expected_workspace_identity=context.workspace_identity,
            error_context="restore_artifact",
        )
        parent = _ensure_restore_parent(context)
        staging_path = _temporary_database(
            parent,
            error_code="sqlite_maintenance_restore_staging_failed",
        )
        temporary_paths.append(staging_path)
        try:
            staging_connection = _open_writable_maintenance_connection(staging_path)
            artifact_connection.backup(staging_connection)
        except sqlite3.Error as exc:
            raise SQLiteMaintenanceError("sqlite_maintenance_restore_staging_failed") from exc
        finally:
            if staging_connection is not None:
                staging_connection.close()
                staging_connection = None
            if artifact_connection is not None:
                artifact_connection.close()
                artifact_connection = None
        try:
            with closing(_open_read_only_connection(staging_path)) as verification_connection:
                _validate_v7_database(
                    verification_connection,
                    expected_workspace_identity=context.workspace_identity,
                    error_context="restore_staging",
                )
        except SQLiteMaintenanceError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise SQLiteMaintenanceError("sqlite_maintenance_restore_verification_failed") from exc
        _require_empty_active_slot(context)
        _require_no_sqlite_sidecars(
            staging_path,
            error_code="sqlite_maintenance_restore_staging_failed",
        )
        _publish(
            staging_path,
            Path(context.state_path),
            exists_code="sqlite_maintenance_restore_target_exists",
            failure_code="sqlite_maintenance_restore_activation_failed",
        )
        _require_no_sqlite_sidecars(
            staging_path,
            error_code="sqlite_maintenance_restore_activation_failed",
        )
        temporary_paths.clear()
        return RestoreResult(state_path=Path(context.state_path))
    except SQLiteMaintenanceError as exc:
        raise _with_cleanup(exc, temporary_paths)
    finally:
        if staging_connection is not None:
            staging_connection.close()
        if artifact_connection is not None:
            artifact_connection.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m delivery_system.sqlite_maintenance")
    subparsers = parser.add_subparsers(dest="command", required=True)
    backup_parser = subparsers.add_parser("backup")
    backup_parser.add_argument("--workspace-root", required=True)
    backup_parser.add_argument("--destination", required=True)
    restore_parser = subparsers.add_parser("restore")
    restore_parser.add_argument("--workspace-root", required=True)
    restore_parser.add_argument("--source", required=True)
    return parser


def _run_backup_command(arguments: argparse.Namespace) -> int:
    result = backup(
        BackupRequest(
            workspace_root=Path(arguments.workspace_root),
            destination=Path(arguments.destination),
        )
    )
    print(f"backup succeeded: {result.destination}")
    return 0


def _run_restore_command(arguments: argparse.Namespace) -> int:
    result = restore(
        RestoreRequest(
            workspace_root=Path(arguments.workspace_root),
            source=Path(arguments.source),
        )
    )
    print(f"restore succeeded: {result.state_path}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        arguments = parser.parse_args(argv)
        if arguments.command == "backup":
            return _run_backup_command(arguments)
        return _run_restore_command(arguments)
    except SQLiteMaintenanceError as exc:
        print(f"error: {exc.code}", file=os.sys.stderr)
        return 2
    except Exception:
        print("error: sqlite_maintenance_internal_failure", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
