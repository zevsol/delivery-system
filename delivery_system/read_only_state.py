"""Read an existing, standalone V7 backup image without reopening its pathname.

This validates recorded bytes and identities; Host custody and backing-file
immutability are separate requirements. Supported on Linux with /proc/self/fd.
"""

from __future__ import annotations

import hashlib
import ctypes
from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
import stat
import sys
from threading import RLock
from typing import Any, Iterator, Sequence

from . import sqlite_schema
from .sqlite_maintenance import SQLiteBackupManifest, MAX_MANIFEST_BYTES


class ReadOnlyStateError(ValueError):
    """A backup image cannot be accepted as read-only state."""


def _close_connection(connection: sqlite3.Connection) -> None:
    connection.close()


def _close_descriptor(descriptor: int) -> None:
    os.close(descriptor)


def _close_owned(*, connection: sqlite3.Connection | None = None,
                 database_fd: int | None = None, manifest_fd: int | None = None,
                 directory_fd: int | None = None) -> list[tuple[str, BaseException]]:
    """Try each owned close once, regardless of failures in earlier closes."""
    failures: list[tuple[str, BaseException]] = []
    for name, resource, closer in (
        ("connection", connection, _close_connection),
        ("database_fd", database_fd, _close_descriptor),
        ("manifest_fd", manifest_fd, _close_descriptor),
        ("directory_fd", directory_fd, _close_descriptor),
    ):
        if resource is not None:
            try:
                closer(resource)
            except BaseException as exc:
                failures.append((name, exc))
    return failures


def _record_cleanup_failures(error: BaseException,
                             failures: list[tuple[str, BaseException]]) -> None:
    if failures:
        summary = tuple(f"{name}:{type(exc).__name__}" for name, exc in failures)
        error.cleanup_failures = summary
        add_note = getattr(error, "add_note", None)
        if add_note is not None:
            add_note("read_only_cleanup_failed: " + ", ".join(summary))


def _open_directory_chain(path: Path) -> int:
    if (not path.is_absolute() or "\x00" in os.fspath(path) or sys.platform != "linux" or
            not Path("/proc/self/fd").is_dir()):
        raise ReadOnlyStateError("read_only_platform_unavailable")
    if any(part in {".", ".."} for part in path.parts):
        raise ReadOnlyStateError("read_only_path_invalid")

    class OpenHow(ctypes.Structure):
        _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64),
                    ("resolve", ctypes.c_uint64)]

    if os.uname().machine not in {"x86_64", "aarch64", "riscv64"}:
        raise ReadOnlyStateError("read_only_platform_unavailable")
    # Linux openat2: RESOLVE_NO_SYMLINKS applies to every path component.
    how = OpenHow(os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, 0, 0x04)
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(437, -100, os.fsencode(path), ctypes.byref(how), ctypes.sizeof(how))
    if result < 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()), str(path))
    return int(result)


def _open_regular(directory_fd: int, name: str) -> int:
    descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size <= 0:
            raise ReadOnlyStateError("read_only_file_invalid")
        return descriptor
    except BaseException as exc:
        _record_cleanup_failures(exc, _close_owned(database_fd=descriptor))
        raise


def _bytes_and_digest(descriptor: int, limit: int | None = None) -> tuple[bytes | None, int, str]:
    hasher = hashlib.sha256()
    size = 0
    chunks: list[bytes] = []
    duplicate = os.dup(descriptor)
    stream = None
    # Keep ownership of the duplicate here. closefd=False means that even a
    # partially failed fdopen cannot close it behind our back.
    try:
        stream = os.fdopen(duplicate, "rb", closefd=False)
        stream.seek(0)
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if limit is not None and size > limit:
                raise ReadOnlyStateError("read_only_manifest_invalid")
            hasher.update(chunk)
            if limit is not None:
                chunks.append(chunk)
    except BaseException as exc:
        failures = _close_digest_resources(stream, duplicate)
        _record_cleanup_failures(exc, failures)
        raise
    failures = _close_digest_resources(stream, duplicate)
    if failures:
        _record_cleanup_failures(failures[0][1], failures)
        raise failures[0][1]
    return (b"".join(chunks) if limit is not None else None), size, hasher.hexdigest()


def _close_digest_resources(stream: Any, descriptor: int) -> list[tuple[str, BaseException]]:
    failures: list[tuple[str, BaseException]] = []
    if stream is not None:
        try:
            stream.close()
        except BaseException as exc:
            failures.append(("digest_stream", exc))
    try:
        _close_digest_descriptor(descriptor)
    except BaseException as exc:
        failures.append(("digest_fd", exc))
    return failures


def _close_digest_descriptor(descriptor: int) -> None:
    os.close(descriptor)


class ReadOnlyState:
    """One pinned SQLite connection for validation and subsequent SELECT queries."""

    def __init__(self, connection: sqlite3.Connection, database_fd: int,
                 manifest: SQLiteBackupManifest) -> None:
        self._connection = connection
        self._database_fd = database_fd
        self._lock = RLock()
        self.manifest = manifest
        self._closed = False

    @classmethod
    def open(cls, bundle: str | os.PathLike[str], *, expected_workspace_identity: str,
             expected_release_id: str) -> "ReadOnlyState":
        if (type(expected_workspace_identity) is not str or not expected_workspace_identity or
                type(expected_release_id) is not str or not expected_release_id):
            raise ReadOnlyStateError("read_only_expectation_invalid")
        path = Path(bundle)
        directory_fd: int | None = None
        manifest_fd: int | None = None
        database_fd: int | None = None
        connection: sqlite3.Connection | None = None
        try:
            directory_fd = _open_directory_chain(path)
            if set(os.listdir(directory_fd)) != {"manifest.json", "state.sqlite3"}:
                raise ReadOnlyStateError("read_only_bundle_invalid")
            manifest_fd = _open_regular(directory_fd, "manifest.json")
            database_fd = _open_regular(directory_fd, "state.sqlite3")
            manifest_bytes, _, _ = _bytes_and_digest(manifest_fd, MAX_MANIFEST_BYTES)
            try:
                manifest = SQLiteBackupManifest.from_json_bytes(manifest_bytes or b"")
            except ValueError as exc:
                raise ReadOnlyStateError("read_only_manifest_invalid") from exc
            if (manifest.workspace_identity != expected_workspace_identity or
                    manifest.release_id != expected_release_id):
                raise ReadOnlyStateError("read_only_identity_mismatch")
            _, size, image_digest = _bytes_and_digest(database_fd)
            if size != manifest.database_size or image_digest != manifest.database_sha256:
                raise ReadOnlyStateError("read_only_digest_mismatch")
            # SQLite opens /proc/self/fd/N as a new descriptor of the already
            # opened inode. The retained descriptor keeps this link valid.
            uri = Path(f"/proc/self/fd/{database_fd}").as_uri() + "?mode=ro"
            connection = sqlite3.connect(uri, uri=True, isolation_level=None, check_same_thread=False)
            connection.execute("PRAGMA query_only=ON")
            if connection.execute("PRAGMA query_only").fetchone() != (1,):
                raise ReadOnlyStateError("read_only_connection_invalid")
            if connection.execute("PRAGMA journal_mode").fetchone() == ("wal",):
                raise ReadOnlyStateError("read_only_sidecar_required")
            databases = connection.execute("PRAGMA database_list").fetchall()
            if len(databases) != 1 or databases[0][1] != "main":
                raise ReadOnlyStateError("read_only_connection_invalid")
            sqlite_schema.validate_schema_v7_read_only(
                connection, expected_workspace_identity=expected_workspace_identity,
            )
            if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                raise ReadOnlyStateError("read_only_integrity_invalid")
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise ReadOnlyStateError("read_only_integrity_invalid")
            # A path swap cannot redirect this connection. Host immutability
            # must independently prevent edits through another writable alias.
            if os.fstat(database_fd).st_size != size:
                raise ReadOnlyStateError("read_only_file_changed")
        except BaseException as exc:
            failures = _close_owned(connection=connection, database_fd=database_fd,
                                    manifest_fd=manifest_fd, directory_fd=directory_fd)
            if isinstance(exc, (OSError, sqlite3.Error, sqlite_schema.SchemaOwnerError)):
                error = ReadOnlyStateError("read_only_state_unavailable")
                _record_cleanup_failures(error, failures)
                raise error from exc
            _record_cleanup_failures(exc, failures)
            raise

        # Temporary descriptors must be closed before ownership of the connection
        # and database descriptor is transferred to a returned instance.
        failures = _close_owned(manifest_fd=manifest_fd, directory_fd=directory_fd)
        manifest_fd = directory_fd = None
        if failures:
            failures.extend(_close_owned(connection=connection, database_fd=database_fd))
            error = ReadOnlyStateError("read_only_state_unavailable")
            _record_cleanup_failures(error, failures)
            raise error from failures[0][1]
        try:
            return cls(connection, database_fd, manifest)
        except BaseException as exc:
            _record_cleanup_failures(
                exc, _close_owned(connection=connection, database_fd=database_fd),
            )
            raise

    def query(self, statement: str, parameters: Sequence[Any] = ()) -> list[tuple[Any, ...]]:
        if type(statement) is not str or not statement.lstrip().upper().startswith("SELECT "):
            raise ReadOnlyStateError("read_only_query_invalid")
        with self._lock:
            if self._closed:
                raise ReadOnlyStateError("read_only_state_closed")
            return self._connection.execute(statement, tuple(parameters)).fetchall()

    def _detach_owned(self) -> tuple[sqlite3.Connection | None, int | None]:
        """Relinquish each resource once while holding the state lock."""
        self._closed = True
        connection, self._connection = self._connection, None
        database_fd, self._database_fd = self._database_fd, None
        return connection, database_fd

    @contextmanager
    def snapshot(self) -> Iterator["ReadOnlyState"]:
        """Hold one SQLite read transaction across a business projection."""
        with self._lock:
            if self._closed:
                raise ReadOnlyStateError("read_only_state_closed")
            self._connection.execute("BEGIN")
            try:
                yield self
            except BaseException as primary:
                if self._closed:
                    raise
                try:
                    self._connection.execute("ROLLBACK")
                except BaseException as rollback:
                    connection, database_fd = self._detach_owned()
                    failures = _close_owned(connection=connection, database_fd=database_fd)
                    _record_cleanup_failures(primary, [("rollback", rollback), *failures])
                raise
            else:
                if self._closed:
                    return
                try:
                    self._connection.execute("ROLLBACK")
                except BaseException as rollback:
                    connection, database_fd = self._detach_owned()
                    failures = _close_owned(connection=connection, database_fd=database_fd)
                    _record_cleanup_failures(rollback, failures)
                    raise

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                connection, database_fd = self._detach_owned()
                failures = _close_owned(connection=connection, database_fd=database_fd)
                if failures:
                    _record_cleanup_failures(failures[0][1], failures)
                    raise failures[0][1]

    def __enter__(self) -> "ReadOnlyState":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class _ReadOnlyCursor:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self._rows = rows
        self._offset = 0

    def fetchone(self) -> tuple[Any, ...] | None:
        if self._offset >= len(self._rows):
            return None
        row = self._rows[self._offset]
        self._offset += 1
        return row

    def fetchall(self) -> list[tuple[Any, ...]]:
        rows = self._rows[self._offset:]
        self._offset = len(self._rows)
        return rows


class _ReadOnlyQueryAdapter:
    """A closeable SELECT-only facade for existing Store read helpers."""

    def __init__(self, state: ReadOnlyState) -> None:
        if not isinstance(state, ReadOnlyState):
            raise TypeError("read_only_state_required")
        self._state = state

    def execute(self, statement: str, parameters: Sequence[Any] = ()) -> _ReadOnlyCursor:
        return _ReadOnlyCursor(self._state.query(statement, parameters))

    def close(self) -> None:
        # Existing helpers use closing(connection); the owner is ReadOnlyState.
        pass
