"""Secure file-backed Ed25519 Host key sources.

This module is intentionally separate from the GitHub App RSA bootstrap.  It
loads only the Ed25519 key role requested by the caller, reads from the opened
file object, and exposes only parsed cryptography key objects or stable safe
errors.
"""

from __future__ import annotations

from typing import Any, BinaryIO, Callable
import os
import stat

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


MAX_ED25519_KEY_BYTES = 64 * 1024
_FAILED = object()


class AttestationKeySourceError(ValueError):
    """Stable, secret-free error from an Ed25519 key source."""

    def __init__(self, code: str = "attestation_key_source_failed") -> None:
        super().__init__(code)
        self.code = code


def _failed() -> AttestationKeySourceError:
    return AttestationKeySourceError()


def _attempt(operation: Callable[[], Any]) -> Any:
    try:
        return operation()
    except Exception:
        return _FAILED


def _validate_path(path: str | os.PathLike[str]) -> str:
    value = os.fspath(path) if isinstance(path, os.PathLike) else path
    if type(value) is not str or not value or not value.strip() or not os.path.isabs(value):
        raise _failed()
    return value


def _open_windows_key(path: str) -> BinaryIO:
    import ctypes
    from ctypes import wintypes
    import msvcrt

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = (
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        )

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    get_file_type = kernel32.GetFileType
    get_file_type.argtypes = (wintypes.HANDLE,)
    get_file_type.restype = wintypes.DWORD
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = (wintypes.HANDLE, ctypes.POINTER(_ByHandleFileInformation))
    get_information.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    generic_read = 0x80000000
    file_share_read = 0x00000001
    open_existing = 3
    file_flag_open_reparse_point = 0x00200000
    file_type_disk = 0x0001
    file_attribute_directory = 0x00000010
    file_attribute_reparse_point = 0x00000400
    invalid_handle = ctypes.c_void_p(-1).value

    handle = create_file(
        path,
        generic_read,
        file_share_read,
        None,
        open_existing,
        file_flag_open_reparse_point,
        None,
    )
    if handle == invalid_handle:
        raise OSError("key open failed")

    fd: int | None = None
    try:
        information = _ByHandleFileInformation()
        if get_file_type(handle) != file_type_disk or not get_information(handle, ctypes.byref(information)):
            raise OSError("key handle validation failed")
        if information.dwFileAttributes & (file_attribute_directory | file_attribute_reparse_point):
            raise OSError("key is not a regular non-reparse file")
        fd = msvcrt.open_osfhandle(int(handle), os.O_RDONLY | getattr(os, "O_BINARY", 0))
        handle = None
        stream = os.fdopen(fd, "rb", closefd=True)
        fd = None
        return stream
    finally:
        if fd is not None:
            os.close(fd)
        if handle is not None:
            close_handle(handle)


def _open_posix_key(path: str) -> BinaryIO:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise OSError("secure no-follow open unavailable")
    flags = os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        stream = os.fdopen(fd, "rb", closefd=True)
    except Exception:
        os.close(fd)
        raise
    return stream


def _open_key(path: str) -> BinaryIO:
    if os.name == "nt":
        return _open_windows_key(path)
    return _open_posix_key(path)


def _read_key_bytes(path: str, opened_file_validator: Callable[[int], None] | None = None) -> bytes:
    with _open_key(path) as stream:
        if opened_file_validator is not None:
            opened_file_validator(stream.fileno())
        file_stat = os.fstat(stream.fileno())
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size <= 0 or file_stat.st_size > MAX_ED25519_KEY_BYTES:
            raise OSError("key size invalid")
        value = stream.read(MAX_ED25519_KEY_BYTES + 1)
        if len(value) != file_stat.st_size or len(value) > MAX_ED25519_KEY_BYTES:
            raise OSError("key size changed")
        return value


class FileEd25519PrivateKeySource:
    """Bounded, handle-first source for one Ed25519 private key."""

    __slots__ = ("__path", "__opened_file_validator")

    def __init__(self, path: str | os.PathLike[str], *,
                 opened_file_validator: Callable[[int], None] | None = None) -> None:
        if opened_file_validator is not None and not callable(opened_file_validator):
            raise _failed()
        object.__setattr__(self, "_FileEd25519PrivateKeySource__path", _validate_path(path))
        object.__setattr__(self, "_FileEd25519PrivateKeySource__opened_file_validator", opened_file_validator)

    def __setattr__(self, name: str, value: object) -> None:
        raise _failed()

    def __repr__(self) -> str:
        return "<FileEd25519PrivateKeySource protected>"

    def load_ed25519_private_key(self) -> Ed25519PrivateKey:
        key = _attempt(self.__load)
        if not isinstance(key, Ed25519PrivateKey):
            raise _failed()
        return key

    def __load(self) -> Ed25519PrivateKey:
        pem = _read_key_bytes(self.__path, self.__opened_file_validator)
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise OSError("wrong private key type")
        return key


class FileEd25519PublicKeySource:
    """Bounded, handle-first source for one Ed25519 public trust root."""

    __slots__ = ("__path", "__opened_file_validator")

    def __init__(self, path: str | os.PathLike[str], *,
                 opened_file_validator: Callable[[int], None] | None = None) -> None:
        if opened_file_validator is not None and not callable(opened_file_validator):
            raise _failed()
        object.__setattr__(self, "_FileEd25519PublicKeySource__path", _validate_path(path))
        object.__setattr__(self, "_FileEd25519PublicKeySource__opened_file_validator", opened_file_validator)

    def __setattr__(self, name: str, value: object) -> None:
        raise _failed()

    def __repr__(self) -> str:
        return "<FileEd25519PublicKeySource protected>"

    def load_ed25519_public_key(self) -> Ed25519PublicKey:
        key = _attempt(self.__load)
        if not isinstance(key, Ed25519PublicKey):
            raise _failed()
        return key

    def __load(self) -> Ed25519PublicKey:
        pem = _read_key_bytes(self.__path, self.__opened_file_validator)
        key = serialization.load_pem_public_key(pem)
        if not isinstance(key, Ed25519PublicKey):
            raise OSError("wrong public key type")
        return key
