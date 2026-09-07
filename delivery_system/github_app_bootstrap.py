"""Offline-testable Host bootstrap for GitHub App installation credentials.

The bootstrap owns the short-lived GitHub App control-plane exchange.  It
does not read environment variables, persist credentials, or expose a generic
HTTP request surface.  The returned lease is the only live credential object
that may cross into the already-reviewed Runtime composition.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import http.client
import json
import os
import re
import ssl
import stat
import threading
from typing import Any, BinaryIO, Callable, Mapping, Protocol
from urllib.parse import quote
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from .attestation_github_app import GitHubAppInstallationCapabilityEvidence
from .drivers.contract import normalize_repository_identity
from .github_app_credential import GitHubAppInstallationCredentialLease


API_HOST = "api.github.com"
API_VERSION = "2026-03-10"
USER_AGENT = "delivery-system-github-app-bootstrap-v1"
ACCEPT = "application/vnd.github+json"
CONNECT_TIMEOUT_SECONDS = 10
READ_TIMEOUT_SECONDS = 10
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_REQUEST_BYTES = 256 * 1024
MAX_PRIVATE_KEY_BYTES = 64 * 1024
MAX_GITHUB_ID = (10 ** 20) - 1
_JSON_MEDIA_TYPES = frozenset({"application/json", "application/vnd.github+json"})
_OWNER_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?\Z")
_REPOSITORY_RE = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,98}[a-z0-9])?\Z")
_FAILED = object()


class GitHubAppBootstrapError(ValueError):
    """Secret-safe public bootstrap failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _configuration_error() -> GitHubAppBootstrapError:
    return GitHubAppBootstrapError("credential_configuration_invalid")


def _acquisition_error() -> GitHubAppBootstrapError:
    return GitHubAppBootstrapError("credential_acquisition_failed")


def _attempt(operation: Callable[[], Any]) -> Any:
    """Discard implementation exceptions before a public safe error is raised."""

    try:
        return operation()
    except Exception:
        return _FAILED


def _positive_id(value: Any) -> bool:
    return type(value) is int and 1 <= value <= MAX_GITHUB_ID


def _matching_id(value: Any, expected: int) -> bool:
    return _positive_id(value) and value == expected


def _valid_token(value: Any) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 4096
        and value == value.strip()
        and all(0x21 <= ord(char) <= 0x7E for char in value)
    )


def _utc(value: Any) -> tuple[str, datetime]:
    if type(value) is not str or not value.strip():
        raise _acquisition_error()
    parsed = _attempt(lambda: datetime.fromisoformat(value.replace("Z", "+00:00")))
    if parsed is _FAILED:
        raise _acquisition_error()
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise _acquisition_error()
    normalized = parsed.astimezone(timezone.utc)
    return normalized.isoformat().replace("+00:00", "Z"), normalized


def _clock_value(clock: Callable[[], datetime]) -> datetime:
    value = _attempt(clock)
    if value is _FAILED:
        raise _acquisition_error()
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() != timezone.utc.utcoffset(value):
        raise _acquisition_error()
    return value.astimezone(timezone.utc)


def _repository_parts(repository_identity: str) -> tuple[str, str]:
    parts = repository_identity.split("/")
    if len(parts) != 2 or _OWNER_RE.fullmatch(parts[0]) is None or _REPOSITORY_RE.fullmatch(parts[1]) is None:
        raise _configuration_error()
    return parts[0], parts[1]


@dataclass(frozen=True)
class GitHubAppBootstrapConfig:
    """Non-secret authority required to acquire one installation credential."""

    app_id: int
    repository_identity: str
    repository_id: int
    private_key_path: str | os.PathLike[str]

    def __post_init__(self) -> None:
        if not _positive_id(self.app_id) or not _positive_id(self.repository_id):
            raise _configuration_error()
        try:
            repository = normalize_repository_identity(self.repository_identity)
        except (TypeError, ValueError):
            raise _configuration_error() from None
        _repository_parts(repository)
        if isinstance(self.private_key_path, os.PathLike):
            path = os.fspath(self.private_key_path)
        else:
            path = self.private_key_path
        if type(path) is not str or not path or not os.path.isabs(path):
            raise _configuration_error()
        object.__setattr__(self, "repository_identity", repository)
        object.__setattr__(self, "private_key_path", path)

    @property
    def repository_owner(self) -> str:
        return self.repository_identity.split("/", 1)[0]

    @property
    def repository_name(self) -> str:
        return self.repository_identity.split("/", 1)[1]

    def __repr__(self) -> str:
        return "<GitHubAppBootstrapConfig protected>"


class GitHubAppPrivateKeySource(Protocol):
    def load_rsa_private_key(self) -> RSAPrivateKey: ...


def _open_windows_private_key(path: str) -> BinaryIO:
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
    file_attribute_normal = 0x00000080
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
        file_attribute_normal | file_flag_open_reparse_point,
        None,
    )
    if handle == invalid_handle:
        raise OSError(ctypes.get_last_error(), "private key open failed")

    fd: int | None = None
    try:
        information = _ByHandleFileInformation()
        if get_file_type(handle) != file_type_disk or not get_information(handle, ctypes.byref(information)):
            raise OSError(ctypes.get_last_error(), "private key handle validation failed")
        if information.dwFileAttributes & (file_attribute_directory | file_attribute_reparse_point):
            raise OSError("private key path is not a regular non-reparse file")
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


def _open_posix_private_key(path: str) -> BinaryIO:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise OSError("secure no-follow open is unavailable")
    flags = os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        stream = os.fdopen(fd, "rb", closefd=True)
    except Exception:
        os.close(fd)
        raise
    return stream


def _open_private_key(path: str) -> BinaryIO:
    if os.name == "nt":
        return _open_windows_private_key(path)
    return _open_posix_private_key(path)


class FileGitHubAppPrivateKeySource:
    """Bounded, file-backed RSA key loader with secret-safe failures."""

    __slots__ = ("__path", "__opened_file_validator")

    def __init__(self, path: str | os.PathLike[str], *,
                 opened_file_validator: Callable[[int], None] | None = None) -> None:
        if isinstance(path, os.PathLike):
            path = os.fspath(path)
        if (type(path) is not str or not path or not os.path.isabs(path) or
                (opened_file_validator is not None and not callable(opened_file_validator))):
            raise _configuration_error()
        object.__setattr__(self, "_FileGitHubAppPrivateKeySource__path", path)
        object.__setattr__(self, "_FileGitHubAppPrivateKeySource__opened_file_validator", opened_file_validator)

    def __setattr__(self, name: str, value: object) -> None:
        raise _configuration_error()

    def __repr__(self) -> str:
        return "<FileGitHubAppPrivateKeySource protected>"

    def load_rsa_private_key(self) -> RSAPrivateKey:
        key = _attempt(self.__load_rsa_private_key)
        if not isinstance(key, RSAPrivateKey):
            raise _acquisition_error()
        return key

    def __load_rsa_private_key(self) -> RSAPrivateKey:
        with _open_private_key(self.__path) as stream:
            if self.__opened_file_validator is not None:
                self.__opened_file_validator(stream.fileno())
            file_stat = os.fstat(stream.fileno())
            if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size <= 0 or file_stat.st_size > MAX_PRIVATE_KEY_BYTES:
                raise _acquisition_error()
            pem = stream.read(MAX_PRIVATE_KEY_BYTES + 1)
            if len(pem) != file_stat.st_size or len(pem) > MAX_PRIVATE_KEY_BYTES:
                raise _acquisition_error()
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, RSAPrivateKey):
            raise _acquisition_error()
        return key


@dataclass(frozen=True)
class GitHubAppBootstrapResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes

    def __post_init__(self) -> None:
        if type(self.status) is not int or not 100 <= self.status <= 599:
            raise _acquisition_error()
        if type(self.body) is not bytes or not isinstance(self.headers, Mapping):
            raise _acquisition_error()
        if any(type(key) is not str or type(value) is not str for key, value in self.headers.items()):
            raise _acquisition_error()


class GitHubAppBootstrapTransport(Protocol):
    def get_app(self, app_jwt: str) -> GitHubAppBootstrapResponse: ...

    def get_repository_installation(self, app_jwt: str, repository_identity: str) -> GitHubAppBootstrapResponse: ...

    def create_installation_token(self, app_jwt: str, installation_id: int, repository_id: int) -> GitHubAppBootstrapResponse: ...

    def get_installation_repositories(self, installation_token: str) -> GitHubAppBootstrapResponse: ...

    def get_repository(self, installation_token: str, repository_identity: str) -> GitHubAppBootstrapResponse: ...


def _header(headers: Mapping[str, str], name: str) -> str | None:
    return next((value for key, value in headers.items() if key.lower() == name.lower()), None)


def _valid_json_content_type(value: str) -> bool:
    parts = value.split(";")
    if not parts or parts[0].strip().lower() not in _JSON_MEDIA_TYPES:
        return False
    if len(parts) == 1:
        return True
    if len(parts) != 2 or not parts[1].strip():
        return False
    parameter = parts[1].split("=", 1)
    if len(parameter) != 2 or parameter[0].strip().lower() != "charset":
        return False
    charset = parameter[1].strip()
    if len(charset) >= 2 and charset[0] == charset[-1] == '"':
        charset = charset[1:-1]
    return charset.lower() == "utf-8"


def _strict_json_object(body: bytes) -> Mapping[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result

    value = json.loads(body.decode("utf-8"), object_pairs_hook=reject_duplicates)
    if not isinstance(value, Mapping):
        raise ValueError("top-level JSON value must be an object")
    return value


def _json_object(response: GitHubAppBootstrapResponse, *, expected_status: int = 200) -> Mapping[str, Any]:
    if response.status != expected_status:
        raise _acquisition_error()
    content_type = _header(response.headers, "Content-Type") or ""
    if not _valid_json_content_type(content_type):
        raise _acquisition_error()
    value = _attempt(lambda: _strict_json_object(response.body))
    if value is _FAILED:
        raise _acquisition_error()
    return value


def _mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _acquisition_error()
    return value


def _text(value: Any) -> str:
    if type(value) is not str or not value.strip():
        raise _acquisition_error()
    return value.strip()


def _login(value: Any) -> str:
    value = _text(value).lower()
    if _OWNER_RE.fullmatch(value) is None:
        raise _acquisition_error()
    return value


def _permissions(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise _acquisition_error()
    allowed = {"issues", "metadata"}
    if any(type(key) is not str or key not in allowed for key in value):
        raise _acquisition_error()
    if value.get("issues") != "write":
        raise _acquisition_error()
    if "metadata" in value and value["metadata"] != "read":
        raise _acquisition_error()


def _path(repository_identity: str, suffix: str) -> str:
    owner, name = _repository_parts(repository_identity)
    return f"/repos/{quote(owner, safe='')}/{quote(name, safe='')}{suffix}"


class HttpsGitHubAppBootstrapTransport:
    """Fixed-origin, one-attempt HTTPS transport for bootstrap operations."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "<HttpsGitHubAppBootstrapTransport protected>"

    @staticmethod
    def _request(method: str, path: str, credential: str, body: bytes | None = None) -> GitHubAppBootstrapResponse:
        if method not in {"GET", "POST"} or type(path) is not str or not path.startswith("/"):
            raise _acquisition_error()
        if body is not None and (type(body) is not bytes or len(body) > MAX_REQUEST_BYTES):
            raise _acquisition_error()
        response = _attempt(lambda: HttpsGitHubAppBootstrapTransport._request_once(method, path, credential, body))
        if type(response) is not GitHubAppBootstrapResponse:
            raise _acquisition_error()
        return response

    @staticmethod
    def _request_once(method: str, path: str, credential: str, body: bytes | None) -> GitHubAppBootstrapResponse:
        headers = {
            "Accept": ACCEPT,
            "Authorization": f"Bearer {credential}",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": USER_AGENT,
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        connection = None
        try:
            connection = http.client.HTTPSConnection(
                API_HOST,
                timeout=CONNECT_TIMEOUT_SECONDS,
                context=ssl.create_default_context(),
            )
            connection.connect()
            if getattr(connection, "sock", None) is not None:
                connection.sock.settimeout(READ_TIMEOUT_SECONDS)
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise _acquisition_error()
            data = response.read(MAX_RESPONSE_BYTES + 1)
            if len(data) > MAX_RESPONSE_BYTES:
                raise _acquisition_error()
            return GitHubAppBootstrapResponse(response.status, dict(response.getheaders()), data)
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass

    def get_app(self, app_jwt: str) -> GitHubAppBootstrapResponse:
        response = _attempt(lambda: self._request("GET", "/app", app_jwt))
        del app_jwt
        if response is _FAILED:
            raise _acquisition_error()
        return response

    def get_repository_installation(self, app_jwt: str, repository_identity: str) -> GitHubAppBootstrapResponse:
        response = _attempt(lambda: self._request("GET", _path(repository_identity, "/installation"), app_jwt))
        del app_jwt
        if response is _FAILED:
            raise _acquisition_error()
        return response

    def create_installation_token(self, app_jwt: str, installation_id: int, repository_id: int) -> GitHubAppBootstrapResponse:
        response = _attempt(lambda: self._create_installation_token(app_jwt, installation_id, repository_id))
        del app_jwt
        if response is _FAILED:
            raise _acquisition_error()
        return response

    def _create_installation_token(self, app_jwt: str, installation_id: int, repository_id: int) -> GitHubAppBootstrapResponse:
        if not _positive_id(installation_id) or not _positive_id(repository_id):
            raise _acquisition_error()
        body = json.dumps(
            {"permissions": {"issues": "write"}, "repository_ids": [repository_id]},
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        return self._request("POST", f"/app/installations/{installation_id}/access_tokens", app_jwt, body)

    def get_installation_repositories(self, installation_token: str) -> GitHubAppBootstrapResponse:
        response = _attempt(lambda: self._request("GET", "/installation/repositories?per_page=100", installation_token))
        del installation_token
        if response is _FAILED:
            raise _acquisition_error()
        return response

    def get_repository(self, installation_token: str, repository_identity: str) -> GitHubAppBootstrapResponse:
        response = _attempt(lambda: self._request("GET", _path(repository_identity, ""), installation_token))
        del installation_token
        if response is _FAILED:
            raise _acquisition_error()
        return response


class GitHubAppInstallationCredentialBootstrap:
    """Acquires one exact GitHub App installation lease."""

    __slots__ = (
        "__config",
        "__private_key_source",
        "__transport",
        "__clock",
        "__instance_factory",
        "__reserved_instance_ids",
        "__instance_lock",
    )

    def __init__(
        self,
        config: GitHubAppBootstrapConfig,
        *,
        private_key_source: GitHubAppPrivateKeySource | None = None,
        transport: GitHubAppBootstrapTransport | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        credential_instance_id_factory: Callable[[], str] = lambda: str(uuid.uuid4()),
    ) -> None:
        if type(config) is not GitHubAppBootstrapConfig or not callable(clock) or not callable(credential_instance_id_factory):
            raise _configuration_error()
        if private_key_source is not None and not callable(getattr(private_key_source, "load_rsa_private_key", None)):
            raise _configuration_error()
        if transport is not None:
            required = (
                "get_app", "get_repository_installation", "create_installation_token",
                "get_installation_repositories", "get_repository",
            )
            if any(not callable(getattr(transport, name, None)) for name in required):
                raise _configuration_error()
        object.__setattr__(self, "_GitHubAppInstallationCredentialBootstrap__config", config)
        object.__setattr__(self, "_GitHubAppInstallationCredentialBootstrap__private_key_source", private_key_source or FileGitHubAppPrivateKeySource(config.private_key_path))
        object.__setattr__(self, "_GitHubAppInstallationCredentialBootstrap__transport", transport or HttpsGitHubAppBootstrapTransport())
        object.__setattr__(self, "_GitHubAppInstallationCredentialBootstrap__clock", clock)
        object.__setattr__(self, "_GitHubAppInstallationCredentialBootstrap__instance_factory", credential_instance_id_factory)
        object.__setattr__(self, "_GitHubAppInstallationCredentialBootstrap__reserved_instance_ids", set())
        object.__setattr__(self, "_GitHubAppInstallationCredentialBootstrap__instance_lock", threading.Lock())

    def __setattr__(self, name: str, value: object) -> None:
        raise _configuration_error()

    def __repr__(self) -> str:
        return "<GitHubAppInstallationCredentialBootstrap protected>"

    def _jwt(self, key: RSAPrivateKey, now: datetime) -> str:
        encoded = _attempt(
            lambda: jwt.encode(
                {"iat": int(now.timestamp()) - 60, "exp": int(now.timestamp()) + 540, "iss": str(self.__config.app_id)},
                key,
                algorithm="RS256",
            )
        )
        if type(encoded) is not str or not encoded:
            raise _acquisition_error()
        return encoded

    def _reserve_instance_id(self) -> str:
        value = _attempt(self.__instance_factory)
        if type(value) is not str:
            raise _acquisition_error()
        parsed = _attempt(lambda: uuid.UUID(value))
        if (
            parsed is _FAILED
            or str(parsed) != value.lower()
            or parsed.version != 4
            or parsed.variant != uuid.RFC_4122
        ):
            raise _acquisition_error()
        normalized = value.lower()
        with self.__instance_lock:
            if normalized in self.__reserved_instance_ids:
                raise _acquisition_error()
            self.__reserved_instance_ids.add(normalized)
        return normalized

    def acquire(self) -> GitHubAppInstallationCredentialLease:
        lease = _attempt(self.__acquire)
        if type(lease) is not GitHubAppInstallationCredentialLease:
            raise _acquisition_error()
        return lease

    def __acquire(self) -> GitHubAppInstallationCredentialLease:
        instance_id = self._reserve_instance_id()
        key = self.__private_key_source.load_rsa_private_key()
        if not isinstance(key, RSAPrivateKey):
            raise _acquisition_error()
        app_jwt = self._jwt(key, _clock_value(self.__clock))
        app = _json_object(self.__transport.get_app(app_jwt))
        if not _matching_id(app.get("id"), self.__config.app_id):
            raise _acquisition_error()
        owner = _mapping(app.get("owner"))
        if _login(owner.get("login")) != self.__config.repository_owner:
            raise _acquisition_error()

        installation = _json_object(self.__transport.get_repository_installation(app_jwt, self.__config.repository_identity))
        installation_id = installation.get("id")
        if not _positive_id(installation_id) or not _matching_id(installation.get("app_id"), self.__config.app_id):
            raise _acquisition_error()
        account = _mapping(installation.get("account"))
        account_identity = _login(account.get("login"))
        if account_identity != self.__config.repository_owner:
            raise _acquisition_error()
        if "suspended_at" not in installation or installation["suspended_at"] is not None or installation.get("repository_selection") != "selected":
            raise _acquisition_error()
        _permissions(installation.get("permissions"))

        token_response = self.__transport.create_installation_token(app_jwt, installation_id, self.__config.repository_id)
        token_data = _json_object(token_response, expected_status=201)
        if not _valid_token(token_data.get("token")):
            raise _acquisition_error()
        installation_token = token_data["token"]
        expires_at, expires = _utc(token_data.get("expires_at"))
        if expires <= _clock_value(self.__clock):
            raise _acquisition_error()
        _permissions(token_data.get("permissions"))
        if "repository_selection" in token_data and token_data["repository_selection"] != "selected":
            raise _acquisition_error()
        if "repositories" in token_data:
            repositories = token_data["repositories"]
            if type(repositories) is not list or len(repositories) != 1:
                raise _acquisition_error()
            self._validate_repository_record(_mapping(repositories[0]))

        scope_data = _json_object(self.__transport.get_installation_repositories(installation_token))
        repositories = scope_data.get("repositories")
        total_count = scope_data.get("total_count")
        if type(total_count) is not int or total_count < 0 or total_count != 1:
            raise _acquisition_error()
        if type(repositories) is not list or len(repositories) != 1:
            raise _acquisition_error()
        self._validate_repository_record(_mapping(repositories[0]))

        target = _json_object(self.__transport.get_repository(installation_token, self.__config.repository_identity))
        self._validate_repository_record(target)
        if target.get("has_issues") is not True or target.get("archived") is not False:
            raise _acquisition_error()
        if "disabled" in target and target["disabled"] is not False:
            raise _acquisition_error()
        if "private" in target and type(target["private"]) is not bool:
            raise _acquisition_error()

        observed = _clock_value(self.__clock)
        if observed >= expires:
            raise _acquisition_error()
        observed_at = observed.isoformat().replace("+00:00", "Z")
        evidence = GitHubAppInstallationCapabilityEvidence(
            app_id=self.__config.app_id,
            installation_id=installation_id,
            installation_account_identity=account_identity,
            repository_id=self.__config.repository_id,
            repository_identity=self.__config.repository_identity,
            repository_scope=(self.__config.repository_identity,),
            effective_permissions=(("issues", "write"),),
            expires_at=expires_at,
            observed_at=observed_at,
            credential_instance_id=instance_id,
        )
        return GitHubAppInstallationCredentialLease._mint(installation_token, evidence)

    def _validate_repository_record(self, value: Mapping[str, Any]) -> None:
        if not _matching_id(value.get("id"), self.__config.repository_id):
            raise _acquisition_error()
        try:
            identity = normalize_repository_identity(_text(value.get("full_name")))
        except (TypeError, ValueError):
            raise _acquisition_error() from None
        if identity != self.__config.repository_identity:
            raise _acquisition_error()
