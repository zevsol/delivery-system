"""Fixed-scope GitHub REST write Driver for V1."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import http.client
import json
import re
import socket
import ssl
from types import MappingProxyType
from typing import Any, Mapping, Protocol
from urllib.parse import quote

from .contract import DriverError, normalize_repository_identity
from .write_contract import (CreateIssueCommand, RelationshipCommand, WriteDriver,
    WriteObservation, WriteObservationKind, WRITE_CONTRACT_VERSION, WRITE_EXECUTOR_IDENTITY)

API_HOST = "api.github.com"
API_VERSION = "2026-03-10"
USER_AGENT = "delivery-system-github-write-v1"
CONNECT_TIMEOUT_SECONDS = 10
READ_TIMEOUT_SECONDS = 10
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_WRITE_REQUEST_BYTES = 256 * 1024
MAX_GITHUB_DECIMAL_DIGITS = 20
MAX_NODE_ID_LENGTH = 512
_DECIMAL_ID = re.compile(r"[1-9][0-9]{0,19}\Z")
_REQUEST_ID = re.compile(r"application-request-[0-9a-f]{64}\Z")
_OWNER = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?\Z")
_REPOSITORY = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,98}[a-z0-9])?\Z")
_REDIRECTS = frozenset({301, 302, 303, 307, 308})
_KNOWN_REJECTIONS = frozenset({400, 401, 403, 404, 409, 410, 422, 429})
_JSON_MEDIA_TYPES = frozenset({"application/json", "application/vnd.github+json"})


class WriteTokenProvider(Protocol):
    def get_token(self) -> str | None: ...


@dataclass(frozen=True)
class WriteTransportResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes

    def __post_init__(self) -> None:
        if type(self.status) is not int or not 100 <= self.status <= 599:
            raise ValueError("github_write_response_invalid")
        if (not isinstance(self.headers, Mapping) or
                any(type(k) is not str or type(v) is not str for k, v in self.headers.items()) or
                type(self.body) is not bytes):
            raise ValueError("github_write_response_invalid")
        object.__setattr__(self, "headers", MappingProxyType(dict(self.headers)))


class WriteTransport(Protocol):
    def post(self, path: str, body: bytes, headers: Mapping[str, str]) -> WriteTransportResponse: ...


def _header(headers: Mapping[str, str], name: str) -> str | None:
    return next((v for k, v in headers.items() if k.lower() == name.lower()), None)


def _valid_json_media_type(headers: Mapping[str, str]) -> bool:
    value = _header(headers, "Content-Type")
    if not isinstance(value, str):
        return False
    media_type, *parameters = value.split(";", 1)
    if parameters:
        parameter_text = parameters[0].strip()
        if not parameter_text or "=" not in parameter_text:
            return False
    return media_type.strip().lower() in _JSON_MEDIA_TYPES


def _json_object(response: WriteTransportResponse) -> Mapping[str, Any] | None:
    if not _valid_json_media_type(response.headers):
        return None
    try:
        value = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, Mapping) else None


def _safe_decimal_id(value: str) -> int:
    if type(value) is not str or _DECIMAL_ID.fullmatch(value) is None:
        raise ValueError("write_reference_invalid")
    return int(value)


def _safe_issue_number(value: int) -> int:
    if type(value) is not int or value < 1 or len(str(value)) > MAX_GITHUB_DECIMAL_DIGITS:
        raise ValueError("write_reference_invalid")
    return value


def _validate_repository(repository: str) -> str:
    if type(repository) is not str or any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7f for c in repository):
        raise ValueError("repository_identity_invalid")
    raw_parts = repository.split("/")
    if len(raw_parts) != 2 or any(part != part.strip() for part in raw_parts):
        raise ValueError("repository_identity_invalid")
    try:
        normalized = normalize_repository_identity(repository)
    except ValueError:
        raise ValueError("repository_identity_invalid") from None
    parts = normalized.split("/")
    if (len(parts) != 2 or len(normalized) > 140 or
            any(ord(c) < 0x21 or ord(c) > 0x7e or c in "%?#\\" for c in normalized) or
            _OWNER.fullmatch(parts[0]) is None or _REPOSITORY.fullmatch(parts[1]) is None):
        raise ValueError("repository_identity_invalid")
    return normalized


def _path(repository: str, suffix: str = "") -> str:
    owner, name = _validate_repository(repository).split("/")
    path = f"/repos/{quote(owner, safe='')}/{quote(name, safe='')}/issues{suffix}"
    if not HttpsWriteTransport.valid_path(path):
        raise ValueError("github_write_path_invalid")
    return path


def _result_identity(value: Mapping[str, Any]) -> str:
    data = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    return "github-write-result-" + hashlib.sha256(data).hexdigest()


def _request_body(value: Mapping[str, Any]) -> bytes:
    error: DriverError | None = None
    try:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except (UnicodeEncodeError, TypeError, ValueError):
        error = DriverError("github_write_request_invalid")
    else:
        if len(encoded) > MAX_WRITE_REQUEST_BYTES:
            error = DriverError("github_write_request_too_large")
    if error is not None:
        raise error
    return encoded


def _credential_headers(provider: WriteTokenProvider) -> Mapping[str, str]:
    token: object = None
    failed = False
    try:
        token = provider.get_token()
    except Exception:
        failed = True
    if (failed or type(token) is not str or not 1 <= len(token) <= 4096 or token != token.strip() or
            any(not 0x21 <= ord(c) <= 0x7e for c in token)):
        raise DriverError("github_write_credential_required")
    return MappingProxyType({"Authorization": f"Bearer {token}"})


class HttpsWriteTransport:
    """Credential-free, POST-only fixed-origin transport."""

    @staticmethod
    def valid_path(path: str) -> bool:
        if type(path) is not str or len(path) > 512 or any(ord(c) < 0x21 or ord(c) > 0x7e for c in path):
            return False
        return re.fullmatch(
            r"/repos/[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?/[a-z0-9](?:[a-z0-9._-]{0,98}[a-z0-9])?/issues(?:/[1-9][0-9]{0,19}/(?:sub_issues|dependencies/blocked_by))?",
            path,
        ) is not None

    def post(self, path: str, body: bytes, headers: Mapping[str, str]) -> WriteTransportResponse:
        if not self.valid_path(path):
            raise DriverError("github_write_path_invalid")
        if type(body) is not bytes or len(body) > MAX_WRITE_REQUEST_BYTES:
            raise DriverError("github_write_request_invalid")
        if (not isinstance(headers, Mapping) or
                any(type(k) is not str or type(v) is not str for k, v in headers.items())):
            raise DriverError("github_write_request_invalid")
        request_headers = {"Accept": "application/vnd.github+json", "Content-Type": "application/json",
                           "X-GitHub-Api-Version": API_VERSION, "User-Agent": USER_AGENT}
        request_headers.update(dict(headers))
        connection = http.client.HTTPSConnection(API_HOST, timeout=CONNECT_TIMEOUT_SECONDS, context=ssl.create_default_context())
        response: WriteTransportResponse | None = None
        failure: DriverError | None = None
        try:
            connection.connect()
            if getattr(connection, "sock", None) is not None:
                connection.sock.settimeout(READ_TIMEOUT_SECONDS)
            connection.request("POST", path, body=body, headers=request_headers)
            raw = connection.getresponse()
            data = raw.read(MAX_RESPONSE_BYTES + 1)
            if len(data) > MAX_RESPONSE_BYTES:
                failure = DriverError("github_write_response_too_large")
            else:
                response = WriteTransportResponse(raw.status, dict(raw.getheaders()), data)
        except socket.timeout:
            failure = DriverError("github_write_timeout")
        except OSError:
            failure = DriverError("github_write_transport_ambiguous")
        except (ValueError, TypeError):
            failure = DriverError("github_write_response_invalid")
        try:
            connection.close()
        except Exception:
            if response is not None:
                response = None
                failure = DriverError("github_write_transport_ambiguous")
        if failure is not None:
            raise failure
        assert response is not None
        return response


class GitHubRestWriteDriver:
    """Typed GitHub V1 write boundary with operation-specific capabilities only."""

    __slots__ = ("_create_issue_capability", "_add_sub_issue_capability", "_add_dependency_capability")
    executor_identity = WRITE_EXECUTOR_IDENTITY

    def __init__(self, transport: WriteTransport, token_provider: WriteTokenProvider) -> None:
        def create(command: CreateIssueCommand) -> WriteObservation:
            return self._create_issue_dispatch(command, transport, token_provider)
        def sub_issue(command: RelationshipCommand) -> WriteObservation:
            return self._sub_issue_dispatch(command, transport, token_provider)
        def dependency(command: RelationshipCommand) -> WriteObservation:
            return self._dependency_dispatch(command, transport, token_provider)
        self._create_issue_capability = create
        self._add_sub_issue_capability = sub_issue
        self._add_dependency_capability = dependency

    @staticmethod
    def _create_issue_dispatch(command: CreateIssueCommand, transport: WriteTransport, provider: WriteTokenProvider) -> WriteObservation:
        if not isinstance(command, CreateIssueCommand):
            raise DriverError("write_command_invalid")
        repository = _validate_repository(command.repository_identity)
        if _REQUEST_ID.fullmatch(command.request_identity) is None:
            raise DriverError("write_correlation_invalid")
        if "<!-- delivery-system-request:" in command.body:
            raise DriverError("write_correlation_reserved")
        body = _request_body({"body": command.body + "\n\n<!-- delivery-system-request:" + command.request_identity + " -->", "title": command.title})
        return _create_result(command, repository, transport, provider, body)

    @staticmethod
    def _sub_issue_dispatch(command: RelationshipCommand, transport: WriteTransport, provider: WriteTokenProvider) -> WriteObservation:
        if not isinstance(command, RelationshipCommand):
            raise DriverError("write_command_invalid")
        repository = _validate_repository(command.repository_identity)
        child, parent = command.first, command.second
        parent_number = _safe_issue_number(parent.issue_number)
        child_id = _safe_decimal_id(child.numeric_issue_id)
        result = {"repository_identity": repository, "parent_issue_number": parent_number,
                  "child_numeric_issue_id": str(child_id), "direction": "child_to_parent",
                  "executor_identity": WRITE_EXECUTOR_IDENTITY, "contract_version": WRITE_CONTRACT_VERSION,
                  "response_status": 201}
        return _dispatch_relationship(transport, provider, _path(repository, f"/{parent_number}/sub_issues"),
                                       {"sub_issue_id": child_id}, result)

    @staticmethod
    def _dependency_dispatch(command: RelationshipCommand, transport: WriteTransport, provider: WriteTokenProvider) -> WriteObservation:
        if not isinstance(command, RelationshipCommand):
            raise DriverError("write_command_invalid")
        repository = _validate_repository(command.repository_identity)
        dependent, prerequisite = command.first, command.second
        dependent_number = _safe_issue_number(dependent.issue_number)
        prerequisite_id = _safe_decimal_id(prerequisite.numeric_issue_id)
        result = {"repository_identity": repository, "dependent_issue_number": dependent_number,
                  "prerequisite_numeric_issue_id": str(prerequisite_id), "direction": "dependent_to_prerequisite",
                  "executor_identity": WRITE_EXECUTOR_IDENTITY, "contract_version": WRITE_CONTRACT_VERSION,
                  "response_status": 201}
        return _dispatch_relationship(transport, provider, _path(repository, f"/{dependent_number}/dependencies/blocked_by"),
                                       {"issue_id": prerequisite_id}, result)

    def create_issue(self, command: CreateIssueCommand) -> WriteObservation:
        return self._create_issue_capability(command)

    def add_sub_issue(self, command: RelationshipCommand) -> WriteObservation:
        return self._add_sub_issue_capability(command)

    def add_dependency(self, command: RelationshipCommand) -> WriteObservation:
        return self._add_dependency_capability(command)


def _dispatch_relationship(transport: WriteTransport, provider: WriteTokenProvider, path: str,
                           request: Mapping[str, Any], result: Mapping[str, Any]) -> WriteObservation:
    headers = _credential_headers(provider)
    try:
        response = transport.post(path, _request_body(request), headers)
    except DriverError as exc:
        if exc.code == "github_write_credential_required":
            raise
        return WriteObservation(WriteObservationKind.AMBIGUOUS, code=exc.code)
    except Exception:
        return WriteObservation(WriteObservationKind.AMBIGUOUS, code="github_write_transport_ambiguous")
    return _normalize_response(response, result)


def _create_result(command: CreateIssueCommand, repository: str, transport: WriteTransport,
                  provider: WriteTokenProvider, body: bytes) -> WriteObservation:
    headers = _credential_headers(provider)
    try:
        response = transport.post(_path(repository), body, headers)
    except DriverError as exc:
        if exc.code == "github_write_credential_required":
            raise
        return WriteObservation(WriteObservationKind.AMBIGUOUS, code=exc.code)
    except Exception:
        return WriteObservation(WriteObservationKind.AMBIGUOUS, code="github_write_transport_ambiguous")
    if response.status != 201:
        return _classify_non_success(response)
    value = _json_object(response)
    if value is None or type(value.get("id")) is not int or not 1 <= value["id"] <= 10**20 - 1 or \
            type(value.get("number")) is not int or not 1 <= value["number"] <= 10**20 - 1 or \
            type(value.get("node_id")) is not str or not 1 <= len(value["node_id"].strip()) <= MAX_NODE_ID_LENGTH or \
            any(ord(c) < 0x20 or ord(c) == 0x7f for c in value.get("node_id", "")):
        return WriteObservation(WriteObservationKind.AMBIGUOUS, code="github_write_response_invalid")
    result = {"repository_identity": repository, "issue_number": value["number"], "numeric_issue_id": str(value["id"]),
              "node_id": value["node_id"], "executor_identity": WRITE_EXECUTOR_IDENTITY,
              "contract_version": WRITE_CONTRACT_VERSION, "response_status": 201}
    return WriteObservation(WriteObservationKind.DEFINITIVE_SUCCESS, result_identity=_result_identity(result), result_payload=result)


def _normalize_response(response: WriteTransportResponse, result: Mapping[str, Any]) -> WriteObservation:
    if response.status == 201:
        if _json_object(response) is None:
            return WriteObservation(WriteObservationKind.AMBIGUOUS, code="github_write_response_invalid")
        return WriteObservation(WriteObservationKind.DEFINITIVE_SUCCESS, result_identity=_result_identity(result), result_payload=result)
    return _classify_non_success(response)


def _classify_non_success(response: WriteTransportResponse) -> WriteObservation:
    if response.status in _REDIRECTS:
        return WriteObservation(WriteObservationKind.DEFINITIVE_REJECTED, code="github_write_redirect_rejected", result_payload={"status": response.status})
    if response.status == 429:
        return WriteObservation(WriteObservationKind.DEFINITIVE_REJECTED, code="github_write_rate_limited", result_payload={"status": response.status})
    if response.status in _KNOWN_REJECTIONS:
        return WriteObservation(WriteObservationKind.DEFINITIVE_REJECTED, code="github_write_rejected", result_payload={"status": response.status})
    return WriteObservation(WriteObservationKind.AMBIGUOUS, code="github_write_ambiguous", result_payload={"status": response.status})
