"""Offline-testable, fixed-origin GitHub REST read-only Driver.

The production transport is deliberately small and injectable. Tests provide a
FakeTransport; no adapter test needs a socket or a credential.
"""

from __future__ import annotations

from dataclasses import dataclass
import http.client
import json
import re
import socket
import ssl
import threading
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import parse_qsl, quote, urlparse

from .contract import DriverError, DriverReadResponse, ReadOnlyDriver, normalize_repository_identity

API_ORIGIN = "https://api.github.com"
API_HOST = "api.github.com"
API_VERSION = "2026-03-10"
USER_AGENT = "delivery-system-local-rest-driver/1"
MAX_PAGES_PER_COLLECTION = 100
MAX_ISSUES = 100
MAX_REQUESTS_PER_READ = 512
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
CONNECT_TIMEOUT_SECONDS = 10
READ_TIMEOUT_SECONDS = 10
AUTOMATIC_RETRIES = 0


class TokenProvider(Protocol):
    def get_token(self) -> str | None: ...


class RestTransport(Protocol):
    def request(self, method: str, path: str, headers: Mapping[str, str]) -> "TransportResponse": ...


@dataclass(frozen=True)
class TransportResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


RestDriverError = DriverError


class SecretTokenProvider:
    """Explicit token injection point; never reads process or user config."""
    def __init__(self, getter: Callable[[], str | None]) -> None:
        self._getter = getter

    def get_token(self) -> str | None:
        token = self._getter()
        return token if token else None


class HttpsRestTransport:
    def __init__(self, token_provider: TokenProvider | None = None) -> None:
        self.token_provider = token_provider

    def request(self, method: str, path: str, headers: Mapping[str, str]) -> TransportResponse:
        if method != "GET" or not path.startswith("/") or "//" in path:
            raise RestDriverError("driver_response_invalid")
        token = self.token_provider.get_token() if self.token_provider else None
        request_headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": USER_AGENT,
        }
        if token:
            request_headers["Authorization"] = f"Bearer {token}"
        request_headers.update(dict(headers))
        connection = http.client.HTTPSConnection(
            API_HOST, timeout=CONNECT_TIMEOUT_SECONDS,
            context=ssl.create_default_context(),
        )
        try:
            connection.connect()
            if getattr(connection, "sock", None) is not None:
                connection.sock.settimeout(READ_TIMEOUT_SECONDS)
            connection.request("GET", path, headers=request_headers)
            response = connection.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                raise RestDriverError("origin_redirect_forbidden")
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise RestDriverError("query_scope_incomplete")
            return TransportResponse(response.status, dict(response.getheaders()), body)
        except socket.timeout as exc:
            raise RestDriverError("remote_timeout") from exc
        except RestDriverError:
            raise
        except OSError as exc:
            raise RestDriverError("remote_transient_failure") from exc
        finally:
            connection.close()


def _header(headers: Mapping[str, str], name: str) -> str | None:
    return next((value for key, value in headers.items() if key.lower() == name.lower()), None)


def _json(response: TransportResponse) -> Any:
    content_type = _header(response.headers, "Content-Type") or ""
    if "json" not in content_type.lower():
        raise RestDriverError("driver_response_invalid")
    try:
        return json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RestDriverError("driver_response_invalid") from exc


def _status_error(status: int) -> str:
    return {401: "authentication_failed", 403: "permission_denied", 404: "remote_resource_not_found", 410: "remote_resource_gone", 429: "rate_limited"}.get(
        status, "remote_transient_failure" if status >= 500 else "driver_response_invalid"
    )


_LINK = re.compile(r"<([^>]+)>\s*;\s*rel=\"([^\"]+)\"")


class LocalRestReadOnlyDriver(ReadOnlyDriver):
    origin = API_ORIGIN
    contract_version = "github-rest-readonly-v1"
    trusted_driver_identity = "delivery-system:github-rest-readonly-v1"
    fixed_query_scope = {
        "api_origin": API_ORIGIN, "api_version": API_VERSION, "issue_state": "all",
        "pull_request_filter": "pull_request_field_excluded",
        "relationships": ["sub_issues", "parent", "blocked_by", "blocking"],
        "pagination_protocol": "link-header", "budget_profile": "github-rest-offline-v1",
    }

    def __init__(self, transport: RestTransport | None = None, token_provider: TokenProvider | None = None) -> None:
        self.transport = transport or HttpsRestTransport(token_provider)
        self.token_provider = token_provider
        self._read_state = threading.local()

    def _get(self, path: str) -> tuple[Any, Mapping[str, str]]:
        parsed = urlparse(API_ORIGIN + path)
        if parsed.scheme != "https" or parsed.netloc != API_HOST:
            raise RestDriverError("origin_redirect_forbidden")
        requests = getattr(self._read_state, "requests", 0) + 1
        self._read_state.requests = requests
        if requests > MAX_REQUESTS_PER_READ:
            raise RestDriverError("query_scope_incomplete")
        request_headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": API_VERSION, "User-Agent": USER_AGENT}
        if self.token_provider is not None:
            token = self.token_provider.get_token()
            if token:
                request_headers["Authorization"] = f"Bearer {token}"
        response = self.transport.request("GET", path, request_headers)
        if not isinstance(response, TransportResponse):
            raise RestDriverError("driver_response_invalid")
        if len(response.body) > MAX_RESPONSE_BYTES:
            raise RestDriverError("query_scope_incomplete")
        if response.status >= 300:
            if 300 <= response.status < 400:
                raise RestDriverError("origin_redirect_forbidden")
            if response.status == 403 and _header(response.headers, "X-RateLimit-Remaining") == "0":
                raise RestDriverError("rate_limited")
            raise RestDriverError(_status_error(response.status))
        return _json(response), response.headers

    def _collection(self, path: str, *, limit: int | None = None) -> list[Mapping[str, Any]]:
        values: list[Mapping[str, Any]] = []
        seen_pages: set[str] = set()
        current = path
        for _ in range(MAX_PAGES_PER_COLLECTION):
            if current in seen_pages:
                raise RestDriverError("pagination_incomplete")
            seen_pages.add(current)
            data, headers = self._get(current)
            if not isinstance(data, list) or not all(isinstance(item, Mapping) for item in data):
                raise RestDriverError("driver_response_invalid")
            values.extend(data)
            if limit is not None and len(values) > limit:
                raise RestDriverError("query_scope_incomplete")
            link_header = headers.get("Link") or headers.get("link") or _header(headers, "Link") or ""
            links = {relation: url for url, relation in _LINK.findall(link_header)}
            nxt = links.get("next")
            if not nxt:
                return values
            parsed = urlparse(nxt)
            initial = urlparse(path)
            collection_path = initial.path
            try:
                initial_pairs = parse_qsl(initial.query, keep_blank_values=True, strict_parsing=True)
                next_pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
            except ValueError as exc:
                raise RestDriverError("pagination_incomplete") from exc
            if (parsed.fragment or parsed.scheme != "https" or parsed.netloc != API_HOST or
                    parsed.path != collection_path or
                    len({key for key, _ in initial_pairs}) != len(initial_pairs) or
                    len({key for key, _ in next_pairs}) != len(next_pairs) or
                    any(not key or not value for key, value in next_pairs)):
                raise RestDriverError("pagination_incomplete")
            initial_map = dict(initial_pairs)
            next_map = dict(next_pairs)
            if any(key not in initial_map and key != "page" for key in next_map):
                raise RestDriverError("pagination_incomplete")
            if any(next_map.get(key) != value for key, value in initial_map.items() if key != "page"):
                raise RestDriverError("pagination_incomplete")
            if "page" not in next_map or not next_map["page"].isdigit() or int(next_map["page"]) < 1:
                raise RestDriverError("pagination_incomplete")
            current = parsed.path + (("?" + parsed.query) if parsed.query else "")
        raise RestDriverError("pagination_incomplete")

    @staticmethod
    def _issue(repository: str, raw: Mapping[str, Any]) -> dict[str, Any] | None:
        if raw.get("pull_request") is not None:
            return None
        required = ("id", "node_id", "number", "title", "updated_at", "repository_url")
        if any(key not in raw for key in required) or not all(raw.get(key) is not None for key in required):
            raise RestDriverError("driver_response_invalid")
        try:
            number = int(raw["number"])
        except (TypeError, ValueError) as exc:
            raise RestDriverError("driver_response_invalid") from exc
        if not isinstance(raw["title"], str) or not raw["title"].strip() or not isinstance(raw["updated_at"], str) or not raw["updated_at"].strip():
            raise RestDriverError("driver_response_invalid")
        expected_url = API_ORIGIN + "/repos/" + repository
        if str(raw["repository_url"]).rstrip("/").lower() != expected_url.lower():
            raise RestDriverError("relationship_scope_invalid")
        return {
            "issue_id": str(raw["node_id"]), "numeric_id": str(raw["id"]), "node_id": str(raw["node_id"]),
            "number": number, "item_type": "issue", "title": raw["title"],
            "updated_at": str(raw["updated_at"]), "repository_identity": repository,
            "repository_url": str(raw["repository_url"]),
        }

    def read_repository(self, repository: str, query_scope: Mapping[str, object]) -> DriverReadResponse:
        self._read_state.requests = 0
        from delivery_system.protocol import canonical_payload
        if canonical_payload(dict(query_scope)) != canonical_payload(self.fixed_query_scope):
            raise RestDriverError("query_scope_incomplete")
        requested = normalize_repository_identity(repository)
        owner, name = requested.split("/")
        prefix = f"/repos/{quote(owner, safe='')}/{quote(name, safe='')}"
        user, _ = self._get("/user")
        repo, _ = self._get(prefix)
        if not isinstance(user, Mapping) or not isinstance(repo, Mapping):
            raise RestDriverError("driver_response_invalid")
        if any(user.get(key) in (None, "") for key in ("id", "node_id", "login")):
            raise RestDriverError("driver_response_invalid")
        if any(repo.get(key) in (None, "") for key in ("id", "node_id", "full_name", "visibility")):
            raise RestDriverError("driver_response_invalid")
        if str(repo.get("full_name", "")).lower() != requested:
            raise RestDriverError("repository_identity_mismatch")
        raw_issues = self._collection(prefix + "/issues?state=all&per_page=100", limit=MAX_ISSUES)
        expected_repo_url = API_ORIGIN + prefix
        if any(str(raw.get("repository_url", "")).rstrip("/").lower() != expected_repo_url.lower() for raw in raw_issues if raw.get("pull_request") is None):
            raise RestDriverError("repository_identity_mismatch")
        issues = [item for raw in raw_issues if (item := self._issue(requested, raw)) is not None]
        by_number = {int(item["number"]): item for item in issues}
        relationships: set[tuple[str, str, str]] = set()
        for item in issues:
            number = item["number"]
            try:
                subs = self._collection(f"{prefix}/issues/{number}/sub_issues?per_page=100")
            except RestDriverError as exc:
                if exc.code in {"remote_resource_not_found", "remote_resource_gone"}:
                    raise RestDriverError("relationship_scope_invalid") from exc
                raise
            for raw in subs:
                target = self._issue(requested, raw)
                if raw.get("pull_request") is not None:
                    raise RestDriverError("relationship_scope_invalid")
                if target and target["issue_id"] in {v["issue_id"] for v in issues}:
                    relationships.add(("existing_parent", target["issue_id"], item["issue_id"]))
                elif target:
                    raise RestDriverError("relationship_scope_invalid")
            try:
                parent, _ = self._get(f"{prefix}/issues/{number}/parent")
                if isinstance(parent, Mapping):
                    if parent.get("pull_request") is not None:
                        raise RestDriverError("relationship_scope_invalid")
                    target = self._issue(requested, parent)
                    if not target or target["issue_id"] not in {v["issue_id"] for v in issues}:
                        raise RestDriverError("relationship_scope_invalid")
                    relationships.add(("existing_parent", item["issue_id"], target["issue_id"]))
            except RestDriverError as exc:
                if exc.code != "remote_resource_not_found":
                    raise
            for suffix in ("dependencies/blocked_by", "dependencies/blocking"):
                for raw in self._collection(f"{prefix}/issues/{number}/{suffix}?per_page=100"):
                    target = self._issue(requested, raw)
                    if raw.get("pull_request") is not None:
                        raise RestDriverError("relationship_scope_invalid")
                    if not target or target["issue_id"] not in {v["issue_id"] for v in issues}:
                        raise RestDriverError("relationship_scope_invalid")
                    source, dest = (item["issue_id"], target["issue_id"]) if suffix.endswith("blocked_by") else (target["issue_id"], item["issue_id"])
                    relationships.add(("existing_dependency", source, dest))
        issues.sort(key=lambda item: (item["repository_identity"], item["number"], item["issue_id"]))
        normalized_relationships = [{"kind": kind, "from": source, "to": target} for kind, source, target in sorted(relationships, key=lambda value: (value[0], value[1], value[2]))]
        query = dict(query_scope)
        query.setdefault("api_origin", API_ORIGIN)
        content = {
            "schema_version": "github-rest-remote-content-v1",
            "requested_repository": repository, "canonical_repository": requested,
            "remote_repository_id": str(repo.get("id")), "remote_repository_node_id": str(repo.get("node_id")),
            "authenticated_user_id": str(user.get("id")), "authenticated_user_node_id": str(user.get("node_id")),
            "authenticated_login": str(user.get("login")), "authenticated_subject": str(user.get("node_id")),
            "visibility": repo.get("visibility"), "permissions": {"read": bool((repo.get("permissions") or {}).get("pull")), "write": bool((repo.get("permissions") or {}).get("push"))},
            "capabilities": {"issues": True, "relationships": True}, "query_scope": query,
            "query_complete": True, "pagination_complete": True, "issue_records": issues,
            "relationship_records": normalized_relationships,
            "evidence_material": [{"source_identity": self.trusted_driver_identity, "repository_identity": requested, "query_scope": query, "payload": {"issue_records": issues, "relationship_records": normalized_relationships}}],
            "source_identity": self.trusted_driver_identity,
        }
        from delivery_system.protocol import digest
        return DriverReadResponse(
            requested_repository=repository, canonical_repository=requested,
            remote_repository_id=str(repo.get("id")), authenticated_subject=str(user.get("node_id")),
            visibility=str(repo.get("visibility")), permissions=content["permissions"],
            capabilities={"issues": True, "relationships": True}, query_scope=query,
            query_complete=True, pagination_complete=True, issue_records=issues,
            relationship_records=normalized_relationships, evidence_material=content["evidence_material"],
            source_identity=self.trusted_driver_identity, remote_content_digest=digest(content),
            remote_repository_node_id=str(repo.get("node_id")), authenticated_user_id=str(user.get("id")),
            authenticated_user_node_id=str(user.get("node_id")), authenticated_login=str(user.get("login")),
        )
