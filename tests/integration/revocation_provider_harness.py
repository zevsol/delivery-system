"""Bounded loopback revocation provider for the V1-INT1 integration harness.

This module is intentionally an integration-test component rather than a
production revocation service.  Its policy is fixed to the V1-INT1 test
repository and attestation identity, and its state is process-local only.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hmac
import http.server
import json
import re
import socket
import sys
from pathlib import Path
from threading import Thread
from typing import Any, Callable, Mapping, Sequence


LOOPBACK_ADDRESS = "127.0.0.1"
ENDPOINT_PATH = "/v1/status"
MAX_REQUEST_BYTES = 64 * 1024
MAX_TOKEN_BYTES = 4096

INT1_REPOSITORY = "zevsol/delivery-system-integration-test"
INT1_ISSUER = "v1-int1-attestation"
INT1_KEY_ID = "v1-int1-attestation-key"
INT1_VERSION = "1"

REQUEST_FIELDS = frozenset(
    {
        "issuer_id",
        "credential_instance_id",
        "attestation_id",
        "key_id",
        "version",
        "repository_identity",
    }
)
_IDENTITY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")


class HarnessConfigurationError(ValueError):
    """Secret-free invalid executable configuration."""


class RequestContractError(ValueError):
    """Secret-free request validation failure."""


class StateIntegrityError(ValueError):
    """Provider state is not the expected in-memory shape."""


@dataclass(frozen=True, slots=True)
class HarnessPolicy:
    """The deliberately non-generalized policy for this integration slice."""

    allowed_repository: str = INT1_REPOSITORY
    allowed_issuer: str = INT1_ISSUER
    allowed_key_id: str = INT1_KEY_ID
    allowed_version: str = INT1_VERSION

    def validate(self) -> None:
        if self != type(self)():
            raise HarnessConfigurationError("policy_outside_int1")


@dataclass(slots=True)
class RevocationState:
    """Explicit process-local revocation state owned by the harness."""

    revoked_credential_instance_ids: set[str] = field(default_factory=set)
    revoked_attestation_ids: set[str] = field(default_factory=set)

    def validate(self) -> None:
        for value in (
            self.revoked_credential_instance_ids,
            self.revoked_attestation_ids,
        ):
            if type(value) is not set:
                raise StateIntegrityError("state_shape_invalid")
            if any(not _valid_identity(item) for item in value):
                raise StateIntegrityError("state_identity_invalid")


@dataclass(frozen=True, slots=True)
class ProviderResponse:
    """HTTP result with no secret-bearing representation."""

    status_code: int
    payload: Mapping[str, object]


def _valid_identity(value: object) -> bool:
    return type(value) is str and bool(_IDENTITY_PATTERN.fullmatch(value))


def read_token_file(path: str | Path) -> str:
    """Read the opaque bearer token without exposing it in errors or output."""

    try:
        raw = Path(path).read_bytes()
        if not raw or len(raw) > MAX_TOKEN_BYTES:
            raise HarnessConfigurationError("token_file_invalid")
        token = raw.decode("utf-8").strip()
    except (OSError, UnicodeError):
        raise HarnessConfigurationError("token_file_invalid") from None
    if not token or any(character.isspace() for character in token):
        raise HarnessConfigurationError("token_file_invalid")
    return token


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RequestContractError("duplicate_json_key")
        result[key] = value
    return result


def _parse_request(raw_body: bytes) -> dict[str, str]:
    if len(raw_body) > MAX_REQUEST_BYTES:
        raise RequestContractError("request_too_large")
    try:
        value = json.loads(
            raw_body.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except RequestContractError:
        raise
    except (UnicodeDecodeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RequestContractError("json_invalid") from exc
    if type(value) is not dict or set(value) != REQUEST_FIELDS:
        raise RequestContractError("request_fields_invalid")
    if any(not _valid_identity(item) for item in value.values()):
        raise RequestContractError("request_identity_invalid")
    return value  # type: ignore[return-value]


def _compact_json(payload: Mapping[str, object]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _utc_timestamp(clock: Callable[[], datetime]) -> str:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise StateIntegrityError("clock_invalid")
    value = value.astimezone(timezone.utc).replace(microsecond=0)
    return value.isoformat().replace("+00:00", "Z")


class RevocationProvider:
    """Validate one INT1 request and evaluate explicit process-local state."""

    def __init__(
        self,
        token: str,
        *,
        policy: HarnessPolicy | None = None,
        state: RevocationState | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if type(token) is not str or not token or any(character.isspace() for character in token):
            raise HarnessConfigurationError("token_invalid")
        selected_policy = policy or HarnessPolicy()
        selected_policy.validate()
        self._token = token
        self._policy = selected_policy
        self._state = state or RevocationState()
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    @property
    def state(self) -> RevocationState:
        return self._state

    def __repr__(self) -> str:
        return "RevocationProvider(policy='v1-int1', token=<redacted>)"

    def handle_request(self, raw_body: bytes, authorization: str | None) -> ProviderResponse:
        if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
            return ProviderResponse(401, {"error": "authentication_required"})
        supplied_token = authorization[len("Bearer ") :]
        if not hmac.compare_digest(supplied_token, self._token):
            return ProviderResponse(401, {"error": "authentication_invalid"})
        try:
            request = _parse_request(raw_body)
        except RequestContractError as exc:
            return ProviderResponse(400, {"error": str(exc)})
        if (
            request["repository_identity"] != self._policy.allowed_repository
            or request["issuer_id"] != self._policy.allowed_issuer
            or request["key_id"] != self._policy.allowed_key_id
            or request["version"] != self._policy.allowed_version
        ):
            return ProviderResponse(403, {"error": "policy_denied"})
        try:
            self._state.validate()
            if request["credential_instance_id"] in self._state.revoked_credential_instance_ids:
                return ProviderResponse(
                    200,
                    {
                        "status": "revoked",
                        "revoked_at": _utc_timestamp(self._clock),
                        "reason": "credential-revoked",
                    },
                )
            if request["attestation_id"] in self._state.revoked_attestation_ids:
                return ProviderResponse(
                    200,
                    {
                        "status": "revoked",
                        "revoked_at": _utc_timestamp(self._clock),
                        "reason": "attestation-revoked",
                    },
                )
        except StateIntegrityError:
            return ProviderResponse(503, {"error": "provider_state_invalid"})
        return ProviderResponse(200, {"status": "valid"})


class _RequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP adapter with compact responses and no default request logging."""

    server: "LoopbackRevocationServer"

    def log_message(self, format: str, *args: object) -> None:
        return

    def _write_payload(self, status_code: int, payload: Mapping[str, object]) -> None:
        body = _compact_json(payload)
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        del message, explain
        self._write_payload(405 if code == 501 else code, {"error": "method_not_allowed" if code == 501 else "http_error"})

    def _reject_method(self) -> None:
        self._write_payload(405, {"error": "method_not_allowed"})

    def do_GET(self) -> None:
        self._reject_method()

    def do_HEAD(self) -> None:
        self._reject_method()

    def do_PUT(self) -> None:
        self._reject_method()

    def do_PATCH(self) -> None:
        self._reject_method()

    def do_DELETE(self) -> None:
        self._reject_method()

    def do_OPTIONS(self) -> None:
        self._reject_method()

    def do_POST(self) -> None:
        if self.path != ENDPOINT_PATH:
            self._write_payload(404, {"error": "endpoint_not_found"})
            return
        content_type = self.headers.get("Content-Type", "")
        if content_type.split(";", 1)[0].strip().lower() != "application/json":
            self._write_payload(400, {"error": "content_type_invalid"})
            return
        content_length = self.headers.get("Content-Length")
        try:
            length = int(content_length) if content_length is not None else -1
        except ValueError:
            length = -1
        if length < 0 or length > MAX_REQUEST_BYTES:
            self._write_payload(400, {"error": "request_length_invalid"})
            return
        body = self.rfile.read(length)
        if len(body) != length:
            self._write_payload(400, {"error": "request_body_incomplete"})
            return
        result = self.server.provider.handle_request(body, self.headers.get("Authorization"))
        self._write_payload(result.status_code, result.payload)


class LoopbackRevocationServer(http.server.ThreadingHTTPServer):
    """IPv4-loopback-only server with an OS-selected port option."""

    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, provider: RevocationProvider, *, port: int = 0) -> None:
        if type(port) is not int or not 0 <= port <= 65535:
            raise HarnessConfigurationError("port_invalid")
        self.provider = provider
        super().__init__((LOOPBACK_ADDRESS, port), _RequestHandler)

    @property
    def bound_port(self) -> int:
        return int(self.server_address[1])

    @property
    def endpoint(self) -> str:
        return f"http://{LOOPBACK_ADDRESS}:{self.bound_port}{ENDPOINT_PATH}"

    def start_background(self) -> Thread:
        """Start serving after construction has successfully bound the socket."""

        thread = Thread(target=self.serve_forever, name="v1-int1-revocation", daemon=True)
        thread.start()
        return thread


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="V1-INT1 loopback revocation harness")
    parser.add_argument("--token-file", required=True, help="path to the external bearer-token file")
    parser.add_argument("--port", type=int, default=0, help="IPv4 loopback port; 0 selects an ephemeral port")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)
    try:
        token = read_token_file(args.token_file)
        provider = RevocationProvider(token)
        server = LoopbackRevocationServer(provider, port=args.port)
    except (HarnessConfigurationError, OSError):
        print("revocation_harness_start_failed", file=sys.stderr)
        return 2
    print(f"READY {server.endpoint}", flush=True)
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        return 130
    finally:
        server.server_close()
    return 0


__all__ = [
    "ENDPOINT_PATH",
    "HarnessConfigurationError",
    "HarnessPolicy",
    "INT1_ISSUER",
    "INT1_KEY_ID",
    "INT1_REPOSITORY",
    "INT1_VERSION",
    "LOOPBACK_ADDRESS",
    "LoopbackRevocationServer",
    "MAX_REQUEST_BYTES",
    "MAX_TOKEN_BYTES",
    "ProviderResponse",
    "RevocationProvider",
    "RevocationState",
    "build_argument_parser",
    "main",
    "read_token_file",
]


if __name__ == "__main__":
    raise SystemExit(main())
