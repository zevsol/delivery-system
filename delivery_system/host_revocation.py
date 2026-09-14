"""Host-owned external revocation lookup for live and restart trust paths."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
from typing import Any, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .attestation import RevocationStatus


class ExternalRevocationError(ValueError):
    """Secret-free failure from the external revocation authority."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class RevocationQuery:
    """Stable revocation identity and anti-confusion context."""

    issuer_id: str
    credential_instance_id: str
    attestation_id: str
    key_id: str
    version: str
    repository_identity: str

    def to_payload(self) -> dict[str, str]:
        return {
            "issuer_id": self.issuer_id,
            "credential_instance_id": self.credential_instance_id,
            "attestation_id": self.attestation_id,
            "key_id": self.key_id,
            "version": self.version,
            "repository_identity": self.repository_identity,
        }


class RevocationTransport(Protocol):
    """Injected transport boundary; implementations do not decide trust."""

    def request(
        self,
        query: RevocationQuery,
        *,
        timeout_seconds: float,
        auth_token: str | None,
    ) -> Mapping[str, Any]: ...


class UrllibRevocationTransport:
    """Generic JSON transport with no vendor-specific protocol assumptions."""

    def __init__(self, endpoint: str) -> None:
        self._endpoint = endpoint

    def request(
        self,
        query: RevocationQuery,
        *,
        timeout_seconds: float,
        auth_token: str | None,
    ) -> Mapping[str, Any]:
        body = json.dumps(query.to_payload(), separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if auth_token is not None:
            headers["Authorization"] = "Bearer " + auth_token
        request = Request(self._endpoint, data=body, headers=headers, method="POST")
        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                raw = response.read(1024 * 1024 + 1)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise ExternalRevocationError("revocation_unavailable") from exc
        if len(raw) > 1024 * 1024:
            raise ExternalRevocationError("revocation_unavailable")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ExternalRevocationError("revocation_unavailable") from exc
        if not isinstance(value, Mapping):
            raise ExternalRevocationError("revocation_unavailable")
        return value


class ExternalRevocationReader:
    """Map one authoritative provider response to the Runtime reader contract."""

    def __init__(
        self,
        *,
        endpoint: str,
        timeout_ms: int,
        repository_identity: str,
        transport: RevocationTransport | None = None,
        auth_token: str | None = None,
    ) -> None:
        if type(endpoint) is not str or not endpoint:
            raise ExternalRevocationError("revocation_configuration_invalid")
        if type(timeout_ms) is not int or isinstance(timeout_ms, bool) or timeout_ms <= 0:
            raise ExternalRevocationError("revocation_configuration_invalid")
        if type(repository_identity) is not str or not repository_identity:
            raise ExternalRevocationError("revocation_configuration_invalid")
        selected = transport or UrllibRevocationTransport(endpoint)
        if not callable(getattr(selected, "request", None)):
            raise ExternalRevocationError("revocation_transport_invalid")
        if auth_token is not None and (type(auth_token) is not str or not auth_token):
            raise ExternalRevocationError("revocation_configuration_invalid")
        self._endpoint = endpoint
        self._timeout_seconds = timeout_ms / 1000.0
        self._repository_identity = repository_identity
        self._transport = selected
        self._auth_token = auth_token

    def read_status(
        self,
        attestation_id: str,
        credential_instance_id: str,
        issuer_id: str,
        key_id: str,
        version: str,
    ) -> RevocationStatus:
        query = RevocationQuery(
            issuer_id=issuer_id,
            credential_instance_id=credential_instance_id,
            attestation_id=attestation_id,
            key_id=key_id,
            version=version,
            repository_identity=self._repository_identity,
        )
        try:
            response = self._transport.request(
                query,
                timeout_seconds=self._timeout_seconds,
                auth_token=self._auth_token,
            )
        except ExternalRevocationError:
            raise
        except Exception as exc:
            raise ExternalRevocationError("revocation_unavailable") from exc
        if not isinstance(response, Mapping) or type(response.get("status")) is not str:
            raise ExternalRevocationError("revocation_unavailable")
        status = response["status"]
        if status == "valid" and set(response) == {"status"}:
            return RevocationStatus()
        if status == "revoked" and set(response) == {"status", "revoked_at", "reason"}:
            try:
                return RevocationStatus(
                    credential_instance_revoked=True,
                    revoked_at=response["revoked_at"],
                    reason=response["reason"],
                )
            except Exception as exc:
                raise ExternalRevocationError("revocation_unavailable") from exc
        if status == "unknown":
            raise ExternalRevocationError("revocation_unknown")
        raise ExternalRevocationError("revocation_unavailable")


__all__ = [
    "ExternalRevocationError",
    "ExternalRevocationReader",
    "RevocationQuery",
    "RevocationTransport",
    "UrllibRevocationTransport",
]
