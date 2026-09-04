"""Host-owned live GitHub App installation credential capability."""

from __future__ import annotations

from typing import Any

from .attestation_github_app import (
    GitHubAppInstallationCapabilityEvidence,
    GITHUB_APP_INSTALLATION_CREDENTIAL_CLASS,
    _normalize_evidence,
    github_app_installation_principal,
)


_LEASE_MARKER = object()


def _valid_token(token: Any) -> bool:
    return (
        type(token) is str
        and 1 <= len(token) <= 4096
        and token == token.strip()
        and all(0x21 <= ord(char) <= 0x7E for char in token)
    )


class GitHubAppInstallationCredentialLease:
    """An exact Host-owned credential instance with a secret-free snapshot."""

    __slots__ = ("__token", "__evidence", "__integrity")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if kwargs.pop("_marker", None) is not _LEASE_MARKER or kwargs or len(args) != 2:
            raise ValueError("host_credential_capability_invalid")
        token, evidence = args
        if not _valid_token(token) or type(evidence) is not GitHubAppInstallationCapabilityEvidence:
            raise ValueError("host_credential_capability_invalid")
        object.__setattr__(self, "_GitHubAppInstallationCredentialLease__token", token)
        object.__setattr__(self, "_GitHubAppInstallationCredentialLease__evidence", evidence)
        object.__setattr__(self, "_GitHubAppInstallationCredentialLease__integrity", self._integrity_value(token, evidence))

    def __setattr__(self, name: str, value: Any) -> None:
        raise ValueError("host_credential_capability_invalid")

    def __copy__(self) -> "GitHubAppInstallationCredentialLease":
        raise ValueError("host_credential_capability_copy_forbidden")

    def __deepcopy__(self, memo: dict[int, Any]) -> "GitHubAppInstallationCredentialLease":
        raise ValueError("host_credential_capability_copy_forbidden")

    def __reduce__(self):
        raise ValueError("host_credential_capability_serialization_forbidden")

    def __reduce_ex__(self, protocol: int):
        raise ValueError("host_credential_capability_serialization_forbidden")

    def __repr__(self) -> str:
        return "<GitHubAppInstallationCredentialLease protected>"

    @classmethod
    def _mint(cls, token: str, evidence: GitHubAppInstallationCapabilityEvidence, *, _marker: object | None = None) -> "GitHubAppInstallationCredentialLease":
        try:
            normalized = _normalize_evidence(evidence)
        except Exception:
            raise ValueError("host_credential_capability_invalid") from None
        if normalized != evidence:
            raise ValueError("host_credential_capability_invalid")
        lease = cls(token, evidence, _marker=_LEASE_MARKER)
        lease._validate_integrity()
        return lease

    @staticmethod
    def _integrity_value(token: str, evidence: GitHubAppInstallationCapabilityEvidence) -> tuple[Any, ...]:
        return (
            token,
            evidence.app_id,
            evidence.installation_id,
            evidence.installation_account_identity,
            evidence.repository_id,
            evidence.repository_identity,
            evidence.repository_scope,
            evidence.effective_permissions,
            evidence.expires_at,
            evidence.observed_at,
            evidence.credential_instance_id,
        )

    def _validate_integrity(self) -> None:
        evidence = self.__evidence
        if (
            not _valid_token(self.__token)
            or type(evidence) is not GitHubAppInstallationCapabilityEvidence
            or self.__integrity != self._integrity_value(self.__token, evidence)
            or evidence.repository_scope != (evidence.repository_identity,)
            or evidence.credential_instance_id == ""
            or dict(evidence.effective_permissions).get("issues") != "write"
        ):
            raise ValueError("host_credential_capability_invalid")

    def _credential_class(self) -> str:
        self._validate_integrity()
        return GITHUB_APP_INSTALLATION_CREDENTIAL_CLASS

    def _snapshot(self) -> GitHubAppInstallationCapabilityEvidence:
        self._validate_integrity()
        return self.__evidence

    def _dispatch_token(self) -> str:
        self._validate_integrity()
        return self.__token
