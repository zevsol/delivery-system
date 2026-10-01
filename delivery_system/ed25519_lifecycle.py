"""Role-scoped Ed25519 lifecycle policy and pure material preflight.

This module contains no file, process, Runtime, persistence, or credential
operations.  Host composition supplies already-loaded Ed25519 material and
trust candidates, and receives an immutable effective verification projection.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .attestation_signing import TrustedEd25519Key


_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$\Z")
_FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}\Z")
_ALGORITHM = "ed25519"
_MANIFEST_VERSION = 1
_STATES = frozenset({"active", "historical", "retired", "compromised"})
_CHALLENGE = b"delivery-system:ed25519-lifecycle-preflight:v1"


class Ed25519LifecycleError(ValueError):
    """Deterministic, secret-free lifecycle validation failure."""

    def __init__(self, code: str = "ed25519_lifecycle_invalid") -> None:
        super().__init__(code)
        self.code = code


def _fail(code: str) -> None:
    raise Ed25519LifecycleError(code)


def _id(value: Any, field: str) -> str:
    if type(value) is not str or _ID_RE.fullmatch(value) is None:
        _fail(f"lifecycle_{field}_invalid")
    return value


def _fingerprint(value: Any) -> str:
    if type(value) is not str or _FINGERPRINT_RE.fullmatch(value) is None:
        _fail("lifecycle_fingerprint_invalid")
    return value


@dataclass(frozen=True, slots=True)
class Ed25519LifecycleIdentity:
    issuer_id: str
    key_id: str
    algorithm: str = _ALGORITHM

    def __post_init__(self) -> None:
        _id(self.issuer_id, "issuer_id")
        _id(self.key_id, "key_id")
        if self.algorithm != _ALGORITHM:
            _fail("lifecycle_algorithm_unsupported")


@dataclass(frozen=True, slots=True)
class Ed25519LifecycleEntry:
    issuer_id: str
    key_id: str
    algorithm: str
    public_key_fingerprint: str
    state: str

    def __post_init__(self) -> None:
        _id(self.issuer_id, "issuer_id")
        _id(self.key_id, "key_id")
        if self.algorithm != _ALGORITHM:
            _fail("lifecycle_algorithm_unsupported")
        _fingerprint(self.public_key_fingerprint)
        if type(self.state) is not str:
            _fail("lifecycle_state_invalid")
        if self.state not in _STATES:
            _fail("lifecycle_state_unknown")

    @property
    def identity(self) -> Ed25519LifecycleIdentity:
        return Ed25519LifecycleIdentity(self.issuer_id, self.key_id, self.algorithm)


@dataclass(frozen=True, slots=True)
class Ed25519LifecycleManifest:
    version: int
    role: str
    issuer_id: str
    keys: tuple[Ed25519LifecycleEntry, ...]

    def __post_init__(self) -> None:
        if type(self.version) is not int or isinstance(self.version, bool) or self.version != _MANIFEST_VERSION:
            _fail("lifecycle_version_unsupported")
        if self.role not in {"attestation", "authority-binding"}:
            _fail("lifecycle_role_invalid")
        _id(self.issuer_id, "issuer_id")
        if type(self.keys) is not tuple or not self.keys:
            _fail("lifecycle_keys_invalid")
        identities: set[tuple[str, str, str]] = set()
        key_ids: set[str] = set()
        for entry in self.keys:
            if type(entry) is not Ed25519LifecycleEntry:
                _fail("lifecycle_keys_invalid")
            identity = (entry.issuer_id, entry.key_id, entry.algorithm)
            if identity in identities or entry.key_id in key_ids:
                _fail("lifecycle_identity_duplicate")
            identities.add(identity)
            key_ids.add(entry.key_id)
            if entry.issuer_id != self.issuer_id:
                _fail("lifecycle_issuer_mismatch")

    @classmethod
    def from_value(cls, value: Any, *, role: str) -> "Ed25519LifecycleManifest":
        if type(value) is not dict:
            _fail("lifecycle_manifest_invalid")
        if set(value) != {"version", "role", "issuer_id", "keys"}:
            _fail("lifecycle_manifest_field_unknown")
        if value["role"] != role:
            _fail("lifecycle_role_mismatch")
        raw_keys = value["keys"]
        if type(raw_keys) is not list or not raw_keys:
            _fail("lifecycle_keys_invalid")
        entries: list[Ed25519LifecycleEntry] = []
        for raw in raw_keys:
            if type(raw) is not dict:
                _fail("lifecycle_key_entry_invalid")
            if set(raw) != {
                "issuer_id", "key_id", "algorithm", "public_key_fingerprint", "state",
            }:
                _fail("lifecycle_key_field_unknown")
            entries.append(Ed25519LifecycleEntry(
                raw["issuer_id"], raw["key_id"], raw["algorithm"],
                raw["public_key_fingerprint"], raw["state"],
            ))
        return cls(value["version"], value["role"], value["issuer_id"], tuple(entries))

    @classmethod
    def from_json(cls, text: str | bytes, *, role: str) -> "Ed25519LifecycleManifest":
        if type(text) not in (str, bytes):
            _fail("lifecycle_manifest_invalid")
        try:
            value = json.loads(text, object_pairs_hook=_reject_duplicate_members)
        except Ed25519LifecycleError:
            raise
        except Exception:
            _fail("lifecycle_manifest_invalid")
        return cls.from_value(value, role=role)


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("lifecycle_duplicate_json_member")
        result[key] = value
    return result


def parse_lifecycle_manifest(value: Any, *, role: str) -> Ed25519LifecycleManifest:
    """Parse one strict role-scoped manifest from JSON text or decoded data."""

    if isinstance(value, (str, bytes)):
        return Ed25519LifecycleManifest.from_json(value, role=role)
    return Ed25519LifecycleManifest.from_value(value, role=role)


def public_key_fingerprint(public_key: Ed25519PublicKey) -> str:
    """Return the canonical fingerprint of an Ed25519 raw public key."""

    if not isinstance(public_key, Ed25519PublicKey):
        _fail("lifecycle_public_key_invalid")
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _identity(entry: TrustedEd25519Key) -> Ed25519LifecycleIdentity:
    return Ed25519LifecycleIdentity(entry.issuer_id, entry.key_id, entry.signature_algorithm)


def _candidate_map(candidates: tuple[TrustedEd25519Key, ...] | list[TrustedEd25519Key]) -> dict[tuple[str, str, str], TrustedEd25519Key]:
    if type(candidates) not in (tuple, list) or not candidates:
        _fail("lifecycle_trust_candidates_invalid")
    result: dict[tuple[str, str, str], TrustedEd25519Key] = {}
    for candidate in candidates:
        if type(candidate) is not TrustedEd25519Key:
            _fail("lifecycle_trust_candidates_invalid")
        identity = (candidate.issuer_id, candidate.key_id, candidate.signature_algorithm)
        if identity in result:
            _fail("lifecycle_trust_candidate_duplicate")
        if candidate.signature_algorithm != _ALGORITHM:
            _fail("lifecycle_algorithm_unsupported")
        result[identity] = candidate
    return result


@dataclass(frozen=True, slots=True)
class Ed25519LifecyclePreflightResult:
    role: str
    mode: str
    active_issuer_id: str
    active_key_id: str
    algorithm: str
    historical_trusted_identities: tuple[Ed25519LifecycleIdentity, ...]
    excluded_retired_identities: tuple[Ed25519LifecycleIdentity, ...]
    excluded_compromised_identities: tuple[Ed25519LifecycleIdentity, ...]
    manifest_version: int | None
    validation_codes: tuple[str, ...]
    effective_trust_keys: tuple[TrustedEd25519Key, ...]

    @property
    def effective_trust_identities(self) -> tuple[Ed25519LifecycleIdentity, ...]:
        return tuple(_identity(entry) for entry in self.effective_trust_keys)


def preflight_ed25519_lifecycle(
    *,
    role: str,
    active_issuer_id: str,
    active_key_id: str,
    private_key: Ed25519PrivateKey,
    public_key: Ed25519PublicKey,
    trust_candidates: tuple[TrustedEd25519Key, ...] | list[TrustedEd25519Key],
    manifest: Ed25519LifecycleManifest | None = None,
) -> Ed25519LifecyclePreflightResult:
    """Validate one role without constructing Runtime or touching persistence."""

    if role not in {"attestation", "authority-binding"}:
        _fail("lifecycle_role_invalid")
    active_issuer_id = _id(active_issuer_id, "active_issuer_id")
    active_key_id = _id(active_key_id, "active_key_id")
    if not isinstance(private_key, Ed25519PrivateKey) or not isinstance(public_key, Ed25519PublicKey):
        _fail("lifecycle_key_invalid")
    try:
        derived = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        configured = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    except Exception:
        _fail("lifecycle_key_invalid")
    if derived != configured:
        _fail("lifecycle_key_pair_mismatch")
    candidates = _candidate_map(trust_candidates)
    active_identity = (active_issuer_id, active_key_id, _ALGORITHM)
    active_candidate = candidates.get(active_identity)
    if active_candidate is None:
        _fail("lifecycle_active_key_not_trusted")
    if public_key_fingerprint(active_candidate.public_key) != public_key_fingerprint(public_key):
        _fail("lifecycle_active_fingerprint_mismatch")

    states: dict[tuple[str, str, str], str] = {}
    if manifest is None:
        states[active_identity] = "active"
        for identity in candidates:
            if identity != active_identity:
                states[identity] = "historical"
        mode = "legacy"
        manifest_version = None
    else:
        if type(manifest) is not Ed25519LifecycleManifest or manifest.role != role:
            _fail("lifecycle_role_mismatch")
        if manifest.issuer_id != active_issuer_id:
            _fail("lifecycle_active_selector_disagreement")
        for entry in manifest.keys:
            identity = (entry.issuer_id, entry.key_id, entry.algorithm)
            candidate = candidates.get(identity)
            if candidate is None:
                _fail("lifecycle_identity_unknown")
            if public_key_fingerprint(candidate.public_key) != entry.public_key_fingerprint:
                _fail("lifecycle_fingerprint_mismatch")
            states[identity] = entry.state
        if set(states) != set(candidates):
            _fail("lifecycle_candidate_unclassified")
        active_entries = [identity for identity, state in states.items() if state == "active"]
        if len(active_entries) != 1:
            _fail("lifecycle_active_count_invalid")
        if active_entries[0] != active_identity:
            _fail("lifecycle_active_selector_disagreement")
        mode = "managed"
        manifest_version = manifest.version

    if states.get(active_identity) != "active":
        _fail("lifecycle_active_selector_disagreement")
    effective = tuple(candidate for identity, candidate in candidates.items()
                      if states.get(identity) in {"active", "historical"})
    if not effective:
        _fail("lifecycle_effective_trust_empty")
    historical = tuple(_identity(candidate) for identity, candidate in candidates.items()
                       if states.get(identity) == "historical")
    retired = tuple(_identity(candidate) for identity, candidate in candidates.items()
                    if states.get(identity) == "retired")
    compromised = tuple(_identity(candidate) for identity, candidate in candidates.items()
                        if states.get(identity) == "compromised")
    try:
        signature = private_key.sign(_CHALLENGE)
        public_key.verify(signature, _CHALLENGE)
    except InvalidSignature:
        _fail("lifecycle_self_check_failed")
    except Exception:
        _fail("lifecycle_self_check_failed")
    return Ed25519LifecyclePreflightResult(
        role=role,
        mode=mode,
        active_issuer_id=active_issuer_id,
        active_key_id=active_key_id,
        algorithm=_ALGORITHM,
        historical_trusted_identities=historical,
        excluded_retired_identities=retired,
        excluded_compromised_identities=compromised,
        manifest_version=manifest_version,
        validation_codes=("preflight_valid",),
        effective_trust_keys=effective,
    )


__all__ = [
    "Ed25519LifecycleEntry",
    "Ed25519LifecycleError",
    "Ed25519LifecycleIdentity",
    "Ed25519LifecycleManifest",
    "Ed25519LifecyclePreflightResult",
    "parse_lifecycle_manifest",
    "preflight_ed25519_lifecycle",
    "public_key_fingerprint",
]
