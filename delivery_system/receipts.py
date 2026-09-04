"""Strict immutable Runtime-owned execution evidence."""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, Iterable

from .application_identity import LogicalApplicationIdentity, operation_identity, request_identity
from .canonical import digest
from .write_operations import normalize_write_operations, operation_set_digest_payload

PROVENANCE_DOMAIN = "delivery-system:authority-provenance:v1"
PROVENANCE_FIELDS = ("authority_id", "credential_binding_id", "credential_instance_id", "issuer_id",
                     "credential_principal_identity", "github_subject_identity", "issued_at", "expires_at",
                     "driver_identity", "remote_authority", "application_id")


def _copy(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _copy(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_copy(item) for item in value)
    return value


def _out(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _out(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_out(item) for item in value]
    return value


@dataclass(frozen=True)
class AuthorityProvenance:
    authority_id: str
    credential_binding_id: str
    credential_instance_id: str
    issuer_id: str
    credential_principal_identity: str
    github_subject_identity: str
    issued_at: str
    expires_at: str
    driver_identity: str
    remote_authority: str
    application_id: str
    _live_context: Any = None

    @classmethod
    def from_authority(cls, value: Any) -> "AuthorityProvenance":
        raise ValueError("runtime_authority_required")

    @classmethod
    def _from_live_authority(cls, value: Any, context: Any) -> "AuthorityProvenance":
        from .application_authority import ApplicationAuthority
        if type(value) is not ApplicationAuthority or getattr(context, "_authority", None) is not value:
            raise ValueError("runtime_authority_required")
        source = value.to_dict()
        from .application_identity import application_id
        source = {**source, "application_id": application_id(source)}
        return cls._from_source(source, live_context=context)

    @classmethod
    def from_dict(cls, value: Any) -> "AuthorityProvenance":
        if not isinstance(value, Mapping) or set(value) != set(PROVENANCE_FIELDS) | {"domain"} or value.get("domain") != PROVENANCE_DOMAIN:
            raise ValueError("authority_provenance_invalid")
        return cls._from_source(value)

    @classmethod
    def from_value(cls, value: Any) -> "AuthorityProvenance":
        from .application_authority import ApplicationAuthority
        if isinstance(value, cls):
            return value
        if type(value) is ApplicationAuthority:
            return cls.from_authority(value)
        return cls.from_dict(value)

    @classmethod
    def _from_source(cls, source: Mapping[str, Any], live_context: Any = None) -> "AuthorityProvenance":
        if not isinstance(source, Mapping):
            raise ValueError("authority_provenance_invalid")
        missing = set(PROVENANCE_FIELDS[:-1]) - set(source)
        if missing:
            raise ValueError("authority_provenance_invalid")
        try:
            values = [source[field] for field in PROVENANCE_FIELDS[:-1]]
            values.append(source["application_id"])
            result = cls(*values, _live_context=live_context)
        except (TypeError, ValueError) as exc:
            raise ValueError("authority_provenance_invalid") from exc
        if any(type(getattr(result, field)) is not str or (field != "credential_principal_identity" and not getattr(result, field)) for field in PROVENANCE_FIELDS):
            raise ValueError("authority_provenance_invalid")
        return result

    def to_dict(self) -> dict[str, str]:
        return {"domain": PROVENANCE_DOMAIN} | {field: getattr(self, field) for field in PROVENANCE_FIELDS}


def _remote_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"result_kind", "result_identity", "result_digest", "result_payload"}:
        raise ValueError("remote_result_invalid")
    if any(type(value[field]) is not str or not value[field] for field in ("result_kind", "result_identity", "result_digest")):
        raise ValueError("remote_result_invalid")
    payload = _copy(value["result_payload"])
    if not isinstance(payload, Mapping) or value["result_digest"] != digest(payload):
        raise ValueError("remote_result_invalid")
    return {"result_kind": value["result_kind"], "result_identity": value["result_identity"],
            "result_digest": value["result_digest"], "result_payload": payload}


@dataclass(frozen=True)
class OperationReceipt:
    operation_receipt_id: str
    application_id: str
    identity: Mapping[str, Any]
    operation_identity: str
    operation_index: int
    canonical_operation: Mapping[str, Any]
    request_identity: str
    authority_binding: AuthorityProvenance
    remote_result: Mapping[str, Any]
    started_at: str
    completed_at: str
    receipt_digest: str = ""
    _live_context: Any = None

    def __post_init__(self) -> None:
        identity = self.identity if isinstance(self.identity, LogicalApplicationIdentity) else LogicalApplicationIdentity.from_dict(self.identity)
        operation = normalize_write_operations([_out(self.canonical_operation)])[0]
        provenance = AuthorityProvenance.from_value(self.authority_binding)
        result = _remote_result(self.remote_result)
        if type(self.operation_index) is not int or self.operation_index < 0:
            raise ValueError("operation_receipt_invalid")
        expected_operation = operation_identity(self.application_id, self.operation_index, operation)
        if self.application_id != identity.application_id or provenance.application_id != identity.application_id or self.operation_identity != expected_operation:
            raise ValueError("operation_receipt_binding_invalid")
        if self.request_identity != request_identity(self.operation_identity):
            raise ValueError("operation_receipt_binding_invalid")
        expected_receipt_id = "operation-receipt-" + digest({"domain": "delivery-system:operation-receipt-id:v1", "operation_identity": self.operation_identity}).split(":", 1)[1]
        if self.operation_receipt_id != expected_receipt_id:
            raise ValueError("operation_receipt_invalid")
        if type(self.started_at) is not str or not self.started_at or type(self.completed_at) is not str or not self.completed_at:
            raise ValueError("operation_receipt_invalid")
        object.__setattr__(self, "identity", identity)
        object.__setattr__(self, "canonical_operation", _copy(operation))
        object.__setattr__(self, "authority_binding", provenance)
        object.__setattr__(self, "remote_result", result)

    @classmethod
    def create(cls, identity: LogicalApplicationIdentity, index: int, operation: Mapping[str, Any], authority: Any,
               remote_result: Mapping[str, Any], started_at: str, completed_at: str) -> "OperationReceipt":
        context = getattr(authority, "_execution_context", None)
        if context is None:
            raise ValueError("runtime_authority_required")
        context._require_current()
        canonical = normalize_write_operations([operation])[0]
        if index < 0 or index >= len(context._expected_operations) or canonical != context._expected_operations[index]:
            raise ValueError("operation_receipt_binding_invalid")
        op_id = operation_identity(identity.application_id, index, canonical)
        return cls("operation-receipt-" + digest({"domain": "delivery-system:operation-receipt-id:v1", "operation_identity": op_id}).split(":", 1)[1],
                   identity.application_id, identity, op_id, index, canonical, request_identity(op_id),
                   AuthorityProvenance._from_live_authority(context._authority, context), remote_result, started_at, completed_at,
                   _live_context=context).with_digest()

    def payload(self) -> dict[str, Any]:
        return {"operation_receipt_id": self.operation_receipt_id, "application_id": self.application_id,
                "identity": self.identity.to_dict(), "operation_identity": self.operation_identity,
                "operation_index": self.operation_index, "canonical_operation": _out(self.canonical_operation),
                "request_identity": self.request_identity, "authority_binding": self.authority_binding.to_dict(),
                "remote_result": _out(self.remote_result), "started_at": self.started_at, "completed_at": self.completed_at}

    def with_digest(self) -> "OperationReceipt":
        return OperationReceipt(**{**self.__dict__, "receipt_digest": digest(self.payload())})

    def verify_integrity(self) -> bool:
        return bool(self.receipt_digest) and self.receipt_digest == digest(self.payload())

    def to_dict(self) -> dict[str, Any]:
        return self.payload() | {"receipt_digest": self.receipt_digest}


@dataclass(frozen=True)
class ApplicationReceipt:
    application_receipt_id: str
    application_id: str
    identity: Mapping[str, Any]
    operation_set_digest: str
    operation_receipt_refs: tuple[Mapping[str, str], ...]
    status: str
    started_at: str
    completed_at: str
    receipt_digest: str = ""
    _live_context: Any = None

    def __post_init__(self) -> None:
        identity = self.identity if isinstance(self.identity, LogicalApplicationIdentity) else LogicalApplicationIdentity.from_dict(self.identity)
        try:
            refs = tuple(MappingProxyType({"operation_receipt_id": ref["operation_receipt_id"], "operation_receipt_digest": ref["operation_receipt_digest"]}) for ref in self.operation_receipt_refs)
        except (KeyError, TypeError) as exc:
            raise ValueError("application_receipt_invalid") from exc
        if self.application_id != identity.application_id or type(self.operation_set_digest) is not str or not self.operation_set_digest:
            raise ValueError("application_receipt_binding_invalid")
        expected_id = "application-receipt-" + digest({"domain": "delivery-system:application-receipt-id:v1", "application_id": self.application_id}).split(":", 1)[1]
        if self.application_receipt_id != expected_id or self.status != "Applied" or not refs:
            raise ValueError("application_receipt_invalid")
        if len(refs) != len(set((r["operation_receipt_id"], r["operation_receipt_digest"]) for r in refs)):
            raise ValueError("application_receipt_invalid")
        if any(set(ref) != {"operation_receipt_id", "operation_receipt_digest"} or any(type(v) is not str or not v for v in ref.values()) for ref in refs):
            raise ValueError("application_receipt_invalid")
        object.__setattr__(self, "identity", identity)
        object.__setattr__(self, "operation_receipt_refs", refs)

    @classmethod
    def create(cls, identity: LogicalApplicationIdentity, operation_set_digest: str, expected_operations: Iterable[Mapping[str, Any]],
               receipts: Iterable[OperationReceipt], started_at: str, completed_at: str) -> "ApplicationReceipt":
        if not receipts:
            raise ValueError("application_finalization_invalid")
        actual = tuple(receipts)
        context = actual[0]._live_context
        if context is None or any(receipt._live_context is not context for receipt in actual):
            raise ValueError("runtime_authority_required")
        operations = tuple(normalize_write_operations(list(expected_operations)))
        if operations != context._expected_operations:
            raise ValueError("application_finalization_invalid")
        if operation_set_digest != identity.values()["operation_set_digest"] or operation_set_digest != digest(operation_set_digest_payload(operations)):
            raise ValueError("application_receipt_binding_invalid")
        if len(operations) != len(actual) or not actual:
            raise ValueError("application_receipt_incomplete")
        refs = []
        for index, (operation, receipt) in enumerate(zip(operations, actual)):
            if not receipt.verify_integrity() or receipt.application_id != identity.application_id or receipt.operation_index != index or receipt.operation_identity != operation_identity(identity.application_id, index, operation):
                raise ValueError("application_receipt_incomplete")
            refs.append({"operation_receipt_id": receipt.operation_receipt_id, "operation_receipt_digest": receipt.receipt_digest})
        return cls("application-receipt-" + digest({"domain": "delivery-system:application-receipt-id:v1", "application_id": identity.application_id}).split(":", 1)[1], identity.application_id, identity, operation_set_digest, tuple(refs), "Applied", started_at, completed_at, _live_context=context).with_digest()

    def validate_against(self, expected_operations: Iterable[Mapping[str, Any]], receipts: Iterable[OperationReceipt]) -> bool:
        try:
            operations = tuple(normalize_write_operations(list(expected_operations)))
            actual = tuple(receipts)
            if self.operation_set_digest != digest(operation_set_digest_payload(operations)) or len(operations) != len(actual) or len(actual) != len(self.operation_receipt_refs):
                return False
            for index, (operation, receipt, ref) in enumerate(zip(operations, actual, self.operation_receipt_refs)):
                if (not receipt.verify_integrity() or receipt.application_id != self.application_id or receipt.operation_index != index or
                        receipt.operation_identity != operation_identity(self.application_id, index, operation) or
                        _out(receipt.canonical_operation) != operation or receipt.operation_receipt_id != ref["operation_receipt_id"] or
                        receipt.receipt_digest != ref["operation_receipt_digest"]):
                    return False
            return True
        except (TypeError, ValueError, KeyError):
            return False

    def payload(self) -> dict[str, Any]:
        return {"application_receipt_id": self.application_receipt_id, "application_id": self.application_id,
                "identity": self.identity.to_dict(), "operation_set_digest": self.operation_set_digest,
                "operation_receipt_refs": _out(self.operation_receipt_refs), "status": self.status,
                "started_at": self.started_at, "completed_at": self.completed_at}

    def with_digest(self) -> "ApplicationReceipt":
        return ApplicationReceipt(**{**self.__dict__, "receipt_digest": digest(self.payload())})

    def verify_integrity(self) -> bool:
        return self.status == "Applied" and bool(self.receipt_digest) and self.receipt_digest == digest(self.payload())

    def to_dict(self) -> dict[str, Any]:
        return self.payload() | {"receipt_digest": self.receipt_digest}
