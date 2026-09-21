"""Versioned existing-Issue endpoint contracts used by Runtime V2 plans."""

from __future__ import annotations

import unicodedata
import re
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlparse

from delivery_system.canonical import digest, normalize


def _text(value: object, *, empty: str = "") -> str:
    if value is None:
        return empty
    if not isinstance(value, str):
        raise ValueError("existing_endpoint_text_invalid")
    return unicodedata.normalize("NFC", value.replace("\r\n", "\n").replace("\r", "\n"))


def normalize_title(value: object) -> str:
    value = _text(value).strip()
    if not value:
        raise ValueError("existing_endpoint_title_required")
    return value


def normalize_body(value: object) -> str:
    return _text(value).strip()


def normalize_state(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("existing_endpoint_state_invalid")
    state = value.strip().casefold()
    if state not in {"open", "closed"}:
        raise ValueError("existing_endpoint_state_invalid")
    return state


def semantic_digest(record: Mapping[str, object]) -> str:
    return digest({
        "domain": "delivery-system:existing-issue-semantics:v1",
        "item_type": record["item_type"],
        "title": normalize_title(record["title"]),
        "body": normalize_body(record.get("body")),
        "state": normalize_state(record["state"]),
    })


def identity_digest(record: Mapping[str, object]) -> str:
    return digest({
        "domain": "delivery-system:existing-issue-identity:v1",
        "repository_identity": record["repository_identity"],
        "node_id": record["issue_id"],
    })


def write_address_digest(record: Mapping[str, object]) -> str:
    return digest({
        "domain": "delivery-system:existing-issue-address:v1",
        "repository_identity": record["repository_identity"],
        "node_id": record["issue_id"],
        "issue_number": record["issue_number"],
        "numeric_issue_id": record["numeric_issue_id"],
    })


@dataclass(frozen=True)
class TypedEndpoint:
    endpoint_type: str
    ref: str

    def to_dict(self) -> dict[str, str]:
        if self.endpoint_type not in {"work_item", "existing_issue"} or not self.ref:
            raise ValueError("endpoint_reference_invalid")
        return {"endpoint_type": self.endpoint_type,
                "client_ref" if self.endpoint_type == "work_item" else "endpoint_ref": self.ref}


@dataclass(frozen=True)
class SealedExistingEndpoint:
    endpoint_ref: str
    selector_digest: str
    issue_id: str
    remote_record_digest: str
    identity_digest: str
    write_address_digest: str
    semantic_digest: str

    def to_dict(self) -> dict[str, str]:
        return normalize({
            "endpoint_ref": self.endpoint_ref,
            "selector_digest": self.selector_digest,
            "issue_id": self.issue_id,
            "remote_record_digest": self.remote_record_digest,
            "identity_digest": self.identity_digest,
            "write_address_digest": self.write_address_digest,
            "semantic_digest": self.semantic_digest,
        })


def endpoint_from_dict(value: Mapping[str, Any]) -> TypedEndpoint:
    if not isinstance(value, Mapping) or set(value) not in ({"endpoint_type", "client_ref"}, {"endpoint_type", "endpoint_ref"}):
        raise ValueError("endpoint_reference_invalid")
    kind = value.get("endpoint_type")
    key = "client_ref" if kind == "work_item" else "endpoint_ref" if kind == "existing_issue" else None
    if key is None or set(value) != {"endpoint_type", key}:
        raise ValueError("endpoint_reference_invalid")
    ref = value.get(key)
    if not isinstance(ref, str) or not ref.strip():
        raise ValueError("endpoint_reference_invalid")
    return TypedEndpoint(kind, ref)


def _v2_record_from_driver(record: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize a trusted read-driver Issue record to the V2 endpoint shape."""
    return {
        "issue_id": record.get("issue_id", record.get("node_id")),
        "numeric_issue_id": record.get("numeric_issue_id", record.get("numeric_id")),
        "issue_number": record.get("issue_number", record.get("number")),
        "item_type": record.get("item_type"),
        "title": record.get("title"),
        "body": record.get("body"),
        "state": record.get("state"),
        "updated_at": record.get("updated_at"),
        "repository_identity": record.get("repository_identity"),
    }


class ExistingEndpointRevalidator:
    """Host-owned, read-only verification for sealed existing endpoints."""

    def __init__(self, driver: Any, trust_context: Any) -> None:
        if not callable(getattr(driver, "read_repository", None)):
            raise ValueError("existing_endpoint_revalidator_invalid")
        if not isinstance(getattr(trust_context, "trusted_driver_identity", None), str):
            raise ValueError("existing_endpoint_revalidator_invalid")
        self.driver = driver
        self.trust_context = trust_context

    def __call__(
        self,
        context: Any,
        endpoint_ref: str,
        operation_kind: str | None = None,
        references: tuple[Any, ...] | list[Any] | None = None,
    ) -> bool:
        from delivery_system.drivers.preflight import validate_driver_facts

        bindings = getattr(context, "_existing_endpoint_bindings", ())
        binding = next((item for item in bindings if item.get("endpoint_ref") == endpoint_ref), None)
        if not isinstance(binding, Mapping):
            raise ValueError("existing_endpoint_identity_mismatch")
        repository = context.repository_identity
        query_scope = getattr(self.driver, "fixed_query_scope", None)
        if not isinstance(query_scope, Mapping) or not query_scope:
            raise ValueError("remote_observation_unavailable")
        facts, failures = validate_driver_facts(
            self.driver,
            repository,
            query_scope,
            self.trust_context.trusted_driver_identity,
        )
        if failures or facts is None:
            codes = {getattr(failure, "code", None) for failure in failures}
            if "repository_identity_mismatch" in codes or "requested_repository_mismatch" in codes:
                raise ValueError("existing_endpoint_repository_mismatch")
            raise ValueError("remote_observation_unavailable")
        records = [_v2_record_from_driver(record) for record in facts.response.issue_records]
        record = next((item for item in records if item.get("issue_id") == binding.get("issue_id")), None)
        if record is None:
            raise ValueError("existing_endpoint_not_found")
        if record.get("repository_identity") != repository or record.get("item_type") != "issue":
            raise ValueError("existing_endpoint_repository_mismatch")
        if identity_digest(record) != binding.get("identity_digest"):
            raise ValueError("existing_endpoint_identity_mismatch")
        if write_address_digest(record) != binding.get("write_address_digest"):
            raise ValueError("existing_endpoint_write_address_invalid")
        if semantic_digest(record) != binding.get("semantic_digest"):
            raise ValueError("existing_endpoint_semantic_stale")
        if operation_kind in {"add_sub_issue", "add_dependency"} and references is not None:
            if len(references) != 2:
                raise ValueError("remote_observation_unavailable")
            relation_kind = "existing_parent" if operation_kind == "add_sub_issue" else "existing_dependency"
            endpoint_ids = {getattr(reference, "node_id", None) for reference in references}
            if None in endpoint_ids or len(endpoint_ids) != 2:
                raise ValueError("remote_observation_unavailable")
            for relation in facts.response.relationship_records:
                if (
                    relation.get("kind") == relation_kind
                    and relation.get("from") == getattr(references[0], "node_id", None)
                    and relation.get("to") == getattr(references[1], "node_id", None)
                ):
                    raise ValueError("relationship_already_exists")
        return True
def selector_digest(selector: Mapping[str, object]) -> str:
    number = selector.get("number")
    url = selector.get("url")
    if number is None and url is None:
        raise ValueError("existing_endpoint_selector_required")
    if number is not None and (type(number) is not int or number < 1):
        raise ValueError("existing_endpoint_selector_invalid")
    if url is not None and (not isinstance(url, str) or not url.strip()):
        raise ValueError("existing_endpoint_selector_invalid")
    return digest({"domain": "delivery-system:existing-issue-selector:v1", "number": number, "url": url})


def validate_issue_selector_url(url: object, repository_identity: str) -> int:
    """Validate and extract a canonical public GitHub Issue URL number."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("existing_endpoint_selector_invalid")
    try:
        parsed = urlparse(url)
        if (parsed.scheme.casefold() != "https" or parsed.hostname is None or
                parsed.hostname.casefold() != "github.com" or parsed.username is not None or
                parsed.password is not None or parsed.port not in (None, 443) or
                parsed.query or parsed.fragment or parsed.params):
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError("existing_endpoint_selector_invalid") from None
    match = re.fullmatch(r"/([^/]+)/([^/]+)/issues/([1-9][0-9]*)", parsed.path)
    if match is None:
        raise ValueError("existing_endpoint_selector_invalid")
    expected = "/".join(part.casefold() for part in repository_identity.split("/"))
    if "/".join((match.group(1), match.group(2))).casefold() != expected:
        raise ValueError("existing_endpoint_repository_mismatch")
    return int(match.group(3))
