"""Guarded, one-read GitHub integration harness for the personal test repository."""

from __future__ import annotations

from dataclasses import dataclass
import getpass
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from delivery_system.auditor import RuleEvaluationDraft, RuntimeAuditor
from delivery_system.drivers.contract import DriverError, DriverReadResponse, DriverTrustContext
from delivery_system.drivers.preflight import validate_driver_facts
from delivery_system.drivers.rest import API_HOST, API_ORIGIN, HttpsRestTransport, LocalRestReadOnlyDriver, TransportResponse
from delivery_system.rules import SemanticOutcome, build_registry_v1
from delivery_system.runtime import InMemoryPreviewStore, RuntimeContext, RuntimePlanner


TARGET_REPOSITORY = "zevsol/delivery-system-integration-test"
TARGET_OWNER = "zevsol"
TARGET_NAME = "delivery-system-integration-test"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_PATH = REPOSITORY_ROOT / ".dev" / "integration-evidence" / "personal-repo-readonly.json"
EVIDENCE_SCHEMA_VERSION = "personal-repo-readonly-v1"
ALLOWED_METHOD = "GET"
REPORT_KEYS = frozenset({
    "schema_version", "target_repository", "authenticated_login", "visibility",
    "issue_numbers", "relationships", "requests", "request_count",
    "query_complete", "pagination_complete", "remote_content_digest",
    "remote_snapshot_digest", "preview_level", "write_eligible",
    "remote_snapshot_exposed", "audit_result", "approval_created",
    "operation_created", "findings", "overall_result",
})
REQUEST_KEYS = frozenset({"method", "path", "status"})
RELATIONSHIP_KEYS = frozenset({"kind", "from_issue", "to_issue"})
FINDING_KEYS = frozenset({
    "kind", "remote_repository_permissions", "pat_configuration",
    "observed_http_methods", "write_permission_inference",
})
_REPOSITORY_PREFIX = f"/repos/{TARGET_OWNER}/{TARGET_NAME}"
_ISSUE_PATH = re.compile(r"^" + re.escape(_REPOSITORY_PREFIX) + r"/issues/([1-4])/(.+)$")
_POSITIVE_INTEGER = re.compile(r"^[1-9][0-9]*$")
_FORBIDDEN_TEXT = ("Authorization", "Headers", "Issue title", "Issue body")
SAFE_HARNESS_ERROR_CODES = frozenset({
    "interactive_terminal_required", "pat_required", "method_not_allowed",
    "path_invalid", "path_traversal_forbidden", "query_invalid",
    "query_not_allowed_or_incomplete", "endpoint_not_allowed", "origin_not_allowed",
    "transport_failed", "redirect_forbidden", "real_remote_read_already_completed",
    "replay_scope_mismatch", "authenticated_identity_mismatch",
    "repository_identity_or_visibility_mismatch", "issue_set_mismatch",
    "relationship_facts_missing", "query_incomplete", "runtime_binding_failed",
    "audit_approval_boundary_failed", "permission_facts_invalid",
    "evidence_schema_invalid", "evidence_redaction_failed", "driver_preflight_failed",
})


class HarnessError(RuntimeError):
    """Secret-free, stable harness failure."""


@dataclass(frozen=True)
class RequestRecord:
    method: str
    path: str
    status: int

    def to_dict(self) -> dict[str, object]:
        return {"method": self.method, "path": self.path, "status": self.status}


def _query(path: str, required: Mapping[str, str], optional: str | None = None) -> None:
    parsed = urlsplit(path)
    if not parsed.query:
        raise HarnessError("query_not_allowed_or_incomplete")
    try:
        pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise HarnessError("query_invalid") from exc
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)) or any(not key or not value for key, value in pairs):
        raise HarnessError("query_invalid")
    values = dict(pairs)
    if any(values.get(key) != value for key, value in required.items()):
        raise HarnessError("query_invalid")
    allowed = set(required) | ({optional} if optional else set())
    if any(key not in allowed for key in keys):
        raise HarnessError("query_invalid")
    if optional and optional in values and not _POSITIVE_INTEGER.fullmatch(values[optional]):
        raise HarnessError("query_invalid")


def _validate_endpoint(path: str) -> None:
    if not isinstance(path, str) or not path:
        raise HarnessError("path_invalid")
    if any(ord(char) > 0x7F or ord(char) <= 0x20 or ord(char) == 0x7F for char in path):
        raise HarnessError("path_invalid")
    if not path.startswith("/") or path.startswith("//") or "\\" in path or "%" in path:
        raise HarnessError("path_invalid")
    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        raise HarnessError("path_invalid")
    normalized = urlunsplit(("", "", parsed.path, parsed.query, ""))
    if normalized != path:
        raise HarnessError("query_invalid")
    if any(segment in {".", ".."} for segment in parsed.path.split("/")):
        raise HarnessError("path_traversal_forbidden")
    if parsed.path == "/user":
        if parsed.query:
            raise HarnessError("query_invalid")
        return
    if parsed.path == _REPOSITORY_PREFIX:
        if parsed.query:
            raise HarnessError("query_invalid")
        return
    if parsed.path == _REPOSITORY_PREFIX + "/issues":
        _query(path, {"state": "all", "per_page": "100"}, "page")
        return
    match = _ISSUE_PATH.fullmatch(parsed.path)
    if match:
        suffix = match.group(2)
        if suffix == "parent":
            if parsed.query:
                raise HarnessError("query_invalid")
            return
        if suffix in {"sub_issues", "dependencies/blocked_by", "dependencies/blocking"}:
            _query(path, {"per_page": "100"}, "page")
            return
    raise HarnessError("endpoint_not_allowed")


class GuardedRecordingTransport:
    """Test-only exact endpoint boundary around the existing HTTPS transport."""

    def __init__(self, token_provider: Any) -> None:
        self._inner = HttpsRestTransport(token_provider)
        self._records: list[RequestRecord] = []

    @property
    def records(self) -> tuple[RequestRecord, ...]:
        return tuple(self._records)

    def request(self, method: str, path: str, headers: Mapping[str, str]) -> TransportResponse:
        if method != ALLOWED_METHOD:
            raise HarnessError("method_not_allowed")
        _validate_endpoint(path)
        if API_ORIGIN != "https://" + API_HOST:
            raise HarnessError("origin_not_allowed")
        try:
            response = self._inner.request(method, path, headers)
        except DriverError:
            raise
        except Exception as exc:
            raise HarnessError("transport_failed") from exc
        if response.status in {301, 302, 303, 307, 308}:
            raise HarnessError("redirect_forbidden")
        self._records.append(RequestRecord(method, path, response.status))
        return response


class CaptureDriver:
    def __init__(self, driver: LocalRestReadOnlyDriver) -> None:
        self.driver = driver
        self.response: DriverReadResponse | None = None

    def read_repository(self, repository: str, query_scope: Mapping[str, object]) -> DriverReadResponse:
        if self.response is not None:
            raise HarnessError("real_remote_read_already_completed")
        self.response = self.driver.read_repository(repository, query_scope)
        return self.response


class ReplayDriver:
    """Replays the captured response without a transport or network."""

    def __init__(self, response: DriverReadResponse) -> None:
        self.response = response
        self.calls = 0

    def read_repository(self, repository: str, query_scope: Mapping[str, object]) -> DriverReadResponse:
        self.calls += 1
        if repository != self.response.requested_repository or dict(query_scope) != dict(self.response.query_scope):
            raise HarnessError("replay_scope_mismatch")
        return self.response


def require_interactive_terminal() -> None:
    try:
        interactive = bool(sys.stdin.isatty() and sys.stderr.isatty())
        sys.stdin.fileno()
    except (AttributeError, OSError, ValueError):
        interactive = False
    if not interactive:
        raise HarnessError("interactive_terminal_required")


def read_pat() -> str:
    require_interactive_terminal()
    token = getpass.getpass("GitHub Fine-grained PAT: ")
    if not token:
        raise HarnessError("pat_required")
    return token


def _issue_numbers(response: DriverReadResponse) -> list[int]:
    return sorted(int(item["number"]) for item in response.issue_records)


def _check_remote_facts(response: DriverReadResponse) -> None:
    if response.authenticated_login != TARGET_OWNER:
        raise HarnessError("authenticated_identity_mismatch")
    if response.canonical_repository != TARGET_REPOSITORY or response.visibility != "private":
        raise HarnessError("repository_identity_or_visibility_mismatch")
    if _issue_numbers(response) != [1, 2, 3, 4]:
        raise HarnessError("issue_set_mismatch")
    ids = {int(item["number"]): item["issue_id"] for item in response.issue_records}
    relationships = {(item["kind"], item["from"], item["to"]) for item in response.relationship_records}
    if {("existing_parent", ids[2], ids[1]), ("existing_dependency", ids[4], ids[3])} - relationships:
        raise HarnessError("relationship_facts_missing")
    if not response.query_complete or not response.pagination_complete:
        raise HarnessError("query_incomplete")


def _plan() -> dict[str, object]:
    def sourced(value: object, source: str = "user_asserted") -> dict[str, object]:
        return {"value": value, "declared_source": source}
    return {"repository_claim": {"owner": TARGET_OWNER, "name": TARGET_NAME}, "work_items": [{
        "client_ref": "integration-check", "role": sourced("Research/Decision", "model_proposed"),
        "title": sourced("Read-only integration verification"), "context_problem": sourced("Verify scoped remote facts."),
        "outcome": sourced("Remote facts are safely bound."), "scope": sourced(["read-only harness"]),
        "non_goals": sourced(["GitHub writes"], "model_assumption"), "acceptance_criteria": sourced(["All checks pass"]),
        "verification": sourced(["Offline replay audit"]), "required_capabilities": sourced(["issues"]),
        "write_metadata": sourced({}, "model_proposed"),
    }], "planned_relationships": [], "operation_intents": []}


def _run_replay(response: DriverReadResponse) -> tuple[dict[str, object], str, bool, bool, bool, bool]:
    replay = ReplayDriver(response)
    trust = DriverTrustContext(LocalRestReadOnlyDriver.trusted_driver_identity, API_ORIGIN, LocalRestReadOnlyDriver.contract_version)
    with tempfile.TemporaryDirectory() as directory:
        context = RuntimeContext.from_workspace_root(directory)
        store = InMemoryPreviewStore(context.workspace_identity, trust)
        preview = RuntimePlanner(context, store, replay, trust).preview(_plan())
        operation_created = bool(preview["operation_intents"])
        remote_snapshot_exposed = preview["remote_snapshot"] is not None
        if replay.calls != 1 or preview["preview_level"] != "RepositoryAware" or preview["write_eligible"] or operation_created or remote_snapshot_exposed:
            raise HarnessError("runtime_binding_failed")
        auditor = RuntimeAuditor(context, store, build_registry_v1(), trust)
        audit_context = auditor.get_context(preview["preview_id"], preview["revision"])
        evaluations = [RuleEvaluationDraft(item["rule_id"], item["rule_version"], SemanticOutcome.PASSED, "verified") for item in audit_context["semantic_rule_contexts"] if item["applicability"] == "Applicable"]
        audit = auditor.record_audit(preview["preview_id"], preview["revision"], audit_context["audit_context_digest"], evaluations, [])
        approval_created = bool(store._approvals)
        audit_approval_eligible = bool(audit.approval_eligible)
        if audit.result.value != "Passed" or approval_created or audit_approval_eligible:
            raise HarnessError("audit_approval_boundary_failed")
        return preview, audit.result.value, approval_created, operation_created, remote_snapshot_exposed, audit_approval_eligible


def _build_report(response: DriverReadResponse, recorder: GuardedRecordingTransport, preview: Mapping[str, object], audit_result: str, approval_created: bool, operation_created: bool, remote_snapshot_exposed: bool) -> dict[str, object]:
    by_id = {item["issue_id"]: int(item["number"]) for item in response.issue_records}
    if any(key not in response.permissions or not isinstance(response.permissions[key], bool) for key in ("read", "write")):
        raise HarnessError("permission_facts_invalid")
    report = {
        "schema_version": EVIDENCE_SCHEMA_VERSION, "target_repository": TARGET_REPOSITORY,
        "authenticated_login": response.authenticated_login, "visibility": response.visibility,
        "issue_numbers": _issue_numbers(response),
        "relationships": [{"kind": item["kind"], "from_issue": by_id[item["from"]], "to_issue": by_id[item["to"]]} for item in response.relationship_records],
        "requests": [record.to_dict() for record in recorder.records], "request_count": len(recorder.records),
        "query_complete": response.query_complete, "pagination_complete": response.pagination_complete,
        "remote_content_digest": response.remote_content_digest, "remote_snapshot_digest": preview["remote_snapshot_digest"],
        "preview_level": preview["preview_level"], "write_eligible": preview["write_eligible"],
        "remote_snapshot_exposed": remote_snapshot_exposed, "audit_result": audit_result,
        "approval_created": approval_created, "operation_created": operation_created,
        "findings": [{
            "kind": "permission_facts_separated",
            "remote_repository_permissions": {key: bool(response.permissions[key]) for key in ("read", "write")},
            "pat_configuration": "operator-declared, not runtime-verified",
            "observed_http_methods": sorted({record.method for record in recorder.records}),
            "write_permission_inference": "not_inferred_from_repository_permissions",
        }], "overall_result": "passed",
    }
    _validate_report(report)
    return report


def _validate_report(report: Mapping[str, object]) -> None:
    if set(report) != REPORT_KEYS:
        raise HarnessError("evidence_schema_invalid")
    if report["schema_version"] != EVIDENCE_SCHEMA_VERSION or report["target_repository"] != TARGET_REPOSITORY:
        raise HarnessError("evidence_schema_invalid")
    if report["authenticated_login"] != TARGET_OWNER or report["visibility"] != "private":
        raise HarnessError("evidence_schema_invalid")
    if report["preview_level"] != "RepositoryAware" or report["write_eligible"] is not False:
        raise HarnessError("evidence_schema_invalid")
    if any(not isinstance(report[key], bool) for key in ("query_complete", "pagination_complete", "write_eligible", "remote_snapshot_exposed", "approval_created", "operation_created")):
        raise HarnessError("evidence_schema_invalid")
    if report["remote_snapshot_exposed"] or report["approval_created"] or report["operation_created"]:
        raise HarnessError("evidence_schema_invalid")
    if not report["query_complete"] or not report["pagination_complete"] or report["audit_result"] != "Passed" or report["overall_result"] != "passed":
        raise HarnessError("evidence_schema_invalid")
    import re as _re
    digest_pattern = _re.compile(r"^sha256:[0-9a-f]{64}$")
    if not isinstance(report["remote_content_digest"], str) or not digest_pattern.fullmatch(report["remote_content_digest"]):
        raise HarnessError("evidence_schema_invalid")
    if not isinstance(report["remote_snapshot_digest"], str) or not digest_pattern.fullmatch(report["remote_snapshot_digest"]):
        raise HarnessError("evidence_schema_invalid")
    if not isinstance(report["issue_numbers"], list) or report["issue_numbers"] != [1, 2, 3, 4]:
        raise HarnessError("evidence_schema_invalid")
    if not isinstance(report["requests"], list) or not report["requests"]:
        raise HarnessError("evidence_schema_invalid")
    if isinstance(report["request_count"], bool) or not isinstance(report["request_count"], int) or report["request_count"] < 1 or report["request_count"] != len(report["requests"]):
        raise HarnessError("evidence_schema_invalid")
    for request in report["requests"]:
        if not isinstance(request, Mapping) or set(request) != REQUEST_KEYS:
            raise HarnessError("evidence_schema_invalid")
        if request["method"] != "GET" or not isinstance(request["path"], str) or isinstance(request["status"], bool) or not isinstance(request["status"], int) or not 100 <= request["status"] <= 599:
            raise HarnessError("evidence_schema_invalid")
        try:
            _validate_endpoint(request["path"])
        except HarnessError as exc:
            raise HarnessError("evidence_schema_invalid") from exc
    for relation in report["relationships"]:
        if not isinstance(relation, Mapping) or set(relation) != RELATIONSHIP_KEYS:
            raise HarnessError("evidence_schema_invalid")
        if relation["kind"] not in {"existing_parent", "existing_dependency"} or any(isinstance(relation[key], bool) or not isinstance(relation[key], int) or relation[key] not in {1, 2, 3, 4} for key in ("from_issue", "to_issue")):
            raise HarnessError("evidence_schema_invalid")
    expected_relationships = {("existing_parent", 2, 1), ("existing_dependency", 4, 3)}
    actual_relationships = {(item["kind"], item["from_issue"], item["to_issue"]) for item in report["relationships"]}
    if len(report["relationships"]) != 2 or actual_relationships != expected_relationships:
        raise HarnessError("evidence_schema_invalid")
    if not isinstance(report["findings"], list) or len(report["findings"]) != 1:
        raise HarnessError("evidence_schema_invalid")
    for finding in report["findings"]:
        if not isinstance(finding, Mapping) or set(finding) != FINDING_KEYS:
            raise HarnessError("evidence_schema_invalid")
        permissions = finding["remote_repository_permissions"]
        if set(permissions) != {"read", "write"} or not all(isinstance(value, bool) for value in permissions.values()):
            raise HarnessError("evidence_schema_invalid")
        if finding["pat_configuration"] != "operator-declared, not runtime-verified":
            raise HarnessError("evidence_schema_invalid")
        if finding["kind"] != "permission_facts_separated" or finding["observed_http_methods"] != ["GET"] or finding["write_permission_inference"] != "not_inferred_from_repository_permissions":
            raise HarnessError("evidence_schema_invalid")
    serialized = json.dumps(report, sort_keys=True, ensure_ascii=True)
    if any(value in serialized for value in _FORBIDDEN_TEXT) or "@" in serialized:
        raise HarnessError("evidence_redaction_failed")


def _write_report(report: Mapping[str, object]) -> None:
    _validate_report(report)
    EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=EVIDENCE_PATH.parent, prefix=".personal-repo-readonly.", suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(json.dumps(report, sort_keys=True, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, EVIDENCE_PATH)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def run_live() -> dict[str, object]:
    require_interactive_terminal()
    token = read_pat()
    provider = None
    try:
        provider = type("InteractiveTokenProvider", (), {"get_token": lambda self: token})()
        recorder = GuardedRecordingTransport(provider)
        driver = CaptureDriver(LocalRestReadOnlyDriver(transport=recorder, token_provider=provider))
        facts, failures = validate_driver_facts(driver, TARGET_REPOSITORY, LocalRestReadOnlyDriver.fixed_query_scope, LocalRestReadOnlyDriver.trusted_driver_identity)
        if failures or facts is None or driver.response is None:
            raise HarnessError("driver_preflight_failed")
        _check_remote_facts(driver.response)
        preview, audit_result, approval_created, operation_created, remote_snapshot_exposed, _ = _run_replay(driver.response)
        report = _build_report(driver.response, recorder, preview, audit_result, approval_created, operation_created, remote_snapshot_exposed)
        _write_report(report)
        return report
    finally:
        provider = None
        token = None


def main() -> int:
    try:
        run_live()
        return 0
    except KeyboardInterrupt:
        print("integration_harness_interrupted", file=sys.stderr)
        return 130
    except HarnessError as exc:
        code = str(exc) if str(exc) in SAFE_HARNESS_ERROR_CODES else "integration_harness_failed"
        print(code, file=sys.stderr)
        return 2
    except DriverError:
        print("integration_harness_driver_failed", file=sys.stderr)
        return 2
    except Exception:
        print("integration_harness_failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
