from __future__ import annotations

import unittest
from dataclasses import replace
from typing import cast

from delivery_system.drivers.contract import DriverReadResponse, ReadOnlyDriver, RuntimeEvidenceBinding
from delivery_system.drivers.preflight import run_preflight
from delivery_system.protocol import digest
from delivery_system.runtime import EvidenceRecord, _preview_is_approval_eligible
from tests.fakes.preflight_driver import PreflightFakeDriver


REPOSITORY = "Owner/Repo"
SCOPE = {"issues": "all", "relationships": "required", "page_size": 100}
BINDING = RuntimeEvidenceBinding("workspace-driver-test", "preview-driver-test", 1)
TRUSTED_IDENTITY = "driver-fixture"


def material(issue_records: tuple[dict[str, object], ...], relationship_records: tuple[dict[str, object], ...], *, source_identity: str = TRUSTED_IDENTITY) -> dict[str, object]:
    return {
        "evidence_type": "driver_repository_read",
        "subject_ref": "repository:owner/repo",
        "source_identity": source_identity,
        "repository_identity": "owner/repo",
        "query_scope": SCOPE,
        "payload": {"issue_records": list(issue_records), "relationship_records": list(relationship_records)},
    }


def response(**changes: object) -> DriverReadResponse:
    issues = ({
        "issue_id": "1", "item_type": "issue", "title": "Existing work",
        "updated_at": "2026-08-13T00:00:00+00:00", "repository_identity": "owner/repo",
    },)
    relationships: tuple[dict[str, object], ...] = ()
    base = DriverReadResponse(
        requested_repository=REPOSITORY,
        canonical_repository="owner/repo",
        remote_repository_id="node-repo-1",
        authenticated_subject="user-1",
        visibility="private",
        permissions={"read": True, "write": False},
        capabilities={"issues": True, "relationships": True},
        query_scope=SCOPE,
        query_complete=True,
        pagination_complete=True,
        issue_records=issues,
        relationship_records=relationships,
        evidence_material=(material(issues, relationships),),
        source_identity=TRUSTED_IDENTITY,
        remote_content_digest="placeholder",
    )
    candidate = replace(base, **changes)
    content_payload = {
        "requested_repository": candidate.requested_repository,
        "canonical_repository": candidate.canonical_repository,
        "remote_repository_id": candidate.remote_repository_id,
        "authenticated_subject": candidate.authenticated_subject,
        "visibility": candidate.visibility,
        "permissions": dict(candidate.permissions),
        "capabilities": dict(candidate.capabilities),
        "query_scope": dict(candidate.query_scope),
        "query_complete": candidate.query_complete,
        "pagination_complete": candidate.pagination_complete,
        "issue_records": list(candidate.issue_records),
        "relationship_records": list(candidate.relationship_records),
        "evidence_material": list(candidate.evidence_material),
        "source_identity": TRUSTED_IDENTITY,
    }
    if "remote_content_digest" not in changes:
        try:
            candidate = replace(candidate, remote_content_digest=digest(content_payload))
        except (TypeError, ValueError):
            candidate = replace(candidate, remote_content_digest="placeholder")
    return candidate


def run(driver: PreflightFakeDriver, **kwargs: object):
    trusted = kwargs.pop("trusted_driver_identity", TRUSTED_IDENTITY)
    return run_preflight(driver, REPOSITORY, SCOPE, BINDING, cast(str, trusted), **kwargs)


class DriverContractTests(unittest.TestCase):
    def test_protocol_is_read_only_and_fake_records_only_read(self):
        self.assertTrue(hasattr(ReadOnlyDriver, "read_repository"))
        self.assertFalse(any(name in ReadOnlyDriver.__dict__ for name in ("write", "create_issue", "update_issue")))
        driver = PreflightFakeDriver(response())
        result = run(driver)
        self.assertTrue(result.passed)
        self.assertEqual([entry["operation"] for entry in driver.trace], ["read_repository"])

    def test_complete_preflight_creates_runtime_bound_typed_evidence_and_snapshot(self):
        result = run(PreflightFakeDriver(response()))
        self.assertTrue(result.passed)
        self.assertIsInstance(result.evidence_records[0], EvidenceRecord)
        self.assertEqual(result.evidence_records[0].workspace_identity, BINDING.workspace_identity)
        self.assertEqual(result.evidence_records[0].preview_id, BINDING.preview_id)
        self.assertEqual(result.evidence_records[0].revision, BINDING.revision)
        self.assertEqual(result.evidence_records[0].source_identity, TRUSTED_IDENTITY)
        self.assertEqual(result.snapshot.evidence_ids, (result.evidence_records[0].evidence_id,))

    def test_same_input_is_deterministic(self):
        first = run(PreflightFakeDriver(response())).to_dict()
        second = run(PreflightFakeDriver(response())).to_dict()
        self.assertEqual(first, second)

    def test_all_authoritative_facts_change_evidence_or_snapshot(self):
        base = run(PreflightFakeDriver(response()))
        mutations = (
            {"remote_repository_id": "node-repo-2"},
            {"authenticated_subject": "user-2"},
            {"visibility": "public"},
            {"permissions": {"read": True, "write": True}},
            {"capabilities": {"issues": True, "relationships": False}},
            {"query_scope": {"issues": "open", "relationships": "required", "page_size": 100}},
            {"query_complete": False},
            {"pagination_complete": False},
            {"issue_records": ({"issue_id": "1", "item_type": "issue", "title": "Changed", "updated_at": "2026-08-13T00:00:00+00:00", "repository_identity": "owner/repo"},)},
            {"relationship_records": ({"kind": "existing_parent", "from": "1", "to": "1"},)},
        )
        for changes in mutations:
            with self.subTest(changes=changes):
                changed = run(PreflightFakeDriver(response(**changes)))
                if changed.passed:
                    self.assertNotEqual((base.evidence_records[0].evidence_id, base.snapshot.digest()), (changed.evidence_records[0].evidence_id, changed.snapshot.digest()))
                else:
                    self.assertTrue(changed.failures)

    def test_evidence_material_must_match_remote_records(self):
        raw = material(({
            "issue_id": "1", "item_type": "issue", "title": "Wrong", "updated_at": "2026-08-13T00:00:00+00:00", "repository_identity": "owner/repo",
        },), ())
        result = run(PreflightFakeDriver(response(evidence_material=(raw,))))
        self.assertFalse(result.passed)
        self.assertEqual(result.failures[0].code, "evidence_remote_content_mismatch")

    def test_runtime_identity_in_driver_material_is_rejected(self):
        raw = material(({
            "issue_id": "1", "item_type": "issue", "title": "Existing work", "updated_at": "2026-08-13T00:00:00+00:00", "repository_identity": "owner/repo",
        },), ())
        raw["preview_id"] = "driver-selected-preview"
        result = run(PreflightFakeDriver(response(evidence_material=(raw,))))
        self.assertFalse(result.passed)
        self.assertEqual(result.failures[0].code, "driver_response_invalid")

    def test_trusted_driver_identity_is_independent_and_exact(self):
        self.assertEqual(run(PreflightFakeDriver(response())).passed, True)
        self.assertEqual(run(PreflightFakeDriver(response(source_identity="other-driver"))).failures[0].code, "driver_identity_untrusted")
        self.assertEqual(run(PreflightFakeDriver(response(source_identity=""))).failures[0].code, "driver_identity_untrusted")
        self.assertEqual(run(PreflightFakeDriver(response()), trusted_driver_identity="").failures[0].code, "driver_identity_untrusted")
        raw = material(({
            "issue_id": "1", "item_type": "issue", "title": "Existing work", "updated_at": "2026-08-13T00:00:00+00:00", "repository_identity": "owner/repo",
        },), (), source_identity="other-driver")
        result = run(PreflightFakeDriver(response(evidence_material=(raw,))))
        self.assertEqual(result.failures[0].code, "evidence_source_untrusted")

    def test_minimum_requirements_cannot_be_removed(self):
        self.assertTrue(run(PreflightFakeDriver(response()), required_permissions=(), required_capabilities=()).passed)
        self.assertEqual(run(PreflightFakeDriver(response(permissions={"read": False})), required_permissions=()).failures[0].code, "permission_insufficient")
        self.assertEqual(run(PreflightFakeDriver(response(permissions={"read": None})), required_permissions=()).failures[0].code, "permission_unknown")
        self.assertEqual(run(PreflightFakeDriver(response(capabilities={"issues": True, "relationships": False})), required_capabilities=()).failures[0].code, "capability_insufficient")
        self.assertEqual(run(PreflightFakeDriver(response(capabilities={"issues": True, "relationships": None})), required_capabilities=()).failures[0].code, "capability_unknown")
        self.assertEqual(run(PreflightFakeDriver(response()), required_capabilities=("",)).failures[0].code, "requirements_invalid")
        self.assertEqual(run(PreflightFakeDriver(response()), required_capabilities=("issues", "issues")).failures[0].code, "requirements_invalid")

    def test_failure_closed_cases_are_structured(self):
        cases = (
            (response(authenticated_subject=None), "authenticated_subject_unknown"),
            (response(canonical_repository="owner/other"), "repository_identity_mismatch"),
            (response(pagination_complete=False), "pagination_incomplete"),
            (response(query_complete=False), "query_scope_incomplete"),
            (response(query_scope={"issues": "all"}), "query_scope_mismatch"),
            (response(evidence_material=()), "evidence_missing"),
            (response(remote_content_digest="wrong"), "remote_state_inconsistent"),
        )
        for candidate, code in cases:
            with self.subTest(code=code):
                result = run(PreflightFakeDriver(candidate))
                self.assertFalse(result.passed)
                self.assertEqual(result.failures[0].code, code)
                self.assertIsNone(result.snapshot)

    def test_malformed_records_and_response_are_structured(self):
        for field in ("issue_records", "relationship_records", "evidence_material"):
            with self.subTest(field=field):
                result = run(PreflightFakeDriver(response(**{field: (object(),)})))
                self.assertFalse(result.passed)
                self.assertEqual(result.failures[0].code, "driver_response_invalid")
        result = run(PreflightFakeDriver(response=cast(DriverReadResponse, object())))
        self.assertEqual(result.failures[0].code, "driver_response_invalid")
        result = run(PreflightFakeDriver(response(permissions={1: True})))
        self.assertEqual(result.failures[0].code, "driver_response_invalid")
        result = run(PreflightFakeDriver(response(visibility=[])))
        self.assertEqual(result.failures[0].code, "repository_visibility_unknown")

    def test_driver_exception_and_bad_digest_are_structured(self):
        result = run(PreflightFakeDriver(error=TimeoutError()))
        self.assertEqual(result.failures[0].code, "driver_call_failed")
        result = run(PreflightFakeDriver(response(remote_content_digest="sha256:wrong")))
        self.assertEqual(result.failures[0].code, "remote_state_inconsistent")

    def test_binding_is_exact_and_write_permission_is_not_human_approval(self):
        result = run(PreflightFakeDriver(response()))
        changed_binding = RuntimeEvidenceBinding("workspace-2", "preview-2", 2)
        changed = run_preflight(PreflightFakeDriver(response()), REPOSITORY, SCOPE, changed_binding, TRUSTED_IDENTITY)
        self.assertNotEqual(result.evidence_records[0].evidence_id, changed.evidence_records[0].evidence_id)
        self.assertTrue(result.passed)
        self.assertFalse(hasattr(result, "approval_record"))
        self.assertFalse(any("approval" in field for field in result.to_dict()))
        self.assertFalse(_preview_is_approval_eligible({"canonical_payload": {}}))

    def test_write_true_still_does_not_create_human_approval(self):
        result = run(PreflightFakeDriver(response(permissions={"read": True, "write": True})))
        self.assertTrue(result.passed)
        self.assertFalse(hasattr(result, "approval_record"))
        self.assertFalse(any("approval" in field for field in result.to_dict()))


if __name__ == "__main__":
    unittest.main()
