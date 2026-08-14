from __future__ import annotations

import io
import json
import os
from pathlib import Path
from unittest import TestCase, mock

from delivery_system.drivers.contract import DriverReadResponse
from delivery_system.drivers.rest import AUTOMATIC_RETRIES, TransportResponse
from delivery_system.protocol import digest
from tests.integration.github_readonly_live import (
    EVIDENCE_PATH, EVIDENCE_SCHEMA_VERSION, FINDING_KEYS, RELATIONSHIP_KEYS,
    REPORT_KEYS, REQUEST_KEYS, REPOSITORY_ROOT, TARGET_REPOSITORY,
    SAFE_HARNESS_ERROR_CODES, CaptureDriver, GuardedRecordingTransport, HarnessError, ReplayDriver,
    _build_report, _check_remote_facts, _run_replay, _validate_endpoint,
    _validate_report, main, require_interactive_terminal,
)


SENTINEL = "SENTINEL_PAT_DO_NOT_LEAK"


def response() -> DriverReadResponse:
    issues = [{"issue_id": f"I{i}", "numeric_id": str(i), "node_id": f"I{i}", "number": i, "item_type": "issue", "title": "fixture", "updated_at": "2026-08-13T00:00:00+00:00", "repository_identity": TARGET_REPOSITORY, "repository_url": "https://api.github.com/repos/zevsol/delivery-system-integration-test"} for i in range(1, 5)]
    relationships = [{"kind": "existing_parent", "from": "I2", "to": "I1"}, {"kind": "existing_dependency", "from": "I4", "to": "I3"}]
    scope = {"api_origin": "https://api.github.com", "api_version": "2026-03-10", "issue_state": "all", "pull_request_filter": "pull_request_field_excluded", "relationships": ["sub_issues", "parent", "blocked_by", "blocking"], "pagination_protocol": "link-header", "budget_profile": "github-rest-offline-v1"}
    material = [{"source_identity": "delivery-system:github-rest-readonly-v1", "repository_identity": TARGET_REPOSITORY, "query_scope": scope, "payload": {"issue_records": issues, "relationship_records": relationships}}]
    content = {"requested_repository": TARGET_REPOSITORY, "canonical_repository": TARGET_REPOSITORY, "remote_repository_id": "R", "authenticated_subject": "U", "visibility": "private", "permissions": {"read": True, "write": True}, "capabilities": {"issues": True, "relationships": True}, "query_scope": scope, "query_complete": True, "pagination_complete": True, "issue_records": issues, "relationship_records": relationships, "evidence_material": material, "source_identity": "delivery-system:github-rest-readonly-v1", "schema_version": "github-rest-remote-content-v1", "authenticated_login": "zevsol"}
    return DriverReadResponse(TARGET_REPOSITORY, TARGET_REPOSITORY, "R", "U", "private", {"read": True, "write": True}, {"issues": True, "relationships": True}, scope, True, True, issues, relationships, material, "delivery-system:github-rest-readonly-v1", digest(content), authenticated_login="zevsol")


def fake_report() -> dict[str, object]:
    record = type("Record", (), {"to_dict": lambda self: {"method": "GET", "path": "/user", "status": 200}, "method": "GET"})()
    recorder = type("Recorder", (), {"records": (record,)})()
    preview = {"remote_snapshot_digest": "sha256:" + "a" * 64, "preview_level": "RepositoryAware", "write_eligible": False}
    return _build_report(response(), recorder, preview, "Passed", False, False, False)


class HarnessTests(TestCase):
    def test_noninteractive_terminal_fails_closed(self):
        with mock.patch("sys.stdin", io.StringIO()), mock.patch("sys.stderr", io.StringIO()), self.assertRaisesRegex(HarnessError, "interactive_terminal_required"):
            require_interactive_terminal()

    def test_token_sources_are_not_environment_or_file_inputs(self):
        import tests.integration.github_readonly_live as module
        self.assertNotIn("os.environ", module.read_pat.__code__.co_names)
        self.assertNotIn("open", module.read_pat.__code__.co_names)
        self.assertNotIn("argv", module.read_pat.__code__.co_names)

    def test_exact_endpoint_allowlist_accepts_only_valid_forms(self):
        allowed = [
            "/user", f"/repos/zevsol/delivery-system-integration-test",
            f"/repos/zevsol/delivery-system-integration-test/issues?state=all&per_page=100",
            f"/repos/zevsol/delivery-system-integration-test/issues?state=all&per_page=100&page=2",
            f"/repos/zevsol/delivery-system-integration-test/issues/1/sub_issues?per_page=100",
            f"/repos/zevsol/delivery-system-integration-test/issues/4/dependencies/blocked_by?per_page=100&page=3",
            f"/repos/zevsol/delivery-system-integration-test/issues/3/dependencies/blocking?per_page=100",
            f"/repos/zevsol/delivery-system-integration-test/issues/2/parent",
        ]
        for path in allowed:
            with self.subTest(path=path):
                _validate_endpoint(path)

    def test_raw_path_tricks_fail_before_inner_and_validated_path_is_unchanged(self):
        inner = mock.Mock()
        guard = GuardedRecordingTransport(mock.Mock())
        guard._inner = inner
        for path in (" /user", "\t/user", "\n/user", "/user\n", "/user\r", "/\tuser", "///user", "//api.github.com/user", "/user\x00", "/user\x7f", "/üser", "/user name"):
            with self.subTest(path=repr(path)), self.assertRaises(HarnessError):
                guard.request("GET", path, {})
        inner.request.assert_not_called()
        inner.request.return_value = TransportResponse(200, {}, b"{}")
        guard.request("GET", "/user", {})
        self.assertEqual(inner.request.call_args.args[1], "/user")

    def test_all_out_of_scope_paths_fail_before_inner_transport(self):
        inner = mock.Mock()
        guard = GuardedRecordingTransport(mock.Mock())
        guard._inner = inner
        paths = [
            "/repos/zevsol/delivery-system-integration-test/actions/secrets",
            "/repos/zevsol/delivery-system-integration-test/contents",
            "/repos/zevsol/delivery-system-integration-test/issues/1/comments",
            "/repos/zevsol/delivery-system-integration-test/issues/5/parent",
            "/repos/zevsol/delivery-system-integration-test/issues/99/sub_issues?per_page=100",
            "/repos/zevsol/delivery-system-integration-test/../contents",
            "/repos/zevsol/delivery-system-integration-test/issues/%31/parent",
            "https://api.github.com/user", "//api.github.com/user",
            "/user#fragment", "/user?x=1",
            "/repos/zevsol/delivery-system-integration-test/issues?state=open&per_page=100",
            "/repos/zevsol/delivery-system-integration-test/issues?state=all&per_page=100&page=1&page=2",
            "/repos/zevsol/delivery-system-integration-test/issues?state=all&per_page=100&page=0",
            "/repos/zevsol/delivery-system-integration-test/issues?state=all&per_page=100&page=-1",
            "/repos/zevsol/delivery-system-integration-test/issues?state=all&per_page=100&foo=1",
        ]
        for path in paths:
            with self.subTest(path=path), self.assertRaises(HarnessError):
                guard.request("GET", path, {})
        inner.request.assert_not_called()

    def test_non_get_is_rejected_before_inner(self):
        inner = mock.Mock()
        guard = GuardedRecordingTransport(mock.Mock())
        guard._inner = inner
        with self.assertRaisesRegex(HarnessError, "method_not_allowed"):
            guard.request("POST", "/user", {})
        inner.request.assert_not_called()

    def test_guard_rejects_redirect_without_recording(self):
        guard = GuardedRecordingTransport(mock.Mock())
        guard._inner = mock.Mock()
        guard._inner.request.return_value = TransportResponse(302, {}, b"redirect")
        with self.assertRaisesRegex(HarnessError, "redirect_forbidden"):
            guard.request("GET", "/user", {})
        self.assertEqual(guard.records, ())

    def test_fixed_origin_and_no_retries(self):
        import tests.integration.github_readonly_live as module
        guard = GuardedRecordingTransport(mock.Mock())
        with mock.patch.object(module, "API_ORIGIN", "https://evil.example"), self.assertRaisesRegex(HarnessError, "origin_not_allowed"):
            guard.request("GET", "/user", {})
        self.assertEqual(AUTOMATIC_RETRIES, 0)

    def test_recorder_has_only_allowlisted_fields_and_no_secret(self):
        guard = GuardedRecordingTransport(mock.Mock())
        guard._inner = mock.Mock()
        guard._inner.request.return_value = TransportResponse(200, {"Authorization": SENTINEL}, SENTINEL.encode())
        guard.request("GET", "/user", {"Authorization": SENTINEL})
        self.assertEqual(set(guard.records[0].to_dict()), REQUEST_KEYS)
        self.assertNotIn(SENTINEL, repr(guard.records))

    def test_fixture_facts_and_relationships_are_exact(self):
        _check_remote_facts(response())

    def test_missing_issue_or_relationship_fails_closed(self):
        for change in ("issue", "relationship"):
            value = response()
            if change == "issue":
                value = DriverReadResponse(**{**value.__dict__, "issue_records": list(value.issue_records[:-1])})
            else:
                value = DriverReadResponse(**{**value.__dict__, "relationship_records": list(value.relationship_records[:-1])})
            with self.subTest(change=change), self.assertRaises(HarnessError):
                _check_remote_facts(value)

    def test_capture_driver_allows_one_read_only(self):
        driver = mock.Mock()
        driver.read_repository.return_value = response()
        capture = CaptureDriver(driver)
        capture.read_repository(TARGET_REPOSITORY, response().query_scope)
        with self.assertRaisesRegex(HarnessError, "real_remote_read_already_completed"):
            capture.read_repository(TARGET_REPOSITORY, response().query_scope)
        self.assertEqual(driver.read_repository.call_count, 1)

    def test_replay_does_not_change_live_request_records(self):
        guard = GuardedRecordingTransport(mock.Mock())
        guard._inner = mock.Mock()
        guard._inner.request.return_value = TransportResponse(200, {}, b"{}")
        guard.request("GET", "/user", {})
        before_count = len(guard.records)
        inner_calls = guard._inner.request.call_count
        replay = ReplayDriver(response())
        replay.read_repository(TARGET_REPOSITORY, response().query_scope)
        after_count = len(guard.records)
        self.assertEqual(before_count, after_count)
        self.assertEqual(inner_calls, guard._inner.request.call_count)
        self.assertEqual(replay.calls, 1)

    def test_runtime_observes_no_approval_no_operation_and_no_public_snapshot(self):
        preview, audit_result, approval_created, operation_created, exposed, audit_eligible = _run_replay(response())
        self.assertEqual(preview["preview_level"], "RepositoryAware")
        self.assertEqual(audit_result, "Passed")
        self.assertFalse(preview["write_eligible"])
        self.assertFalse(operation_created)
        self.assertFalse(approval_created)
        self.assertFalse(exposed)
        self.assertFalse(audit_eligible)

    def test_complete_report_has_exact_schema_and_no_secret(self):
        report = fake_report()
        self.assertEqual(set(report), REPORT_KEYS)
        _validate_report(report)
        serialized = json.dumps(report)
        self.assertNotIn(SENTINEL, serialized)
        self.assertNotIn("Authorization", serialized)
        self.assertNotIn("title", serialized)
        self.assertNotIn("body", serialized)
        self.assertEqual(set(report["findings"][0]), FINDING_KEYS)
        self.assertEqual(set(report["relationships"][0]), RELATIONSHIP_KEYS)
        self.assertEqual(set(report["requests"][0]), REQUEST_KEYS)

    def test_sentinel_guard_records_feed_complete_report_without_leak(self):
        guard = GuardedRecordingTransport(type("TokenProvider", (), {"get_token": lambda self: SENTINEL})())
        guard._inner = mock.Mock()
        guard._inner.request.return_value = TransportResponse(200, {"Authorization": SENTINEL, "X-Body": SENTINEL}, SENTINEL.encode())
        guard.request("GET", "/user", {"Authorization": SENTINEL})
        report = _build_report(response(), guard, {"remote_snapshot_digest": "sha256:" + "a" * 64, "preview_level": "RepositoryAware", "write_eligible": False}, "Passed", False, False, False)
        serialized = json.dumps(report, sort_keys=True)
        self.assertNotIn(SENTINEL, serialized)
        self.assertNotIn("Authorization", serialized)
        self.assertNotIn("header", serialized.lower())
        self.assertNotIn("body", serialized.lower())
        _validate_report(report)

    def test_report_rejects_nested_extra_fields_and_permission_nonbooleans(self):
        for mutate in (lambda value: value["requests"][0].update({"headers": {}}), lambda value: value["findings"][0]["remote_repository_permissions"].update({"admin": True}), lambda value: value["relationships"][0].update({"title": "x"})):  # noqa: E501
            value = fake_report()
            mutate(value)
            with self.assertRaisesRegex(HarnessError, "evidence_schema_invalid"):
                _validate_report(value)

    def test_report_observes_runtime_values_not_constants(self):
        report = fake_report()
        report["write_eligible"] = True
        with self.assertRaisesRegex(HarnessError, "evidence_schema_invalid"):
            _validate_report(report)

    def test_every_allowed_evidence_value_is_closed(self):
        mutations = [
            ("schema_version", "wrong"), ("target_repository", "other/repo"), ("authenticated_login", "other"), ("visibility", "public"),
            ("issue_numbers", [1, 2, 3]), ("query_complete", False), ("pagination_complete", False), ("preview_level", "Conceptual"),
            ("write_eligible", True), ("remote_snapshot_exposed", True), ("audit_result", "Failed"), ("approval_created", True),
            ("operation_created", True), ("overall_result", "failed"), ("remote_content_digest", "sha256:bad"), ("remote_snapshot_digest", "sha256:bad"),
            ("requests", []), ("request_count", 0), ("relationships", [{"kind": "existing_parent", "from_issue": 1, "to_issue": 2}]),
            ("findings", []),
        ]
        for key, value in mutations:
            report = fake_report()
            report[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(HarnessError, "evidence_schema_invalid"):
                _validate_report(report)
        nested = [
            lambda r: r["requests"][0].update({"status": True}),
            lambda r: r["requests"][0].update({"path": "/user?x=1"}),
            lambda r: r["relationships"][0].update({"kind": "other"}),
            lambda r: r["relationships"][0].update({"from_issue": True}),
            lambda r: r["findings"][0].update({"observed_http_methods": ["POST"]}),
        ]
        for mutate in nested:
            report = fake_report()
            mutate(report)
            with self.assertRaisesRegex(HarnessError, "evidence_schema_invalid"):
                _validate_report(report)

    def test_error出口_is_stable_and_does_not_leak_exception_text(self):
        import tests.integration.github_readonly_live as module
        with mock.patch.object(module, "run_live", side_effect=RuntimeError(SENTINEL)), mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            self.assertEqual(main(), 2)
        self.assertEqual(err.getvalue().strip(), "integration_harness_failed")
        self.assertNotIn(SENTINEL, err.getvalue())

    def test_only_safe_error_codes_are_public(self):
        import tests.integration.github_readonly_live as module
        for value in ("sentinel_pat_do_not_leak", "github_pat_abc123", "ghp_abc123", "private", "unknown_123"):
            with mock.patch.object(module, "run_live", side_effect=HarnessError(value)), mock.patch("sys.stderr", new_callable=io.StringIO) as err:
                self.assertEqual(main(), 2)
            self.assertEqual(err.getvalue().strip(), "integration_harness_failed")
            self.assertNotIn(value, err.getvalue())
        self.assertIsInstance(SAFE_HARNESS_ERROR_CODES, frozenset)

    def test_keyboard_interrupt_has_stable_output(self):
        import tests.integration.github_readonly_live as module
        with mock.patch.object(module, "run_live", side_effect=KeyboardInterrupt()), mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            self.assertEqual(main(), 130)
        self.assertEqual(err.getvalue().strip(), "integration_harness_interrupted")

    def test_evidence_path_is_repository_root_anchored(self):
        self.assertEqual(EVIDENCE_PATH, REPOSITORY_ROOT / ".dev" / "integration-evidence" / "personal-repo-readonly.json")
        original = Path.cwd()
        try:
            os.chdir(REPOSITORY_ROOT.parent)
            self.assertEqual(EVIDENCE_PATH, REPOSITORY_ROOT / ".dev" / "integration-evidence" / "personal-repo-readonly.json")
        finally:
            os.chdir(original)


if __name__ == "__main__":
    import unittest
    unittest.main()
