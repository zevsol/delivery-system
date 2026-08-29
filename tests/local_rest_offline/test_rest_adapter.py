from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from delivery_system.drivers.rest import HttpsRestTransport, LocalRestReadOnlyDriver, TransportResponse, SecretTokenProvider, MAX_RESPONSE_BYTES, RestDriverError
from delivery_system.protocol import digest
from delivery_system.drivers.preflight import validate_driver_facts


class FakeTransport:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def request(self, method, path, headers):
        self.calls.append((method, path, dict(headers)))
        value = self.responses[path]
        if isinstance(value, TransportResponse):
            return value
        return TransportResponse(200, {"Content-Type": "application/json"}, json.dumps(value).encode())


class LocalRestOfflineTests(unittest.TestCase):
    def test_headers_and_sentinel_token_stay_at_transport_boundary(self):
        transport = FakeTransport({"/user": {"id": 7, "node_id": "U7", "login": "owner"}})
        driver = LocalRestReadOnlyDriver(transport=transport, token_provider=SecretTokenProvider(lambda: "SENTINEL_TOKEN"))
        driver._get("/user")
        method, path, headers = transport.calls[0]
        self.assertEqual((method, path), ("GET", "/user"))
        self.assertEqual(headers["Accept"], "application/vnd.github+json")
        self.assertEqual(headers["X-GitHub-Api-Version"], "2026-03-10")
        self.assertTrue(headers["User-Agent"])
        self.assertEqual(headers["Authorization"], "Bearer SENTINEL_TOKEN")
        self.assertNotIn("SENTINEL_TOKEN", repr(driver))

    def test_fixed_read_only_endpoints_and_node_id_relationships(self):
        repo = {"id": 9, "node_id": "R9", "full_name": "Owner/Repo", "visibility": "private", "permissions": {"pull": True}}
        issue = {"id": 1, "node_id": "I1", "number": 1, "title": "Existing", "updated_at": "2026-08-13T00:00:00+00:00", "repository_url": "https://api.github.com/repos/Owner/Repo"}
        responses = {
            "/user": {"id": 7, "node_id": "U7", "login": "owner"},
            "/repos/owner/repo": repo,
            "/repos/owner/repo/issues?state=all&per_page=100": [issue],
            "/repos/owner/repo/issues/1/sub_issues?per_page=100": [],
            "/repos/owner/repo/issues/1/parent": TransportResponse(404, {"Content-Type": "application/json"}, b"{}"),
            "/repos/owner/repo/issues/1/dependencies/blocked_by?per_page=100": [],
            "/repos/owner/repo/issues/1/dependencies/blocking?per_page=100": [],
        }
        transport = FakeTransport(responses)
        driver = LocalRestReadOnlyDriver(transport=transport)
        result = driver.read_repository("Owner/Repo", {
            "api_origin": driver.origin, "api_version": "2026-03-10", "issue_state": "all",
            "pull_request_filter": "pull_request_field_excluded", "relationships": ["sub_issues", "parent", "blocked_by", "blocking"],
            "pagination_protocol": "link-header", "budget_profile": "github-rest-offline-v1",
        })
        self.assertEqual(result.issue_records[0]["issue_id"], "I1")
        self.assertEqual([call[0] for call in transport.calls], ["GET"] * len(transport.calls))
        self.assertEqual(result.authenticated_user_node_id, "U7")
        self.assertEqual(result.remote_repository_node_id, "R9")

    def test_pull_requests_are_filtered_at_adapter_boundary(self):
        issue = {"id": 1, "node_id": "I1", "number": 1, "title": "Existing", "updated_at": "2026-08-13T00:00:00+00:00", "repository_url": "https://api.github.com/repos/Owner/Repo"}
        pr = dict(issue, id=2, node_id="P2", number=2, pull_request={"url": "p"})
        base = {"api_origin": "https://api.github.com", "api_version": "2026-03-10", "issue_state": "all", "pull_request_filter": "pull_request_field_excluded", "relationships": ["sub_issues", "parent", "blocked_by", "blocking"], "pagination_protocol": "link-header", "budget_profile": "github-rest-offline-v1"}
        responses = {"/user": {"id": 7, "node_id": "U7", "login": "owner"}, "/repos/owner/repo": {"id": 9, "node_id": "R9", "full_name": "Owner/Repo", "visibility": "private"}, "/repos/owner/repo/issues?state=all&per_page=100": [issue, pr]}
        for endpoint in ("sub_issues?per_page=100", "parent", "dependencies/blocked_by?per_page=100", "dependencies/blocking?per_page=100"):
            responses[f"/repos/owner/repo/issues/1/{endpoint}"] = [] if endpoint != "parent" else TransportResponse(404, {"Content-Type": "application/json"}, b"{}")
        result = LocalRestReadOnlyDriver(FakeTransport(responses)).read_repository("Owner/Repo", base)
        self.assertEqual([item["issue_id"] for item in result.issue_records], ["I1"])

    def test_link_next_is_consumed_and_loop_or_cross_origin_fails_closed(self):
        first = TransportResponse(200, {"Content-Type": "application/json", "Link": '<https://api.github.com/repos/o/r/issues?page=2>; rel="next"'}, b"[]")
        second = TransportResponse(200, {"Content-Type": "application/json"}, b"[]")
        transport = FakeTransport({"/repos/o/r/issues": first, "/repos/o/r/issues?page=2": second})
        self.assertEqual(LocalRestReadOnlyDriver(transport=transport)._collection("/repos/o/r/issues"), [])
        loop = TransportResponse(200, {"Content-Type": "application/json", "Link": '<https://api.github.com/repos/o/r/issues>; rel="next"'}, b"[]")
        with self.assertRaisesRegex(RestDriverError, "pagination_incomplete"):
            LocalRestReadOnlyDriver(transport=FakeTransport({"/repos/o/r/issues": loop}))._collection("/repos/o/r/issues")
        foreign = TransportResponse(200, {"Content-Type": "application/json", "Link": '<https://example.test/repos/o/r/issues?page=2>; rel="next"'}, b"[]")
        with self.assertRaisesRegex(RestDriverError, "pagination_incomplete"):
            LocalRestReadOnlyDriver(transport=FakeTransport({"/repos/o/r/issues": foreign}))._collection("/repos/o/r/issues")
        sibling = TransportResponse(200, {"Content-Type": "application/json", "Link": '<https://api.github.com/repos/o/revil/issues?page=2>; rel="next"'}, b"[]")
        with self.assertRaisesRegex(RestDriverError, "pagination_incomplete"):
            LocalRestReadOnlyDriver(transport=FakeTransport({"/repos/o/r/issues": sibling}))._collection("/repos/o/r/issues")
        changed_query = TransportResponse(200, {"Content-Type": "application/json", "Link": '<https://api.github.com/repos/o/r/issues?state=open&per_page=1&page=2>; rel="next"'}, b"[]")
        transport = FakeTransport({"/repos/o/r/issues?state=all&per_page=100": changed_query})
        with self.assertRaisesRegex(RestDriverError, "pagination_incomplete"):
            LocalRestReadOnlyDriver(transport=transport)._collection("/repos/o/r/issues?state=all&per_page=100")
        self.assertEqual(len(transport.calls), 1)

    def test_http_error_mapping_and_response_boundary(self):
        for status, headers, code in (
            (401, {}, "authentication_failed"), (403, {}, "permission_denied"),
            (403, {"X-RateLimit-Remaining": "0"}, "rate_limited"), (404, {}, "remote_resource_not_found"),
            (410, {}, "remote_resource_gone"), (429, {}, "rate_limited"), (500, {}, "remote_transient_failure"),
            (302, {"Location": "https://example.test"}, "origin_redirect_forbidden"),
        ):
            with self.subTest(status=status):
                response = TransportResponse(status, {"Content-Type": "application/json", **headers}, b"{}")
                with self.assertRaisesRegex(RestDriverError, code):
                    LocalRestReadOnlyDriver(transport=FakeTransport({"/x": response}))._get("/x")
        bad_type = TransportResponse(200, {"Content-Type": "text/plain"}, b"{}")
        with self.assertRaisesRegex(RestDriverError, "driver_response_invalid"):
            LocalRestReadOnlyDriver(transport=FakeTransport({"/x": bad_type}))._get("/x")
        oversized = TransportResponse(200, {"Content-Type": "application/json"}, b"x" * (MAX_RESPONSE_BYTES + 1))
        with self.assertRaisesRegex(RestDriverError, "query_scope_incomplete"):
            LocalRestReadOnlyDriver(transport=FakeTransport({"/x": oversized}))._get("/x")

    def test_https_transport_enforces_same_response_budget_without_socket(self):
        from unittest.mock import patch
        class Response:
            status = 200
            def getheaders(self): return [("Content-Type", "application/json")]
            def read(self, size): self.size = size; return b"x" * (MAX_RESPONSE_BYTES + 1)
        class Connection:
            def __init__(self, *args, **kwargs): self.response = Response()
            def connect(self): pass
            def request(self, method, path, headers): self.request_args = (method, path, headers)
            def getresponse(self): return self.response
            def close(self): pass
        connection = Connection()
        with patch("delivery_system.drivers.rest.http.client.HTTPSConnection", return_value=connection):
            with self.assertRaisesRegex(RestDriverError, "query_scope_incomplete"):
                HttpsRestTransport().request("GET", "/user", {})
        self.assertEqual(connection.response.size, MAX_RESPONSE_BYTES + 1)

    def test_resource_budget_boundaries_are_failure_closed(self):
        page = TransportResponse(200, {"Content-Type": "application/json", "Link": '<https://api.github.com/repos/o/r/issues?page=2>; rel="next"'}, b"[]")
        with patch("delivery_system.drivers.rest.MAX_PAGES_PER_COLLECTION", 1):
            with self.assertRaisesRegex(RestDriverError, "pagination_incomplete"):
                LocalRestReadOnlyDriver(transport=FakeTransport({"/repos/o/r/issues": page}))._collection("/repos/o/r/issues")
        with patch("delivery_system.drivers.rest.MAX_ISSUES", 1):
            issues = [{"id": i, "node_id": f"I{i}", "number": i, "title": "x", "updated_at": "2026-08-13T00:00:00+00:00", "repository_url": "https://api.github.com/repos/o/r"} for i in (1, 2)]
            with self.assertRaisesRegex(RestDriverError, "query_scope_incomplete"):
                LocalRestReadOnlyDriver(transport=FakeTransport({"/repos/o/r/issues": issues}))._collection("/repos/o/r/issues", limit=1)
        with patch("delivery_system.drivers.rest.MAX_REQUESTS_PER_READ", 1):
            driver = LocalRestReadOnlyDriver(transport=FakeTransport({"/x": TransportResponse(200, {"Content-Type": "application/json"}, b"{}"), "/y": TransportResponse(200, {"Content-Type": "application/json"}, b"{}") }))
            driver._get("/x")
            with self.assertRaisesRegex(RestDriverError, "query_scope_incomplete"):
                driver._get("/y")

    def test_parent_410_and_relationship_410_fail_closed(self):
        parent410 = TransportResponse(410, {"Content-Type": "application/json"}, b"{}")
        responses = {"/user": {"id": 7, "node_id": "U7", "login": "owner"}, "/repos/owner/repo": {"id": 9, "node_id": "R9", "full_name": "Owner/Repo", "visibility": "private", "permissions": {"pull": True}}, "/repos/owner/repo/issues?state=all&per_page=100": [{"id": 1, "node_id": "I1", "number": 1, "title": "x", "updated_at": "2026-08-13T00:00:00+00:00", "repository_url": "https://api.github.com/repos/Owner/Repo"}], "/repos/owner/repo/issues/1/sub_issues?per_page=100": [], "/repos/owner/repo/issues/1/parent": parent410, "/repos/owner/repo/issues/1/dependencies/blocked_by?per_page=100": [], "/repos/owner/repo/issues/1/dependencies/blocking?per_page=100": []}
        with self.assertRaisesRegex(RestDriverError, "remote_resource_gone"):
            LocalRestReadOnlyDriver(FakeTransport(responses)).read_repository("Owner/Repo", LocalRestReadOnlyDriver.fixed_query_scope)

    def test_complete_rest_fixture_passes_phase_one_preflight(self):
        issue = {"id": 1, "node_id": "I1", "number": 1, "title": "Existing", "updated_at": "2026-08-13T00:00:00+00:00", "repository_url": "https://api.github.com/repos/Owner/Repo"}
        responses = {
            "/user": {"id": 7, "node_id": "U7", "login": "owner"},
            "/repos/owner/repo": {"id": 9, "node_id": "R9", "full_name": "Owner/Repo", "visibility": "private", "permissions": {"pull": True}},
            "/repos/owner/repo/issues?state=all&per_page=100": [issue],
            "/repos/owner/repo/issues/1/sub_issues?per_page=100": [],
            "/repos/owner/repo/issues/1/dependencies/blocked_by?per_page=100": [],
            "/repos/owner/repo/issues/1/dependencies/blocking?per_page=100": [],
            "/repos/owner/repo/issues/1/parent": TransportResponse(404, {"Content-Type": "application/json"}, b"{}"),
        }
        driver = LocalRestReadOnlyDriver(transport=FakeTransport(responses))
        facts, failures = validate_driver_facts(driver, "Owner/Repo", driver.fixed_query_scope, driver.trusted_driver_identity)
        self.assertFalse(failures)
        self.assertIsNotNone(facts)
        self.assertEqual(facts.response.permissions["read"], True)


if __name__ == "__main__":
    unittest.main()
