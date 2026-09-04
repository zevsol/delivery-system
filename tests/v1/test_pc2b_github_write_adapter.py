"""Offline adversarial tests for the fixed-scope GitHub REST write adapter."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from delivery_system.drivers.contract import DriverError, ReadOnlyDriver
from delivery_system.drivers.github_write import (
    API_HOST, API_VERSION, HttpsWriteTransport, GitHubRestWriteDriver,
    MAX_RESPONSE_BYTES, MAX_WRITE_REQUEST_BYTES, USER_AGENT,
    WriteTransportResponse,
)
from delivery_system.drivers.write_contract import (
    CreateIssueCommand, RelationshipCommand, RemoteIssueReference,
    WriteObservationKind, WRITE_EXECUTOR_IDENTITY,
)
from tests.fakes.fake_write_transport import FakeWriteTransport

VALID_REQUEST_ID = "application-request-" + "a" * 64


def response(status: int = 201, payload: object = None, content_type: str = "application/json") -> WriteTransportResponse:
    if payload is None:
        payload = {}
    return WriteTransportResponse(status, {"Content-Type": content_type}, json.dumps(payload).encode())


class Token:
    def __init__(self, value: str = "secret-token") -> None:
        self.value = value
        self.calls = 0

    def get_token(self) -> str | None:
        self.calls += 1
        return self.value


class AdapterTests(unittest.TestCase):
    def issue(self, transport: FakeWriteTransport, body: str = "Body") -> object:
        return GitHubRestWriteDriver(transport, Token()).create_issue(
            CreateIssueCommand("Owner/Repo", "client-1", "Title", body, VALID_REQUEST_ID))

    def relation(self) -> RelationshipCommand:
        child = RemoteIssueReference("owner/repo", 2, "123", "child-node")
        parent = RemoteIssueReference("owner/repo", 1, "456", "parent-node")
        return RelationshipCommand("owner/repo", child, parent)

    def test_surface_and_exact_create_request(self):
        methods = {name for name in GitHubRestWriteDriver.__dict__ if not name.startswith("_")}
        self.assertEqual(methods, {"executor_identity", "create_issue", "add_sub_issue", "add_dependency"})
        transport = FakeWriteTransport((response(payload={"id": 9, "number": 4, "node_id": "N4"}),))
        result = self.issue(transport)
        self.assertEqual(result.kind, WriteObservationKind.DEFINITIVE_SUCCESS)
        self.assertEqual(transport.trace[0].path, "/repos/owner/repo/issues")
        payload = json.loads(transport.trace[0].body)
        self.assertEqual(payload, {"title": "Title", "body": "Body\n\n<!-- delivery-system-request:" + VALID_REQUEST_ID + " -->"})
        self.assertNotIn("client_ref", payload)

    def test_configured_driver_does_not_expose_raw_write_capability(self):
        driver = GitHubRestWriteDriver(FakeWriteTransport(), Token())
        self.assertFalse(hasattr(driver, "__dict__"))
        for name in ("transport", "_transport", "token_provider", "_token_provider", "post", "request", "dispatch"):
            self.assertFalse(hasattr(driver, name), name)
        self.assertEqual(set(GitHubRestWriteDriver.__slots__), {
            "_create_issue_capability", "_add_sub_issue_capability", "_add_dependency_capability"})

    def test_reserved_marker_and_request_budget_are_pre_dispatch_rejections(self):
        transport = FakeWriteTransport()
        with self.assertRaisesRegex(DriverError, "write_correlation_reserved"):
            self.issue(transport, "x <!-- delivery-system-request:other -->")
        self.assertEqual(transport.trace, ())

    def test_request_budget_exact_boundary_and_token_input_matrix(self):
        def command_for_size(target):
            for length in range(max(0, target - 512), target + 512):
                command = CreateIssueCommand("owner/repo", "c", "t", "x" * length, VALID_REQUEST_ID)
                encoded = json.dumps({"body": command.body + "\n\n<!-- delivery-system-request:" + VALID_REQUEST_ID + " -->", "title": "t"},
                                     ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
                if len(encoded) == target:
                    return command
            self.fail("could not construct deterministic request boundary")
        boundary = command_for_size(MAX_WRITE_REQUEST_BYTES)
        exact_transport = FakeWriteTransport((response(payload={"id": 1, "number": 1, "node_id": "N"}),))
        self.assertEqual(GitHubRestWriteDriver(exact_transport, Token()).create_issue(boundary).kind,
                         WriteObservationKind.DEFINITIVE_SUCCESS)
        over = command_for_size(MAX_WRITE_REQUEST_BYTES + 1)
        over_transport = FakeWriteTransport((response(),))
        with self.assertRaisesRegex(DriverError, "github_write_request_too_large"):
            GitHubRestWriteDriver(over_transport, Token()).create_issue(over)
        self.assertEqual(over_transport.trace, ())
        for value in (None, "", " ", b"token", 1, "token\r\n", "token\t", "x" * 4097):
            with self.subTest(token=value):
                provider = Token(value)
                transport = FakeWriteTransport((response(),))
                with self.assertRaisesRegex(DriverError, "github_write_credential_required"):
                    GitHubRestWriteDriver(transport, provider).create_issue(
                        CreateIssueCommand("owner/repo", "c", "t", "b", VALID_REQUEST_ID))
                self.assertEqual(provider.calls, 1)
                self.assertEqual(transport.trace, ())
        huge = "x" * MAX_WRITE_REQUEST_BYTES
        with self.assertRaisesRegex(DriverError, "github_write_request_too_large"):
            self.issue(transport, huge)
        self.assertEqual(transport.trace, ())

    def test_relationship_directions_and_integer_wire_values(self):
        transport = FakeWriteTransport((response(), response()))
        driver = GitHubRestWriteDriver(transport, Token())
        driver.add_sub_issue(self.relation())
        driver.add_dependency(self.relation())
        self.assertEqual(transport.trace[0].path, "/repos/owner/repo/issues/1/sub_issues")
        self.assertEqual(json.loads(transport.trace[0].body), {"sub_issue_id": 123})
        self.assertEqual(transport.trace[1].path, "/repos/owner/repo/issues/2/dependencies/blocked_by")
        self.assertEqual(json.loads(transport.trace[1].body), {"issue_id": 456})
        self.assertIs(type(json.loads(transport.trace[0].body)["sub_issue_id"]), int)

    def test_invalid_numeric_ids_do_not_dispatch(self):
        for value in ("", "0", "01", "+1", "-1", " 1", "1.0", "abc", "١", "１２", "1" * 21):
            with self.subTest(value=value):
                child = RemoteIssueReference("owner/repo", 2, value or "x", "child")
                parent = RemoteIssueReference("owner/repo", 1, "2", "parent")
                transport = FakeWriteTransport((response(),))
                with self.assertRaisesRegex(ValueError, "write_reference_invalid"):
                    GitHubRestWriteDriver(transport, Token()).add_sub_issue(RelationshipCommand("owner/repo", child, parent))
                self.assertEqual(transport.trace, ())

    def test_request_identity_and_repository_path_inputs_fail_closed(self):
        for request_id in ("hello", "APPLICATION-REQUEST-" + "a" * 64, "application-request-" + "A" * 64,
                           "application-request-" + "a" * 63, "application-request-" + "a" * 65,
                           "application-request-" + "a" * 63 + "<"):
            with self.subTest(request_id=request_id):
                transport = FakeWriteTransport((response(payload={"id": 1, "number": 1, "node_id": "N"}),))
                with self.assertRaisesRegex(DriverError, "write_correlation_invalid"):
                    GitHubRestWriteDriver(transport, Token()).create_issue(CreateIssueCommand("owner/repo", "c", "t", "b", request_id))
                self.assertEqual(transport.trace, ())
        for repository in ("owner/..", "owner/.", "owner/repo?x=1", "owner/repo#x", "owner/repo%2fissues", "owner/repo\\x", "owner/é"):
            with self.subTest(repository=repository):
                transport = FakeWriteTransport((response(),))
                with self.assertRaisesRegex(ValueError, "repository_identity_invalid"):
                    GitHubRestWriteDriver(transport, Token()).create_issue(CreateIssueCommand(repository, "c", "t", "b", VALID_REQUEST_ID))
                self.assertEqual(transport.trace, ())

    def test_direct_path_allowlist_rejects_breakout_and_unbounded_forms(self):
        invalid = ("https://api.github.com/repos/owner/repo/issues", "/repos/owner/repo/issues?x=1",
                   "/repos/owner/repo/issues#x", "/repos/owner/../issues", "/repos//owner/repo/issues",
                   "/repos/owner/repo/issues/1/sub_issues/extra", "/repos/owner/repo/issues/%31/sub_issues",
                   "/repos/owner/repo/issues/1/sub_issues\\x", "/repos/owner/repo/issues/" + "9" * 21 + "/sub_issues")
        for path in invalid:
            with self.subTest(path=path):
                self.assertFalse(HttpsWriteTransport.valid_path(path))
        self.assertTrue(HttpsWriteTransport.valid_path("/repos/owner/repo/issues/1/sub_issues"))

    def test_status_classification_is_exact_and_has_no_retry(self):
        statuses = (400, 401, 403, 404, 409, 410, 422, 429)
        for status in statuses:
            with self.subTest(status=status):
                transport = FakeWriteTransport((response(status, {"message": "secret"}), response()))
                result = self.issue(transport)
                self.assertEqual(result.kind, WriteObservationKind.DEFINITIVE_REJECTED)
                self.assertEqual(len(transport.trace), 1)
        for status in (200, 202, 204, 500, 503, 418):
            with self.subTest(status=status):
                transport = FakeWriteTransport((response(status), response()))
                result = self.issue(transport)
                self.assertEqual(result.kind, WriteObservationKind.AMBIGUOUS)
                self.assertEqual(len(transport.trace), 1)

    def test_malformed_success_and_oversize_are_ambiguous(self):
        cases = (response(201, "not-object"), response(201, {"id": True, "number": 1, "node_id": "N"}),
                 response(201, {"id": 1, "number": 1, "node_id": "N"}, "text/plain"),
                 WriteTransportResponse(201, {"Content-Type": "application/json"}, b"{"))
        for candidate in cases:
            with self.subTest(candidate=candidate):
                result = self.issue(FakeWriteTransport((candidate,)))
                self.assertEqual(result.kind, WriteObservationKind.AMBIGUOUS)
        oversized = WriteTransportResponse(503, {"Content-Type": "application/json"}, b"x" * (4 * 1024 * 1024 + 1))
        result = self.issue(FakeWriteTransport((oversized,)))
        self.assertEqual(result.kind, WriteObservationKind.AMBIGUOUS)

    def test_strict_content_types_and_transport_exceptions(self):
        for content_type in ("application/jsonp", "text/json", "text/plain", "", "application/json;", "application/json; charset=utf-8"):
            with self.subTest(content_type=content_type):
                candidate = response(201, {"id": 1, "number": 1, "node_id": "N"}, content_type)
                transport = FakeWriteTransport((candidate,))
                result = self.issue(transport)
                expected = WriteObservationKind.DEFINITIVE_SUCCESS if content_type == "application/json; charset=utf-8" else WriteObservationKind.AMBIGUOUS
                self.assertEqual(result.kind, expected)
        provider_error = Token()
        def raises():
            raise RuntimeError("SECRET_TOKEN_VALUE")
        provider_error.get_token = raises
        with self.assertRaises(DriverError) as captured:
            GitHubRestWriteDriver(FakeWriteTransport(), provider_error).create_issue(
                CreateIssueCommand("owner/repo", "c", "t", "b", VALID_REQUEST_ID))
        self.assertIsNone(captured.exception.__cause__)
        self.assertIsNone(captured.exception.__context__)
        self.assertNotIn("SECRET_TOKEN_VALUE", repr(captured.exception))
        result = self.issue(FakeWriteTransport((OSError("SECRET_TRANSPORT_VALUE"),)))
        self.assertEqual(result.kind, WriteObservationKind.AMBIGUOUS)
        self.assertNotIn("SECRET_TRANSPORT_VALUE", repr(result))

    def test_result_payload_is_bounded_and_secret_free(self):
        token = "top-secret-token"
        transport = FakeWriteTransport((response(payload={"id": 9, "number": 4, "node_id": "N4", "token": token}),))
        result = self.issue(transport)
        serialized = repr(result)
        self.assertNotIn(token, serialized)
        self.assertEqual(set(result.result_payload), {"repository_identity", "issue_number", "numeric_issue_id", "node_id", "executor_identity", "contract_version", "response_status"})

    def test_fake_transport_is_one_shot_and_trace_is_immutable(self):
        transport = FakeWriteTransport((response(),))
        self.issue(transport)
        self.assertEqual(len(transport.trace), 1)
        with self.assertRaises(AttributeError):
            transport.trace[0].body = b"changed"

    def test_fake_transport_rejects_unsupported_outcome(self):
        transport = FakeWriteTransport((object(),))
        with self.assertRaisesRegex(DriverError, "fake_write_response_invalid"):
            transport.post("/repos/owner/repo/issues", b"{}", {})
        self.assertEqual(len(transport.trace), 1)


class HttpsTransportTests(unittest.TestCase):
    def test_fixed_post_headers_token_once_and_bounded_body_read(self):
        token = Token()
        transport = HttpsWriteTransport()
        class Sock:
            def settimeout(self, value): self.value = value
        class Response:
            status = 201
            def getheaders(self): return [("Content-Type", "application/json")]
            def read(self, amount): self.amount = amount; return b"{}"
        connections = []
        responses = []
        class Connection:
            sock = Sock()
            def __init__(self, host, timeout, context):
                self.host, self.timeout = host, timeout
                connections.append(self)
            def connect(self): pass
            def request(self, method, path, body, headers): self.request_data = (method, path, body, headers)
            def getresponse(self):
                value = Response()
                responses.append(value)
                return value
            def close(self): pass
        with patch("delivery_system.drivers.github_write.http.client.HTTPSConnection", Connection):
            result = transport.post("/repos/owner/repo/issues", b"{}", {"Authorization": "Bearer secret-token"})
        self.assertEqual(result.status, 201)
        self.assertEqual(len(connections), 1)
        self.assertEqual(connections[0].host, API_HOST)
        self.assertEqual(connections[0].timeout, 10)
        method, path, sent_body, headers = connections[0].request_data
        self.assertEqual((method, path, sent_body), ("POST", "/repos/owner/repo/issues", b"{}"))
        self.assertEqual(headers["Accept"], "application/vnd.github+json")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(headers["X-GitHub-Api-Version"], API_VERSION)
        self.assertEqual(headers["User-Agent"], USER_AGENT)
        self.assertEqual(headers["Authorization"], "Bearer secret-token")
        self.assertEqual(responses[0].amount, MAX_RESPONSE_BYTES + 1)
        self.assertFalse(hasattr(transport, "_token_provider"))

    def test_missing_token_is_local_and_errors_are_sanitized(self):
        token = Token("")
        with self.assertRaisesRegex(DriverError, "github_write_credential_required"):
            GitHubRestWriteDriver(HttpsWriteTransport(), token).create_issue(
                CreateIssueCommand("owner/repo", "c", "t", "b", "application-request-" + "a" * 64))
        self.assertNotIn("secret", str(DriverError("github_write_timeout")))

    def test_timeout_and_redirect_are_fail_closed(self):
        class TimeoutConnection:
            sock = None
            def __init__(self, *args, **kwargs): pass
            def connect(self): raise TimeoutError()
            def close(self): pass
        token = Token()
        with patch("delivery_system.drivers.github_write.http.client.HTTPSConnection", TimeoutConnection):
            result = GitHubRestWriteDriver(HttpsWriteTransport(), token).create_issue(
                CreateIssueCommand("owner/repo", "c", "t", "b", "application-request-" + "a" * 64))
            self.assertEqual(result.kind, WriteObservationKind.AMBIGUOUS)
        with self.assertRaisesRegex(DriverError, "github_write_path_invalid"):
            HttpsWriteTransport().post("https://other.invalid/write", b"{}", {})


class ReadOnlyRegressionTests(unittest.TestCase):
    def test_read_only_protocol_has_no_write_surface(self):
        self.assertFalse(any(name in ReadOnlyDriver.__dict__ for name in ("write", "create_issue", "add_sub_issue")))
        self.assertEqual(WRITE_EXECUTOR_IDENTITY, "delivery-system:github-rest-write-v1")
