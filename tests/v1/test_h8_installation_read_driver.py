"""Offline adversarial coverage for the installation-aware read Driver."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import inspect
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from mcp import Client

from delivery_system.attestation_runtime import _subject_from_payload
from delivery_system.drivers.contract import DriverTrustContext, RuntimeEvidenceBinding
from delivery_system.drivers.preflight import bind_validated_facts, validate_driver_facts
from delivery_system.drivers.rest import (
    GitHubAppInstallationReadOnlyDriver,
    RestDriverError,
    TransportResponse,
)
from delivery_system.host_composition import (
    HostCompositionError,
    _LeaseReadAuthView,
    compose_write_enabled_host,
    load_host_configuration,
)
from delivery_system.runtime import InMemoryPreviewStore, RuntimeContext
from mcp_server.server import create_server

from tests.v1.test_h4_host_composition import (
    APP_ID,
    INSTALLATION_ID,
    NOW,
    REPOSITORY_ID,
    TOKEN,
    FakeBootstrapTransport,
    _environment,
    _pem_private,
    _pem_public,
)


REPOSITORY = "Owner/Repo"
SUBJECT = "github-app-installation-12345-54321"
TOKEN_SENTINEL = "SYNTHETIC_INSTALLATION_TOKEN_SENTINEL"


class FakeAuthProvider:
    def __init__(
        self,
        token: str = TOKEN_SENTINEL,
        subject: str = SUBJECT,
        effective_permissions: object = None,
    ) -> None:
        self.token = token
        self.subject = subject
        self.permissions = {"issues": "write"} if effective_permissions is None else effective_permissions

    def get_token(self) -> str:
        return self.token

    def authenticated_subject_identity(self) -> str:
        return self.subject

    def effective_permissions(self) -> object:
        return self.permissions


class FakeTransport:
    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, dict[str, str]]] = []

    def request(self, method: str, path: str, headers: dict[str, str]) -> TransportResponse:
        self.calls.append((method, path, dict(headers)))
        value = self.responses[path]
        if isinstance(value, TransportResponse):
            return value
        return TransportResponse(200, {"Content-Type": "application/json"}, json.dumps(value).encode())


class FakeHttpsResponse:
    def __init__(self, response: TransportResponse, raw_headers: list[tuple[str, str]] | None = None) -> None:
        self.status = response.status
        self._headers = list(raw_headers if raw_headers is not None else response.headers.items())
        self._body = response.body

    def getheaders(self):
        return self._headers

    def read(self, size):
        return self._body


class FakeHttpsConnection:
    responses: dict[str, TransportResponse] = {}
    raw_headers: dict[str, list[tuple[str, str]]] = {}
    calls: list[tuple[str, str, dict[str, str]]] = []

    def __init__(self, *args, **kwargs) -> None:
        self.response: TransportResponse | None = None
        self.path: str | None = None

    def connect(self) -> None:
        pass

    def request(self, method: str, path: str, headers: dict[str, str]) -> None:
        self.calls.append((method, path, dict(headers)))
        self.path = path
        self.response = self.responses[path]

    def getresponse(self) -> FakeHttpsResponse:
        assert self.response is not None
        raw_headers = self.raw_headers.get(self.path or "")
        return FakeHttpsResponse(self.response, raw_headers)

    def close(self) -> None:
        pass


class InstallationDriverTests(unittest.TestCase):
    def _responses(self, *, scope: object | None = None, repository: object | None = None) -> dict[str, object]:
        issue = {
            "id": 1, "node_id": "I1", "number": 1, "title": "Existing",
            "updated_at": "2026-09-07T00:00:00+00:00",
            "repository_url": "https://api.github.com/repos/Owner/Repo",
        }
        return {
            "/installation/repositories?per_page=100": scope if scope is not None else {
                "total_count": 1, "repositories": [{"id": REPOSITORY_ID, "full_name": "owner/repo"}],
            },
            "/repos/owner/repo": repository if repository is not None else {
            "id": REPOSITORY_ID, "node_id": "R9", "full_name": "Owner/Repo",
                "visibility": "private", "permissions": {"pull": True, "push": False},
            },
            "/repos/owner/repo/issues?state=all&per_page=100": [issue],
            "/repos/owner/repo/issues/1/sub_issues?per_page=100": [],
            "/repos/owner/repo/issues/1/parent": TransportResponse(404, {"Content-Type": "application/json"}, b"{}"),
            "/repos/owner/repo/issues/1/dependencies/blocked_by?per_page=100": [],
            "/repos/owner/repo/issues/1/dependencies/blocking?per_page=100": [],
        }

    def _driver(self, *, scope: object | None = None, provider: object | None = None):
        transport = FakeTransport(self._responses(scope=scope))
        driver = GitHubAppInstallationReadOnlyDriver(
            provider or FakeAuthProvider(), REPOSITORY_ID, transport=transport
        )
        return driver, transport

    def test_constructor_has_one_auth_authority_and_strict_repository_id(self) -> None:
        params = inspect.signature(GitHubAppInstallationReadOnlyDriver).parameters
        self.assertEqual(tuple(params), ("auth_provider", "expected_repository_id", "transport"))
        self.assertNotIn("token_provider", params)
        self.assertNotIn("subject_provider", params)
        for value in (True, False, 0, -1, 1.0, "67890", 10 ** 20, None):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "repository_id_invalid"):
                GitHubAppInstallationReadOnlyDriver(FakeAuthProvider(), value)

    def test_constructor_requires_one_permission_authority(self) -> None:
        class MissingPermissions:
            def get_token(self):
                return TOKEN_SENTINEL

            def authenticated_subject_identity(self):
                return SUBJECT

        with self.assertRaisesRegex(ValueError, "installation_auth_provider_invalid"):
            GitHubAppInstallationReadOnlyDriver(MissingPermissions(), REPOSITORY_ID)

    def test_scope_probe_is_first_and_never_requests_user(self) -> None:
        driver, transport = self._driver()
        result = driver.read_repository(REPOSITORY, driver.fixed_query_scope)
        self.assertEqual(transport.calls[0][0:2], ("GET", "/installation/repositories?per_page=100"))
        self.assertEqual(transport.calls[0][2]["Authorization"], f"Bearer {TOKEN_SENTINEL}")
        self.assertNotIn("/user", [path for _, path, _ in transport.calls])
        self.assertEqual(result.authenticated_subject, SUBJECT)
        self.assertIsNone(result.authenticated_user_id)
        self.assertIsNone(result.authenticated_user_node_id)
        self.assertIsNone(result.authenticated_login)
        self.assertTrue(all(method == "GET" for method, _, _ in transport.calls))

    def test_issue_body_flows_through_mcp_audit_context_without_extra_read(self) -> None:
        responses = self._responses()
        responses["/repos/owner/repo/issues?state=all&per_page=100"][0]["body"] = "Evidence body"
        transport = FakeTransport(responses)
        driver = GitHubAppInstallationReadOnlyDriver(FakeAuthProvider(), REPOSITORY_ID, transport=transport)
        trust = DriverTrustContext(driver.trusted_driver_identity, driver.origin, driver.contract_version)

        def sourced(value):
            return {"value": value, "declared_source": "user_asserted"}

        plan = {
            "repository_claim": {"owner": "Owner", "name": "Repo"},
            "work_items": [{
                "client_ref": "item", "role": sourced("Evidence"), "title": sourced("Existing"),
                "context_problem": sourced("Problem"), "outcome": sourced("Outcome"),
                "scope": sourced(["repo"]), "non_goals": sourced([]),
                "acceptance_criteria": sourced(["Works"]), "verification": sourced(["Test"]),
                "required_capabilities": sourced(["issues"]), "write_metadata": sourced({}),
            }],
            "planned_relationships": [], "operation_intents": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            context = RuntimeContext.from_workspace_root(directory)
            store = InMemoryPreviewStore(context.workspace_identity, trust)
            server = create_server(context, store, driver, trust)

            async def exercise():
                async with Client(server, raise_exceptions=True) as client:
                    preview = await client.call_tool("delivery_plan_preview", {"payload": {"plan": plan}})
                    audit_context = await client.call_tool("delivery_get_audit_context", {"payload": {
                        "preview_id": preview.structured_content["preview_id"], "revision": 1,
                    }})
                    return audit_context

            result = asyncio.run(exercise())
        self.assertFalse(result.is_error)
        driver_evidence = next(item for item in result.structured_content["evidence_records"] if item["source_kind"] == "driver")
        self.assertEqual(driver_evidence["payload"]["issue_records"][0]["body"], "Evidence body")
        self.assertEqual(len(transport.calls), 7)
        self.assertNotIn("/issues/1/body", [path for _, path, _ in transport.calls])

    def test_unusable_installation_tokens_fail_before_transport(self) -> None:
        for label, token in (("none", None), ("empty", ""), ("spaces", "   "), ("padded", " token ")):
            with self.subTest(label=label):
                driver, transport = self._driver(provider=FakeAuthProvider(token=token))
                with self.assertRaisesRegex(RestDriverError, "authentication_failed"):
                    driver.read_repository(REPOSITORY, driver.fixed_query_scope)
                self.assertEqual(transport.calls, [])

    def test_transport_token_cannot_replace_or_rescue_driver_authority(self) -> None:
        import delivery_system.drivers.rest as rest_module
        complete = self._responses()
        FakeHttpsConnection.raw_headers = {}
        FakeHttpsConnection.responses = {
            path: value if isinstance(value, TransportResponse) else TransportResponse(
                200, {"Content-Type": "application/json"}, json.dumps(value).encode()
            )
            for path, value in complete.items()
        }
        FakeHttpsConnection.calls = []
        with patch.object(rest_module.http.client, "HTTPSConnection", FakeHttpsConnection):
            driver = GitHubAppInstallationReadOnlyDriver(
                FakeAuthProvider(token="TOKEN_A"), REPOSITORY_ID,
                transport=rest_module.HttpsRestTransport(FakeAuthProvider(token="TOKEN_B")),
            )
            driver.read_repository(REPOSITORY, driver.fixed_query_scope)
        self.assertTrue(FakeHttpsConnection.calls)
        self.assertTrue(all(call[2].get("Authorization") == "Bearer TOKEN_A" for call in FakeHttpsConnection.calls))
        FakeHttpsConnection.calls = []
        with patch.object(rest_module.http.client, "HTTPSConnection", FakeHttpsConnection):
            driver = GitHubAppInstallationReadOnlyDriver(
                FakeAuthProvider(token=None), REPOSITORY_ID,
                transport=rest_module.HttpsRestTransport(FakeAuthProvider(token="TOKEN_B")),
            )
            with self.assertRaisesRegex(RestDriverError, "authentication_failed"):
                driver.read_repository(REPOSITORY, driver.fixed_query_scope)
        self.assertEqual(FakeHttpsConnection.calls, [])

    def test_installation_permissions_require_exact_booleans(self) -> None:
        invalid_permissions = (
            None, [], "permissions", {},
            {"pull": True}, {"push": False},
            {"pull": None, "push": False}, {"pull": True, "push": None},
            {"pull": 0, "push": False}, {"pull": 1, "push": False},
            {"pull": True, "push": 0}, {"pull": True, "push": 1},
            {"pull": "false", "push": False}, {"pull": "true", "push": False},
            {"pull": True, "push": "false"}, {"pull": True, "push": "true"},
            {"pull": [], "push": False}, {"pull": {}, "push": False},
        )
        for permissions in invalid_permissions:
            with self.subTest(permissions=permissions):
                repository = {
                    "id": REPOSITORY_ID, "node_id": "R9", "full_name": "Owner/Repo",
                    "visibility": "private", "permissions": permissions,
                }
                driver, transport = self._driver()
                transport.responses["/repos/owner/repo"] = repository
                with self.assertRaisesRegex(RestDriverError, "driver_response_invalid"):
                    driver.read_repository(REPOSITORY, driver.fixed_query_scope)
                self.assertEqual(
                    [path for _, path, _ in transport.calls],
                    ["/installation/repositories?per_page=100", "/repos/owner/repo"],
                )

    def test_installation_pull_push_values_do_not_project_authority(self) -> None:
        for pull, push in ((True, True), (True, False), (False, False)):
            with self.subTest(pull=pull, push=push):
                repository = {
                    "id": REPOSITORY_ID, "node_id": "R9", "full_name": "Owner/Repo",
                    "visibility": "private", "permissions": {"pull": pull, "push": push},
                }
                driver, transport = self._driver()
                transport.responses["/repos/owner/repo"] = repository
                result = driver.read_repository(REPOSITORY, driver.fixed_query_scope)
                self.assertEqual(result.permissions, {"read": True, "write": True})

    def test_installation_permission_projection_uses_lease_authority(self) -> None:
        repository = {
            "id": REPOSITORY_ID, "node_id": "R9", "full_name": "Owner/Repo",
            "visibility": "private", "permissions": {"pull": False, "push": False},
        }
        driver, transport = self._driver()
        transport.responses["/repos/owner/repo"] = repository
        result = driver.read_repository(REPOSITORY, driver.fixed_query_scope)
        self.assertEqual(result.permissions, {"read": True, "write": True})
        facts, failures = validate_driver_facts(
            driver, REPOSITORY, driver.fixed_query_scope, driver.trusted_driver_identity,
        )
        self.assertIsNotNone(facts)
        self.assertEqual(failures, ())

    def test_installation_read_permission_projects_read_only(self) -> None:
        repository = {
            "id": REPOSITORY_ID, "node_id": "R9", "full_name": "Owner/Repo",
            "visibility": "private", "permissions": {"pull": False, "push": False},
        }
        driver, transport = self._driver(
            provider=FakeAuthProvider(effective_permissions={"issues": "read"}),
        )
        transport.responses["/repos/owner/repo"] = repository
        result = driver.read_repository(REPOSITORY, driver.fixed_query_scope)
        self.assertEqual(result.permissions, {"read": True, "write": False})
        facts, failures = validate_driver_facts(
            driver, REPOSITORY, driver.fixed_query_scope, driver.trusted_driver_identity,
        )
        self.assertIsNotNone(facts)
        self.assertEqual(failures, ())

    def test_installation_invalid_issues_permission_fails_before_transport(self) -> None:
        invalid_permissions = (
            {}, {"issues": None}, {"issues": ""}, {"issues": " read "},
            {"issues": "write "}, {"issues": True}, {"issues": False},
            {"issues": 0}, {"issues": 1}, {"issues": []}, {"issues": {}},
        )
        for permissions in invalid_permissions:
            with self.subTest(permissions=permissions):
                driver, transport = self._driver(
                    provider=FakeAuthProvider(effective_permissions=permissions),
                )
                with self.assertRaisesRegex(RestDriverError, "installation_auth_invalid"):
                    driver.read_repository(REPOSITORY, driver.fixed_query_scope)
                self.assertEqual(transport.calls, [])

        class RaisingProvider(FakeAuthProvider):
            def effective_permissions(self):
                raise RuntimeError("not exposed")

        driver, transport = self._driver(provider=RaisingProvider())
        with self.assertRaisesRegex(RestDriverError, "installation_auth_invalid"):
            driver.read_repository(REPOSITORY, driver.fixed_query_scope)
        self.assertEqual(transport.calls, [])

    def test_https_transport_preserves_raw_duplicate_link_headers(self) -> None:
        import delivery_system.drivers.rest as rest_module
        complete = self._responses()
        scope_path = "/installation/repositories?per_page=100"
        FakeHttpsConnection.responses = {
            path: value if isinstance(value, TransportResponse) else TransportResponse(
                200, {"Content-Type": "application/json"}, json.dumps(value).encode()
            )
            for path, value in complete.items()
        }
        FakeHttpsConnection.raw_headers = {
            scope_path: [
                ("Content-Type", "application/json"),
                ("Link", ""),
                ("Link", '<https://api.github.com/installation/repositories?page=2>; rel="next"'),
            ]
        }
        FakeHttpsConnection.calls = []
        with patch.object(rest_module.http.client, "HTTPSConnection", FakeHttpsConnection):
            response = rest_module.HttpsRestTransport().request("GET", scope_path, {})
            self.assertEqual(response.headers["Link"], ',<https://api.github.com/installation/repositories?page=2>; rel="next"')
            driver = GitHubAppInstallationReadOnlyDriver(FakeAuthProvider(), REPOSITORY_ID)
            with self.assertRaisesRegex(RestDriverError, "query_scope_incomplete"):
                driver.read_repository(REPOSITORY, driver.fixed_query_scope)
        self.assertEqual([path for _, path, _ in FakeHttpsConnection.calls], [scope_path, scope_path])

    def test_https_transport_duplicate_singleton_headers_fail_closed(self) -> None:
        import delivery_system.drivers.rest as rest_module
        FakeHttpsConnection.responses = {"/x": TransportResponse(200, {}, b"{}")}
        FakeHttpsConnection.raw_headers = {
            "/x": [("Content-Type", "application/json"), ("Content-Type", "text/plain")]
        }
        FakeHttpsConnection.calls = []
        with patch.object(rest_module.http.client, "HTTPSConnection", FakeHttpsConnection):
            with self.assertRaisesRegex(RestDriverError, "driver_response_invalid"):
                rest_module.LocalRestReadOnlyDriver(
                    transport=rest_module.HttpsRestTransport()
                )._get("/x")
        self.assertEqual([path for _, path, _ in FakeHttpsConnection.calls], ["/x"])
        FakeHttpsConnection.raw_headers = {}

    def test_scope_cardinality_and_shape_fail_closed_before_repository(self) -> None:
        invalid_scopes = (
            {"total_count": 0, "repositories": []},
            {"total_count": 2, "repositories": [{"id": REPOSITORY_ID, "full_name": "owner/repo"}] * 2},
            {"total_count": True, "repositories": [{"id": REPOSITORY_ID, "full_name": "owner/repo"}]},
            {"total_count": "1", "repositories": [{"id": REPOSITORY_ID, "full_name": "owner/repo"}]},
            {"repositories": [{"id": REPOSITORY_ID, "full_name": "owner/repo"}]},
            {"total_count": 1, "repositories": []},
            {"total_count": 1, "repositories": [{"id": REPOSITORY_ID, "full_name": "owner/repo"}] * 2},
            {"total_count": 1, "repositories": "owner/repo"},
            {"total_count": 1, "repositories": ["malformed"]},
            [ {"total_count": 1, "repositories": [{"id": REPOSITORY_ID, "full_name": "owner/repo"}]} ],
        )
        for scope in invalid_scopes:
            with self.subTest(scope=scope):
                driver, transport = self._driver(scope=scope)
                with self.assertRaisesRegex(RestDriverError, "installation_scope_invalid"):
                    driver.read_repository(REPOSITORY, driver.fixed_query_scope)
                self.assertEqual([path for _, path, _ in transport.calls], ["/installation/repositories?per_page=100"])

    def test_scope_target_id_and_full_name_are_exactly_bound(self) -> None:
        scopes = (
            {"total_count": 1, "repositories": [{"id": REPOSITORY_ID + 1, "full_name": "owner/repo"}]},
            {"total_count": 1, "repositories": [{"id": REPOSITORY_ID, "full_name": "owner/other"}]},
            {"total_count": 1, "repositories": [{"id": REPOSITORY_ID, "full_name": "owner//repo"}]},
            {"total_count": 1, "repositories": [{"id": REPOSITORY_ID, "full_name": " owner/repo"}]},
            {"total_count": 1, "repositories": [{"full_name": "owner/repo"}]},
        )
        for scope in scopes:
            with self.subTest(scope=scope):
                driver, transport = self._driver(scope=scope)
                with self.assertRaisesRegex(RestDriverError, "installation_scope_invalid"):
                    driver.read_repository(REPOSITORY, driver.fixed_query_scope)
                self.assertEqual(len(transport.calls), 1)

    def test_scope_link_metadata_is_fail_closed_before_repository(self) -> None:
        for label, link in (
            ("next", '<https://api.github.com/installation/repositories?per_page=100&page=2>; rel="next"'),
            ("malformed", "not-a-link"),
            ("ambiguous", '<https://api.github.com/installation/repositories?page=2>; rel="next", broken'),
        ):
            with self.subTest(label=label):
                scope_body = {"total_count": 1, "repositories": [{"id": REPOSITORY_ID, "full_name": "owner/repo"}]}
                responses = self._responses(scope=TransportResponse(200, {"Content-Type": "application/json", "Link": link}, json.dumps(scope_body).encode()))
                transport = FakeTransport(responses)
                driver = GitHubAppInstallationReadOnlyDriver(FakeAuthProvider(), REPOSITORY_ID, transport=transport)
                with self.assertRaisesRegex(RestDriverError, "query_scope_incomplete"):
                    driver.read_repository(REPOSITORY, driver.fixed_query_scope)
                self.assertEqual([path for _, path, _ in transport.calls], ["/installation/repositories?per_page=100"])

    def test_scope_link_case_variants_and_duplicate_empty_values_fail_closed(self) -> None:
        scope_body = {"total_count": 1, "repositories": [{"id": REPOSITORY_ID, "full_name": "owner/repo"}]}
        scopes = (
            {"Link": "", "link": '<https://api.github.com/installation/repositories?page=2>; rel="next"'},
            {"Link": '<https://api.github.com/installation/repositories?page=2>; rel="next"', "link": ""},
            {"Link": "", "link": ""},
            {"Link": '<https://api.github.com/installation/repositories?page=2>; rel="next"', "link": '<https://api.github.com/installation/repositories?page=2>; rel="next"'},
            {"LINK": "not-a-link", "Link": ""},
        )
        for headers in scopes:
            with self.subTest(headers=headers):
                response = TransportResponse(200, {"Content-Type": "application/json", **headers}, json.dumps(scope_body).encode())
                transport = FakeTransport(self._responses(scope=response))
                driver = GitHubAppInstallationReadOnlyDriver(FakeAuthProvider(), REPOSITORY_ID, transport=transport)
                with self.assertRaisesRegex(RestDriverError, "query_scope_incomplete"):
                    driver.read_repository(REPOSITORY, driver.fixed_query_scope)
                self.assertEqual([path for _, path, _ in transport.calls], ["/installation/repositories?per_page=100"])

    def test_scope_without_link_metadata_remains_valid(self) -> None:
        for headers in ({}, {"Link": ""}):
            with self.subTest(headers=headers):
                scope = TransportResponse(200, {"Content-Type": "application/json", **headers}, json.dumps({
                    "total_count": 1, "repositories": [{"id": REPOSITORY_ID, "full_name": "owner/repo"}],
                }).encode())
                driver, transport = self._driver(scope=scope)
                driver.read_repository(REPOSITORY, driver.fixed_query_scope)
                self.assertEqual(transport.calls[0][1], "/installation/repositories?per_page=100")

    def test_subject_is_provider_derived_and_preflight_digest_matches(self) -> None:
        provider = FakeAuthProvider(subject="provider-subject-not-owner")
        driver, _ = self._driver(provider=provider)
        result = driver.read_repository(REPOSITORY, driver.fixed_query_scope)
        self.assertEqual(result.authenticated_subject, "provider-subject-not-owner")
        self.assertEqual(result.remote_repository_id, str(REPOSITORY_ID))
        facts, failures = validate_driver_facts(
            driver, REPOSITORY, driver.fixed_query_scope, driver.trusted_driver_identity
        )
        self.assertIsNotNone(facts)
        self.assertEqual(failures, ())

    def test_runtime_evidence_and_attestation_subject_use_new_identity(self) -> None:
        driver, _ = self._driver()
        facts, failures = validate_driver_facts(
            driver, REPOSITORY, driver.fixed_query_scope, driver.trusted_driver_identity
        )
        self.assertEqual(failures, ())
        assert facts is not None
        trust = DriverTrustContext(driver.trusted_driver_identity, driver.origin, driver.contract_version)
        bound = bind_validated_facts(facts, RuntimeEvidenceBinding("workspace-1", "preview-1", 1), trust)
        self.assertEqual(bound.evidence_record.evidence_type, "driver_remote_read")
        self.assertEqual(bound.evidence_record.source_kind, "driver")
        self.assertEqual(bound.evidence_record.source_identity, driver.trusted_driver_identity)
        self.assertEqual(bound.evidence_record.verification_status, "driver_verified")
        self.assertEqual(bound.evidence_record.repository_identity, "owner/repo")
        payload = {
            "authenticated_user_node_id": None,
            "authenticated_user_id": None,
            "authenticated_subject": SUBJECT,
        }
        self.assertEqual(_subject_from_payload(payload), SUBJECT)

    def test_http_authentication_and_permission_errors_are_stable(self) -> None:
        for status, code in ((401, "authentication_failed"), (403, "permission_denied")):
            with self.subTest(status=status):
                scope = TransportResponse(status, {"Content-Type": "application/json"}, b"{}")
                driver, transport = self._driver(scope=scope)
                with self.assertRaisesRegex(RestDriverError, code):
                    driver.read_repository(REPOSITORY, driver.fixed_query_scope)
                self.assertEqual(len(transport.calls), 1)

    def test_secret_is_absent_from_driver_repr_and_provider_failure(self) -> None:
        driver, _ = self._driver()
        self.assertNotIn(TOKEN_SENTINEL, repr(driver))

        class BrokenProvider:
            def get_token(self) -> str:
                raise RuntimeError(TOKEN_SENTINEL)

            def authenticated_subject_identity(self) -> str:
                return SUBJECT

            def effective_permissions(self) -> dict[str, str]:
                return {"issues": "write"}

        broken, _ = self._driver(provider=BrokenProvider())
        with self.assertRaises(RestDriverError) as raised:
            broken.read_repository(REPOSITORY, broken.fixed_query_scope)
        self.assertEqual(str(raised.exception), "authentication_failed")
        self.assertNotIn(TOKEN_SENTINEL, str(raised.exception))
        self.assertNotIn(TOKEN_SENTINEL, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)


class HostReadAuthCompositionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = tempfile.TemporaryDirectory()
        self.keys = tempfile.TemporaryDirectory()
        workspace = Path(self.workspace.name)
        keys = Path(self.keys.name)
        self.context = RuntimeContext.from_workspace_root(workspace)
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ed_private = ed25519.Ed25519PrivateKey.generate()
        self.rsa_path = keys / "github-rsa.pem"
        self.ed_private_path = keys / "attestation-private.pem"
        self.ed_public_path = keys / "attestation-public.pem"
        self.rsa_path.write_bytes(_pem_private(rsa_key))
        self.ed_private_path.write_bytes(_pem_private(ed_private))
        self.ed_public_path.write_bytes(_pem_public(ed_private.public_key()))
        self.environment = _environment(self.rsa_path, self.ed_private_path, self.ed_public_path)

    def tearDown(self) -> None:
        self.keys.cleanup()
        self.workspace.cleanup()

    def test_production_host_uses_one_lease_rooted_read_auth_view(self) -> None:
        transport = FakeBootstrapTransport()
        with patch.object(type(self.context), "ensure_store_ready", lambda self, **kwargs: Path(self.state_path).parent.mkdir(parents=True, exist_ok=True)):
            composition = compose_write_enabled_host(
                self.context,
                configuration=load_host_configuration(self.environment),
                bootstrap_transport=transport,
                clock=lambda: NOW,
                credential_instance_id_factory=lambda: "00000000-0000-4000-8000-000000000008",
                nonce_factory=lambda: "nonce-" + "a" * 32,
            )
        driver = composition.driver
        self.assertIs(type(driver), GitHubAppInstallationReadOnlyDriver)
        self.assertEqual(composition.trust_context.trusted_driver_identity, driver.trusted_driver_identity)
        self.assertEqual(composition.trust_context.contract_version, driver.contract_version)
        self.assertIs(type(driver._installation_auth_provider), _LeaseReadAuthView)
        view = driver._installation_auth_provider
        self.assertIs(view._LeaseReadAuthView__lease, composition.lease)
        self.assertEqual(view.get_token(), TOKEN)
        self.assertEqual(view.authenticated_subject_identity(), f"github-app-installation-{APP_ID}-{INSTALLATION_ID}")
        self.assertEqual(dict(view.effective_permissions()), {"issues": "write"})
        self.assertIs(composition.provider._GitHubAppCredentialCapabilityProvider__evidence_source._LeaseEvidenceSource__lease, composition.lease)
        self.assertIs(composition.approval_authority_service._host_credential_lease, composition.lease)
        self.assertIsNone(driver.token_provider)
        self.assertEqual(transport.token_posts, 1)
        self.assertNotIn(TOKEN, repr(view))

    def test_read_auth_view_is_exact_type_immutable_and_non_serializable(self) -> None:
        with self.assertRaises(HostCompositionError):
            _LeaseReadAuthView(object())
        with patch.object(type(self.context), "ensure_store_ready", lambda self, **kwargs: Path(self.state_path).parent.mkdir(parents=True, exist_ok=True)):
            composition = compose_write_enabled_host(
                self.context,
                configuration=load_host_configuration(self.environment),
                bootstrap_transport=FakeBootstrapTransport(),
                clock=lambda: NOW,
                credential_instance_id_factory=lambda: "00000000-0000-4000-8000-000000000009",
                nonce_factory=lambda: "nonce-" + "b" * 32,
            )
        view = composition.driver._installation_auth_provider
        with self.assertRaises(HostCompositionError):
            view.extra = TOKEN_SENTINEL
        self.assertNotIn(TOKEN_SENTINEL, repr(view))


if __name__ == "__main__":
    unittest.main()
