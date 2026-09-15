from __future__ import annotations

from datetime import datetime, timezone
import http.server
import json
from pathlib import Path
import socket
import tempfile
from threading import Thread
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from delivery_system.host_revocation import (
    ExternalRevocationError,
    ExternalRevocationReader,
    RevocationQuery,
)
from tests.integration.revocation_provider_harness import (
    ENDPOINT_PATH,
    INT1_ISSUER,
    INT1_KEY_ID,
    INT1_REPOSITORY,
    INT1_VERSION,
    LOOPBACK_ADDRESS,
    LoopbackRevocationServer,
    RevocationProvider,
    RevocationState,
    build_argument_parser,
    read_token_file,
)


TOKEN = "v1-int1-test-bearer-token"


def query_payload(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "issuer_id": INT1_ISSUER,
        "credential_instance_id": "credential-instance-1",
        "attestation_id": "attestation-1",
        "key_id": INT1_KEY_ID,
        "version": INT1_VERSION,
        "repository_identity": INT1_REPOSITORY,
    }
    value.update(changes)
    return value


def encoded(payload: object) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def http_request(endpoint: str, *, method: str = "POST", body: bytes | None = None, token: str | None = TOKEN) -> tuple[int, dict[str, object]]:
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    request = Request(endpoint, data=body, headers=headers, method=method)
    try:
        with urlopen(request, timeout=2) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


class _MalformedResponseHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        body = b"not-json"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class _MalformedResponseServer(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True


class HarnessTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.token_path = Path(self.tempdir.name) / "token.txt"
        self.token_path.write_text(TOKEN + "\n", encoding="utf-8")
        self.state = RevocationState()
        self.provider = RevocationProvider(
            read_token_file(self.token_path),
            state=self.state,
            clock=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        self.server = LoopbackRevocationServer(self.provider)
        self.thread = self.server.start_background()
        self.endpoint = self.server.endpoint

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()
        self.tempdir.cleanup()

    def reader(self, *, endpoint: str | None = None, token: str | None = TOKEN) -> ExternalRevocationReader:
        return ExternalRevocationReader(
            endpoint=endpoint or self.endpoint,
            timeout_ms=1000,
            repository_identity=INT1_REPOSITORY,
            auth_token=token,
        )

    def read(self, *, endpoint: str | None = None, token: str | None = TOKEN):
        return self.reader(endpoint=endpoint, token=token).read_status(
            "attestation-1",
            "credential-instance-1",
            INT1_ISSUER,
            INT1_KEY_ID,
            INT1_VERSION,
        )


class ProviderContractTests(HarnessTestCase):
    def test_exact_valid_request_returns_200_valid(self) -> None:
        status, payload = http_request(self.endpoint, body=encoded(query_payload()))
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"status": "valid"})

    def test_revoked_credential_returns_200_revoked(self) -> None:
        self.state.revoked_credential_instance_ids.add("credential-instance-1")
        status, payload = http_request(self.endpoint, body=encoded(query_payload()))
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "revoked")
        self.assertEqual(payload["reason"], "credential-revoked")
        self.assertEqual(payload["revoked_at"], "2026-01-01T00:00:00Z")

    def test_revoked_attestation_returns_200_revoked(self) -> None:
        self.state.revoked_attestation_ids.add("attestation-1")
        status, payload = http_request(self.endpoint, body=encoded(query_payload()))
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "revoked")
        self.assertEqual(payload["reason"], "attestation-revoked")

    def test_malformed_json_returns_400(self) -> None:
        status, payload = http_request(self.endpoint, body=b"{")
        self.assertEqual((status, payload["error"]), (400, "json_invalid"))

    def test_duplicate_json_keys_return_400(self) -> None:
        body = b'{"issuer_id":"v1-int1-attestation","issuer_id":"duplicate"}'
        status, payload = http_request(self.endpoint, body=body)
        self.assertEqual((status, payload["error"]), (400, "duplicate_json_key"))

    def test_missing_field_returns_400(self) -> None:
        value = query_payload()
        del value["attestation_id"]
        status, payload = http_request(self.endpoint, body=encoded(value))
        self.assertEqual(status, 400)
        self.assertNotEqual(payload, {"status": "valid"})

    def test_extra_field_returns_400(self) -> None:
        status, payload = http_request(self.endpoint, body=encoded(query_payload(extra="nope")))
        self.assertEqual((status, payload["error"]), (400, "request_fields_invalid"))

    def test_wrong_type_and_invalid_identity_return_400(self) -> None:
        for change in ({"credential_instance_id": 1}, {"credential_instance_id": "contains whitespace"}):
            with self.subTest(change=change):
                status, _ = http_request(self.endpoint, body=encoded(query_payload(**change)))
                self.assertEqual(status, 400)

    def test_missing_authorization_returns_401(self) -> None:
        status, payload = http_request(self.endpoint, body=encoded(query_payload()), token=None)
        self.assertEqual((status, payload["error"]), (401, "authentication_required"))

    def test_wrong_bearer_token_returns_401(self) -> None:
        status, payload = http_request(self.endpoint, body=encoded(query_payload()), token="wrong-token")
        self.assertEqual((status, payload["error"]), (401, "authentication_invalid"))

    def test_correct_bearer_token_is_accepted(self) -> None:
        status, payload = http_request(self.endpoint, body=encoded(query_payload()), token=TOKEN)
        self.assertEqual((status, payload), (200, {"status": "valid"}))

    def test_out_of_policy_repository_issuer_key_and_version_return_403(self) -> None:
        for field, value in (
            ("repository_identity", "zevsol/other-repository"),
            ("issuer_id", "other-issuer"),
            ("key_id", "other-key"),
            ("version", "2"),
        ):
            with self.subTest(field=field):
                status, payload = http_request(self.endpoint, body=encoded(query_payload(**{field: value})))
                self.assertEqual(status, 403)
                self.assertNotEqual(payload, {"status": "valid"})

    def test_unsupported_method_returns_405(self) -> None:
        status, payload = http_request(self.endpoint, method="GET", body=None)
        self.assertEqual((status, payload["error"]), (405, "method_not_allowed"))

    def test_corrupt_provider_state_returns_503(self) -> None:
        self.state.revoked_credential_instance_ids = ["corrupted"]  # type: ignore[assignment]
        status, payload = http_request(self.endpoint, body=encoded(query_payload()))
        self.assertEqual((status, payload["error"]), (503, "provider_state_invalid"))

    def test_no_error_case_returns_valid(self) -> None:
        cases = [
            (b"{", None),
            (encoded(query_payload(extra="x")), None),
            (encoded(query_payload(repository_identity="zevsol/other")), None),
            (encoded(query_payload()), "wrong-token"),
        ]
        for body, token in cases:
            with self.subTest(body=body, token=token):
                status, payload = http_request(self.endpoint, body=body, token=token or TOKEN)
                self.assertNotEqual((status, payload), (200, {"status": "valid"}))

    def test_listener_is_ipv4_loopback_only(self) -> None:
        self.assertEqual(self.server.server_address[0], LOOPBACK_ADDRESS)
        self.assertEqual(self.server.address_family, socket.AF_INET)
        self.assertTrue(self.endpoint.startswith("http://127.0.0.1:"))
        self.assertTrue(self.endpoint.endswith(ENDPOINT_PATH))

    def test_token_is_file_input_not_raw_cli_input(self) -> None:
        parser = build_argument_parser()
        option_strings = {option for action in parser._actions for option in action.option_strings}
        self.assertIn("--token-file", option_strings)
        self.assertNotIn("--token", option_strings)
        self.assertEqual(read_token_file(self.token_path), TOKEN)

    def test_token_is_absent_from_repr_and_diagnostics(self) -> None:
        self.assertNotIn(TOKEN, repr(self.provider))
        status, payload = http_request(self.endpoint, body=encoded(query_payload()), token="wrong-token")
        self.assertEqual(status, 401)
        self.assertNotIn(TOKEN, json.dumps(payload))


class ProductionReaderIntegrationTests(HarnessTestCase):
    def test_actual_reader_handles_valid_response(self) -> None:
        status = self.read()
        self.assertFalse(status.credential_instance_revoked)

    def test_actual_reader_handles_revoked_response(self) -> None:
        self.state.revoked_credential_instance_ids.add("credential-instance-1")
        status = self.read()
        self.assertTrue(status.credential_instance_revoked)

    def test_actual_reader_maps_http_failure_to_fail_closed_error(self) -> None:
        with self.assertRaisesRegex(ExternalRevocationError, "revocation_unavailable"):
            self.read(token="wrong-token")

    def test_actual_reader_interoperates_with_bearer_authentication(self) -> None:
        self.assertFalse(self.read(token=TOKEN).credential_instance_revoked)

    def test_actual_reader_maps_malformed_response_to_fail_closed_error(self) -> None:
        server = _MalformedResponseServer((LOOPBACK_ADDRESS, 0), _MalformedResponseHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            endpoint = f"http://{LOOPBACK_ADDRESS}:{server.server_address[1]}{ENDPOINT_PATH}"
            with self.assertRaisesRegex(ExternalRevocationError, "revocation_unavailable"):
                self.read(endpoint=endpoint)
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()

    def test_actual_reader_maps_unavailable_provider_to_fail_closed_error(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((LOOPBACK_ADDRESS, 0))
            endpoint = f"http://{LOOPBACK_ADDRESS}:{probe.getsockname()[1]}{ENDPOINT_PATH}"
        with self.assertRaisesRegex(ExternalRevocationError, "revocation_unavailable"):
            self.read(endpoint=endpoint)

    def test_response_size_boundary_is_owned_by_production_reader_tests(self) -> None:
        self.skipTest("Oversized-response coverage belongs to host_revocation.py tests; this harness adds no unique value.")


class QueryContractTests(unittest.TestCase):
    def test_production_query_shape_matches_harness_fields(self) -> None:
        query = RevocationQuery(
            issuer_id=INT1_ISSUER,
            credential_instance_id="credential-instance-1",
            attestation_id="attestation-1",
            key_id=INT1_KEY_ID,
            version=INT1_VERSION,
            repository_identity=INT1_REPOSITORY,
        )
        self.assertEqual(set(query.to_payload()), set(query_payload()))


if __name__ == "__main__":
    unittest.main()
