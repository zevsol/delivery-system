"""Offline tests for the GitHub App installation bootstrap boundary."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from delivery_system.attestation_github_app import GitHubAppInstallationCapabilityEvidence
from delivery_system.github_app_bootstrap import (
    API_HOST,
    API_VERSION,
    MAX_PRIVATE_KEY_BYTES,
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    USER_AGENT,
    FileGitHubAppPrivateKeySource,
    GitHubAppBootstrapConfig,
    GitHubAppBootstrapError,
    GitHubAppBootstrapResponse,
    GitHubAppInstallationCredentialBootstrap,
    HttpsGitHubAppBootstrapTransport,
    _json_object,
)
from delivery_system.github_app_credential import GitHubAppInstallationCredentialLease


NOW = datetime(2026, 9, 6, 12, tzinfo=timezone.utc)
CONFIG = GitHubAppBootstrapConfig(12345, "owner/repo", 67890, "C:\\outside\\app.pem")
TOKEN = "synthetic-installation-token"
INSTALLATION_ID = 54321
INSTANCE_IDS = iter((str(uuid.uuid4()), str(uuid.uuid4())))


def response(status, value, content_type="application/vnd.github+json"):
    body = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return GitHubAppBootstrapResponse(status, {"Content-Type": content_type}, body)


def raw_response(status, body, content_type="application/vnd.github+json"):
    return GitHubAppBootstrapResponse(status, {"Content-Type": content_type}, body)


def assert_clean_exception(testcase, exception, *sentinels):
    testcase.assertIsNone(exception.__cause__)
    testcase.assertIsNone(exception.__context__)
    public = f"{exception!s}\n{exception!r}"
    for sentinel in sentinels:
        testcase.assertNotIn(sentinel, public)


def _contains_secret(value, sentinels, seen=None):
    if seen is None:
        seen = set()
    if isinstance(value, (str, bytes, bytearray)):
        text = value.decode("utf-8", "replace") if isinstance(value, (bytes, bytearray)) else value
        return any(sentinel in text for sentinel in sentinels)
    identity = id(value)
    if identity in seen:
        return False
    seen.add(identity)
    if isinstance(value, dict):
        return any(
            _contains_secret(item, sentinels, seen)
            for pair in value.items()
            for item in pair
        )
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(_contains_secret(item, sentinels, seen) for item in value)
    return any(sentinel in repr(value) for sentinel in sentinels)


def assert_secret_free_surface(testcase, exception, *sentinels):
    testcase.assertIsNone(exception.__cause__)
    testcase.assertIsNone(exception.__context__)
    for sentinel in sentinels:
        testcase.assertNotIn(sentinel, str(exception))
        testcase.assertNotIn(sentinel, repr(exception))
    for name, value in vars(exception).items():
        testcase.assertFalse(_contains_secret(value, sentinels), name)
    chain = []
    current = exception
    while current is not None and id(current) not in {id(item) for item in chain}:
        chain.append(current)
        current = current.__cause__ or current.__context__
    for item in chain:
        testcase.assertFalse(_contains_secret(item.args, sentinels))
    traceback = exception.__traceback__
    while traceback is not None:
        filename = traceback.tb_frame.f_code.co_filename.replace("\\", "/")
        if "/delivery_system/" in filename:
            for name, value in traceback.tb_frame.f_locals.items():
                testcase.assertFalse(_contains_secret(value, sentinels), name)
        traceback = traceback.tb_next


def app_response(**changes):
    value = {"id": CONFIG.app_id, "owner": {"login": "owner"}}
    value.update(changes)
    return response(200, value)


def installation_response(**changes):
    value = {
        "id": INSTALLATION_ID,
        "app_id": CONFIG.app_id,
        "account": {"login": "owner"},
        "suspended_at": None,
        "repository_selection": "selected",
        "permissions": {"metadata": "read", "issues": "write"},
    }
    value.update(changes)
    return response(200, value)


def repository_record(**changes):
    value = {"id": CONFIG.repository_id, "full_name": CONFIG.repository_identity}
    value.update(changes)
    return value


def token_response(**changes):
    value = {
        "token": TOKEN,
        "expires_at": "2026-09-06T13:00:00Z",
        "permissions": {"metadata": "read", "issues": "write"},
        "repository_selection": "selected",
    }
    value.update(changes)
    return response(201, value)


def scope_response(**changes):
    value = {"total_count": 1, "repositories": [repository_record()]}
    value.update(changes)
    return response(200, value)


class FakeSource:
    def __init__(self, key):
        self.key = key
        self.calls = 0

    def load_rsa_private_key(self):
        self.calls += 1
        return self.key


class FakeTransport:
    def __init__(self, *, app=None, installation=None, token=None, scope=None, repository=None):
        self.app = app or app_response()
        self.installation = installation or installation_response()
        self.token = token or token_response()
        self.scope = scope or scope_response()
        self.repository = repository or response(200, repository_record(has_issues=True, archived=False, disabled=False, private=True))
        self.calls = []
        self.tokens = []

    def get_app(self, app_jwt):
        self.calls.append(("get_app", app_jwt))
        self._assert_jwt(app_jwt)
        return self.app

    def get_repository_installation(self, app_jwt, repository_identity):
        self.calls.append(("get_installation", app_jwt, repository_identity))
        self._assert_jwt(app_jwt)
        return self.installation

    def create_installation_token(self, app_jwt, installation_id, repository_id):
        self.calls.append(("create_token", app_jwt, installation_id, repository_id))
        self._assert_jwt(app_jwt)
        self.tokens.append(TOKEN)
        return self.token

    def get_installation_repositories(self, installation_token):
        self.calls.append(("get_scope", installation_token))
        self._assert_token(installation_token)
        return self.scope

    def get_repository(self, installation_token, repository_identity):
        self.calls.append(("get_repository", installation_token, repository_identity))
        self._assert_token(installation_token)
        return self.repository

    @staticmethod
    def _assert_jwt(value):
        if not isinstance(value, str) or value.count(".") != 2:
            raise AssertionError("JWT was not supplied to the App operations")

    @staticmethod
    def _assert_token(value):
        if value != TOKEN:
            raise AssertionError("unexpected synthetic token")


def bootstrap(source=None, transport=None, config=CONFIG, instance_factory=None):
    return GitHubAppInstallationCredentialBootstrap(
        config,
        private_key_source=source or FakeSource(rsa.generate_private_key(public_exponent=65537, key_size=2048)),
        transport=transport or FakeTransport(),
        clock=lambda: NOW,
        credential_instance_id_factory=instance_factory or (lambda: str(uuid.uuid4())),
    )


class ConfigurationTests(unittest.TestCase):
    def test_rejects_invalid_configuration(self):
        cases = [
            (True, "owner/repo", 1, "C:\\a.pem"),
            (0, "owner/repo", 1, "C:\\a.pem"),
            (1, "owner/repo", 0, "C:\\a.pem"),
            (1, "invalid", 1, "C:\\a.pem"),
            (1, "owner/repo", 1, "relative.pem"),
            (1, "owner/repo", 1, ""),
        ]
        for values in cases:
            with self.subTest(values=values):
                with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_configuration_invalid"):
                    GitHubAppBootstrapConfig(*values)

    def test_constructor_is_side_effect_free(self):
        source = FakeSource(rsa.generate_private_key(public_exponent=65537, key_size=2048))
        transport = FakeTransport()
        bootstrapper = GitHubAppInstallationCredentialBootstrap(CONFIG, private_key_source=source, transport=transport)
        self.assertEqual(source.calls, 0)
        self.assertEqual(transport.calls, [])
        self.assertNotIn(TOKEN, repr(bootstrapper))


class KeySourceTests(unittest.TestCase):
    def write(self, value):
        directory = tempfile.TemporaryDirectory()
        path = Path(directory.name) / "app.pem"
        path.write_bytes(value)
        self.addCleanup(directory.cleanup)
        return path

    def test_valid_rsa_key_loads(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        loaded = FileGitHubAppPrivateKeySource(str(self.write(pem))).load_rsa_private_key()
        self.assertIsInstance(loaded, type(key))

    def test_missing_directory_empty_oversized_and_invalid_keys_fail(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        missing = FileGitHubAppPrivateKeySource(str(Path(directory.name) / "missing.pem"))
        with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_acquisition_failed"):
            missing.load_rsa_private_key()
        folder = Path(directory.name) / "folder"
        folder.mkdir()
        with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_acquisition_failed"):
            FileGitHubAppPrivateKeySource(str(folder)).load_rsa_private_key()
        empty = Path(directory.name) / "empty.pem"
        empty.write_bytes(b"")
        with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_acquisition_failed"):
            FileGitHubAppPrivateKeySource(str(empty)).load_rsa_private_key()
        oversized = Path(directory.name) / "large.pem"
        oversized.write_bytes(b"x" * (MAX_PRIVATE_KEY_BYTES + 1))
        with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_acquisition_failed"):
            FileGitHubAppPrivateKeySource(str(oversized)).load_rsa_private_key()
        for key in (ed25519.Ed25519PrivateKey.generate(), ec.generate_private_key(ec.SECP256R1())):
            pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_acquisition_failed"):
                FileGitHubAppPrivateKeySource(str(self.write(pem))).load_rsa_private_key()
        public_pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_acquisition_failed"):
            FileGitHubAppPrivateKeySource(str(self.write(public_pem))).load_rsa_private_key()

    def test_malformed_and_leaf_symlink_fail(self):
        path = self.write(b"not a private key")
        with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_acquisition_failed"):
            FileGitHubAppPrivateKeySource(str(path)).load_rsa_private_key()
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        target = Path(directory.name) / "target.pem"
        target.write_bytes(b"not a key")
        link = Path(directory.name) / "link.pem"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("platform cannot create a deterministic symlink")
        with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_acquisition_failed"):
            FileGitHubAppPrivateKeySource(str(link)).load_rsa_private_key()

    def test_private_key_read_uses_validated_open_handle(self):
        original_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        replacement_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        original_pem = original_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        replacement_pem = replacement_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "app.pem"
        replacement = Path(directory.name) / "replacement.pem"
        path.write_bytes(original_pem)
        replacement.write_bytes(replacement_pem)

        original_fstat = os.fstat
        replacement_attempted = False

        def replace_after_open(fd):
            nonlocal replacement_attempted
            result = original_fstat(fd)
            if not replacement_attempted:
                replacement_attempted = True
                try:
                    os.replace(replacement, path)
                except PermissionError:
                    pass
            return result

        with patch("pathlib.Path.open", side_effect=AssertionError("a second pathname open is forbidden")):
            with patch("delivery_system.github_app_bootstrap.os.fstat", side_effect=replace_after_open):
                loaded = FileGitHubAppPrivateKeySource(str(path)).load_rsa_private_key()
        self.assertTrue(replacement_attempted)
        self.assertEqual(loaded.private_numbers(), original_key.private_numbers())

    def test_secret_failure_has_no_exception_context(self):
        sentinel = "SYNTHETIC_PEM_SECRET_SENTINEL"
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        source = FileGitHubAppPrivateKeySource(str(self.write(pem)))
        with patch(
            "delivery_system.github_app_bootstrap.serialization.load_pem_private_key",
            side_effect=ValueError(sentinel),
        ):
            with self.assertRaises(GitHubAppBootstrapError) as raised:
                source.load_rsa_private_key()
        assert_clean_exception(self, raised.exception, sentinel)


class BootstrapTests(unittest.TestCase):
    def test_end_to_end_offline_bootstrap_returns_exact_lease(self):
        source = FakeSource(rsa.generate_private_key(public_exponent=65537, key_size=2048))
        transport = FakeTransport()
        instance = str(uuid.uuid4())
        lease = bootstrap(source, transport, instance_factory=lambda: instance).acquire()
        self.assertIs(type(lease), GitHubAppInstallationCredentialLease)
        snapshot = lease._snapshot()
        self.assertEqual(snapshot.app_id, CONFIG.app_id)
        self.assertEqual(snapshot.installation_id, INSTALLATION_ID)
        self.assertEqual(snapshot.repository_scope, (CONFIG.repository_identity,))
        self.assertEqual(snapshot.effective_permissions, (("issues", "write"),))
        self.assertEqual(snapshot.credential_instance_id, instance)
        self.assertEqual([call[0] for call in transport.calls], ["get_app", "get_installation", "create_token", "get_scope", "get_repository"])

    def test_jwt_claims_are_exact_and_verifiable(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        source = FakeSource(key)
        transport = FakeTransport()
        bootstrap(source, transport, instance_factory=lambda: str(uuid.uuid4())).acquire()
        app_jwt = transport.calls[0][1]
        claims = jwt.decode(app_jwt, key.public_key(), algorithms=["RS256"], options={"verify_exp": False, "verify_iat": False})
        self.assertEqual(claims, {"iat": int(NOW.timestamp()) - 60, "exp": int(NOW.timestamp()) + 540, "iss": str(CONFIG.app_id)})

    def test_exact_token_request_and_no_extra_mint(self):
        transport = FakeTransport()
        bootstrap(transport=transport).acquire()
        token_calls = [call for call in transport.calls if call[0] == "create_token"]
        self.assertEqual(len(token_calls), 1)
        self.assertEqual(token_calls[0][2:], (INSTALLATION_ID, CONFIG.repository_id))
        self.assertEqual(len(transport.tokens), 1)

    def test_identity_scope_permission_and_metadata_fail_closed(self):
        mutations = [
            ("app", {"id": 1}),
            ("app", {"owner": {"login": "other"}}),
            ("installation", {"app_id": 1}),
            ("installation", {"account": {"login": "other"}}),
            ("installation", {"suspended_at": "2026-09-06T11:00:00Z"}),
            ("installation", {"suspended_at": None, "repository_selection": "all"}),
            ("installation", {"repository_selection": None}),
            ("installation", {"permissions": {"issues": "read"}}),
            ("installation", {"permissions": {"issues": "write", "contents": "write"}}),
            ("token", {"permissions": {"issues": "write", "contents": "write"}}),
            ("scope", {"total_count": 2, "repositories": [repository_record(), repository_record(id=999)]}),
            ("scope", {"total_count": 0, "repositories": []}),
            ("scope", {"total_count": 1, "repositories": [repository_record(full_name="owner/other")]}),
            ("repository", {"id": 999}),
            ("repository", {"full_name": "owner/other"}),
            ("repository", {"has_issues": False}),
            ("repository", {"archived": True}),
        ]
        for target, changes in mutations:
            with self.subTest(target=target, changes=changes):
                transport = FakeTransport()
                if target == "app": transport.app = app_response(**changes)
                if target == "installation": transport.installation = installation_response(**changes)
                if target == "token": transport.token = token_response(**changes)
                if target == "scope": transport.scope = scope_response(**changes)
                if target == "repository":
                    repository_changes = {"has_issues": True, "archived": False, "disabled": False, "private": True}
                    repository_changes.update(changes)
                    transport.repository = response(200, repository_record(**repository_changes))
                with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_acquisition_failed"):
                    bootstrap(transport=transport).acquire()

    def test_remote_boolean_ids_are_rejected(self):
        config = GitHubAppBootstrapConfig(1, "owner/repo", 1, "C:\\outside\\app.pem")

        def matching_transport():
            return FakeTransport(
                app=response(200, {"id": 1, "owner": {"login": "owner"}}),
                installation=response(200, {
                    "id": 1,
                    "app_id": 1,
                    "account": {"login": "owner"},
                    "suspended_at": None,
                    "repository_selection": "selected",
                    "permissions": {"metadata": "read", "issues": "write"},
                }),
                scope=response(200, {"total_count": 1, "repositories": [{"id": 1, "full_name": "owner/repo"}]}),
                repository=response(200, {
                    "id": 1,
                    "full_name": "owner/repo",
                    "has_issues": True,
                    "archived": False,
                    "disabled": False,
                    "private": True,
                }),
            )

        for location in ("app_id", "installation_id", "installation_app_id", "scope_id", "target_id", "total_count"):
            for invalid in (True, False, "1", 1.0):
                with self.subTest(location=location, invalid=invalid):
                    transport = matching_transport()
                    if location == "app_id":
                        transport.app = response(200, {"id": invalid, "owner": {"login": "owner"}})
                    elif location == "installation_id":
                        value = json.loads(transport.installation.body)
                        value["id"] = invalid
                        transport.installation = response(200, value)
                    elif location == "installation_app_id":
                        value = json.loads(transport.installation.body)
                        value["app_id"] = invalid
                        transport.installation = response(200, value)
                    elif location == "scope_id":
                        transport.scope = response(200, {
                            "total_count": 1,
                            "repositories": [{"id": invalid, "full_name": "owner/repo"}],
                        })
                    elif location == "target_id":
                        transport.repository = response(200, {
                            "id": invalid,
                            "full_name": "owner/repo",
                            "has_issues": True,
                            "archived": False,
                        })
                    else:
                        transport.scope = response(200, {
                            "total_count": invalid,
                            "repositories": [{"id": 1, "full_name": "owner/repo"}],
                        })
                    with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_acquisition_failed"):
                        bootstrap(transport=transport, config=config).acquire()

    def test_duplicate_json_keys_are_rejected(self):
        bodies = (
            b'{"id":12345,"id":999,"owner":{"login":"owner"}}',
            b'{"permissions":{"issues":"write","issues":"read"}}',
            b'{"harmless":"first","harmless":"second"}',
        )
        for body in bodies:
            with self.subTest(body=body):
                with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_acquisition_failed"):
                    _json_object(raw_response(200, body))

    def test_expiry_and_shape_failures(self):
        cases = [
            {"expires_at": "2026-09-06T11:00:00Z"},
            {"expires_at": "2026-09-06T13:00:00"},
            {"expires_at": "invalid"},
            {"token": ""},
            {"permissions": {"issues": "read"}},
        ]
        for changes in cases:
            with self.subTest(changes=changes):
                transport = FakeTransport(token=token_response(**changes))
                with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_acquisition_failed"):
                    bootstrap(transport=transport).acquire()

        non_201 = response(200, {
            "token": TOKEN,
            "expires_at": "2026-09-06T13:00:00Z",
            "permissions": {"issues": "write"},
        })
        with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_acquisition_failed"):
            bootstrap(transport=FakeTransport(token=non_201)).acquire()

    def test_get_responses_require_exact_success_status(self):
        transport = FakeTransport(app=response(201, {"id": CONFIG.app_id, "owner": {"login": "owner"}}))
        with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_acquisition_failed"):
            bootstrap(transport=transport).acquire()

    def test_injected_noncanonical_bootstrap_errors_are_redacted(self):
        sentinel = "JWT_OR_TOKEN_SENTINEL"

        class BadTransport(FakeTransport):
            def get_app(self, app_jwt):
                raise GitHubAppBootstrapError(sentinel)

        with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_acquisition_failed") as raised:
            bootstrap(transport=BadTransport()).acquire()
        assert_clean_exception(self, raised.exception, sentinel)

    def test_ambiguous_token_post_has_no_retry_or_lease(self):
        class Ambiguous(FakeTransport):
            def create_installation_token(self, app_jwt, installation_id, repository_id):
                self.calls.append(("create_token", app_jwt, installation_id, repository_id))
                raise GitHubAppBootstrapError("credential_acquisition_failed")
        transport = Ambiguous()
        with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_acquisition_failed"):
            bootstrap(transport=transport).acquire()
        self.assertEqual(len([call for call in transport.calls if call[0] == "create_token"]), 1)

    def test_secret_strings_do_not_escape_errors_or_repr(self):
        sentinel = "SYNTHETIC_SECRET_SENTINEL"
        class BadSource:
            def load_rsa_private_key(self):
                raise RuntimeError(sentinel)
        bootstrapper = GitHubAppInstallationCredentialBootstrap(CONFIG, private_key_source=BadSource(), transport=FakeTransport())
        with self.assertRaises(GitHubAppBootstrapError) as raised:
            bootstrapper.acquire()
        assert_clean_exception(self, raised.exception, sentinel)
        self.assertNotIn(sentinel, repr(bootstrapper))
        self.assertNotIn(TOKEN, repr(bootstrapper))

    def test_bootstrap_secret_failures_have_no_exception_context(self):
        jwt_sentinel = "SYNTHETIC_JWT_SECRET_SENTINEL"
        with patch("delivery_system.github_app_bootstrap.jwt.encode", side_effect=RuntimeError(jwt_sentinel)):
            with self.assertRaises(GitHubAppBootstrapError) as raised:
                bootstrap().acquire()
        assert_clean_exception(self, raised.exception, jwt_sentinel)

        transport_sentinel = "SYNTHETIC_AUTHORIZATION_SECRET_SENTINEL"

        class BadTransport(FakeTransport):
            def get_app(self, app_jwt):
                raise RuntimeError(transport_sentinel)

        with self.assertRaises(GitHubAppBootstrapError) as raised:
            bootstrap(transport=BadTransport()).acquire()
        assert_clean_exception(self, raised.exception, transport_sentinel)

        token_sentinel = "SYNTHETIC_TOKEN_RESPONSE_SENTINEL"
        malformed = raw_response(201, ('{"token":"' + token_sentinel + '",').encode("utf-8"))
        with self.assertRaises(GitHubAppBootstrapError) as raised:
            bootstrap(transport=FakeTransport(token=malformed)).acquire()
        assert_clean_exception(self, raised.exception, token_sentinel)

    def test_two_acquisitions_have_distinct_uuid4_instances(self):
        ids = [str(uuid.uuid4()), str(uuid.uuid4())]
        first = bootstrap(instance_factory=lambda: ids[0]).acquire()
        second = bootstrap(instance_factory=lambda: ids[1]).acquire()
        self.assertNotEqual(first._snapshot().credential_instance_id, second._snapshot().credential_instance_id)
        self.assertIsNot(first, second)

    def test_credential_instance_id_cannot_be_reused(self):
        instance = str(uuid.uuid4())
        source = FakeSource(rsa.generate_private_key(public_exponent=65537, key_size=2048))
        transport = FakeTransport()
        bootstrapper = GitHubAppInstallationCredentialBootstrap(
            CONFIG,
            private_key_source=source,
            transport=transport,
            clock=lambda: NOW,
            credential_instance_id_factory=lambda: instance,
        )
        first = bootstrapper.acquire()
        self.assertEqual(first._snapshot().credential_instance_id, instance)
        with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_acquisition_failed"):
            bootstrapper.acquire()
        self.assertEqual(source.calls, 1)
        self.assertEqual(len([call for call in transport.calls if call[0] == "create_token"]), 1)

        failed_transport = FakeTransport(app=app_response(id=999))
        failed_source = FakeSource(rsa.generate_private_key(public_exponent=65537, key_size=2048))
        failed_bootstrapper = GitHubAppInstallationCredentialBootstrap(
            CONFIG,
            private_key_source=failed_source,
            transport=failed_transport,
            clock=lambda: NOW,
            credential_instance_id_factory=lambda: instance,
        )
        with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_acquisition_failed"):
            failed_bootstrapper.acquire()
        failed_transport.app = app_response()
        with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_acquisition_failed"):
            failed_bootstrapper.acquire()
        self.assertEqual(failed_source.calls, 1)
        self.assertEqual(len([call for call in failed_transport.calls if call[0] == "create_token"]), 0)

        wrong_variant = uuid.UUID(int=uuid.uuid4().int & ~(0b11 << 62))
        invalid_values = (
            str(uuid.uuid1()),
            str(uuid.uuid3(uuid.NAMESPACE_DNS, "example")),
            str(uuid.uuid5(uuid.NAMESPACE_DNS, "example")),
            str(wrong_variant),
            "not-a-uuid",
            object(),
        )
        for invalid in invalid_values:
            with self.subTest(invalid=invalid):
                candidate = bootstrap(instance_factory=lambda invalid=invalid: invalid)
                with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_acquisition_failed"):
                    candidate.acquire()

    def test_observation_must_precede_expiry(self):
        class SequenceClock:
            def __init__(self, *values):
                self.values = iter(values)

            def __call__(self):
                return next(self.values)

        before = NOW + timedelta(minutes=30)
        passing = GitHubAppInstallationCredentialBootstrap(
            CONFIG,
            private_key_source=FakeSource(rsa.generate_private_key(public_exponent=65537, key_size=2048)),
            transport=FakeTransport(),
            clock=SequenceClock(NOW, NOW, before),
            credential_instance_id_factory=lambda: str(uuid.uuid4()),
        ).acquire()
        self.assertEqual(passing._snapshot().observed_at, before.isoformat().replace("+00:00", "Z"))

        expiry = datetime(2026, 9, 6, 13, tzinfo=timezone.utc)
        for final_time in (expiry, expiry + timedelta(seconds=1)):
            with self.subTest(final_time=final_time):
                bootstrapper = GitHubAppInstallationCredentialBootstrap(
                    CONFIG,
                    private_key_source=FakeSource(rsa.generate_private_key(public_exponent=65537, key_size=2048)),
                    transport=FakeTransport(),
                    clock=SequenceClock(NOW, NOW, final_time),
                    credential_instance_id_factory=lambda: str(uuid.uuid4()),
                )
                with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_acquisition_failed"):
                    bootstrapper.acquire()


class TransportTests(unittest.TestCase):
    def test_direct_transport_operations_have_secret_free_tracebacks(self):
        app_jwt = "SENTINEL_APP_JWT_DO_NOT_LEAK"
        installation_token = "SENTINEL_INSTALLATION_TOKEN_DO_NOT_LEAK"
        operations = (
            ("get_app", lambda transport: transport.get_app(app_jwt), app_jwt),
            (
                "get_installation",
                lambda transport: transport.get_repository_installation(app_jwt, CONFIG.repository_identity),
                app_jwt,
            ),
            (
                "create_token",
                lambda transport: transport.create_installation_token(app_jwt, INSTALLATION_ID, CONFIG.repository_id),
                app_jwt,
            ),
            (
                "get_scope",
                lambda transport: transport.get_installation_repositories(installation_token),
                installation_token,
            ),
            (
                "get_repository",
                lambda transport: transport.get_repository(installation_token, CONFIG.repository_identity),
                installation_token,
            ),
        )
        for name, operation, secret in operations:
            with self.subTest(operation=name):
                with patch(
                    "delivery_system.github_app_bootstrap.HttpsGitHubAppBootstrapTransport._request_once",
                    side_effect=RuntimeError("SYNTHETIC_INTERNAL_FAILURE"),
                ), patch(
                    "delivery_system.github_app_bootstrap.http.client.HTTPSConnection",
                    side_effect=AssertionError("real network is forbidden"),
                ):
                    with self.assertRaises(GitHubAppBootstrapError) as raised:
                        operation(HttpsGitHubAppBootstrapTransport())
                assert_secret_free_surface(self, raised.exception, secret, "SYNTHETIC_INTERNAL_FAILURE")

    def test_token_response_secret_has_no_public_traceback_surface(self):
        token_sentinel = "SENTINEL_MINTED_TOKEN_DO_NOT_LEAK"
        malformed = token_response(token=token_sentinel, expires_at="not-a-timestamp")
        with self.assertRaises(GitHubAppBootstrapError) as raised:
            bootstrap(transport=FakeTransport(token=malformed)).acquire()
        assert_secret_free_surface(self, raised.exception, token_sentinel)

    def test_fixed_headers_and_bounded_post(self):
        calls = []
        class Sock:
            def settimeout(self, value): self.timeout = value
        class Response:
            status = 201
            def getheaders(self): return [("Content-Type", "application/vnd.github+json")]
            def read(self, amount): self.amount = amount; return b"{}"
        class Connection:
            sock = Sock()
            def __init__(self, host, timeout, context): self.host, self.timeout = host, timeout
            def connect(self): pass
            def request(self, method, path, body, headers): calls.append((method, path, body, headers))
            def getresponse(self): return Response()
            def close(self): pass
        with patch("delivery_system.github_app_bootstrap.http.client.HTTPSConnection", Connection):
            result = HttpsGitHubAppBootstrapTransport().create_installation_token("jwt", INSTALLATION_ID, CONFIG.repository_id)
        self.assertEqual(result.status, 201)
        self.assertEqual(calls[0][0:2], ("POST", f"/app/installations/{INSTALLATION_ID}/access_tokens"))
        self.assertEqual(calls[0][3]["Accept"], "application/vnd.github+json")
        self.assertEqual(calls[0][3]["X-GitHub-Api-Version"], API_VERSION)
        self.assertEqual(calls[0][3]["User-Agent"], USER_AGENT)
        self.assertEqual(calls[0][3]["Authorization"], "Bearer jwt")
        self.assertLessEqual(len(calls[0][2]), MAX_REQUEST_BYTES)

    def test_json_media_type_and_malformed_body_fail_closed(self):
        class Connection:
            sock = None
            def __init__(self, *args, **kwargs): pass
            def connect(self): pass
            def request(self, *args, **kwargs): pass
            def close(self): pass

            def getresponse(self):
                class Response:
                    status = 200
                    def getheaders(self): return [("Content-Type", "text/plain")]
                    def read(self, amount): return b"{}"
                return Response()

        with patch("delivery_system.github_app_bootstrap.http.client.HTTPSConnection", Connection):
            with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_acquisition_failed"):
                response = HttpsGitHubAppBootstrapTransport().get_app("jwt")
                from delivery_system.github_app_bootstrap import _json_object
                _json_object(response)

    def test_content_type_rejects_unknown_parameters(self):
        accepted = (
            "application/json",
            "application/json; charset=utf-8",
            "application/json; charset=UTF-8",
            "application/vnd.github+json; charset=utf-8",
            'application/json; charset="utf-8"',
        )
        rejected = (
            "application/json; attacker=accepted",
            "application/json; charset=utf-8; attacker=x",
            "application/json; charset=latin1",
            "application/json; charset=utf-8; charset=utf-8",
            "application/json;",
        )
        for content_type in accepted:
            with self.subTest(content_type=content_type):
                self.assertEqual(_json_object(raw_response(200, b"{}", content_type)), {})
        for content_type in rejected:
            with self.subTest(content_type=content_type):
                with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_acquisition_failed"):
                    _json_object(raw_response(200, b"{}", content_type))

    def test_transport_failure_has_no_exception_context(self):
        sentinel = "SYNTHETIC_TRANSPORT_SECRET_SENTINEL"

        class Connection:
            def __init__(self, *args, **kwargs):
                pass

            def connect(self):
                raise RuntimeError(sentinel)

            def close(self):
                pass

        with patch("delivery_system.github_app_bootstrap.http.client.HTTPSConnection", Connection):
            with self.assertRaises(GitHubAppBootstrapError) as raised:
                HttpsGitHubAppBootstrapTransport().get_app("synthetic-jwt")
        assert_clean_exception(self, raised.exception, sentinel, "synthetic-jwt")

    def test_redirect_and_oversized_response_fail(self):
        class Response:
            def __init__(self, status, body): self.status, self.body = status, body
            def getheaders(self): return [("Content-Type", "application/json")]
            def read(self, amount): return self.body
        class Connection:
            sock = None
            response = Response(302, b"{}")
            def __init__(self, *args, **kwargs): pass
            def connect(self): pass
            def request(self, *args, **kwargs): pass
            def getresponse(self): return self.response
            def close(self): pass
        with patch("delivery_system.github_app_bootstrap.http.client.HTTPSConnection", Connection):
            with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_acquisition_failed"):
                HttpsGitHubAppBootstrapTransport().get_app("jwt")
        class LargeConnection(Connection):
            response = Response(200, b"x" * (MAX_RESPONSE_BYTES + 1))
        with patch("delivery_system.github_app_bootstrap.http.client.HTTPSConnection", LargeConnection):
            with self.assertRaisesRegex(GitHubAppBootstrapError, "credential_acquisition_failed"):
                HttpsGitHubAppBootstrapTransport().get_app("jwt")


if __name__ == "__main__":
    unittest.main()
