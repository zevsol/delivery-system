"""Offline tests for the explicit H4 production Host composition."""

from __future__ import annotations

from datetime import datetime, timezone
import copy
import json
import pickle
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from delivery_system.attestation_key_source import (
    AttestationKeySourceError,
    FileEd25519PrivateKeySource,
    FileEd25519PublicKeySource,
    MAX_ED25519_KEY_BYTES,
)
from delivery_system.attestation_signing import (
    Ed25519HostSigner,
    Ed25519ProofVerifier,
    TrustedEd25519IssuerKeyRegistry,
)
from delivery_system.drivers.rest import LocalRestReadOnlyDriver
from delivery_system.github_app_bootstrap import (
    GitHubAppBootstrapResponse,
    GitHubAppBootstrapError,
    FileGitHubAppPrivateKeySource,
    MAX_GITHUB_ID,
)
from delivery_system.github_app_credential import GitHubAppInstallationCredentialLease
from delivery_system.host_composition import (
    HostComposition,
    HostCompositionError,
    HostConfiguration,
    compose_write_enabled_host,
    load_host_configuration,
)
from delivery_system.runtime import RuntimeApprovalAuthorityService, RuntimeContext


NOW = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
APP_ID = 12345
REPOSITORY_ID = 67890
INSTALLATION_ID = 54321
TOKEN = "h4-synthetic-installation-token"
COMPOSITION_SENTINEL = "SYNTHETIC_COMPOSITION_SECRET_SENTINEL"
KEY_SOURCE_SENTINEL = "SYNTHETIC_ED25519_PEM_SENTINEL"


def _assert_no_marker(value, marker: str, seen: set[int] | None = None) -> None:
    seen = set() if seen is None else seen
    if id(value) in seen:
        return
    seen.add(id(value))
    if marker in str(value) or marker in repr(value):
        raise AssertionError(f"secret marker escaped through {type(value).__name__}")
    if isinstance(value, dict):
        for key, item in value.items():
            _assert_no_marker(key, marker, seen)
            _assert_no_marker(item, marker, seen)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _assert_no_marker(item, marker, seen)


def _assert_secret_free_exception(test_case: unittest.TestCase, exc: BaseException, *markers: str) -> None:
    chain: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None and current not in chain:
        chain.append(current)
        current = current.__cause__ or current.__context__
    for item in chain:
        for marker in markers:
            _assert_no_marker(str(item), marker)
            _assert_no_marker(repr(item), marker)
            _assert_no_marker(getattr(item, "__dict__", {}), marker)
    tb = exc.__traceback__
    while tb is not None:
        if tb.tb_frame.f_globals.get("__name__", "").startswith("delivery_system."):
            for marker in markers:
                _assert_no_marker(tb.tb_frame.f_locals, marker)
        tb = tb.tb_next
    test_case.assertIsNone(exc.__cause__)
    test_case.assertIsNone(exc.__context__)


def _pem_private(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _pem_public(key):
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def _response(status: int, value: object) -> GitHubAppBootstrapResponse:
    return GitHubAppBootstrapResponse(
        status,
        {"Content-Type": "application/vnd.github+json"},
        json.dumps(value, separators=(",", ":")).encode("utf-8"),
    )


class FakeBootstrapTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []
        self.token_posts = 0

    def get_app(self, app_jwt: str) -> GitHubAppBootstrapResponse:
        self.calls.append(("app", app_jwt))
        return _response(200, {"id": APP_ID, "owner": {"login": "owner"}})

    def get_repository_installation(self, app_jwt: str, repository_identity: str) -> GitHubAppBootstrapResponse:
        self.calls.append(("installation", app_jwt, repository_identity))
        return _response(200, {
            "id": INSTALLATION_ID, "app_id": APP_ID, "account": {"login": "owner"},
            "suspended_at": None, "repository_selection": "selected",
            "permissions": {"metadata": "read", "issues": "write"},
        })

    def create_installation_token(self, app_jwt: str, installation_id: int, repository_id: int) -> GitHubAppBootstrapResponse:
        self.calls.append(("token", app_jwt, installation_id, repository_id))
        self.token_posts += 1
        return _response(201, {
            "token": TOKEN, "expires_at": "2026-09-07T13:00:00Z",
            "permissions": {"metadata": "read", "issues": "write"},
            "repository_selection": "selected",
        })

    def get_installation_repositories(self, installation_token: str) -> GitHubAppBootstrapResponse:
        self.calls.append(("scope", installation_token))
        return _response(200, {"total_count": 1, "repositories": [{"id": REPOSITORY_ID, "full_name": "owner/repo"}]})

    def get_repository(self, installation_token: str, repository_identity: str) -> GitHubAppBootstrapResponse:
        self.calls.append(("repository", installation_token, repository_identity))
        return _response(200, {
            "id": REPOSITORY_ID, "full_name": "owner/repo", "has_issues": True,
            "archived": False, "disabled": False, "private": True,
        })


def _environment(rsa_path: Path, ed_private_path: Path, ed_public_path: Path) -> dict[str, str]:
    return {
        "DELIVERY_SYSTEM_GITHUB_APP_ID": str(APP_ID),
        "DELIVERY_SYSTEM_GITHUB_APP_PRIVATE_KEY_PATH": str(rsa_path),
        "DELIVERY_SYSTEM_GITHUB_REPOSITORY": "OWNER/Repo",
        "DELIVERY_SYSTEM_GITHUB_REPOSITORY_ID": str(REPOSITORY_ID),
        "DELIVERY_SYSTEM_ATTESTATION_ISSUER_ID": "host-issuer",
        "DELIVERY_SYSTEM_ATTESTATION_KEY_ID": "host-key",
        "DELIVERY_SYSTEM_ATTESTATION_PRIVATE_KEY_PATH": str(ed_private_path),
        "DELIVERY_SYSTEM_ATTESTATION_PUBLIC_KEY_PATH": str(ed_public_path),
    }


class KeySourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.private = ed25519.Ed25519PrivateKey.generate()
        self.private_path = self.root / "private.pem"
        self.public_path = self.root / "public.pem"
        self.private_path.write_bytes(_pem_private(self.private))
        self.public_path.write_bytes(_pem_public(self.private.public_key()))

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_ed25519_private_and_public_sources_load_real_opened_files(self) -> None:
        with patch("pathlib.Path.open", side_effect=AssertionError("pathname Path.open is forbidden")):
            loaded_private = FileEd25519PrivateKeySource(self.private_path).load_ed25519_private_key()
            loaded_public = FileEd25519PublicKeySource(self.public_path).load_ed25519_public_key()
        self.assertEqual(
            loaded_private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()),
            self.private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()),
        )
        self.assertEqual(
            loaded_public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            self.private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
        )

    def test_sources_reject_relative_directory_oversized_and_wrong_types(self) -> None:
        with self.assertRaises(AttestationKeySourceError):
            FileEd25519PrivateKeySource("relative.pem")
        folder = self.root / "folder"
        folder.mkdir()
        with self.assertRaises(AttestationKeySourceError):
            FileEd25519PrivateKeySource(folder).load_ed25519_private_key()
        oversized = self.root / "oversized.pem"
        oversized.write_bytes(b"x" * (MAX_ED25519_KEY_BYTES + 1))
        with self.assertRaises(AttestationKeySourceError):
            FileEd25519PublicKeySource(oversized).load_ed25519_public_key()
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_path = self.root / "rsa.pem"
        rsa_path.write_bytes(_pem_private(rsa_key))
        with self.assertRaises(AttestationKeySourceError):
            FileEd25519PrivateKeySource(rsa_path).load_ed25519_private_key()
        with self.assertRaises(AttestationKeySourceError):
            FileEd25519PublicKeySource(self.private_path).load_ed25519_public_key()

    def test_sources_reject_malformed_and_encrypted_private_material_without_context(self) -> None:
        malformed = self.root / "malformed.pem"
        malformed.write_bytes(KEY_SOURCE_SENTINEL.encode("ascii"))
        with self.assertRaises(AttestationKeySourceError) as raised:
            FileEd25519PrivateKeySource(malformed).load_ed25519_private_key()
        _assert_secret_free_exception(self, raised.exception, KEY_SOURCE_SENTINEL)
        encrypted = self.root / "encrypted.pem"
        encrypted.write_bytes(self.private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"synthetic-password"),
        ))
        with self.assertRaises(AttestationKeySourceError):
            FileEd25519PrivateKeySource(encrypted).load_ed25519_private_key()

    def test_leaf_symlink_is_rejected_when_platform_supports_it(self) -> None:
        link = self.root / "link.pem"
        try:
            link.symlink_to(self.private_path)
        except (OSError, NotImplementedError):
            self.skipTest("platform cannot create a deterministic symlink")
        with self.assertRaises(AttestationKeySourceError):
            FileEd25519PrivateKeySource(link).load_ed25519_private_key()

    def test_opened_file_validator_runs_before_rsa_parse(self) -> None:
        validator_calls = []

        def reject(fd: int) -> None:
            validator_calls.append(fd)
            raise ValueError("opened object rejected")

        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        path = self.root / "rsa.pem"
        path.write_bytes(_pem_private(rsa_key))
        with patch("delivery_system.github_app_bootstrap.serialization.load_pem_private_key",
                   side_effect=AssertionError("RSA parser reached before validator")):
            with self.assertRaises(GitHubAppBootstrapError):
                FileGitHubAppPrivateKeySource(path, opened_file_validator=reject).load_rsa_private_key()
        self.assertEqual(len(validator_calls), 1)

    def test_opened_file_validator_runs_before_ed_private_parse(self) -> None:
        validator_calls = []

        def reject(fd: int) -> None:
            validator_calls.append(fd)
            raise ValueError("opened object rejected")

        path = self.root / "ed-private-validator.pem"
        path.write_bytes(_pem_private(self.private))
        with patch("delivery_system.attestation_key_source.serialization.load_pem_private_key",
                   side_effect=AssertionError("Ed25519 parser reached before validator")):
            with self.assertRaises(AttestationKeySourceError):
                FileEd25519PrivateKeySource(path, opened_file_validator=reject).load_ed25519_private_key()
        self.assertEqual(len(validator_calls), 1)


class ConfigurationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.env = _environment(root / "rsa.pem", root / "ed-private.pem", root / "ed-public.pem")

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_configuration_is_explicit_and_normalized(self) -> None:
        config = load_host_configuration(self.env)
        self.assertIsInstance(config, HostConfiguration)
        self.assertEqual(config.github_app.repository_identity, "owner/repo")
        self.assertNotIn("token", repr(config).lower())

    def test_configuration_rejects_installation_authority_and_bad_ids(self) -> None:
        for name, value in (
            ("DELIVERY_SYSTEM_GITHUB_APP_ID", "true"),
            ("DELIVERY_SYSTEM_GITHUB_APP_ID", "1.0"),
            ("DELIVERY_SYSTEM_GITHUB_APP_ID", str(MAX_GITHUB_ID + 1)),
            ("DELIVERY_SYSTEM_GITHUB_REPOSITORY_ID", "0"),
            ("DELIVERY_SYSTEM_GITHUB_REPOSITORY_ID", "-1"),
            ("DELIVERY_SYSTEM_GITHUB_REPOSITORY_ID", "1.0"),
            ("DELIVERY_SYSTEM_ATTESTATION_ISSUER_ID", "Bad_ID"),
        ):
            candidate = dict(self.env)
            candidate[name] = value
            with self.subTest(name=name, value=value), self.assertRaises(HostCompositionError):
                load_host_configuration(candidate)
        candidate = dict(self.env)
        candidate["DELIVERY_SYSTEM_GITHUB_INSTALLATION_ID"] = "54321"
        with self.assertRaises(HostCompositionError):
            load_host_configuration(candidate)

    def test_configuration_rejects_relative_and_empty_key_paths(self) -> None:
        for name, value in (
            ("DELIVERY_SYSTEM_GITHUB_APP_PRIVATE_KEY_PATH", "rsa.pem"),
            ("DELIVERY_SYSTEM_ATTESTATION_PRIVATE_KEY_PATH", " "),
            ("DELIVERY_SYSTEM_ATTESTATION_PUBLIC_KEY_PATH", "public.pem"),
        ):
            candidate = dict(self.env)
            candidate[name] = value
            with self.subTest(name=name), self.assertRaises(HostCompositionError):
                load_host_configuration(candidate)


class CompositionTests(unittest.TestCase):
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

    def _compose(self, transport=None, instance_factory=None, environment=None):
        return compose_write_enabled_host(
            self.context,
            environment=environment or self.environment,
            bootstrap_transport=transport or FakeBootstrapTransport(),
            clock=lambda: NOW,
            credential_instance_id_factory=instance_factory,
            nonce_factory=lambda: "nonce-" + "a" * 32,
        )

    def _composition_rejects_parent_swap(self, role: str, target_bytes: bytes, *, expected_posts: int) -> None:
        workspace = Path(self.workspace.name)
        keys = Path(self.keys.name)
        safe_parent = keys / ("safe-" + role.replace("DELIVERY_SYSTEM_", "").lower())
        race_parent = keys / ("race-" + role.replace("DELIVERY_SYSTEM_", "").lower())
        safe_parent.mkdir()
        race_parent.symlink_to(safe_parent, target_is_directory=True)
        workspace_target = workspace / "race-key.pem"
        workspace_target.write_bytes(target_bytes)
        candidate = dict(self.environment)
        candidate[role] = str(race_parent / workspace_target.name)
        original = __import__("delivery_system.host_composition", fromlist=["_validate_external_key_paths"])._validate_external_key_paths

        def validate_then_swap(context, config):
            original(context, config)
            race_parent.unlink()
            race_parent.symlink_to(workspace, target_is_directory=True)

        transport = FakeBootstrapTransport()
        try:
            with patch("delivery_system.host_composition._validate_external_key_paths", validate_then_swap):
                with self.assertRaises(HostCompositionError):
                    self._compose(transport, environment=candidate)
        finally:
            if race_parent.is_symlink() or race_parent.exists():
                race_parent.unlink()
        self.assertEqual(transport.token_posts, expected_posts)
        if expected_posts == 0:
            self.assertEqual(transport.calls, [])

    def test_rsa_parent_topology_swap_rejected_before_jwt_or_network(self) -> None:
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._composition_rejects_parent_swap(
            "DELIVERY_SYSTEM_GITHUB_APP_PRIVATE_KEY_PATH",
            _pem_private(rsa_key),
            expected_posts=0,
        )

    def test_ed_private_parent_topology_swap_rejected_after_acquire(self) -> None:
        ed_private = ed25519.Ed25519PrivateKey.generate()
        self._composition_rejects_parent_swap(
            "DELIVERY_SYSTEM_ATTESTATION_PRIVATE_KEY_PATH",
            _pem_private(ed_private),
            expected_posts=1,
        )

    def test_ed_public_parent_topology_swap_rejected_after_acquire(self) -> None:
        ed_private = ed25519.Ed25519PrivateKey.generate()
        self._composition_rejects_parent_swap(
            "DELIVERY_SYSTEM_ATTESTATION_PUBLIC_KEY_PATH",
            _pem_public(ed_private.public_key()),
            expected_posts=1,
        )

    def test_explicit_profile_composes_actual_h3_lease_attestation_and_runtime(self) -> None:
        transport = FakeBootstrapTransport()
        instance = str(uuid.uuid4())
        with patch.object(type(self.context), "ensure_store_ready", lambda self, **kwargs: Path(self.state_path).parent.mkdir(parents=True, exist_ok=True)):
            composition = self._compose(transport, lambda: instance)
        self.assertIs(type(composition), HostComposition)
        self.assertIs(type(composition.lease), GitHubAppInstallationCredentialLease)
        self.assertIs(type(composition.signer), Ed25519HostSigner)
        self.assertIs(type(composition.verifier), Ed25519ProofVerifier)
        self.assertIs(type(composition.registry), TrustedEd25519IssuerKeyRegistry)
        self.assertIs(type(composition.approval_authority_service), RuntimeApprovalAuthorityService)
        self.assertIs(composition.approval_authority_service._host_credential_lease, composition.lease)
        self.assertIs(composition.execution_store.runtime_service, composition.approval_authority_service)
        self.assertEqual(composition.lease._snapshot().credential_instance_id, instance)
        self.assertEqual(transport.token_posts, 1)
        server = composition.create_server()
        self.assertIsNotNone(server)

    def test_composition_rejects_workspace_controlled_paths_before_acquire(self) -> None:
        for name in (
            "DELIVERY_SYSTEM_GITHUB_APP_PRIVATE_KEY_PATH",
            "DELIVERY_SYSTEM_ATTESTATION_PRIVATE_KEY_PATH",
            "DELIVERY_SYSTEM_ATTESTATION_PUBLIC_KEY_PATH",
        ):
            transport = FakeBootstrapTransport()
            candidate = dict(self.environment)
            candidate[name] = str(Path(self.context.normalized_workspace_root) / (name + ".pem"))
            with self.subTest(name=name), self.assertRaises(HostCompositionError):
                self._compose(transport, environment=candidate)
            self.assertEqual(transport.calls, [])

    def test_composition_rejects_reused_key_role_path_before_acquire(self) -> None:
        for names in (
            ("DELIVERY_SYSTEM_GITHUB_APP_PRIVATE_KEY_PATH", "DELIVERY_SYSTEM_ATTESTATION_PRIVATE_KEY_PATH"),
            ("DELIVERY_SYSTEM_GITHUB_APP_PRIVATE_KEY_PATH", "DELIVERY_SYSTEM_ATTESTATION_PUBLIC_KEY_PATH"),
            ("DELIVERY_SYSTEM_ATTESTATION_PRIVATE_KEY_PATH", "DELIVERY_SYSTEM_ATTESTATION_PUBLIC_KEY_PATH"),
        ):
            transport = FakeBootstrapTransport()
            candidate = dict(self.environment)
            candidate[names[1]] = candidate[names[0]]
            with self.subTest(names=names), self.assertRaises(HostCompositionError):
                self._compose(transport, environment=candidate)
            self.assertEqual(transport.calls, [])

    def test_ed25519_pair_mismatch_fails_without_publishing_server(self) -> None:
        other = ed25519.Ed25519PrivateKey.generate()
        Path(self.ed_public_path).write_bytes(_pem_public(other.public_key()))
        transport = FakeBootstrapTransport()
        with patch.object(type(self.context), "ensure_store_ready", lambda self, **kwargs: Path(self.state_path).parent.mkdir(parents=True, exist_ok=True)):
            with self.assertRaises(HostCompositionError):
                self._compose(transport, lambda: str(uuid.uuid4()))
        self.assertEqual(transport.token_posts, 1)

    def test_two_compositions_acquire_once_each_and_reserve_distinct_instances(self) -> None:
        first_transport = FakeBootstrapTransport()
        second_transport = FakeBootstrapTransport()
        first_id = str(uuid.uuid4())
        second_id = str(uuid.uuid4())
        factories = iter((first_id, second_id))
        with patch.object(type(self.context), "ensure_store_ready", lambda self, **kwargs: Path(self.state_path).parent.mkdir(parents=True, exist_ok=True)):
            first = self._compose(first_transport, lambda: next(factories))
            second = self._compose(second_transport, lambda: next(factories))
        self.assertIsNot(first.lease, second.lease)
        self.assertNotEqual(first.lease._snapshot().credential_instance_id, second.lease._snapshot().credential_instance_id)
        self.assertEqual(first_transport.token_posts, 1)
        self.assertEqual(second_transport.token_posts, 1)
        from mcp_server.server import create_server
        with self.assertRaises(ValueError):
            create_server(
                second.context,
                second.store,
                second.driver,
                second.trust_context,
                first.approval_authority_service,
                second.execution_store,
            )

    def test_failed_explicit_composition_does_not_fallback_to_disabled_server(self) -> None:
        with self.assertRaises(HostCompositionError):
            compose_write_enabled_host(self.context, environment={})

    def test_environment_token_names_are_ignored(self) -> None:
        candidate = dict(self.environment)
        candidate["GH_TOKEN"] = "SYNTHETIC_FALLBACK_TOKEN"
        candidate["GITHUB_TOKEN"] = "SYNTHETIC_FALLBACK_TOKEN_2"
        transport = FakeBootstrapTransport()
        with patch.object(type(self.context), "ensure_store_ready", lambda self, **kwargs: Path(self.state_path).parent.mkdir(parents=True, exist_ok=True)):
            composition = self._compose(transport, lambda: str(uuid.uuid4()), candidate)
        self.assertIs(type(composition.lease), GitHubAppInstallationCredentialLease)
        self.assertEqual(transport.token_posts, 1)

    def test_composition_public_errors_discard_secret_bearing_internal_context(self) -> None:
        class BrokenSource:
            def load_rsa_private_key(self):
                raise ValueError(COMPOSITION_SENTINEL)

        with self.assertRaises(HostCompositionError) as raised:
            compose_write_enabled_host(self.context, environment=self.environment, private_key_source=BrokenSource())
        _assert_secret_free_exception(self, raised.exception, COMPOSITION_SENTINEL)

    def test_composition_bundle_cannot_be_copied_or_serialized(self) -> None:
        with patch.object(type(self.context), "ensure_store_ready", lambda self, **kwargs: Path(self.state_path).parent.mkdir(parents=True, exist_ok=True)):
            composition = self._compose(FakeBootstrapTransport(), lambda: str(uuid.uuid4()))
        with self.assertRaises(HostCompositionError):
            copy.copy(composition)
        with self.assertRaises(HostCompositionError):
            copy.deepcopy(composition)
        with self.assertRaises(HostCompositionError):
            pickle.dumps(composition)


class ServerProfileTests(unittest.TestCase):
    def test_cli_has_explicit_profile_and_no_secret_value_options(self) -> None:
        import mcp_server.server as server_module
        with patch.object(server_module, "create_server") as create_server:
            create_server.return_value.run.return_value = None
            with patch.object(server_module, "SQLitePreviewStore", return_value=object()):
                with patch.object(server_module.RuntimeContext, "from_workspace_root", return_value=object()):
                    with patch("builtins.print"):
                        server_module.main(["--workspace-root", "C:\\workspace"])
        parser_text = Path(server_module.__file__).read_text(encoding="utf-8")
        self.assertIn('"--host-profile"', parser_text)
        self.assertNotIn("--private-key", parser_text)
        self.assertNotIn("--jwt", parser_text)
        self.assertNotIn("--installation-token", parser_text)
        self.assertNotIn("--pat", parser_text)

    def test_default_main_does_not_load_host_configuration(self) -> None:
        import mcp_server.server as server_module
        with patch("delivery_system.host_composition.load_host_configuration", side_effect=AssertionError("default inspected Host env")):
            with patch.object(server_module, "create_server") as create_server:
                create_server.return_value.run.return_value = None
                with patch.object(server_module, "SQLitePreviewStore", return_value=object()):
                    with patch.object(server_module.RuntimeContext, "from_workspace_root", return_value=object()):
                        server_module.main(["--workspace-root", "C:\\workspace"])
        create_server.assert_called_once()

    def test_explicit_profile_requires_configuration_and_does_not_fallback(self) -> None:
        import mcp_server.server as server_module
        with patch.object(server_module.RuntimeContext, "from_workspace_root", return_value=object()):
            with patch("delivery_system.host_composition.compose_write_enabled_host", side_effect=HostCompositionError("host_composition_failed")) as compose:
                with self.assertRaises(HostCompositionError):
                    server_module.main(["--workspace-root", "C:\\workspace", "--host-profile", "github-app-write"])
        compose.assert_called_once()

    def test_explicit_profile_without_workspace_fails_before_composition(self) -> None:
        import mcp_server.server as server_module
        with patch("delivery_system.host_composition.compose_write_enabled_host") as compose:
            with self.assertRaises(SystemExit):
                server_module.main(["--host-profile", "github-app-write"])
        compose.assert_not_called()


if __name__ == "__main__":
    unittest.main()
