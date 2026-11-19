from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tests.integration.github_apply_harness import (
    EvidenceError,
    HarnessConfigurationError,
    LIVE_OPT_IN_VARIABLE,
    PRODUCTION_REPOSITORY,
    SANDBOX_TARGETS,
    build_evidence,
    classify_execution,
    evidence_directory,
    require_live_opt_in,
    run_bounded_subprocess,
    validate_host_configuration,
    validate_remote_scope,
    verify_checkout_provenance,
    verify_evidence_manifest,
    write_evidence,
)


class GitHubApplyHarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.env = self.valid_environment()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def valid_environment(self) -> dict[str, str]:
        target = SANDBOX_TARGETS[0]
        value = {
            "DELIVERY_SYSTEM_GITHUB_APP_ID": target.app_id,
            "DELIVERY_SYSTEM_GITHUB_REPOSITORY": target.repository,
            "DELIVERY_SYSTEM_GITHUB_REPOSITORY_ID": target.repository_id,
            "DELIVERY_SYSTEM_ATTESTATION_ISSUER_ID": "attestation-issuer",
            "DELIVERY_SYSTEM_ATTESTATION_KEY_ID": "attestation-key",
            "DELIVERY_SYSTEM_AUTHORITY_BINDING_ISSUER_ID": "binding-issuer",
            "DELIVERY_SYSTEM_AUTHORITY_BINDING_ACTIVE_KEY_ID": "binding-key",
            "DELIVERY_SYSTEM_REVOCATION_PROVIDER_URL": "https://revocation.example.test/status",
            "DELIVERY_SYSTEM_REVOCATION_TIMEOUT_MS": "1500",
        }
        for name in (
            "DELIVERY_SYSTEM_GITHUB_APP_PRIVATE_KEY_PATH",
            "DELIVERY_SYSTEM_ATTESTATION_PRIVATE_KEY_PATH",
            "DELIVERY_SYSTEM_ATTESTATION_PUBLIC_KEY_PATH",
            "DELIVERY_SYSTEM_ATTESTATION_TRUSTED_KEYS_PATH",
            "DELIVERY_SYSTEM_AUTHORITY_BINDING_PRIVATE_KEY_PATH",
            "DELIVERY_SYSTEM_AUTHORITY_BINDING_PUBLIC_KEY_PATH",
            "DELIVERY_SYSTEM_AUTHORITY_BINDING_TRUSTED_KEYS_PATH",
        ):
            path = self.root / (name + ".material")
            path.write_bytes(b"placeholder-protected-material")
            value[name] = str(path)
        return value

    def configuration(self):
        return validate_host_configuration(self.env)

    def test_live_gate_requires_explicit_exact_opt_in(self) -> None:
        for value in (None, "true", "yes", "0", " 1"):
            environment = {} if value is None else {LIVE_OPT_IN_VARIABLE: value}
            with self.subTest(value=value), self.assertRaisesRegex(HarnessConfigurationError, "live_opt_in_required"):
                require_live_opt_in(environment)
        require_live_opt_in({LIVE_OPT_IN_VARIABLE: "1"})

    def test_missing_required_configuration_is_rejected(self) -> None:
        for key in (
            "DELIVERY_SYSTEM_GITHUB_APP_ID",
            "DELIVERY_SYSTEM_GITHUB_REPOSITORY",
            "DELIVERY_SYSTEM_GITHUB_REPOSITORY_ID",
            "DELIVERY_SYSTEM_ATTESTATION_ISSUER_ID",
            "DELIVERY_SYSTEM_ATTESTATION_KEY_ID",
            "DELIVERY_SYSTEM_AUTHORITY_BINDING_ISSUER_ID",
            "DELIVERY_SYSTEM_AUTHORITY_BINDING_ACTIVE_KEY_ID",
            "DELIVERY_SYSTEM_REVOCATION_PROVIDER_URL",
            "DELIVERY_SYSTEM_REVOCATION_TIMEOUT_MS",
            "DELIVERY_SYSTEM_GITHUB_APP_PRIVATE_KEY_PATH",
        ):
            environment = dict(self.env)
            environment.pop(key)
            with self.subTest(key=key), self.assertRaisesRegex(HarnessConfigurationError, "configuration_invalid"):
                validate_host_configuration(environment)

    def test_wrong_repository_or_app_identity_is_rejected(self) -> None:
        for key, value in (
            ("DELIVERY_SYSTEM_GITHUB_REPOSITORY", "zevsol/other-sandbox"),
            ("DELIVERY_SYSTEM_GITHUB_APP_ID", "123456"),
        ):
            environment = dict(self.env)
            environment[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(HarnessConfigurationError, "configuration_invalid"):
                validate_host_configuration(environment)

    def test_production_repository_is_rejected(self) -> None:
        self.env["DELIVERY_SYSTEM_GITHUB_REPOSITORY"] = PRODUCTION_REPOSITORY
        self.env["DELIVERY_SYSTEM_GITHUB_REPOSITORY_ID"] = "123"
        with self.assertRaisesRegex(HarnessConfigurationError, "configuration_invalid"):
            validate_host_configuration(self.env)

    def test_installation_id_must_be_discovered_not_configured(self) -> None:
        for value in ("161812475", ""):
            self.env["DELIVERY_SYSTEM_GITHUB_INSTALLATION_ID"] = value
            with self.subTest(value=value), self.assertRaisesRegex(HarnessConfigurationError, "configuration_invalid"):
                self.configuration()
        self.env.pop("DELIVERY_SYSTEM_GITHUB_INSTALLATION_ID")

    def test_missing_protected_key_or_trust_material_is_rejected_without_reading(self) -> None:
        names = (
            "DELIVERY_SYSTEM_GITHUB_APP_PRIVATE_KEY_PATH",
            "DELIVERY_SYSTEM_ATTESTATION_PRIVATE_KEY_PATH",
            "DELIVERY_SYSTEM_ATTESTATION_PUBLIC_KEY_PATH",
            "DELIVERY_SYSTEM_ATTESTATION_TRUSTED_KEYS_PATH",
            "DELIVERY_SYSTEM_AUTHORITY_BINDING_PRIVATE_KEY_PATH",
            "DELIVERY_SYSTEM_AUTHORITY_BINDING_PUBLIC_KEY_PATH",
            "DELIVERY_SYSTEM_AUTHORITY_BINDING_TRUSTED_KEYS_PATH",
        )
        for name in names:
            with self.subTest(name=name):
                path = Path(self.env[name])
                path.unlink()
                with self.assertRaisesRegex(HarnessConfigurationError, "configuration_invalid"):
                    self.configuration()
                path.write_bytes(b"restored-test-material")

    def test_protected_file_references_must_be_absolute(self) -> None:
        self.env["DELIVERY_SYSTEM_GITHUB_APP_PRIVATE_KEY_PATH"] = "relative-key-file"
        with self.assertRaisesRegex(HarnessConfigurationError, "configuration_invalid"):
            self.configuration()

    def test_revocation_endpoint_requires_safe_https_url(self) -> None:
        for value in ("http://revocation.example.test", "https://user:pass@example.test/a", "https://example.test/#fragment"):
            with self.subTest(value=value):
                self.env["DELIVERY_SYSTEM_REVOCATION_PROVIDER_URL"] = value
                with self.assertRaisesRegex(HarnessConfigurationError, "configuration_invalid"):
                    self.configuration()

    def test_protected_file_contents_are_not_in_configuration_representation(self) -> None:
        sentinel = "PRIVATE_KEY_CONTENT_SENTINEL"
        path = Path(self.env["DELIVERY_SYSTEM_GITHUB_APP_PRIVATE_KEY_PATH"])
        path.write_text(sentinel, encoding="utf-8")
        config = self.configuration()
        self.assertNotIn(sentinel, repr(config))
        self.assertEqual(path.stat().st_size, len(sentinel))

    def test_wrong_numeric_repository_id_is_rejected(self) -> None:
        config = self.configuration()
        with self.assertRaisesRegex(HarnessConfigurationError, "scope_invalid"):
            validate_remote_scope(
                config, app_id=config.app_id, installation_id="101",
                repository=config.repository, repository_id="999999",
                installed_repositories=[config.repository], permissions={"issues": "write"},
            )

    def test_wrong_app_id_or_untrusted_installation_id_is_rejected(self) -> None:
        config = self.configuration()
        for app_id, installation_id in (("123", "101"), (config.app_id, "not-discovered")):
            with self.subTest(app_id=app_id, installation_id=installation_id), self.assertRaisesRegex(HarnessConfigurationError, "scope_invalid"):
                validate_remote_scope(
                    config, app_id=app_id, installation_id=installation_id,
                    repository=config.repository, repository_id=config.repository_id,
                    installed_repositories=[config.repository], permissions={"issues": "write"},
                )

    def test_wrong_remote_repository_identity_is_rejected(self) -> None:
        config = self.configuration()
        with self.assertRaisesRegex(HarnessConfigurationError, "scope_invalid"):
            validate_remote_scope(
                config, app_id=config.app_id, installation_id="101",
                repository="zevsol/other", repository_id=config.repository_id,
                installed_repositories=["zevsol/other"], permissions={"issues": "write"},
            )

    def test_broader_installation_repository_scope_is_rejected(self) -> None:
        config = self.configuration()
        with self.assertRaisesRegex(HarnessConfigurationError, "scope_invalid"):
            validate_remote_scope(
                config, app_id=config.app_id, installation_id="101",
                repository=config.repository, repository_id=config.repository_id,
                installed_repositories=[config.repository, "zevsol/other"],
                permissions={"issues": "write"},
            )

    def test_missing_issues_write_permission_is_rejected(self) -> None:
        config = self.configuration()
        for permissions in ({}, {"issues": "read"}, {"issues": "write", "contents": "write"}):
            with self.subTest(permissions=permissions), self.assertRaisesRegex(HarnessConfigurationError, "permission_missing"):
                validate_remote_scope(
                    config, app_id=config.app_id, installation_id="101",
                    repository=config.repository, repository_id=config.repository_id,
                    installed_repositories=[config.repository], permissions=permissions,
                )

    def test_valid_exact_single_repository_scope_is_accepted(self) -> None:
        config = self.configuration()
        validate_remote_scope(
            config, app_id=config.app_id, installation_id="101",
            repository=config.repository, repository_id=config.repository_id,
            installed_repositories=[config.repository], permissions={"issues": "write"},
        )

    def test_checkout_provenance_matches_exact_worktree_commit(self) -> None:
        checkout = Path(__file__).resolve().parents[2]
        expected = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=checkout, check=True,
            capture_output=True, text=True,
        ).stdout.strip()
        self.assertEqual(verify_checkout_provenance(checkout, expected), expected)
        with self.assertRaisesRegex(HarnessConfigurationError, "provenance_invalid"):
            verify_checkout_provenance(checkout, "0" * 40)

    def test_provenance_rejects_non_git_checkout(self) -> None:
        with self.assertRaisesRegex(HarnessConfigurationError, "provenance_invalid"):
            verify_checkout_provenance(self.root, "0" * 40)

    def test_provenance_rejects_wrong_origin(self) -> None:
        outputs = [
            str(Path(__file__).resolve().parents[2]),
            "0" * 40,
            "https://github.com/zevsol/unrelated.git",
        ]

        def fake_run(*args, **kwargs):
            return subprocess.CompletedProcess(args[0], 0, outputs.pop(0), "")

        checkout = Path(__file__).resolve().parents[2]
        with self.assertRaisesRegex(HarnessConfigurationError, "provenance_invalid"):
            verify_checkout_provenance(checkout, "0" * 40, run=fake_run)

    def test_subprocess_timeout_terminates_child_and_does_not_retry(self) -> None:
        started: list[subprocess.Popen[bytes]] = []

        def start(*args, **kwargs):
            process = subprocess.Popen(*args, **kwargs)
            started.append(process)
            return process

        result = run_bounded_subprocess(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=self.root, timeout_seconds=0.1, popen=start,
        )
        self.assertEqual(result.state, "timed_out")
        self.assertTrue(result.timed_out)
        self.assertFalse(result.retry_allowed)
        self.assertEqual(len(started), 1)
        self.assertIsNotNone(started[0].poll())

    def test_subprocess_uses_no_shell_and_discards_output(self) -> None:
        observed = {}

        class FakeProcess:
            def wait(self, timeout=None):
                return 0

        def fake_popen(arguments, **kwargs):
            observed.update(kwargs)
            return FakeProcess()

        result = run_bounded_subprocess(["safe-command"], cwd=self.root, popen=fake_popen)
        self.assertEqual(result.state, "succeeded")
        self.assertIs(observed["shell"], False)
        self.assertIs(observed["stdout"], subprocess.DEVNULL)
        self.assertIs(observed["stderr"], subprocess.DEVNULL)

    def test_ambiguous_execution_is_not_retried(self) -> None:
        classification = classify_execution("submitted", remote_request_started=True)
        self.assertEqual(classification.outcome, "ambiguous")
        self.assertFalse(classification.retry_allowed)
        self.assertEqual(classify_execution("not_started", remote_request_started=False).outcome, "not_started")
        self.assertEqual(classify_execution("confirmed", remote_request_started=True).outcome, "confirmed")

    def test_evidence_is_closed_sanitized_and_counts_operations(self) -> None:
        evidence = build_evidence(
            repository=SANDBOX_TARGETS[0].repository,
            repository_id=SANDBOX_TARGETS[0].repository_id,
            operations=[
                {"kind": "create_issue", "state": "confirmed"},
                {"kind": "add_dependency", "state": "not_started"},
            ],
        )
        encoded = json.dumps(evidence)
        self.assertEqual(evidence["operation_counts"]["confirmed"], 1)
        self.assertEqual(evidence["operation_counts"]["not_started"], 1)
        self.assertEqual(evidence["retry_attempts"], 0)
        self.assertNotIn("title", encoded)
        self.assertNotIn("body", encoded)
        self.assertNotIn("token", encoded.lower())

    def test_secret_bearing_or_unrecognized_evidence_is_rejected(self) -> None:
        evidence = build_evidence(
            repository=SANDBOX_TARGETS[0].repository,
            repository_id=SANDBOX_TARGETS[0].repository_id,
            operations=[],
        )
        evidence["credential"] = "SENTINEL_SECRET"
        with self.assertRaisesRegex(EvidenceError, "evidence_invalid"):
            write_evidence(self.root / "bad", evidence)
        evidence.pop("credential")
        evidence["operations"] = [{"kind": "create_issue", "state": "confirmed", "body": "SENTINEL_SECRET"}]
        with self.assertRaisesRegex(EvidenceError, "evidence_invalid"):
            write_evidence(self.root / "bad2", evidence)
        self.assertFalse((evidence_directory(self.root / "bad") / "github-apply-report.json").exists())

    def test_evidence_sha256_manifest_verifies_and_detects_tampering(self) -> None:
        evidence = build_evidence(
            repository=SANDBOX_TARGETS[0].repository,
            repository_id=SANDBOX_TARGETS[0].repository_id,
            operations=[{"kind": "create_issue", "state": "not_started"}],
        )
        directory = self.root / "evidence"
        manifest = write_evidence(directory, evidence)
        directory = evidence_directory(directory)
        self.assertTrue(verify_evidence_manifest(directory))
        payload = (directory / "github-apply-report.json").read_bytes()
        self.assertEqual(hashlib.sha256(payload).hexdigest(), manifest["files"][0]["sha256"])
        (directory / "github-apply-report.json").write_bytes(payload + b" ")
        self.assertFalse(verify_evidence_manifest(directory))

    def test_evidence_creation_collision_preserves_existing_file(self) -> None:
        evidence = build_evidence(
            repository=SANDBOX_TARGETS[0].repository,
            repository_id=SANDBOX_TARGETS[0].repository_id,
            operations=[],
        )
        directory = evidence_directory(self.root / "collision")
        directory.mkdir(parents=True)
        report = directory / "github-apply-report.json"
        report.write_text("existing", encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "evidence_invalid"):
            write_evidence(self.root / "collision", evidence)
        self.assertEqual(report.read_text(encoding="utf-8"), "existing")

    def test_evidence_partial_write_is_cleaned_up(self) -> None:
        evidence = build_evidence(
            repository=SANDBOX_TARGETS[0].repository,
            repository_id=SANDBOX_TARGETS[0].repository_id,
            operations=[],
        )
        original_open = Path.open

        def fail_manifest(path, *args, **kwargs):
            if path.name == "evidence-manifest.json":
                raise OSError("synthetic failure")
            return original_open(path, *args, **kwargs)

        with mock.patch.object(Path, "open", fail_manifest):
            with self.assertRaisesRegex(EvidenceError, "evidence_invalid"):
                write_evidence(self.root, evidence)
        self.assertFalse((evidence_directory(self.root) / "github-apply-report.json").exists())

    def test_evidence_flush_failure_removes_partial_report(self) -> None:
        evidence = build_evidence(
            repository=SANDBOX_TARGETS[0].repository,
            repository_id=SANDBOX_TARGETS[0].repository_id,
            operations=[],
        )
        with mock.patch("tests.integration.github_apply_harness.os.fsync", side_effect=OSError("disk failure")):
            with self.assertRaisesRegex(EvidenceError, "evidence_invalid"):
                write_evidence(self.root, evidence)
        directory = evidence_directory(self.root)
        self.assertFalse((directory / "github-apply-report.json").exists())
        self.assertFalse((directory / "evidence-manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
