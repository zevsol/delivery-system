from __future__ import annotations

import asyncio
from dataclasses import FrozenInstanceError, fields
import logging
import unittest
from unittest.mock import patch

from mcp import Client

from delivery_system.public_error_contract import (
    PUBLIC_ERROR_REGISTRY,
    PublicErrorCategory,
    PublicToolError,
    RecoveryAction,
    RetryDisposition,
    descriptor_for_code,
)
from mcp_server.server import DeliverySystemMCPServer, create_server
from delivery_system.drivers.contract import DriverError
from delivery_system.runtime import StorePreflightError


EXPECTED_CODES = frozenset({
    "application_authority_id_invalid",
    "application_authority_rejected",
    "application_binding_conflict",
    "application_id_invalid",
    "application_not_found",
    "application_reconciliation_boundary_unavailable",
    "application_reconciliation_state_invalid",
    "application_receipt_integrity_invalid",
    "application_receipt_not_found",
    "application_replay_validation_required",
    "approval_audit_ambiguous",
    "approval_binding_conflict",
    "approval_binding_mismatch",
    "approval_command_invalid",
    "approval_invalid",
    "approval_not_found",
    "approval_runtime_boundary_invalid",
    "approval_stale",
    "approval_workspace_mismatch",
    "attempt_integrity_invalid",
    "attestation_service_unavailable",
    "audit_context_stale",
    "audit_not_approval_eligible",
    "audit_not_found",
    "audit_stale",
    "authority_issuance_requires_recovery",
    "context_stale",
    "credential_binding_mismatch",
    "credential_capability_insufficient",
    "credential_expired",
    "driver_trust_context_mismatch",
    "input_invalid",
    "internal_error",
    "operation_receipt_not_found",
    "preview_digest_mismatch",
    "preview_not_found",
    "preview_stale",
    "reconciliation_operation_unsupported",
    "receipt_integrity_invalid",
    "remote_observation_unavailable",
    "sealed_preview_schema_invalid",
    "sealed_preview_unavailable",
    "state_integrity_invalid",
    "store_corrupt",
    "store_unavailable",
    "verified_attestation_context_unverified",
    "workspace_identity_unavailable",
    "write_execution_boundary_unavailable",
    "write_executor_required",
})

META_KEY = "com.delivery-system/public-tool-error"


class PublicErrorContractTests(unittest.TestCase):
    @staticmethod
    def run_async(coroutine):
        return asyncio.run(coroutine)

    def _call(self, server, name, arguments):
        async def exercise():
            async with Client(server, raise_exceptions=False) as client:
                return await client.call_tool(name, arguments)

        return self.run_async(exercise())

    def test_public_tool_error_has_exact_four_fields(self):
        self.assertEqual(
            tuple(field.name for field in fields(PublicToolError)),
            ("code", "category", "retry_disposition", "recovery_action"),
        )

    def test_closed_enums_and_exact_registry(self):
        self.assertEqual(
            {value.value for value in PublicErrorCategory},
            {
                "INPUT_VALIDATION", "DOMAIN_BUSINESS", "CURRENTNESS_STALENESS",
                "IDENTITY_BINDING", "PERSISTENCE_WORKSPACE", "AUTHORITY_CREDENTIAL",
                "TRANSPORT_HOST",
            },
        )
        self.assertEqual({value.value for value in RetryDisposition}, {"NO_AUTOMATIC_RETRY"})
        self.assertEqual(
            {value.value for value in RecoveryAction},
            {
                "CORRECT_CALLER_INPUT",
                "ESTABLISH_CURRENT_AUDIT_CONTEXT",
                "ESTABLISH_CURRENT_PREVIEW_THEN_RESTART_CEREMONY",
                "RESTART_APPROVAL_CEREMONY",
                "INVESTIGATE_APPROVAL_STATE",
                "RESTORE_WORKSPACE_CONTEXT",
                "REACQUIRE_CURRENT_CREDENTIAL",
                "REESTABLISH_APPLICATION_AUTHORITY_AFTER_CURRENT_APPROVAL",
                "INVESTIGATE_DURABLE_STATE",
                "ESCALATE_TO_HOST_OPERATOR",
            },
        )
        self.assertEqual(len(PUBLIC_ERROR_REGISTRY), 49)
        self.assertEqual(set(PUBLIC_ERROR_REGISTRY), EXPECTED_CODES)
        for code, descriptor in PUBLIC_ERROR_REGISTRY.items():
            with self.subTest(code=code):
                self.assertEqual(descriptor.code, code)
                self.assertIsInstance(descriptor.category, PublicErrorCategory)
                self.assertEqual(descriptor.retry_disposition, RetryDisposition.NO_AUTOMATIC_RETRY)
                self.assertIsInstance(descriptor.recovery_action, RecoveryAction)
                self.assertIsInstance(descriptor.safe_text, str)
                self.assertNotIn("{", descriptor.safe_text)
                self.assertNotIn("}", descriptor.safe_text)

    def test_registry_is_immutable_and_unknown_codes_fail_closed(self):
        with self.assertRaises(TypeError):
            PUBLIC_ERROR_REGISTRY["new_code"] = descriptor_for_code("internal_error")
        self.assertEqual(descriptor_for_code("unregistered_code").code, "internal_error")

    def test_public_error_and_registry_descriptor_are_frozen(self):
        public_error = descriptor_for_code("internal_error").public_error()
        with self.assertRaises(FrozenInstanceError):
            public_error.code = "credential_expired"
        descriptor = descriptor_for_code("internal_error")
        with self.assertRaises(FrozenInstanceError):
            descriptor.code = "credential_expired"

    def test_representative_descriptors(self):
        expected = {
            "input_invalid": ("INPUT_VALIDATION", "CORRECT_CALLER_INPUT"),
            "application_id_invalid": ("INPUT_VALIDATION", "CORRECT_CALLER_INPUT"),
            "workspace_identity_unavailable": ("PERSISTENCE_WORKSPACE", "RESTORE_WORKSPACE_CONTEXT"),
            "preview_stale": ("CURRENTNESS_STALENESS", "ESTABLISH_CURRENT_PREVIEW_THEN_RESTART_CEREMONY"),
            "audit_not_found": ("CURRENTNESS_STALENESS", "ESTABLISH_CURRENT_AUDIT_CONTEXT"),
            "audit_not_approval_eligible": (
                "DOMAIN_BUSINESS", "ESTABLISH_CURRENT_PREVIEW_THEN_RESTART_CEREMONY",
            ),
            "approval_audit_ambiguous": ("IDENTITY_BINDING", "INVESTIGATE_APPROVAL_STATE"),
            "approval_binding_conflict": ("IDENTITY_BINDING", "INVESTIGATE_APPROVAL_STATE"),
            "approval_binding_mismatch": ("IDENTITY_BINDING", "INVESTIGATE_APPROVAL_STATE"),
            "approval_invalid": ("DOMAIN_BUSINESS", "INVESTIGATE_APPROVAL_STATE"),
            "approval_stale": ("CURRENTNESS_STALENESS", "RESTART_APPROVAL_CEREMONY"),
            "credential_expired": ("AUTHORITY_CREDENTIAL", "REACQUIRE_CURRENT_CREDENTIAL"),
            "store_corrupt": ("PERSISTENCE_WORKSPACE", "INVESTIGATE_DURABLE_STATE"),
            "state_integrity_invalid": ("PERSISTENCE_WORKSPACE", "INVESTIGATE_DURABLE_STATE"),
            "internal_error": ("TRANSPORT_HOST", "ESCALATE_TO_HOST_OPERATOR"),
        }
        for code, (category, action) in expected.items():
            with self.subTest(code=code):
                descriptor = PUBLIC_ERROR_REGISTRY[code]
                self.assertEqual(descriptor.category.value, category)
                self.assertEqual(descriptor.recovery_action.value, action)

    def test_known_error_has_four_field_meta_and_no_structured_content(self):
        result = self._call(
            create_server(),
            "delivery_get_application_status",
            {"payload": {"application_id": "invalid"}},
        )
        self.assertTrue(result.is_error)
        self.assertIsNone(result.structured_content)
        self.assertIn(META_KEY, result.meta)
        public_error = result.meta[META_KEY]
        self.assertEqual(
            set(public_error),
            {"code", "category", "retry_disposition", "recovery_action"},
        )
        self.assertEqual(public_error["code"], "application_id_invalid")
        self.assertEqual(public_error["category"], "INPUT_VALIDATION")
        self.assertEqual(public_error["retry_disposition"], "NO_AUTOMATIC_RETRY")
        self.assertEqual(public_error["recovery_action"], "CORRECT_CALLER_INPUT")
        self.assertEqual(
            result.content[0].text,
            descriptor_for_code("application_id_invalid").safe_text,
        )

    def test_generic_validation_maps_to_input_invalid(self):
        result = self._call(
            create_server(),
            "delivery_plan_preview",
            {"payload": {}},
        )
        self.assertTrue(result.is_error)
        self.assertEqual(result.meta[META_KEY]["code"], "input_invalid")
        self.assertIsNone(result.structured_content)

    def test_unexpected_exception_is_sanitized(self):
        server = DeliverySystemMCPServer("public-error-test")

        @server.tool(name="unexpected", structured_output=False)
        def unexpected():
            raise RuntimeError("FAKE_PATH fake-token-marker fake-http-body")

        result = self._call(server, "unexpected", {})
        self.assertTrue(result.is_error)
        self.assertEqual(result.meta[META_KEY]["code"], "internal_error")
        wire_text = result.content[0].text
        self.assertNotIn("FAKE_PATH", wire_text)
        self.assertNotIn("fake-token-marker", wire_text)
        self.assertNotIn("fake-http-body", wire_text)
        self.assertNotIn("FAKE_PATH", str(result.meta))
        self.assertNotIn("fake-token-marker", str(result.meta))
        self.assertNotIn("fake-http-body", str(result.meta))

    def test_audit_storage_and_commit_boundary_codes_remain_private(self):
        for internal_code in ("audit_persistence_failed", "audit_commit_boundary_required"):
            with self.subTest(internal_code=internal_code):
                server = DeliverySystemMCPServer("audit-error-contract-test")

                @server.tool(name="delivery_record_audit", structured_output=False)
                def fail_audit():
                    raise ValueError(internal_code)

                with self.assertLogs("mcp_server.read_only_contracts", level="ERROR") as captured:
                    result = self._call(server, "delivery_record_audit", {})
                self.assertTrue(result.is_error)
                self.assertEqual(result.meta[META_KEY]["code"], "internal_error")
                self.assertNotIn(internal_code, result.content[0].text)
                self.assertNotIn(internal_code, str(result.meta))
                self.assertIn(internal_code, "\n".join(captured.output))

    def test_audit_log_handler_failure_preserves_original_public_error(self):
        server = DeliverySystemMCPServer("audit-error-log-failure-test")
        tool_calls = 0
        log_failures = 0
        original_marker = "original-audit-stale-marker"
        logger_failure_marker = "logger-failure-sensitive-marker"

        class AuditStaleError(ValueError):
            def __str__(self):
                return original_marker

        @server.tool(name="delivery_record_audit", structured_output=False)
        def fail_audit():
            nonlocal tool_calls
            tool_calls += 1
            raise AuditStaleError("audit_stale")

        class FailingHandler(logging.Handler):
            def emit(self, record):
                nonlocal log_failures
                log_failures += 1
                raise RuntimeError(logger_failure_marker)

        logger = logging.getLogger("mcp_server.read_only_contracts")
        old_level = logger.level
        handler = FailingHandler()
        logger.setLevel(logging.ERROR)
        logger.addHandler(handler)
        fallback_records = []

        def capture_fallback(file_descriptor, payload):
            fallback_records.append((file_descriptor, payload))
            return len(payload)

        try:
            with patch("mcp_server.read_only_contracts.os.write", side_effect=capture_fallback):
                result = self._call(server, "delivery_record_audit", {})
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)

        self.assertTrue(result.is_error)
        self.assertEqual(result.meta[META_KEY]["code"], "audit_stale")
        self.assertEqual(result.content[0].text, descriptor_for_code("audit_stale").safe_text)
        self.assertNotIn(original_marker, result.content[0].text)
        self.assertNotIn(logger_failure_marker, result.content[0].text)
        self.assertNotIn(original_marker, str(result.meta))
        self.assertNotIn(logger_failure_marker, str(result.meta))
        self.assertEqual(tool_calls, 1)
        self.assertEqual(log_failures, 1)
        self.assertEqual(len(fallback_records), 1)
        self.assertEqual(fallback_records[0][0], 2)
        fallback_output = fallback_records[0][1].decode("ascii")
        self.assertIn("request_id=", fallback_output)
        self.assertIn("exception_type=tests.v1.test_public_error_contract", fallback_output)
        self.assertIn("AuditStaleError", fallback_output)
        self.assertIn("reason=audit_stale", fallback_output)
        self.assertIn("logger_handler_failure=true", fallback_output)
        self.assertNotIn(original_marker, fallback_output)
        self.assertNotIn(logger_failure_marker, fallback_output)

    def test_audit_fallback_diagnostic_failure_preserves_public_error(self):
        server = DeliverySystemMCPServer("audit-error-fallback-failure-test")
        tool_calls = 0
        logger_failure_marker = "logger-failure-sensitive-marker"
        fallback_failure_marker = "fallback-failure-sensitive-marker"

        @server.tool(name="delivery_record_audit", structured_output=False)
        def fail_audit():
            nonlocal tool_calls
            tool_calls += 1
            raise ValueError("audit_stale")

        class FailingHandler(logging.Handler):
            def emit(self, record):
                raise RuntimeError(logger_failure_marker)

        logger = logging.getLogger("mcp_server.read_only_contracts")
        old_level = logger.level
        handler = FailingHandler()
        logger.setLevel(logging.ERROR)
        logger.addHandler(handler)
        try:
            with patch(
                "mcp_server.read_only_contracts.os.write",
                side_effect=OSError(fallback_failure_marker),
            ):
                result = self._call(server, "delivery_record_audit", {})
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)

        self.assertTrue(result.is_error)
        self.assertEqual(result.meta[META_KEY]["code"], "audit_stale")
        self.assertEqual(result.content[0].text, descriptor_for_code("audit_stale").safe_text)
        self.assertNotIn(logger_failure_marker, result.content[0].text)
        self.assertNotIn(fallback_failure_marker, result.content[0].text)
        self.assertNotIn(logger_failure_marker, str(result.meta))
        self.assertNotIn(fallback_failure_marker, str(result.meta))
        self.assertEqual(tool_calls, 1)

    def test_arbitrary_code_attribute_does_not_select_public_recovery(self):
        class SpoofedCodeError(RuntimeError):
            def __init__(self):
                super().__init__("do not trust me")
                self.code = "credential_expired"

        server = DeliverySystemMCPServer("public-error-test")

        @server.tool(name="spoofed_code", structured_output=False)
        def spoofed_code():
            raise SpoofedCodeError()

        result = self._call(server, "spoofed_code", {})
        self.assertTrue(result.is_error)
        self.assertEqual(
            result.meta[META_KEY],
            {
                "code": "internal_error",
                "category": "TRANSPORT_HOST",
                "retry_disposition": "NO_AUTOMATIC_RETRY",
                "recovery_action": "ESCALATE_TO_HOST_OPERATOR",
            },
        )

    def test_trusted_driver_error_code_selects_registered_recovery(self):
        server = DeliverySystemMCPServer("public-error-test")

        @server.tool(name="driver_error", structured_output=False)
        def driver_error():
            raise DriverError("credential_expired")

        result = self._call(server, "driver_error", {})
        self.assertTrue(result.is_error)
        self.assertEqual(result.meta[META_KEY]["code"], "credential_expired")

    def test_store_preflight_error_code_requires_registry_membership(self):
        registered_server = DeliverySystemMCPServer("public-error-test")

        @registered_server.tool(name="registered_preflight", structured_output=False)
        def registered_preflight():
            raise StorePreflightError("store_corrupt")

        registered_result = self._call(registered_server, "registered_preflight", {})
        self.assertTrue(registered_result.is_error)
        self.assertEqual(registered_result.meta[META_KEY]["code"], "store_corrupt")

        unregistered_server = DeliverySystemMCPServer("public-error-test")

        @unregistered_server.tool(name="unregistered_preflight", structured_output=False)
        def unregistered_preflight():
            raise StorePreflightError("operation_set_mismatch")

        unregistered_result = self._call(unregistered_server, "unregistered_preflight", {})
        self.assertTrue(unregistered_result.is_error)
        self.assertEqual(unregistered_result.meta[META_KEY]["code"], "internal_error")

    def test_value_error_uses_only_exact_registered_argument(self):
        registered_server = DeliverySystemMCPServer("public-error-test")

        @registered_server.tool(name="registered_value_error", structured_output=False)
        def registered_value_error():
            raise ValueError("credential_expired")

        registered_result = self._call(registered_server, "registered_value_error", {})
        self.assertTrue(registered_result.is_error)
        self.assertEqual(registered_result.meta[META_KEY]["code"], "credential_expired")

        unregistered_server = DeliverySystemMCPServer("public-error-test")

        @unregistered_server.tool(name="unregistered_value_error", structured_output=False)
        def unregistered_value_error():
            raise ValueError("operation_set_mismatch")

        unregistered_result = self._call(unregistered_server, "unregistered_value_error", {})
        self.assertTrue(unregistered_result.is_error)
        self.assertEqual(unregistered_result.meta[META_KEY]["code"], "internal_error")


if __name__ == "__main__":
    unittest.main()
