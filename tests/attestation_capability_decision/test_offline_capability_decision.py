from __future__ import annotations

from datetime import datetime, timezone
import inspect
import unittest
from unittest.mock import patch

from delivery_system.attestation import AttestationRuntimeBoundary, RevocationStatus
from delivery_system.attestation_capability_decision import (
    OfflineCapabilityDecision,
    OfflineCredentialCapabilityDecisionResult,
    OfflineCredentialCapabilityDecisionService,
)
from delivery_system.attestation_persistence import PersistenceContractError, RevalidationAttemptBoundary
from delivery_system.attestation_persistence_store import InMemoryAttestationPersistenceStore, StoreContractError
from delivery_system.attestation_restart import RestartRevalidationError, RestartRevalidationService
from tests.fakes.attestation_persistence_store_contract import artifact_for, reference_for


NOW = datetime(2026, 8, 14, 12, tzinfo=timezone.utc)
PAIRINGS = (
    (OfflineCapabilityDecision.SATISFIED, "offline_capability_satisfied"),
    (OfflineCapabilityDecision.NOT_SATISFIED, "attestation_revalidation_expired"),
    (OfflineCapabilityDecision.NOT_SATISFIED, "attestation_revalidation_revoked"),
)
KNOWN_REASONS = (
    "offline_capability_satisfied",
    "attestation_revalidation_expired",
    "attestation_revalidation_revoked",
)


class _Reader:
    def __init__(self, status: object = RevocationStatus()) -> None:
        self.status = status
        self.calls = 0

    def read_status(self, *_args: object) -> object:
        self.calls += 1
        return self.status


class _Clock:
    def __init__(self, value: object = NOW) -> None:
        self.value = value
        self.calls = 0

    def __call__(self) -> object:
        self.calls += 1
        return self.value


class _Entropy:
    def __init__(self, value: bytes = b"capability-attempt") -> None:
        self.value = value
        self.calls = 0

    def __call__(self, size: int) -> bytes:
        self.calls += 1
        if len(self.value) != size:
            return self.value.ljust(size, b"0")[:size]
        return self.value


class _RuntimeRestartFixture:
    def __init__(self, *, status: object = RevocationStatus(), now: object = NOW) -> None:
        self.artifact = artifact_for()
        self.reference = reference_for(self.artifact)
        self.store = InMemoryAttestationPersistenceStore()
        self.store.persist_artifact(self.artifact, self.reference)
        self.reader = _Reader(status)
        self.clock = _Clock(now)
        self.entropy = _Entropy()
        self.request = AttestationRuntimeBoundary(
            None, None, self.reader, _CapabilityPolicy()
        ).create_request(
            repository_identity="owner/repository",
            github_subject_identity="subject-node-1",
            required_capabilities=("issues:read", "issues:write"),
            driver_identity="github-rest-driver-v1",
            remote_authority="sha256:" + "a" * 64,
            preview_id="preview-1",
            revision=1,
            operation_set_digest="sha256:" + "b" * 64,
            remote_snapshot_digest="sha256:" + "c" * 64,
            evidence_digest="sha256:" + "d" * 64,
        )
        self.restart = RestartRevalidationService(
            store=self.store,
            revocation_reader=self.reader,
            attempt_boundary=RevalidationAttemptBoundary(self.entropy),
            clock=self.clock,
        )


class _CapabilityPolicy:
    def is_supported(self, capability: str) -> bool:
        return capability in {"issues:read", "issues:write"}


class _AnyCapabilityPolicy:
    def is_supported(self, _capability: str) -> bool:
        return True


def _base_result(**overrides: object) -> OfflineCredentialCapabilityDecisionResult:
    values: dict[str, object] = {
        "decision": OfflineCapabilityDecision.SATISFIED,
        "reason_code": "offline_capability_satisfied",
        "workspace_identity": "workspace-1",
        "artifact_id": "artifact-1",
        "requested_capabilities": ("issues:read", "issues:write"),
        "revalidation_attempt_id": "attempt-1",
        "event_sequence": 1,
        "revalidation_context_digest": "sha256:" + "a" * 64,
        "revalidated_at": "2026-08-14T12:00:00.000000Z",
    }
    values.update(overrides)
    return OfflineCredentialCapabilityDecisionResult(**values)


class _ResultService:
    def __init__(self, result: object) -> None:
        self.result = result
        self.calls = 0
        self.arguments: dict[str, object] | None = None

    def revalidate(self, **kwargs: object) -> object:
        self.calls += 1
        self.arguments = kwargs
        return self.result


class _RaisingService:
    def __init__(self, error: BaseException) -> None:
        self.error = error
        self.calls = 0

    def revalidate(self, **_kwargs: object) -> object:
        self.calls += 1
        raise self.error


class _SequenceService:
    def __init__(self, results: tuple[object, ...]) -> None:
        self.results = iter(results)
        self.calls = 0

    def revalidate(self, **_kwargs: object) -> object:
        self.calls += 1
        return next(self.results)


class _PropertyErrorResult:
    def __init__(self, error: BaseException) -> None:
        self.error = error

    @property
    def event(self) -> object:
        raise self.error


class ApiAndResultContractTests(unittest.TestCase):
    def test_public_surface_and_signatures_are_exact(self) -> None:
        import delivery_system.attestation_capability_decision as module

        self.assertEqual(
            module.__all__,
            (
                "OfflineCapabilityDecision",
                "OfflineCredentialCapabilityDecisionResult",
                "OfflineCredentialCapabilityDecisionService",
            ),
        )
        constructor = inspect.signature(OfflineCredentialCapabilityDecisionService)
        self.assertEqual(tuple(constructor.parameters), ("revalidation_service",))
        self.assertTrue(all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in constructor.parameters.values()))
        decide = inspect.signature(OfflineCredentialCapabilityDecisionService.decide)
        self.assertEqual(
            tuple(decide.parameters),
            ("self", "workspace_identity", "artifact_id", "reference", "request"),
        )
        self.assertTrue(all(p.kind is inspect.Parameter.KEYWORD_ONLY for p in list(decide.parameters.values())[1:]))
        self.assertNotIn("store", constructor.parameters)
        self.assertNotIn("revalidation_context_digest", decide.parameters)

    def test_all_three_legal_pairings_construct_directly(self) -> None:
        for decision, reason in PAIRINGS:
            with self.subTest(decision=decision, reason=reason):
                result = _base_result(decision=decision, reason_code=reason)
                self.assertEqual(result.decision, decision)
                self.assertEqual(result.reason_code, reason)

    def test_complete_known_pairing_matrix_and_unknown_reasons(self) -> None:
        for decision in OfflineCapabilityDecision:
            for reason in KNOWN_REASONS:
                with self.subTest(decision=decision, reason=reason):
                    if (decision, reason) in PAIRINGS:
                        _base_result(decision=decision, reason_code=reason)
                    else:
                        with self.assertRaisesRegex(ValueError, "^offline_capability_decision_reason_pair_invalid$") as raised:
                            _base_result(decision=decision, reason_code=reason)
                        self.assertEqual(repr(raised.exception), "ValueError('offline_capability_decision_reason_pair_invalid')")
        for reason in ("", " ", "unknown", None, 1):
            with self.subTest(reason=reason):
                with self.assertRaises(ValueError) as raised:
                    _base_result(reason_code=reason)
                self.assertEqual(str(raised.exception), "offline_capability_decision_reason_pair_invalid")
                self.assertEqual(repr(raised.exception), "ValueError('offline_capability_decision_reason_pair_invalid')")

    def test_result_is_frozen_slotted_value_object_with_safe_repr(self) -> None:
        result = _base_result()
        equal = _base_result()
        self.assertEqual(result, equal)
        self.assertEqual(hash(result), hash(equal))
        self.assertEqual(
            str(result),
            "OfflineCredentialCapabilityDecisionResult(decision='satisfied', reason_code='offline_capability_satisfied')",
        )
        self.assertEqual(repr(result), str(result))
        self.assertNotIn("workspace-1", repr(result))
        self.assertNotIn("artifact-1", repr(result))
        self.assertNotIn("sha256:", repr(result))
        with self.assertRaises((AttributeError, TypeError)):
            result.decision = OfflineCapabilityDecision.NOT_SATISFIED  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            result.extra = "not allowed"  # type: ignore[attr-defined]


class ServiceContractTests(unittest.TestCase):
    def test_decide_uses_only_same_call_result_and_calls_restart_once(self) -> None:
        fixture = _RuntimeRestartFixture()
        spy = _ResultService(
            fixture.restart.revalidate(
                workspace_identity=fixture.artifact.workspace_identity,
                artifact_id=fixture.artifact.artifact_id,
                reference=fixture.reference,
                request=fixture.request,
            )
        )
        decision = OfflineCredentialCapabilityDecisionService(revalidation_service=spy)
        result = decision.decide(
            workspace_identity=fixture.artifact.workspace_identity,
            artifact_id=fixture.artifact.artifact_id,
            reference=fixture.reference,
            request=fixture.request,
        )
        self.assertEqual(spy.calls, 1)
        self.assertEqual(result.decision, OfflineCapabilityDecision.SATISFIED)
        self.assertEqual(result.reason_code, "offline_capability_satisfied")
        self.assertEqual(result.workspace_identity, fixture.artifact.workspace_identity)
        self.assertEqual(result.artifact_id, fixture.artifact.artifact_id)
        self.assertEqual(result.requested_capabilities, fixture.request.required_capabilities)
        self.assertEqual(result.event_sequence, 1)
        self.assertEqual(result.revalidation_attempt_id, spy.result.event.event.revalidation_attempt_id)
        self.assertEqual(result.revalidation_context_digest, spy.result.event.event.revalidation_context_digest)
        self.assertEqual(result.revalidated_at, spy.result.event.event.revalidated_at)

    def test_real_restart_success_expired_and_revoked_map_to_results(self) -> None:
        cases = (
            ("success", {}, OfflineCapabilityDecision.SATISFIED, "offline_capability_satisfied"),
            ("expired", {"now": datetime(2026, 8, 14, 14, tzinfo=timezone.utc)}, OfflineCapabilityDecision.NOT_SATISFIED, "attestation_revalidation_expired"),
            ("revoked", {"status": RevocationStatus(attestation_revoked=True, revoked_at="2026-08-14T11:30:00Z", reason="revoked")}, OfflineCapabilityDecision.NOT_SATISFIED, "attestation_revalidation_revoked"),
        )
        for label, kwargs, expected_decision, expected_reason in cases:
            with self.subTest(label=label):
                fixture = _RuntimeRestartFixture(**kwargs)
                service = OfflineCredentialCapabilityDecisionService(revalidation_service=fixture.restart)
                result = service.decide(
                    workspace_identity=fixture.artifact.workspace_identity,
                    artifact_id=fixture.artifact.artifact_id,
                    reference=fixture.reference,
                    request=fixture.request,
                )
                self.assertEqual(result.decision, expected_decision)
                self.assertEqual(result.reason_code, expected_reason)
                self.assertEqual(fixture.clock.calls, 1)
                self.assertEqual(fixture.store.get_latest_revalidation_event(fixture.artifact.workspace_identity, fixture.artifact.artifact_id).event_sequence, 1)

    def test_restart_owned_identity_mismatch_is_propagated_without_result(self) -> None:
        fixture = _RuntimeRestartFixture()
        altered = AttestationRuntimeBoundary(
            None, None, fixture.reader, _AnyCapabilityPolicy()
        ).create_request(
            repository_identity="owner/repository",
            github_subject_identity="subject-node-1",
            required_capabilities=("missing:capability",),
            driver_identity="github-rest-driver-v1",
            remote_authority="sha256:" + "a" * 64,
            preview_id="preview-1",
            revision=1,
            operation_set_digest="sha256:" + "b" * 64,
            remote_snapshot_digest="sha256:" + "c" * 64,
            evidence_digest="sha256:" + "d" * 64,
        )
        service = OfflineCredentialCapabilityDecisionService(revalidation_service=fixture.restart)
        with self.assertRaises(Exception) as raised:
            service.decide(
                workspace_identity=fixture.artifact.workspace_identity,
                artifact_id=fixture.artifact.artifact_id,
                reference=fixture.reference,
                request=altered,
            )
        self.assertEqual(getattr(raised.exception, "code", None), "attestation_restart_identity_mismatch")
        self.assertIsNone(fixture.store.get_latest_revalidation_event(fixture.artifact.workspace_identity, fixture.artifact.artifact_id))

    def test_decision_does_not_read_store_or_latest_event(self) -> None:
        fixture = _RuntimeRestartFixture()
        result = fixture.restart.revalidate(
            workspace_identity=fixture.artifact.workspace_identity,
            artifact_id=fixture.artifact.artifact_id,
            reference=fixture.reference,
            request=fixture.request,
        )
        spy = _ResultService(result)
        decision = OfflineCredentialCapabilityDecisionService(revalidation_service=spy)
        with patch.object(fixture.store, "get_latest_revalidation_event", side_effect=AssertionError("Decision must not read Store")):
            output = decision.decide(
                workspace_identity=fixture.artifact.workspace_identity,
                artifact_id=fixture.artifact.artifact_id,
                reference=fixture.reference,
                request=fixture.request,
            )
        self.assertEqual(output.event_sequence, 1)

    def test_result_constructor_failure_does_not_compensate_restart_event(self) -> None:
        fixture = _RuntimeRestartFixture()
        decision = OfflineCredentialCapabilityDecisionService(revalidation_service=fixture.restart)
        with patch(
            "delivery_system.attestation_capability_decision.OfflineCredentialCapabilityDecisionResult",
            side_effect=RuntimeError("constructor programming failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "constructor programming failure"):
                decision.decide(
                    workspace_identity=fixture.artifact.workspace_identity,
                    artifact_id=fixture.artifact.artifact_id,
                    reference=fixture.reference,
                    request=fixture.request,
                )
        persisted = fixture.store.get_latest_revalidation_event(
            fixture.artifact.workspace_identity, fixture.artifact.artifact_id
        )
        self.assertIsNotNone(persisted)
        self.assertEqual(persisted.event_sequence, 1)

    def test_restart_owner_errors_propagate_without_retry_or_result(self) -> None:
        errors = (
            PersistenceContractError("attestation_attempt_id_collision"),
            StoreContractError("attestation_persistence_rollback_failed"),
            StoreContractError("attestation_persistence_commit_outcome_unknown"),
            RestartRevalidationError(code="attestation_restart_clock_invalid"),
        )
        for error in errors:
            with self.subTest(error=type(error).__name__ + ":" + str(error)):
                dependency = _RaisingService(error)
                decision = OfflineCredentialCapabilityDecisionService(revalidation_service=dependency)
                with self.assertRaises(Exception) as raised:
                    decision.decide(
                        workspace_identity="workspace-1",
                        artifact_id="artifact-1",
                        reference=object(),
                        request=object(),
                    )
                self.assertIs(raised.exception, error)
                self.assertIs(type(raised.exception), type(error))
                self.assertEqual(dependency.calls, 1)

    def test_ordinary_store_failure_delegates_without_retry_or_conversion(self) -> None:
        expected_exception = StoreContractError("attestation_persistence_store_unavailable")
        dependency = _RaisingService(expected_exception)
        decision = OfflineCredentialCapabilityDecisionService(revalidation_service=dependency)

        with self.assertRaises(StoreContractError) as caught:
            decision.decide(
                workspace_identity="workspace-1",
                artifact_id="artifact-1",
                reference=object(),
                request=object(),
            )

        self.assertIs(caught.exception, expected_exception)
        self.assertIs(type(caught.exception), StoreContractError)
        self.assertEqual(caught.exception.code, "attestation_persistence_store_unavailable")
        self.assertEqual(str(caught.exception), "attestation_persistence_store_unavailable")
        self.assertEqual(
            repr(caught.exception),
            "StoreContractError('attestation_persistence_store_unavailable')",
        )
        self.assertEqual(dependency.calls, 1)
        self.assertNotIsInstance(caught.exception, RestartRevalidationError)
        self.assertNotEqual(str(caught.exception), "offline_capability_decision_reason_pair_invalid")
        legacy_result_error = "_".join(
            ("offline", "capability", "decision", "result", "invalid")
        )
        self.assertNotIn(legacy_result_error, str(caught.exception))

    def test_programming_errors_propagate_as_same_exception_object(self) -> None:
        sentinel = RuntimeError("sentinel programming failure")
        dependency = _RaisingService(sentinel)
        decision = OfflineCredentialCapabilityDecisionService(revalidation_service=dependency)
        with self.assertRaises(RuntimeError) as raised:
            decision.decide(
                workspace_identity="workspace-1",
                artifact_id="artifact-1",
                reference=object(),
                request=object(),
            )
        self.assertIs(raised.exception, sentinel)
        self.assertEqual(str(raised.exception), "sentinel programming failure")
        self.assertEqual(dependency.calls, 1)
        property_error = KeyError("same-call event property failure")
        property_dependency = _ResultService(_PropertyErrorResult(property_error))
        property_decision = OfflineCredentialCapabilityDecisionService(revalidation_service=property_dependency)
        with self.assertRaises(KeyError) as property_raised:
            property_decision.decide(
                workspace_identity="workspace-1",
                artifact_id="artifact-1",
                reference=object(),
                request=object(),
            )
        self.assertIs(property_raised.exception, property_error)
        self.assertEqual(property_dependency.calls, 1)

    def test_two_calls_revalidate_again_and_use_the_second_same_call_event(self) -> None:
        first_fixture = _RuntimeRestartFixture(now=NOW)
        second_fixture = _RuntimeRestartFixture(
            now=datetime(2026, 8, 14, 12, 1, tzinfo=timezone.utc)
        )
        first_event = first_fixture.restart.revalidate(
            workspace_identity=first_fixture.artifact.workspace_identity,
            artifact_id=first_fixture.artifact.artifact_id,
            reference=first_fixture.reference,
            request=first_fixture.request,
        )
        second_event = second_fixture.restart.revalidate(
            workspace_identity=second_fixture.artifact.workspace_identity,
            artifact_id=second_fixture.artifact.artifact_id,
            reference=second_fixture.reference,
            request=second_fixture.request,
        )
        dependency = _SequenceService((first_event, second_event))
        decision = OfflineCredentialCapabilityDecisionService(revalidation_service=dependency)
        first = decision.decide(
            workspace_identity=first_fixture.artifact.workspace_identity,
            artifact_id=first_fixture.artifact.artifact_id,
            reference=first_fixture.reference,
            request=first_fixture.request,
        )
        second = decision.decide(
            workspace_identity=second_fixture.artifact.workspace_identity,
            artifact_id=second_fixture.artifact.artifact_id,
            reference=second_fixture.reference,
            request=second_fixture.request,
        )
        self.assertEqual(dependency.calls, 2)
        self.assertEqual(first.revalidation_attempt_id, first_event.event.event.revalidation_attempt_id)
        self.assertEqual(second.revalidation_attempt_id, second_event.event.event.revalidation_attempt_id)
        self.assertEqual(first.revalidated_at, first_event.event.event.revalidated_at)
        self.assertEqual(second.revalidated_at, second_event.event.event.revalidated_at)
        self.assertNotEqual(first.revalidated_at, second.revalidated_at)


if __name__ == "__main__":
    unittest.main()
