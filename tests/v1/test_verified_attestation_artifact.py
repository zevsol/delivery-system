from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
import base64
from delivery_system.attestation import SignedCredentialCapabilityAttestation
from pathlib import Path
import tempfile
import threading
import unittest
import weakref

from delivery_system.attestation_persistence import (
    AttestationBindingReference,
    PersistedAttestationArtifact,
)
from delivery_system.attestation_persistence_store import (
    InMemoryAttestationPersistenceStore,
    SQLiteAttestationPersistenceStore,
)
from delivery_system.attestation_runtime import (
    RuntimeCredentialCapabilityBinding,
    RuntimeAttestationOrchestrationService,
    VerifiedRuntimeCredentialContext,
)
from delivery_system.verified_attestation_artifact import (
    VerifiedAttestationArtifactAdapter,
    VerifiedAttestationArtifactError,
    VerifiedCredentialArtifactLink,
)
import tests.attestation_orchestration.test_attestation_orchestration as orchestration_tests
from tests.fakes.attestation_persistence_store_contract import artifact_for, make_claims, reference_for

NOW = orchestration_tests.NOW


class Clock:
    def __init__(self, *values: datetime) -> None:
        self.values = list(values)
        self.calls = 0

    def __call__(self) -> datetime:
        self.calls += 1
        return self.values.pop(0)


class FirstLookupMissingStore:
    """Force both adapters through the missing-artifact branch before writes."""

    def __init__(self, wrapped, barrier: threading.Barrier) -> None:
        self.wrapped = wrapped
        self.barrier = barrier
        self._first_lookup = True
        self._lock = threading.Lock()

    def get_artifact_aggregate(self, workspace_identity, artifact_id):
        with self._lock:
            first = self._first_lookup
            self._first_lookup = False
        if first:
            self.barrier.wait(timeout=10)
            return None
        return self.wrapped.get_artifact_aggregate(workspace_identity, artifact_id)

    def persist_artifact(self, artifact, binding_reference):
        return self.wrapped.persist_artifact(artifact, binding_reference)


class ReadOnlyProbeStore:
    def __init__(self, wrapped) -> None:
        self.wrapped = wrapped
        self.get_calls = 0
        self.persist_calls = 0

    def get_artifact_aggregate(self, workspace_identity, artifact_id):
        self.get_calls += 1
        return self.wrapped.get_artifact_aggregate(workspace_identity, artifact_id)

    def persist_artifact(self, artifact, binding_reference):
        self.persist_calls += 1
        raise AssertionError("read_only_resolver_must_not_persist")


class VerifiedArtifactAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runtime = orchestration_tests.OrchestrationTests()
        self.runtime.setUp()
        result = self.runtime.run_service()
        self.assertTrue(result.success)
        self.context = result.verified_context
        self.assertIsInstance(self.context, VerifiedRuntimeCredentialContext)
        assert self.context is not None
        self.envelope = self.context.envelope
        self.binding = self.context.binding
        self.assertIsInstance(self.binding, RuntimeCredentialCapabilityBinding)

    def tearDown(self) -> None:
        self.runtime.tearDown()

    def _adapter(self, store, clock=None) -> VerifiedAttestationArtifactAdapter:
        return VerifiedAttestationArtifactAdapter(
            store,
            clock=clock or (lambda: NOW + timedelta(minutes=1)),
        )

    def _stores(self):
        memory = InMemoryAttestationPersistenceStore()
        temporary = tempfile.TemporaryDirectory()
        path = Path(temporary.name) / "attestation.sqlite3"
        sqlite = SQLiteAttestationPersistenceStore(
            path, workspace_identity=self.binding.workspace_identity
        )
        return (("memory", memory), ("sqlite", sqlite)), temporary

    @staticmethod
    def _close_stores(stores) -> None:
        for _, store in stores:
            if hasattr(store, "close"):
                store.close()

    def test_verified_envelope_and_binding_persist_exactly_for_both_stores(self) -> None:
        stores, temporary = self._stores()
        try:
            for name, store in stores:
                with self.subTest(store=name):
                    link = self._adapter(store).persist_verified_attestation(
                        self.context
                    )
                    self.assertIsInstance(link, VerifiedCredentialArtifactLink)
                    self.assertEqual(link.credential_binding_id, self.binding.binding_id)
                    self.assertEqual(link.artifact_id, link.artifact.artifact_id)
                    self.assertEqual(link.artifact_digest, link.artifact.artifact_digest)
                    self.assertEqual(link.artifact.attestation_id, self.envelope.claims.attestation_id)
                    self.assertEqual(link.artifact.claims_payload.to_payload(), self.envelope.claims.to_payload())
                    self.assertEqual(link.artifact.detached_proof, self.envelope.proof)
                    self.assertEqual(link.artifact.claims_digest, self.envelope.claims.claims_digest())
                    self.assertEqual(link.binding_reference.binding_id, self.binding.binding_id)
        finally:
            self._close_stores(stores)
            temporary.cleanup()

    def test_exact_retry_reuses_artifact_digest_without_second_clock_call(self) -> None:
        stores, temporary = self._stores()
        try:
            for name, store in stores:
                with self.subTest(store=name):
                    clock = Clock(NOW + timedelta(minutes=1), NOW + timedelta(minutes=2))
                    adapter = self._adapter(store, clock)
                    first = adapter.persist_verified_attestation(self.context)
                    second = adapter.persist_verified_attestation(self.context)
                    self.assertEqual(first.artifact_id, second.artifact_id)
                    self.assertEqual(first.artifact_digest, second.artifact_digest)
                    self.assertEqual(first.binding_reference, second.binding_reference)
                    self.assertEqual(clock.calls, 1)
        finally:
            self._close_stores(stores)
            temporary.cleanup()

    def test_read_only_resolver_returns_existing_aggregate_without_clock_or_write(self) -> None:
        stores, temporary = self._stores()
        try:
            for name, store in stores:
                with self.subTest(store=name):
                    self._adapter(store).persist_verified_attestation(self.context)
                    probe = ReadOnlyProbeStore(store)
                    clock = Clock(NOW + timedelta(minutes=2))
                    link = self._adapter(probe, clock).resolve_verified_attestation(self.context)
                    expected = store.get_artifact_aggregate(
                        self.binding.workspace_identity,
                        link.artifact_id,
                    )
                    self.assertEqual(link.aggregate, expected)
                    self.assertEqual(probe.get_calls, 1)
                    self.assertEqual(probe.persist_calls, 0)
                    self.assertEqual(clock.calls, 0)
        finally:
            self._close_stores(stores)
            temporary.cleanup()

    def test_read_only_resolver_missing_artifact_does_not_clock_or_write(self) -> None:
        stores, temporary = self._stores()
        try:
            for name, store in stores:
                with self.subTest(store=name):
                    probe = ReadOnlyProbeStore(store)
                    clock = Clock(NOW + timedelta(minutes=2))
                    with self.assertRaisesRegex(
                        VerifiedAttestationArtifactError,
                        "^verified_attestation_artifact_not_found$",
                    ):
                        self._adapter(probe, clock).resolve_verified_attestation(self.context)
                    self.assertEqual(probe.get_calls, 1)
                    self.assertEqual(probe.persist_calls, 0)
                    self.assertEqual(clock.calls, 0)
        finally:
            self._close_stores(stores)
            temporary.cleanup()

    def test_read_only_resolver_rejects_existing_evidence_mismatch(self) -> None:
        store = InMemoryAttestationPersistenceStore()
        try:
            created = (NOW + timedelta(minutes=1)).isoformat(timespec="microseconds").replace("+00:00", "Z")
            altered_proof = base64.urlsafe_b64encode(b"m" * 64).decode("ascii").rstrip("=")
            winner = PersistedAttestationArtifact.create(
                workspace_identity=self.binding.workspace_identity,
                claims_payload=self.context.claims,
                detached_proof=altered_proof,
                original_verified_at=self.context.verified_at,
                created_at=created,
            )
            reference = AttestationBindingReference.create(
                artifact=winner,
                binding_values=self.binding.to_dict(),
            )
            store.persist_artifact(winner, reference)
            with self.assertRaisesRegex(
                VerifiedAttestationArtifactError,
                "^verified_attestation_artifact_conflict$",
            ):
                self._adapter(store).resolve_verified_attestation(self.context)
        finally:
            if hasattr(store, "close"):
                store.close()

    def test_read_only_resolver_rejects_unowned_context(self) -> None:
        store = InMemoryAttestationPersistenceStore()
        try:
            forged = object.__new__(VerifiedRuntimeCredentialContext)
            object.__setattr__(
                forged,
                "_VerifiedRuntimeCredentialContext__event",
                self.context.event,
            )
            object.__setattr__(
                forged,
                "_VerifiedRuntimeCredentialContext__binding",
                self.context.binding,
            )
            object.__setattr__(
                forged,
                "_VerifiedRuntimeCredentialContext__owner",
                object.__getattribute__(self.context, "_VerifiedRuntimeCredentialContext__owner"),
            )
            with self.assertRaisesRegex(
                VerifiedAttestationArtifactError,
                "^verified_attestation_context_unverified$",
            ):
                self._adapter(store).resolve_verified_attestation(forged)
        finally:
            if hasattr(store, "close"):
                store.close()

    def test_retry_preserves_the_original_creation_timestamp(self) -> None:
        stores, temporary = self._stores()
        first_time = NOW + timedelta(minutes=1)
        try:
            for name, store in stores:
                with self.subTest(store=name):
                    clock = Clock(first_time, NOW + timedelta(minutes=2))
                    adapter = self._adapter(store, clock)
                    first = adapter.persist_verified_attestation(self.context)
                    second = adapter.persist_verified_attestation(self.context)
                    expected = first_time.isoformat(timespec="microseconds").replace(
                        "+00:00", "Z"
                    )
                    self.assertEqual(first.artifact.created_at, expected)
                    self.assertEqual(second.artifact.created_at, expected)
        finally:
            self._close_stores(stores)
            temporary.cleanup()

    def test_original_verification_timestamp_comes_from_binding(self) -> None:
        store = InMemoryAttestationPersistenceStore()
        try:
            link = self._adapter(store).persist_verified_attestation(
                self.context
            )
            expected = NOW.isoformat(timespec="microseconds").replace("+00:00", "Z")
            self.assertEqual(link.artifact.original_verified_at, expected)
        finally:
            if hasattr(store, "close"):
                store.close()

    def test_artifact_content_projection_preserves_verified_evidence(self) -> None:
        store = InMemoryAttestationPersistenceStore()
        try:
            link = self._adapter(store).persist_verified_attestation(
                self.context
            )
            self.assertEqual(
                link.artifact.content_payload(),
                {
                    "domain": "delivery-system:attestation-artifact-content:v1",
                    "artifact_contract_version": "offline-attestation-artifact-v1",
                    "workspace_identity": self.binding.workspace_identity,
                    "attestation_id": self.envelope.claims.attestation_id,
                    "claims_payload": self.envelope.claims.to_payload(),
                    "detached_proof": self.envelope.proof,
                    "claims_digest": self.envelope.claims.claims_digest(),
                    "original_verified_at": link.artifact.original_verified_at,
                    "created_at": link.artifact.created_at,
                },
            )
        finally:
            if hasattr(store, "close"):
                store.close()

    def test_adapter_has_no_independent_envelope_or_binding_trust_inputs(self) -> None:
        store = InMemoryAttestationPersistenceStore()
        try:
            with self.assertRaises(TypeError):
                self._adapter(store).persist_verified_attestation(  # type: ignore[call-arg]
                    self.context, self.envelope, self.binding
                )
        finally:
            if hasattr(store, "close"):
                store.close()

    def test_unverified_input_types_are_rejected(self) -> None:
        store = InMemoryAttestationPersistenceStore()
        try:
            with self.assertRaisesRegex(VerifiedAttestationArtifactError, "^verified_attestation_context_unverified$"):
                self._adapter(store).persist_verified_attestation(object())
            with self.assertRaisesRegex(ValueError, "^verified_runtime_context_internal_only$"):
                VerifiedRuntimeCredentialContext()
            forged = object.__new__(VerifiedRuntimeCredentialContext)
            object.__setattr__(
                forged,
                "_VerifiedRuntimeCredentialContext__event",
                self.context.event,
            )
            object.__setattr__(
                forged,
                "_VerifiedRuntimeCredentialContext__binding",
                self.context.binding,
            )
            object.__setattr__(
                forged,
                "_VerifiedRuntimeCredentialContext__owner",
                object.__getattribute__(self.context, "_VerifiedRuntimeCredentialContext__owner"),
            )
            self.assertFalse(forged.is_source_owned())
            with self.assertRaisesRegex(VerifiedAttestationArtifactError, "^verified_attestation_context_unverified$"):
                self._adapter(store).persist_verified_attestation(forged)
        finally:
            if hasattr(store, "close"):
                store.close()

    def test_caller_service_subclass_cannot_authorize_forged_context(self) -> None:
        class EvilRuntimeAttestationService(RuntimeAttestationOrchestrationService):
            def _accepts_verified_event_binding(self, event, binding):
                return True

            def _accepts_verified_context(self, context):
                return True

        evil = EvilRuntimeAttestationService(
            self.runtime.context,
            self.runtime.store,
            orchestration_tests.TRUST,
            orchestration_tests.AttestationRuntimeBoundary(
                self.runtime.fake_issuer,
                self.runtime.fake_issuer,
                self.runtime.fake_issuer,
                orchestration_tests.FakeCapabilityPolicy(),
            ),
            self.runtime.provider,
            self.runtime.resolver,
            clock=lambda: NOW,
        )
        forged_event = object.__new__(type(self.context.event))
        alternate_proof = base64.urlsafe_b64encode(b"z" * 64).decode("ascii").rstrip("=")
        alternate_envelope = SignedCredentialCapabilityAttestation(
            self.context.claims,
            alternate_proof,
        )
        object.__setattr__(
            forged_event,
            "_VerifiedCredentialAttestationEvent__envelope",
            alternate_envelope,
        )
        object.__setattr__(forged_event, "_VerifiedCredentialAttestationEvent__claims", self.context.claims)
        object.__setattr__(forged_event, "_VerifiedCredentialAttestationEvent__verified_at", self.context.verified_at)
        object.__setattr__(forged_event, "_VerifiedCredentialAttestationEvent__event_id", self.context.event_id)
        forged = object.__new__(VerifiedRuntimeCredentialContext)
        object.__setattr__(forged, "_VerifiedRuntimeCredentialContext__event", forged_event)
        object.__setattr__(forged, "_VerifiedRuntimeCredentialContext__binding", self.binding)
        object.__setattr__(forged, "_VerifiedRuntimeCredentialContext__owner", weakref.ref(evil))
        self.assertFalse(forged.is_source_owned())

        store = InMemoryAttestationPersistenceStore()
        try:
            with self.assertRaisesRegex(VerifiedAttestationArtifactError, "^verified_attestation_context_unverified$"):
                self._adapter(store).persist_verified_attestation(forged)
            artifact_id = PersistedAttestationArtifact.artifact_id_for(
                self.binding.workspace_identity,
                self.binding.attestation_id,
            )
            self.assertIsNone(store.get_artifact_aggregate(self.binding.workspace_identity, artifact_id))
        finally:
            if hasattr(store, "close"):
                store.close()

    def test_only_concrete_base_service_can_issue_verified_context(self) -> None:
        class EvilRuntimeAttestationService(RuntimeAttestationOrchestrationService):
            def _accepts_verified_event_binding(self, event, binding):
                return True

            def _accepts_verified_context(self, context):
                return True

        evil = EvilRuntimeAttestationService(
            self.runtime.context,
            self.runtime.store,
            orchestration_tests.TRUST,
            orchestration_tests.AttestationRuntimeBoundary(
                self.runtime.fake_issuer,
                self.runtime.fake_issuer,
                self.runtime.fake_issuer,
                orchestration_tests.FakeCapabilityPolicy(),
            ),
            self.runtime.provider,
            self.runtime.resolver,
            clock=lambda: NOW,
        )
        self.assertTrue(self.context.is_source_owned())
        with self.assertRaisesRegex(ValueError, "^verified_runtime_context_source_mismatch$"):
            VerifiedRuntimeCredentialContext._issue(evil, self.context.event, self.binding)

    def test_same_artifact_identity_with_changed_proof_fails_closed(self) -> None:
        store = InMemoryAttestationPersistenceStore()
        try:
            adapter = self._adapter(store)
            adapter.persist_verified_attestation(self.context)
            altered_proof = base64.urlsafe_b64encode(b"x" * 64).decode("ascii").rstrip("=")
            object.__setattr__(self.context.envelope, "proof", altered_proof)
            with self.assertRaisesRegex(VerifiedAttestationArtifactError, "^verified_attestation_context_unverified$"):
                adapter.persist_verified_attestation(self.context)
        finally:
            if hasattr(store, "close"):
                store.close()

    def test_existing_same_id_with_changed_proof_fails_closed(self) -> None:
        store = InMemoryAttestationPersistenceStore()
        try:
            created = (NOW + timedelta(minutes=1)).isoformat(timespec="microseconds").replace("+00:00", "Z")
            altered_proof = base64.urlsafe_b64encode(b"x" * 64).decode("ascii").rstrip("=")
            winner = PersistedAttestationArtifact.create(
                workspace_identity=self.binding.workspace_identity,
                claims_payload=self.context.claims,
                detached_proof=altered_proof,
                original_verified_at=self.context.verified_at,
                created_at=created,
            )
            reference = AttestationBindingReference.create(
                artifact=winner,
                binding_values=self.binding.to_dict(),
            )
            store.persist_artifact(winner, reference)
            with self.assertRaisesRegex(VerifiedAttestationArtifactError, "^verified_attestation_artifact_conflict$"):
                self._adapter(store).persist_verified_attestation(self.context)
        finally:
            if hasattr(store, "close"):
                store.close()

    def test_existing_artifact_with_conflicting_binding_reference_fails_closed(self) -> None:
        store = InMemoryAttestationPersistenceStore()
        try:
            created = (NOW + timedelta(minutes=1)).isoformat(timespec="microseconds").replace("+00:00", "Z")
            winner = PersistedAttestationArtifact.create(
                workspace_identity=self.binding.workspace_identity,
                claims_payload=self.context.claims,
                detached_proof=self.context.envelope.proof,
                original_verified_at=self.context.verified_at,
                created_at=created,
            )
            altered_values = self.binding.to_dict()
            altered_values["binding_id"] = "binding-" + "f" * 64
            reference = AttestationBindingReference.create(
                artifact=winner,
                binding_values=altered_values,
            )
            store.persist_artifact(winner, reference)
            with self.assertRaisesRegex(VerifiedAttestationArtifactError, "^verified_attestation_artifact_conflict$"):
                self._adapter(store).persist_verified_attestation(self.context)
        finally:
            if hasattr(store, "close"):
                store.close()

    def test_conflicting_binding_reference_fails_closed(self) -> None:
        altered = object.__new__(RuntimeCredentialCapabilityBinding)
        for field in RuntimeCredentialCapabilityBinding.__slots__:
            if not field.endswith("__weakref__"):
                object.__setattr__(altered, field, getattr(self.binding, field))
        object.__setattr__(altered, "binding_id", "binding-" + "f" * 64)
        store = InMemoryAttestationPersistenceStore()
        try:
            adapter = self._adapter(store)
            adapter.persist_verified_attestation(self.context)
            forged = object.__new__(VerifiedRuntimeCredentialContext)
            object.__setattr__(forged, "_VerifiedRuntimeCredentialContext__event", self.context.event)
            object.__setattr__(forged, "_VerifiedRuntimeCredentialContext__binding", altered)
            with self.assertRaisesRegex(VerifiedAttestationArtifactError, "^verified_attestation_context_unverified$"):
                adapter.persist_verified_attestation(forged)
        finally:
            if hasattr(store, "close"):
                store.close()

    def test_link_carrier_is_immutable_and_contains_no_store(self) -> None:
        store = InMemoryAttestationPersistenceStore()
        try:
            link = self._adapter(store).persist_verified_attestation(
                self.context
            )
            with self.assertRaises(AttributeError):
                link.credential_binding_id = "binding-" + "0" * 64  # type: ignore[misc]
            with self.assertRaises(AttributeError):
                link.aggregate = link.aggregate  # type: ignore[misc]
            self.assertNotIn("store", link.__dataclass_fields__)
        finally:
            if hasattr(store, "close"):
                store.close()

    def test_persistence_failure_does_not_return_link(self) -> None:
        class FailingStore:
            def get_artifact_aggregate(self, workspace_identity, artifact_id):
                return None

            def persist_artifact(self, artifact, binding_reference):
                raise ValueError("persistence_failed")

        with self.assertRaisesRegex(ValueError, "^persistence_failed$"):
            self._adapter(FailingStore()).persist_verified_attestation(
                self.context
            )

    def test_canonical_factories_reproduce_existing_contract_values(self) -> None:
        claims = make_claims()
        expected_artifact = artifact_for(claims)
        actual_artifact = PersistedAttestationArtifact.create(
            workspace_identity=expected_artifact.workspace_identity,
            claims_payload=claims,
            detached_proof=expected_artifact.detached_proof,
            original_verified_at=expected_artifact.original_verified_at,
            created_at=expected_artifact.created_at,
        )
        self.assertEqual(actual_artifact, expected_artifact)
        self.assertEqual(actual_artifact.artifact_id, "artifact-734d3e7a95d34db5f3880bb769a577c8dd76b34869b8da41f076487c50676dec")
        self.assertEqual(actual_artifact.artifact_digest, "sha256:0aa849503e83f9be968cfc7753f14c69a4935243cf1fd4324ecf094ebdf8beeb")

        expected_reference = reference_for(expected_artifact)
        values = expected_reference.to_payload()
        values["attestation_version"] = "1"
        actual_reference = AttestationBindingReference.create(
            artifact=actual_artifact,
            binding_values=values,
        )
        self.assertEqual(actual_reference, expected_reference)
        self.assertEqual(actual_reference.reference_id, "binding-reference-6540147e60af24b1ccca41295109099e02bc88007ca7b29f4811efe20781be66")
        self.assertEqual(actual_reference.binding_reference_digest, "sha256:68786a166a8f123b98c88eeb10c05752cac3b63e9fd7c0c4d56f11fe675c619a")

    def test_adapter_uses_canonical_factories(self) -> None:
        store = InMemoryAttestationPersistenceStore()
        try:
            original_artifact_create = PersistedAttestationArtifact.create
            original_reference_create = AttestationBindingReference.create
            calls = {"artifact": 0, "reference": 0}

            def artifact_create(*args, **kwargs):
                calls["artifact"] += 1
                return original_artifact_create(*args, **kwargs)

            def reference_create(*args, **kwargs):
                calls["reference"] += 1
                return original_reference_create(*args, **kwargs)

            PersistedAttestationArtifact.create = artifact_create  # type: ignore[method-assign]
            AttestationBindingReference.create = reference_create  # type: ignore[method-assign]
            try:
                self._adapter(store).persist_verified_attestation(self.context)
            finally:
                PersistedAttestationArtifact.create = original_artifact_create  # type: ignore[method-assign]
                AttestationBindingReference.create = original_reference_create  # type: ignore[method-assign]
            self.assertGreaterEqual(calls["artifact"], 1)
            self.assertGreaterEqual(calls["reference"], 1)
        finally:
            if hasattr(store, "close"):
                store.close()

    def test_concurrent_identical_inmemory_first_write_converges(self) -> None:
        store = InMemoryAttestationPersistenceStore()
        barrier = threading.Barrier(2)
        stores = [FirstLookupMissingStore(store, barrier) for _ in range(2)]
        adapters = [
            self._adapter(stores[0], Clock(NOW + timedelta(minutes=1))),
            self._adapter(stores[1], Clock(NOW + timedelta(minutes=2))),
        ]
        try:
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(
                    lambda adapter: adapter.persist_verified_attestation(self.context), adapters
                ))
            self.assertEqual({result.artifact_id for result in results}, {results[0].artifact_id})
            self.assertEqual({result.artifact_digest for result in results}, {results[0].artifact_digest})
            self.assertEqual({result.artifact.created_at for result in results}, {results[0].artifact.created_at})
            self.assertEqual(results[0].binding_reference, results[1].binding_reference)
        finally:
            if hasattr(store, "close"):
                store.close()

    def test_concurrent_identical_sqlite_first_write_converges_across_instances(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        path = Path(temporary.name) / "attestation.sqlite3"
        stores = [
            SQLiteAttestationPersistenceStore(path, workspace_identity=self.binding.workspace_identity)
            for _ in range(2)
        ]
        barrier = threading.Barrier(2)
        wrapped = [FirstLookupMissingStore(store, barrier) for store in stores]
        adapters = [
            self._adapter(wrapped[0], Clock(NOW + timedelta(minutes=1))),
            self._adapter(wrapped[1], Clock(NOW + timedelta(minutes=2))),
        ]
        try:
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(
                    lambda adapter: adapter.persist_verified_attestation(self.context), adapters
                ))
            self.assertEqual({result.artifact_id for result in results}, {results[0].artifact_id})
            self.assertEqual({result.artifact_digest for result in results}, {results[0].artifact_digest})
            self.assertEqual({result.artifact.created_at for result in results}, {results[0].artifact.created_at})
            self.assertEqual(results[0].binding_reference, results[1].binding_reference)
        finally:
            for store in stores:
                store.close()
            temporary.cleanup()

    def test_concurrent_same_id_different_proof_fails_on_conflict_reload(self) -> None:
        class AcceptAnyProofIssuer(orchestration_tests.FakeIssuer):
            def verify(self, payload, proof, issuer_id, key_id, signature_algorithm):
                self.proofs.append(proof)
                self.payloads.append(payload)
                return True

        class AlternateProofProvider(orchestration_tests.FakeCredentialCapabilityProvider):
            def attest(self, request):
                original = super().attest(request)
                alternate_proof = base64.urlsafe_b64encode(b"z" * 64).decode("ascii").rstrip("=")
                self.last_attestation = SignedCredentialCapabilityAttestation(
                    original.claims, alternate_proof
                )
                return self.last_attestation

        issuer = AcceptAnyProofIssuer()
        provider = AlternateProofProvider()
        service = orchestration_tests.RuntimeAttestationOrchestrationService(
            self.runtime.context,
            self.runtime.store,
            orchestration_tests.TRUST,
            orchestration_tests.AttestationRuntimeBoundary(
                issuer, issuer, issuer, orchestration_tests.FakeCapabilityPolicy()
            ),
            provider,
            self.runtime.resolver,
            clock=lambda: NOW,
        )
        alternate_result = service.orchestrate(
            self.runtime.preview["preview_id"], self.runtime.preview["revision"]
        )
        self.assertTrue(alternate_result.success)
        assert alternate_result.verified_context is not None
        self.assertEqual(alternate_result.binding.attestation_id, self.binding.attestation_id)
        self.assertNotEqual(alternate_result.verified_context.envelope.proof, self.context.envelope.proof)

        store = InMemoryAttestationPersistenceStore()
        barrier = threading.Barrier(2)
        stores = [FirstLookupMissingStore(store, barrier) for _ in range(2)]
        adapters = [
            self._adapter(stores[0], Clock(NOW + timedelta(minutes=1))),
            self._adapter(stores[1], Clock(NOW + timedelta(minutes=2))),
        ]

        def invoke(adapter, context):
            try:
                return adapter.persist_verified_attestation(context)
            except VerifiedAttestationArtifactError as exc:
                return exc

        try:
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(
                    invoke,
                    adapters,
                    (self.context, alternate_result.verified_context),
                ))
            links = [result for result in results if isinstance(result, VerifiedCredentialArtifactLink)]
            failures = [result for result in results if isinstance(result, VerifiedAttestationArtifactError)]
            self.assertEqual(len(links), 1)
            self.assertEqual(len(failures), 1)
            self.assertEqual(failures[0].code, "verified_attestation_artifact_conflict")
            persisted = store.get_artifact_aggregate(self.binding.workspace_identity, links[0].artifact_id)
            self.assertIsNotNone(persisted)
            self.assertEqual(persisted, links[0].aggregate)
            self.assertEqual(persisted.artifact.detached_proof, links[0].artifact.detached_proof)
        finally:
            if hasattr(store, "close"):
                store.close()

if __name__ == "__main__":
    unittest.main()
