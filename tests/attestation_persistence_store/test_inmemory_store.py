from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import unittest

from delivery_system.attestation_persistence import (
    ATTESTATION_REVALIDATION_FAILURE_CODES,
    PersistenceContractError,
)
from delivery_system.attestation_persistence_store import (
    AttestationArtifactAggregate,
    InMemoryAttestationPersistenceStore,
    SequencedAttestationRevalidationEvent,
)
from tests.fakes.attestation_persistence_store_contract import (
    DIGEST_E,
    artifact_for,
    event_for,
    expect_code,
    reference_for,
    run_shared_store_contract,
)


class InMemoryStoreTests(unittest.TestCase):
    def _stored(self):
        artifact = artifact_for()
        reference = reference_for(artifact)
        store = InMemoryAttestationPersistenceStore()
        store.persist_artifact(artifact, reference)
        return store, artifact, reference

    def _stored_event(self):
        store, artifact, reference = self._stored()
        event = event_for(artifact, reference)
        store.append_revalidation_event(event)
        return store, artifact, reference, event

    @staticmethod
    def _state(store: InMemoryAttestationPersistenceStore) -> str:
        return repr((
            store._artifact_snapshots,
            store._reference_snapshots,
            store._aggregate_keys,
            store._event_snapshots,
            store._event_partitions,
        ))

    def _assert_all_operations_fail_without_state_change(
        self, store, artifact, reference, event, code: str,
    ) -> None:
        key = (artifact.workspace_identity, artifact.artifact_id)
        before = self._state(store)
        operations = (
            lambda: store.persist_artifact(artifact, reference),
            lambda: store.get_artifact_aggregate(*key),
            lambda: store.append_revalidation_event(event),
            lambda: store.get_latest_revalidation_event(*key),
        )
        for operation in operations:
            expect_code(self, code, operation)
            self.assertEqual(self._state(store), before)

    def test_shared_store_contract(self) -> None:
        def corruptor(store: InMemoryAttestationPersistenceStore, kind: str) -> None:
            artifact = artifact_for()
            key = (artifact.workspace_identity, artifact.artifact_id)
            if kind == "aggregate":
                del store._reference_snapshots[key]

        run_shared_store_contract(self, InMemoryAttestationPersistenceStore, corruptor)

    def test_instances_are_isolated_and_new_instance_is_empty(self) -> None:
        artifact = artifact_for()
        reference = reference_for(artifact)
        event = event_for(artifact, reference)
        first = InMemoryAttestationPersistenceStore()
        first.persist_artifact(artifact, reference)
        first.append_revalidation_event(event)
        second = InMemoryAttestationPersistenceStore()
        self.assertIsNone(second.get_artifact_aggregate(artifact.workspace_identity, artifact.artifact_id))
        expect_code(self, "attestation_artifact_not_found", lambda: second.get_latest_revalidation_event(artifact.workspace_identity, artifact.artifact_id))
        self.assertEqual(first.get_latest_revalidation_event(artifact.workspace_identity, artifact.artifact_id).event_sequence, 1)
        self.assertFalse(hasattr(second, "export"))
        self.assertFalse(hasattr(second, "restore"))

    def test_public_store_surface_has_only_four_contract_methods(self) -> None:
        public = {
            name for name in dir(InMemoryAttestationPersistenceStore)
            if not name.startswith("_")
        }
        self.assertEqual(public, {
            "append_revalidation_event", "get_artifact_aggregate",
            "get_latest_revalidation_event", "persist_artifact",
        })

    def test_query_keys_are_strict_and_canonical(self) -> None:
        artifact = artifact_for(workspace="  workspace-1  ")
        reference = reference_for(artifact)
        store = InMemoryAttestationPersistenceStore()
        store.persist_artifact(artifact, reference)
        self.assertIsNotNone(store.get_artifact_aggregate(" workspace-1 ", artifact.artifact_id))
        expect_code(self, "attestation_persistence_type_invalid", lambda: store.get_artifact_aggregate(True, artifact.artifact_id))
        expect_code(self, "attestation_persistence_payload_invalid", lambda: store.get_artifact_aggregate("workspace-1", "bad-id"))

    def test_corrupt_internal_event_snapshot_fails_closed(self) -> None:
        artifact = artifact_for()
        reference = reference_for(artifact)
        event = event_for(artifact, reference)
        store = InMemoryAttestationPersistenceStore()
        store.persist_artifact(artifact, reference)
        store.append_revalidation_event(event)
        key = (artifact.workspace_identity, artifact.artifact_id)
        sequence, _ = store._event_snapshots[key][event.event_id]
        store._event_snapshots[key][event.event_id] = (sequence + 1, "{}")
        expect_code(self, "attestation_revalidation_event_corrupt", lambda: store.get_latest_revalidation_event(*key))

    def test_event_snapshot_decode_failures_are_event_corruption(self) -> None:
        for snapshot in ("not-json", "[]", "null", json.dumps({"outcome": "bad"})):
            store, artifact, _, event = self._stored_event()
            key = (artifact.workspace_identity, artifact.artifact_id)
            store._event_snapshots[key][event.event_id] = (1, snapshot)
            expect_code(
                self, "attestation_revalidation_event_corrupt",
                lambda: store.get_latest_revalidation_event(*key),
            )

    def test_aggregate_marker_and_snapshot_combinations_fail_closed(self) -> None:
        store, artifact, _, = self._stored()
        key = (artifact.workspace_identity, artifact.artifact_id)
        del store._aggregate_keys
        expect_code(self, "attestation_artifact_aggregate_corrupt", lambda: store.get_artifact_aggregate(*key))

        store, artifact, _ = self._stored()
        key = (artifact.workspace_identity, artifact.artifact_id)
        store._aggregate_keys.remove(key)
        expect_code(self, "attestation_artifact_aggregate_corrupt", lambda: store.get_artifact_aggregate(*key))

        store, artifact, _ = self._stored()
        key = (artifact.workspace_identity, artifact.artifact_id)
        del store._artifact_snapshots[key]
        del store._reference_snapshots[key]
        expect_code(self, "attestation_artifact_aggregate_corrupt", lambda: store.get_artifact_aggregate(*key))

    def test_aggregate_registry_container_and_snapshot_types_fail_closed(self) -> None:
        store, artifact, _ = self._stored()
        key = (artifact.workspace_identity, artifact.artifact_id)
        store._artifact_snapshots = None
        expect_code(self, "attestation_artifact_aggregate_corrupt", lambda: store.get_artifact_aggregate(*key))

        store, artifact, _ = self._stored()
        key = (artifact.workspace_identity, artifact.artifact_id)
        store._reference_snapshots = []
        expect_code(self, "attestation_artifact_aggregate_corrupt", lambda: store.get_artifact_aggregate(*key))

        store, artifact, _ = self._stored()
        key = (artifact.workspace_identity, artifact.artifact_id)
        store._aggregate_keys = []
        expect_code(self, "attestation_artifact_aggregate_corrupt", lambda: store.get_artifact_aggregate(*key))

        class TextAlias(str):
            pass

        store, artifact, _ = self._stored()
        key = (artifact.workspace_identity, artifact.artifact_id)
        store._artifact_snapshots[key] = TextAlias(store._artifact_snapshots[key])
        expect_code(self, "attestation_artifact_aggregate_corrupt", lambda: store.get_artifact_aggregate(*key))

    def test_event_registry_marker_and_partition_types_fail_closed(self) -> None:
        store, artifact, _, _ = self._stored_event()
        key = (artifact.workspace_identity, artifact.artifact_id)
        del store._event_partitions
        expect_code(self, "attestation_revalidation_event_corrupt", lambda: store.get_latest_revalidation_event(*key))

        store, artifact, _, _ = self._stored_event()
        key = (artifact.workspace_identity, artifact.artifact_id)
        store._event_partitions.remove(key)
        expect_code(self, "attestation_revalidation_event_corrupt", lambda: store.get_latest_revalidation_event(*key))

        store, artifact, _, _ = self._stored_event()
        key = (artifact.workspace_identity, artifact.artifact_id)
        store._event_snapshots[key] = {}
        expect_code(self, "attestation_revalidation_event_corrupt", lambda: store.get_latest_revalidation_event(*key))

        store, artifact, _, _ = self._stored_event()
        key = (artifact.workspace_identity, artifact.artifact_id)
        store._event_snapshots = None
        expect_code(self, "attestation_revalidation_event_corrupt", lambda: store.get_latest_revalidation_event(*key))

        store, artifact, _, _ = self._stored_event()
        key = (artifact.workspace_identity, artifact.artifact_id)
        store._event_partitions = []
        expect_code(self, "attestation_revalidation_event_corrupt", lambda: store.get_latest_revalidation_event(*key))

    def test_aggregate_partition_keys_are_exact_and_canonical(self) -> None:
        class TupleAlias(tuple):
            pass

        class TextAlias(str):
            pass

        cases = ("marker", "artifact", "reference", "workspace-subclass", "artifact-subclass",
                 "whitespace", "non-nfc", "bad-artifact")
        for case in cases:
            store, artifact, reference, event = self._stored_event()
            key = (artifact.workspace_identity, artifact.artifact_id)
            if case == "marker":
                store._aggregate_keys.remove(key)
                store._aggregate_keys.add(TupleAlias(key))
            elif case == "artifact":
                value = store._artifact_snapshots.pop(key)
                store._artifact_snapshots[TupleAlias(key)] = value
            elif case == "reference":
                value = store._reference_snapshots.pop(key)
                store._reference_snapshots[TupleAlias(key)] = value
            elif case == "workspace-subclass":
                bad = (TextAlias(key[0]), key[1])
                value = store._artifact_snapshots.pop(key)
                store._artifact_snapshots[bad] = value
            elif case == "artifact-subclass":
                bad = (key[0], TextAlias(key[1]))
                value = store._reference_snapshots.pop(key)
                store._reference_snapshots[bad] = value
            elif case == "whitespace":
                bad = (" " + key[0], key[1])
                value = store._aggregate_keys.pop()
                store._aggregate_keys.add(bad)
            elif case == "non-nfc":
                bad = ("cafe\u0301", key[1])
                value = store._aggregate_keys.pop()
                store._aggregate_keys.add(bad)
            else:
                bad = (key[0], "not-an-artifact-id")
                value = store._aggregate_keys.pop()
                store._aggregate_keys.add(bad)
            self._assert_all_operations_fail_without_state_change(
                store, artifact, reference, event,
                "attestation_artifact_aggregate_corrupt",
            )

    def test_event_partition_keys_are_exact_and_canonical(self) -> None:
        class TupleAlias(tuple):
            pass

        class TextAlias(str):
            pass

        cases = ("marker", "outer", "member", "workspace-subclass", "noncanonical")
        for case in cases:
            store, artifact, reference, event = self._stored_event()
            key = (artifact.workspace_identity, artifact.artifact_id)
            if case == "marker":
                store._event_partitions.remove(key)
                store._event_partitions.add(TupleAlias(key))
            elif case == "outer":
                value = store._event_snapshots.pop(key)
                store._event_snapshots[TupleAlias(key)] = value
            elif case == "member":
                bad = (TextAlias(key[0]), key[1])
                value = store._event_partitions.pop()
                store._event_partitions.add(bad)
            elif case == "workspace-subclass":
                bad = (TextAlias(key[0]), key[1])
                value = store._event_snapshots.pop(key)
                store._event_snapshots[bad] = value
            else:
                bad = (" workspace-1 ", key[1])
                value = store._event_partitions.pop()
                store._event_partitions.add(bad)
            self._assert_all_operations_fail_without_state_change(
                store, artifact, reference, event,
                "attestation_revalidation_event_corrupt",
            )

    def test_hidden_invalid_partitions_are_not_not_found(self) -> None:
        class TupleAlias(tuple):
            pass

        artifact = artifact_for()
        reference = reference_for(artifact)
        event = event_for(artifact, reference)
        store = InMemoryAttestationPersistenceStore()
        hidden = ("hidden-workspace", artifact.artifact_id)
        store._aggregate_keys.add(TupleAlias(hidden))
        expect_code(
            self, "attestation_artifact_aggregate_corrupt",
            lambda: store.get_artifact_aggregate("other-workspace", artifact.artifact_id),
        )

        store = InMemoryAttestationPersistenceStore()
        store._event_partitions.add(TupleAlias(hidden))
        expect_code(
            self, "attestation_revalidation_event_corrupt",
            lambda: store.get_latest_revalidation_event("other-workspace", artifact.artifact_id),
        )

    def test_orphan_event_state_blocks_all_operations_without_repair(self) -> None:
        store, artifact, reference, event = self._stored_event()
        key = (artifact.workspace_identity, artifact.artifact_id)
        del store._artifact_snapshots[key]
        del store._reference_snapshots[key]
        store._aggregate_keys.remove(key)
        for operation in (
            lambda: store.get_artifact_aggregate(*key),
            lambda: store.get_latest_revalidation_event(*key),
            lambda: store.append_revalidation_event(event),
            lambda: store.persist_artifact(artifact, reference),
        ):
            expect_code(self, "attestation_revalidation_event_corrupt", operation)

    def test_corrupt_sequence_gap_and_duplicate_fail_closed(self) -> None:
        artifact = artifact_for()
        reference = reference_for(artifact)
        store = InMemoryAttestationPersistenceStore()
        store.persist_artifact(artifact, reference)
        first = event_for(artifact, reference, attempt_id="attempt-" + "1" * 32)
        second = event_for(artifact, reference, attempt_id="attempt-" + "2" * 32)
        store.append_revalidation_event(first)
        store.append_revalidation_event(second)
        key = (artifact.workspace_identity, artifact.artifact_id)
        sequence, snapshot = store._event_snapshots[key][second.event_id]
        store._event_snapshots[key][second.event_id] = (sequence + 2, snapshot)
        expect_code(self, "attestation_revalidation_event_corrupt", lambda: store.get_latest_revalidation_event(*key))

    def test_missing_event_index_after_append_fails_closed(self) -> None:
        artifact = artifact_for()
        reference = reference_for(artifact)
        store = InMemoryAttestationPersistenceStore()
        store.persist_artifact(artifact, reference)
        store.append_revalidation_event(event_for(artifact, reference))
        key = (artifact.workspace_identity, artifact.artifact_id)
        del store._event_snapshots[key]
        expect_code(self, "attestation_revalidation_event_corrupt", lambda: store.get_latest_revalidation_event(*key))

    def test_missing_aggregate_side_is_corrupt_without_repair(self) -> None:
        artifact = artifact_for()
        reference = reference_for(artifact)
        store = InMemoryAttestationPersistenceStore()
        store.persist_artifact(artifact, reference)
        key = (artifact.workspace_identity, artifact.artifact_id)
        del store._artifact_snapshots[key]
        expect_code(self, "attestation_artifact_aggregate_corrupt", lambda: store.get_artifact_aggregate(*key))
        self.assertNotIn(key, store._artifact_snapshots)
        self.assertIn(key, store._reference_snapshots)

    def test_missing_both_aggregate_snapshots_after_write_is_corrupt(self) -> None:
        artifact = artifact_for()
        reference = reference_for(artifact)
        store = InMemoryAttestationPersistenceStore()
        store.persist_artifact(artifact, reference)
        key = (artifact.workspace_identity, artifact.artifact_id)
        del store._artifact_snapshots[key]
        del store._reference_snapshots[key]
        expect_code(self, "attestation_artifact_aggregate_corrupt", lambda: store.get_artifact_aggregate(*key))

    def test_returned_event_projection_isolated(self) -> None:
        artifact = artifact_for()
        reference = reference_for(artifact)
        event = event_for(artifact, reference)
        store = InMemoryAttestationPersistenceStore()
        store.persist_artifact(artifact, reference)
        returned = store.append_revalidation_event(event)
        object.__setattr__(returned, "event", event_for(artifact, reference, outcome="Failed",
                                                         failure_code=next(iter(ATTESTATION_REVALIDATION_FAILURE_CODES)),
                                                         result_digest=None))
        fresh = store.get_latest_revalidation_event(artifact.workspace_identity, artifact.artifact_id)
        self.assertEqual(fresh.event.outcome, "Successful")
        self.assertEqual(fresh.event.event_payload_digest, event.event_payload_digest)

    def test_concurrent_same_aggregate_converges(self) -> None:
        artifact = artifact_for()
        reference = reference_for(artifact)
        store = InMemoryAttestationPersistenceStore()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: store.persist_artifact(artifact, reference), range(8)))
        self.assertEqual({result.artifact.artifact_digest for result in results}, {artifact.artifact_digest})
        self.assertEqual(len(store._artifact_snapshots), 1)
        self.assertEqual(len(store._reference_snapshots), 1)

    def test_concurrent_conflicting_aggregate_has_one_winner(self) -> None:
        artifact = artifact_for()
        reference = reference_for(artifact)
        store = InMemoryAttestationPersistenceStore()

        def save(value):
            try:
                store.persist_artifact(artifact, value)
                return "ok"
            except PersistenceContractError as exc:
                return exc.code

        candidates = [
            reference_for(artifact, binding_id=f"binding-{index:064x}")
            for index in range(1, 9)
        ]
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(save, candidates))
        self.assertEqual(results.count("ok"), 1)
        self.assertEqual(results.count("attestation_binding_reference_conflict"), 7)

    def test_concurrent_same_event_has_one_sequence(self) -> None:
        artifact = artifact_for()
        reference = reference_for(artifact)
        event = event_for(artifact, reference)
        store = InMemoryAttestationPersistenceStore()
        store.persist_artifact(artifact, reference)
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: store.append_revalidation_event(event), range(8)))
        self.assertEqual({result.event_sequence for result in results}, {1})

    def test_concurrent_distinct_events_are_contiguous(self) -> None:
        artifact = artifact_for()
        reference = reference_for(artifact)
        events = [event_for(artifact, reference, attempt_id=f"attempt-{index:032x}") for index in range(1, 9)]
        store = InMemoryAttestationPersistenceStore()
        store.persist_artifact(artifact, reference)
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(store.append_revalidation_event, events))
        self.assertEqual({result.event_sequence for result in results}, set(range(1, 9)))
        self.assertEqual(store.get_latest_revalidation_event(artifact.workspace_identity, artifact.artifact_id).event_sequence, 8)

    def test_no_sequence_or_current_authority_on_domain_event(self) -> None:
        artifact = artifact_for()
        reference = reference_for(artifact)
        event = event_for(artifact, reference)
        self.assertNotIn("event_sequence", event.to_payload())
        self.assertFalse(hasattr(event, "write_eligible"))
        self.assertFalse(hasattr(event, "current_capability"))
        self.assertNotIn("attestation_artifact_aggregate_corrupt", ATTESTATION_REVALIDATION_FAILURE_CODES)
        self.assertNotIn("attestation_attempt_replayed", ATTESTATION_REVALIDATION_FAILURE_CODES)

    def test_projection_keysets_and_types_are_closed(self) -> None:
        store, artifact, reference, event = self._stored_event()
        aggregate = store.get_artifact_aggregate(artifact.workspace_identity, artifact.artifact_id)
        sequenced = store.get_latest_revalidation_event(artifact.workspace_identity, artifact.artifact_id)

        class DictAlias(dict):
            pass

        class KeyAlias(str):
            pass

        for constructor, payload in (
            (AttestationArtifactAggregate.from_untrusted, {"artifact": artifact}),
            (SequencedAttestationRevalidationEvent.from_untrusted, {"event_sequence": 1}),
        ):
            expect_code(self, "attestation_persistence_keyset_invalid", lambda: constructor(payload))

        bad_aggregate = DictAlias(aggregate.to_payload())
        expect_code(self, "attestation_persistence_type_invalid", lambda: AttestationArtifactAggregate.from_untrusted(bad_aggregate))
        bad_event = DictAlias(sequenced.to_payload())
        expect_code(self, "attestation_persistence_type_invalid", lambda: SequencedAttestationRevalidationEvent.from_untrusted(bad_event))

        aggregate_payload = aggregate.to_payload()
        aggregate_payload[KeyAlias("artifact")] = aggregate_payload.pop("artifact")
        expect_code(self, "attestation_persistence_keyset_invalid", lambda: AttestationArtifactAggregate.from_untrusted(aggregate_payload))

        event_payload = sequenced.to_payload()
        event_payload[KeyAlias("event")] = event_payload.pop("event")
        expect_code(self, "attestation_persistence_keyset_invalid", lambda: SequencedAttestationRevalidationEvent.from_untrusted(event_payload))

        forged_aggregate = object.__new__(AttestationArtifactAggregate)
        object.__setattr__(forged_aggregate, "artifact", artifact)
        expect_code(self, "attestation_persistence_payload_invalid", lambda: AttestationArtifactAggregate.from_untrusted(forged_aggregate))

        forged_event = object.__new__(SequencedAttestationRevalidationEvent)
        object.__setattr__(forged_event, "event_sequence", True)
        object.__setattr__(forged_event, "event", event)
        expect_code(self, "attestation_persistence_type_invalid", lambda: SequencedAttestationRevalidationEvent.from_untrusted(forged_event))

        class IntAlias(int):
            pass

        event_payload = sequenced.to_payload()
        event_payload["event_sequence"] = IntAlias(1)
        expect_code(self, "attestation_persistence_type_invalid", lambda: SequencedAttestationRevalidationEvent.from_untrusted(event_payload))

    def test_shared_contract_exports_are_defined(self) -> None:
        import tests.fakes.attestation_persistence_store_contract as contract
        for name in contract.__all__:
            self.assertTrue(hasattr(contract, name), name)


if __name__ == "__main__":
    unittest.main()
