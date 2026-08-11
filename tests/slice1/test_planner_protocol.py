import copy
import inspect
import math
import unittest
from dataclasses import FrozenInstanceError

from tests.fakes.fake_driver import FakeDriver
import tests.fakes.fake_driver as fake_module
from tests.fakes.inbox import (
    MANAGED_END,
    MANAGED_START,
    SCHEMA,
    USER_END,
    USER_START,
    InboxProtocolError,
    parse_inbox,
    replace_managed,
)
from delivery_system.planner import Planner
from delivery_system.protocol import (
    Assumption,
    Proposed,
    RemoteItemType,
    LegacyRemoteSnapshot,
    UserFact,
    canonical_payload,
    digest,
)


class PlannerProtocolTests(unittest.TestCase):
    def setUp(self):
        self.request = {
            "title": "Inventory batches",
            "problem": "Inventory lacks batch tracking",
            "outcome": "Users can trace inventory batches",
            "scope": "inventory batch tracking",
            "acceptance_criteria": ["A batch can be recorded"],
            "required_capabilities": ["sub_issues", "dependencies"],
            "proposed": {"issue_type": "feature"},
            "user_facts": {
                "title": "Inventory batches",
                "problem": "Inventory lacks batch tracking",
                "outcome": "Users can trace inventory batches",
                "scope": "inventory batch tracking",
                "acceptance_criteria": ["A batch can be recorded"],
            },
        }

    def test_canonical_payload_ignores_mapping_order(self):
        first = {"b": "value  \n", "a": {"x": 1, "y": 2}}
        second = {"a": {"y": 2, "x": 1}, "b": "value\n"}
        self.assertEqual(canonical_payload(first), canonical_payload(second))

    def test_canonical_payload_ignores_set_order(self):
        self.assertEqual(canonical_payload({"values": {"b", "a"}}), canonical_payload({"values": {"a", "b"}}))

    def test_canonical_payload_preserves_list_order(self):
        self.assertNotEqual(canonical_payload({"values": ["a", "b"]}), canonical_payload({"values": ["b", "a"]}))

    def test_canonical_payload_normalizes_unicode_and_newlines(self):
        self.assertEqual(canonical_payload({"text": "e\u0301\r\nline\r"}), canonical_payload({"text": "é\nline\n"}))

    def test_canonical_payload_trims_line_trailing_and_outer_whitespace(self):
        self.assertEqual(canonical_payload({"text": "  one  \n two \n"}), canonical_payload({"text": "one\n two"}))

    def test_canonical_payload_rejects_non_string_mapping_key(self):
        with self.assertRaises(TypeError):
            canonical_payload({1: "one"})

    def test_canonical_payload_rejects_non_finite_float(self):
        for value in (math.nan, math.inf, -math.inf):
            with self.subTest(value=value), self.assertRaises(ValueError):
                canonical_payload({"value": value})

    def test_canonical_payload_rejects_unsupported_object(self):
        with self.assertRaises(TypeError):
            canonical_payload({"value": object()})

    def test_digest_changes_for_semantic_text(self):
            self.assertNotEqual(digest({"scope": "one"}), digest({"scope": "two"}))

    def test_identical_independent_requests_get_different_request_and_preview_ids(self):
        first = Planner(id_factory=iter(["1" * 32, "2" * 32]).__next__).plan(self.request)
        second = Planner(id_factory=iter(["3" * 32, "4" * 32]).__next__).plan(self.request)
        self.assertNotEqual(first.request_id, second.request_id)
        self.assertNotEqual(first.preview_id, second.preview_id)

    def test_assumption_and_capability_changes_increment_revision(self):
        first = Planner(id_factory=iter(["1" * 32, "2" * 32]).__next__).plan(self.request)
        changed = dict(self.request, assumptions=["repository owner confirmation"])
        second = Planner(id_factory=iter(["3" * 32]).__next__).plan(changed, previous_preview=first)
        self.assertEqual(second.revision, 2)
        changed_caps = dict(self.request, required_capabilities=["issues"])
        third = Planner(id_factory=iter(["4" * 32]).__next__).plan(changed_caps, previous_preview=first)
        self.assertEqual(third.revision, 2)

    def test_unicode_mapping_keys_normalize_and_collisions_fail(self):
        self.assertEqual(canonical_payload({"e\u0301": 1}), canonical_payload({"é": 1}))
        with self.assertRaises(ValueError):
            canonical_payload({"e\u0301": 1, "é": 2})

    def test_acceptance_criteria_string_is_rejected(self):
        with self.assertRaises(TypeError):
            Planner().plan(dict(self.request, user_facts=dict(self.request["user_facts"], acceptance_criteria="one criterion")))

    def test_missing_remote_issue_id_is_rejected_before_findings(self):
        with self.assertRaises(ValueError):
            Planner(FakeDriver(issues=[{"item_type": "issue", "title": "Missing ID"}])).plan(self.request, "owner/repo")

    def test_remote_candidate_fields_are_bound_to_snapshot_digest(self):
        first = Planner(FakeDriver(issues=[{"item_type": "issue", "issue_id": 1, "title": "one", "scope": "a"}])).plan(self.request, "owner/repo")
        second = Planner(FakeDriver(issues=[{"item_type": "issue", "issue_id": 1, "title": "two", "scope": "a"}])).plan(self.request, "owner/repo")
        self.assertNotEqual(first.remote_snapshot_digest, second.remote_snapshot_digest)

    def test_fake_driver_can_simulate_deterministic_read_failure(self):
        with self.assertRaisesRegex(RuntimeError, "fixture failure"):
            Planner(FakeDriver(repository={"read_error": "fixture failure"})).plan(self.request, "owner/repo")

    def test_same_plan_keeps_identity_revision_and_digest(self):
        first = Planner(FakeDriver()).plan(self.request, "owner/repo")
        second = Planner(FakeDriver()).plan(self.request, "owner/repo", previous_preview=first)
        self.assertEqual((first.preview_id, first.revision, first.stable_digest), (second.preview_id, second.revision, second.stable_digest))

    def test_scope_change_keeps_preview_id_increments_revision_and_changes_digest(self):
        first = Planner(FakeDriver()).plan(self.request, "owner/repo")
        changed = dict(self.request, scope="inventory and warehouse batch tracking", user_facts=dict(self.request["user_facts"], scope="inventory and warehouse batch tracking"))
        second = Planner(FakeDriver()).plan(changed, "owner/repo", previous_preview=first)
        self.assertEqual(second.preview_id, first.preview_id)
        self.assertEqual(second.revision, first.revision + 1)
        self.assertNotEqual(second.stable_digest, first.stable_digest)

    def test_acceptance_criteria_change_has_same_revision_behavior(self):
        first = Planner(FakeDriver()).plan(self.request, "owner/repo")
        changed = dict(self.request, acceptance_criteria=["A batch can be recorded", "A batch can be traced"], user_facts=dict(self.request["user_facts"], acceptance_criteria=["A batch can be recorded", "A batch can be traced"]))
        second = Planner(FakeDriver()).plan(changed, "owner/repo", previous_preview=first)
        self.assertEqual(second.preview_id, first.preview_id)
        self.assertEqual(second.revision, 2)
        self.assertNotEqual(second.stable_digest, first.stable_digest)

    def test_request_identifier_is_explicitly_reusable_after_user_supplement(self):
        first = Planner().plan(self.request)
        second = Planner().plan(dict(self.request, scope="new scope", acceptance_criteria=["new criterion"], user_facts=dict(self.request["user_facts"], scope="new scope", acceptance_criteria=["new criterion"])), request_identifier=first.request_id, preview_identifier=first.preview_id)
        self.assertEqual(second.request_id, first.request_id)
        self.assertEqual(second.preview_id, first.preview_id)

    def test_previous_request_id_mismatch_fails(self):
        first = Planner().plan(self.request)
        with self.assertRaises(ValueError):
            Planner().plan(self.request, previous_preview=first, request_identifier="request-" + "f" * 32)

    def test_previous_preview_id_mismatch_fails(self):
        first = Planner().plan(self.request)
        with self.assertRaises(ValueError):
            Planner().plan(self.request, previous_preview=first, preview_identifier="preview-" + "e" * 32)

    def test_revision_does_not_remain_fixed_at_one(self):
        first = Planner().plan(self.request)
        second = Planner().plan(dict(self.request, scope="changed", user_facts=dict(self.request["user_facts"], scope="changed")), previous_preview=first)
        third = Planner().plan(dict(self.request, scope="third", user_facts=dict(self.request["user_facts"], scope="third")), previous_preview=second)
        self.assertEqual((first.revision, second.revision, third.revision), (1, 2, 3))

    def test_only_remote_snapshot_change_keeps_plan_revision_and_marks_stale(self):
        first = Planner(FakeDriver(issues=[{"item_type": "issue", "issue_id": 1, "updated_at": "one"}])).plan(self.request, "owner/repo")
        second = Planner(FakeDriver(issues=[{"item_type": "issue", "issue_id": 1, "updated_at": "two"}])).plan(self.request, "owner/repo", previous_preview=first)
        self.assertEqual(second.revision, first.revision)
        self.assertEqual(second.stable_digest, first.stable_digest)
        self.assertNotEqual(second.remote_snapshot_digest, first.remote_snapshot_digest)
        self.assertTrue(first.is_stale(second.remote_snapshot_digest))

    def test_sources_are_frozen_distinct_and_not_overridable(self):
        values = (UserFact("x"), Proposed("x"), Assumption("x"))
        self.assertEqual({value.to_dict()["kind"] for value in values}, {"user_fact", "proposed", "assumption"})
        with self.assertRaises(FrozenInstanceError):
            values[0].value = "changed"
        with self.assertRaises(TypeError):
            UserFact("x", "proposed")

    def test_source_serialization_is_stable(self):
        self.assertEqual(canonical_payload(UserFact({"b": 1, "a": 2}).to_dict()), canonical_payload(UserFact({"a": 2, "b": 1}).to_dict()))

    def test_proposed_item_marks_each_field_source(self):
        preview = Planner().plan(self.request)
        item = preview.proposed_items[0]
        self.assertEqual(item["title"]["kind"], "user_fact")
        self.assertEqual(item["acceptance_criteria"][0]["kind"], "user_fact")
        default_item = Planner().plan({"problem": "problem"}).proposed_items[0]
        self.assertEqual(default_item["title"]["kind"], "proposed")
        self.assertEqual(default_item["acceptance_criteria"][0]["kind"], "assumption")

    def test_assumption_is_visible_and_never_write_eligible(self):
        preview = Planner().plan({"title": "Only title"})
        self.assertTrue(preview.assumptions)
        self.assertFalse(preview.write_eligible)

    def test_remote_snapshot_normalizes_independent_input_order(self):
        first = LegacyRemoteSnapshot("repo", ("2", "1"), (("2", "now2"), ("1", "now1")), ("z", "a"), (("write", True), ("read", True)))
        second = LegacyRemoteSnapshot("repo", ("1", "2"), (("1", "now1"), ("2", "now2")), ("a", "z"), (("read", True), ("write", True)))
        self.assertEqual(canonical_payload(first.to_dict()), canonical_payload(second.to_dict()))
        self.assertEqual(digest(first.to_dict()), digest(second.to_dict()))

    def test_remote_snapshot_rejects_duplicate_issue_id(self):
        with self.assertRaises(ValueError):
            LegacyRemoteSnapshot("repo", ("1", "1")).to_dict()

    def test_remote_snapshot_contains_query_completeness(self):
        self.assertFalse(LegacyRemoteSnapshot("repo", query_complete=False).to_dict()["query_complete"])

    def test_remote_snapshot_digest_changes_when_remote_state_changes(self):
        self.assertNotEqual(digest(LegacyRemoteSnapshot("repo", ("1",)).to_dict()), digest(LegacyRemoteSnapshot("repo", ("2",)).to_dict()))

    def test_issue_and_pull_request_types_are_explicit(self):
        self.assertEqual(RemoteItemType("issue"), RemoteItemType.ISSUE)
        self.assertEqual(RemoteItemType("pull_request"), RemoteItemType.PULL_REQUEST)

    def test_issue_enters_candidate_and_pr_is_excluded_from_findings_and_snapshot(self):
        driver = FakeDriver(issues=[
            {"item_type": "issue", "issue_id": 1, "title": "Issue"},
            {"item_type": "pull_request", "issue_id": 2, "title": "PR"},
        ])
        preview = Planner(driver).plan(self.request, "owner/repo")
        self.assertEqual([item["issue_id"] for item in preview.duplicate_findings], [1])
        self.assertEqual(preview.remote_snapshot.to_dict()["issue_ids"], ["1"])

    def test_missing_or_unknown_remote_type_fails(self):
        for fixture in ({"issue_id": 1}, {"item_type": "unknown", "issue_id": 1}):
            with self.subTest(fixture=fixture), self.assertRaises(ValueError):
                Planner(FakeDriver(issues=[fixture])).plan(self.request, "owner/repo")

    def test_remote_snapshot_blockers_are_explicit(self):
        driver = FakeDriver(repository={"can_read": True, "permissions": {"read": True, "write": "unknown"}, "capability_conflict": True, "query_complete": False})
        preview = Planner(driver).plan(self.request, "owner/repo")
        self.assertEqual(set(preview.blockers), {"permissions_missing_or_invalid", "capability_detection_conflict", "remote_query_incomplete"})

    def test_exact_identity_requires_runtime_identity_evidence(self):
        request = dict(self.request, item_key="item-1")
        finding = Planner(FakeDriver(issues=[{"item_type": "issue", "issue_id": 9, "item_key": "item-1"}])).plan(request, "owner/repo").duplicate_findings[0]
        self.assertEqual(finding["category"], "exact_identity")

    def test_semantic_overlap_requires_review(self):
        driver = FakeDriver(issues=[{"item_type": "issue", "issue_id": 1, "scope": "inventory"}])
        finding = Planner(driver).plan(self.request, "owner/repo").duplicate_findings[0]
        self.assertEqual(finding["category"], "requires_semantic_review")
        self.assertIn("common_points", finding["evidence"])

    def test_same_title_different_outcome_is_not_exact(self):
        finding = Planner(FakeDriver(issues=[{"item_type": "issue", "issue_id": 1, "title": self.request["title"], "outcome": "different"}])).plan(self.request, "owner/repo").duplicate_findings[0]
        self.assertNotEqual(finding["category"], "exact_identity")

    def test_no_semantic_evidence_requires_review_not_related(self):
        finding = Planner(FakeDriver(issues=[{"item_type": "issue", "issue_id": 1, "title": "Elsewhere"}])).plan(self.request, "owner/repo").duplicate_findings[0]
        self.assertEqual(finding["category"], "requires_semantic_review")

    def test_relationship_evidence_is_separated_from_inference(self):
        findings = Planner(FakeDriver(issues=[
            {"item_type": "issue", "issue_id": 1, "existing_dependency": True},
            {"item_type": "issue", "issue_id": 2, "proposed_parent_candidate": True},
        ])).plan(self.request, "owner/repo").duplicate_findings
        self.assertEqual([item["category"] for item in findings], ["existing_dependency", "proposed_parent_candidate"])

    def test_permission_and_capability_degradation_never_write_eligible(self):
        read_denied = Planner(FakeDriver(repository={"can_read": False})).plan(self.request, "owner/repo")
        capability_gap = Planner(FakeDriver(repository={"can_read": True, "capabilities": ["issues"]})).plan(self.request, "owner/repo")
        self.assertFalse(read_denied.write_eligible)
        self.assertFalse(capability_gap.write_eligible)
        self.assertEqual(capability_gap.capability_gaps, ("dependencies", "sub_issues"))

    def test_input_is_not_mutated(self):
        original = copy.deepcopy(self.request)
        Planner(FakeDriver()).plan(self.request, "owner/repo")
        self.assertEqual(self.request, original)

    def test_fake_driver_records_reads_rejects_writes_and_has_no_network_import(self):
        driver = FakeDriver()
        Planner(driver).plan(self.request, "owner/repo")
        self.assertEqual([entry["operation"] for entry in driver.trace], ["inspect_repository", "search_issues"])
        with self.assertRaises(RuntimeError):
            driver.write()
        self.assertEqual([entry["operation"] for entry in driver.trace], ["inspect_repository", "search_issues", "write"])
        source = inspect.getsource(fake_module)
        for forbidden in ("requests", "urllib", "httpx", "aiohttp", "socket", "subprocess", "os.system"):
            self.assertNotIn(forbidden, source)


class InboxProtocolTests(unittest.TestCase):
    def sample(self, user="User 原文\nline", managed="old"):
        return f"{SCHEMA}\n{USER_START}\n{user}\n{USER_END}\n{MANAGED_START}\n{managed}\n{MANAGED_END}\n"

    def test_normal_parse_and_empty_user(self):
        self.assertEqual(parse_inbox(self.sample(user="")).user_text, "\n\n")
        self.assertEqual(parse_inbox(self.sample()).managed_text, "\nold\n")

    def test_user_original_and_crlf_unicode_are_preserved(self):
        text = self.sample(user="第一行\r\n第二行")
        parsed = parse_inbox(text)
        self.assertEqual(parsed.user_text, "\n第一行\r\n第二行\n")
        updated = replace_managed(text, "new")
        self.assertIn("第一行\r\n第二行", updated)

    def test_managed_replacement_preserves_user_region_bytes(self):
        text = self.sample(user="  exact  \n\tbytes")
        before = parse_inbox(text).user_text
        after = replace_managed(text, "replacement")
        self.assertEqual(parse_inbox(after).user_text, before)

    def test_missing_schema_or_marker_fails_without_partial_result(self):
        text = self.sample().replace(SCHEMA, "")
        with self.assertRaises(InboxProtocolError):
            parse_inbox(text)
        self.assertNotIn("replacement", text)

    def test_missing_start_or_end_fails(self):
        for marker in (USER_START, USER_END, MANAGED_START, MANAGED_END):
            with self.subTest(marker=marker), self.assertRaises(InboxProtocolError):
                parse_inbox(self.sample().replace(marker, ""))

    def test_duplicate_marker_fails(self):
        with self.assertRaises(InboxProtocolError):
            parse_inbox(self.sample() + USER_START)

    def test_order_inversion_fails(self):
        text = f"{SCHEMA}\n{USER_END}\n{USER_START}\n{MANAGED_START}\n{MANAGED_END}"
        with self.assertRaises(InboxProtocolError):
            parse_inbox(text)

    def test_nested_or_cross_region_marker_fails(self):
        for marker in (USER_START, USER_END, MANAGED_START, MANAGED_END):
            with self.subTest(marker=marker), self.assertRaises(InboxProtocolError):
                parse_inbox(self.sample(user="bad " + marker))

    def test_invalid_input_does_not_modify_original(self):
        text = self.sample().replace(MANAGED_END, "")
        original = text
        with self.assertRaises(InboxProtocolError):
            replace_managed(text, "replacement")
        self.assertEqual(text, original)

    def test_replacement_content_cannot_nest_protocol_markers(self):
        with self.assertRaises(InboxProtocolError):
            replace_managed(self.sample(), "bad " + USER_START)


if __name__ == "__main__":
    unittest.main()
