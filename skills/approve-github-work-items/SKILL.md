---
name: approve-github-work-items
description: Record explicit Human Approval for a specific Delivery System Sealed Preview through delivery_record_approval when the user supplies its exact Preview ID, Revision, approver claim, and exact approval command; do not issue ApplicationAuthority, execute the Applier, or write to GitHub. Do not use for planning, auditing, ordinary code review, PR approval or review, credential authorization, or GitHub Issue mutation.
---

# Approve GitHub Work Items

Record explicit Human Approval for one specific Delivery System Sealed Preview. This Skill guides the current human interaction; Runtime owns identity, persistence, validation, audit eligibility, approval binding, and all trust-sensitive semantics.

## Boundaries

- This Skill does not plan, audit, revise, or create a Preview.
- It does not perform ordinary code review or PR approval/review.
- It does not issue ApplicationAuthority, perform attestation, discover credentials, bind capabilities, or authorize `issues:write`.
- It does not execute the Applier or create, update, comment on, label, or otherwise mutate a GitHub Issue.
- Human Approval can be recorded locally without credentials or attestation bootstrap.

## Required identifiers and target resolution

Require the exact `preview_id` and positive integer `revision` before any MCP call. Exact identifiers may be carried forward without asking the human to retype them only when both came directly from Runtime in the current interaction, still refer to the same ceremony target, and are unambiguous. Always display both identifiers before Approval.

Never guess, derive, or infer identifiers from “that one,” “the latest,” a title, semantic similarity, prior-session memory, or conversation context. Never reuse a stale target or automatically substitute a Revision. If exact current target identity is unavailable or ambiguous, ask for exact `preview_id` and `revision`.

## Guided ceremony

Follow this order exactly:

1. Resolve the exact `preview_id` and `revision`.
2. Call `delivery_get_audit_context` with exactly `{ "preview_id": <preview_id>, "revision": <revision> }`.
3. If the call fails, stop. In particular, `context_stale` or `audit_context_stale` requires the current Preview and Revision and a restarted ceremony; do not request approval for the old Revision.
4. Inspect `audit_scope`. If `audit_scope` is not exactly `WriteEligible`, do not conduct the ceremony and do not call `delivery_record_approval`. Explain that the Preview is not a WriteEligible approval target. This is an early presentation gate; Runtime remains final authority.
5. Present a primary Human Decision Summary using only Runtime-returned evidence. Include, when available, the repository, Preview ID, Revision, WriteEligible scope, Work Item count and titles, intended operation count and types, Issue creation intents, relationship intents, existing remote Issue endpoints, scope/non-goals, and the future external effect. Never fabricate missing information.
6. Render operation intents without changing their meaning. `create_issue` describes the Work Item/title and retains its `client_ref`; `add_sub_issue` describes child → parent; `add_dependency` describes dependent → prerequisite; existing endpoint operands are identified as existing remote Issues with their exact endpoint references; Work Item titles come only from sealed Preview data. If `verify_relationship` is present, describe it as verification/no-duplicate-mutation intent, not another relationship write.
7. Present an `Integrity details` layer separately. Preserve the full exact sealed Preview digest, plan digest, operation-set digest, remote-snapshot digest, audit/context digest when available, rule-registry version/digest when available, and Runtime identifiers. Do not recalculate or omit them, but do not make digest strings the primary decision summary.
8. Explain: “Runtime returned a current sealed context with WriteEligible scope. When Approval is recorded, Runtime will independently require a current WriteEligible Preview and exactly one current Active approval-eligible Passed Audit.” Do not claim that `delivery_get_audit_context` has certified that condition. Audit context retrieval does not retrieve the current AuditRecord, prove `AuditResult=Passed`, prove `approval_eligible=true`, or prove that Approval will succeed.
9. Ask the human for a non-empty `approver_claim`. Explain that it is a human-supplied opaque label recorded with Approval, opaque, unverified provenance, not authentication, not authenticated identity, a verified identity, a GitHub account, a credential, a capability, or authorization proof. Do not use a model-inferred identity, ChatGPT display name, GitHub username discovered elsewhere, OS username, commit author, email address, prior conversation identity, memory, guessed name, or host identity not exposed through a trusted Host contract. Do not rewrite, embellish, authenticate, or fabricate the claim; do not normalize it at the Skill layer. Trusted Host provenance is deferred to PC4.
10. Present the final required command only after the claim is obtained:

    `批准写入 {preview_id} {revision}`

    Present it as clear, copyable exact text. The displayed command is not approval. State that displaying the command is not approval. The human must type and send the complete command.

11. Compare the user’s actual command character-for-character with `f"批准写入 {preview_id} {revision}"`. Do not trim, fuzzy-match, normalize whitespace, paraphrase, translate, substitute yes/no, accept emoji, accept “approve,” accept “批准” alone, or inherit conversational agreement. The Skill may display the command but must never construct `approval_command` as though the human supplied it.
12. If the command is not exact, do not call `delivery_record_approval`. State that Approval was not recorded and show the exact required command again. A near-match remains awaiting the exact command unless the human explicitly abandons.
13. If the exact command is received, immediately call `delivery_record_approval` with exactly `preview_id`, `revision`, `approval_command` equal to the user’s exact command, and the human-provided `approver_claim`. Supply no Runtime-owned IDs, digests, audit values, identity values, authority data, credential data, or extra fields.

## Decline and non-approval text

An explicit cancellation or refusal such as `cancel`, `stop`, `do not approve`, or `abandon` produces the presentation state `Abandoned`. Do not call `delivery_record_approval`, do not create an ApprovalRecord, do not mutate Runtime state, and discard transient ceremony state. State clearly: “No Approval was recorded.” Do not invent a persisted rejection state.

A clarification question, ordinary discussion, unrelated text, or any other non-exact approval text means `NOT APPROVED`; it is not automatically abandonment. Do not call `delivery_record_approval`, do not convert the text into approval, answer or clarify when appropriate, retain exact current context while it remains unambiguous, and continue to require the exact approval command. Only clear cancellation or refusal produces `Abandoned`.

## Timing, replay, recovery, and failure

If state changes after context display, `delivery_record_approval` may fail with `preview_stale`, `audit_not_found`, `audit_stale`, `approval_audit_ambiguous`, or `approval_binding_mismatch`. Stop, do not automatically retry, substitute a Revision, or reuse the command against another Preview. After correction, restart at `delivery_get_audit_context` and obtain fresh exact context and command. Also stop on `workspace_identity_unavailable`, `preview_not_found`, `sealed_preview_unavailable`, `preview_digest_mismatch`, or equivalent integrity failures.

Use these recovery categories:

- Safe interaction correction: a near-match command before any Approval call. Remain in the ceremony; no Runtime mutation occurred.
- Ceremony restart required: `context_stale`, `audit_context_stale`, `preview_stale`, `audit_stale`, `approval_stale`, or `audit_not_found`. Discard stale target state as appropriate and restart from fresh context.
- State investigation required: `approval_audit_ambiguous`, `approval_binding_conflict`, or `approval_binding_mismatch`. Stop; never overwrite, silently choose a target, or retry automatically.
- Integrity/system failure: `preview_digest_mismatch`, `sealed_preview_unavailable`, or `workspace_identity_unavailable`. Fail closed.

For `approval_invalid` or `approval_command_invalid`, report that Approval was not recorded and stop the Runtime attempt. For `approval_binding_conflict`, state that the deterministic Approval identity already has different binding content; never overwrite, silently choose a claim, or retry with fabricated content. For `approval_stale`, report that the existing Approval is no longer current and stop. Default automatic Runtime retry is `NO`.

If `delivery_record_approval` may have completed but the host did not receive a reliable response, do not claim success, do not claim failure, do not automatically repeat the call, and do not issue ApplicationAuthority. Call `delivery_get_approval_status` for the exact Preview and Revision. If it returns `CURRENT`, present the recovered current Approval receipt. If it returns `NO_CURRENT_APPROVAL`, state only that no current persisted Approval was found for the currently resolved binding; do not claim that the earlier call failed or never executed. Require fresh explicit human action before any later Approval attempt. Runtime idempotency remains a safety property, not permission for automatic retry.

Runtime approval replay is idempotent. Return the same persisted Approval receipt when Runtime returns it. A no-call replay optimization is allowed only when the complete exact successful ApprovalRecord is already present in the current interaction and unambiguously matches this request; never assume persisted approval across conversations or uncertain host state.

## MCP boundary

Allowed MCP calls are exactly `delivery_get_audit_context`, `delivery_record_approval`, and `delivery_get_approval_status`. Do not call `delivery_plan_preview`, `delivery_record_audit`, `delivery_issue_application_authority`, `delivery_apply_approved_work_items`, `delivery_get_application_status`, `delivery_observe_application_postcondition`, or any GitHub mutation tool. The Skill must never call `delivery_issue_application_authority`; Approval is not ApplicationAuthority.

## Approval and ApplicationAuthority

Approval is explicit human intent recorded for one exact Preview and Revision. It is not GitHub write permission. ApplicationAuthority is a separate Runtime-issued executable authority requiring current validation, credential attestation, capability checks, and bindings. Application authority is not issued by this Skill.

## Receipt

After success, say “Approval recorded.” Show the Approval ID, Preview ID, Revision, Audit ID, Audit Result, repository identity, approver claim, approved timestamp, and status. Preserve the complete Runtime structured record without recalculation or omission:

`approval_id`, `audit_id`, `audit_digest`, `audit_result`, `preview_id`, `revision`, `plan_digest`, `remote_snapshot_digest`, `operation_set_digest`, `repository_identity`, `approval_command`, `approver_claim`, `approved_at`, `status`.

Also state: “Application authority was not issued. No GitHub mutation was executed.” Do not describe Approval as GitHub write authorization, credential capability, ApplicationAuthority, or completed GitHub work.

## Handoff to Apply

After successful `delivery_record_approval`, preserve the exact Runtime-returned `approval_id`, `preview_id`, and `revision`.

State:

- Approval was recorded;
- no GitHub mutation occurred;
- ApplicationAuthority was not issued;
- Apply remains a separate user job.

If the user explicitly chooses to execute the approved work, the next user-facing Skill is `apply-github-work-items`. Do not invoke Apply automatically because Approval succeeded. Approval records explicit human intent for one exact target; it is not executable GitHub authority.
