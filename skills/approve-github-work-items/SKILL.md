---
name: approve-github-work-items
description: Record explicit Human Approval for a specific Delivery System Sealed Preview through delivery_record_approval when the user supplies its exact Preview ID, Revision, approver claim, and exact approval command; do not issue ApplicationAuthority, execute the Applier, or write to GitHub. Do not use for planning, auditing, ordinary code review, PR approval or review, credential authorization, or GitHub Issue mutation.
---

# Approve GitHub Work Items

Record explicit Human Approval for one specific Delivery System Sealed Preview. This Skill orchestrates the host interaction; Runtime owns identity, persistence, validation, audit eligibility, approval binding, and all trust-sensitive semantics.

## Boundaries

- This Skill does not plan, audit, revise, or create a Preview.
- It does not perform ordinary code review or PR approval/review.
- It does not issue ApplicationAuthority, perform attestation, discover credentials, bind capabilities, or authorize `issues:write`.
- It does not execute the Applier or create, update, comment on, label, or otherwise mutate a GitHub Issue.
- Human Approval can be recorded locally without credentials or attestation bootstrap.

## Required identifiers

Require the exact `preview_id` and positive integer `revision` before any MCP call. Ask for a missing value. Never guess, derive, or infer identifiers from “that one,” “the latest,” semantic similarity, or conversation context. Reuse an identifier only when it is an exact Runtime-returned value in the current interaction and its referent is unambiguous.

## Ceremony

Follow this order exactly:

1. Resolve the exact `preview_id` and `revision`.
2. Call `delivery_get_audit_context` with exactly `{ "preview_id": <preview_id>, "revision": <revision> }`.
3. If the call fails, stop. In particular, `context_stale` requires the current Preview and Revision and a restarted ceremony; do not request approval for the old Revision.
4. Inspect `audit_scope`. If `audit_scope` is not exactly `WriteEligible`, do not conduct the ceremony and do not call `delivery_record_approval`. Explain that the Preview is not a WriteEligible approval target. This is an early presentation gate; Runtime remains final authority.
5. Present the exact Runtime-returned object being approved. At minimum show the Preview ID, Revision, Audit Scope, repository identity, sealed Preview digest, plan digest, operation-set digest, remote-snapshot digest, and operation intents/intended operations from `sealed_preview` and the context response. A concise presentation summary is presentation text, not a Runtime-owned field. Never invent or recalculate digest values.
6. Explain: “When Approval is recorded, the Runtime will independently require a current WriteEligible Preview and exactly one current Active approval-eligible Passed Audit.” Do not claim that `delivery_get_audit_context` has certified that condition. Audit context retrieval does not retrieve the current AuditRecord, prove `AuditResult=Passed`, prove `approval_eligible=true`, or prove that Approval will succeed.
7. Ask the human for a non-empty `approver_claim`. It is opaque, unverified provenance, not authenticated identity. Do not use a model-inferred identity, ChatGPT display name, GitHub username discovered elsewhere, OS username, commit author, email address, prior conversation identity, memory, guessed name, or host identity not exposed through a trusted Host contract. Do not rewrite, embellish, authenticate, or fabricate the claim. Trusted Host provenance is deferred to PC4.
8. Present the final required command only after the claim is obtained:

   `批准写入 {preview_id} {revision}`

   The displayed command is not approval. The human must type and send the complete command.

9. Compare the user’s actual command character-for-character with `f"批准写入 {preview_id} {revision}"`. Do not trim, fuzzy-match, paraphrase, translate, substitute yes/no, accept emoji, accept “approve,” accept “批准” alone, or inherit conversational agreement. The Skill may display the command but must never construct `approval_command` as though the human supplied it.
10. If the command is not exact, do not call `delivery_record_approval`; ask the human to enter the exact displayed command. If it is exact, immediately call `delivery_record_approval` with exactly `preview_id`, `revision`, `approval_command` equal to the user’s exact command, and the human-provided `approver_claim`. Supply no Runtime-owned IDs, digests, audit values, or extra fields.

## Timing, replay, and failure

If state changes after context display, `delivery_record_approval` may fail with `preview_stale`, `audit_not_found`, `audit_stale`, `approval_audit_ambiguous`, or `approval_binding_mismatch`. Stop, do not automatically retry, substitute a Revision, or reuse the command against another Preview. After correction, restart at `delivery_get_audit_context` and obtain a fresh exact command. Also stop on `workspace_identity_unavailable`, `preview_not_found`, `sealed_preview_unavailable`, `preview_digest_mismatch`, or equivalent integrity failures.

For `approval_invalid` or `approval_command_invalid`, report the Runtime rejection and stop. For `approval_binding_conflict`, state that the deterministic Approval identity already has different binding content; never overwrite, silently choose a claim, or retry with fabricated content. For `approval_stale`, report that the existing Approval is no longer current and stop.

Runtime approval replay is idempotent. Return the same persisted Approval receipt when Runtime returns it. There is no read-Approval MCP tool. A no-call replay optimization is allowed only when the exact successful ApprovalRecord is already present in the current interaction and unambiguously matches this request; never assume persisted approval across conversations or uncertain host state.

## MCP boundary

Allowed MCP calls are exactly `delivery_get_audit_context` and `delivery_record_approval`. Do not call `delivery_plan_preview`, `delivery_record_audit`, `delivery_issue_application_authority`, or any GitHub mutation tool. The Skill must never call `delivery_issue_application_authority`; Approval is not ApplicationAuthority.

## Receipt

After success, say “Approval recorded.” Show the Approval ID, Preview ID, Revision, Audit ID, Audit Result, repository identity, approver claim, approved timestamp, and status. Preserve the complete Runtime structured record without recalculation or omission:

`approval_id`, `audit_id`, `audit_digest`, `audit_result`, `preview_id`, `revision`, `plan_digest`, `remote_snapshot_digest`, `operation_set_digest`, `repository_identity`, `approval_command`, `approver_claim`, `approved_at`, `status`.

Also state: “Application authority was not issued. No GitHub mutation was executed.” Do not describe Approval as GitHub write authorization, credential capability, ApplicationAuthority, or completed GitHub work.
