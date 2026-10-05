---
name: apply-github-work-items
description: Apply one exact, explicitly approved Delivery System Sealed Preview through the bounded application path when a user asks to execute approved GitHub work items. Do not use for planning, auditing, approval, arbitrary GitHub writes, or recovery reconciliation.
---

# Apply GitHub Work Items

Apply one exact Delivery System Sealed Preview and its approved operation set. Apply is a user job separate from planning, independent audit, and Human Approval. It may perform irreversible GitHub Issue mutations within the already approved boundary.

## Preconditions and handoff

- Require the exact `preview_id` and positive integer `revision`.
- Require the exact successful Human Approval context for that Preview and Revision, including the Runtime-returned `approval_id`. Human Approval handoff does not supply `approval_digest`; do not require a caller-known digest at Skill entry. Do not infer approval from conversation agreement, a prior Preview, or a semantic match. If the exact approval context is unavailable, stop and ask the user to complete or provide the approval handoff.
- Never calculate or derive `approval_digest`, hash an ApprovalRecord outside Runtime, ask the user for it, read raw SQLite to obtain it, or use a model- or Host-generated value.
- Treat the approval context as proof of which object was approved, not as executable authority. Human Approval remains distinct from ApplicationAuthority and application.
- Do not ask the user to construct, copy, or manipulate an `ApplicationAuthority` ID. The Skill owns the internal handoff to the existing Runtime support path.

## Workflow

1. Resolve the exact approved `preview_id`, `revision`, and Runtime-returned `approval_id`. Never substitute “latest”, “that one”, or a guessed identifier.
2. Call `delivery_get_audit_context` for the exact Preview and Revision. Stop if the context is missing, stale, integrity-invalid, or not suitable for the existing Runtime gate.
3. Call `delivery_issue_application_authority` internally using exactly `preview_id`, `revision`, and `approval_id`; do not supply `approval_digest`. Runtime independently resolves and validates the durable Approval and its full Preview/Audit binding. This issues the protected executable authority; it is not a separate user objective and it does not write GitHub.
4. Require a complete, valid Runtime-returned ApplicationAuthority receipt containing a non-empty `approval_digest`. If Authority issuance fails, is stale or integrity-invalid, or the receipt is incomplete or lacks `approval_digest`, stop without calling Apply. Do not derive or substitute a digest.
5. Immediately after successful Authority issuance and before calling `delivery_apply_approved_work_items`, retain the exact Runtime-owned `preview_id`, `revision`, `approval_id`, and `approval_digest`. The digest source is the Runtime-returned ApplicationAuthority output, not the Approval receipt/status, model or Host calculation, user input, or SQLite inspection. Retain these four values as the lost-result recovery context.
6. Pass only the Runtime-returned ApplicationAuthority to `delivery_apply_approved_work_items` and invoke the existing bounded Apply path.
7. Use the returned durable application state and receipt exactly as returned. Do not calculate, replace, or invent Runtime-owned identifiers, digests, states, or recovery values.

If the Apply response is lost or ambiguous before the Application ID is safely handed off, do not invoke Apply again. Use the exact `preview_id`, `revision`, `approval_id`, and `approval_digest` retained immediately after successful ApplicationAuthority issuance and before Apply dispatch. Call `delivery_get_application_status` with exactly those four values. Interpret the returned Runtime-owned status without retry, resume, or reconciliation. Do not derive the digest later, issue another Authority merely to recover it, invent an Application ID, enumerate workspace state, or inspect raw SQLite. If the lookup returns `application_not_found`, state only that no matching durable Application was found; do not claim that Apply did not run or that GitHub was not mutated.

## Responsibility boundary

Apply does not own or perform planning, audit creation, Human Approval creation or modification, credential discovery, arbitrary GitHub writes, arbitrary Driver invocation or use, schema or database administration or migration, revocation checks or authoritative revocation decisions, or any other post-V1 revocation lifecycle. It does not call planning, audit-recording, approval-recording, direct GitHub mutation, or arbitrary Driver tools, and it does not bypass the bounded Applier.

## Result and recovery

- Report definitive success only for a durable `Applied` result supported by the returned application receipt.
- Report `Failed` or `Blocked` as a definitive failure with the Runtime result.
- Treat `OutcomeUnknown`, an ambiguous execution result, or a recovery-required result as terminal for this Skill. Stop immediately, state that the remote effect may already have occurred, state that durable evidence has been retained, and state that operator or Host escalation is required.
- Never automatically retry an ambiguous operation. Do not perform built-in remote reconciliation or remote reobservation.
- Mixed-endpoint applications revalidate existing Issue identity, write address, semantic evidence, and desired relationship state immediately before the relationship write. If the endpoint is stale, missing, mismatched, or the relationship already exists before dispatch, settle the claimed operation as `Blocked` even when earlier receipts exist; retain those receipts as observable prior progress. If a relationship mutation was dispatched and its result is ambiguous, report `OutcomeUnknown` and stop without retrying. Never compensate by deleting newly created Issues.

The user-facing result must distinguish Approval from Application, and definitive success or failure from recovery-required. Application is not read-only; disclose that it may mutate GitHub Issues within the exact approved operation set.

## OutcomeUnknown relationship observation

- Only an `OutcomeUnknown` `add_sub_issue` or `add_dependency` operation is eligible for current relationship observation. Call `delivery_observe_application_postcondition` with the exact `application_id`.
- `postcondition_confirmed` means the desired relationship currently exists. `postcondition_absent` means the desired relationship does not currently exist. `inconclusive` means the current relationship state cannot be safely classified.
- Every observation reports historical causal attribution as `not_established`. No observation result authorizes automatic retry or resume. Do not invoke Apply again automatically, do not mutate GitHub, and keep durable recovery state as `OutcomeUnknown`.

## Status inspection

- When a user asks to inspect an existing application or its retained recovery evidence, call `delivery_get_application_status` with the exact Runtime-returned `application_id`. If the Apply result was lost before that ID was handed off, use the exact four-field context (`preview_id`, `revision`, `approval_id`, and `approval_digest`) retained from the Runtime ApplicationAuthority receipt before Apply dispatch with the same status tool.
- Report only the Runtime-owned safe projection. Do not expose raw remote results, canonical operations, authority or credential data, or arbitrary persisted payloads.
- Status inspection is read-only. Never retry, resume, reobserve GitHub, reconcile, transition application state, or mutate remote state.
- A missing context match means only that no matching durable Application was found. It does not prove that the remote operation did not occur and does not authorize another Apply attempt.
- Preserve the terminal recovery semantics above when the application remains `OutcomeUnknown`, `Failed`, `Blocked`, or otherwise recovery-required.
