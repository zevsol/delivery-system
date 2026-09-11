---
name: apply-github-work-items
description: Apply one exact, explicitly approved Delivery System Sealed Preview through the bounded application path when a user asks to execute approved GitHub work items. Do not use for planning, auditing, approval, arbitrary GitHub writes, or recovery reconciliation.
---

# Apply GitHub Work Items

Apply one exact Delivery System Sealed Preview and its approved operation set. Apply is a user job separate from planning, independent audit, and Human Approval. It may perform irreversible GitHub Issue mutations within the already approved boundary.

## Preconditions and handoff

- Require the exact `preview_id` and positive integer `revision`.
- Require the exact successful Human Approval context for that Preview and Revision, including the Runtime-returned `approval_id`. Do not infer approval from conversation agreement, a prior Preview, or a semantic match. If the exact approval context is unavailable, stop and ask the user to complete or provide the approval handoff.
- Treat the approval context as proof of which object was approved, not as executable authority. Human Approval remains distinct from ApplicationAuthority and application.
- Do not ask the user to construct, copy, or manipulate an `ApplicationAuthority` ID. The Skill owns the internal handoff to the existing Runtime support path.

## Workflow

1. Resolve the exact approved `preview_id`, `revision`, and approval context. Never substitute “latest”, “that one”, or a guessed identifier.
2. Call `delivery_get_audit_context` for the exact Preview and Revision. Stop if the context is missing, stale, integrity-invalid, or not suitable for the existing Runtime gate.
3. Call `delivery_issue_application_authority` internally with the exact approved context. This issues the protected executable authority; it is not a separate user objective and it does not write GitHub.
4. Pass only the Runtime-returned authority to `delivery_apply_approved_work_items` and invoke the existing bounded Apply path.
5. Use the returned durable application state and receipt exactly as returned. Do not calculate, replace, or invent Runtime-owned identifiers, digests, states, or recovery values.

## Responsibility boundary

Apply does not own or perform planning, audit creation, Human Approval creation or modification, credential discovery, arbitrary GitHub writes, arbitrary Driver invocation or use, schema or database administration or migration, revocation checks or authoritative revocation decisions, or any other post-V1 revocation lifecycle. It does not call planning, audit-recording, approval-recording, direct GitHub mutation, or arbitrary Driver tools, and it does not bypass the bounded Applier.

## Result and recovery

- Report definitive success only for a durable `Applied` result supported by the returned application receipt.
- Report `Failed` or `Blocked` as a definitive failure with the Runtime result.
- Treat `OutcomeUnknown`, an ambiguous execution result, or a recovery-required result as terminal for this Skill. Stop immediately, state that the remote effect may already have occurred, state that durable evidence has been retained, and state that operator or Host escalation is required.
- Never automatically retry an ambiguous operation. Do not perform built-in remote reconciliation or remote reobservation.

The user-facing result must distinguish Approval from Application, and definitive success or failure from recovery-required. Application is not read-only; disclose that it may mutate GitHub Issues within the exact approved operation set.

## Status inspection

- When a user asks to inspect an existing application or its retained recovery evidence, call `delivery_get_application_status` with the exact Runtime-returned `application_id`.
- Report only the Runtime-owned safe projection. Do not expose raw remote results, canonical operations, authority or credential data, or arbitrary persisted payloads.
- Status inspection is read-only. Never retry, resume, reobserve GitHub, reconcile, transition application state, or mutate remote state.
- Preserve the terminal recovery semantics above when the application remains `OutcomeUnknown`, `Failed`, `Blocked`, or otherwise recovery-required.
