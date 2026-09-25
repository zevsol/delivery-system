# User Workflow

This document describes the implemented source-level Delivery System workflow from planning through GitHub application and recovery. It explains the user-facing handoffs and safety boundaries. It does not establish Host Tested, Install Tested, Integration Tested, or Released evidence.

## Workflow at a glance

| Stage | User-facing purpose | GitHub effect | Next step |
| --- | --- | --- | --- |
| Plan | Prepare and inspect a Sealed Preview | No GitHub write | Audit the exact Preview |
| Audit | Independently evaluate the Preview | No GitHub write | Human Approval only when eligible |
| Human Approval | Record explicit approval for one exact Preview | No GitHub write | Apply only after a separate user decision |
| Apply | Execute only the approved operation set | GitHub-write boundary | Review the definitive result or recovery state |
| Result / Recovery | Understand what happened and what is safe next | No automatic retry | Stop, inspect bounded evidence, or escalate |

## 1. Plan

Plan turns a user intention into a Runtime-produced Preview. The Preview may change local Delivery System state, but Plan does not write GitHub.

The user-facing Skill for this stage is `plan-github-work-items`.

A successful Preview includes exact Runtime-produced identifiers:

- `preview_id`;
- positive `revision`;
- the returned Preview result and its Runtime-owned evidence.

A Preview is not an Audit and is not Human Approval. Do not invent, infer, substitute, or silently replace a Preview ID or Revision.

Stop when planning is blocked, incomplete, stale, or requires clarification. Resolve the blocker or create a new valid Preview before continuing.

### Handoff to Audit

When the Preview is ready for independent review, carry forward the exact `preview_id` and `revision` returned by Runtime.

The next user-facing Skill is:

`audit-github-work-items`

Audit must use that exact Preview and Revision. A successful Preview does not authorize Approval or Apply.

## 2. Audit

Audit independently evaluates the exact Sealed Preview and records the Runtime-validated audit locally. Audit does not write GitHub.

The authoritative result includes:

- `preview_id`;
- `revision`;
- `audit_id`;
- Audit result and status;
- `audit_scope`;
- `approval_eligible`;
- findings and evidence returned by Runtime.

Possible Audit results include `Passed`, `NeedsInformation`, `ChangesRequired`, and `Blocked`.

A `Passed` result alone does not establish Approval eligibility. A Conceptual Audit may pass but remains ineligible for GitHub-writing Approval. Runtime remains the final authority.

### Handoff to Human Approval

Continue to Human Approval only when the current Runtime result is approval-eligible, including the relevant `WriteEligible` condition and `approval_eligible=true`.

Carry forward the exact `preview_id` and `revision`. The `audit_id` is useful audit receipt information, but Approval is not driven by a caller-supplied `audit_id`.

The next user-facing Skill is:

`approve-github-work-items`

For any non-eligible result, stop, obtain missing information, correct the Preview, or revise and re-audit.

## 3. Human Approval

Human Approval records explicit human intent for one exact Preview and Revision. It does not write GitHub and does not issue executable ApplicationAuthority.

The Approval ceremony requires the exact target and the exact human command:

`批准写入 {preview_id} {revision}`

Successful Approval returns a Runtime-owned receipt containing, at minimum:

- `approval_id`;
- `preview_id`;
- `revision`;
- the associated Audit binding and approval status.

Approval must not be inferred from conversational agreement, a prior Preview, or a semantic match.

### Handoff to Apply

After successful Approval:

- state that Approval was recorded;
- state that no GitHub mutation occurred;
- state that ApplicationAuthority was not issued;
- preserve the exact `approval_id`, `preview_id`, and `revision`;
- explain that Apply is a separate user job.

If the user explicitly chooses to execute the approved work, the next user-facing Skill is:

`apply-github-work-items`

Do not invoke Apply automatically because Approval succeeded.

## 4. Apply

Apply is the GitHub-write boundary. It may mutate GitHub Issues only within the exact operation set represented by the current approved Preview and validated by Runtime.

Apply requires the exact approved Preview, Revision, and successful Approval context. The Skill obtains ApplicationAuthority internally through Runtime. Users must not construct, copy, or manipulate ApplicationAuthority identifiers.

Apply does not authorize arbitrary GitHub writes and does not expand the approved operation set.

## Result and Recovery

| Result | Meaning | Required user action |
| --- | --- | --- |
| `Applied` | Definitive success only when a durable application receipt is present | Report success and retain the receipt information |
| `Failed` | Definitive failure | Stop and report the Runtime result and recovery information |
| `Blocked` | Definitive blocked result | Stop and report the Runtime-provided cause and recovery information |
| `OutcomeUnknown` | Recovery-required or ambiguous outcome; the remote effect may already have occurred | Stop, retain evidence, do not retry or resume automatically, and escalate when required |

Automatic retry is not authorized:

`NO_AUTOMATIC_RETRY`

`delivery_get_application_status` may read bounded durable application status and recovery evidence. It is read-only and does not retry, resume, reconcile, transition state, or write GitHub.

For an eligible `OutcomeUnknown` `add_sub_issue` or `add_dependency` operation, `delivery_observe_application_postcondition` may inspect the current relationship state. It is read-only, does not establish historical causal attribution, and does not authorize retry or resume.

## Terminology

| Public term | Runtime or internal term |
| --- | --- |
| Plan | Sealed Preview |
| Audit | AuditRecord / `audit_id` |
| Human Approval | ApprovalRecord / `approval_id` |
| Apply | Internal ApplicationAuthority-backed execution |
| Result | Application state and application receipt |
| Recovery | `OutcomeUnknown` and retained recovery evidence |

Internal identifiers and mechanisms support the workflow but are not separate user objectives.

## Evidence boundary

This workflow documents the implemented source-level MCP and Skill contract, including local stdio composition and bounded GitHub application semantics.

It does not establish:

- concrete Codex, ChatGPT, Claude, VS Code, or other Host Tested support;
- Install Tested evidence;
- external Integration Tested release evidence;
- formal Released status;
- automatic retry or recovery;
- a new Runtime capability.
