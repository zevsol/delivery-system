# Delivery System

Delivery System is a Corrective Runtime Prototype for deterministic work-item planning, auditing, and explicit Human Approval of Sealed Previews.

It provides a structured planning protocol with:

- explicit User-asserted, model-proposed, and model-assumption values;
- deterministic canonical payloads and plan digests;
- Runtime-owned request, preview, revision, and item lineage;
- typed audit and approval record schemas and validators;
- a Runtime-owned Rule Registry and deterministic audit recording contract;
- explicit Human Approval recording for approval-eligible Sealed Previews;
- a local PreviewStore contract with SQLite preflight checks;
- an official MCP SDK stdio server exposed through `delivery-system-mcp`.

The Planner does not write to GitHub. The Runtime may write local PreviewStore state under the explicitly supplied workspace root. A workspace is started with:

```text
delivery-system-mcp --workspace-root <absolute-path>
```

The current Runtime Auditor records deterministic audit results for Conceptual previews from declared semantic evaluations. The user-facing `audit-github-work-items` Skill reads an existing Sealed Preview, evaluates the returned audit context, and records a local Runtime Audit. It does not approve a Preview, write to GitHub, implement the Applier, or create or modify a Preview. Conceptual audits are never approval-eligible.

The user-facing `approve-github-work-items` Skill records explicit Human Approval for a specific Sealed Preview through the Runtime. Approval is not ApplicationAuthority, does not issue ApplicationAuthority, and does not execute the Applier or write to GitHub. Human Approval can be recorded locally without credential or attestation bootstrap.

The current package is source code and a Python runtime prototype. It is not a ChatGPT or Codex Plugin, Universal Public Plugin, Personal Repository Beta, Host Tested installation, or external Integration Tested release.

The bundled local state database is `.delivery-system/state.sqlite3` and is excluded from Git. It does not store tokens, cookies, or authentication configuration. The Planner does not provide destructive cleanup operations.

The current local stdio server exposes five MCP surfaces: `delivery_plan_preview`, `delivery_get_audit_context`, `delivery_record_audit`, `delivery_record_approval`, and `delivery_issue_application_authority`. The Planner, Auditor, and Approval Skills are deterministically contract-tested; the Auditor Skill has also been behavior-tested through isolated local execution with three real Runtime audit contexts and independent semantic review. Host credential/bootstrap, installation, and GitHub integration remain outside the verified capability boundary. No GitHub application write or Applier is implemented by PC1B-C.
