# Delivery System

Delivery System is a Corrective Runtime Prototype for deterministic work-item planning.

It provides a structured planning protocol with:

- explicit User-asserted, model-proposed, and model-assumption values;
- deterministic canonical payloads and plan digests;
- Runtime-owned request, preview, revision, and item lineage;
- typed audit and approval record schemas and validators;
- a Runtime-owned Rule Registry and deterministic audit recording contract;
- a local PreviewStore contract with SQLite preflight checks;
- an official MCP SDK stdio server exposed through `delivery-system-mcp`.

The Planner does not write to GitHub. The Runtime may write local PreviewStore state under the explicitly supplied workspace root. A workspace is started with:

```text
delivery-system-mcp --workspace-root <absolute-path>
```

The current Runtime Auditor records deterministic audit results for Conceptual previews from declared semantic evaluations. It does not implement a user-facing Auditor Skill, real GitHub Driver, GitHub authentication, GitHub write operation, Human Approval Workflow, or Applier product. Conceptual audits are never approval-eligible.

The current package is source code and a Python runtime prototype. It is not a ChatGPT or Codex Plugin, Universal Public Plugin, Personal Repository Beta, Host Tested installation, or external Integration Tested release.

The bundled local state database is `.delivery-system/state.sqlite3` and is excluded from Git. It does not store tokens, cookies, or authentication configuration. The Planner does not provide destructive cleanup operations.

The Planner and Runtime Auditor MCP tools are available through the local stdio server. Host, installation, GitHub, and semantic Skill Forward validation remain outside the verified capability boundary.
