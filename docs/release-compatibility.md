# Delivery System Release Compatibility

Delivery System is currently source-usable prototype software. This document defines the compatibility posture for a future formal release; it does not declare the current `0.1.0` metadata as formally Released.

Implemented behavior, historical migrations, tests, matching metadata versions, successful parsing, and successful state reopening do not independently create a cross-release compatibility promise. A formal release guarantees only compatibility surfaces explicitly declared and evidenced for that release.

## Policy identity

The policy identity is **EXACT RELEASE BASELINE + EXPLICIT COMPATIBILITY DECLARATION**. Compatibility is declaration-based per release and per future release transition.

## First-release artifact boundary

The bounded first-release artifact model is two coordinated artifacts, and its installation lifecycle is Install Tested on Windows 11 / CPython 3.14.6:

- the Python Runtime wheel and sdist, whose canonical version is owned by `pyproject.toml` under `[project].version`;
- a release-owned Skills plugin artifact containing exactly the four bundled Skills and a root `plugin.json` with the same version.

Installed Runtime code reads its release identity from distribution metadata. An uninstalled source checkout may use the canonical `pyproject.toml` as a developer-only fallback; that fallback is not the installed-release authority. Installed metadata and source metadata must agree when both are present. A contradiction fails closed.

The Skills plugin artifact does not contain `mcp.json`, `.mcp.json`, `.app.json`, credentials, or an embedded Runtime path. Host/operator configuration separately connects the installed `delivery-system-mcp` console entrypoint through local stdio. The plugin artifact does not imply a remote MCP service or public Plugin Directory publication.

The Runtime and Skills/plugin artifacts are one release-bound set: their versions must match, the release must contain exactly nine public MCP tools and exactly four Skills, and artifact/install evidence is required before `0.1.0` can be declared formally Released.

## Compatibility policy

### REL-VERSION — Release version identity

The canonical release identifier is the project version owned by `pyproject.toml` under `[project].version`. `mcp_server.SERVER_VERSION` must correspond to that value for a formal release. A metadata version alone does not constitute a release; current `0.1.0` remains metadata only. This policy does not define Git-tag syntax or a publication channel. Delivery System does not adopt Semantic Versioning compatibility semantics, so major, minor, and patch numbers do not automatically communicate compatibility behavior.

### REL-BASELINE — First formal release baseline

The first formal release establishes the first formal compatibility baseline. Prototype and pre-release repository states, historical local Runtime states, and current metadata do not automatically belong to that baseline. Existing pre-release behavior may continue to work without creating a compatibility obligation.

### REL-CROSS-RELEASE — Explicit release transition declarations

There is no default backward, forward, N-1, or perpetual compatibility promise between formal releases. A future transition from Release N to Release N+1 requires an explicit declaration. A declaration may identify a compatible, migration-supported, partially compatible, incompatible, or unsupported relationship. An absent declaration means **NOT GUARANTEED**. This policy does not create a release-management subsystem.

### MCP-CONTRACT — Public MCP contract

At the first formal release, the current public MCP surface becomes release-owned. The current nine public tools are:

- `delivery_plan_preview`
- `delivery_get_audit_context`
- `delivery_record_audit`
- `delivery_record_approval`
- `delivery_get_approval_status`
- `delivery_issue_application_authority`
- `delivery_apply_approved_work_items`
- `delivery_get_application_status`
- `delivery_observe_application_postcondition`

Compatibility-significant MCP surfaces include tool names, required input fields and semantic meaning, public structured result fields and meaning, documented public enum/literal values, public machine-consumable error identity and metadata, material null/absent behavior, and safety/write-boundary semantics. No independent MCP contract-version number is introduced. Future incompatible MCP changes require explicit classification and declaration.

MCP changes are **BREAKING** relative to a declared baseline when they remove or rename a public tool, add a newly required input, remove or rename a public output, change field meaning, narrow accepted enum/literal values, change a relied-upon public error identity, change material null/absent behavior, or change safety/write-boundary behavior.

The following changes are **REVIEW REQUIRED**, not automatically compatible: optional input addition, output-field addition, enum widening, new error variants, default changes, and new optional behavior.

### SKILL-CONTRACT — Bundled Skill contract

The first formal release owns the following four Skills as one release-bound set:

- `plan-github-work-items`
- `audit-github-work-items`
- `approve-github-work-items`
- `apply-github-work-items`

No independent Skill version carrier is required for the first release. Compatibility-significant Skill surfaces include Skill identity and name, public job and purpose, owned workflow stage, safety/write boundary, required handoff semantics, and execution-critical MCP dependencies. Explanatory prose formatting and YAML serialization/layout are not compatibility guarantees. Internal clarification that preserves semantics is not breaking. Skill rename, stage-semantic change, safety-boundary change, or incompatible required-tool change is breaking relative to a declared baseline.

### WORKFLOW-CONTRACT — Public workflow and safety

The compatibility-significant public workflow is:

`Plan → Audit → Human Approval → Apply → Result / Recovery`

Plan does not write GitHub. Audit does not write GitHub. Human Approval does not write GitHub. Apply is the GitHub-write boundary and is limited to approved operations. Automatic retry is not authorized. Ambiguous outcomes stop safely and require bounded recovery or operator/Host escalation. ApplicationAuthority, attestations, digests, receipts, and Runtime orchestration remain internal mechanisms rather than additional user-facing stages.

### SQLITE-CURRENT — Current canonical SQLite baseline

V7 is the declared first-formal-release compatibility baseline for the complete current Runtime state model. The implementation may initialize shared state through V5 and V6 layers before the V7 authority-binding layer is reached; those intermediate layers are implementation mechanisms, not separate formal release baselines. This document does not declare a current formal release.

### SQLITE-OLDER — Older SQLite state

Current implementation contains V3–V6 migration machinery, and that machinery remains intact. The ability to handle a historical state is not itself a release guarantee. Arbitrary prototype or pre-release V3/V4/V5/V6 databases are not guaranteed formal-release inputs. A future release may guarantee a source schema only through an explicit declaration and appropriate fixtures and evidence. Existing V3–V6 code is not thereby invalid or subject to removal.

### SQLITE-NEWER — Newer, unknown, or invalid SQLite state

State newer than the versions explicitly supported by a Runtime, unknown or malformed schema metadata, structural fingerprint mismatch, and integrity-invalid persisted state must fail closed. The Runtime performs no speculative parsing, silent rewrite, automatic downgrade, or forward-compatible assumption. Internal error strings are not public compatibility guarantees unless separately declared.

### SQLITE-DOWNGRADE — SQLite downgrade

Downgrade is not supported. There is no N+1-to-N guarantee, reverse migration guarantee, or claim that an older Runtime can open state written by a newer Runtime.

### SQLITE-ROLLBACK — Migration rollback boundary

Transaction rollback during a failed migration remains a supported integrity behavior. Rollback after a successfully committed migration is not supported. Transaction rollback is not release downgrade capability.

### BACKUP-COMPAT — Backup and restore boundary

Future backup and restore work is initially bounded to the same formal release and the same workspace identity. No cross-release restore, Release N backup to Release N+1 restore, restore into an older Runtime, or portable restore across workspace identities is guaranteed. Backup and restore are separate capabilities and are not implemented or changed by this policy.

### WORKSPACE-IDENTITY — Workspace identity boundary

Workspace identity is path-derived. Relocation, rename, a different canonical path, a new clone, another machine, automatic rebinding, and portable restore are not guaranteed. Workspace identity portability remains separately owned.

### CONFIG-CONTRACT — Operator configuration contract

The documented release-time operator contract is compatibility-significant. It includes `--workspace-root`, `--host-profile`, the `github-app-write` profile, documented `DELIVERY_SYSTEM_*` configuration names, documented protected-material references, and the `.delivery-system/state.sqlite3` location. Removing, renaming, or semantically redefining a documented required configuration surface is breaking relative to a declared baseline. Key rotation, replacement, recovery, and token lifecycle remain separate security concerns.

### PACKAGE-CONTRACT — Package and distribution boundary

The formal distribution contract may include the project/package name, release version, documented installation mechanism once established, the `delivery-system-mcp` console entrypoint, and the declared Python eligibility/support boundary. Exact lock contents, exact dependency pins, CI-only interpreter choices, and internal build mechanics are not automatically stable public contracts unless they materially alter an explicitly supported environment.

### PYTHON-CONTRACT — Python eligibility and evidence

`requires-python = ">=3.10"` is package eligibility metadata. It is not evidence that every Python version at or above 3.10 is Install Tested or supported. Current Install Tested evidence covers Windows 11 / CPython 3.14.6 only. Tested and supported interpreter claims require separate evidence. Raising the declared minimum Python version is compatibility-significant relative to environments explicitly supported by a prior release.

### INSTALL-UPGRADE — Installation and upgrade boundary

For the bounded first-release artifact model, clean wheel installation, Runtime uninstall with workspace/plugin preservation, and same-release reinstall/reopen are evidenced on Windows 11 / CPython 3.14.6. A source-checkout to first-formal-release upgrade is not automatically supported. Cross-release upgrade compatibility is transition-specific; no universal N-to-N+1 upgrade guarantee exists.

### SUPPORT-WINDOW — Support window

The policy establishes no LTS promise, time-based support window, minimum number of supported previous releases, N-1 rule, or perpetual backward compatibility. A future support-window policy requires separate approval.

### BREAKING-CHANGE — Change classification

The durable compatibility classifications are:

- **BREAKING**
- **REVIEW REQUIRED**
- **INTERNAL/NONBREAKING**
- **DEPENDENT ON DECLARED GUARANTEE**

A future release is compatibility-breaking relative to a prior declared baseline when it changes an explicitly declared public or operator contract incompatibly, or stops accepting durable state that it explicitly promised to accept from that prior release. Breaking releases are permitted, but the break must be explicitly classified and declared. This classification does not dictate SemVer numbering.

Changes to durable-state acceptance or migration, backup/restore, workspace relocation or rebinding, installation/upgrade/uninstall, or support windows are dependent on the applicable declared guarantee.

### GUARANTEE-EVIDENCE — Evidence required for guarantees

Implementation or tests alone do not create compatibility promises. A guarantee requires proportional evidence, including an explicit product or architecture decision, durable documentation, deterministic contract tests, and CI evidence. Durable-state compatibility additionally requires state fixtures; installation or upgrade compatibility requires lifecycle evidence; Host compatibility requires Host evidence; external integration compatibility requires external integration evidence.

## Explicit non-guarantees

The first formal release does not automatically guarantee:

- compatibility with arbitrary prototype or pre-release states;
- backward or forward compatibility across formal releases;
- SemVer compatibility semantics;
- downgrade or reverse migration;
- rollback after a committed migration;
- cross-release backup or restore;
- workspace relocation, rebinding, or portable restore;
- universal upgrade support;
- an LTS, time-based, perpetual, or N-1 support window;
- Install Tested, Host Tested, external Integration Tested, or Released status without separate evidence and authorization.

## Release review checklist

Before a future formal release or declared transition, review the release identifier, formal baseline, transition relationship, affected compatibility surfaces, source and target release/schema where durable-state migration is claimed, evidence supporting each guarantee, explicit non-guarantees, and all evidence-level claims. This document does not define release tags, publication channels, automation, artifact publishing, or a release service.
