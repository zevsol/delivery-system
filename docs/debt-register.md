# Delivery System Debt Register

## Purpose

This register preserves material deferred work and resolved governance decisions that affect product, security, lifecycle, release, operator, or future design constraints.

## Interpretation rules

Entries record debt; they do not authorize implementation. Evidence references identify durable context without exposing secrets. Resolved entries remain as compact historical context.

## Category definitions

Product, Security, Architecture, Governance, Operator, Tooling, Release/CI, and UX classify the primary affected responsibility.

## Status definitions

`Open` requires a decision or work. `Deferred` is intentionally postponed. `Blocked` cannot proceed safely. `Resolved` has an accepted durable resolution. `Superseded` is replaced by a named record.

## Risk definitions

`Low`, `Medium`, and `High` express current consequence if the matter is ignored; they are not numeric scores.

## Entry schema

Every entry has Category, Status, Risk, Why deferred / rationale, Constraints preserved, Evidence/reference, Reconsideration trigger, Review point, and Decision/owner state.

## Open and deferred entries

### GOV-DIAG-TELEMETRY-01 — Standard diagnostic telemetry protocol
- Category: Governance; Status: Deferred; Risk: Medium
- Why deferred / rationale: Sanitized telemetry was demonstrated; a reusable protocol is not yet justified as an implemented subsystem.
- Constraints preserved: Preserve failure telemetry without secret capture.
- Evidence/reference: V1-INT1 retained POST evidence; `AGENTS.md` handoff rule.
- Reconsideration trigger: Comparable live integration work.
- Review point: Before comparable integration.
- Decision/owner state: No current implementation authorization.

### GOV-EVIDENCE-LIFECYCLE-01 — Retained evidence lifecycle
- Category: Governance; Status: Open; Risk: Medium
- Why deferred / rationale: Handoff/retention principle is established; archive, promotion, and deletion policy is incomplete.
- Constraints preserved: Never delete evidence before durable handoff.
- Evidence/reference: `AGENTS.md`; workspace ownership rules.
- Reconsideration trigger: Evidence archival or cleanup request.
- Review point: Before retained-evidence cleanup.
- Decision/owner state: Governance policy decision required.

### ARC-HARNESS-01 — Tested integration harness
- Category: Architecture; Status: Deferred; Risk: Medium
- Why deferred / rationale: Reusable responsibilities are demonstrated; framework implementation is premature.
- Constraints preserved: Native product boundaries remain unmodified.
- Evidence/reference: V1-INT1 retained evidence family.
- Reconsideration trigger: Comparable live integration.
- Review point: Before comparable integration.
- Decision/owner state: Separate implementation authorization required.

### ARC-WORKSPACE-ID-01 — Workspace identity portability
- Category: Architecture; Status: Open; Risk: Medium
- Why deferred / rationale: Current identity is path-derived; relocation and restore semantics are unspecified.
- Constraints preserved: Do not imply state portability.
- Evidence/reference: `delivery_system/runtime.py`.
- Reconsideration trigger: Relocation, clone portability, restore, or migration feature.
- Review point: Before portability work.
- Decision/owner state: Architecture decision required.

### ARC-INSTALL-LIFECYCLE-01 — Install, upgrade, uninstall
- Category: Release/CI; Status: Deferred; Risk: Medium
- Why deferred / rationale: Packaging is not a complete operator lifecycle.
- Constraints preserved: Do not claim install testing or release readiness.
- Evidence/reference: `pyproject.toml`; README evidence-level policy.
- Reconsideration trigger: Release preparation.
- Review point: Before first release.
- Decision/owner state: Release decision required.

### SEC-REVOCATION-TEST-01 — Revocation 1 MiB test coverage
- Category: Security; Status: Deferred; Risk: Low
- Why deferred / rationale: Boundary exists; maximum-payload automated coverage remains absent.
- Constraints preserved: Existing revocation failure-close semantics remain unchanged.
- Evidence/reference: Revocation transport tests.
- Reconsideration trigger: Revocation transport modification.
- Review point: Related capability reopening.
- Decision/owner state: Test work authorization required.

### SEC-TRANSPORT-TIMEOUT-01 — Slow-body/socket timeout behavior
- Category: Security; Status: Deferred; Risk: Medium
- Why deferred / rationale: Timeout behavior needs broader adversarial coverage.
- Constraints preserved: Do not relax bounded transport behavior.
- Evidence/reference: REST transport implementation/tests.
- Reconsideration trigger: HTTP transport modification.
- Review point: Related capability reopening.
- Decision/owner state: Security/test authorization required.

### SEC-HTTP-FRAMING-01 — Conflicting HTTP framing
- Category: Security; Status: Deferred; Risk: Medium
- Why deferred / rationale: Conflicting framing hardening remains unreviewed.
- Constraints preserved: Fixed-origin and response limits remain intact.
- Evidence/reference: REST transport implementation/tests.
- Reconsideration trigger: HTTP parser or transport modification.
- Review point: Related capability reopening.
- Decision/owner state: Security authorization required.

### SEC-TOKEN-REPARSE-01 — Token-file reparse hardening
- Category: Security; Status: Deferred; Risk: Medium
- Why deferred / rationale: Token-file symlink/reparse protection needs platform review.
- Constraints preserved: Never expose token contents.
- Evidence/reference: Host revocation token loading.
- Reconsideration trigger: Credential-file lifecycle work.
- Review point: Before production rollout.
- Decision/owner state: Security/operator authorization required.

### TOOL-HTTPERROR-WARNING-01 — HTTPError fixture warning
- Category: Tooling; Status: Deferred; Risk: Low
- Why deferred / rationale: Fixture ResourceWarning is nonblocking.
- Constraints preserved: Do not change production transport to suppress a test warning.
- Evidence/reference: HTTP transport tests.
- Reconsideration trigger: Fixture or transport-test maintenance.
- Review point: Related capability reopening.
- Decision/owner state: Test maintenance authorization required.

### PROD-NULL-PARITY-01 — Optional-null semantic parity
- Category: Product; Status: Deferred; Risk: Low
- Why deferred / rationale: Outside current reviewed surface.
- Constraints preserved: Preserve currently specified null/absent semantics.
- Evidence/reference: Driver normalization and schema tests.
- Reconsideration trigger: Related schema/API expansion.
- Review point: Related capability reopening.
- Decision/owner state: Product decision required.

### PROD-REMOTE-REL-01 — Existing remote relationship capability
- Category: Product; Status: Deferred; Risk: Medium
- Why deferred / rationale: Not required by the V1-INT1 create-issue scope.
- Constraints preserved: No relationship mutation without approved operation set.
- Evidence/reference: Driver relationship handling and V1 non-goals.
- Reconsideration trigger: Relationship feature authorization.
- Review point: Related capability reopening.
- Decision/owner state: Product decision required.

### UX-APPROVAL-01 — Approval user experience
- Category: UX; Status: Deferred; Risk: Medium
- Why deferred / rationale: Approval behavior is implemented; workflow refinement is separate work.
- Constraints preserved: Human approval remains distinct from technical authority.
- Evidence/reference: Approval Runtime, MCP, and Skill surfaces.
- Reconsideration trigger: Approval workflow iteration.
- Review point: Before broader user rollout.
- Decision/owner state: Product/UX decision required.

## Resolved and superseded entries

### ARC-OBSERVABILITY-01 — Operator observability and recovery tooling
- Category: Operator; Status: Resolved; Risk: Medium
- Why deferred / rationale: Resolved by the bounded V1 operator observability and recovery contract: stable startup/runtime error identities; Approval status recovery; known-ID Application status; exact approved-context Application status recovery for a lost Apply result; bounded `OutcomeUnknown` relationship observation; durable restart reconstruction; documented SQLite recovery; and Host/process stderr ownership.
- Constraints preserved: Resolution does not add product-owned persistent logs, centralized logging, metrics, traces, alerts, health/readiness endpoints, a global Runtime status API, generic Application enumeration, automatic retry/recovery, a reusable telemetry protocol, or evidence archival/retention/deletion policy.
- Evidence/reference: `delivery_system/execution_store.py`; `delivery_system/runtime.py`; `mcp_server/server.py`; `tests/v1/test_pc2d_application_status.py`; `skills/apply-github-work-items/SKILL.md`; `docs/user-workflow.md`; `docs/architecture-and-lifecycle.md`.
- Reconsideration trigger: Long-lived operator deployment, a requirement for fleet monitoring or remote collection, a new recovery action, or a need to enumerate durable recovery items.
- Review point: Before first release and before expanding beyond bounded stdio/operator recovery.
- Decision/owner state: Bounded first-release observability is resolved. `GOV-DIAG-TELEMETRY-01` remains Deferred; `GOV-EVIDENCE-LIFECYCLE-01` remains Open; `ARC-INSTALL-LIFECYCLE-01` and `ARC-HARNESS-01` remain Deferred.

### ARC-SQLITE-COMPAT-01 — SQLite upgrade and rollback compatibility
- Category: Architecture; Status: Resolved; Risk: High
- Why deferred / rationale: Resolved by the bounded first-release compatibility policy: V7 is the first formal SQLite baseline; historical V3–V6 migrations remain implementation behavior only; newer or unknown state fails closed; failed migration transactions roll back; committed migrations are forward-only; downgrade and reverse migration are unsupported; cross-release restore is not guaranteed; and future formal transitions require explicit declarations and evidence.
- Constraints preserved: Resolution does not establish arbitrary prototype-state support, universal N→N+1 compatibility, backward/forward/N-1 compatibility, downgrade, reverse migration, post-commit migration rollback, cross-release backup/restore, workspace portability, installation upgrade lifecycle, or LTS/support-window guarantees.
- Evidence/reference: `delivery_system/sqlite_schema.py`; `delivery_system/runtime.py`; relevant attestation/schema migration tests; `tests/v1/test_authority_binding_persistence.py`; `tests/v1/test_sqlite_backup_restore.py`; `tests/v1/test_release_compatibility_contract.py`; `docs/release-compatibility.md`; `docs/architecture-and-lifecycle.md`; `docs/sqlite-backup-restore.md`; D1 targeted `123 tests / OK`; canonical main full-suite evidence `1191 tests / OK / skipped=1`.
- Reconsideration trigger: An actual formal Release N → N+1 transition, a selected historical-state guarantee, downgrade/reverse migration, cross-release restore, a changed formal SQLite baseline, or a materially changed support-window policy.
- Review point: Before declaring a formal release transition or changing the bounded first-release compatibility contract.
- Decision/owner state: The bounded V7 first-formal-release SQLite compatibility contract is resolved. Future transition-specific compatibility remains declaration-based and is not guaranteed without separate evidence.

### ARC-SQLITE-RECOVERY-01 — SQLite corruption recovery
- Category: Architecture; Status: Resolved; Risk: High
- Why deferred / rationale: Resolved by pre-migration read-only physical-integrity validation for existing canonical state, stable fail-closed corruption mapping, preservation/no-replacement behavior, explicit offline quarantine, reuse of validated exact-release/exact-workspace empty-slot restore, and fresh-process restart.
- Constraints preserved: Resolution does not provide in-place repair/salvage, automatic quarantine, automatic backup selection, automatic empty-state fallback, zero-data-loss without a valid backup, backup retention/upload/encryption/authentication, cross-release or cross-workspace recovery, migration rollback/downgrade, or complete incident-response automation.
- Evidence/reference: `delivery_system/sqlite_schema.py`; `delivery_system/runtime.py`; `docs/sqlite-backup-restore.md`; `docs/architecture-and-lifecycle.md`; `tests/slice1_5/test_revision22_runtime.py`; `tests/v1/test_sqlite_backup_restore.py`; `tests/attestation_persistence_store/test_sqlite_store.py`; D2 focused and full-suite evidence.
- Reconsideration trigger: Any requirement for in-place repair/salvage, automatic quarantine or backup selection, automatic empty fallback, zero-data-loss recovery, cross-release/workspace recovery, migration rollback, or automated incident response.
- Review point: Before changing the recovery boundary or before a release requiring capabilities outside this bounded contract.
- Decision/owner state: Bounded first-release SQLite corruption recovery is resolved. `ARC-WORKSPACE-ID-01`, `ARC-INSTALL-LIFECYCLE-01`, and unrelated recovery/observability/evidence debts remain separately owned and unchanged.

### ARC-SQLITE-BACKUP-01 — SQLite backup and restore
- Category: Architecture; Status: Resolved; Risk: High
- Why deferred / rationale: Resolved by the bounded offline operator maintenance contract **OFFLINE VERIFIED SQLITE BACKUP BUNDLE + EMPTY-SLOT ATOMIC RESTORE**, providing source-runnable backup and restore for the complete current V7 Runtime SQLite state with independent artifact validation and fail-closed activation.
- Constraints preserved: Backup/restore remains offline, V7-only, exact-release, exact-workspace, and empty-slot only. Restore does not overwrite or repair existing state, migrate artifacts, rebind workspace identity, provide cross-release or cross-workspace portability, resume application execution, or establish a complete disaster-recovery guarantee. Backup artifact SHA-256 detects manifest/database inconsistency but is not authentication or provenance. The bounded damaged-state recovery procedure is recorded by `ARC-SQLITE-RECOVERY-01`; future cross-release transitions remain declaration-based under `ARC-RELEASE-COMPAT-01`; workspace portability remains owned by `ARC-WORKSPACE-ID-01`.
- Evidence/reference: `delivery_system/sqlite_maintenance.py`; `delivery_system/runtime.py`; `delivery_system/sqlite_schema.py`; `docs/sqlite-backup-restore.md`; `docs/architecture-and-lifecycle.md`; `tests/v1/test_sqlite_backup_restore.py`; PR #54; PR CI run `36541468534`; post-merge main CI run `36543713298`.
- Reconsideration trigger: Runtime SQLite state/schema ownership, backup bundle format, release identity binding, workspace identity binding, restore activation/publication semantics, supported publication platforms, or an explicit cross-release/portable restore requirement changes.
- Review point: Before changing the backup/restore contract and before each formal release when those boundaries have changed.
- Decision/owner state: The bounded first-release SQLite backup/restore contract is resolved for the current V7 exact-release/exact-workspace Runtime state. Corruption recovery, future transition-specific declarations, workspace portability, installation lifecycle, key lifecycle, observability, and broader disaster-recovery concerns remain separately bounded by their existing contracts.

### ARC-RELEASE-COMPAT-01 — Release compatibility policy
- Category: Architecture; Status: Resolved; Risk: High
- Why deferred / rationale: Resolved by the canonical `docs/release-compatibility.md` policy using **EXACT RELEASE BASELINE + EXPLICIT COMPATIBILITY DECLARATION**, which defines release identity, public MCP/Skill/workflow compatibility surfaces, SQLite first-formal-release state boundaries, operator/package/Python/install/support-window boundaries, change classification, and evidence requirements.
- Constraints preserved: Compatibility remains declaration-based. No default backward, forward, N-1, SemVer, downgrade, committed-migration rollback, cross-release backup/restore, workspace-portability, universal-upgrade, or support-window guarantee is created. Current `0.1.0` remains metadata only and is not formally Released. SQLite backup/recovery, future transition-specific declarations, workspace portability, installation lifecycle, key lifecycle, observability, Host evidence, external integration evidence, and formal release authorization remain separately bounded.
- Evidence/reference: `docs/release-compatibility.md`; `README.md`; `docs/architecture-and-lifecycle.md`; `tests/v1/test_release_compatibility_contract.py`; PR #52; PR CI run `36310580171`; post-merge main CI run `36311071824`.
- Reconsideration trigger: Formal release preparation; any compatibility-sensitive change to public MCP/Skill/workflow contracts, durable-state acceptance or migration, documented operator configuration, packaging/Python support, installation/upgrade behavior, support-window policy, or an explicit release-to-release transition.
- Review point: Before each formal release or declared cross-release transition, and before accepting a change classified **BREAKING** or **REVIEW REQUIRED** against a declared baseline.
- Decision/owner state: Release compatibility policy is resolved by the canonical per-release declaration contract. Future compatibility guarantees and transition-specific support require explicit declaration and proportional evidence; adjacent lifecycle and operational debts remain with their existing owners.

### CI-VALIDATOR-01 — Official-validator CI coverage
- Category: Release/CI; Status: Resolved; Risk: Medium
- Why deferred / rationale: Resolved by deterministic GitHub CI provisioning of the official OpenAI Codex Skill Validator from an immutable upstream commit, SHA-256 verification before publication, workflow-level UTF-8 execution, and official Validator contract coverage for all four bundled public Skills.
- Constraints preserved: CI Validator acquisition must remain fail-closed before `SKILL_CREATOR_VALIDATOR` publication, and Planner, Auditor, Approval, and Apply must remain covered by official Validator execution. This resolution does not establish Install Tested, Host Tested, external Integration Tested, or Released status.
- Evidence/reference: `.github/workflows/ci.yml`; `tests/slice2c/test_planner_skill_contract.py`; `tests/slice2c/test_auditor_skill_contract.py`; `tests/slice2d/test_approval_skill_contract.py`; `tests/slice2d/test_apply_skill_contract.py`; PR #50; PR CI run `36094423972`; post-merge main CI run `36095274275`.
- Reconsideration trigger: Official Validator provenance, acquisition, integrity verification, CI runtime/dependency behavior, bundled public Skill set, or Validator invocation contract changes.
- Review point: Before changing CI Validator enforcement or adding/removing a bundled public Skill, and before first release review if the enforcement contract has changed.
- Decision/owner state: Official Validator CI enforcement is resolved for the current four bundled public Skills. Installation, release compatibility, Host/integration evidence, operator lifecycle, and other release-readiness concerns remain owned by their existing debt entries.

### GOV-HOSTCFG-01 — Durable Host configuration contract
- Category: Operator; Status: Resolved; Risk: High
- Why deferred / rationale: Resolved by an explicit code-owned `HostConfiguration` contract, a canonical environment inventory consumed by the environment adapter, explicit Host composition input, durable operator documentation, and focused drift/reproducibility verification.
- Constraints preserved: Protected credential and token material remains external to tracked configuration and Runtime state. This resolution does not define a configuration-file format, secret manager, daemon, service manager, deployment architecture, shutdown lifecycle, or recovery lifecycle.
- Evidence/reference: `delivery_system/host_composition.py`; `mcp_server/server.py`; `docs/host-configuration.md`; `tests/v1/test_h4_host_composition.py`; `tests/v1/test_host_configuration_contract.py`.
- Reconsideration trigger: Host configuration fields, configuration ownership, environment adapter behavior, or the production Host startup boundary changes.
- Review point: Before changing the Host configuration contract or before introducing a different operator configuration mechanism.
- Decision/owner state: Configuration ownership remains resolved by the code-owned `HostConfiguration` contract plus operator documentation. The bounded Host lifecycle contract is resolved separately by `ARC-HOST-LIFECYCLE-01`; deployment, installation, observability, key, and SQLite disaster-recovery concerns remain with their respective debt owners.

### ARC-HOST-LIFECYCLE-01 — Host lifecycle contract
- Category: Operator; Status: Resolved; Risk: High
- Why deferred / rationale: Resolved by explicit production startup ordering, retained `HostComposition` ownership for the write-profile server lifetime, deterministic cleanup after normal and exceptional server unwind, preservation of primary execution or control-flow failure when ordinary cleanup also fails, documented fresh-process restart and Runtime-recovery boundaries, and focused lifecycle regression coverage.
- Constraints preserved: Resolution does not define daemon or service-manager behavior, deployment architecture, installation lifecycle, automatic execution resume, SQLite backup/restore/corruption recovery, key rotation/recovery, or long-lived observability/recovery tooling. Configuration remains owned by the resolved `GOV-HOSTCFG-01` contract.
- Evidence/reference: `mcp_server/server.py`; `tests/v1/test_h4_host_composition.py`; `delivery_system/host_composition.py`; `docs/architecture-and-lifecycle.md`; `docs/host-configuration.md`.
- Reconsideration trigger: Changes to production Host startup/run/shutdown ownership, composition resource lifetime, restart semantics, or the server execution boundary.
- Review point: Before changing those lifecycle boundaries.
- Decision/owner state: The bounded Host process lifecycle contract is resolved. Remaining deployment/install, observability, key, SQLite disaster-recovery, reusable harness, and diagnostic telemetry concerns remain with their existing debt owners.

### ARC-KEY-LIFECYCLE-01 — Key rotation and recovery
- Category: Security; Status: Resolved; Risk: High
- Why deferred / rationale: Resolved by the bounded first-release key and credential lifecycle contract comprising role-scoped Ed25519 lifecycle policy and trust projection, GitHub App fresh-composition replacement-key continuity, fail-closed installation-token expiry, credential-instance-bound authority/provenance, external revocation checks during initial attestation and restart reconstruction, and explicit secret non-persistence boundaries.
- Constraints preserved: Resolution does not establish automatic Ed25519 or GitHub App key rotation, live key reload, automatic failover or rollback, automatic installation-token renewal/reacquisition, provider-side GitHub key/token revocation, per-write external revocation polling, durable key-transition history, secret persistence, a universal KeyManager, or complete incident-response automation.
- Evidence/reference: `delivery_system/ed25519_lifecycle.py`; `delivery_system/host_composition.py`; `delivery_system/github_app_bootstrap.py`; `delivery_system/github_app_credential.py`; `delivery_system/host_revocation.py`; `delivery_system/restart_credential_verification.py`; `delivery_system/runtime.py`; `docs/host-configuration.md`; `docs/architecture-and-lifecycle.md`; relevant lifecycle/Host/bootstrap/restart tests; PR #56 and its accepted PR/post-merge CI evidence; PR #58 and its accepted PR/post-merge CI evidence.
- Reconsideration trigger: Automatic key rotation, live reload, automatic installation-token renewal/reacquisition, per-write revocation freshness, provider-side GitHub revocation integration, durable transition history, different credential-instance rebinding semantics, or a new key/trust role becomes a product requirement.
- Review point: Before changing those lifecycle boundaries or before a production rollout that requires capabilities outside the bounded resolution.
- Decision/owner state: The bounded first-release key/credential lifecycle contract is resolved. `ARC-INSTALL-LIFECYCLE-01`, `SEC-TOKEN-REPARSE-01`, `SEC-REVOCATION-TEST-01`, `GOV-EVIDENCE-LIFECYCLE-01`, and unrelated recovery/observability debts remain separately owned and retain their existing statuses.

### GOV-CURRENT-HEAD-DATAMODEL-01 — Current implementation inspection
- Category: Governance; Status: Resolved; Risk: Medium
- Why deferred / rationale: Resolved by the durable current-HEAD contract-inspection rule.
- Constraints preserved: Historical representations cannot substitute for current implementation.
- Evidence/reference: `AGENTS.md` current-HEAD inspection rule.
- Reconsideration trigger: Rule contradiction discovered.
- Review point: Next governance review.
- Decision/owner state: Rule owner: engineering governance.

### GOV-DIAGNOSTIC-SCHEMA-01 — Schema field ownership inspection
- Category: Governance; Status: Resolved; Risk: Medium
- Why deferred / rationale: Resolved by current-HEAD schema/payload inspection.
- Constraints preserved: Field-name similarity is not schema evidence.
- Evidence/reference: `AGENTS.md` current-HEAD inspection rule.
- Reconsideration trigger: Persisted-schema diagnostic failure.
- Review point: Next governance review.
- Decision/owner state: Rule owner: engineering governance.

### GOV-DIAGNOSTIC-INSTRUMENTATION-01 — Native instrumentation preference
- Category: Governance; Status: Resolved; Risk: Medium
- Why deferred / rationale: Resolved by the validation-strategy native-instrumentation rule.
- Constraints preserved: Instrumentation must not alter measured behavior.
- Evidence/reference: `AGENTS.md` validation strategy rule.
- Reconsideration trigger: Instrumentation-induced discrepancy.
- Review point: Next governance review.
- Decision/owner state: Rule owner: engineering governance.

### GOV-EXEC-PROVENANCE-01 — Current-checkout execution provenance
- Category: Governance; Status: Resolved; Risk: Medium
- Why deferred / rationale: Resolved by proportional loaded-module provenance rule.
- Constraints preserved: No ceremony for unambiguous repository-local unit tests.
- Evidence/reference: `AGENTS.md` failure-source classification rule.
- Reconsideration trigger: Source-provenance ambiguity.
- Review point: Next governance review.
- Decision/owner state: Rule owner: engineering governance.

### GOV-STATE-REACHABILITY-01 — Intermediate-state reachability
- Category: Governance; Status: Resolved; Risk: High
- Why deferred / rationale: Resolved by durable lifecycle-boundary rule.
- Constraints preserved: This does not claim future recovery architecture exists.
- Evidence/reference: `AGENTS.md` vertical work units rule.
- Reconsideration trigger: Split authority/execution workflow.
- Review point: Before such a workflow.
- Decision/owner state: Rule owner: engineering governance.

## Review rules

Review entries at their stated trigger or review point. Update status only with evidence; retain resolved and superseded context in this document.
