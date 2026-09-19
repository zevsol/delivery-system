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

### GOV-HOSTCFG-01 — Durable Host configuration contract
- Category: Operator; Status: Open; Risk: High
- Why deferred / rationale: Composition validates supplied inputs, but no durable operator-facing configuration/start mechanism owns reproducibility.
- Constraints preserved: Do not expose secrets or prescribe a format before authorization.
- Evidence/reference: `delivery_system/host_composition.py`; V1-INT1 retained evidence family.
- Reconsideration trigger: Next live Host workflow.
- Review point: Before next feature requiring production Host operation.
- Decision/owner state: Architecture/operator decision required.

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

### ARC-SQLITE-BACKUP-01 — SQLite backup and restore
- Category: Architecture; Status: Open; Risk: High
- Why deferred / rationale: Runtime persistence exists without backup/restore policy.
- Constraints preserved: No unsupported restore guarantee.
- Evidence/reference: Runtime SQLite persistence modules.
- Reconsideration trigger: First release preparation.
- Review point: Before first release.
- Decision/owner state: Architecture/operator decision required.

### ARC-SQLITE-RECOVERY-01 — SQLite corruption recovery
- Category: Architecture; Status: Open; Risk: High
- Why deferred / rationale: Integrity detection exists; recovery procedure does not.
- Constraints preserved: Preserve failure-closed behavior.
- Evidence/reference: Runtime SQLite integrity checks.
- Reconsideration trigger: Corruption incident or first release preparation.
- Review point: Before first release.
- Decision/owner state: Architecture/operator decision required.

### ARC-SQLITE-COMPAT-01 — SQLite upgrade and rollback compatibility
- Category: Architecture; Status: Open; Risk: High
- Why deferred / rationale: Versioning/migration exists without long-term compatibility guarantees.
- Constraints preserved: Do not promise compatibility unapproved by product.
- Evidence/reference: Runtime schema/migration code.
- Reconsideration trigger: Schema-changing feature.
- Review point: Before first release.
- Decision/owner state: Architecture decision required.

### ARC-KEY-LIFECYCLE-01 — Key rotation and recovery
- Category: Security; Status: Open; Risk: High
- Why deferred / rationale: Key roles and trust validation exist; rotation/replacement/recovery does not.
- Constraints preserved: Never record secrets in documentation.
- Evidence/reference: `delivery_system/host_composition.py`.
- Reconsideration trigger: Production operator rollout or key change.
- Review point: Before production rollout.
- Decision/owner state: Security/operator decision required.

### ARC-HOST-LIFECYCLE-01 — Host lifecycle contract
- Category: Operator; Status: Open; Risk: High
- Why deferred / rationale: Composition exists; durable startup, shutdown, configuration, and recovery procedure does not.
- Constraints preserved: Do not prescribe final configuration format.
- Evidence/reference: `delivery_system/host_composition.py`; GOV-HOSTCFG-01.
- Reconsideration trigger: Next live Host workflow.
- Review point: Before next live Host workflow.
- Decision/owner state: Architecture/operator decision required.

### ARC-INSTALL-LIFECYCLE-01 — Install, upgrade, uninstall
- Category: Release/CI; Status: Deferred; Risk: Medium
- Why deferred / rationale: Packaging is not a complete operator lifecycle.
- Constraints preserved: Do not claim install testing or release readiness.
- Evidence/reference: `pyproject.toml`; README evidence-level policy.
- Reconsideration trigger: Release preparation.
- Review point: Before first release.
- Decision/owner state: Release decision required.

### ARC-OBSERVABILITY-01 — Operator observability and recovery tooling
- Category: Operator; Status: Open; Risk: Medium
- Why deferred / rationale: Bounded status exists; long-lived logs, inspection, and recovery procedures do not.
- Constraints preserved: Preserve bounded status semantics.
- Evidence/reference: MCP status surface; runtime recovery code.
- Reconsideration trigger: Long-lived operator deployment.
- Review point: Before first release.
- Decision/owner state: Operator architecture decision required.

### ARC-RELEASE-COMPAT-01 — Release compatibility policy
- Category: Architecture; Status: Open; Risk: High
- Why deferred / rationale: Stored and public contracts lack approved compatibility policy.
- Constraints preserved: Do not promise backward compatibility.
- Evidence/reference: Runtime persistence, MCP surfaces, Skills.
- Reconsideration trigger: First release or compatibility-sensitive change.
- Review point: Before first release.
- Decision/owner state: Product/architecture decision required.

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

### CI-VALIDATOR-01 — Official-validator CI coverage
- Category: Release/CI; Status: Deferred; Risk: Medium
- Why deferred / rationale: Local validator evidence exists; CI enforcement remains incomplete.
- Constraints preserved: Do not claim CI evidence not executed.
- Evidence/reference: Validator scripts and CI configuration.
- Reconsideration trigger: CI or release preparation.
- Review point: Before first release.
- Decision/owner state: Release/CI authorization required.

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
