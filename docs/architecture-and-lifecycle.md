# Delivery System Architecture and Lifecycle

## Purpose and scope

This document owns the current architecture and lifecycle boundaries for maintainers and operators. It records implemented guarantees and unresolved decisions; it is not a roadmap, execution diary, or replacement for the debt register.

## System boundary and sources of truth

Planner, Auditor, Human Approval, Runtime, and GitHub have distinct responsibilities. GitHub Issues are the V1 formal work-item source of truth. Runtime state supports planning evidence, approval, authorization, execution, recovery, and receipts; it must not become a second requirements database.

## State and artifact ownership

Tracked files own shipped product source, tests, documentation, and governance. `.dev/` owns active repository-coupled process material. `.delivery-system/` owns active repo-local Runtime state. Workspace local owns disposable output and retained diagnostics; workspace research owns reusable active research; workspace archive owns completed historical evidence. Protected external trust-root material remains operator controlled and outside repository state.

## Runtime state lifecycle

Current Runtime state is `.delivery-system/state.sqlite3`. Runtime initializes and validates this active state, versions and migrates supported schemas, performs integrity checks, and preserves bounded recovery/execution records. An existing canonical state receives a read-only physical-integrity validation before schema initialization or migration; genuinely absent state remains the only automatic initialization case. Offline operator backup and restore are provided by the source-runnable [`SQLite backup and restore`](sqlite-backup-restore.md) maintenance module. The current contract is V7-only, exact-release, exact-workspace, and limited to restoring into an empty active state slot; it does not provide migration, overwrite, portability, or in-place corruption repair.

## Workspace identity lifetime

Workspace identity is derived from the canonical workspace path. Rename or relocation, a new clone, multiple worktrees, restore at another path, and machine migration therefore do not imply automatic state portability or rebinding. See `ARC-WORKSPACE-ID-01`.

## SQLite lifecycle and current limitations

Schema versioning, migrations, integrity checking, current-scope concurrency behavior, and the bounded offline backup/restore contract are implemented. The bounded current V7 exact-release, exact-workspace, empty-slot backup/restore boundary is resolved by `ARC-SQLITE-BACKUP-01`. Cross-release backup transition compatibility, rollback after committed migration, long-term compatibility, and multi-version upgrade guarantees remain separately owned by `ARC-SQLITE-COMPAT-01`.

## SQLite corruption recovery

For an existing canonical SQLite state, Runtime performs read-only physical integrity validation before initialization or migration. A damaged or zero-byte existing state fails closed before Runtime becomes operational; it is never treated as normal first use. Only genuinely absent state may be initialized automatically.

The bounded first-release recovery model is `detect → fail closed → stop processes → preserve/quarantine damaged state → validate a known-good exact-release/exact-workspace backup → restore into an empty canonical slot → fresh process`. The operator procedure preserves the damaged database and associated sidecars together and reuses the validated no-overwrite restore boundary.

In-place repair, SQLite salvage, `.recover`, dump/reimport, automatic replacement, automatic empty-state fallback, and a zero-data-loss guarantee without a valid backup are not supported. Recovery does not provide cross-release or cross-workspace restoration. Runtime does not delete or repair database sidecars; offline recovery remains an explicit operator action. Release-transition compatibility remains owned by `ARC-SQLITE-COMPAT-01`, and workspace identity/portability remains owned by `ARC-WORKSPACE-ID-01`.

## Credential and trust lifecycle

GitHub App, attestation, and authority-binding private keys serve separate roles; trusted key bundles establish public trust; the revocation credential authorizes revocation status lookup. Secrets are external operator material and do not belong in Runtime state, logs, or this document. The bounded first-release Ed25519 lifecycle uses one active signer per role, with `active`, `historical`, `retired`, and `compromised` lifecycle states. Active and historical identities may verify; retired and compromised identities are excluded. Activation is fresh-process-only, has no automatic fallback, and does not persist secrets or introduce a universal KeyManager. The Ed25519 lifecycle Slice 1 implements this role-specific policy for attestation and authority-binding material. Optional role-specific non-secret manifests distinguish the lifecycle states; only active and historical identities enter the effective verification registry. Legacy deployments without a manifest derive the configured selector as active and other existing trusted candidates as historical, but cannot express retirement or compromise. The active Host selector remains authoritative and is cross-validated against exactly one manifest active identity.

Lifecycle preflight uses the canonical raw 32-byte Ed25519 public key for `sha256:` fingerprints, rejects duplicate or unknown manifest fields, validates material/trust readiness, and performs a non-secret sign/verify self-check before operational Runtime and GitHub lease construction. It does not open SQLite, persist lifecycle state, create a second Host, watch files, reload a running process, generate keys, or mutate external material. Attestation and Authority Binding retain independent manifests, selectors, key material, registries, and lifecycle state; reuse of the same public key across roles remains rejected.

Normal retirement is distinct from compromise: historical artifacts remain verifiable only while their identity remains active or historical in the effective trust policy. Retired and compromised identities are excluded even if stale public material remains in a candidate bundle, and no fallback to an old signer occurs. Token-file hardening, operational recovery, and durable lifecycle evidence remain separate or deferred responsibilities under `SEC-TOKEN-REPARSE-01` and the applicable governance debts.

Fresh-composition GitHub App continuity is supported through externally managed replacement RSA material plus successful GitHub App installation bootstrap and lease validation. The provider administrator owns App private keys and provider-side deletion or revocation. A successful bootstrap and installation lease acquisition are required before the replacement Host becomes operational. The lifecycle has no persistent App-key history, no simultaneous multi-key runtime, no live reload, no automatic App-key rotation, no automatic rollback or failover, no provider-side key deletion/revocation implementation, and no universal KeyManager.

The bounded installation-token contract is one acquisition per fresh composition: an expired lease fails closed before write dispatch, with no automatic renewal or reacquisition; fresh composition obtains a fresh lease and credential instance. The installation-token secret remains in memory only. Token retrieval and network write occur only after live lease, credential-instance, authority/binding, repository/scope/capability, integrity, and expiry guards pass. Historical authority provenance is not silently rebound from credential instance C1 to a fresh-process credential instance C2.

External revocation is credential-instance/attestation oriented. Initial attestation checks external revocation status, and restart reconstruction checks it again. Malformed, unknown, or unavailable provider status fails closed at those boundaries. Ordinary same-process live writes do not promise per-write external revocation polling or continuous monitoring; they continue to enforce credential-instance, authority/binding, repository/scope/capability, integrity, and expiry guards. Delivery System does not revoke a GitHub installation token through GitHub, delete or revoke an App private key, suspend an installation, or automatically renew/refresh an installation token; those remain provider, administrator, or operator concerns.

Durable key-transition history is not required by the current first-release contract. Current consumers derive required state from external configuration, signed persisted artifacts, authority provenance, credential-instance identity, the revocation provider, and GitHub bootstrap/lease evidence. No transition ledger is introduced. `ARC-KEY-LIFECYCLE-01` is resolved for this bounded first-release contract; the separate installation, token-file, evidence, recovery, and observability debts remain independently owned.

## Host and operator lifecycle

Host composition receives and validates required configuration and protected material before composing services. The existing `github-app-write` profile has an explicit operator-facing configuration contract owned by `HostConfiguration` and documented in [`docs/host-configuration.md`](host-configuration.md). Its production lifecycle is `workspace/context → HostConfiguration → Host composition → MCP server creation → server run`; entry into server `.run()` after composition and server creation succeed is the successful-running boundary. Pre-running configuration or composition failures propagate fail-closed without falling back to the default profile. The write-profile entrypoint retains the exact `HostComposition` for the server lifetime and attempts deterministic cleanup when server creation or execution unwinds; normal-return cleanup failures propagate, while an ordinary cleanup failure does not replace an already-active primary create, run, or control-flow failure. Host restart means a fresh process invocation with fresh configuration and composition using current external protected material; it does not provide automatic process restart or execution resume. Runtime owns interpretation and reconstruction of eligible durable execution and authority state, while SQLite backup, restore, and corruption recovery are separately bounded concerns. Abrupt process death has no in-process cleanup guarantee. This bounded process lifecycle contract does not define daemon, service-manager, deployment, installation, long-lived observability, or key lifecycle behavior; those remain with their respective debt owners. See resolved `GOV-HOSTCFG-01` and `ARC-HOST-LIFECYCLE-01`.

## Application execution lifecycle

`Preview → Audit → Human Approval → Application Authority → Application Execution → Operation Attempt → Operation Receipt → Application Receipt` is the execution record lifecycle. Durable intermediate authority or state may be split across boundaries only when the next phase remains legally and technically reachable, or an explicit recovery path exists.

## Evidence lifecycle

Evidence follows `generation → required persistence → interpretation → report handoff → archive/delete decision`. Required evidence survives handoff before cleanup. See `GOV-EVIDENCE-LIFECYCLE-01` and `GOV-DIAG-TELEMETRY-01`.

## Integration-harness boundary

A tested reusable harness is justified before another comparable live integration workflow. Candidate shared responsibilities are current-checkout provenance, explicit environment construction, subprocess lifecycle, sanitized telemetry, retained evidence, native accounting, cleanup, and failure classification. It is not an implemented product capability. See `ARC-HARNESS-01`.

## Installation, upgrade, and uninstall status

Packaging or build evidence is not a complete install, upgrade, uninstall, or operator lifecycle. See `ARC-INSTALL-LIFECYCLE-01`.

## Observability and recovery status

Bounded Runtime status and recovery surfaces exist. Long-lived operator observability, logs, inspection, and recovery procedures remain unresolved. See `ARC-OBSERVABILITY-01`.

## Compatibility policy surface

Formal compatibility is declaration-based and evidence-backed; the full policy is maintained in [Release compatibility](release-compatibility.md). V7 is the declared first-formal-release compatibility baseline for the complete current Runtime state model. V3–V6 migration paths and intermediate V5/V6 store layers remain implementation mechanisms and do not automatically create formal release guarantees. Newer or invalid state remains fail-closed; downgrade and rollback after committed migration are unsupported. The bounded current V7 exact-release, exact-workspace, empty-slot backup/restore capability is resolved by `ARC-SQLITE-BACKUP-01`, and bounded offline corruption recovery is resolved by `ARC-SQLITE-RECOVERY-01`. Cross-release backup/restore and SQLite transition compatibility remain owned by `ARC-SQLITE-COMPAT-01`; workspace portability remains owned by `ARC-WORKSPACE-ID-01`; installation lifecycle remains owned by `ARC-INSTALL-LIFECYCLE-01`. Current prototype metadata is not a formal release declaration. See `ARC-RELEASE-COMPAT-01`, `ARC-SQLITE-COMPAT-01`, `ARC-SQLITE-BACKUP-01`, `ARC-SQLITE-RECOVERY-01`, `ARC-INSTALL-LIFECYCLE-01`, and `ARC-WORKSPACE-ID-01`.

## Architecture decisions and debt references

Workspace identity: `ARC-WORKSPACE-ID-01`. SQLite lifecycle: `ARC-SQLITE-BACKUP-01` (resolved), `ARC-SQLITE-RECOVERY-01` (resolved), `ARC-SQLITE-COMPAT-01`. Credential lifecycle: `ARC-KEY-LIFECYCLE-01` (resolved for the bounded first-release contract), `SEC-TOKEN-REPARSE-01`. Host/operator configuration: `GOV-HOSTCFG-01` (resolved); bounded Host process lifecycle: `ARC-HOST-LIFECYCLE-01` (resolved). Evidence lifecycle: `GOV-EVIDENCE-LIFECYCLE-01`, `GOV-DIAG-TELEMETRY-01`. Integration harness: `ARC-HARNESS-01`. Installation: `ARC-INSTALL-LIFECYCLE-01`. Observability: `ARC-OBSERVABILITY-01`. Compatibility: `ARC-RELEASE-COMPAT-01` (resolved), `ARC-SQLITE-COMPAT-01`.
