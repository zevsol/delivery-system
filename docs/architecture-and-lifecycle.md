# Delivery System Architecture and Lifecycle

## Purpose and scope

This document owns the current architecture and lifecycle boundaries for maintainers and operators. It records implemented guarantees and unresolved decisions; it is not a roadmap, execution diary, or replacement for the debt register.

## System boundary and sources of truth

Planner, Auditor, Human Approval, Runtime, and GitHub have distinct responsibilities. GitHub Issues are the V1 formal work-item source of truth. Runtime state supports planning evidence, approval, authorization, execution, recovery, and receipts; it must not become a second requirements database.

## State and artifact ownership

Tracked files own shipped product source, tests, documentation, and governance. `.dev/` owns active repository-coupled process material. `.delivery-system/` owns active repo-local Runtime state. Workspace local owns disposable output and retained diagnostics; workspace research owns reusable active research; workspace archive owns completed historical evidence. Protected external trust-root material remains operator controlled and outside repository state.

## Runtime state lifecycle

Current Runtime state is `.delivery-system/state.sqlite3`. Runtime initializes and validates this active state, versions and migrates supported schemas, performs integrity checks, and preserves bounded recovery/execution records. Backup, restore, rollback, and corruption-recovery procedures are not yet specified.

## Workspace identity lifetime

Workspace identity is derived from the canonical workspace path. Rename or relocation, a new clone, multiple worktrees, restore at another path, and machine migration therefore do not imply automatic state portability or rebinding. See `ARC-WORKSPACE-ID-01`.

## SQLite lifecycle and current limitations

Schema versioning, migrations, integrity checking, and current-scope concurrency behavior are implemented. Operational WAL/journal policy, backup, restore, rollback, corruption recovery, long-term compatibility, and multi-version upgrade guarantees remain unresolved. See `ARC-SQLITE-BACKUP-01`, `ARC-SQLITE-RECOVERY-01`, and `ARC-SQLITE-COMPAT-01`.

## Credential and trust lifecycle

GitHub App, attestation, and authority-binding private keys serve separate roles; trusted key bundles establish public trust; the revocation credential authorizes revocation status lookup. Secrets are external operator material and do not belong in Runtime state, logs, or this document. Rotation, replacement, and disaster recovery remain unresolved. See `ARC-KEY-LIFECYCLE-01` and `SEC-TOKEN-REPARSE-01`.

## Host and operator lifecycle

Host composition receives and validates required configuration and protected material before composing services. A durable operator-facing startup, configuration, shutdown, and recovery contract does not yet exist. No CLI, configuration-file format, secret-manager, or service-manager design is implied here. See `GOV-HOSTCFG-01` and `ARC-HOST-LIFECYCLE-01`.

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

Future compatibility decisions may cover SQLite schema, Preview/Audit/Approval records, attestations, authority bindings, execution receipts, MCP/API structures, and Skills. No unapproved backward-compatibility promise is made. See `ARC-RELEASE-COMPAT-01` and `ARC-SQLITE-COMPAT-01`.

## Open architecture decisions and debt references

Workspace identity: `ARC-WORKSPACE-ID-01`. SQLite lifecycle: `ARC-SQLITE-BACKUP-01`, `ARC-SQLITE-RECOVERY-01`, `ARC-SQLITE-COMPAT-01`. Credential lifecycle: `ARC-KEY-LIFECYCLE-01`, `SEC-TOKEN-REPARSE-01`. Host/operator lifecycle: `GOV-HOSTCFG-01`, `ARC-HOST-LIFECYCLE-01`. Evidence lifecycle: `GOV-EVIDENCE-LIFECYCLE-01`, `GOV-DIAG-TELEMETRY-01`. Integration harness: `ARC-HARNESS-01`. Installation: `ARC-INSTALL-LIFECYCLE-01`. Observability: `ARC-OBSERVABILITY-01`. Compatibility: `ARC-RELEASE-COMPAT-01`, `ARC-SQLITE-COMPAT-01`.
