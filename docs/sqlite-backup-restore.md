# SQLite Backup and Restore

Delivery System provides an offline operator maintenance capability for the complete current Runtime SQLite state.

## Supported commands

Run these commands from the source checkout:

```text
python -m delivery_system.sqlite_maintenance backup --workspace-root <workspace> --destination <backup-bundle-directory>
python -m delivery_system.sqlite_maintenance restore --workspace-root <workspace> --source <backup-bundle-directory>
```

The Delivery System Host using the workspace must already be stopped. The maintenance command does not stop a Host and does not prove that no other process has the database open. Busy, locked, unsafe, or otherwise invalid maintenance conditions fail closed.

## Backup artifact

A completed backup is a directory bundle containing exactly:

```text
manifest.json
state.sqlite3
```

The database member is a standalone SQLite image produced by SQLite's native backup API. Active `-wal`, `-shm`, and `-journal` files are not copied into the bundle.

The manifest records the format identity and version, the exact Runtime release identity, schema version `7`, workspace identity, database size, lowercase SHA-256 digest, and UTC creation time. The digest detects inconsistency relative to the manifest; it is not a signature or cryptographic provenance mechanism.

Backup accepts only the exact current V7 schema and does not migrate older state. The destination must not already exist. Backup publication occurs only after independent database and manifest verification.

Backup artifacts can contain sensitive durable operational state, including planning, audit, approval, authority, attestation, execution, attempt, and receipt records. Store them with appropriate operator access controls. They do not contain external private keys, tokens, credentials, trusted key bundles, revocation material, source files, Git history, GitHub state, or deployment state.

## Restore boundary

Restore requires:

- the exact current Runtime release identity;
- schema version `7`;
- the exact target workspace identity;
- a valid manifest and matching database digest/size;
- a valid standalone SQLite database with the expected schema and integrity checks;
- an empty active state slot.

The canonical `state.sqlite3` and each active `state.sqlite3-wal`, `state.sqlite3-shm`, and `state.sqlite3-journal` path must be absent. Restore never overwrites, deletes, quarantines, or replaces an existing database or sidecar. It stages a validated database under `.delivery-system` and atomically publishes it only when the target remains absent.

Restore does not migrate the artifact, rebind workspace identity, provide cross-release or cross-workspace portability, repair corruption, start the Host, or resume an interrupted application. Existing damaged-state replacement and corruption remediation remain owned by `ARC-SQLITE-RECOVERY-01`; release transition compatibility remains separately owned by `ARC-SQLITE-COMPAT-01`.

## Scope and limitations

This capability is a SQLite Runtime-state backup and restore boundary, not a complete deployment disaster-recovery package. It does not provide online backup, live restore, scheduling, retention, rotation, compression, encryption, signing, remote upload, credential/key backup, Git/GitHub backup, evidence archive management, or service-manager integration.

On platforms without a demonstrated atomic no-overwrite publication primitive, publication fails closed. A successful restore does not imply formal release status, installation testing, Host testing, or external integration testing.
