# Host configuration

## Purpose and boundary

This document owns the operator-facing configuration contract for the existing `github-app-write` Host profile. It describes how the Host obtains and validates configuration before composing the existing Runtime services. It does not define deployment, daemon, or general Host lifecycle behavior.

## Startup inputs

The Host requires an explicit `--workspace-root` input. The Runtime derives workspace identity and `.delivery-system/state.sqlite3` from that root.

The Host environment adapter reads the documented operator environment contract and produces a validated `HostConfiguration`. Protected external key and token references point to material outside tracked repository content. Public key and trust-bundle references point to operator-controlled public trust material.

Attestation and authority-binding lifecycle manifests are optional external, non-secret lifecycle-policy/authorization-policy inputs. Each manifest is validated during fresh-process composition before the operational Runtime and GitHub installation lease are constructed. A manifest does not contain private key material or cryptographic trust material.

The composition flow is:

```text
workspace + operator environment
        ↓
load_host_configuration
        ↓
HostConfiguration
        ↓
compose_write_enabled_host
        ↓
HostComposition
```

## Environment inventory

The following inputs are required:

| Name | Purpose | Accepted shape | Classification |
| --- | --- | --- | --- |
| `DELIVERY_SYSTEM_GITHUB_APP_ID` | GitHub App identity | positive decimal ID | non-secret |
| `DELIVERY_SYSTEM_GITHUB_REPOSITORY` | target repository identity | normalized `owner/name` | non-secret |
| `DELIVERY_SYSTEM_GITHUB_REPOSITORY_ID` | target repository numeric identity | positive decimal ID | non-secret |
| `DELIVERY_SYSTEM_GITHUB_APP_PRIVATE_KEY_PATH` | GitHub App signing key reference | absolute path | protected reference |
| `DELIVERY_SYSTEM_ATTESTATION_ISSUER_ID` | attestation issuer identity | bounded lowercase ID | non-secret |
| `DELIVERY_SYSTEM_ATTESTATION_KEY_ID` | active attestation key identity | bounded lowercase ID | non-secret |
| `DELIVERY_SYSTEM_ATTESTATION_PRIVATE_KEY_PATH` | attestation signing key reference | absolute path | protected reference |
| `DELIVERY_SYSTEM_ATTESTATION_PUBLIC_KEY_PATH` | attestation public-key reference | absolute path | public trust-material reference |
| `DELIVERY_SYSTEM_ATTESTATION_TRUSTED_KEYS_PATH` | attestation trust-bundle reference | absolute path | public trust-material reference |
| `DELIVERY_SYSTEM_AUTHORITY_BINDING_ISSUER_ID` | authority-binding issuer identity | bounded lowercase ID | non-secret |
| `DELIVERY_SYSTEM_AUTHORITY_BINDING_ACTIVE_KEY_ID` | active authority-binding key identity | bounded lowercase ID | non-secret |
| `DELIVERY_SYSTEM_AUTHORITY_BINDING_PRIVATE_KEY_PATH` | authority-binding signing key reference | absolute path | protected reference |
| `DELIVERY_SYSTEM_AUTHORITY_BINDING_PUBLIC_KEY_PATH` | authority-binding public-key reference | absolute path | public trust-material reference |
| `DELIVERY_SYSTEM_AUTHORITY_BINDING_TRUSTED_KEYS_PATH` | authority-binding trust-bundle reference | absolute path | public trust-material reference |
| `DELIVERY_SYSTEM_REVOCATION_PROVIDER_URL` | revocation provider endpoint | HTTP or HTTPS URL with network location | non-secret |
| `DELIVERY_SYSTEM_REVOCATION_TIMEOUT_MS` | revocation request timeout | integer from `1` through `120000` | non-secret |

The following inputs are optional:

| Name | Purpose | Accepted shape | Classification |
| --- | --- | --- | --- |
| `DELIVERY_SYSTEM_REVOCATION_AUTH_TOKEN_PATH` | optional revocation authentication token reference | absolute path | protected reference |
| `DELIVERY_SYSTEM_ATTESTATION_LIFECYCLE_PATH` | optional attestation Ed25519 lifecycle manifest | absolute path | non-secret lifecycle-policy reference |
| `DELIVERY_SYSTEM_AUTHORITY_BINDING_LIFECYCLE_PATH` | optional authority-binding Ed25519 lifecycle manifest | absolute path | non-secret lifecycle-policy reference |

The following operator authority input is forbidden:

| Name | Status | Semantic purpose | Classification |
| --- | --- | --- | --- |
| `DELIVERY_SYSTEM_GITHUB_INSTALLATION_ID` | forbidden | installation identity is discovered and verified by the GitHub App bootstrap flow | forbidden |

`RuntimeContext.workspace_root` is a separate startup input and is not an environment configuration field. Injected transports, clocks, ID factories, and test key sources are test seams, not operator configuration.

## Configuration and protected material

Non-secret identifiers, repository values, endpoint, and timeout may be supplied as configuration values. Private key and token contents remain external protected material; only their path references are part of this contract. Public keys and trust bundles remain operator-controlled external cryptographic trust material. Lifecycle manifest paths are separate non-secret lifecycle-policy/authorization-policy references; the manifest supplies lifecycle policy while the trust bundle supplies cryptographic candidate material. No private key, token, or protected credential content belongs in tracked configuration, Runtime state, logs, errors, or this document.

The existing composition checks remain authoritative, including workspace exclusion, opened-object validation, path-role separation, key-pair verification, and active-key trust checks. When a lifecycle manifest is present, strict manifest parsing rejects duplicate or unknown JSON members, unknown states, invalid fingerprints, unclassified trust candidates, and selector disagreement. The canonical fingerprint is `sha256:` followed by the lowercase SHA-256 digest of the raw 32-byte Ed25519 public key; PEM/DER container formatting and file paths are not part of the fingerprint.

Without a lifecycle manifest, bounded legacy mode derives the configured active identity as `active` and all other existing trusted bundle identities as `historical`. Managed mode permits exactly one `active` identity and classifies other identities as `historical`, `retired`, or `compromised`. Only active and historical identities enter the effective verification registry. Retired and compromised material never regains trust merely because it remains in the candidate bundle. The active selector remains owned by Host configuration; the manifest cross-validates it rather than introducing another selector.

Lifecycle activation is fresh-process-only. Pure Ed25519 material/trust preflight performs parsing, public/private matching, lifecycle validation, effective trust projection, role checks, and a non-secret sign/verify self-check. It does not start a second Host, open SQLite, acquire an installation lease, or reload a running process. A failed preflight stops the new composition closed. Only when the previous process is still running and healthy, its material remains usable, and that material has not been compromised may an operator use it as a manual rollback boundary; no automatic fallback or rollback occurs.

## GitHub App fresh-composition continuity

The bounded `G1 → G2` procedure supports normal GitHub App key rotation through a fresh process composition. The GitHub App owner or administrator provisions G2 and owns provider-side deletion or revocation of G1. During normal rotation, G1 should remain available while the operator validates G2; this is an operator-controlled continuity boundary, not a Delivery System failover mechanism.

The operator must configure a fresh Delivery System process with G2's protected key path. G2 is validated through the complete existing GitHub App bootstrap path: App identity, owner and repository identity, installation identity, repository scope, required permissions, token scope, and lease expiry are checked. A successful installation lease must be acquired before the new Host becomes operational. Failed G2 composition fails closed, with no operational HostComposition and no automatic fallback to G1 or to the disabled/default profile.

Normal rotation and compromise are different operator situations. For normal rotation, a previously healthy G1 process may remain available while its existing lease remains valid. If G1 is compromised, do not use that process as a continuity boundary; the GitHub App owner or administrator must handle provider-side containment and deletion. Delivery System does not claim full provider-side compromise recovery, does not invoke provider installation-token revocation, and does not guarantee that deleting G1 immediately invalidates an already-issued installation token. An installation token is distinct from the App private key.

This contract is fresh-composition-only. There is no live reload, automatic App-key rotation, App-key history, or automatic rollback or failover. There is no automatic installation-token renewal/reacquisition loop. RSA private-key material remains external and non-persistent; installation-token secret material is likewise not persisted in Runtime or workspace state. No claim is made that an already-issued token is revoked merely because provider-side key state changed.

## Composition result

Successful composition means that inputs were validated, the installation lease was acquired and verified, signing and trust roles were validated, Runtime services were composed, and a sealed `HostComposition` was returned. It does not mean that a GitHub Issue write occurred.

Invalid or incomplete configuration fails closed through the existing Host composition error boundary. No fallback to the disabled/default MCP profile is permitted after an explicitly requested `github-app-write` composition fails.

## Non-goals

This contract does not define:

- daemon lifecycle;
- shutdown orchestration;
- crash recovery;
- a service manager;
- deployment architecture;
- SQLite backup or recovery;
- GitHub App key rotation, installation-token renewal, or automatic rotation;
- in-process reload, process orchestration, or automatic rollback;
- key generation, private-key backup, or secret persistence;
- provider-level key compromise/revocation semantics;
- durable lifecycle evidence or final operational recovery procedures;
- a reusable integration harness.
