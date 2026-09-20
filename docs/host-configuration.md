# Host configuration

## Purpose and boundary

This document owns the operator-facing configuration contract for the existing `github-app-write` Host profile. It describes how the Host obtains and validates configuration before composing the existing Runtime services. It does not define deployment, daemon, or general Host lifecycle behavior.

## Startup inputs

The Host requires an explicit `--workspace-root` input. The Runtime derives workspace identity and `.delivery-system/state.sqlite3` from that root.

The Host environment adapter reads the documented operator environment contract and produces a validated `HostConfiguration`. Protected external key and token references point to material outside tracked repository content. Public key and trust-bundle references point to operator-controlled public trust material.

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

The following input is optional:

| Name | Purpose | Accepted shape | Classification |
| --- | --- | --- | --- |
| `DELIVERY_SYSTEM_REVOCATION_AUTH_TOKEN_PATH` | optional revocation authentication token reference | absolute path | protected reference |

The following operator authority input is forbidden:

| Name | Status | Semantic purpose | Classification |
| --- | --- | --- | --- |
| `DELIVERY_SYSTEM_GITHUB_INSTALLATION_ID` | forbidden | installation identity is discovered and verified by the GitHub App bootstrap flow | forbidden |

`RuntimeContext.workspace_root` is a separate startup input and is not an environment configuration field. Injected transports, clocks, ID factories, and test key sources are test seams, not operator configuration.

## Configuration and protected material

Non-secret identifiers, repository values, endpoint, and timeout may be supplied as configuration values. Private key and token contents remain external protected material; only their path references are part of this contract. Public keys and trust bundles remain operator-controlled external trust material. No private key, token, or protected credential content belongs in tracked configuration, Runtime state, logs, errors, or this document.

The existing composition checks remain authoritative, including workspace exclusion, opened-object validation, path-role separation, key-pair verification, and active-key trust checks.

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
- key rotation;
- a reusable integration harness.
