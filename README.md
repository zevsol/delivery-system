# Delivery System

Delivery System turns development intent into reviewed, approved, and traceable GitHub work items. It gives an external source-checkout user a governed path from a proposed change to a bounded application, with an independent audit and explicit Human Approval before GitHub can be modified.

> **Safe first run:** start with Preview-only planning.
> Local Delivery System state may change; GitHub is not modified.
> → [Getting Started](docs/getting-started.md)

## What it does

V1 is bounded to GitHub Issues and their relationships. The product path is:

```text
Plan → Audit → Human Approval → Apply → Result / Recovery
```

For the complete handoff and safety path, see [User Workflow](docs/user-workflow.md).

The four user-facing jobs are provided by the bundled Skills:

- `plan-github-work-items` prepares a Sealed Preview.
- `audit-github-work-items` independently audits an existing Preview.
- `approve-github-work-items` records Human Approval for one exact Preview.
- `apply-github-work-items` applies only the approved operation set.

## Safety at a glance

| Stage | Local Delivery System effect | GitHub effect |
| --- | --- | --- |
| Plan | May create or update local planning state | Plan does not write GitHub |
| Audit | May record local audit state | Audit does not write GitHub |
| Human Approval | Records local approval state | Human Approval does not write GitHub |
| Apply | Records execution/result state | Apply is the GitHub-write boundary; only approved operations may be applied |

Automatic retry is not authorized.

Ambiguous execution outcomes stop safely and require recovery or operator/Host escalation.

ApplicationAuthority, attestation, receipts, digests, and other integrity details are internal orchestration rather than ordinary user objectives.

## Current status

Delivery System is currently source-usable prototype software. It is not currently claimed as Install Tested, Host Tested, an externally Integration Tested release, or formally Released. Host credential/bootstrap configuration, installation lifecycle, and formal release packaging remain outside the verified capability boundary.

## Quick start

The safe first path is Preview-only: [Getting Started](docs/getting-started.md).

The guide uses a source checkout, a dependency-ready Python environment, and a local stdio MCP server. A first Preview may change local Runtime state, but it does not modify GitHub and does not imply Approval.

## First Preview

Start with a clear intent, problem, desired outcome, scope, non-goals, acceptance criteria, and verification expectation. The guide includes a representative inventory batch-tracking example and explains how to interpret the resulting Preview and Revision.

## Write-enabled use

A separate `github-app-write` Host profile supports the governed write-enabled path. It requires operator configuration. Apply is the only stage that may modify GitHub. See [Host configuration](docs/host-configuration.md) for the canonical operator contract; it is not required for the Preview-only first run.

## Documentation

| Audience | Start here | Purpose |
| --- | --- | --- |
| User | [Getting Started](docs/getting-started.md) | Source checkout, startup, and first safe Preview |
| Operator | [Host configuration](docs/host-configuration.md) | Write-enabled Host configuration |
| Maintainer | [Architecture and lifecycle](docs/architecture-and-lifecycle.md) | Runtime and lifecycle architecture |
| Maintainer | [Debt register](docs/debt-register.md) | Deferred work and residual responsibilities |

## Maintainer / operator references

The repository is MIT licensed. Public product documentation is written for users first; architecture, lifecycle, Host configuration, and debt details remain in their respective maintained documents.
