# Getting Started

This guide is for a developer using a source checkout of Delivery System with a local stdio MCP host. The first objective is a safe, Preview-only planning result. It does not establish Install Tested, Host Tested, Integration Tested, or Released evidence.

## Prerequisites

- A source checkout of this repository.
- Python 3.10 or newer.
- An isolated Python environment is recommended.

## Create an isolated environment

From the repository root:

```text
python -m venv .venv
```

Activate `.venv` using the convention for your shell, or invoke its Python executable directly. The executable locations are:

```text
Windows: .venv\Scripts\python.exe
POSIX:   .venv/bin/python
```

Use that environment's `python` and `pip` commands for the remaining steps. Do not rely on ambient user-level packages.

## Install runtime dependencies

The runtime portion of the repository's CI dependency-installation pattern is adapted below for ordinary source use. Run the command after `.venv` exists, using the isolated environment's interpreter:

Windows:

```text
.venv\Scripts\python.exe -m pip --isolated install --no-user --no-cache-dir --index-url https://pypi.org/simple --no-require-hashes -r pylock.toml
```

POSIX:

```text
.venv/bin/python -m pip --isolated install --no-user --no-cache-dir --index-url https://pypi.org/simple --no-require-hashes -r pylock.toml
```

These commands prepare a source-run environment; they are not a formal installation, upgrade, or uninstall lifecycle. CI installs both runtime and test dependency material. `pylock.test.toml` contains test/development dependency material and is not required for normal product use.

## Start the local source server

From the repository root, in the dependency-ready environment, run:

```text
python -B -m mcp_server.server --workspace-root <absolute-path>
```

`<absolute-path>` is the existing workspace whose Delivery System state is being managed. The source-run command is the primary first-checkout path. The declared console script, `delivery-system-mcp`, is package-script metadata and is not used as the primary Quick Start because formal installation has not been established.

This command demonstrates the source server entry point. An MCP Host normally launches the same module as a stdio subprocess; manually starting the command in a terminal is not itself an interactive Host session.

Delivery System stores local Runtime state beneath:

```text
<workspace-root>/.delivery-system/state.sqlite3
```

This local state is not a GitHub mutation. Current workspace identity depends on the workspace path; relocation and portability guarantees are outside this Product Entry workstream.

## Connect a local stdio MCP host

Use a local MCP Host that accepts a stdio server command and an argument array. Configure it with these semantic values:

- Transport: `stdio`.
- Working directory: `<delivery-system-repository-root>`.
- Executable on Windows: `<delivery-system-repository-root>\.venv\Scripts\python.exe`.
- Executable on POSIX: `<delivery-system-repository-root>/.venv/bin/python`.
- Arguments:

  ```text
  -B
  -m
  mcp_server.server
  --workspace-root
  <absolute-workspace-path>
  ```

The repository source must be importable from the configured working directory. Exact host configuration-file or user-interface syntax is Host-specific and is not currently claimed as Host Tested.

The source repository also contains the bundled planning Skill at `skills/plan-github-work-items`. After the server is connected, use the Host's own Skill mechanism to expose or select the user-visible job `plan-github-work-items`. Not every MCP Host automatically loads repository Skills, and no universal Skill-install command is claimed.

## Make the first Preview

The first-run sequence is:

1. Prepare the dependency-ready source environment.
2. Choose an existing workspace path.
3. Configure a local stdio MCP Host to launch the Delivery System source server.
4. Expose or select `plan-github-work-items` using the Host's own Skill mechanism.
5. Give the planning request below to that job.
6. Review the returned Preview and Revision.

A representative request is:

> Track inventory batches. Inventory currently lacks batch tracking. The desired outcome is that users can trace inventory by batch. Scope this to inventory, exclude billing, require that a batch can be recorded, and expect unit test coverage.

This request supplies the planning information a user needs to provide:

- intent and problem;
- desired outcome;
- scope;
- non-goals;
- acceptance criteria;
- verification expectations.

The example is illustrative. It is not evidence of an executed GitHub integration. The bundled Skill and MCP server are source artifacts; a particular ChatGPT, Codex, or other Host setup has not been claimed as Host Tested.

## Understand the Preview

A successful first result means:

- a Preview exists in local Delivery System state;
- its Revision identifies that exact Preview version;
- local Runtime state may have changed;
- GitHub was not modified;
- blockers or clarification findings may still be present;
- write eligibility is not Human Approval.

Preview-only is the safe first path. Audit is the next governed product stage; this guide does not replace the later Audit → Approval → Apply workflow documentation.

## Write-enabled path

Delivery System also has an advanced `github-app-write` Host profile. It requires separate operator configuration and protected credential material. Apply is the GitHub-write boundary. See [Host configuration](host-configuration.md) for the canonical operator contract; do not publish tokens, private keys, or other protected material in public issues.

The optional `--host-profile github-app-write` server argument selects that write-enabled composition. It is not part of the Preview-only first run and does not itself perform a GitHub write.

## Evidence boundary

Source code and deterministic local tests establish the source-run path. They do not establish a published package, formal installer, upgrade/uninstall lifecycle, Host Tested integration, external Integration Tested release, or formal Release status.

For maintainer context, see [Architecture and lifecycle](architecture-and-lifecycle.md) and the [Debt register](debt-register.md).
