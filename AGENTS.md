# Delivery System Engineering Rules

## Product direction

- Delivery System turns user ideas and development discoveries into reviewed, approved, traceable GitHub work items.
- GitHub is the V1 source of truth for formal work items. Local files may support input, recovery, and derived state, but must not become a second requirements database.
- The three user jobs are planning work items, independently auditing a sealed preview, and applying an explicitly approved preview.
- Optimize for a complete, trustworthy user journey. Do not optimize for maximum protocol, schema, or infrastructure completeness in isolation.
- Prefer vertical slices that make a user-visible workflow executable and testable.
- Add or expand Runtime infrastructure only when it is consumed by the current approved vertical slice or is required to close a demonstrated safety defect.

## Artifact semantics

- Public files are final product artifacts for users and maintainers, not transcripts of the Codex interaction.
- Write public code, documentation, examples, generated Issue content, and templates in durable product voice.
- Do not use conversational first-person narration such as “I changed”, “we decided”, “this round”, or “next I will” inside public artifacts.
- Public documentation may accurately state available capabilities, limitations, prerequisites, and evidence levels. It must not contain session narration, temporary investigation notes, approval conversations, or migration diaries.
- Keep temporary requirements, research evidence, review packages, and discussion notes under ignored `.dev/`.
- Never ship `.dev/` content or use development-process files as Runtime sources of truth.

## Active development brief

- `.dev/skill-brief.md` is the concise active development brief, not a chronological log.
- Keep only the current product direction, frozen decisions, implemented checkpoint, current milestone, open product decisions, and deferred release prerequisites.
- Replace obsolete statements instead of appending newer contradictory statements.
- Do not append per-run test output, ZIP paths, hashes, Git status, review narration, or completed Finding histories.
- Explicit current user instructions override the brief. When an approved decision changes, update the active brief in the same work unit.
- The brief informs development but is not a public artifact, Runtime input, remote fact source, or substitute for executable tests.

## Decision authority

User approval is required before:

- changing the product problem, user-visible behavior, V1 scope, non-goals, or permission boundary;
- adding, removing, merging, or splitting a user-visible Skill;
- performing an external write or changing its approval semantics;
- introducing authentication, a production dependency, global configuration, a distribution channel, or a remote service;
- changing a released or externally consumed data contract in a compatibility-breaking way;
- performing a destructive or difficult-to-recover operation.

Within an approved work unit, Codex owns:

- internal module layout, private names, helper APIs, test organization, and low-risk refactoring;
- deterministic implementation details that preserve the approved behavior and trust boundary;
- internal validation, error representation, and storage details that are not externally consumed;
- fixing defects and review findings that remain inside the approved scope.

Before the first release, an internal protocol detail is not automatically a user decision. Codex may choose a deterministic, tested, reversible design when it does not change user-visible semantics, permissions, external effects, or compatibility commitments.

When ambiguity remains:

- proceed with a documented assumption when the choice is internal, reversible, and covered by tests;
- ask the user only when reasonable alternatives materially change product behavior, security, external writes, irreversible data, public compatibility, or project scope;
- batch related product questions instead of requesting one approval per field, enum, digest, or error code.

## Approval coverage

- A user-approved slice authorizes all necessary internal implementation decisions within its stated responsibility, files, non-goals, and side-effect boundary.
- Do not create micro Contract Amendments for ordinary implementation choices already implied by the approved slice.
- A new Finding inside the approved boundary should be fixed and tested without reopening product Discovery.
- Reopen the product Contract only when concrete evidence shows that the approved behavior is contradictory, unsafe, impossible, or materially incomplete.
- If a genuine product decision blocks the work, report the conflict, alternatives, consequences, and one recommended choice in a single decision request.

## Vertical work units

Every implementation work unit must define:

- one user job or safety property;
- an observable input and output;
- the consumer of every new file or component;
- explicit non-goals and side-effect boundaries;
- deterministic completion evidence;
- the next user-visible validation level.

A work unit must not exist solely to introduce another abstraction layer, schema family, placeholder module, or future architecture.

Except for an explicitly authorized corrective safety repair, each slice must advance at least one executable product path through Skill, tool, Runtime, or external integration.

## Skill engineering

- One Skill maps to one recognizable user job.
- Split Skills only when their triggers, permissions, outputs, or lifecycles are independently different.
- Use the official `skill-creator` workflow when creating or materially updating a Skill.
- A Skill defines triggers, workflow, decision points, stop conditions, tool use, outputs, and failure feedback.
- Deterministic algorithms, identity generation, persistence, authorization checks, and external actions belong in tested Runtime or tools, not duplicated prose across Skill files.
- Skill instructions must not claim semantic quality, Host behavior, installation success, or integration support without the corresponding executed evidence.
- Test realistic trigger phrasing and negative triggers, not only structure and frontmatter.

## File consumer rule

Before adding a file, identify:

- who consumes it;
- when and how it is consumed;
- why an existing file cannot serve that responsibility;
- how its behavior is verified;
- whether it ships in the release package.

Do not add a file without a real consumer. Tests and validators are valid consumers; speculative future architecture is not.

## Evidence levels

Use these terms precisely:

- **Designed** — design only.
- **Implemented** — implementation exists.
- **Statically Validated** — structure or static checks pass.
- **Deterministically Tested** — deterministic tests pass.
- **Behavior Tested** — realistic Skill behavior cases were executed.
- **Host Tested** — executed through a real Codex or ChatGPT host.
- **Integration Tested** — executed against the real external platform.
- **Install Tested** — installed through the intended installation channel.
- **Released** — formally published.

Never promote evidence from one level to another. Defined scenarios are not executed tests; local stdio tests are not Host Tests; test fixtures are not external integration.

## Validation strategy

Use the smallest applicable validation set while preserving confidence:

1. Run focused failure-first or regression tests for the changed behavior.
2. Run the relevant slice suite.
3. Run the full deterministic suite before a checkpoint commit.
4. Validate Skill structure when a Skill changes.
5. Run realistic behavior, Host, external integration, installation, and public-semantic tests only when the work reaches those boundaries.

Do not manufacture test layers that the current work cannot honestly execute.

## Review discipline

- Perform one bounded design/threat review before implementing a risky slice and one closure review after implementation.
- Group related Findings into a single repair batch and rerun the affected review after the batch.
- Do not generate a new ZIP, review package, phase report, or approval request after every individual Finding.
- Continue review when unresolved Blocker or High findings remain, but do not reopen already closed decisions without new evidence.
- A closure review proves only its named contract and evidence level.

## Git workflow

- `main` contains only reviewed, public artifacts.
- Develop on feature or governance branches.
- Keep planning, implementation, governance, and release preparation as separately reviewable changes.
- Do not push directly to `main`.
- Do not commit, push, create a PR, or modify a remote unless the current user instruction authorizes that exact action.
- Preserve unrelated user changes and ignored local development material.
- Before a checkpoint, report the exact file set, validation evidence, and remaining unverified capabilities.

## Working sequence

Use this sequence:

Product direction → bounded vertical-slice contract → one user approval → implementation → focused and regression validation → closure review → user-visible behavior/Host/integration validation → release preparation.

Do not restart Discovery between these steps unless a genuine product-level contradiction is found.

## Session loading

- Codex loads the applicable `AGENTS.md` instruction chain when a session starts.
- A file created or changed during the current session must not be described as governing that same session.
- After changing this root `AGENTS.md`, stop at a clean review point so the user can start a new Codex session before further product implementation.
