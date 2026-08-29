# Delivery System Engineering Rules

## Product direction

* Delivery System turns user ideas and development discoveries into reviewed, approved, traceable GitHub work items.
* GitHub is the V1 source of truth for formal work items. Local files may support input, recovery, execution state, and derived state, but must not become a second requirements database.
* The three user jobs are planning work items, independently auditing a sealed preview, and applying an explicitly approved preview.
* Optimize for a complete, trustworthy user journey. Do not optimize for maximum protocol, schema, or infrastructure completeness in isolation.
* Prefer vertical slices that make a user-visible workflow executable and testable.
* Add or expand Runtime infrastructure only when it is consumed by the current approved vertical slice or is required to close a demonstrated safety defect.

## Instruction and state hierarchy

Use the following authority order when determining what to do:

1. the user's current explicit authorization;
2. the applicable `AGENTS.md` instruction chain;
3. the current repository and Git state;
4. `.dev/skill-brief.md` and approved design material;
5. historical review or investigation records.

The current Git state is authoritative for Branch, HEAD, staged state, tracked modifications, and committed history.

If `.dev/skill-brief.md` disagrees with the repository, do not force the repository to match the brief. Treat the brief as stale, report the discrepancy, and update the brief only when authorized within the current work unit.

A roadmap item, TODO, old Finding, design idea, or historical next action is not current authorization.

## Artifact semantics

* Public files are final product artifacts for users and maintainers, not transcripts of the Codex interaction.
* Write public code, documentation, examples, generated Issue content, and templates in durable product voice.
* Do not use conversational first-person narration such as “I changed”, “we decided”, “this round”, or “next I will” inside public artifacts.
* Public documentation may accurately state available capabilities, limitations, prerequisites, and evidence levels. It must not contain session narration, temporary investigation notes, approval conversations, or migration diaries.
* Keep temporary requirements, research evidence, review packages, checkpoints, and discussion notes under ignored `.dev/`.
* Never ship `.dev/` content or use development-process files as Runtime sources of truth.

## Active development brief

* `.dev/skill-brief.md` is the concise active development brief, not a chronological log.
* Keep only the current product direction, frozen decisions, latest implemented checkpoint, current milestone, genuinely open product decisions, current blockers, and deferred release prerequisites.
* Replace obsolete statements instead of appending newer contradictory statements.
* Closed Finding histories, old implementation rounds, superseded checkpoints, and detailed investigation trails belong in the relevant `.dev/design/` closure records, not in the active brief.
* Do not append per-run test output, temporary paths, ZIP paths, transient hashes, Git narration, or completed review histories.
* The latest committed Branch/HEAD and current worktree state must supersede stale checkpoint text.
* Explicit current user instructions override the brief. When an approved decision or checkpoint changes, update the brief in the same work unit when that update is authorized and useful.
* The brief informs development but is not a public artifact, Runtime input, remote fact source, executable contract, or substitute for tests.

## Baseline gate

Before any work unit that may modify project files, dependencies, Git state, databases, or external systems:

* identify the current Branch and HEAD;
* inspect `git status --short`;
* inspect staged state;
* preserve ignored `.dev/` material;
* compare the actual repository state with any baseline explicitly supplied in the authorization.

If the authorization names an expected Branch, HEAD, Parent, clean state, or file scope and the actual state does not match, stop before mutation and report the mismatch.

Do not silently reinterpret a baseline or continue from a different commit because the repository “looks close enough.”

Read-only investigation may proceed only when the mismatch itself is the subject of the investigation.

## Decision authority

User approval is required before:

* changing the product problem, user-visible behavior, V1 scope, non-goals, or permission boundary;
* adding, removing, merging, or splitting a user-visible Skill;
* performing an external write or changing its approval semantics;
* introducing authentication, a production dependency, global configuration, a distribution channel, or a remote service;
* changing a released or externally consumed data contract in a compatibility-breaking way;
* performing a destructive or difficult-to-recover operation;
* staging or committing changes unless the current authorization explicitly permits that Git action;
* changing branches, merging, rebasing, cherry-picking, resetting, pushing, or modifying remote state unless explicitly authorized.

Within an approved work unit, Codex owns:

* internal module layout, private names, helper APIs, test organization, and low-risk refactoring;
* deterministic implementation details that preserve the approved behavior and trust boundary;
* internal validation, error representation, and storage details that are not externally consumed;
* fixing defects and review findings that remain inside the approved responsibility, file scope, non-goals, and side-effect boundary.

Before the first release, an internal protocol detail is not automatically a user decision. Codex may choose a deterministic, tested, reversible design when it does not change user-visible semantics, permissions, external effects, compatibility commitments, or the authorized scope.

When ambiguity remains:

* proceed with a documented assumption when the choice is internal, reversible, inside the authorized scope, and covered by tests;
* ask the user only when reasonable alternatives materially change product behavior, security, external writes, irreversible data, public compatibility, project scope, or authorization;
* batch related product questions instead of requesting one approval per field, enum, digest, or error code.

## Authorization coverage and scope discipline

* A user-approved slice authorizes all necessary internal implementation decisions within its stated responsibility, files, non-goals, and side-effect boundary.
* Authorization is a ceiling, not a starting point for broader cleanup.
* Do not modify an additional file, dependency, external system, Git ref, or trust boundary merely because doing so would make the implementation cleaner.
* Do not create micro Contract Amendments for ordinary implementation choices already implied by the approved slice.
* A new Finding may be fixed without reopening Product Discovery only when the fix remains inside the current authorized responsibility and mutation scope.
* If a Finding requires a new file scope, dependency, external effect, architectural commitment, permission, or independently valuable feature, record it and stop for separate authorization.
* Reopen the product Contract only when concrete evidence shows that the approved behavior is contradictory, unsafe, impossible, or materially incomplete.
* If a genuine product decision blocks the work, report the conflict, alternatives, consequences, and one recommended choice in a single decision request.
* Do not “fix while here” unrelated defects, formatting, dependency versions, documentation, or technical debt.

## Stop and failure-closed discipline

Stopping at a proven boundary is a successful engineering outcome.

Stop rather than improvise when:

* required evidence is unavailable;
* an authorized operation would require expanding file, dependency, network, Git, database, or product scope;
* a lock or artifact field cannot be derived from trustworthy evidence;
* a tool would introduce unrelated dependency or file churn;
* an implementation would leave a knowingly incomplete contract;
* the requested verification cannot honestly establish the claimed evidence level;
* a new independent Finding appears outside the current authorized work unit;
* an expected baseline no longer matches.

Never fabricate or guess:

* hashes;
* package artifacts;
* lock metadata;
* remote state;
* capabilities;
* permissions;
* test evidence;
* Git history;
* approval state.

Do not turn an inability to prove correctness into a permissive fallback.

When temporary exploratory changes are necessary, do not leave knowingly invalid or half-completed tracked state at the end of the work unit. Preserve unrelated user changes and never use broad reset or clean operations to achieve this.

## Failure-source classification

Before changing production code in response to a failure, determine the responsible layer as precisely as practical.

Classify failures into one or more of:

* Product or behavior contract;
* Production code;
* Test contract;
* Dependency metadata;
* Dependency lock;
* Build system;
* Runtime environment;
* Tooling;
* External or remote system;
* Data or persisted state.

A failing test does not by itself prove a production-code defect.

Environment, build, dependency, lock, and tooling failures must not be “fixed” by modifying production behavior unless evidence shows production behavior is actually incorrect.

If the responsible layer cannot yet be proven, perform bounded diagnosis before repair.

## Vertical work units

Every implementation work unit must define:

* one user job or safety property;
* an observable input and output;
* the consumer of every new file or component;
* explicit non-goals and side-effect boundaries;
* deterministic completion evidence;
* the next user-visible validation level.

A work unit must not exist solely to introduce another abstraction layer, schema family, placeholder module, or future architecture.

Except for an explicitly authorized corrective safety repair, each slice must advance at least one executable product path through Skill, tool, Runtime, or external integration.

## Skill engineering

* One Skill maps to one recognizable user job.
* Split Skills only when their triggers, permissions, outputs, or lifecycles are independently different.
* Use the official `skill-creator` workflow when creating or materially updating a Skill.
* A Skill defines triggers, workflow, decision points, stop conditions, tool use, outputs, and failure feedback.
* Deterministic algorithms, identity generation, persistence, authorization checks, and external actions belong in tested Runtime or tools, not duplicated prose across Skill files.
* Skill instructions must not claim semantic quality, Host behavior, installation success, or integration support without the corresponding executed evidence.
* Test realistic trigger phrasing and negative triggers, not only structure and frontmatter.

## File consumer rule

Before adding a file, identify:

* who consumes it;
* when and how it is consumed;
* why an existing file cannot serve that responsibility;
* how its behavior is verified;
* whether it ships in the release package.

Do not add a file without a real consumer. Tests, validators, packaging, and explicitly approved development tooling are valid consumers. Speculative future architecture is not.

## Evidence levels

Use these terms precisely:

* **Designed** — design only.
* **Implemented** — implementation exists.
* **Statically Validated** — structure or static checks pass.
* **Deterministically Tested** — deterministic tests pass.
* **Behavior Tested** — realistic Skill behavior cases were executed.
* **Host Tested** — executed through a real Codex or ChatGPT host.
* **Integration Tested** — executed against the real external platform.
* **Install Tested** — installed through the intended installation channel.
* **Released** — formally published.

Never promote evidence from one level to another. Defined scenarios are not executed tests; local stdio tests are not Host Tests; test fixtures are not external integration.

## Verification evidence reuse

Verification evidence is reusable when the state it proves has not been invalidated.

Before rerunning an expensive validation, determine:

* which files, dependency contracts, locks, schemas, runtime assumptions, or external facts the existing evidence covered;
* whether any of those inputs changed after the evidence was produced;
* whether the execution environment remains equivalent where environment identity matters.

If the covered state is unchanged, inherit the existing evidence instead of rerunning it solely for ceremony.

A commit created directly from an already reviewed and verified worktree does not invalidate that evidence when the committed content is identical.

Invalidate and rerun affected evidence when relevant code, tests, dependencies, locks, schemas, configuration, environment assumptions, or remote facts change.

Do not reuse evidence merely because a test passed somewhere in historical project records.

## Validation strategy

Use the smallest applicable validation set while preserving confidence:

1. Run focused failure-first or regression tests for the changed behavior.
2. Run the relevant slice suite.
3. Run the full deterministic suite before a checkpoint commit when existing valid full-suite evidence is unavailable or has been invalidated.
4. Validate Skill structure when a Skill changes.
5. Run realistic behavior, Host, external integration, installation, and public-semantic tests only when the work reaches those boundaries.

Do not rerun a full suite when still-valid full-suite evidence already covers the exact candidate state.

Do not manufacture test layers that the current work cannot honestly execute.

Do not describe a suite as clean when collection errors, skipped required validators, environment failures, or unexecuted required paths prevent that claim.

## Review discipline

* Perform one bounded design/threat review before implementing a risky slice and one closure review after implementation.
* Group related Findings into a single repair batch and rerun the affected review after the batch.
* Do not generate a new ZIP, review package, phase report, or approval request after every individual Finding.
* Continue review when unresolved Blocker or High findings remain, but do not reopen already closed decisions without new evidence.
* Historical Finding identifiers are evidence, not an invitation to rerun old reviews.
* A Finding marked Closed, Superseded, Deferred, or Misattributed must not be reopened without new evidence.
* A closure review proves only its named contract and evidence level.

## Environment and build discipline

* Keep project behavior, dependency contracts, build tooling, installer behavior, and host environment concerns distinct.
* Do not install or mutate global or user-level tools or packages unless explicitly authorized.
* Prefer temporary isolated environments for dependency, build, installation, and compatibility verification.
* `[build-system].requires` is a build-time contract and must not be silently promoted into Runtime dependencies.
* Installer or package-manager limitations do not automatically justify changing project behavior or lock semantics.
* When a lock is being validated, distinguish packages explicitly locked by the project from bootstrap and build tooling used only to consume that lock.
* Temporary environments, wheelhouses, build directories, metadata, and diagnostics created by a work unit must be removed when the work unit completes, provided they are clearly attributable to that work unit.
* Never use `git clean` as a general cleanup mechanism.

## Git workflow

* `main` contains only reviewed, public artifacts.
* Develop on feature or governance branches.
* Keep planning, implementation, governance, dependency correction, and release preparation as separately reviewable changes when they represent distinct responsibilities.
* Do not push directly to `main`.
* Do not commit, push, create a PR, modify a remote, change branches, merge, rebase, cherry-pick, reset, or tag unless the current user instruction authorizes that exact action.
* Preserve unrelated user changes and ignored local development material.
* `.dev/` must never be staged or committed.
* Do not use `git add .`, `git add -A`, or `git add --all` when an explicit file scope is known.
* When staging is authorized, stage explicit paths and inspect the cached diff before committing.
* Do not bypass commit hooks with `--no-verify` unless the user explicitly authorizes that exception.
* Do not amend a commit unless explicitly authorized.
* Before a checkpoint commit, report the exact file set, validation evidence, and remaining unverified capabilities.
* After a commit, verify the new HEAD, Parent, Subject, committed file set, worktree state, and ignored `.dev/` state.
* Push authorization is separate from commit authorization.

## Branch lifecycle and integration

A branch scope is defined by its approved objective, not by every future roadmap item that could logically follow it.

When the branch's approved objective is complete:

* do not automatically start the next Slice;
* do not add unrelated roadmap work merely because the current branch is convenient;
* reconcile outstanding Findings and verification evidence;
* determine whether the branch is complete;
* enter a separate branch-completion and integration decision.

Before integration, determine the correct target from both project records and actual Git ancestry. Do not assume the target is `main`, an integration branch, or the preceding feature branch based only on naming.

A local roadmap item remaining `Not Started`, `Deferred`, or `Not Authorized` does not make a completed feature branch incomplete.

Do not rewrite branch history, rebase, cherry-pick, merge, delete the branch, or push without explicit authorization for that operation.

## Checkpoint and handoff discipline

A checkpoint records where the project is now, not the full story of how it arrived there.

At an approved checkpoint, retain enough state to recover:

* current Branch and HEAD;
* current milestone and branch objective;
* open blockers or decisions;
* current evidence level;
* current authorized or next legal transition.

Do not copy entire review histories into the active checkpoint.

When a session resumes:

1. load the applicable `AGENTS.md`;
2. read the current `.dev/skill-brief.md`;
3. inspect the actual Git state;
4. reconcile the brief with Git;
5. continue from the latest valid checkpoint instead of repeating completed work.

If context from an earlier session is missing but repository evidence is sufficient, reconstruct from repository state instead of rerunning completed implementation.

## Working sequence

Use this sequence:

Product direction → bounded vertical-slice contract → one user approval → implementation → focused and regression validation → closure review → checkpoint → branch completion/integration when appropriate → user-visible behavior/Host/integration validation → release preparation.

Do not restart Discovery between these steps unless a genuine product-level contradiction is found.

Do not treat “there is more roadmap work” as evidence that the current branch or work unit remains incomplete.

## Session loading

* Codex loads the applicable `AGENTS.md` instruction chain when a session starts.
* A file created or changed during the current session must not be described as governing that same session.
* After changing this root `AGENTS.md`, stop at a clean review point so the user can start a new Codex session before further project work.
* In the new session, reload the active brief and actual repository state before accepting historical checkpoint assumptions.
