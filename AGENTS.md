# Codex Skill Engineering Foundation

## Artifact boundary

- Public files serve end users and maintainers; write them as durable product material.
- Do not put chat-style language, execution narration, investigation notes, or one-off implementation specifications in public files.
- Do not use public files to describe a working session, a phase completion, future agent actions, or migration history.
- Put temporary requirements, research evidence, and discussion notes only in ignored `.dev/`.
- Never include `.dev/` content in a public release package.
- Development-process files are never runtime sources of truth.

## Preconditions for a Skill

Before implementing a Skill, establish and have approved:

- the user problem and one core responsibility;
- inputs, outputs, non-goals, external systems, and permission boundary;
- at least three positive examples and two negative or boundary examples;
- a definition of done and verifiable evidence.

Ask the user for missing boundary information. Do not implement from an incomplete brief.

## Skill design

- One Skill maps to one recognizable user job.
- Do not split Skills merely to mirror code layers. Split only when triggers, permissions, outputs, or lifecycles are independently different.
- State triggers, inputs, steps, outputs, stop conditions, and failure feedback clearly.
- Keep historical developer explanation and no-consumer documentation out of Skill contents.
- Using official `$skill-creator` does not override this repository's approved boundaries.

## File consumer rule

Before adding any file, answer: who reads it, when, why it is needed, how it is verified, and whether it ships in a release package. Do not create a file without those answers.

## Evidence levels

Use these terms precisely:

- **Designed** — design only.
- **Implemented** — implementation exists.
- **Statically Validated** — structure or static checks pass.
- **Deterministically Tested** — deterministic tests pass.
- **Host Tested** — triggered in a real Codex or ChatGPT host.
- **Integration Tested** — tested against a real external platform.
- **Install Tested** — installed through the target installation channel.
- **Released** — formally published.

Never use lower-level evidence to claim a higher-level capability.

## Test layers

Select and report the applicable layers:

1. Structure and static validation.
2. Deterministic unit tests.
3. Skill trigger and behavior tests.
4. Host-environment tests.
5. External tool or platform integration tests.
6. Installation and distribution tests.
7. Public-semantic review before release.

Defining test scenarios is not executing tests.

## Change control

Request user approval before expanding scope, adding dependencies, introducing external writes, modifying global configuration, creating distribution channels, adding a user-visible Skill, or presenting an idea as an implemented capability.

## Git workflow

- `main` holds only public, releasable artifacts.
- Develop on feature branches.
- Do not place unverified development artifacts directly on `main`.
- Do not push directly to `main`.
- Before merge, provide exact test evidence and remaining unverified items.
- Local `.dev/` material is excluded from releases.

## Standard workflow

Discovery → boundary confirmation → examples and counterexamples → contract preview → user approval → implementation → deterministic validation → real-host test → installation or integration test → public-semantic review → release preparation.

Keep planning, implementation, and release preparation as separately reviewable changes.

## Session loading fact

A newly created `AGENTS.md` must not be described as governing the session that created it. It guides Codex sessions started later in this repository. The creating session can validate only file content and structure, not host loading.
