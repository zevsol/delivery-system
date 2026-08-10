# Codex Skill Engineering Foundation

This repository is a small, durable foundation for engineering public, testable, installable Codex Skills and Plugins. It addresses the gap between an idea for a reusable workflow and evidence-backed, maintainable delivery.

It provides engineering rules only. It contains no business Skill, Plugin package, connector, or product implementation.

## Use a local brief

Copy the prompts in `.dev/skill-brief.md` into a completed local brief, or edit that file directly. The brief is ignored by Git. Codex checks its completeness, asks about material gaps, previews the contract, and waits for approval before implementation. A brief is development input, not the eventual user documentation for a Skill.

## How work is governed

[`AGENTS.md`](AGENTS.md) requires a clear user problem, one core responsibility, inputs, outputs, non-goals, permissions, examples, and evidence before a Skill is built. Use official `$skill-creator` after those boundaries are approved when it helps scaffold or refine a Skill; it does not replace the repository rules.

The official model treats a Skill as a focused `SKILL.md` workflow with optional resources, while a Plugin is an installable distribution package. Validate a Skill's behavior first; package or publish it only after behavior evidence supports that later step. See the official [Skill documentation](https://developers.openai.com/plugins/build/skills) and [Plugin packaging documentation](https://developers.openai.com/plugins/build/plugins).

Evidence is reported as Designed, Implemented, Statically Validated, Deterministically Tested, Host Tested, Integration Tested, Install Tested, or Released. Each label has the meaning defined in `AGENTS.md`; none implies a stronger label.

Public versions exclude local briefs, credentials, caches, logs, generated packages, and other development-only material.
