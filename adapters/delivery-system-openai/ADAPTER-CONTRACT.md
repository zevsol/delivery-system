# Delivery System for OpenAI：Adapter Contract

> Adapter ID：`delivery-system-openai`
>
> Core Version：`0.1.0-draft`
>
> 状态：实验性 Adapter；已完成本地 marketplace 安装，尚未完成真实宿主端到端验证或官方目录发布

## 目标平台与角色映射

目标平台为 ChatGPT 与 Codex。该 Adapter 将三个 Core Role/Workflow 映射为三个 Skill：

| Core Role / Workflow | OpenAI/Codex Skill |
|---|---|
| Idea to Delivery | `idea-to-delivery` |
| Audit Delivery | `audit-delivery` |
| Execute Delivery | `execute-delivery` |

## 能力与限制

- 触发方式：Skill 描述的隐式匹配，或 ChatGPT `@` / Codex `$` 显式调用；
- 文件读写、审批和外部工具能力：由当前宿主、工作区和用户授权决定；
- 外部操作：本 Adapter 不声明 MCP、不创建 GitHub Issue、不发布内容；
- 审批降级：无法获得明确用户批准时，输出草稿、预览或 Blocked 状态；
- 已知限制：跨 Skill 共享资源的运行时行为需要安装测试验证。

## Core 同步规则

Skill 下的 `references/core-projection.md` 是针对该角色的受控同步投影，来源为仓库 `core/` 的 `0.1.0-draft` 语义。它不是独立事实来源。修改投影时必须同时审查其 Core 来源与 Conformance 场景；Core 变更后必须重新检查所有投影。

## Conformance

本 Adapter 已完成本地 marketplace 安装与仓库级一致性校验。发布或宣称完整支持前，仍必须通过 `tests/conformance/core-behavior.md` 中适用场景，以及平台特定的触发、权限和真实宿主测试。当前验证边界见 `docs/maintainers/validation-status.md`。
