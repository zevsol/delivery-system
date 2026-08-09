# Delivery System

Delivery System 是一套面向 AI 辅助软件开发的交付工作流。它将模糊想法推进为有需求、架构决策、可执行 Issue、验证证据与变更记录的交付基线，而不是直接把一句需求转换成代码。

首个实现目标是 ChatGPT/Codex：通过三个 Skill 分别负责规划、独立审查和受控执行。平台无关的交付规则保留在 `core/`，因此未来可以为其他宿主实现独立 Adapter，而不复制或改变治理语义。

> **状态：预发布 / Experimental。** Adapter 已完成仓库结构校验和本地 marketplace 安装，但尚未完成真实 ChatGPT/Codex 宿主中的端到端验证。请用于评估、学习和贡献，不要将其视为生产可用承诺。详见 [项目状态](docs/project/status.md)。

## 已实现的能力

| Skill | 用途 | 主要产出 |
|---|---|---|
| `idea-to-delivery` | 将 Idea 或变更请求推进为可审查的交付计划 | Brief、Requirements、ADR、Roadmap、Issue、Change Request |
| `audit-delivery` | 独立、只读地审查计划或交付证据 | 有证据的 Finding 与所需决定 |
| `execute-delivery` | 在已批准且无阻塞的 Issue 范围内实施 | 实现、验证证据与 Completion Report |

Core 同时提供角色边界、Issue 粒度、质量门、追踪关系、变更管理、模板和 JSON Schema。完整规范见 [Core Contract](core/CORE-CONTRACT.md)。

## 快速开始

前提：已安装 Codex CLI，并已克隆本仓库。请在仓库根目录运行：

```powershell
codex plugin marketplace add .
codex plugin add delivery-system-openai --marketplace delivery-system
```

在新会话中优先显式调用 Skill：

```text
$idea-to-delivery 我想为现有产品增加一个可配置的导出功能。

$audit-delivery 审查当前的需求、ADR 和 Issue，列出带证据的 Findings。

$execute-delivery 按 ISSUE-017 实现；先检查依赖、验收标准和范围外风险。
```

完整安装、更新和卸载步骤见 [本地安装](docs/guides/local-install.md)，工作流说明见 [使用指南](docs/guides/using-delivery-system.md)。

## 当前不支持的内容

- MCP Server、GitHub/Linear/Jira 集成或自动外部写操作；
- 自动创建 Issue、发布内容或替用户作出范围、架构、审查和发布决定；
- OpenAI/Codex 以外的平台 Adapter；
- OpenAI Plugin Directory 上架、托管服务或稳定版支持承诺。

## 仓库结构

```text
core/       平台无关的角色、工作流、政策、模板和 Schema
adapters/   canonical 平台 Adapter 源码
plugins/    由 canonical Adapter 生成的本地安装包
tests/      Core 行为场景与测试资产
scripts/    构建与仓库一致性校验脚本
docs/       用户指南、维护指南和项目状态
```

`plugins/` 是生成内容；请修改 `core/` 或 `adapters/`，再重新构建分发包。具体流程见 [Adapter 维护](docs/maintainers/adapter-maintenance.md)。

## 文档

### 使用者

- [本地安装、更新与卸载](docs/guides/local-install.md)
- [使用 Delivery System](docs/guides/using-delivery-system.md)
- [常见问题](docs/guides/faq.md)

### 维护者与贡献者

- [项目状态与路线图](docs/project/status.md)
- [仓库分支与 PR 工作流](docs/project/repository-workflow.md)
- [Adapter 与分发包维护](docs/maintainers/adapter-maintenance.md)
- [验证状态](docs/maintainers/validation-status.md)
- [版本与发布维护](docs/maintainers/versioning-and-releases.md)
- [OpenAI/Codex 发布前检查清单](docs/maintainers/openai-codex-release-checklist.md)
- [新平台 Adapter 开发指南](docs/maintainers/adapter-development.md)

## 贡献、安全与许可证

贡献方式见 [CONTRIBUTING.md](CONTRIBUTING.md)。非敏感使用问题见 [SUPPORT.md](SUPPORT.md)，安全问题见 [SECURITY.md](SECURITY.md)。本项目采用 [MIT License](LICENSE)。
