# Delivery System

Delivery System 是一个平台无关的软件交付工作流系统。它把模糊 Idea 推进为可审查、可执行、可追踪、可变更和可验收的交付闭环。

项目当前处于预发布阶段。首版建立平台无关的 Core，并提供 OpenAI/Codex 的本地可安装 Adapter；Adapter 是 Core 的实现入口，而不是项目语义来源。

## 当前范围

- `core/`：角色、工作流、策略、产物协议与一致性规则的唯一事实来源；
- `adapters/delivery-system-openai/`：OpenAI/Codex 的 skills-only Adapter；
- `plugins/delivery-system-openai/`：由 Adapter 生成、供本地 marketplace 安装的分发包；
- `tests/`：Core 行为、fixture 与预期结果；
- `scripts/validate_v0.py`：不依赖第三方包的 V0 结构一致性校验。

当前 Core 审查稿见 [CORE-CONTRACT.md](core/CORE-CONTRACT.md)。

## 发布状态

源码已公开，但尚未声明稳定版或提交 OpenAI Plugin Directory。OpenAI/Codex Adapter 已完成本地结构校验与本地 marketplace 安装；新会话中的 Skill 发现与显式/隐式触发仍待端到端验证。因此，请将当前版本视为开发预览版，而非生产承诺。

V0 范围仅包含 Core 与 OpenAI/Codex Adapter；不包含 MCP Server、外部写操作或其他平台 Adapter。

## 许可证

本项目采用 [MIT License](LICENSE)。

## 贡献与支持

贡献方式见 [CONTRIBUTING.md](CONTRIBUTING.md)。安全问题见 [SECURITY.md](SECURITY.md)。公开支持渠道将在项目发布准备阶段确定。

## 使用

- [本地安装与更新](docs/guides/local-install.md)
- [使用 Delivery System](docs/guides/using-delivery-system.md)
- [常见问题](docs/guides/faq.md)

## 维护与发布

- [Adapter 与分发包维护](docs/guides/adapter-maintenance.md)
- [版本与发布维护](docs/maintainers/versioning-and-releases.md)
- [新平台 Adapter 开发指南](docs/maintainers/adapter-development.md)
- [发布前检查清单](docs/release/openai-codex-release-checklist.md)

## 项目治理

- [Core Contract](core/CORE-CONTRACT.md)
- [V0 工程计划与验证状态](docs/tasks/v0-completion/README.md)
- [跨平台 Adapter 路线](docs/roadmap/cross-platform-adapters.md)
- [仓库分支与 PR 工作流](docs/project/repository-workflow.md)
