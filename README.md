# Delivery System

Delivery System 是一个平台无关的软件交付工作流系统。它把模糊 Idea 推进为可审查、可执行、可追踪、可变更和可验收的交付闭环。

项目当前处于早期设计阶段。首版优先建立平台无关的 Core；OpenAI/Codex 只是未来的首个可选适配器，不是项目核心。

## 当前范围

- `core/`：角色、工作流、策略、产物协议与一致性规则的唯一事实来源；
- `adapters/delivery-system-openai/`：OpenAI/Codex 的 skills-only Adapter；
- `plugins/delivery-system-openai/`：由 Adapter 生成、供本地 marketplace 安装的分发包；
- `tests/`：Core 行为、fixture 与预期结果；
- `scripts/validate_v0.py`：不依赖第三方包的 V0 结构一致性校验。

当前 Core 审查稿见 [CORE-CONTRACT.md](core/CORE-CONTRACT.md)。

## 项目状态

尚未公开发布、尚未提供外部集成或自有 MCP。OpenAI/Codex Adapter 已完成本地结构校验与 marketplace 安装；新会话中的显式/隐式触发仍需人工体验验证。未核验的平台能力必须标记为 `TBD / Requires verification`。

## 许可证

本项目采用 [MIT License](LICENSE)。

## 贡献与支持

贡献方式见 [CONTRIBUTING.md](CONTRIBUTING.md)。安全问题见 [SECURITY.md](SECURITY.md)。公开支持渠道将在项目发布准备阶段确定。

## 使用与维护

- [本地安装与更新](docs/guides/local-install.md)
- [使用 Delivery System](docs/guides/using-delivery-system.md)
- [常见问题](docs/guides/faq.md)
- [Adapter 与分发包维护](docs/guides/adapter-maintenance.md)
- [版本与发布维护](docs/maintainers/versioning-and-releases.md)
- [跨平台 Adapter 路线](docs/roadmap/cross-platform-adapters.md)
- [发布前检查清单](docs/release/openai-codex-release-checklist.md)
- [V0 完善任务总览](docs/tasks/v0-completion/README.md)
