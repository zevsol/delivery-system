# Delivery System

Delivery System 是一个平台无关的软件交付工作流系统。它把模糊 Idea 推进为可审查、可执行、可追踪、可变更和可验收的交付闭环。

项目当前处于早期设计阶段。首版优先建立平台无关的 Core；OpenAI/Codex 只是未来的首个可选适配器，不是项目核心。

## 当前范围

- `core/`：角色、工作流、策略、产物协议与一致性规则的唯一事实来源；
- `adapters/`：未来的平台适配器，尚未创建；
- `tests/`：未来的 Core 行为与适配器一致性测试，尚未创建。

当前 Core 审查稿见 [CORE-CONTRACT.md](core/CORE-CONTRACT.md)。

## 项目状态

尚未发布、尚未提供外部集成，也尚未承诺任何特定平台的适配格式或能力。未核验的平台能力必须标记为 `TBD / Requires verification`。

## 许可证

本项目采用 [MIT License](LICENSE)。

## 贡献与支持

贡献方式见 [CONTRIBUTING.md](CONTRIBUTING.md)。安全问题见 [SECURITY.md](SECURITY.md)。公开支持渠道将在项目发布准备阶段确定。
