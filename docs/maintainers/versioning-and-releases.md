# 版本与发布维护

Delivery System 使用语义化版本原则：破坏性 Core 或 Adapter 语义变更为 Major；向后兼容的新规则、模板或能力为 Minor；不改变语义的澄清和修正为 Patch。Core 变更还必须评估 Schema、测试、Adapter 投影和生成分发包的兼容性。

发布分为四条独立路线：GitHub 源码、GitHub Release、Codex/ChatGPT 本地安装和 OpenAI Plugin Directory。任一渠道完成不代表其他渠道已经发布。

每次准备发布时：更新 CHANGELOG；更新 canonical Adapter；生成 `plugins/` 分发包；运行适用校验；检查 marketplace 与文档；依照分支策略创建 PR；创建 Git 标签和 GitHub Release（如适用）；再按渠道发布。完整门槛见 [OpenAI/Codex 发布前检查清单](openai-codex-release-checklist.md)。

OpenAI Plugin Directory 的提交条件和审核材料以当前官方文档与提交门户为准，不应从本地 marketplace 安装结果推断。
