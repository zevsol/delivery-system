# 项目状态与路线图

## 当前版本

Delivery System 当前处于 `0.1.0` 预发布阶段。仓库已公开，首个 OpenAI/Codex Adapter 可从本地 marketplace 安装；项目尚未声明稳定版，也尚未提交 OpenAI Plugin Directory。

## 已实现

- 平台无关的 Core：角色边界、交付工作流、质量门、变更管理、追踪规则、模板与 JSON Schema；
- 三个 OpenAI/Codex Skill：规划、独立审查与受控执行；
- canonical Adapter 到本地安装包的构建流程；
- Core 行为场景、结构校验与 Adapter/分发包一致性校验；
- 面向贡献者的分支、PR、发布与安全维护规则。

## 已验证与未验证

已完成静态结构、Schema、Skill 文件、Adapter 投影和本地 marketplace 安装校验。尚未完成目标 ChatGPT/Codex 宿主中的新会话发现、显式/隐式触发、文件权限与真实场景端到端验证。

因此，当前版本适合评估、贡献和本地试用，不应被视为生产可用承诺。完整验证边界见 [验证状态](../maintainers/validation-status.md)。

## 当前不包含

- MCP Server 或任何外部系统连接；
- 自动创建 Issue、发布内容或其他外部写操作；
- OpenAI/Codex 以外的平台 Adapter；
- OpenAI Plugin Directory 上架或托管服务。

## 下一阶段

1. 在目标宿主完成端到端验证并记录证据；
2. 根据验证结果修复问题或更新已知限制；
3. 完成独立发布审查；
4. 决定是否创建稳定 GitHub Release，以及是否提交 OpenAI Plugin Directory。

其他平台的支持只会在 OpenAI/Codex 验证完成后，按 [Adapter 路线](../roadmap/cross-platform-adapters.md) 单独评估。
