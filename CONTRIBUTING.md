# 贡献指南

Delivery System 处于预发布阶段。欢迎边界明确的文档、Core、Adapter 和验证改进；大规模实现或新的平台 Adapter 应先通过 Issue 或讨论说明范围。

贡献前请先阅读 `README.md`、`core/CORE-CONTRACT.md` 和 [仓库工作流](docs/project/repository-workflow.md)，并确保提议不会把平台私有格式、工具能力或发布要求写入 Core。

## 分支与 Pull Request

- 不直接推送到 `main`；从 `develop` 创建 `feature/<topic>`，通过 PR 合并；
- 影响发布基线的专项工作使用 `release/*` 分支，并通过 PR 合并到 `main`；
- PR 应说明目标、影响范围、验证证据和仍未验证的事项；
- 所有远程分支均可被第三方阅读；不得提交内部协作记录、凭据或私有资料。

提交内容时应：

- 保持 Core 与 Adapter 的责任边界；
- 为行为变更提供相应的测试或验证证据；
- 不提交凭据、真实用户数据或未获授权的外部内容；
- 说明对 Artifact、追踪关系和 Adapter 兼容性的影响。
