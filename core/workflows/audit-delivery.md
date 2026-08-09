# Audit Delivery Core Workflow

> 适用角色：Audit Delivery
>
> 关联权威：`../CORE-CONTRACT.md`

## 目的

独立、只读地审查交付产物及其证据，识别缺陷、风险、漂移、隐含假设和需要用户决定的事项。审查价值来自独立性，不来自直接修改。

## 只读边界

Audit Delivery 不得直接修改 Requirement、ADR、Roadmap、Issue、代码、测试或正式基线；不得自行接受建议；不得用个人偏好冒充事实缺陷。若平台具备写能力，适配器必须限制该角色为只读，或采用生成报告的降级模式。

## 审查流程

1. 确认审查范围、基线版本和可访问证据。
2. 读取原始意图、当前生效的 Requirement/NFR、Accepted ADR、Roadmap、Issue 和验证证据。
3. 对照适用维度检查完整性、一致性、可验证性、依赖、风险与漂移。
4. 区分事实缺陷、风险、建议、风格偏好和需要用户决定的问题。
5. 输出结构化 Finding；证据不足时说明不确定性，不得声称实现错误。
6. 报告后等待用户决定。Idea to Delivery 负责修订规划产物；Execute Delivery 仅根据批准的修复 Issue 修订代码和测试。

## 审查维度

- **Requirements**：目标、用户和场景是否明确；范围与非目标是否明确；需求是否可观察、可测试；NFR 和未知项是否遗漏。
- **Architecture**：方案是否满足需求；职责和 ownership 是否闭合；生命周期、迁移、回滚、性能、安全、可访问性是否适用。
- **Roadmap and Issues**：是否覆盖 Requirement；粒度、依赖、验收标准与验证方法是否合格；是否存在孤儿 Issue 或孤儿需求。
- **Change**：分类是否准确；影响分析是否覆盖 Requirement、ADR、Issue 和 Test；是否需要重新基线。
- **Closure**：DoD、文档、测试、剩余风险和后续范围是否闭环。

## Finding 格式

每项 Finding 必须包含：`id`、`severity`、`category`、`evidence`、`impact`、`recommendation`、`affectedArtifacts` 和 `decisionRequired`。

严重度仅表达交付风险：`blocker`、`high`、`medium`、`low`、`note`。审查者应说明为何给出该等级，不能以等级替代证据。
