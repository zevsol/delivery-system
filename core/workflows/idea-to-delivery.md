# Idea to Delivery Core Workflow

> 适用角色：Idea to Delivery
>
> 关联权威：`../CORE-CONTRACT.md`

## 目的

将原始 Idea 稳定推进为可审查、可批准、可执行的交付基线。该工作流负责生成、维护和修订交付产物，但不能以生产者身份宣称自己的产物已独立审查通过。

## 输入与输出

输入可以是模糊 Idea、已有需求、现有代码库、审查 Finding、Change Candidate 或已批准的用户决定。

输出按项目规模裁剪，可包括 Idea Brief、Requirement、NFR、ADR、Roadmap、Milestone、Epic、Issue Draft、Traceability Record、Change Request、Clarification Request、Spike 或 Closure Report。

## 标准流程

1. **Intake**：记录原始意图、已知约束、非目标、当前项目状态和风险信号；不直接进入实现。
2. **Discovery**：澄清问题、目标用户、核心场景、成功标准、未知项和假设。关键未知不得被猜测填补。
3. **Requirements**：建立可观察的功能与非功能需求、业务规则、范围、非目标和验收标准。
4. **Architecture / Feasibility**：针对从零项目评估方案；针对已有项目先调查现状；针对高风险未知创建 Spike 或 ADR Decision Required。
5. **Roadmap and Decomposition**：按可观察结果组织 Milestone、Epic、Feature 和 Issue，并建立依赖与追踪。
6. **Audit Preparation**：确认产物包含证据、未知项、决策状态与关系，交由 Audit Delivery 独立检查。
7. **Revision and Baseline**：只有在用户接受相关决定或 Finding 后，才修订正式产物并建立新基线。
8. **Change and Closure**：处理 Change Request、更新下游关系，并在交付结束时检查承诺是否闭环。

## 项目规模裁剪

| 情形 | 最小流程 |
|---|---|
| 小修复 | Brief → Issue → Verification |
| 中型功能 | Mini PRD → 必要 ADR → Epic / Issues |
| 新项目 | Idea Brief → Requirements → Architecture → Roadmap → Issues |
| 高风险重构 | 现状调查 → Baseline → ADR → 迁移计划 → Issues |
| 探索性想法 | Discovery → Research / Spike → Decision |

安全、支付、医疗、法律或其他高风险领域应优先识别专业审查和外部约束；本工作流不得自动替代专业判断。

## 阻塞规则

当关键产品、业务、架构、合规或依赖条件未知时，必须创建适当的 Clarification Request、Research Task、Spike、ADR Decision Required 或 Blocked Issue。不得生成伪确定的实施计划。

## 变更规则

发现新需求时必须先交给 `../policies/change-management.md` 分类和影响分析。只有不改变原目标、不产生新能力、不显著扩大测试、不改变架构与依赖、且仍可按原验收标准闭环的澄清，才可以留在原 Issue。

## 完成条件

一个计划达到 Implementation Ready 前，必须满足 Core Contract 的第 9 节，并通过适用的独立审查。未获批准的建议、待决事项和风险必须继续保持可见，不得写入正式基线。
