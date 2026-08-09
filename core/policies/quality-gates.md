# 质量门政策

质量门用于确认必要证据和批准已到位，不是自动替代产品判断的机制。默认门如下：

| Gate | 通过条件 |
|---|---|
| Discovery Complete | 问题、用户、场景、未知项与成功标准已记录 |
| Requirements Approved | 需求、范围、非目标与关键验收标准已批准 |
| Architecture Approved | 关键 ADR、风险、依赖与迁移策略已被接受或明确阻塞 |
| Plan Audited | 独立审查已完成，Finding 已被用户决定 |
| Issues Ready | Issue 满足 Implementation Ready，依赖与验证方法明确 |
| Implementation Verified | 完成证据和适用验证已记录，DoD 已检查 |
| Release Approved | 用户确认发布范围、已知风险和外部操作 |

适配器可以改变 Gate 的展示和交互方式，但不能静默跳过适用的批准。无法获取批准时，应降级为草稿、预览或 blocked 状态。
