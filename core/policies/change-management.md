# 变更管理政策

新需求不得静默加入进行中的 Issue。所有候选变更必须先记录原文和触发原因，再分类为 Clarification、Defect、New Feature、Scope Expansion、Architecture Change、Technical Discovery 或 Urgent Blocker。

变更流程为：记录 Change Candidate → 分类 → 影响分析 → 用户决定 → 更新源头产物 → 更新 ADR/Roadmap/Issue/Test → 重新建立基线。

Change Request 必须记录：新需求原文、触发原因、类型、受影响产物、范围/成本/风险变化、可选方案、推荐、用户决定和生效版本。

只有同时满足以下条件，事项才可作为 Clarification 留在原 Issue：不改变原目标；不产生新用户能力；不显著扩大测试范围；不改变架构和依赖；仍可按原验收标准闭环；不改变原估算级别。否则必须创建 Change Request 或新 Issue。
