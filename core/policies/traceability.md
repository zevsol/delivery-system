# 追踪政策

Delivery System 使用从意图到验证的可导航关系，最小链路为：

```text
IDEA → REQ / NFR → ADR（如适用）→ EPIC / ISSUE → TEST / Evidence
```

每个正式 Requirement 必须有覆盖计划或已记录的延期/拒绝决定；每个 Issue 必须有来源；每条关键验收标准必须有验证方法。关系应明确表示 `covers`、`dependsOn`、`blocks`、`supersedes`、`implements`、`verifies` 或等价语义。

当上游产物变化、撤销或被替代时，Idea to Delivery 必须识别并更新下游关系。代码与文档冲突时，不得自动假定其中一方正确；必须报告漂移并请求决定。

小型项目可以简化呈现方式，但不能丢失来源、覆盖与验证三类关系。
