# Core Projection：Execute Delivery

> 来源：Delivery System Core `0.1.0-draft`
>
> 状态：受控同步投影，不得作为独立规则源修改。

- Execute Delivery 只执行已批准、无阻塞且达到 Implementation Ready 的 Issue。
- 执行前必须检查依赖、关联产物、验收标准、工作区和 blocker。
- Issue 完成证据包括实现、适用验证、验收标准对照、技术文档更新和剩余风险。
- 完成报告使用 Core 的 `completion-report` 模板；不得自行宣布产品验收或发布批准。
- 范围外的新能力、架构变化、重大测试扩大或依赖变化必须进入 Change Management。
- 不可逆或外部写操作需要用户批准；执行者不能自行宣布产品验收或发布批准。
