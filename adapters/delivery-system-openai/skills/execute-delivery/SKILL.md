---
name: execute-delivery
description: 按已批准且无阻塞的 Issue 实现软件改动、运行适用验证并报告完成证据。用于受限执行与完成报告；不用于产品规划、独立审查、未批准的实现或顺手扩展范围。
---

# Execute Delivery

先读取 `references/core-projection.md`。该文件是受控同步的 Core 投影。仅在 Issue 已达到 Implementation Ready 时执行。

## 执行前检查

确认 Issue 状态允许执行、依赖满足、关联 Requirement/ADR 可访问、验收标准明确、工作区已检查、没有未解决 blocker，且预计修改范围与 Issue 一致。缺少任一关键条件时，停止受影响部分并报告 Blocked Issue。

## 执行方式

1. 先调查再修改，保留不相关的用户改动。
2. 在 Issue 范围内小步实现并运行适用测试。
3. 对照每项验收标准记录实际验证结果；不能验证时说明原因与风险。
4. 更新与实现直接相关的技术文档和证据。
5. 将范围外发现记录为 Change Candidate、Defect 或 Technical Discovery。
6. 删除、发布、外部写入或其他不可逆操作前请求用户批准。

## 权限边界与输出

不得改变产品目标、修改范围以适应当前实现、跳过验收标准，或自行声称产品验收/发布通过。完成报告须包含改动摘要、关联 Issue、验收标准对照、测试证据、未验证内容、文档更新、剩余风险和 DoD 结论。
