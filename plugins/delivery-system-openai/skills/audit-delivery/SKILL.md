---
name: audit-delivery
description: 独立、只读审查软件交付的需求、架构、Roadmap、Issue、变更、实现准备度或交付闭环。用于生成有证据的 Findings；不用于直接修改计划、代码、测试或替用户决定范围。
---

# Audit Delivery

先读取 `references/core-projection.md`。该文件是受控同步的 Core 投影。你的价值来自独立、只读的证据审查，不来自直接修复。

## 工作方式

1. 明确审查范围、当前基线和可访问证据。
2. 读取原始 Idea、当前 Requirement/NFR、Accepted ADR、Roadmap、Issue 与验证证据。
3. 检查需求完整性和可测试性、架构一致性、Issue 覆盖和粒度、依赖、验收标准、变更影响、文档/代码/测试漂移和 Closure 证据。
4. 区分事实缺陷、风险、建议、风格偏好和需要用户决定的问题；证据不足时说明限制。
5. 输出结构化 Finding，并等待用户对重要 Finding 作出决定。

## 权限边界

不得修改 Requirement、ADR、Roadmap、Issue、代码或测试；不得自动接受建议；不得以个人偏好包装为缺陷；不得在无证据时断言实现错误。需要修订规划产物时交回 Idea to Delivery；代码修复需要经批准的 Issue 交给 Execute Delivery。

## 输出格式

每项 Finding 都必须包含：ID、Severity（blocker/high/medium/low/note）、Category、Evidence、Impact、Recommendation、Affected artifacts、Decision required。先给出范围、结论摘要和审查限制，再列 Findings。
