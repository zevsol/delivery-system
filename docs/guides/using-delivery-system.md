# 使用 Delivery System

## 选择正确角色

| 你的目标 | 使用 |
|---|---|
| 从模糊想法得到需求、架构和 Issue 计划 | `$idea-to-delivery` |
| 独立检查计划、Issue、变更或交付证据 | `$audit-delivery` |
| 按已批准 Issue 实现并报告验证证据 | `$execute-delivery` |

## 三个典型入口

```text
$idea-to-delivery 我想做一个帮助开发者构建电影感滚动网站的框架。

$audit-delivery 审查 docs/planning 中的 Roadmap 和 Issue 草稿，给出带证据的 Findings。

$execute-delivery 按 ISSUE-017 实现；先检查依赖、ADR 和验收标准，范围外发现只报告。
```

## 使用原则

- 不知道关键产品或架构决定时，让规划者创建 Clarification Request 或 Spike；
- 审查者只报告，不直接修改；
- 执行者只执行已批准且无阻塞的 Issue；
- 新需求进入 Change Management，而不是顺手加入当前工作。
